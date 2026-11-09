// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Howard M. Harte

//! Match visible ASCII prompt text after host output has been quiet.
//!
//! The parser shares terminal control-sequence boundaries with the injection
//! interlock, so control parameters cannot satisfy a prompt. A quiet interval
//! also prevents answering while the host is still drawing the screen.
//! Standing rules can repeat; one-shot rules become eligible in order.
//! Declaration order breaks ties between eligible matches.

use std::time::{Duration, Instant};

use crate::inject::{step, State};

/// Ignore matches for this long after firing.
///
/// Insurance against a repaint: the window is cleared on every match, so a
/// second fire needs the pattern to arrive again, but a program that redraws
/// its prompt could do exactly that within milliseconds.  Long next to a
/// repaint, short next to any real prompt-to-prompt interval -- a `vttest`
/// screen at 9600 baud takes seconds.
pub const MATCH_REFRACTORY: Duration = Duration::from_millis(400);

/// How much recent screen text is kept for matching, in characters.
///
/// Two 80x24 screenfuls.  Bounded because a suite run prints megabytes and an
/// unbounded window would both grow without limit and let a pattern match
/// text from twenty tests ago.
pub const DEFAULT_WINDOW: usize = 4096;

/// One `PATTERN => KEYS` rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// Literal text to look for in the host's output.
    pub pattern: String,
    /// Bytes to inject when it appears.
    pub keys: Vec<u8>,
    /// Retire after firing, and gate the script rules that follow.
    pub once: bool,
}

impl Rule {
    /// Parse a `PATTERN => KEYS` specification.
    ///
    /// The keys half goes through the same escape decoder as `--send`, so
    /// `\r`, `\e[A` and `\x03` mean the same thing in both places.  A rule
    /// with an empty pattern is rejected: it would match every window,
    /// including the empty one, and fire forever.
    pub fn parse(
        spec: &str,
        once: bool,
        decode: impl Fn(&str) -> Result<Vec<u8>, String>,
    ) -> Result<Self, String> {
        let flag = if once { "--expect-once" } else { "--expect" };
        let (pat, keys) = spec.split_once("=>").ok_or_else(|| {
            format!(
                "{} '{}' needs a '=>' between the text to wait for and the \
                 keys to send, e.g. {} 'Push <RETURN> => \\r'",
                flag, spec, flag
            )
        })?;
        let pattern = pat.trim().to_string();
        if pattern.is_empty() {
            return Err(format!(
                "{} '{}' has an empty pattern, which would match immediately \
                 and repeatedly",
                flag, spec
            ));
        }
        if !pattern.is_ascii() {
            return Err(format!("{flag} pattern must use ASCII text"));
        }
        Ok(Self {
            pattern,
            keys: decode(keys.trim())?,
            once,
        })
    }
}

/// A rule that just fired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fired {
    /// Position on the command line, for messages.
    pub index: usize,
    /// The pattern that matched.
    pub pattern: String,
    /// The bytes to inject.
    pub keys: Vec<u8>,
}

/// Watches the host's output and decides when to answer it.
pub struct Expect {
    rules: Vec<Rule>,
    retired: Vec<bool>,
    window: String,
    limit: usize,
    /// Escape-sequence position, so control sequences are not matched as text.
    /// Shared with [`crate::inject`] on purpose: two parsers would eventually
    /// disagree about what a sequence is, and the interlock and this module
    /// would then be protecting against different things.
    state: State,
    quiet: Duration,
    timeout: Option<Duration>,
    last_byte: Option<Instant>,
    last_match: Option<Instant>,
    waiting_since: Instant,
    /// Rules fired so far.
    pub matches: u64,
}

impl Expect {
    /// Build a watcher.  `quiet` is how long the host must be idle before a
    /// match counts; `timeout` bounds how long to wait for the next script
    /// rule before declaring the run stuck.
    pub fn new(rules: Vec<Rule>, quiet: Duration, timeout: Option<Duration>) -> Self {
        Self::with_window(rules, quiet, timeout, DEFAULT_WINDOW, Instant::now())
    }

    /// [`Expect::new`] with the window size and the clock supplied, for tests.
    pub fn with_window(
        rules: Vec<Rule>,
        quiet: Duration,
        timeout: Option<Duration>,
        limit: usize,
        now: Instant,
    ) -> Self {
        let retired = vec![false; rules.len()];
        Self {
            rules,
            retired,
            window: String::new(),
            limit: limit.max(1),
            state: State::Ground,
            quiet,
            timeout,
            last_byte: None,
            last_match: None,
            waiting_since: now,
            matches: 0,
        }
    }

    /// Whether any rules were given at all.
    pub fn is_active(&self) -> bool {
        !self.rules.is_empty()
    }

    /// Whether a script was given -- i.e. whether "done" is a thing that can
    /// happen.  Standing rules alone never finish: they answer prompts for as
    /// long as prompts arrive.
    pub fn has_script(&self) -> bool {
        self.rules.iter().any(|r| r.once)
    }

    /// Every script rule has fired.
    pub fn is_done(&self) -> bool {
        self.has_script() && self.next_script().is_none()
    }

    /// The next script rule waiting to fire, if any.
    fn next_script(&self) -> Option<usize> {
        self.rules
            .iter()
            .enumerate()
            .find(|(i, r)| r.once && !self.retired[*i])
            .map(|(i, _)| i)
    }

    /// Feed bytes the host sent to the terminal.
    pub fn feed(&mut self, bytes: &[u8]) {
        self.feed_at(bytes, Instant::now());
    }

    /// [`Expect::feed`] with the clock supplied.
    pub fn feed_at(&mut self, bytes: &[u8], now: Instant) {
        if bytes.is_empty() {
            return;
        }
        self.last_byte = Some(now);
        for &b in bytes {
            let prev = self.state;
            self.state = step(prev, b);
            // A byte is screen text only if it was not inside a control
            // sequence and did not start one. Everything else is addressing,
            // attributes and reports, none of which a person reads.
            if prev != State::Ground || b == 0x1b {
                continue;
            }
            match b {
                b'\r' | b'\n' => self.window.push('\n'),
                b'\t' => self.window.push(' '),
                0x20..=0x7e => self.window.push(b as char),
                // Everything else -- backspace, bell, the C1 range, anything
                // above ASCII -- is dropped rather than substituted, so it
                // cannot accidentally satisfy a pattern.
                _ => {}
            }
        }
        if self.window.len() > self.limit {
            // Only ASCII is ever pushed, so a byte count is a char count and
            // this cannot split a code point.
            let cut = self.window.len() - self.limit;
            self.window.drain(..cut);
        }
    }

    /// Whether the host has been quiet long enough for a prompt to be final.
    fn settled(&self, now: Instant) -> bool {
        match self.last_byte {
            Some(t) => now.duration_since(t) >= self.quiet,
            // Nothing has arrived at all: there is no prompt to answer.
            None => false,
        }
    }

    /// Check the window and return a rule to fire, if one is due.
    pub fn poll(&mut self) -> Option<Fired> {
        self.poll_at(Instant::now())
    }

    /// [`Expect::poll`] with the clock supplied.
    pub fn poll_at(&mut self, now: Instant) -> Option<Fired> {
        if self.rules.is_empty()
            || self.window.is_empty()
            || self.state != State::Ground
            || !self.settled(now)
        {
            return None;
        }
        if let Some(t) = self.last_match {
            if now.duration_since(t) < MATCH_REFRACTORY {
                return None;
            }
        }

        let script = self.next_script();
        let hit = self.rules.iter().enumerate().find(|(i, r)| {
            let eligible = if r.once { script == Some(*i) } else { true };
            eligible && !self.retired[*i] && self.window.contains(&r.pattern)
        });
        let (index, rule) = match hit {
            Some((i, r)) => (i, r.clone()),
            None => return None,
        };

        // Clearing the window is what stops a prompt that is still on the
        // screen from firing the same rule again on the very next pass.
        self.window.clear();
        self.last_match = Some(now);
        self.waiting_since = now;
        self.matches += 1;
        if rule.once {
            self.retired[index] = true;
        }
        Some(Fired {
            index,
            pattern: rule.pattern,
            keys: rule.keys,
        })
    }

    /// The script rule that has been waited on past `--expect-timeout`.
    ///
    /// Only script rules can stall: a standing rule has no obligation to ever
    /// match, and treating an idle one as a failure would make a suite run
    /// that finished early look broken.
    pub fn stalled(&self, now: Instant) -> Option<&Rule> {
        let timeout = self.timeout?;
        let idx = self.next_script()?;
        if now.duration_since(self.waiting_since) >= timeout {
            Some(&self.rules[idx])
        } else {
            None
        }
    }

    /// How long the current script rule has been waiting.
    pub fn waited(&self, now: Instant) -> Duration {
        now.duration_since(self.waiting_since)
    }

    /// How long since the host last printed anything.
    ///
    /// Zero before the first byte, so "the host has gone quiet" cannot be
    /// true of a host that has never spoken.
    pub fn quiet_for(&self, now: Instant) -> Duration {
        match self.last_byte {
            Some(t) => now.duration_since(t),
            None => Duration::ZERO,
        }
    }

    /// One line for the banner.
    pub fn describe(&self) -> String {
        let once = self.rules.iter().filter(|r| r.once).count();
        let standing = self.rules.len() - once;
        let mut s = format!("{} standing, {} scripted", standing, once);
        if self.quiet > Duration::ZERO {
            s.push_str(&format!(
                ", answer after {} ms quiet",
                self.quiet.as_millis()
            ));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_ascii_prompt_patterns_fail_early_instead_of_waiting_forever() {
        assert!(
            Rule::parse("café => x", false, |s| Ok(s.as_bytes().to_vec()))
                .unwrap_err()
                .contains("ASCII")
        );
    }

    #[test]
    fn c1_and_charset_parameters_cannot_be_matched_as_screen_text() {
        for bytes in [
            &b"\x9b24;80H"[..],
            &b"\x90needle\x9c"[..],
            &b"\x1b(needle"[..],
        ] {
            let mut expect = watcher(
                &[("needle => x", false), ("24;80 => x", false)],
                Instant::now(),
            );
            expect.feed(bytes);
            assert!(expect.poll().is_none(), "{bytes:?}");
        }
    }

    #[test]
    fn a_matching_prompt_waits_for_the_last_control_sequence_to_finish() {
        let now = Instant::now();
        let mut expect = watcher(&[("prompt => x", false)], now);
        expect.feed_at(b"prompt\x1b[", now);
        assert!(expect.poll_at(now).is_none());
        expect.feed_at(b"0m", now);
        assert!(expect.poll_at(now).is_some());
    }

    /// The escape decoder the real parser uses is in `args`; these tests only
    /// need enough of it to prove the split.
    fn decode(s: &str) -> Result<Vec<u8>, String> {
        Ok(s.replace("\\r", "\r").into_bytes())
    }

    fn rules(specs: &[(&str, bool)]) -> Vec<Rule> {
        specs
            .iter()
            .map(|(s, once)| Rule::parse(s, *once, decode).unwrap())
            .collect()
    }

    /// Quiet of zero, so tests that are not about settling do not have to
    /// simulate it.
    fn watcher(specs: &[(&str, bool)], now: Instant) -> Expect {
        Expect::with_window(rules(specs), Duration::ZERO, None, DEFAULT_WINDOW, now)
    }

    // ---- rule parsing -------------------------------------------------

    #[test]
    fn a_rule_splits_on_the_arrow_and_trims() {
        let r = Rule::parse("Push <RETURN> => \\r", false, decode).unwrap();
        assert_eq!(r.pattern, "Push <RETURN>");
        assert_eq!(r.keys, b"\r".to_vec());
        assert!(!r.once);
    }

    #[test]
    fn a_rule_without_an_arrow_says_what_it_wanted() {
        let e = Rule::parse("Push <RETURN>", false, decode).unwrap_err();
        assert!(e.contains("=>"), "{}", e);
    }

    /// An empty pattern is in every window, including the empty one, so it
    /// would fire on the first poll and every poll after it.
    #[test]
    fn an_empty_pattern_is_refused() {
        assert!(Rule::parse(" => \\r", false, decode).is_err());
    }

    #[test]
    fn keys_may_be_empty_even_though_a_pattern_may_not() {
        // Waiting for text and sending nothing is a legitimate barrier.
        let r = Rule::parse("Push <RETURN> =>", false, decode).unwrap();
        assert!(r.keys.is_empty());
    }

    // ---- text extraction ----------------------------------------------

    #[test]
    fn control_sequences_are_not_matched_as_text() {
        let mut e = watcher(&[("24;80 => x", false)], Instant::now());
        // A cursor-position report's parameters must not satisfy a pattern
        // that looks like them.
        e.feed(b"\x1b[24;80H");
        assert!(e.poll().is_none());
    }

    #[test]
    fn text_split_by_a_sequence_still_matches() {
        // vttest positions the cursor part-way through writing a line, so the
        // prompt reaches the wire in halves with addressing between them.
        let now = Instant::now();
        let mut e = watcher(&[("Push <RETURN> => \\r", false)], now);
        e.feed_at(b"Push <RE", now);
        e.feed_at(b"\x1b[1;1H", now);
        e.feed_at(b"TURN>", now);
        assert!(e.poll_at(now).is_some());
    }

    #[test]
    fn the_window_is_bounded_and_keeps_the_most_recent_text() {
        let now = Instant::now();
        let mut e = Expect::with_window(
            rules(&[("needle => x", false)]),
            Duration::ZERO,
            None,
            32,
            now,
        );
        e.feed_at(&vec![b'.'; 4096], now);
        assert!(e.poll_at(now).is_none());
        e.feed_at(b"needle", now);
        assert!(
            e.poll_at(now).is_some(),
            "recent text must survive the trim"
        );
    }

    /// Dropping CR and LF entirely would weld the end of one line to the start
    /// of the next and invent phrases nobody printed.
    #[test]
    fn line_ends_do_not_weld_words_together() {
        let now = Instant::now();
        let mut e = watcher(&[("foobar => x", false)], now);
        e.feed_at(b"foo\r\nbar", now);
        assert!(e.poll_at(now).is_none());
    }

    // ---- standing rules -----------------------------------------------

    #[test]
    fn a_standing_rule_fires_every_time_its_prompt_appears() {
        let now = Instant::now();
        let mut e = watcher(&[("Push <RETURN> => \\r", false)], now);
        for i in 0..3 {
            let t = now + MATCH_REFRACTORY * (i + 1);
            e.feed_at(b"...done. Push <RETURN>", t);
            let f = e.poll_at(t).expect("prompt should be answered");
            assert_eq!(f.keys, b"\r".to_vec());
        }
        assert_eq!(e.matches, 3);
    }

    /// The double-fire guard: after answering, the prompt is still the last
    /// thing on the screen.
    #[test]
    fn a_prompt_is_answered_once_not_on_every_pass() {
        let now = Instant::now();
        let mut e = watcher(&[("Push <RETURN> => \\r", false)], now);
        e.feed_at(b"Push <RETURN>", now);
        assert!(e.poll_at(now).is_some());
        assert!(
            e.poll_at(now + MATCH_REFRACTORY * 2).is_none(),
            "the same text must not be answered twice"
        );
    }

    #[test]
    fn the_refractory_period_swallows_a_repaint() {
        let now = Instant::now();
        let mut e = watcher(&[("Push <RETURN> => \\r", false)], now);
        e.feed_at(b"Push <RETURN>", now);
        assert!(e.poll_at(now).is_some());
        // The host redraws the prompt immediately.
        let t = now + Duration::from_millis(10);
        e.feed_at(b"Push <RETURN>", t);
        assert!(e.poll_at(t).is_none(), "a redraw is not a new prompt");
    }

    // ---- script rules -------------------------------------------------

    #[test]
    fn script_rules_fire_in_order_and_gate_each_other() {
        let now = Instant::now();
        let mut e = watcher(
            &[
                ("Enter choice number => 6\\r", true),
                ("Enter choice number => 0\\r", true),
            ],
            now,
        );
        e.feed_at(b"Enter choice number", now);
        let first = e.poll_at(now).unwrap();
        assert_eq!(first.keys, b"6\r".to_vec());

        let t = now + MATCH_REFRACTORY * 2;
        e.feed_at(b"Enter choice number", t);
        let second = e.poll_at(t).unwrap();
        assert_eq!(second.keys, b"0\r".to_vec(), "the script must advance");

        let t2 = t + MATCH_REFRACTORY * 2;
        e.feed_at(b"Enter choice number", t2);
        assert!(e.poll_at(t2).is_none(), "a retired rule must stay retired");
        assert!(e.is_done());
    }

    /// The real shape of a suite run: a script that walks the menus, and a
    /// standing rule that answers the prompt every test ends with.
    #[test]
    fn a_script_and_a_standing_rule_coexist() {
        let now = Instant::now();
        let mut e = watcher(
            &[
                ("Push <RETURN> => \\r", false),
                ("Enter choice number => 1\\r", true),
            ],
            now,
        );
        e.feed_at(b"Enter choice number", now);
        assert_eq!(e.poll_at(now).unwrap().keys, b"1\r".to_vec());

        let t = now + MATCH_REFRACTORY * 2;
        e.feed_at(b"Test 1 done. Push <RETURN>", t);
        assert_eq!(e.poll_at(t).unwrap().keys, b"\r".to_vec());
        assert!(e.is_done(), "the script finished even though a rule stands");
    }

    #[test]
    fn declaration_order_decides_which_rule_wins() {
        let now = Instant::now();
        let mut e = watcher(&[("choice => a", false), ("Enter choice => b", false)], now);
        e.feed_at(b"Enter choice number", now);
        assert_eq!(e.poll_at(now).unwrap().keys, b"a".to_vec());
    }

    #[test]
    fn standing_rules_alone_are_never_done() {
        let e = watcher(&[("Push <RETURN> => \\r", false)], Instant::now());
        assert!(!e.has_script());
        assert!(
            !e.is_done(),
            "a bridge with no script must not exit by itself"
        );
    }

    // ---- the quiet gate -----------------------------------------------

    #[test]
    fn a_prompt_is_not_answered_while_the_host_is_still_painting() {
        let now = Instant::now();
        let mut e = Expect::with_window(
            rules(&[("Push <RETURN> => \\r", false)]),
            Duration::from_millis(200),
            None,
            DEFAULT_WINDOW,
            now,
        );
        e.feed_at(b"Push <RETURN>", now);
        assert!(e.poll_at(now).is_none(), "the screen is not finished");
        assert!(e.poll_at(now + Duration::from_millis(199)).is_none());
        assert!(e.poll_at(now + Duration::from_millis(200)).is_some());
    }

    #[test]
    fn more_output_restarts_the_quiet_timer() {
        let now = Instant::now();
        let mut e = Expect::with_window(
            rules(&[("Push <RETURN> => \\r", false)]),
            Duration::from_millis(200),
            None,
            DEFAULT_WINDOW,
            now,
        );
        e.feed_at(b"Push <RETURN>", now);
        let t = now + Duration::from_millis(150);
        e.feed_at(b" and more text", t);
        assert!(
            e.poll_at(now + Duration::from_millis(210)).is_none(),
            "the host is still talking"
        );
        assert!(e.poll_at(t + Duration::from_millis(200)).is_some());
    }

    #[test]
    fn silence_before_anything_arrives_is_not_a_prompt() {
        let now = Instant::now();
        let e = Expect::with_window(
            rules(&[("Push <RETURN> => \\r", false)]),
            Duration::from_millis(50),
            None,
            DEFAULT_WINDOW,
            now,
        );
        // No bytes have ever arrived; an hour of quiet must still not fire.
        let mut e = e;
        assert!(e.poll_at(now + Duration::from_secs(3600)).is_none());
    }

    // ---- stalling ------------------------------------------------------

    #[test]
    fn a_script_rule_that_never_matches_is_reported_as_stalled() {
        let now = Instant::now();
        let mut e = Expect::with_window(
            rules(&[("Enter choice number => 1\\r", true)]),
            Duration::ZERO,
            Some(Duration::from_secs(30)),
            DEFAULT_WINDOW,
            now,
        );
        assert!(e.stalled(now + Duration::from_secs(29)).is_none());
        let stuck = e.stalled(now + Duration::from_secs(30)).unwrap();
        assert_eq!(stuck.pattern, "Enter choice number");

        // Matching it restarts the clock for whatever comes next.
        e.feed_at(b"Enter choice number", now);
        assert!(e.poll_at(now).is_some());
        assert!(e.stalled(now + Duration::from_secs(31)).is_none());
    }

    #[test]
    fn a_finished_script_cannot_stall() {
        let now = Instant::now();
        let mut e = Expect::with_window(
            rules(&[("Push <RETURN> => \\r", false), ("choice => 1\\r", true)]),
            Duration::ZERO,
            Some(Duration::from_secs(5)),
            DEFAULT_WINDOW,
            now,
        );
        e.feed_at(b"choice", now);
        assert!(e.poll_at(now).is_some());
        assert!(
            e.stalled(now + Duration::from_secs(600)).is_none(),
            "a standing rule with nothing to answer is not a failure"
        );
    }

    // ---- prompt-driven timing -------------------------------------------

    /// Elapsed time alone must not inject a key before the prompt arrives.
    #[test]
    fn time_alone_never_produces_a_keystroke() {
        let now = Instant::now();
        let mut e = Expect::with_window(
            rules(&[("Push <RETURN> => \\r", false)]),
            Duration::from_millis(200),
            None,
            DEFAULT_WINDOW,
            now,
        );
        // A report exchange, exactly as vttest drives one: the host asks, and
        // nothing that looks like a prompt is ever printed.
        e.feed_at(b"\x1b[6n", now);
        for i in 1..50 {
            assert!(
                e.poll_at(now + Duration::from_millis(i * 100)).is_none(),
                "a keystroke escaped at {} ms with no prompt on the screen",
                i * 100
            );
        }
        assert_eq!(e.matches, 0);
    }
}

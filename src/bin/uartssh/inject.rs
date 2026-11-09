// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Howard M. Harte

//! Merge injected keys with terminal replies without splitting a sequence.
//!
//! The sequence watch is shared with prompt matching. It recognizes CSI,
//! control strings, single shifts, charset escapes and UTF-8 code-point
//! boundaries across read chunks. The interlock releases held keys after
//! MAX_HOLD if a sequence never completes, counting that loss of protection.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// How long a keystroke may be held waiting for a terminal reply to finish.
///
/// A finite grace interval for incomplete replies. Expiry increments the
/// forced-release counter so a loss of interlock protection remains visible.
pub const MAX_HOLD: Duration = Duration::from_millis(250);

/// Where the terminal's byte stream currently sits in a control sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum State {
    /// Not inside anything; a keystroke here is safe.
    Ground,
    /// `ESC` seen; the next byte decides what this is.
    Esc,
    /// An escape with intermediate bytes, such as a character-set designation.
    EscIntermediate,
    /// SS2/SS3 holds through the following graphic character or key code.
    Shift,
    /// A UTF-8 code point; continuation bytes must not become C1 controls.
    Utf8 {
        remaining: u8,
    },
    /// Inside a control sequence, waiting for a final byte.
    Csi,
    /// Inside a control string, waiting for ST (or BEL for OSC).
    Str {
        bel_terminates: bool,
    },
    StrUtf8 {
        bel_terminates: bool,
        remaining: u8,
    },
    /// Inside a string sequence with `ESC` seen -- a backslash here ends it.
    StrEsc {
        bel_terminates: bool,
    },
}

/// Tracks whether the terminal is part-way through a control sequence.
///
/// Deliberately permissive: this is not a terminal emulator and does not need
/// to *understand* the replies, only to know when one is open.  Anything it
/// cannot classify resolves to ground, which fails towards letting keystrokes
/// through rather than towards holding them.
#[derive(Debug)]
pub struct SequenceWatch {
    state: State,
}

impl Default for SequenceWatch {
    fn default() -> Self {
        Self::new()
    }
}

impl SequenceWatch {
    /// A watch that starts on solid ground.
    pub fn new() -> Self {
        Self {
            state: State::Ground,
        }
    }

    /// Feed bytes the terminal sent.
    pub fn feed(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.state = step(self.state, b);
        }
    }

    /// Whether a reply is open right now.
    pub fn in_flight(&self) -> bool {
        !matches!(self.state, State::Ground)
    }
}

/// One byte of the terminal's stream against the sequence state machine.
pub(crate) fn step(s: State, b: u8) -> State {
    const ESC: u8 = 0x1b;
    const BEL: u8 = 0x07;
    const CAN: u8 = 0x18;
    const SUB: u8 = 0x1a;

    // ECMA-48 control strings have 7-bit ESC and 8-bit C1 forms. Cancellation
    // and a new ESC also work between reads, not just within a complete packet.
    if matches!(b, CAN | SUB) {
        return State::Ground;
    }
    if b == ESC {
        return match s {
            State::Str { bel_terminates }
            | State::StrEsc { bel_terminates }
            | State::StrUtf8 { bel_terminates, .. } => State::StrEsc { bel_terminates },
            _ => State::Esc,
        };
    }

    match s {
        State::Ground => match b {
            0x9b => State::Csi,
            0x8e | 0x8f => State::Shift,
            0x9d => State::Str {
                bel_terminates: true,
            },
            0x90 | 0x98 | 0x9e | 0x9f => State::Str {
                bel_terminates: false,
            },
            byte => utf8_tail(byte).map_or(State::Ground, |remaining| State::Utf8 { remaining }),
        },
        State::Esc => match b {
            b'[' => State::Csi,
            b']' => State::Str {
                bel_terminates: true,
            },
            b'P' | b'_' | b'^' | b'X' => State::Str {
                bel_terminates: false,
            },
            b'N' | b'O' => State::Shift,
            0x20..=0x2f => State::EscIntermediate,
            0x00..=0x1f | 0x7f => State::Esc,
            // Anything else completes a two-byte escape.
            _ => State::Ground,
        },
        State::EscIntermediate => match b {
            0x20..=0x2f | 0x00..=0x1f | 0x7f => State::EscIntermediate,
            _ => State::Ground,
        },
        State::Shift => match b {
            0x00..=0x1f | 0x7f => State::Shift,
            _ => State::Ground,
        },
        State::Utf8 { remaining } => {
            if (0x80..=0xbf).contains(&b) {
                if remaining == 1 {
                    State::Ground
                } else {
                    State::Utf8 {
                        remaining: remaining - 1,
                    }
                }
            } else {
                step(State::Ground, b)
            }
        }
        State::Csi => match b {
            // Parameter and intermediate bytes keep the sequence open.
            0x20..=0x3f => State::Csi,
            // A final byte closes it.
            0x40..=0x7e => State::Ground,
            _ => State::Csi,
        },
        State::Str { bel_terminates } => match b {
            0x9c => State::Ground,
            BEL if bel_terminates => State::Ground,
            byte => {
                utf8_tail(byte).map_or(State::Str { bel_terminates }, |remaining| State::StrUtf8 {
                    bel_terminates,
                    remaining,
                })
            }
        },
        State::StrUtf8 {
            bel_terminates,
            remaining,
        } => {
            if (0x80..=0xbf).contains(&b) {
                if remaining == 1 {
                    State::Str { bel_terminates }
                } else {
                    State::StrUtf8 {
                        bel_terminates,
                        remaining: remaining - 1,
                    }
                }
            } else {
                step(State::Str { bel_terminates }, b)
            }
        }
        State::StrEsc { .. } => match b {
            // ESC backslash is ST: the string is over.
            b'\\' | 0x9c => State::Ground,
            // A different escape restarts parsing instead of leaking its
            // parameters into prompt matching as ordinary screen text.
            _ => step(State::Esc, b),
        },
    }
}

fn utf8_tail(byte: u8) -> Option<u8> {
    match byte {
        0xc2..=0xdf => Some(1),
        0xe0..=0xef => Some(2),
        0xf0..=0xf4 => Some(3),
        _ => None,
    }
}

/// Queues injected bytes and decides when they may go out.
#[derive(Debug)]
pub struct Injector {
    pending: VecDeque<u8>,
    holding_since: Option<Instant>,
    interlock: bool,
    /// Times the deadline fired and bytes were released mid-sequence.
    pub forced_releases: u64,
    /// Total bytes injected towards the host.
    pub sent: u64,
}

impl Injector {
    /// `interlock == false` disables the hold entirely (`--no-interlock`).
    pub fn new(interlock: bool) -> Self {
        Self {
            pending: VecDeque::new(),
            holding_since: None,
            interlock,
            forced_releases: 0,
            sent: 0,
        }
    }

    /// Accept bytes from a keyboard or a `--send` string.
    pub fn queue(&mut self, bytes: &[u8]) {
        self.pending.extend(bytes.iter().copied());
    }

    /// Whether anything is waiting.
    pub fn is_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Bytes that may be sent to the host now, given whether the terminal is
    /// mid-reply.  Empty while holding.
    pub fn drain(&mut self, in_flight: bool) -> Vec<u8> {
        self.drain_at(in_flight, Instant::now())
    }

    /// [`Injector::drain`] with the clock supplied, so the deadline is
    /// testable without sleeping.
    pub fn drain_at(&mut self, in_flight: bool, now: Instant) -> Vec<u8> {
        if self.pending.is_empty() {
            self.holding_since = None;
            return Vec::new();
        }
        if self.interlock && in_flight {
            let since = *self.holding_since.get_or_insert(now);
            if now.duration_since(since) < MAX_HOLD {
                return Vec::new();
            }
            // Deadline: the reply is not going to finish. Let the keys out
            // and count it -- a wedged keyboard must not be the quiet option.
            self.forced_releases += 1;
        }
        self.holding_since = None;
        let out: Vec<u8> = self.pending.drain(..).collect();
        self.sent += out.len() as u64;
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn watch_after(bytes: &[u8]) -> SequenceWatch {
        let mut w = SequenceWatch::new();
        w.feed(bytes);
        w
    }

    #[test]
    fn plain_text_is_never_in_flight() {
        assert!(!watch_after(b"hello world\r\n").in_flight());
    }

    #[test]
    fn a_bare_escape_opens_a_sequence() {
        assert!(watch_after(b"\x1b").in_flight());
    }

    #[test]
    fn a_two_byte_escape_closes_immediately() {
        assert!(!watch_after(b"\x1bM").in_flight());
    }

    #[test]
    fn a_csi_is_open_until_its_final_byte() {
        assert!(watch_after(b"\x1b[").in_flight());
        assert!(watch_after(b"\x1b[24").in_flight());
        assert!(watch_after(b"\x1b[24;80").in_flight());
        assert!(!watch_after(b"\x1b[24;80R").in_flight());
    }

    /// Representative VT-510 primary device-attributes reply.
    #[test]
    fn the_real_da_reply_opens_and_closes() {
        let da = b"\x1b[?65;1;2;7;18;21;44;45;46c";
        assert!(!watch_after(da).in_flight());
        // ...and it is open at every point before the final `c`.
        for cut in 1..da.len() {
            assert!(
                watch_after(&da[..cut]).in_flight(),
                "should still be open after {} bytes",
                cut
            );
        }
    }

    #[test]
    fn c1_replies_and_shifted_keys_hold_injection_until_complete() {
        for reply in [
            &b"\x9b24;80R"[..],
            &b"\x90answer\x9c"[..],
            &b"\x9dtitle\x07"[..],
            &b"\x1bOP"[..],
            &b"\x8fP"[..],
            &b"\x1b(B"[..],
        ] {
            for split in 1..reply.len() {
                let mut watch = watch_after(&reply[..split]);
                assert!(watch.in_flight(), "reply={reply:?}, split={split}");
                let mut injector = Injector::new(true);
                injector.queue(b"x");
                assert!(injector.drain(watch.in_flight()).is_empty());
                watch.feed(&reply[split..]);
                assert!(!watch.in_flight(), "{reply:?}");
                assert_eq!(injector.drain(watch.in_flight()), b"x");
            }
        }
    }

    #[test]
    fn a_bell_inside_dcs_does_not_release_keys_before_string_termination() {
        let mut watch = watch_after(b"\x1bPdata\x07more");
        assert!(watch.in_flight());
        watch.feed(b"\x1b\\");
        assert!(!watch.in_flight());
        assert!(!watch_after(b"\x90data\x18").in_flight());
        assert!(!watch_after(b"\x1b(data\x1a").in_flight());
    }

    #[test]
    fn utf8_continuations_that_equal_c1_controls_do_not_open_or_close_sequences() {
        let mut watch = watch_after(b"\xd0");
        assert!(watch.in_flight(), "do not split a UTF-8 code point");
        watch.feed(b"\x9b");
        assert!(!watch.in_flight(), "the second byte is not CSI");
        watch.feed(b"\x1b]title\xd0\x9c");
        assert!(watch.in_flight(), "the second byte is not ST");
        watch.feed(b"\x07");
        assert!(!watch.in_flight());
    }

    #[test]
    fn a_reply_split_across_reads_stays_open_between_them() {
        let mut w = SequenceWatch::new();
        w.feed(b"\x1b[24;8");
        assert!(w.in_flight(), "the chunk boundary must not close it");
        w.feed(b"0R");
        assert!(!w.in_flight());
    }

    #[test]
    fn a_string_sequence_runs_to_st() {
        assert!(watch_after(b"\x1bP1$r").in_flight());
        assert!(watch_after(b"\x1bP1$r0m").in_flight());
        assert!(!watch_after(b"\x1bP1$r0m\x1b\\").in_flight());
    }

    #[test]
    fn an_osc_runs_to_bel() {
        assert!(watch_after(b"\x1b]0;title").in_flight());
        assert!(!watch_after(b"\x1b]0;title\x07").in_flight());
    }

    #[test]
    fn can_and_sub_abort_a_sequence() {
        assert!(!watch_after(b"\x1b[24;\x18").in_flight());
        assert!(!watch_after(b"\x1b[24;\x1a").in_flight());
    }

    #[test]
    fn nothing_queued_means_nothing_to_send() {
        let mut inj = Injector::new(true);
        assert!(inj.drain(false).is_empty());
        assert!(!inj.is_pending());
    }

    #[test]
    fn keys_go_straight_out_when_the_terminal_is_quiet() {
        let mut inj = Injector::new(true);
        inj.queue(b"vttest\r");
        assert_eq!(inj.drain(false), b"vttest\r".to_vec());
        assert_eq!(inj.sent, 7);
        assert!(!inj.is_pending());
    }

    /// The headline: a keystroke must not land inside a reply.
    #[test]
    fn keys_are_held_while_a_reply_is_in_flight() {
        let mut watch = SequenceWatch::new();
        let mut inj = Injector::new(true);

        watch.feed(b"\x1b[24;8"); // half of a cursor-position report
        inj.queue(b"r");
        assert!(
            inj.drain(watch.in_flight()).is_empty(),
            "the keystroke would have split the reply"
        );

        watch.feed(b"0R"); // the reply completes
        assert_eq!(inj.drain(watch.in_flight()), b"r".to_vec());
        assert_eq!(inj.forced_releases, 0);
    }

    #[test]
    fn no_interlock_lets_keys_through_mid_reply() {
        let mut inj = Injector::new(false);
        inj.queue(b"r");
        assert_eq!(inj.drain(true), b"r".to_vec());
    }

    #[test]
    fn a_held_key_is_released_when_the_deadline_expires() {
        let mut inj = Injector::new(true);
        let t0 = Instant::now();
        inj.queue(b"r");

        assert!(inj.drain_at(true, t0).is_empty());
        assert!(inj
            .drain_at(true, t0 + MAX_HOLD - Duration::from_millis(1))
            .is_empty());

        // A terminal that never finishes its sequence must not silence the
        // keyboard for good.
        assert_eq!(inj.drain_at(true, t0 + MAX_HOLD), b"r".to_vec());
        assert_eq!(inj.forced_releases, 1, "a forced release must be counted");
    }

    #[test]
    fn the_hold_clock_restarts_after_a_release() {
        let mut inj = Injector::new(true);
        let t0 = Instant::now();
        inj.queue(b"a");
        assert_eq!(inj.drain_at(false, t0), b"a".to_vec());

        inj.queue(b"b");
        // Held from now, not from t0: the earlier wait must not be inherited.
        assert!(inj.drain_at(true, t0 + MAX_HOLD).is_empty());
        assert_eq!(inj.drain_at(true, t0 + MAX_HOLD + MAX_HOLD), b"b".to_vec());
    }

    #[test]
    fn held_keys_accumulate_in_order() {
        let mut inj = Injector::new(true);
        inj.queue(b"vtt");
        let _ = inj.drain(true);
        inj.queue(b"est\r");
        assert_eq!(inj.drain(false), b"vttest\r".to_vec());
    }
}

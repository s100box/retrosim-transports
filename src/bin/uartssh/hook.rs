// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Howard M. Harte

//! Run a configured shell command after a settled prompt matches and before
//! its answering keys are queued. The hook runs synchronously, pausing the pump
//! so a screenshot can precede the key that changes it. Failures are reported
//! and counted without abandoning the rest of the capture run.

use std::process::Command;

/// A command to run each time a prompt is answered.
#[derive(Debug, Clone)]
pub struct Hook {
    template: String,
    /// Commands that did not start, or exited non-zero.
    pub failures: u64,
    /// Commands that ran and succeeded.
    pub runs: u64,
}

impl Hook {
    /// Build a hook from a command template.
    pub fn new(template: impl Into<String>) -> Self {
        Self {
            template: template.into(),
            failures: 0,
            runs: 0,
        }
    }

    /// Substitute the placeholders for one match.
    ///
    /// `%n` is the match ordinal, padded to at least three digits (lexical
    /// ordering holds through 999). `%p` is the matching pattern inserted as
    /// literal shell text; the template supplies any required shell quoting.
    /// `%%` is a literal percent.
    pub fn render(&self, ordinal: u64, pattern: &str) -> String {
        let mut out = String::with_capacity(self.template.len() + 16);
        let mut chars = self.template.chars().peekable();
        while let Some(c) = chars.next() {
            if c != '%' {
                out.push(c);
                continue;
            }
            match chars.next() {
                Some('n') => out.push_str(&format!("{:03}", ordinal)),
                Some('p') => out.push_str(pattern),
                Some('%') => out.push('%'),
                // An unknown placeholder is left alone rather than eaten: a
                // Windows path full of percent signs should survive being
                // used as a template.
                Some(other) => {
                    out.push('%');
                    out.push(other);
                }
                None => out.push('%'),
            }
        }
        out
    }

    /// Run the command for one match.  Returns an error message to report,
    /// or `None` if it succeeded.
    pub fn fire(&mut self, ordinal: u64, pattern: &str) -> Option<String> {
        let cmd = self.render(ordinal, pattern);
        let result = if cfg!(windows) {
            Command::new("cmd").args(["/C", &cmd]).status()
        } else {
            Command::new("sh").args(["-c", &cmd]).status()
        };
        match result {
            Ok(st) if st.success() => {
                self.runs += 1;
                None
            }
            Ok(st) => {
                self.failures += 1;
                Some(format!("hook exited {}: {}", st, cmd))
            }
            Err(e) => {
                self.failures += 1;
                Some(format!("hook did not start ({}): {}", e, cmd))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ordinal_is_zero_padded_so_a_directory_sorts() {
        let h = Hook::new("grab %n.png");
        assert_eq!(h.render(2, "x"), "grab 002.png");
        assert_eq!(h.render(10, "x"), "grab 010.png");
        // Sorting the rendered names must agree with the numeric order --
        // this is the whole reason for the padding.
        let mut names: Vec<String> = [2u64, 10, 1].iter().map(|n| h.render(*n, "x")).collect();
        names.sort();
        assert_eq!(names, ["grab 001.png", "grab 002.png", "grab 010.png"]);
    }

    #[test]
    fn the_pattern_is_available_to_the_command() {
        let h = Hook::new("echo %p");
        assert_eq!(h.render(1, "Push <RETURN>"), "echo Push <RETURN>");
    }

    #[test]
    fn a_literal_percent_survives() {
        let h = Hook::new("copy %%TEMP%% %n");
        assert_eq!(h.render(3, "x"), "copy %TEMP% 003");
    }

    /// A Windows environment reference must not be silently eaten -- the
    /// command would then run against a path that does not exist and the
    /// failure would look like a grabber fault.
    #[test]
    fn an_unknown_placeholder_is_left_alone() {
        let h = Hook::new("dir %USERPROFILE%");
        assert_eq!(h.render(1, "x"), "dir %USERPROFILE%");
    }

    #[test]
    fn a_trailing_percent_is_not_a_panic() {
        let h = Hook::new("weird %");
        assert_eq!(h.render(1, "x"), "weird %");
    }

    #[test]
    fn a_successful_command_is_counted_and_reports_nothing() {
        let mut h = Hook::new(if cfg!(windows) { "exit 0" } else { "true" });
        assert!(h.fire(1, "p").is_none());
        assert_eq!(h.runs, 1);
        assert_eq!(h.failures, 0);
    }

    /// A grab that failed must be loud. A gap in a numbered sequence found an
    /// hour later reads as a crash, not as one missing frame.
    #[test]
    fn a_failing_command_is_counted_and_named() {
        // `exit 3` means the same thing to cmd.exe and to sh.
        let mut h = Hook::new("exit 3");
        let msg = h.fire(7, "p").expect("a non-zero exit must be reported");
        assert!(msg.contains("hook exited"), "{}", msg);
        assert_eq!(h.failures, 1);
        assert_eq!(h.runs, 0);
    }
}

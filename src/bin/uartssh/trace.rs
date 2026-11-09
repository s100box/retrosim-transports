// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Howard M. Harte

//! Annotated hex logs and raw source-byte captures for each direction.
//!
//! The pump records bytes before forwarding them. A failed run can therefore
//! contain a source suffix that the destination did not accept; captures are
//! not delivery acknowledgments. Notes stay in the readable log, never in raw
//! captures. Every record is flushed for inspection during a running session.

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::pump::Dir;

/// Bytes per line in the hex dump.
const COLS: usize = 16;

/// Open log and capture sinks, and time-stamp everything against one origin.
pub struct Trace {
    log: Option<BufWriter<File>>,
    h2t: Option<BufWriter<File>>,
    t2h: Option<BufWriter<File>>,
    /// Injected keystrokes, opened on first use.
    ///
    /// Lazily, because most runs inject nothing and a zero-length
    /// `<prefix>.k2h.bin` sitting next to two files with content invites the
    /// reading "the keyboard was dead", which is a different fact from "no
    /// keyboard was used". The file exists exactly when something was typed.
    k2h: Option<BufWriter<File>>,
    capture_prefix: Option<PathBuf>,
    start: Instant,
}

impl Trace {
    /// Create the requested sinks.  `capture` is a prefix: `<prefix>.h2t.bin`
    /// receives everything sent to the terminal, `<prefix>.t2h.bin`
    /// everything the terminal sent back.
    pub fn new(log: Option<&Path>, capture: Option<&Path>) -> io::Result<Self> {
        validate_outputs(log, capture, None)?;
        let log = match log {
            Some(p) => Some(BufWriter::new(File::create(p)?)),
            None => None,
        };
        let capture_prefix = capture.map(Path::to_path_buf);
        // A reused prefix must not retain another run's injected keystrokes.
        if let Some(base) = &capture_prefix {
            match std::fs::remove_file(capture_path(base, ".k2h.bin")) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        let (h2t, t2h) = match &capture_prefix {
            Some(base) => (
                Some(BufWriter::new(File::create(capture_path(
                    base, ".h2t.bin",
                ))?)),
                Some(BufWriter::new(File::create(capture_path(
                    base, ".t2h.bin",
                ))?)),
            ),
            None => (None, None),
        };
        Ok(Self {
            log,
            h2t,
            t2h,
            k2h: None,
            capture_prefix,
            start: Instant::now(),
        })
    }

    /// A trace with no sinks: `record` becomes a cheap no-op.
    pub fn disabled() -> Self {
        Self {
            log: None,
            h2t: None,
            t2h: None,
            k2h: None,
            capture_prefix: None,
            start: Instant::now(),
        }
    }

    /// Whether anything is being written at all.
    pub fn is_active(&self) -> bool {
        self.log.is_some() || self.h2t.is_some() || self.t2h.is_some()
    }

    /// Record one chunk.  Empty chunks are ignored so an idle link does not
    /// fill the log with zero-length entries.
    pub fn record(&mut self, dir: Dir, bytes: &[u8]) -> io::Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        if let Some(log) = self.log.as_mut() {
            let mut s = String::new();
            format_chunk(&mut s, self.start.elapsed(), dir, bytes);
            log.write_all(s.as_bytes())?;
            log.flush()?;
        }
        let raw = match dir {
            Dir::HostToTerm => self.h2t.as_mut(),
            Dir::TermToHost => self.t2h.as_mut(),
            Dir::KeyToHost => {
                if self.k2h.is_none() {
                    if let Some(base) = &self.capture_prefix {
                        self.k2h = Some(BufWriter::new(File::create(capture_path(
                            base, ".k2h.bin",
                        ))?));
                    }
                }
                self.k2h.as_mut()
            }
        };
        if let Some(f) = raw {
            f.write_all(bytes)?;
            f.flush()?;
        }
        Ok(())
    }

    /// Record a note about the session in the readable log.
    ///
    /// The log only, never the raw captures. Those files are evidence
    /// precisely because they contain the wire and nothing else: a comment
    /// spliced into `<prefix>.h2t.bin` would be replayed into a simulator as
    /// if the host had sent it, and every later reading of that file would be
    /// wrong. A note explains a byte; it is not one.
    pub fn note(&mut self, text: &str) -> io::Result<()> {
        if let Some(log) = self.log.as_mut() {
            writeln!(
                log,
                "{:>10.3}  ---  {}",
                self.start.elapsed().as_secs_f64(),
                text
            )?;
            log.flush()?;
        }
        Ok(())
    }

    /// Flush every sink.
    pub fn flush(&mut self) -> io::Result<()> {
        for w in [
            self.log.as_mut(),
            self.h2t.as_mut(),
            self.t2h.as_mut(),
            self.k2h.as_mut(),
        ]
        .into_iter()
        .flatten()
        {
            w.flush()?;
        }
        Ok(())
    }
}

fn capture_path(prefix: &Path, suffix: &str) -> PathBuf {
    let mut path = prefix.as_os_str().to_os_string();
    path.push(suffix);
    path.into()
}

/// Reject paths that resolve to the same name before any output is truncated.
/// Callers must also avoid distinct hard links to the same existing file.
pub fn validate_outputs(
    log: Option<&Path>,
    capture: Option<&Path>,
    manifest: Option<&Path>,
) -> io::Result<()> {
    let mut paths: Vec<PathBuf> = log
        .into_iter()
        .chain(manifest)
        .map(Path::to_path_buf)
        .collect();
    if let Some(base) = capture {
        paths.extend([".h2t.bin", ".t2h.bin", ".k2h.bin"].map(|suffix| capture_path(base, suffix)));
    }
    let mut resolved = std::collections::HashSet::new();
    for path in paths {
        let canonical = if path.exists() {
            path.canonicalize()?
        } else {
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            parent.canonicalize()?.join(path.file_name().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "output path needs a file name")
            })?)
        };
        // Windows file names normally ignore ASCII case, including outputs
        // that do not exist yet and therefore cannot be canonicalized.
        #[cfg(windows)]
        let canonical = {
            use std::os::windows::ffi::{OsStrExt, OsStringExt};
            let units: Vec<u16> = canonical
                .as_os_str()
                .encode_wide()
                .map(|u| if (65..=90).contains(&u) { u + 32 } else { u })
                .collect();
            PathBuf::from(std::ffi::OsString::from_wide(&units))
        };
        if !resolved.insert(canonical) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("output paths overlap at {}", path.display()),
            ));
        }
    }
    Ok(())
}

/// Render one chunk as timestamped hex lines, appending to `out`.
///
/// Every line carries its own timestamp and direction tag so that a `grep`
/// for one direction still yields readable output -- a continuation line that
/// inherits its heading from a line the filter removed is worse than
/// redundant, it is misattributed.
pub fn format_chunk(out: &mut String, elapsed: Duration, dir: Dir, bytes: &[u8]) {
    use std::fmt::Write as _;

    let secs = elapsed.as_secs_f64();
    for row in bytes.chunks(COLS) {
        let _ = write!(out, "{:9.3} {} ", secs, dir.tag());
        for (i, b) in row.iter().enumerate() {
            // A gap after 8 bytes: the eye counts to eight far better than
            // to sixteen when locating a byte by column.
            let _ = write!(out, "{}{:02x} ", if i == 8 { " " } else { "" }, b);
        }
        // Pad so the ASCII gutter lines up on short final rows.
        for i in row.len()..COLS {
            let _ = write!(out, "{}   ", if i == 8 { " " } else { "" });
        }
        out.push('|');
        for &b in row {
            out.push(if (0x20..0x7f).contains(&b) {
                b as char
            } else {
                '.'
            });
        }
        for _ in row.len()..COLS {
            out.push(' ');
        }
        out.push('|');
        if let Some(note) = flow_note(dir, row) {
            let _ = write!(out, "  <-- {}", note);
        }
        out.push('\n');
    }
}

/// Name XON/XOFF when the *terminal* sends them.
///
/// Only that direction: 0x11 and 0x13 in a screen paint are ordinary data
/// (for example inside binary display payloads), and flagging those would bury the occurrences that
/// actually mean "stop sending" in noise.
fn flow_note(dir: Dir, row: &[u8]) -> Option<&'static str> {
    if dir != Dir::TermToHost {
        return None;
    }
    // Last one in the row wins: it is the state the terminal ends up in.
    row.iter().rev().find_map(|&b| match b {
        0x13 => Some("XOFF from terminal"),
        0x11 => Some("XON from terminal"),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlapping_sinks_are_rejected_before_truncation_or_stale_file_removal() {
        let dir = std::env::temp_dir().join(format!("uartssh-overlap-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        let prefix = dir.join("run");
        let h2t = capture_path(&prefix, ".h2t.bin");
        let k2h = capture_path(&prefix, ".k2h.bin");
        std::fs::write(&h2t, b"evidence").unwrap();
        std::fs::write(&k2h, b"keys").unwrap();
        assert!(Trace::new(Some(&h2t), Some(&prefix)).is_err());
        assert_eq!(std::fs::read(&h2t).unwrap(), b"evidence");
        assert_eq!(std::fs::read(&k2h).unwrap(), b"keys");
        let alias = dir.join("sub").join("..").join("run.h2t.bin");
        assert!(validate_outputs(Some(&alias), None, Some(&h2t)).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_reused_prefix_cannot_claim_keystrokes_from_an_earlier_run() {
        let dir = std::env::temp_dir().join(format!("uartssh-reused-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let prefix = dir.join("capture");
        let mut first = Trace::new(None, Some(&prefix)).unwrap();
        first.record(Dir::KeyToHost, b"old").unwrap();
        drop(first);
        assert!(capture_path(&prefix, ".k2h.bin").exists());
        let second = Trace::new(None, Some(&prefix)).unwrap();
        assert!(!capture_path(&prefix, ".k2h.bin").exists());
        drop(second);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn suffixes_preserve_native_path_encoding() {
        #[cfg(windows)]
        let native = {
            use std::os::windows::ffi::OsStringExt;
            std::ffi::OsString::from_wide(&[b'x' as u16, 0xd800])
        };
        #[cfg(unix)]
        let native = {
            use std::os::unix::ffi::OsStringExt;
            std::ffi::OsString::from_vec(vec![b'x', 0xff])
        };
        let mut expected = native.clone();
        expected.push(".h2t.bin");
        assert_eq!(
            capture_path(Path::new(&native), ".h2t.bin"),
            PathBuf::from(expected)
        );
    }

    fn fmt(dir: Dir, bytes: &[u8]) -> String {
        let mut s = String::new();
        format_chunk(&mut s, Duration::from_millis(12345), dir, bytes);
        s
    }

    #[test]
    fn empty_chunk_produces_no_lines() {
        assert_eq!(fmt(Dir::HostToTerm, b""), "");
    }

    #[test]
    fn a_full_row_is_one_line() {
        let s = fmt(Dir::HostToTerm, &[0u8; 16]);
        assert_eq!(s.lines().count(), 1);
    }

    #[test]
    fn seventeen_bytes_wrap_to_two_lines() {
        let s = fmt(Dir::HostToTerm, &[0u8; 17]);
        assert_eq!(s.lines().count(), 2);
    }

    #[test]
    fn every_line_carries_its_own_timestamp_and_direction() {
        // So that `grep 'T>H'` yields lines that mean what they say.
        let s = fmt(Dir::TermToHost, &[0x41u8; 40]);
        assert_eq!(s.lines().count(), 3);
        for line in s.lines() {
            assert!(line.contains("T>H"), "line lost its direction: {}", line);
            assert!(line.contains("12.345"), "line lost its timestamp: {}", line);
        }
    }

    #[test]
    fn hex_and_gutter_agree_with_the_bytes() {
        let s = fmt(Dir::HostToTerm, b"\x1b[2J");
        assert!(s.contains("1b 5b 32 4a"), "{}", s);
        assert!(s.contains("|.[2J"), "{}", s);
    }

    #[test]
    fn control_and_high_bytes_render_as_dots() {
        let s = fmt(Dir::HostToTerm, &[0x00, 0x1f, 0x7f, 0x80, 0xff]);
        let gutter = s.split('|').nth(1).unwrap();
        assert!(
            gutter.starts_with("....."),
            "non-printables must not reach the gutter: {:?}",
            gutter
        );
    }

    #[test]
    fn printable_boundaries_are_space_through_tilde() {
        let s = fmt(Dir::HostToTerm, &[0x1f, 0x20, 0x7e, 0x7f]);
        let gutter = s.split('|').nth(1).unwrap();
        assert_eq!(&gutter[..4], ". ~.");
    }

    #[test]
    fn short_rows_keep_the_gutter_aligned() {
        // A ragged final row makes a long trace much harder to scan.
        let full = fmt(Dir::HostToTerm, &[0x41u8; 16]);
        let short = fmt(Dir::HostToTerm, b"hi");
        let col = |s: &str| s.find('|').unwrap();
        assert_eq!(col(&full), col(&short));
        assert_eq!(
            full.lines().next().unwrap().len(),
            short.lines().next().unwrap().len()
        );
    }

    #[test]
    fn xoff_from_the_terminal_is_called_out() {
        let s = fmt(Dir::TermToHost, &[0x13]);
        assert!(s.contains("XOFF from terminal"), "{}", s);
    }

    #[test]
    fn xon_from_the_terminal_is_called_out() {
        let s = fmt(Dir::TermToHost, &[0x11]);
        assert!(s.contains("XON from terminal"), "{}", s);
    }

    #[test]
    fn the_same_bytes_going_the_other_way_are_not_flagged() {
        // 0x11/0x13 in a screen paint are ordinary data; flagging them would
        // bury the real ones.
        let s = fmt(Dir::HostToTerm, &[0x13, 0x11]);
        assert!(!s.contains("XOFF"), "{}", s);
        assert!(!s.contains("XON"), "{}", s);
    }

    #[test]
    fn the_last_flow_byte_in_a_row_wins() {
        // XOFF then XON leaves the terminal willing to receive.
        let s = fmt(Dir::TermToHost, &[0x13, b'x', 0x11]);
        assert!(s.contains("XON from terminal"), "{}", s);
        assert!(!s.contains("XOFF"), "{}", s);
    }

    #[test]
    fn disabled_trace_is_inert() {
        let mut t = Trace::disabled();
        assert!(!t.is_active());
        t.record(Dir::HostToTerm, b"nothing happens").unwrap();
        t.flush().unwrap();
    }

    #[test]
    fn capture_files_hold_raw_bytes_split_by_direction() {
        let dir = std::env::temp_dir().join(format!(
            "uartssh-trace-test-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let prefix = dir.join("run");
        let logfile = dir.join("log.txt");

        let mut t = Trace::new(Some(&logfile), Some(&prefix)).unwrap();
        assert!(t.is_active());
        // Bytes chosen to be illegal UTF-8 and to include a NUL: the capture
        // must be a byte channel, not a text one.
        t.record(Dir::HostToTerm, &[0x00, 0xff, 0x1b, 0xfe])
            .unwrap();
        t.record(Dir::TermToHost, b"abc").unwrap();
        t.flush().unwrap();
        drop(t);

        let h2t = std::fs::read(dir.join("run.h2t.bin")).unwrap();
        let t2h = std::fs::read(dir.join("run.t2h.bin")).unwrap();
        assert_eq!(h2t, vec![0x00, 0xff, 0x1b, 0xfe]);
        assert_eq!(t2h, b"abc");

        let log = std::fs::read_to_string(&logfile).unwrap();
        assert!(log.contains("H>T"), "{}", log);
        assert!(log.contains("T>H"), "{}", log);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_log_is_readable_before_the_process_ends() {
        // Ctrl-C is the normal way to stop the bridge; a buffered log would
        // lose exactly the seconds worth keeping.
        let dir = std::env::temp_dir().join(format!(
            "uartssh-flush-test-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let logfile = dir.join("log.txt");

        let mut t = Trace::new(Some(&logfile), None).unwrap();
        t.record(Dir::HostToTerm, b"written and readable").unwrap();
        // No flush(), no drop: read it from underneath the live writer.
        let log = std::fs::read_to_string(&logfile).unwrap();
        assert!(
            log.contains("77 72 69 74"),
            "log was still buffered: {:?}",
            log
        );

        drop(t);
        std::fs::remove_dir_all(&dir).ok();
    }
}

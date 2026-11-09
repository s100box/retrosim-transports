// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Howard M. Harte

//! JSON Lines index of matched prompts and their host-to-terminal offsets.
//!
//! The offset is sampled before answering keys are injected, allowing a replay
//! of the source capture up to the matched screen. Each record is flushed so
//! completed records remain readable after an interrupted run. `keys` is a
//! readable UTF-8 view; `keys_hex` preserves every original key byte.

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;

/// Writes one JSON object per answered prompt.
pub struct Manifest {
    out: BufWriter<File>,
}

impl Manifest {
    /// Create the file, truncating any previous run's.
    pub fn create(path: &Path) -> io::Result<Self> {
        Ok(Self {
            out: BufWriter::new(File::create(path)?),
        })
    }

    /// Record one answered prompt.
    ///
    /// Flushed immediately: the point of the file is to be readable while the
    /// run is still going, and after one that did not finish.
    pub fn record(
        &mut self,
        ordinal: u64,
        pattern: &str,
        keys: &[u8],
        h2t_offset: u64,
        elapsed_s: f64,
    ) -> io::Result<()> {
        if !elapsed_s.is_finite() || elapsed_s < 0.0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "elapsed time must be finite and nonnegative",
            ));
        }
        // Keep `keys` readable for existing consumers; `keys_hex` preserves
        // binary input that cannot be represented by a UTF-8 string.
        let keys_hex: String = keys.iter().map(|b| format!("{b:02x}")).collect();
        writeln!(
            self.out,
            "{{\"n\":{},\"pattern\":{},\"keys\":{},\"keys_hex\":{},\"h2t_offset\":{},\"t\":{:.3}}}",
            ordinal,
            json_string(pattern),
            json_string(&String::from_utf8_lossy(keys)),
            json_string(&keys_hex),
            h2t_offset,
            elapsed_s
        )?;
        self.out.flush()
    }
}

/// Render a JSON string literal, quotes included.
///
/// Hand-written rather than pulled from a dependency: the crate has no JSON
/// dependency and this is the only place one would be needed. The escaping
/// that matters here is not the obvious `"` and `\` -- it is the control
/// characters, because the keys field is *mostly* control characters. A raw
/// carriage return inside a JSON string is a parse error, so the field that
/// this file exists to record is exactly the field that would break it.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\u{:04x}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_text_is_quoted_and_otherwise_untouched() {
        assert_eq!(json_string("Push <RETURN>"), "\"Push <RETURN>\"");
    }

    /// The whole point of the file is to record keystrokes, and keystrokes are
    /// control bytes. A raw CR inside a JSON string is a parse error.
    #[test]
    fn a_carriage_return_does_not_break_the_line() {
        assert_eq!(json_string("\r"), "\"\\r\"");
        assert_eq!(json_string("6\r"), "\"6\\r\"");
    }

    #[test]
    fn escape_and_other_controls_become_unicode_escapes() {
        assert_eq!(json_string("\x1b[A"), "\"\\u001b[A\"");
        assert_eq!(json_string("\x03"), "\"\\u0003\"");
        assert_eq!(json_string("\x7f"), "\"\\u007f\"");
    }

    #[test]
    fn quotes_and_backslashes_are_escaped() {
        assert_eq!(json_string("a\"b\\c"), "\"a\\\"b\\\\c\"");
    }

    /// Round-trip through a real parser, because a hand-written escaper that
    /// only agrees with its own tests has proved nothing.
    #[test]
    fn every_byte_value_survives_a_real_json_parser() {
        let path = std::env::temp_dir().join(format!(
            "uartssh_manifest_roundtrip-{}.jsonl",
            std::process::id()
        ));
        let mut m = Manifest::create(&path).unwrap();
        // Every control byte, the ASCII range, and the characters that need
        // escaping -- as both the pattern and the keys.
        let hairy: String = (0u8..=0x7f).map(|b| b as char).collect();
        let keys: Vec<u8> = (0..=255).collect();
        for elapsed in [f64::NAN, f64::INFINITY, -1.0] {
            assert_eq!(
                m.record(0, "invalid", &[], 0, elapsed).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
        m.record(1, &hairy, &keys, 4096, 1.5).unwrap();
        drop(m);

        let line = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        let v: serde_json::Value = serde_json::from_str(line.trim()).expect("must parse");
        assert_eq!(v["n"], 1);
        assert_eq!(v["pattern"], hairy);
        let hex = v["keys_hex"].as_str().unwrap();
        let decoded: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        assert_eq!(decoded, keys);
        assert_eq!(v["h2t_offset"], 4096);
    }

    #[test]
    fn each_record_is_its_own_line_so_a_killed_run_still_parses() {
        let path = std::env::temp_dir().join(format!(
            "uartssh_manifest_lines-{}.jsonl",
            std::process::id()
        ));
        let mut m = Manifest::create(&path).unwrap();
        m.record(1, "Push <RETURN>", b"\r", 100, 0.5).unwrap();
        m.record(2, "Enter choice number", b"6\r", 200, 1.0)
            .unwrap();
        drop(m);

        let text = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        for l in lines {
            serde_json::from_str::<serde_json::Value>(l).expect("each line stands alone");
        }
    }
}

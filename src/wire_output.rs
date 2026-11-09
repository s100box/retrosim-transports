// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Howard M. Harte
//! Bounded encoded output that survives short writes and temporary backpressure.

use std::collections::VecDeque;
use std::io::{self, Write};

/// Holds bytes already accepted from a caller, in their exact wire order.
/// Remove a prefix only after the underlying writer confirms it was written.
pub(crate) struct WireOutput {
    bytes: VecDeque<u8>,
    limit: usize,
}

impl WireOutput {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            bytes: VecDeque::new(),
            limit,
        }
    }

    /// Append the raw prefix that fits; the return value counts wire bytes.
    pub(crate) fn push_raw(&mut self, bytes: &[u8]) -> usize {
        let count = bytes.len().min(self.limit - self.bytes.len());
        self.bytes.extend(&bytes[..count]);
        count
    }

    /// Accept a prefix of Telnet data, doubling IAC. The return value counts
    /// caller bytes, and an escaped byte is accepted only if both halves fit.
    pub(crate) fn push_data(&mut self, bytes: &[u8]) -> usize {
        let mut accepted = 0;
        for &byte in bytes {
            let needed = if byte == 255 { 2 } else { 1 };
            if self.limit - self.bytes.len() < needed {
                break;
            }
            self.bytes.push_back(byte);
            if byte == 255 {
                self.bytes.push_back(byte);
            }
            accepted += 1;
        }
        accepted
    }

    /// Try to drain accepted output. On WouldBlock or another error, retain
    /// every unwritten byte, including the second half of an escaped IAC.
    pub(crate) fn flush<W: Write + ?Sized>(&mut self, writer: &mut W) -> io::Result<()> {
        // Bound work even when a writer makes one-byte progress repeatedly.
        // Callers with deadlines must get control back between attempts.
        for _ in 0..16 {
            if self.is_empty() {
                return Ok(());
            }
            let (front, _) = self.bytes.as_slices();
            match writer.write(front) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(count) => {
                    self.bytes.drain(..count);
                }
                Err(error) => return Err(error),
            }
        }
        if self.is_empty() {
            Ok(())
        } else {
            Err(io::ErrorKind::WouldBlock.into())
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Abandon output when its connection ends; protocol bytes cannot be
    /// continued on a different peer's connection.
    pub(crate) fn clear(&mut self) {
        self.bytes.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Writer {
        steps: VecDeque<io::Result<usize>>,
        bytes: Vec<u8>,
    }
    impl Write for Writer {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let count = self
                .steps
                .pop_front()
                .unwrap_or(Ok(bytes.len()))?
                .min(bytes.len());
            self.bytes.extend_from_slice(&bytes[..count]);
            Ok(count)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_split_iac_survives_backpressure_without_repeating_its_prefix() {
        let mut output = WireOutput::new(8);
        assert_eq!(output.push_data(&[b'A', 255, b'B']), 3);
        let mut writer = Writer {
            steps: [Ok(2), Err(io::ErrorKind::WouldBlock.into())].into(),
            bytes: Vec::new(),
        };
        assert_eq!(
            output.flush(&mut writer).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(writer.bytes, [b'A', 255]);
        output.flush(&mut writer).unwrap();
        assert_eq!(writer.bytes, [b'A', 255, 255, b'B']);
        assert!(output.is_empty());
    }

    #[test]
    fn capacity_counts_encoded_bytes_and_preserves_control_data_order() {
        let mut output = WireOutput::new(4);
        assert_eq!(output.push_raw(&[255, 251]), 2);
        assert_eq!(output.push_data(&[255, b'X']), 1);
        assert_eq!(output.push_data(b"X"), 0);
        let mut writer = Vec::new();
        output.flush(&mut writer).unwrap();
        assert_eq!(writer, [255, 251, 255, 255]);
        assert_eq!(output.push_data(b"X"), 1);
        output.flush(&mut writer).unwrap();
        assert_eq!(writer, [255, 251, 255, 255, b'X']);
    }

    #[test]
    fn zero_and_interrupted_writes_preserve_output_for_retry() {
        let mut output = WireOutput::new(4);
        output.push_raw(b"abc");
        let mut writer = Writer {
            steps: [Ok(0), Err(io::ErrorKind::Interrupted.into()), Ok(1)].into(),
            bytes: Vec::new(),
        };
        assert_eq!(
            output.flush(&mut writer).unwrap_err().kind(),
            io::ErrorKind::WriteZero
        );
        assert_eq!(
            output.flush(&mut writer).unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
        output.flush(&mut writer).unwrap();
        assert_eq!(writer.bytes, b"abc");
        output.push_raw(b"old");
        output.clear();
        assert!(output.is_empty());
    }

    #[test]
    fn a_slow_writer_yields_so_the_caller_can_enforce_a_deadline() {
        let mut output = WireOutput::new(64);
        output.push_raw(&[42; 33]);
        let mut writer = Writer {
            steps: (0..33).map(|_| Ok(1)).collect(),
            bytes: Vec::new(),
        };
        assert_eq!(
            output.flush(&mut writer).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(writer.bytes.len(), 16);
        assert_eq!(
            output.flush(&mut writer).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        output.flush(&mut writer).unwrap();
        assert_eq!(writer.bytes, [42; 33]);
    }
}

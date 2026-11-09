//! Null transport: discards all output, never produces input.

use std::io::{self, Read, Write};
use std::time::Duration;

use retrosim_core::transport::Transport;

/// A transport that discards all output and never produces input.
///
/// Useful for ports that exist in hardware but aren't connected to anything.
pub struct NullTransport;

impl NullTransport {
    /// Create a new null transport.
    pub fn new() -> Self {
        Self
    }
}

impl Default for NullTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Read for NullTransport {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::WouldBlock, "null transport"))
    }
}

impl Write for NullTransport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len()) // discard
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Transport for NullTransport {
    fn set_read_timeout(&mut self, _timeout: Option<Duration>) -> io::Result<()> {
        Ok(())
    }

    fn description(&self) -> &str {
        "null"
    }

    fn is_connected(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_discards_writes() {
        let mut t = NullTransport::new();
        assert_eq!(t.write(b"hello").unwrap(), 5);
    }

    #[test]
    fn null_read_returns_would_block() {
        let mut t = NullTransport::new();
        let mut buf = [0u8; 1];
        let err = t.read(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn null_is_not_connected() {
        let t = NullTransport::new();
        assert!(!t.is_connected());
    }

    #[test]
    fn null_description() {
        let t = NullTransport::new();
        assert_eq!(t.description(), "null");
    }
}

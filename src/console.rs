//! Console transport: marker for local terminal I/O.
//!
//! This transport signals that a port is connected to the local terminal.
//! No background thread is needed — the run loop handles it directly via
//! crossterm events (input) and stdout (output).

use std::io::{self, Read, Write};
use std::time::Duration;

use retrosim_core::transport::Transport;

/// Marker transport for local terminal I/O.
///
/// The console transport doesn't actually carry bytes — it tells the
/// transport manager that this port should be driven by the local
/// terminal's event loop.
pub struct ConsoleTransport {
    desc: String,
}

impl ConsoleTransport {
    /// Create a new console transport.
    pub fn new() -> Self {
        Self {
            desc: "console (local terminal)".to_string(),
        }
    }
}

impl Default for ConsoleTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Read for ConsoleTransport {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "console transport: use crossterm",
        ))
    }
}

impl Write for ConsoleTransport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Transport for ConsoleTransport {
    fn set_read_timeout(&mut self, _timeout: Option<Duration>) -> io::Result<()> {
        Ok(())
    }

    fn description(&self) -> &str {
        &self.desc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn console_description() {
        let t = ConsoleTransport::new();
        assert!(t.description().contains("console"));
    }

    #[test]
    fn console_is_connected_by_default() {
        let t = ConsoleTransport::new();
        assert!(t.is_connected());
    }
}

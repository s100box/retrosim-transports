// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Howard M. Harte
//! UDP transport: an unreliable byte view over datagrams, with buffering.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use retrosim_core::transport::{Transport, TransportError};

/// UDP datagram transport with byte-level buffering.
///
/// Buffers partial datagrams across `read()` calls so callers see a
/// byte stream interface despite the underlying datagram protocol.
pub struct UdpTransport {
    socket: UdpSocket,
    desc: String,
    /// Peer address (learned from first datagram in server mode).
    peer: Option<SocketAddr>,
    /// Buffered bytes from partially-consumed datagrams.
    pending: VecDeque<u8>,
}

impl UdpTransport {
    /// Bind an ephemeral local port and select the destination for writes.
    ///
    /// The socket is unconnected: reads can receive datagrams from any sender.
    pub fn connect(addr: &str) -> Result<Self, TransportError> {
        let peer = resolve_addr(addr)?;
        let local = if peer.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(local)
            .map_err(|e| TransportError::Transport(format!("udp bind: {}", e)))?;
        Ok(Self {
            desc: format!("udp:{}", peer),
            socket,
            peer: Some(peer),
            pending: VecDeque::new(),
        })
    }

    /// Create a UDP server: bind to local address, learn peer from first datagram.
    pub fn bind(bind_addr: &str) -> Result<Self, TransportError> {
        let local = resolve_addr(bind_addr)?;
        let socket = UdpSocket::bind(local)
            .map_err(|e| TransportError::Transport(format!("udp bind {}: {}", bind_addr, e)))?;
        let actual = socket
            .local_addr()
            .map_or_else(|_| bind_addr.to_string(), |a| a.to_string());
        Ok(Self {
            desc: format!("udp-server:{}", actual),
            socket,
            peer: None,
            pending: VecDeque::new(),
        })
    }
}

impl Read for UdpTransport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Read's empty-buffer contract must not consume or wait for a datagram.
        if buf.is_empty() {
            return Ok(0);
        }
        // First drain any pending bytes from a previous datagram
        if !self.pending.is_empty() {
            let n = buf.len().min(self.pending.len());
            for slot in &mut buf[..n] {
                *slot = self.pending.pop_front().unwrap();
            }
            return Ok(n);
        }

        // Receive a new datagram
        let mut dgram = [0u8; 4096];
        let (n, from) = self.socket.recv_from(&mut dgram)?;

        // Learn peer on first datagram (server mode)
        if self.peer.is_none() {
            self.peer = Some(from);
            self.desc = format!("udp-server:{} (peer {})", self.socket.local_addr()?, from);
        }

        // Copy what fits into buf, buffer the rest
        let copy_n = buf.len().min(n);
        buf[..copy_n].copy_from_slice(&dgram[..copy_n]);
        if copy_n < n {
            self.pending.extend(&dgram[copy_n..n]);
        }
        Ok(copy_n)
    }
}

impl Write for UdpTransport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(peer) = self.peer {
            self.socket.send_to(buf, peer)
        } else {
            // No peer yet — discard
            Ok(buf.len())
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(()) // UDP is datagram-based, no buffering to flush
    }
}

impl Transport for UdpTransport {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        // A zero socket timeout is invalid; the Transport contract uses it
        // for polling. Restore blocking mode when a later timeout requests it.
        if timeout == Some(Duration::ZERO) {
            self.socket.set_nonblocking(true)
        } else {
            self.socket.set_nonblocking(false)?;
            self.socket.set_read_timeout(timeout)
        }
    }

    fn description(&self) -> &str {
        &self.desc
    }
}

/// Resolve an address string, accepting bare port numbers.
fn resolve_addr(addr: &str) -> Result<SocketAddr, TransportError> {
    use std::net::ToSocketAddrs;

    if let Ok(port) = addr.parse::<u16>() {
        return Ok(SocketAddr::from(([0, 0, 0, 0], port)));
    }
    addr.to_socket_addrs()
        .map_err(|e| TransportError::InvalidSpec(format!("cannot resolve '{}': {}", addr, e)))?
        .next()
        .ok_or_else(|| TransportError::InvalidSpec(format!("no addresses for '{}'", addr)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_clients_bind_the_matching_address_family() {
        let socket = match UdpSocket::bind("[::1]:0") {
            Ok(socket) => socket,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::AddrNotAvailable | io::ErrorKind::Unsupported
                ) =>
            {
                return
            }
            Err(e) => panic!("IPv6 fixture bind: {e}"),
        };
        socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut client = UdpTransport::connect(&socket.local_addr().unwrap().to_string()).unwrap();
        client.write_all(b"ipv6").unwrap();
        let mut data = [0; 4];
        assert_eq!(socket.recv(&mut data).unwrap(), 4);
        assert_eq!(&data, b"ipv6");
        assert!(client.socket.local_addr().unwrap().is_ipv6());
    }

    #[test]
    fn udp_zero_timeout_and_empty_reads() {
        let mut server = UdpTransport::bind("127.0.0.1:0").unwrap();
        server.set_read_timeout(Some(Duration::ZERO)).unwrap();
        assert_eq!(server.read(&mut []).unwrap(), 0);
        assert_eq!(
            server.read(&mut [0u8; 1]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        server
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        assert!(server.socket.read_timeout().unwrap().is_some());
        let mut peer =
            UdpTransport::connect(&server.socket.local_addr().unwrap().to_string()).unwrap();
        peer.write_all(b"still readable").unwrap();
        let mut data = [0u8; 32];
        let n = server.read(&mut data).unwrap();
        assert_eq!(&data[..n], b"still readable");
        server.set_read_timeout(None).unwrap();
        assert_eq!(server.socket.read_timeout().unwrap(), None);
    }

    #[test]
    fn udp_loopback() {
        let server = UdpTransport::bind("127.0.0.1:0").unwrap();
        let server_addr = server.socket.local_addr().unwrap();

        let mut client = UdpTransport::connect(&server_addr.to_string()).unwrap();
        let mut server = server;

        client.write_all(b"hello").unwrap();

        server
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut buf = [0u8; 10];
        let n = server.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello");

        assert!(server.peer.is_some());

        server.write_all(b"world").unwrap();

        client
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let n = client.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"world");
    }

    #[test]
    fn udp_buffering() {
        let server = UdpTransport::bind("127.0.0.1:0").unwrap();
        let server_addr = server.socket.local_addr().unwrap();
        let mut client = UdpTransport::connect(&server_addr.to_string()).unwrap();
        let mut server = server;

        client.write_all(b"abcdef").unwrap();

        server
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();

        let mut buf = [0u8; 3];
        let n = server.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"abc");

        let n = server.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"def");
    }

    #[test]
    fn udp_description() {
        let t = UdpTransport::bind("127.0.0.1:0").unwrap();
        assert!(t.description().starts_with("udp-server:"));
    }
}

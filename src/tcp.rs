//! TCP transport: raw TCP byte stream (no telnet negotiation).

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::time::Duration;

use retrosim_core::transport::{ModemControl, Transport, TransportError};

use crate::flow_control::FlowControlGate;

/// Raw TCP byte stream transport.
///
/// Supports both client (connect) and server (listen/accept) modes.
pub struct TcpTransport {
    stream: TcpStream,
    desc: String,
    /// Software (XON/XOFF) + hardware (RTS/CTS) flow-control gate —
    /// see `flow_control.rs`.  TCP can't carry RTS/CTS natively, so
    /// the gate translates the firmware's flow-control intent into
    /// "stop reading the socket" and leans on TCP's own receive
    /// window to backpressure the remote.
    flow: FlowControlGate,
}

impl TcpTransport {
    /// Connect to a remote TCP address (client mode).
    pub fn connect(addr: &str) -> Result<Self, TransportError> {
        let resolved = resolve_addresses(addr)?;
        let stream = TcpStream::connect(resolved.as_slice())
            .map_err(|e| TransportError::Transport(format!("tcp connect to {}: {}", addr, e)))?;
        let peer = stream
            .peer_addr()
            .map_or_else(|_| addr.to_string(), |a| a.to_string());
        Ok(Self {
            stream,
            desc: format!("tcp:{}", peer),
            flow: FlowControlGate::new(),
        })
    }

    /// Listen on a local address and accept one connection (server mode).
    ///
    /// This blocks until a client connects.
    pub fn accept(bind_addr: &str) -> Result<Self, TransportError> {
        let resolved = resolve_addr(bind_addr)?;
        let listener = bind_listener_reuse(resolved)
            .map_err(|e| TransportError::Transport(format!("tcp bind {}: {}", bind_addr, e)))?;
        let local = listener
            .local_addr()
            .map_or_else(|_| bind_addr.to_string(), |a| a.to_string());
        let (stream, peer) = listener
            .accept()
            .map_err(|e| TransportError::Transport(format!("tcp accept on {}: {}", local, e)))?;
        Ok(Self {
            stream,
            desc: format!("tcp-server:{} (peer {})", local, peer),
            flow: FlowControlGate::new(),
        })
    }

    /// Wrap an already-connected `TcpStream`.
    pub fn from_stream(stream: TcpStream, desc: String) -> Self {
        Self {
            stream,
            desc,
            flow: FlowControlGate::new(),
        }
    }
}

impl Read for TcpTransport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        // Honor the flow-control gate (XOFF seen in TX or RTS low).
        // Reporting WouldBlock leaves the TCP receive window alone —
        // the kernel stops ACKing after the window fills, which is
        // what pauses the remote sender.
        if self.flow.is_paused() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "flow-control paused (XOFF or RTS low)",
            ));
        }
        self.stream.read(buf)
    }
}

impl Write for TcpTransport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.stream.write(buf)?;
        self.flow.observe_outbound(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

impl Transport for TcpTransport {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        if timeout == Some(Duration::ZERO) {
            self.stream.set_nonblocking(true)
        } else {
            self.stream.set_nonblocking(false)?;
            self.stream.set_read_timeout(timeout)
        }
    }

    fn description(&self) -> &str {
        &self.desc
    }

    fn modem_control(&mut self) -> Option<&mut dyn ModemControl> {
        Some(self)
    }
}

/// `ModemControl` impl for TCP: same semantics as the SSH impl —
/// the wire carries no RS-232 sideband, so RTS becomes a read-side
/// throttle via the `FlowControlGate` and CTS/DSR/DCD answer
/// "asserted" so polling firmware doesn't hang.
impl ModemControl for TcpTransport {
    fn set_dtr(&mut self, _active: bool) -> io::Result<()> {
        Ok(())
    }
    fn set_rts(&mut self, active: bool) -> io::Result<()> {
        self.flow.set_rts(active);
        Ok(())
    }
    fn set_break(&mut self, _active: bool) -> io::Result<()> {
        Ok(())
    }
    fn read_cts(&mut self) -> io::Result<bool> {
        Ok(true)
    }
    fn read_dsr(&mut self) -> io::Result<bool> {
        Ok(true)
    }
    fn read_dcd(&mut self) -> io::Result<bool> {
        Ok(true)
    }
    fn read_ri(&mut self) -> io::Result<bool> {
        Ok(false)
    }
}

/// Bind with Unix address reuse for quick restarts, or Windows exclusive use
/// to prevent another socket from taking the same listening endpoint.
/// See <https://learn.microsoft.com/en-us/windows/win32/winsock/so-exclusiveaddruse>.
pub(crate) fn bind_listener_reuse(addr: std::net::SocketAddr) -> io::Result<TcpListener> {
    use socket2::{Domain, Socket, Type};
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::STREAM, None)?;
    #[cfg(not(windows))]
    sock.set_reuse_address(true)?;
    #[cfg(windows)]
    exclusive_address(&sock)?;
    sock.bind(&addr.into())?;
    sock.listen(128)?;
    Ok(sock.into())
}

#[cfg(windows)]
fn exclusive_address(socket: &socket2::Socket) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    #[link(name = "ws2_32")]
    extern "system" {
        fn setsockopt(socket: usize, level: i32, option: i32, value: *const u8, length: i32)
            -> i32;
        fn WSAGetLastError() -> i32;
    }
    const SOL_SOCKET: i32 = 0xffff;
    const SO_EXCLUSIVEADDRUSE: i32 = !0x0004;
    let enabled: i32 = 1;
    // SAFETY: socket owns a live Winsock handle; value points to a BOOL-sized
    // integer that remains valid for this synchronous call. No ownership moves.
    let result = unsafe {
        setsockopt(
            socket.as_raw_socket() as usize,
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            (&enabled as *const i32).cast(),
            std::mem::size_of_val(&enabled) as i32,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        // SAFETY: WSAGetLastError has no preconditions and reads this thread's error.
        Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }))
    }
}

pub(crate) fn resolve_addresses(addr: &str) -> Result<Vec<std::net::SocketAddr>, TransportError> {
    if let Ok(port) = addr.parse::<u16>() {
        return Ok(vec![std::net::SocketAddr::from(([0, 0, 0, 0], port))]);
    }
    let addresses: Vec<_> = addr
        .to_socket_addrs()
        .map_err(|e| TransportError::InvalidSpec(format!("cannot resolve '{addr}': {e}")))?
        .collect();
    if addresses.is_empty() {
        return Err(TransportError::InvalidSpec(format!(
            "no addresses for '{addr}'"
        )));
    }
    Ok(addresses)
}

/// Resolve the first address, interpreting a bare port as `0.0.0.0:port`.
fn resolve_addr(addr: &str) -> Result<std::net::SocketAddr, TransportError> {
    if let Ok(port) = addr.parse::<u16>() {
        return Ok(std::net::SocketAddr::from(([0, 0, 0, 0], port)));
    }
    addr.to_socket_addrs()
        .map_err(|e| TransportError::InvalidSpec(format!("cannot resolve '{}': {}", addr, e)))?
        .next()
        .ok_or_else(|| TransportError::InvalidSpec(format!("no addresses for '{}'", addr)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn localhost_connection_tries_all_resolved_addresses_and_empty_reads_ignore_flow() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut transport = TcpTransport::connect(&format!("localhost:{port}")).unwrap();
        let (_peer, _) = listener.accept().unwrap();
        transport.set_rts(false).unwrap();
        assert_eq!(transport.read(&mut []).unwrap(), 0);
    }

    #[test]
    fn a_listener_cannot_be_rebound_by_a_second_listener() {
        let listener = bind_listener_reuse("127.0.0.1:0".parse().unwrap()).unwrap();
        let address = listener.local_addr().unwrap();
        let competitor =
            socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
        competitor.set_reuse_address(true).unwrap();
        let result = competitor
            .bind(&address.into())
            .and_then(|_| competitor.listen(1));
        assert!(result.is_err(), "a competing listener claimed {address}");
    }

    #[test]
    fn resolve_bare_port() {
        let addr = resolve_addr("2023").unwrap();
        assert_eq!(addr.port(), 2023);
        assert!(addr.ip().is_unspecified());
    }

    #[test]
    fn resolve_full_addr() {
        let addr = resolve_addr("127.0.0.1:8080").unwrap();
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    fn resolve_invalid() {
        assert!(resolve_addr("not-a-valid-addr:::").is_err());
    }

    #[test]
    fn tcp_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_thread = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            TcpTransport::from_stream(stream, "test-server".into())
        });

        let mut client = TcpTransport::connect(&addr.to_string()).unwrap();
        let mut server = server_thread.join().unwrap();

        client.write_all(b"hello").unwrap();
        client.flush().unwrap();

        server
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let mut buf = [0u8; 5];
        let n = server.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello");

        server.write_all(b"world").unwrap();
        server.flush().unwrap();

        client
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let n = client.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"world");
    }

    #[test]
    fn tcp_description_contains_tcp() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let _server = std::thread::spawn(move || {
            listener.accept().unwrap();
        });

        let t = TcpTransport::connect(&addr.to_string()).unwrap();
        assert!(t.description().starts_with("tcp:"));
    }
}

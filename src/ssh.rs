//! SSH transport using the `ssh2` crate.
//!
//! Supports client mode (connecting to a remote SSH server).
//! Server mode is not yet supported (libssh2 is client-focused).
//!
//! # Spec string format
//!
//! - **Client:** `ssh:<user>@<host>:<port>` — connect to a remote SSH server
//!
//! # Authentication
//!
//! [`SshTransport::connect_with_auth`] takes a [`crate::ssh_auth::SshAuth`]
//! naming the methods to try and the material to try them with (agent, key
//! files, password, keyboard-interactive, `none`).
//!
//! [`SshTransport::connect`] and [`SshTransport::connect_with_pty`] use
//! [`crate::ssh_auth::SshAuth::legacy`], which tries:
//! 1. SSH agent
//! 2. Password from `TVI950_SSH_PASSWORD` (or `S100BOX_SSH_PASSWORD`) env var
//! 3. `none` authentication
//!
//! # Host key verification
//!
//! Connection helpers strictly verify `.ssh/known_hosts` before authentication.
//! [`SshTransport::connect_with_policy`] accepts an explicit known-hosts file,
//! SHA-256 fingerprint pin, or opt-in insecure lab policy.

use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::{Duration, Instant};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const SETUP_TIMEOUT_MS: u32 = 10_000;

use ssh2::Session;

use retrosim_core::transport::{ModemControl, Transport, TransportError};

use crate::flow_control::FlowControlGate;
use crate::ssh_auth::{authenticate, SshAuth, SshAuthMethod};
use crate::ssh_host_key::SshHostKeyPolicy;

/// PTY parameters for SSH connections.
#[derive(Debug, Clone)]
pub struct SshPtyParams {
    /// Terminal type string (e.g., "tvi955", "vt100", "xterm").
    pub term: String,
    /// Terminal width in columns.
    pub cols: u32,
    /// Terminal height in rows.
    pub rows: u32,
    /// Line speed to report on the remote pty, in baud.
    ///
    /// A PTY has no physical wire and its default speed depends on the server.
    /// Report the cable's rate when bridging a real terminal: programs such as
    /// `vttest` use `cfgetospeed` to pace timing-sensitive tests.
    ///
    /// `None` leaves the server's default unchanged.
    pub speed: Option<u32>,
}

impl Default for SshPtyParams {
    fn default() -> Self {
        Self {
            term: "xterm".to_string(),
            cols: 80,
            rows: 24,
            speed: None,
        }
    }
}

/// SSH transport wrapping an `ssh2::Channel`.
pub struct SshTransport {
    /// The SSH session (must stay alive while the channel is in use).
    session: Session,
    /// The SSH channel for data transfer.
    channel: ssh2::Channel,
    /// Human-readable description of this transport.
    desc: String,
    /// Whether the transport is still connected.
    connected: bool,
    /// Software (XON/XOFF) + hardware (RTS/CTS) flow-control gate.
    /// SSH has no way to carry RTS/CTS on the wire, so the gate
    /// translates the firmware's intent into "stop reading the SSH
    /// socket" and lets TCP's receive-window backpressure actually
    /// throttle the remote — see `flow_control.rs`.
    flow: FlowControlGate,
    /// The successful authentication method, available to caller diagnostics.
    auth_method: SshAuthMethod,
}

impl SshTransport {
    /// Connect to a remote SSH server (client mode).
    ///
    /// Authentication tries (in order):
    /// 1. SSH agent
    /// 2. Password from env var
    /// 3. `none` authentication
    pub fn connect(user: &str, host: &str, port: u16) -> Result<Self, TransportError> {
        Self::connect_with_pty(user, host, port, &SshPtyParams::default())
    }

    /// Connect to a remote SSH server with explicit PTY parameters.
    ///
    /// The `pty` parameter controls the terminal type and dimensions
    /// reported to the remote server.  Use this to match the emulated
    /// terminal (e.g., `term = "tvi955"`) so that the remote system
    /// sends the correct escape sequences.
    pub fn connect_with_pty(
        user: &str,
        host: &str,
        port: u16,
        pty: &SshPtyParams,
    ) -> Result<Self, TransportError> {
        Self::connect_with_auth(user, host, port, pty, &SshAuth::legacy())
    }

    /// Connect with explicit PTY parameters *and* an explicit authentication
    /// policy.
    ///
    /// [`connect`](Self::connect) and [`connect_with_pty`](Self::connect_with_pty)
    /// call this with [`SshAuth::legacy`]. A caller that wants key files,
    /// a password prompt, or keyboard-interactive passes its own [`SshAuth`]; see
    /// [`crate::ssh_auth`].
    pub fn connect_with_auth(
        user: &str,
        host: &str,
        port: u16,
        pty: &SshPtyParams,
        auth: &SshAuth,
    ) -> Result<Self, TransportError> {
        Self::connect_with_policy(user, host, port, pty, auth, &SshHostKeyPolicy::default())
    }

    /// Connect with explicit authentication and server host-key policies.
    ///
    /// Verifies the server immediately after key exchange, before any user
    /// authentication request. Other connection helpers use strict default
    /// known-hosts verification. Unknown and changed keys never fall back to
    /// the insecure policy.
    pub fn connect_with_policy(
        user: &str,
        host: &str,
        port: u16,
        pty: &SshPtyParams,
        auth: &SshAuth,
        host_key: &SshHostKeyPolicy,
    ) -> Result<Self, TransportError> {
        validate_target(user, host, port)?;
        let addr = format!("{host}:{port}");
        let addresses = (host, port)
            .to_socket_addrs()
            .map_err(|e| TransportError::InvalidSpec(format!("cannot resolve '{addr}': {e}")))?;
        // DNS is synchronous; the budget covers connection attempts after it.
        let started = Instant::now();
        let mut last = io::Error::new(io::ErrorKind::AddrNotAvailable, "no resolved addresses");
        let mut tcp = None;
        for address in addresses {
            let Some(remaining) = CONNECT_TIMEOUT.checked_sub(started.elapsed()) else {
                break;
            };
            match TcpStream::connect_timeout(&address, remaining) {
                Ok(stream) => {
                    tcp = Some(stream);
                    break;
                }
                Err(error) => last = error,
            }
        }
        let tcp = tcp.ok_or_else(|| {
            TransportError::Transport(format!("ssh tcp connect to {addr}: {last}"))
        })?;

        let mut session = Session::new().map_err(|e| {
            TransportError::Transport(format!("ssh session creation failed: {}", e))
        })?;
        session.set_tcp_stream(tcp);
        session.set_timeout(SETUP_TIMEOUT_MS);
        session.handshake().map_err(|e| {
            TransportError::Transport(format!("ssh handshake with {} failed: {}", addr, e))
        })?;

        host_key.verify(&session, host, port)?;

        // The failure message carries the whole ladder -- what was tried, what
        // was skipped and why, and what the server said it would accept. A
        // bare "authentication failed" sends you looking at the password when
        // the real answer is that the server never offered that method.
        let auth_method = authenticate(&session, user, auth)
            .map_err(|e| TransportError::Transport(e.with_target(&addr).to_string()))?;

        let mut channel = session
            .channel_session()
            .map_err(|e| TransportError::Transport(format!("ssh channel open failed: {}", e)))?;
        // Both directions, because a terminal's cable has one speed and
        // `stty`/`cfgetospeed` will report them separately if they differ.
        let modes = pty.speed.map(|baud| {
            let mut m = ssh2::PtyModes::new();
            m.set_u32(ssh2::PtyModeOpcode::TTY_OP_ISPEED, baud);
            m.set_u32(ssh2::PtyModeOpcode::TTY_OP_OSPEED, baud);
            m
        });
        channel
            .request_pty(&pty.term, modes, Some((pty.cols, pty.rows, 0, 0)))
            .map_err(|e| TransportError::Transport(format!("ssh pty request failed: {}", e)))?;
        channel
            .shell()
            .map_err(|e| TransportError::Transport(format!("ssh shell request failed: {}", e)))?;

        // Preserve the Transport default of blocking reads after bounded setup.
        session.set_timeout(0);
        let desc = format!("ssh:{}@{}:{}", user, host, port);
        Ok(Self {
            session,
            channel,
            desc,
            connected: true,
            flow: FlowControlGate::new(),
            auth_method,
        })
    }

    /// The method that authenticated this session.
    pub fn auth_method(&self) -> SshAuthMethod {
        self.auth_method
    }

    /// Accept one incoming SSH connection (server mode).
    ///
    /// **Not yet supported.** Returns an error immediately.
    pub fn accept(_bind_addr: &str, _host_key_path: Option<&Path>) -> Result<Self, TransportError> {
        Err(TransportError::Transport(
            "ssh server mode is not yet supported (ssh2 crate supports client mode only)".into(),
        ))
    }
}

impl Read for SshTransport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        // Transport-level flow control: pretend the socket is empty
        // while the firmware has the stream paused (XOFF seen on TX,
        // or RTS de-asserted).  TCP's own receive window then stalls
        // the remote naturally — the only reliable way to throttle a
        // sender over a byte-stream transport.
        if self.flow.is_paused() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "flow-control paused (XOFF or RTS low)",
            ));
        }
        match self.channel.read(buf) {
            Ok(0) => {
                self.connected = false;
                Ok(0)
            }
            Ok(n) => Ok(n),
            Err(e) => {
                if is_transient(&e) {
                    Err(e)
                } else {
                    self.connected = false;
                    Err(e)
                }
            }
        }
    }
}

impl Write for SshTransport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        match self.channel.write(buf) {
            Ok(n) => {
                self.flow.observe_outbound(&buf[..n]);
                Ok(n)
            }
            Err(e) => {
                if !is_transient(&e) {
                    self.connected = false;
                }
                Err(e)
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.channel.flush()
    }
}

/// `ModemControl` impl for SSH: the wire can't carry RS-232 sideband
/// signals, but we honor the firmware's MCR RTS bit as a read-side
/// throttle via the `FlowControlGate` and answer CTS/DSR/DCD with
/// "always asserted" so firmware that polls modem status doesn't
/// hang.  DTR / break are no-ops.
impl ModemControl for SshTransport {
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

impl Transport for SshTransport {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        apply_timeout(&self.session, timeout);
        Ok(())
    }

    fn description(&self) -> &str {
        &self.desc
    }

    fn is_connected(&self) -> bool {
        self.connected
    }

    fn modem_control(&mut self) -> Option<&mut dyn ModemControl> {
        Some(self)
    }
}

impl Drop for SshTransport {
    fn drop(&mut self) {
        // Teardown is best effort: a silent peer must not hold Drop forever.
        self.session.set_blocking(false);
        let _ = self.channel.send_eof();
        let _ = self.channel.close();
        let _ = self.session.disconnect(None, "session ended", None);
    }
}

/// Parse an SSH client spec string: `[user@]host[:port]`.
///
/// The port is optional and defaults to 22, and the username is
/// optional and defaults to the operating-system username (`USERNAME`
/// on Windows, `USER` on Unix) — so `ssh:192.168.1.42`,
/// `ssh:hharte@192.168.1.42`, and `ssh:hharte@192.168.1.42:22` are
/// all accepted.
///
/// Returns `(user, host, port)`.
pub fn parse_ssh_client_spec(spec: &str) -> Result<(String, String, u16), TransportError> {
    let (user, rest) = match spec.split_once('@') {
        Some((user, rest)) => (user.to_string(), rest),
        None => {
            let user = std::env::var("USERNAME")
                .or_else(|_| std::env::var("USER"))
                .map_err(|_| {
                    TransportError::InvalidSpec(format!(
                        "ssh client spec '{}' has no user@ and neither USERNAME nor USER \
                         is set in the environment (expected [user@]host[:port])",
                        spec
                    ))
                })?;
            (user, spec)
        }
    };

    if user.is_empty() {
        return Err(TransportError::InvalidSpec(
            "ssh spec has empty username".into(),
        ));
    }

    let (host, port) = if let Some(bracketed) = rest.strip_prefix('[') {
        let (host, suffix) = bracketed.split_once(']').ok_or_else(|| {
            TransportError::InvalidSpec("ssh spec has an unclosed IPv6 address".into())
        })?;
        host.parse::<std::net::Ipv6Addr>().map_err(|_| {
            TransportError::InvalidSpec("ssh spec has an invalid IPv6 address".into())
        })?;
        let port = if suffix.is_empty() {
            22
        } else {
            let value = suffix.strip_prefix(':').ok_or_else(|| {
                TransportError::InvalidSpec("ssh spec expects :port after ]".into())
            })?;
            value.parse::<u16>().map_err(|_| {
                TransportError::InvalidSpec(format!("ssh spec invalid port: '{value}'"))
            })?
        };
        (host, port)
    } else {
        if rest.matches(':').count() > 1 {
            return Err(TransportError::InvalidSpec(
                "ssh IPv6 addresses must be bracketed".into(),
            ));
        }
        match rest.rsplit_once(':') {
            Some((host, value)) => (
                host,
                value.parse::<u16>().map_err(|_| {
                    TransportError::InvalidSpec(format!("ssh spec invalid port: '{value}'"))
                })?,
            ),
            None => (rest, 22),
        }
    };
    validate_target(&user, host, port)?;

    Ok((user.to_string(), host.to_string(), port))
}

fn validate_target(user: &str, host: &str, port: u16) -> Result<(), TransportError> {
    let problem = if user.is_empty() {
        Some("empty username")
    } else if host.is_empty() {
        Some("empty host")
    } else if user.contains('\0') || host.contains('\0') {
        Some("embedded NUL")
    } else if port == 0 {
        Some("port must be nonzero")
    } else {
        None
    };
    match problem {
        Some(problem) => Err(TransportError::InvalidSpec(format!(
            "ssh spec has {problem}"
        ))),
        None => Ok(()),
    }
}

fn is_transient(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

// libssh2 exposes one timeout for both read and write operations. Round a
// positive sub-millisecond duration up; zero alone means nonblocking polling.
fn apply_timeout(session: &Session, timeout: Option<Duration>) {
    if timeout == Some(Duration::ZERO) {
        session.set_blocking(false);
    } else {
        let ms = timeout.map_or(0, |d| {
            d.as_millis()
                .saturating_add(u128::from(d.subsec_nanos() % 1_000_000 != 0))
                .min(u128::from(u32::MAX)) as u32
        });
        session.set_blocking(true);
        session.set_timeout(ms);
    }
}

/// Parse an SSH server spec string: `bind_addr` (e.g., `0.0.0.0:2222` or `2222`).
pub fn parse_ssh_server_spec(spec: &str) -> Result<String, TransportError> {
    let _ = resolve_bind_addr(spec)?;
    Ok(spec.to_string())
}

/// Resolve a bind address, accepting bare port numbers.
fn resolve_bind_addr(addr: &str) -> Result<std::net::SocketAddr, TransportError> {
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

    #[test]
    fn ipv6_specs_and_invalid_targets() {
        for (spec, port) in [("user@[::1]", 22), ("user@[::1]:2222", 2222)] {
            assert_eq!(
                parse_ssh_client_spec(spec).unwrap(),
                ("user".into(), "::1".into(), port)
            );
        }
        for spec in [
            "user@::1",
            "user@[::1",
            "user@[bogus]",
            "user@[::1]junk",
            "user@host:0",
            "user@host\0:22",
            "u\0@host",
        ] {
            assert!(parse_ssh_client_spec(spec).is_err(), "{spec:?}");
        }
    }

    #[test]
    fn only_zero_timeout_selects_polling() {
        let session = Session::new().unwrap();
        apply_timeout(&session, Some(Duration::from_nanos(1)));
        assert!(session.is_blocking());
        assert_eq!(session.timeout(), 1);
        apply_timeout(&session, Some(Duration::from_micros(1001)));
        assert_eq!(session.timeout(), 2);
        apply_timeout(&session, Some(Duration::MAX));
        assert_eq!(session.timeout(), u32::MAX);
        apply_timeout(&session, Some(Duration::ZERO));
        assert!(!session.is_blocking());
        apply_timeout(&session, None);
        assert!(session.is_blocking());
        assert_eq!(session.timeout(), 0);
    }

    #[test]
    fn retryable_io_errors_do_not_imply_disconnect() {
        for kind in [
            io::ErrorKind::WouldBlock,
            io::ErrorKind::TimedOut,
            io::ErrorKind::Interrupted,
        ] {
            assert!(is_transient(&io::Error::from(kind)));
        }
        assert!(!is_transient(&io::Error::from(io::ErrorKind::BrokenPipe)));
    }

    #[test]
    fn parse_client_spec_basic() {
        let (user, host, port) = parse_ssh_client_spec("root@example.com:22").unwrap();
        assert_eq!(user, "root");
        assert_eq!(host, "example.com");
        assert_eq!(port, 22);
    }

    #[test]
    fn parse_client_spec_with_ip() {
        let (user, host, port) = parse_ssh_client_spec("admin@192.168.1.1:2222").unwrap();
        assert_eq!(user, "admin");
        assert_eq!(host, "192.168.1.1");
        assert_eq!(port, 2222);
    }

    #[test]
    fn parse_client_spec_missing_user_defaults_to_os_username() {
        // USERNAME (Windows) or USER (Unix) is set in any normal test
        // environment; the parser falls back to it when there is no
        // `user@` in the spec.
        let expected = std::env::var("USERNAME")
            .or_else(|_| std::env::var("USER"))
            .expect("test environment must define USERNAME or USER");
        let (user, host, port) = parse_ssh_client_spec("example.com:22").unwrap();
        assert_eq!(user, expected);
        assert_eq!(host, "example.com");
        assert_eq!(port, 22);
    }

    #[test]
    fn parse_client_spec_bare_host_defaults_user_and_port() {
        let (user, host, port) = parse_ssh_client_spec("192.168.1.42").unwrap();
        assert!(!user.is_empty());
        assert_eq!(host, "192.168.1.42");
        assert_eq!(port, 22);
    }

    #[test]
    fn parse_client_spec_empty_user() {
        match parse_ssh_client_spec("@example.com:22") {
            Err(TransportError::InvalidSpec(s)) => assert!(s.contains("empty username")),
            other => panic!("expected InvalidSpec, got: {:?}", other),
        }
    }

    #[test]
    fn parse_client_spec_missing_port_defaults_to_22() {
        let (user, host, port) = parse_ssh_client_spec("root@example.com").unwrap();
        assert_eq!(user, "root");
        assert_eq!(host, "example.com");
        assert_eq!(port, 22);
    }

    #[test]
    fn parse_server_spec_bare_port() {
        let spec = parse_ssh_server_spec("2222").unwrap();
        assert_eq!(spec, "2222");
    }

    #[test]
    fn ssh_connect_to_nonexistent_host_fails() {
        let result = SshTransport::connect("testuser", "127.0.0.1", 1);
        assert!(result.is_err());
    }

    #[test]
    fn ssh_server_mode_not_supported() {
        let result = SshTransport::accept("127.0.0.1:0", None);
        assert!(result.is_err());
        if let Err(TransportError::Transport(msg)) = result {
            assert!(msg.contains("not yet supported"));
        }
    }
}

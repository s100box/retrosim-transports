//! Reusable transport implementations for retro system simulators.
//!
//! Provides concrete [`Transport`] implementations for TCP, telnet,
//! UDP, serial ports, RFC 2217 (a serial port another process serves), and
//! SSH.  Each transport is a bidirectional byte
//! stream suitable for connecting a simulated UART to an external host.
//!
//! The [`open_transport`] factory function parses a spec string and
//! returns a boxed transport, following the same spec format used by
//! the s100box simulator.

pub mod console;
pub mod flow_control;
mod line;
pub mod null;
pub mod rfc2217;
#[cfg(feature = "serial")]
pub mod serial;
#[cfg(feature = "ssh")]
pub mod ssh;
#[cfg(feature = "ssh")]
pub mod ssh_auth;
#[cfg(feature = "ssh")]
pub mod ssh_host_key;
pub mod tcp;
pub mod telnet;
pub mod udp;
mod wire_output;

pub use flow_control::FlowControlGate;

pub use console::ConsoleTransport;
pub use null::NullTransport;
pub use rfc2217::Rfc2217Transport;
#[cfg(feature = "serial")]
pub use serial::SerialTransport;
#[cfg(feature = "ssh")]
pub use ssh::{SshPtyParams, SshTransport};
#[cfg(feature = "ssh")]
pub use ssh_auth::{KbdPrompt, SshAuth, SshAuthError, SshAuthMethod};
#[cfg(feature = "ssh")]
pub use ssh_host_key::SshHostKeyPolicy;
pub use tcp::TcpTransport;
pub use telnet::TelnetTransport;
pub use udp::UdpTransport;

use retrosim_core::transport::{Transport, TransportError};

/// Open a transport from a spec string.
///
/// # Spec format
///
/// | Spec                          | `listen=false` (client)   | `listen=true` (server)      |
/// |-------------------------------|---------------------------|-----------------------------|
/// | `console`                     | Local terminal marker     | (same)                      |
/// | `null`                        | Discard all I/O           | (same)                      |
/// | `tcp:<host:port>`             | TCP client                | TCP server on `<port>`      |
/// | `telnet:<host:port>`          | Telnet client             | Telnet server on `<port>`   |
/// | `udp:<host:port>`             | UDP client                | UDP server on `<port>`      |
/// | `serial:<port>@<baud>[,fmt[,flow]]` | Serial port, or the bridge serving it | Error (not applicable) |
/// | `rfc2217:<host:port>[@<baud>[,fmt[,flow]]]` | RFC 2217 client | Error (not applicable) |
/// | `ssh:[<user>@]<host>[:<port>]`| SSH client (defaults: OS user, port 22) | (not yet supported) |
///
/// Bare port numbers are accepted for TCP/telnet/UDP: `tcp:2023` binds to `0.0.0.0:2023`.
///
/// A `serial:` spec opens the port through its bridge when one holds it: if
/// [`rfc2217::bridge_addr`] finds the file a bridge such as `serbridge` writes
/// for the port, the transport is an [`Rfc2217Transport`] connected there, with
/// the spec's settings sent to the bridge. A file left behind by a bridge that
/// is no longer running is passed over and the port opened directly.
/// Direct-port fallback requires feature `serial`; bridge discovery also works
/// without it. An established bridge that refuses settings returns an error
/// rather than falling back to another connection.
/// [`SerialTransport::open`] (feature `serial`) always opens it directly.
///
/// SSH (feature `ssh`) verifies the server against the native user's
/// `.ssh/known_hosts` before authentication. Unknown or changed keys fail.
/// Direct `SshTransport::connect_with_policy` calls select an explicit trust
/// file or fingerprint policy.
pub fn open_transport(spec: &str, listen: bool) -> Result<Box<dyn Transport>, TransportError> {
    open_transport_inner(spec, listen, None)
}

/// Open a transport from a spec string with optional SSH PTY parameters.
///
/// For SSH connections, `pty_params` controls the terminal type and
/// dimensions reported to the remote server.  This allows terminal
/// simulators to request the correct `TERM` setting (e.g., `"tvi955"`)
/// so the remote system sends appropriate escape sequences.
///
/// For non-SSH transports, `pty_params` is ignored.
#[cfg(feature = "ssh")]
pub fn open_transport_with_pty(
    spec: &str,
    listen: bool,
    pty_params: &ssh::SshPtyParams,
) -> Result<Box<dyn Transport>, TransportError> {
    open_transport_inner(spec, listen, Some(pty_params))
}

fn open_transport_inner(
    spec: &str,
    listen: bool,
    #[cfg(feature = "ssh")] pty_params: Option<&ssh::SshPtyParams>,
    #[cfg(not(feature = "ssh"))] _pty_params: Option<()>,
) -> Result<Box<dyn Transport>, TransportError> {
    match spec {
        "console" => Ok(Box::new(ConsoleTransport::new())),
        "null" => Ok(Box::new(NullTransport::new())),
        _ => {
            if let Some(addr) = spec.strip_prefix("tcp:") {
                if listen {
                    Ok(Box::new(TcpTransport::accept(addr)?))
                } else {
                    Ok(Box::new(TcpTransport::connect(addr)?))
                }
            } else if let Some(addr) = spec.strip_prefix("telnet:") {
                if listen {
                    Ok(Box::new(TelnetTransport::accept(addr)?))
                } else {
                    Ok(Box::new(TelnetTransport::connect(addr)?))
                }
            } else if let Some(addr) = spec.strip_prefix("udp:") {
                if listen {
                    Ok(Box::new(UdpTransport::bind(addr)?))
                } else {
                    Ok(Box::new(UdpTransport::connect(addr)?))
                }
            } else if let Some(serial_spec) = spec.strip_prefix("serial:") {
                open_serial_transport(serial_spec, listen)
            } else if let Some(rfc_spec) = spec.strip_prefix("rfc2217:") {
                if listen {
                    return Err(TransportError::InvalidSpec(
                        "rfc2217 transport does not support listen mode".into(),
                    ));
                }
                Ok(Box::new(Rfc2217Transport::open(rfc_spec)?))
            } else if let Some(ssh_spec) = spec.strip_prefix("ssh:") {
                #[cfg(feature = "ssh")]
                {
                    open_ssh_transport(ssh_spec, listen, pty_params)
                }
                #[cfg(not(feature = "ssh"))]
                {
                    let _ = ssh_spec;
                    Err(TransportError::Transport(
                        "ssh transport is not available (compiled without 'ssh' feature)".into(),
                    ))
                }
            } else {
                Err(TransportError::InvalidSpec(format!(
                    "unknown transport spec: '{}' (expected console, null, tcp:, telnet:, udp:, serial:, rfc2217:, ssh:)",
                    spec
                )))
            }
        }
    }
}

fn open_serial_transport(spec: &str, listen: bool) -> Result<Box<dyn Transport>, TransportError> {
    if listen {
        return Err(TransportError::InvalidSpec(
            "serial transport does not support listen mode".into(),
        ));
    }
    let (port, rest) = line::split_spec("serial", spec)?;
    let settings = line::parse_settings(rest)?;
    if let Some(addr) = rfc2217::bridge_addr(port) {
        // A refused connection is a stale file; anything after the connection
        // is made is the bridge's answer and is reported as it is.
        if let Ok(stream) = rfc2217::connect_tcp(&addr) {
            return Ok(Box::new(Rfc2217Transport::over(
                stream,
                &addr,
                Some(settings.params),
                Some(settings.flow),
                format!("serial:{spec} via rfc2217://{addr}"),
            )?));
        }
    }
    open_serial_direct(spec)
}

#[cfg(feature = "serial")]
fn open_serial_direct(spec: &str) -> Result<Box<dyn Transport>, TransportError> {
    Ok(Box::new(SerialTransport::open(spec)?))
}

#[cfg(not(feature = "serial"))]
fn open_serial_direct(_spec: &str) -> Result<Box<dyn Transport>, TransportError> {
    Err(TransportError::Transport(
        "serial transport is not available (compiled without 'serial' feature)".into(),
    ))
}

#[cfg(feature = "ssh")]
fn open_ssh_transport(
    spec: &str,
    listen: bool,
    pty_params: Option<&ssh::SshPtyParams>,
) -> Result<Box<dyn Transport>, TransportError> {
    if listen {
        let _ = ssh::parse_ssh_server_spec(spec)?;
        Ok(Box::new(SshTransport::accept(spec, None)?))
    } else {
        let (user, host, port) = ssh::parse_ssh_client_spec(spec)?;
        match pty_params {
            Some(pty) => Ok(Box::new(SshTransport::connect_with_pty(
                &user, &host, port, pty,
            )?)),
            None => Ok(Box::new(SshTransport::connect(&user, &host, port)?)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_console() {
        let t = open_transport("console", false).unwrap();
        assert!(t.description().contains("console"));
    }

    #[test]
    fn open_null() {
        let t = open_transport("null", false).unwrap();
        assert_eq!(t.description(), "null");
    }

    #[test]
    fn open_unknown_spec() {
        match open_transport("foobar:something", false) {
            Err(TransportError::InvalidSpec(s)) => assert!(s.contains("foobar")),
            Err(other) => panic!("expected InvalidSpec, got: {:?}", other),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn open_serial_listen_rejected() {
        match open_transport("serial:COM3@9600", true) {
            Err(TransportError::InvalidSpec(s)) => assert!(s.contains("listen")),
            Err(other) => panic!("expected InvalidSpec error, got: {:?}", other),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn open_serial_missing_baud() {
        match open_transport("serial:COM3", false) {
            Err(TransportError::InvalidSpec(s)) => assert!(s.contains("@baud")),
            Err(other) => panic!("expected InvalidSpec error, got: {:?}", other),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn open_rfc2217_client() {
        let s = rfc2217::test_server::serve(rfc2217::test_server::Mode::Echo);
        let t = open_transport(&format!("rfc2217:{}@9600,7E1", s.addr), false).unwrap();
        assert_eq!(t.description(), format!("rfc2217:{}", s.addr));
        let p = s.port.lock().unwrap();
        assert_eq!((p.baud, p.data, p.parity), (9600, 7, 3));
    }

    #[test]
    fn open_rfc2217_listen_rejected() {
        match open_transport("rfc2217:127.0.0.1:1", true) {
            Err(TransportError::InvalidSpec(s)) => assert!(s.contains("listen")),
            Err(other) => panic!("expected InvalidSpec error, got: {:?}", other),
            Ok(_) => panic!("expected error"),
        }
    }

    /// A bridge URL file for a port name no real port has, removed on drop.
    struct BridgeFile(std::path::PathBuf);

    impl BridgeFile {
        fn new(tag: &str, url: &str) -> (String, BridgeFile) {
            let port = format!("rtl{}{tag}", std::process::id());
            let path = rfc2217::url_file(&port);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, url).unwrap();
            (port, BridgeFile(path))
        }
    }

    impl Drop for BridgeFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn a_serial_spec_uses_the_bridge_holding_the_port() {
        let s = rfc2217::test_server::serve(rfc2217::test_server::Mode::Echo);
        let (port, _f) = BridgeFile::new("live", &format!("rfc2217://{}", s.addr));
        let t = open_transport(&format!("serial:{port}@2400,8N2,hw"), false).unwrap();
        assert_eq!(
            t.description(),
            format!("serial:{port}@2400,8N2,hw via rfc2217://{}", s.addr)
        );
        let p = s.port.lock().unwrap();
        assert_eq!(
            (p.baud, p.data, p.parity, p.stop, p.flow),
            (2400, 8, 1, 2, 3)
        );
    }

    #[test]
    fn a_bridge_that_refuses_the_settings_is_reported_not_bypassed() {
        let s = rfc2217::test_server::serve(rfc2217::test_server::Mode::Echo);
        s.port.lock().unwrap().refuse_baud = Some(1234);
        let (port, _f) = BridgeFile::new("refuse", &format!("rfc2217://{}", s.addr));
        let e = match open_transport(&format!("serial:{port}@1234"), false) {
            Ok(_) => panic!("{port} opened"),
            Err(e) => e.to_string(),
        };
        assert!(e.contains("refused baud rate 1234"), "{e}");
    }

    #[test]
    fn a_stale_bridge_file_falls_back_to_the_port() {
        let dead = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let (port, _f) = BridgeFile::new("stale", &format!("rfc2217://{dead}"));
        let e = match open_transport(&format!("serial:{port}@9600"), false) {
            Ok(_) => panic!("{port} opened"),
            Err(e) => e.to_string(),
        };
        // The direct open was tried, and failed as it would with no file.
        #[cfg(feature = "serial")]
        assert!(e.contains(&format!("serial open {port}")), "{e}");
        #[cfg(not(feature = "serial"))]
        assert!(e.contains("not available"), "{e}");
    }

    #[test]
    fn a_bad_serial_spec_is_refused_before_any_bridge_lookup() {
        assert!(matches!(
            open_transport("serial:@9600", false),
            Err(TransportError::InvalidSpec(_))
        ));
        assert!(matches!(
            open_transport("serial:COM3@9600,8N1,bogus", false),
            Err(TransportError::InvalidSpec(_))
        ));
    }

    #[test]
    fn open_tcp_client() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let _handle = std::thread::spawn(move || {
            listener.accept().unwrap();
        });

        let t = open_transport(&format!("tcp:{}", addr), false).unwrap();
        assert!(t.description().starts_with("tcp:"));
    }

    #[test]
    fn open_telnet_client() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let _handle = std::thread::spawn(move || {
            listener.accept().unwrap();
        });

        let t = open_transport(&format!("telnet:{}", addr), false).unwrap();
        assert!(t.description().starts_with("telnet:"));
    }
}

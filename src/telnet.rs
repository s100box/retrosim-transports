// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Howard M. Harte
//! Telnet byte transport with bounded output and reconnecting server mode.
//!
//! Client mode refuses options. Server mode offers ECHO and SUPPRESS-GO-AHEAD;
//! acknowledgements are tracked so negotiation cannot loop. Incoming IAC
//! commands are removed and outgoing data IAC bytes are doubled.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use crate::flow_control::FlowControlGate;
use crate::wire_output::WireOutput;
use retrosim_core::transport::{ModemControl, Transport, TransportError};

const IAC: u8 = 255;
const WILL: u8 = 251;
const WONT: u8 = 252;
const DO: u8 = 253;
const DONT: u8 = 254;
const SB: u8 = 250;
const SE: u8 = 240;
const OPT_ECHO: u8 = 1;
const OPT_SGA: u8 = 3;

/// Before a client attaches, retain the latest 64 KiB of console output.
const MAX_PENDING_OUT: usize = 64 * 1024;
/// Connected output is bounded separately and never overwritten on backpressure.
const MAX_WIRE_OUT: usize = 128 * 1024;

#[derive(Debug, Clone, Copy, PartialEq)]
enum IacState {
    Data,
    Iac,
    Negotiate(u8),
    Subneg,
    SubnegIac,
}

/// TCP transport with Telnet escaping and option negotiation.
///
/// A listener accepts replacements after disconnection. Until a peer connects,
/// writes retain the latest 64 KiB. Connected writes accept only the prefix that
/// fits a 128 KiB encoded queue; WouldBlock never discards accepted output.
/// Call `flush`, `read`, or `write` again to service queued bytes.
pub struct TelnetTransport {
    stream: Option<TcpStream>,
    listener: Option<TcpListener>,
    desc: String,
    state: IacState,
    response_buf: Vec<u8>,
    pending_in: VecDeque<u8>,
    pending_out: VecDeque<u8>,
    wire: WireOutput,
    /// Negotiated local options, separate from the options we are willing to offer.
    local_options: [bool; 256],
    server_options: bool,
    timeout: Option<Duration>,
    /// An externally supplied stream retains its configuration until the
    /// caller explicitly requests a timeout through Transport.
    manage_timeout: bool,
    /// Report a deferred send error after delivering already-decoded input.
    pending_error: Option<io::Error>,
    flow: FlowControlGate,
}

impl TelnetTransport {
    fn new(
        stream: Option<TcpStream>,
        listener: Option<TcpListener>,
        desc: String,
        timeout: Option<Duration>,
    ) -> Self {
        Self {
            stream,
            listener,
            desc,
            state: IacState::Data,
            response_buf: Vec::new(),
            pending_in: VecDeque::new(),
            pending_out: VecDeque::new(),
            wire: WireOutput::new(MAX_WIRE_OUT),
            local_options: [false; 256],
            server_options: false,
            timeout,
            manage_timeout: true,
            pending_error: None,
            flow: FlowControlGate::new(),
        }
    }

    /// Connect to a remote Telnet server with no initial socket read timeout.
    pub fn connect(addr: &str) -> Result<Self, TransportError> {
        let resolved = crate::tcp::resolve_addresses(addr)?;
        let stream = TcpStream::connect(resolved.as_slice())
            .map_err(|e| TransportError::Transport(format!("telnet connect to {addr}: {e}")))?;
        let peer = stream
            .peer_addr()
            .map_or_else(|_| addr.to_string(), |a| a.to_string());
        Ok(Self::from_stream(stream, format!("telnet:{peer}")))
    }

    /// Bind and return immediately. Accepts are polled and newly accepted peers
    /// inherit the requested read timeout, which initially defaults to zero.
    pub fn accept(bind_addr: &str) -> Result<Self, TransportError> {
        let listener = crate::tcp::bind_listener_reuse(resolve_addr(bind_addr)?)
            .map_err(|e| TransportError::Transport(format!("telnet bind {bind_addr}: {e}")))?;
        listener.set_nonblocking(true).map_err(|e| {
            TransportError::Transport(format!("telnet listener configuration: {e}"))
        })?;
        let local = listener
            .local_addr()
            .map_or_else(|_| bind_addr.to_string(), |a| a.to_string());
        Ok(Self::new(
            None,
            Some(listener),
            format!("telnet-server:{local} (listening)"),
            Some(Duration::ZERO),
        ))
    }

    /// Wrap a stream without changing its socket configuration. Call
    /// `set_read_timeout` to request nonblocking or finite-timeout reads.
    pub fn from_stream(stream: TcpStream, desc: String) -> Self {
        let mut transport = Self::new(Some(stream), None, desc, None);
        transport.manage_timeout = false;
        transport
    }

    fn try_accept(&mut self) -> io::Result<bool> {
        if self.stream.is_some() {
            return Ok(true);
        }
        let Some(listener) = &self.listener else {
            return Ok(false);
        };
        let (stream, peer) = match listener.accept() {
            Ok(pair) => pair,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) => return Err(error),
        };
        apply_timeout(&stream, self.timeout)?;
        self.desc = format!("telnet-server:{} (peer {peer})", listener.local_addr()?);
        self.stream = Some(stream);
        if let Err(error) = self.send_server_options() {
            if !retryable(&error) {
                self.disconnect();
                return Err(error);
            }
        }
        Ok(true)
    }

    fn disconnect(&mut self) {
        self.stream = None;
        self.state = IacState::Data;
        self.local_options.fill(false);
        self.server_options = false;
        self.response_buf.clear();
        self.wire.clear();
    }

    fn buffer_out(&mut self, buf: &[u8]) {
        if buf.len() >= MAX_PENDING_OUT {
            self.pending_out.clear();
            self.pending_out.extend(&buf[buf.len() - MAX_PENDING_OUT..]);
        } else {
            let count = (self.pending_out.len() + buf.len()).saturating_sub(MAX_PENDING_OUT);
            self.pending_out.drain(..count);
            self.pending_out.extend(buf);
        }
    }

    /// Preserve wire order across short writes: accepted output first, then
    /// protocol replies, then console bytes retained before this connection.
    fn flush_output(&mut self) -> io::Result<()> {
        let Some(stream) = self.stream.as_mut() else {
            return Ok(());
        };
        loop {
            self.wire.flush(stream)?;
            if !self.response_buf.is_empty() {
                let count = self.wire.push_raw(&self.response_buf);
                self.response_buf.drain(..count);
            } else if !self.pending_out.is_empty() {
                let (front, _) = self.pending_out.as_slices();
                let count = self.wire.push_data(front);
                self.pending_out.drain(..count);
            } else {
                return Ok(());
            }
        }
    }

    fn process_byte(&mut self, byte: u8) -> Option<u8> {
        self.state = match self.state {
            IacState::Data if byte == IAC => IacState::Iac,
            IacState::Data => return Some(byte),
            IacState::Iac => match byte {
                IAC => {
                    self.state = IacState::Data;
                    return Some(IAC);
                }
                WILL | WONT | DO | DONT => IacState::Negotiate(byte),
                SB => IacState::Subneg,
                _ => IacState::Data,
            },
            IacState::Negotiate(command) => {
                let active = &mut self.local_options[byte as usize];
                let supported = self.server_options && matches!(byte, OPT_ECHO | OPT_SGA);
                let response = match command {
                    DO if supported && !*active => {
                        *active = true;
                        Some(WILL)
                    }
                    DO if supported => None, // acknowledgement of our offer
                    DO => Some(WONT),
                    DONT if *active => {
                        *active = false;
                        Some(WONT)
                    }
                    DONT | WONT => None, // never acknowledge a refusal repeatedly
                    WILL => Some(DONT),
                    _ => None,
                };
                if let Some(response) = response {
                    self.response_buf.extend([IAC, response, byte]);
                }
                IacState::Data
            }
            IacState::Subneg if byte == IAC => IacState::SubnegIac,
            IacState::Subneg => IacState::Subneg,
            IacState::SubnegIac if byte == SE => IacState::Data,
            IacState::SubnegIac => IacState::Subneg,
        };
        None
    }

    /// Offer ECHO and SUPPRESS-GO-AHEAD. Repeated calls do not repeat active
    /// offers. A WouldBlock leaves the complete negotiation queued for retry.
    pub fn send_server_options(&mut self) -> io::Result<()> {
        if self.stream.is_none() {
            return Err(io::ErrorKind::NotConnected.into());
        }
        self.server_options = true;
        for option in [OPT_ECHO, OPT_SGA] {
            if !self.local_options[option as usize] {
                self.local_options[option as usize] = true;
                self.response_buf.extend([IAC, WILL, option]);
            }
        }
        self.flush_output()
    }

    fn take_input(&mut self, buf: &mut [u8]) -> usize {
        let count = buf.len().min(self.pending_in.len());
        for (slot, byte) in buf.iter_mut().zip(self.pending_in.drain(..count)) {
            *slot = byte;
        }
        count
    }
}

fn retryable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

fn apply_timeout(stream: &TcpStream, timeout: Option<Duration>) -> io::Result<()> {
    if timeout == Some(Duration::ZERO) {
        stream.set_nonblocking(true)
    } else {
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(timeout)
    }
}

impl Read for TelnetTransport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if !self.pending_in.is_empty() {
            return Ok(self.take_input(buf));
        }
        if let Some(error) = self.pending_error.take() {
            return Err(error);
        }
        if self.flow.is_paused() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let started = Instant::now();
        loop {
            if !self.try_accept()? {
                return if self.listener.is_some() {
                    Err(io::ErrorKind::WouldBlock.into())
                } else {
                    Ok(0)
                };
            }
            if let Err(error) = self.flush_output() {
                if !retryable(&error) {
                    self.disconnect();
                    return Err(error);
                }
                // Do not collect more replies while a previous reply cannot
                // enter the bounded wire queue. Already-queued data can drain.
                if !self.response_buf.is_empty() {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
            }
            let timeout = match self.timeout {
                Some(duration) if !duration.is_zero() => Some(
                    duration
                        .checked_sub(started.elapsed())
                        .filter(|left| !left.is_zero())
                        .ok_or(io::ErrorKind::TimedOut)?,
                ),
                other => other,
            };
            let stream = self.stream.as_mut().expect("accepted connection");
            if self.manage_timeout {
                apply_timeout(stream, timeout)?;
            }
            let mut raw = [0u8; 256];
            let count = match stream.read(&mut raw) {
                Ok(0) => {
                    self.disconnect();
                    return if self.listener.is_some() {
                        Err(io::ErrorKind::WouldBlock.into())
                    } else {
                        Ok(0)
                    };
                }
                Ok(count) => count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if retryable(&error) => return Err(error),
                Err(error) => {
                    self.disconnect();
                    return Err(error);
                }
            };
            for &byte in &raw[..count] {
                if let Some(data) = self.process_byte(byte) {
                    self.pending_in.push_back(data);
                }
            }
            if let Err(error) = self.flush_output() {
                if !retryable(&error) {
                    self.disconnect();
                    if self.pending_in.is_empty() {
                        return Err(error);
                    }
                    self.pending_error = Some(error);
                }
            }
            if !self.pending_in.is_empty() {
                return Ok(self.take_input(buf));
            }
            if !self.manage_timeout || self.timeout == Some(Duration::ZERO) {
                return Err(io::ErrorKind::WouldBlock.into());
            }
        }
    }
}

impl Write for TelnetTransport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if let Some(error) = self.pending_error.take() {
            return Err(error);
        }
        if !self.try_accept()? {
            if self.listener.is_none() {
                return Err(io::ErrorKind::NotConnected.into());
            }
            self.buffer_out(buf);
            self.flow.observe_outbound(buf);
            return Ok(buf.len());
        }
        if let Err(error) = self.flush_output() {
            if !retryable(&error) {
                self.disconnect();
                if self.listener.is_none() {
                    return Err(error);
                }
                self.buffer_out(buf);
                self.flow.observe_outbound(buf);
                return Ok(buf.len());
            }
            if !self.response_buf.is_empty() || !self.pending_out.is_empty() {
                return Err(io::ErrorKind::WouldBlock.into());
            }
        }
        let count = self.wire.push_data(buf);
        if count == 0 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.flow.observe_outbound(&buf[..count]);
        if let Err(error) = self.flush_output() {
            if !retryable(&error) {
                self.disconnect();
                if self.listener.is_some() {
                    self.buffer_out(&buf[..count]);
                } else {
                    self.pending_error = Some(error);
                }
            }
        }
        // These bytes belong to the queue even if the socket became blocked.
        // Reporting an error here would invite the caller to repeat them.
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(error) = self.pending_error.take() {
            return Err(error);
        }
        self.try_accept()?;
        if let Err(error) = self.flush_output() {
            if !retryable(&error) {
                self.disconnect();
            }
            return Err(error);
        }
        match &mut self.stream {
            Some(stream) => stream.flush(),
            None => Ok(()),
        }
    }
}

impl Transport for TelnetTransport {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        if let Some(stream) = &self.stream {
            apply_timeout(stream, timeout)?;
        }
        self.timeout = timeout;
        self.manage_timeout = true;
        Ok(())
    }
    fn description(&self) -> &str {
        &self.desc
    }
    fn is_connected(&self) -> bool {
        self.stream.is_some()
    }
    fn is_listening(&self) -> bool {
        self.listener.is_some()
    }
    fn modem_control(&mut self) -> Option<&mut dyn ModemControl> {
        Some(self)
    }
}

/// The wire has no RS-232 sideband. RTS gates reads; modem inputs are synthetic.
impl ModemControl for TelnetTransport {
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

/// Resolve the first address, interpreting a bare port as `0.0.0.0:port`.
fn resolve_addr(addr: &str) -> Result<std::net::SocketAddr, TransportError> {
    if let Ok(port) = addr.parse::<u16>() {
        return Ok(([0, 0, 0, 0], port).into());
    }
    addr.to_socket_addrs()
        .map_err(|e| TransportError::InvalidSpec(format!("cannot resolve '{addr}': {e}")))?
        .next()
        .ok_or_else(|| TransportError::InvalidSpec(format!("no addresses for '{addr}'")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_connect_tries_every_resolved_localhost_address() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let _transport = TelnetTransport::connect(&format!("localhost:{port}")).unwrap();
        listener.accept().unwrap();
    }

    fn connected_pair() -> (TelnetTransport, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let (stream, _) = listener.accept().unwrap();
        (TelnetTransport::from_stream(stream, "test".into()), peer)
    }

    fn negotiate(transport: &mut TelnetTransport, command: u8, option: u8) {
        for byte in [IAC, command, option] {
            assert_eq!(transport.process_byte(byte), None);
        }
    }

    #[test]
    fn refusal_acknowledgements_do_not_start_negotiation_loops() {
        let (mut transport, _peer) = connected_pair();
        for command in [DONT, WONT, DONT, WONT] {
            negotiate(&mut transport, command, 42);
        }
        assert!(transport.response_buf.is_empty());
        negotiate(&mut transport, DO, 42);
        negotiate(&mut transport, WILL, 42);
        assert_eq!(transport.response_buf, [IAC, WONT, 42, IAC, DONT, 42]);
    }

    #[test]
    fn server_offer_acknowledgements_remain_enabled_and_changes_are_answered_once() {
        let (mut transport, mut peer) = connected_pair();
        transport.send_server_options().unwrap();
        let mut offers = [0; 6];
        peer.read_exact(&mut offers).unwrap();
        assert_eq!(offers, [IAC, WILL, OPT_ECHO, IAC, WILL, OPT_SGA]);
        negotiate(&mut transport, DO, OPT_ECHO);
        negotiate(&mut transport, DO, OPT_SGA);
        assert!(transport.response_buf.is_empty());
        assert!(transport.local_options[OPT_ECHO as usize]);
        negotiate(&mut transport, DONT, OPT_ECHO);
        negotiate(&mut transport, DONT, OPT_ECHO);
        assert_eq!(transport.response_buf, [IAC, WONT, OPT_ECHO]);
        transport.response_buf.clear();
        negotiate(&mut transport, DO, OPT_ECHO);
        negotiate(&mut transport, DO, OPT_ECHO);
        assert_eq!(transport.response_buf, [IAC, WILL, OPT_ECHO]);
    }

    #[test]
    fn connected_writes_report_only_the_prefix_that_fits_after_escaping() {
        let (mut transport, mut peer) = connected_pair();
        transport.wire = WireOutput::new(3);
        let input = [b'A', IAC, b'B'];
        assert_eq!(transport.write(&input).unwrap(), 2);
        assert_eq!(transport.write(&input[2..]).unwrap(), 1);
        transport.flush().unwrap();
        let mut received = [0; 4];
        peer.read_exact(&mut received).unwrap();
        assert_eq!(received, [b'A', IAC, IAC, b'B']);
    }

    #[test]
    fn only_accepted_bytes_affect_software_flow_control() {
        let (mut transport, mut peer) = connected_pair();
        transport.wire = WireOutput::new(1);
        assert_eq!(
            transport.write(&[b'A', crate::flow_control::XOFF]).unwrap(),
            1
        );
        assert!(!transport.flow.is_paused());
        assert_eq!(transport.write(&[crate::flow_control::XOFF]).unwrap(), 1);
        assert!(transport.flow.is_paused());
        let mut received = [0; 2];
        peer.read_exact(&mut received).unwrap();
        assert_eq!(received, [b'A', crate::flow_control::XOFF]);
    }

    #[test]
    fn client_eof_clears_connection_state_and_does_not_buffer_new_writes() {
        let (mut transport, peer) = connected_pair();
        transport
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        assert_eq!(transport.read(&mut []).unwrap(), 0);
        assert!(transport.is_connected());
        drop(peer);
        assert_eq!(transport.read(&mut [0]).unwrap(), 0);
        assert!(!transport.is_connected());
        assert_eq!(
            transport.write(b"lost").unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
        assert!(transport.pending_out.is_empty());
    }

    #[test]
    fn decoded_pending_input_is_delivered_before_reading_another_socket_chunk() {
        let (mut transport, mut peer) = connected_pair();
        transport.pending_in.extend(b"ab");
        peer.write_all(b"cd").unwrap();
        transport
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut received = [0; 4];
        assert_eq!(transport.read(&mut received).unwrap(), 2);
        assert_eq!(&received[..2], b"ab");
        assert_eq!(transport.read(&mut received).unwrap(), 2);
        assert_eq!(&received[..2], b"cd");
    }

    #[test]
    fn a_timeout_configured_before_accept_is_kept_for_replacement_peers() {
        let (mut server, port) = bind_server();
        let timeout = Duration::from_millis(80);
        server.set_read_timeout(Some(timeout)).unwrap();
        for _ in 0..2 {
            let mut peer = TcpStream::connect(("127.0.0.1", port)).unwrap();
            assert!(server.try_accept().unwrap());
            assert!(server
                .stream
                .as_ref()
                .unwrap()
                .read_timeout()
                .unwrap()
                .is_some());
            assert!(server.local_options[OPT_ECHO as usize]);
            let mut options = [0; 6];
            peer.read_exact(&mut options).unwrap();
            let started = Instant::now();
            let error = server.read(&mut [0]).unwrap_err();
            assert!(retryable(&error), "{error}");
            assert!(
                started.elapsed() >= Duration::from_millis(40),
                "accepted stream became a polling socket"
            );
            drop(peer);
            assert!(server.read(&mut [0]).is_err());
            assert!(!server.is_connected());
        }
    }

    #[test]
    fn wrapping_a_stream_preserves_its_existing_polling_mode() {
        let (mut transport, _peer) = connected_pair();
        transport
            .stream
            .as_ref()
            .unwrap()
            .set_nonblocking(true)
            .unwrap();
        assert_eq!(
            transport.read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(!transport.manage_timeout);
    }

    #[test]
    fn control_only_traffic_does_not_restart_a_finite_read_deadline() {
        let (mut transport, mut peer) = connected_pair();
        transport
            .set_read_timeout(Some(Duration::from_millis(80)))
            .unwrap();
        let sender = std::thread::spawn(move || {
            for _ in 0..40 {
                if peer.write_all(&[IAC, 241]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            let _ = peer.write_all(b"late");
        });
        assert_eq!(
            transport.read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        drop(transport);
        sender.join().unwrap();
    }

    fn make_test_transport() -> TelnetTransport {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let _handle = std::thread::spawn(move || {
            listener.accept().unwrap();
        });
        TelnetTransport::from_stream(TcpStream::connect(addr).unwrap(), String::new())
    }

    #[test]
    fn iac_state_machine_passes_data() {
        let mut t = make_test_transport();
        assert_eq!(t.process_byte(b'A'), Some(b'A'));
        assert_eq!(t.process_byte(b'\n'), Some(b'\n'));
    }

    #[test]
    fn iac_escaped_ff() {
        let mut t = make_test_transport();
        assert_eq!(t.process_byte(IAC), None);
        assert_eq!(t.process_byte(IAC), Some(0xFF));
    }

    #[test]
    fn iac_will_refused() {
        let mut t = make_test_transport();
        assert_eq!(t.process_byte(IAC), None);
        assert_eq!(t.process_byte(WILL), None);
        assert_eq!(t.process_byte(1), None);
        assert_eq!(t.response_buf, vec![IAC, DONT, 1]);
    }

    #[test]
    fn iac_do_refused() {
        let mut t = make_test_transport();
        assert_eq!(t.process_byte(IAC), None);
        assert_eq!(t.process_byte(DO), None);
        assert_eq!(t.process_byte(1), None);
        assert_eq!(t.response_buf, vec![IAC, WONT, 1]);
    }

    #[test]
    fn iac_subneg_skipped() {
        let mut t = make_test_transport();
        assert_eq!(t.process_byte(IAC), None);
        assert_eq!(t.process_byte(SB), None);
        assert_eq!(t.process_byte(0x01), None);
        assert_eq!(t.process_byte(0x02), None);
        assert_eq!(t.process_byte(IAC), None);
        assert_eq!(t.process_byte(SE), None);
        assert_eq!(t.process_byte(b'X'), Some(b'X'));
    }

    #[test]
    fn write_escapes_ff() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_millis(200)))
                .unwrap();
            let mut buf = [0u8; 10];
            let n = stream.read(&mut buf).unwrap();
            buf[..n].to_vec()
        });

        let mut t = TelnetTransport::from_stream(TcpStream::connect(addr).unwrap(), String::new());

        let data = [0x41, 0xFF, 0x42];
        let n = t.write(&data).unwrap();
        assert_eq!(n, 3);
        t.flush().unwrap();

        let received = handle.join().unwrap();
        assert_eq!(received, vec![0x41, 0xFF, 0xFF, 0x42]);
    }

    #[test]
    fn telnet_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server_thread = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            TelnetTransport::from_stream(stream, "server".into())
        });

        let mut client = TelnetTransport::connect(&addr.to_string()).unwrap();
        let mut server = server_thread.join().unwrap();

        client.write_all(b"hello").unwrap();
        client.flush().unwrap();

        server
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut buf = [0u8; 10];
        let n = server.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello");

        assert!(client.description().starts_with("telnet:"));
    }

    #[test]
    fn accept_auto_sends_will_echo_sga() {
        // Bind a server-mode TelnetTransport on an ephemeral port,
        // then connect a client and verify the very first bytes the
        // client receives are the WILL ECHO + WILL SGA negotiation.
        // This is the "Microsoft Telnet shows doubled echo" fix:
        // the server must volunteer ECHO so the client drops local
        // echo without the user having to type `set localecho` first.
        let mut server = TelnetTransport::accept("127.0.0.1:0").unwrap();
        let port: u16 = server
            .description()
            .rsplit(':')
            .next()
            .and_then(|s| s.split_whitespace().next())
            .and_then(|s| s.parse().ok())
            .expect("parse listening port from description");

        let client_thread = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_millis(500)))
                .unwrap();
            let mut buf = [0u8; 16];
            let n = stream.read(&mut buf).unwrap();
            buf[..n].to_vec()
        });

        // Trigger the accept by polling. read() returns WouldBlock
        // after accepting because the freshly-connected client hasn't
        // sent anything yet — that's the path we want to exercise.
        let mut sink = [0u8; 16];
        for _ in 0..50 {
            match server.read(&mut sink) {
                Ok(_) => break,
                Err(_) => std::thread::sleep(Duration::from_millis(10)),
            }
            if server.is_connected() {
                break;
            }
        }

        let received = client_thread.join().unwrap();
        assert_eq!(
            received,
            vec![IAC, WILL, OPT_ECHO, IAC, WILL, OPT_SGA],
            "accept() should volunteer WILL ECHO + WILL SGA on connect"
        );
    }

    /// Helper for the buffering tests: bind a server-mode
    /// TelnetTransport on an ephemeral port and parse the port
    /// number out of its `(listening)` description.
    fn bind_server() -> (TelnetTransport, u16) {
        let server = TelnetTransport::accept("127.0.0.1:0").unwrap();
        let port: u16 = server
            .description()
            .rsplit(':')
            .next()
            .and_then(|s| s.split_whitespace().next())
            .and_then(|s| s.parse().ok())
            .expect("parse listening port from description");
        (server, port)
    }

    /// Helper for the buffering tests: connect a TCP client,
    /// drive `server` through poll cycles to fire `try_accept`,
    /// then read up to `wanted` bytes from the client and join
    /// the reader thread. Returns the bytes the client saw.
    fn drive_client_read(server: &mut TelnetTransport, port: u16, wanted: usize) -> Vec<u8> {
        let client_thread = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_millis(500)))
                .unwrap();
            let mut all = Vec::with_capacity(wanted);
            let mut buf = [0u8; 4096];
            while all.len() < wanted {
                match stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => all.extend_from_slice(&buf[..n]),
                    Err(_) => break,
                }
            }
            all
        });

        let mut sink = [0u8; 16];
        for _ in 0..50 {
            let _ = server.read(&mut sink);
            if server.is_connected() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        client_thread.join().unwrap()
    }

    /// A guest write before any client is connected must be
    /// preserved and replayed when a client eventually attaches.
    /// This is the "OASIS-86 banner + Time prompt printed before
    /// I opened my telnet client" use case.
    #[test]
    fn pending_out_replays_to_late_client() {
        let (mut server, port) = bind_server();
        // No client connected yet — guest writes go to buffer.
        assert!(!server.is_connected());
        server.write_all(b"BANNER\r\nTime? ").unwrap();
        server.flush().unwrap();
        assert!(!server.is_connected());

        // The IAC WILL ECHO/SGA negotiation arrives first, then
        // the buffered guest output.
        let received = drive_client_read(&mut server, port, 20);
        let mut expected = vec![IAC, WILL, OPT_ECHO, IAC, WILL, OPT_SGA];
        expected.extend_from_slice(b"BANNER\r\nTime? ");
        assert_eq!(received, expected);
    }

    /// Pending output must escape any 0xFF bytes (IAC) so the
    /// connecting client doesn't misinterpret guest data as a
    /// telnet command.
    #[test]
    fn pending_out_escapes_ff_on_flush() {
        let (mut server, port) = bind_server();
        server.write_all(&[0x41, 0xFF, 0x42]).unwrap();

        let received = drive_client_read(&mut server, port, 16);
        let mut expected = vec![IAC, WILL, OPT_ECHO, IAC, WILL, OPT_SGA];
        // 0x41, 0xFF→IAC IAC, 0x42
        expected.extend_from_slice(&[0x41, IAC, IAC, 0x42]);
        assert_eq!(received, expected);
    }

    /// More than `MAX_PENDING_OUT` bytes written without a
    /// client must keep only the most recent `MAX_PENDING_OUT`
    /// (drop-oldest ring-buffer behavior). Ensures a long-idle
    /// guest doesn't OOM the host and that the connecting
    /// client sees the freshest output.
    #[test]
    fn pending_out_drops_oldest_when_full() {
        let (mut server, port) = bind_server();
        // Write a recognisable head, then enough zeros to force
        // the head to be dropped, then a recognisable tail.
        let head = b"OLDEST_BYTES_SHOULD_BE_DROPPED_____";
        let tail = b"___THIS_TAIL_MUST_SURVIVE";
        server.write_all(head).unwrap();
        let zeros = vec![0u8; MAX_PENDING_OUT];
        server.write_all(&zeros).unwrap();
        server.write_all(tail).unwrap();

        let total = MAX_PENDING_OUT + 6 /* IAC negotiation */;
        let received = drive_client_read(&mut server, port, total);
        // Must start with the IAC negotiation.
        assert_eq!(&received[..6], &[IAC, WILL, OPT_ECHO, IAC, WILL, OPT_SGA]);
        // Must end with the tail (the head was dropped to fit).
        let body = &received[6..];
        assert_eq!(body.len(), MAX_PENDING_OUT);
        assert!(
            body.ends_with(tail),
            "expected tail to survive, body ends with {:?}",
            &body[body.len() - tail.len().min(body.len())..]
        );
        assert!(
            !body.windows(head.len()).any(|w| w == head),
            "head should have been dropped"
        );
    }

    /// A single guest write larger than `MAX_PENDING_OUT` must
    /// still be capped (only the tail kept), not OOM the host.
    #[test]
    fn pending_out_caps_single_oversize_write() {
        let (mut server, _port) = bind_server();
        let oversize = vec![b'X'; MAX_PENDING_OUT * 2];
        server.write_all(&oversize).unwrap();
        assert_eq!(server.pending_out.len(), MAX_PENDING_OUT);
    }

    #[test]
    fn server_options_will_echo_sga() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let client_thread = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(addr).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_millis(200)))
                .unwrap();
            let mut buf = [0u8; 16];
            let n = stream.read(&mut buf).unwrap();
            buf[..n].to_vec()
        });

        let (stream, _) = listener.accept().unwrap();
        let mut server = TelnetTransport::from_stream(stream, "test-server".into());
        server.send_server_options().unwrap();

        let received = client_thread.join().unwrap();
        assert_eq!(received, vec![IAC, WILL, OPT_ECHO, IAC, WILL, OPT_SGA]);
    }
}

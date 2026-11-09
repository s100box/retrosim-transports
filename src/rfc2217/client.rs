// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Howard M. Harte
//! The client half: [`Rfc2217Transport`], a serial port another process
//! serves over RFC 2217, used like one opened locally.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use retrosim_core::serial::{SerialParams, SerialParity, SerialStopBits};
use retrosim_core::transport::{ModemControl, Transport, TransportError};

use super::*;
use crate::line::Flow;
use crate::wire_output::WireOutput;

/// How long a connection attempt may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_TX: usize = 128 * 1024;
const MAX_RX: usize = 1024 * 1024;
const DRAIN_POLLS: usize = 16;
/// How long the server has to answer a request.
const ANSWER_TIMEOUT: Duration = if cfg!(test) {
    Duration::from_millis(300)
} else {
    Duration::from_secs(3)
};

/// Options this side offers and performs when asked.
const WE_WILL: &[u8] = &[BINARY, SGA, COM_PORT];
/// Options the server may perform.
const THEY_MAY: &[u8] = &[BINARY, ECHO, SGA, COM_PORT];

/// The server's answers are kept by sub-option number, 0..=12.
const ANSWERS: usize = PURGE_DATA as usize + 1;

#[derive(Clone, Copy)]
enum State {
    Data,
    Iac,
    Negotiate(u8),
    Sub,
    SubIac,
}

/// How long one read of the socket may wait.
#[derive(Clone, Copy)]
enum Wait {
    /// Not at all.
    No,
    /// Until data arrives or this long passes (`None`: until data arrives).
    For(Option<Duration>),
}

/// A serial port served over RFC 2217 (for instance by `serbridge`).
///
/// Reads return the port's data with Telnet's escaping removed; writes are
/// escaped. [`Transport::reconfigure`] and [`ModemControl`] become RFC 2217
/// requests, each answered by the server before the call returns, so a
/// setting the server refused comes back as an error rather than going
/// unnoticed. The modem inputs (CTS, DSR, DCD, RI) are the server's latest
/// notification.
///
/// Opening sets nothing the caller did not ask for: DTR and RTS stay as the
/// server has them until [`ModemControl::set_dtr`] or
/// [`ModemControl::set_rts`] is called.
pub struct Rfc2217Transport {
    stream: TcpStream,
    desc: String,
    state: State,
    sb: Subnegotiation,
    we: [bool; 256],
    they: [bool; 256],
    /// Whether the server agreed to COM-PORT-OPTION; `None` until it says.
    com_port: Option<bool>,
    answers: [Option<Vec<u8>>; ANSWERS],
    modem: Option<u8>,
    rx: VecDeque<u8>,
    reply: Vec<u8>,
    tx: WireOutput,
    pending_error: Option<io::Error>,
    timeout: Option<Duration>,
    nonblocking: bool,
    socket_timeout: Option<Duration>,
    connected: bool,
}

impl Rfc2217Transport {
    /// Opens `host:port[@baud[,format[,flow]]]`; an `rfc2217://` prefix is
    /// accepted. The settings take the form a `serial:` spec's do and are
    /// sent to the server; with none, the port keeps the settings it has.
    ///
    /// Examples: `127.0.0.1:4001`, `rfc2217://bench:4001@115200`,
    /// `localhost:4001@9600,7E2,hw`.
    pub fn open(spec: &str) -> Result<Self, TransportError> {
        let spec = spec.strip_prefix("rfc2217://").unwrap_or(spec);
        let (addr, settings) = match spec.split_once('@') {
            Some((addr, rest)) => (addr, Some(crate::line::parse_settings(rest)?)),
            None => (spec, None),
        };
        let addr = addr.trim_end_matches('/');
        if addr.is_empty() {
            return Err(TransportError::InvalidSpec(
                "rfc2217 spec missing host:port".into(),
            ));
        }
        Self::connect_with(
            addr,
            settings.map(|s| s.params),
            settings.map(|s| s.flow),
            format!("rfc2217:{addr}"),
        )
    }

    /// Connects to the server at `addr` (`host:port`) and, if `params` is
    /// given, sets the line to them. Flow control is left as the server has
    /// it.
    pub fn connect(addr: &str, params: Option<&SerialParams>) -> Result<Self, TransportError> {
        Self::connect_with(addr, params.copied(), None, format!("rfc2217:{addr}"))
    }

    pub(crate) fn connect_with(
        addr: &str,
        params: Option<SerialParams>,
        flow: Option<Flow>,
        desc: String,
    ) -> Result<Self, TransportError> {
        let stream = connect_tcp(addr)
            .map_err(|e| TransportError::Transport(format!("rfc2217 {addr}: {e}")))?;
        Self::over(stream, addr, params, flow, desc)
    }

    /// The protocol over a connection already made to `addr`.
    pub(crate) fn over(
        stream: TcpStream,
        addr: &str,
        params: Option<SerialParams>,
        flow: Option<Flow>,
        desc: String,
    ) -> Result<Self, TransportError> {
        let fail = |e: io::Error| TransportError::Transport(format!("rfc2217 {addr}: {e}"));
        stream.set_nodelay(true).map_err(fail)?;
        let mut t = Rfc2217Transport {
            stream,
            desc,
            state: State::Data,
            sb: Subnegotiation::default(),
            we: [false; 256],
            they: [false; 256],
            com_port: None,
            answers: Default::default(),
            modem: None,
            rx: VecDeque::new(),
            reply: Vec::new(),
            tx: WireOutput::new(MAX_TX),
            pending_error: None,
            timeout: None,
            nonblocking: false,
            socket_timeout: None,
            connected: true,
        };
        t.start(params, flow).map_err(fail)?;
        Ok(t)
    }

    /// Negotiates RFC 2217, asks for the modem state and sends the settings,
    /// then waits for every answer.
    fn start(&mut self, params: Option<SerialParams>, flow: Option<Flow>) -> io::Result<()> {
        let mut out = Vec::new();
        for &opt in WE_WILL {
            self.we[opt as usize] = true;
            out.extend([IAC, WILL, opt]);
        }
        for &opt in &[BINARY, SGA, COM_PORT] {
            self.they[opt as usize] = true;
            out.extend([IAC, DO, opt]);
        }
        let mut asked = Vec::new();
        if let Some(p) = params {
            asked.extend(settings_requests(&p));
        }
        if let Some(f) = flow {
            asked.push((SET_CONTROL, vec![flow_code(f)]));
        }
        for (code, value) in &asked {
            subnegotiation(&mut out, *code, value);
        }
        // A poll: the answer is the modem state, so the inputs read correctly
        // from the start.
        subnegotiation(&mut out, NOTIFY_MODEMSTATE, &[]);
        self.send(&out)?;
        self.wait_until("RFC 2217 negotiation", |t| {
            t.com_port == Some(false)
                || (t.com_port == Some(true)
                    && t.modem.is_some()
                    && asked.iter().all(|(c, _)| t.answers[*c as usize].is_some()))
        })?;
        if self.com_port == Some(false) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "the server refused COM-PORT-OPTION: not an RFC 2217 server",
            ));
        }
        self.check(&asked)
    }

    /// Discards data not yet read: on this side, and in the server's buffers
    /// as `rx` and `tx` say.
    pub fn purge(&mut self, rx: bool, tx: bool) -> io::Result<()> {
        if rx {
            self.drain()?;
            self.rx.clear();
        }
        let code = u8::from(rx) | u8::from(tx) << 1;
        if code == 0 {
            return Ok(());
        }
        self.request(&[(PURGE_DATA, vec![code])])
    }

    /// The server's signature (serbridge answers `serbridge`).
    pub fn signature(&mut self) -> io::Result<String> {
        self.answers[SIGNATURE as usize] = None;
        let mut out = Vec::new();
        subnegotiation(&mut out, SIGNATURE, &[]);
        self.send(&out)?;
        self.wait_until("SIGNATURE", |t| t.answers[SIGNATURE as usize].is_some())?;
        let v = self.answers[SIGNATURE as usize].take().unwrap_or_default();
        Ok(String::from_utf8_lossy(&v).into_owned())
    }

    /// Sends requests, waits for every answer and checks each one.
    fn request(&mut self, asked: &[(u8, Vec<u8>)]) -> io::Result<()> {
        let mut out = Vec::new();
        for (code, value) in asked {
            self.answers[*code as usize] = None;
            subnegotiation(&mut out, *code, value);
        }
        self.send(&out)?;
        self.wait_until("a request", |t| {
            asked.iter().all(|(c, _)| t.answers[*c as usize].is_some())
        })?;
        self.check(asked)
    }

    /// A server refuses a request by answering with the value in effect, so
    /// any answer that differs from the request is a refusal.
    fn check(&self, asked: &[(u8, Vec<u8>)]) -> io::Result<()> {
        for (code, value) in asked {
            let got = self.answers[*code as usize].as_deref().unwrap_or(&[]);
            // Zero-valued line settings query the current value; a differing
            // answer is expected, rather than a refusal to set the line to zero.
            let query = matches!(
                (*code, value.as_slice()),
                (SET_BAUDRATE, [0, 0, 0, 0]) | (SET_DATASIZE | SET_PARITY | SET_STOPSIZE, [0])
            );
            if query && got.len() == value.len() {
                continue;
            }
            if got != value.as_slice() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "{}: the server refused {} {} (in effect: {})",
                        self.desc,
                        name(*code),
                        show(*code, value),
                        show(*code, got)
                    ),
                ));
            }
        }
        Ok(())
    }

    /// Reads the socket until `done` holds, or fails after ANSWER_TIMEOUT.
    fn wait_until(&mut self, what: &str, done: impl Fn(&Self) -> bool) -> io::Result<()> {
        let deadline = Instant::now() + ANSWER_TIMEOUT;
        while !done(self) {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("{}: no answer to {what}", self.desc),
                ));
            }
            match self.pump(Wait::For(Some(left))) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!("{}: the server closed the connection", self.desc),
                    ))
                }
                Ok(_) => {}
                Err(e) if quiet(&e) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Poll a bounded amount of input for modem notifications. Leave room for
    /// normal reads to consume serial data instead of growing without bound.
    fn drain(&mut self) -> io::Result<()> {
        self.drain_with(Self::pump)
    }

    fn drain_with(
        &mut self,
        mut pump: impl FnMut(&mut Self, Wait) -> io::Result<usize>,
    ) -> io::Result<()> {
        for _ in 0..DRAIN_POLLS {
            if !self.connected || self.rx.len() >= MAX_RX {
                break;
            }
            match pump(self, Wait::No) {
                Ok(0) => return Ok(()),
                Ok(_) => {}
                Err(e) if quiet(&e) => return Ok(()),
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// One read of the socket, decoded. Returns the number of bytes read;
    /// 0 is the end of the connection.
    fn pump(&mut self, wait: Wait) -> io::Result<usize> {
        match self.poll_output() {
            Err(error) if quiet(&error) && !self.reply.is_empty() => return Err(error),
            Err(error) if quiet(&error) => {}
            Err(error) => return Err(self.lost(error)),
            Ok(()) => {}
        }
        match wait {
            Wait::No => self.set_nonblocking(true)?,
            Wait::For(t) => {
                self.set_nonblocking(false)?;
                if self.socket_timeout != t {
                    self.stream.set_read_timeout(t)?;
                    self.socket_timeout = t;
                }
            }
        }
        let mut buf = [0u8; 4096];
        let n = self.stream.read(&mut buf).map_err(|e| self.lost(e))?;
        if n == 0 {
            self.connected = false;
            return Ok(0);
        }
        self.decode(&buf[..n]).map_err(|error| self.lost(error))?;
        if let Err(error) = self.poll_output() {
            if !quiet(&error) {
                let error = self.lost(error);
                if self.rx.is_empty() {
                    return Err(error);
                }
                self.pending_error = Some(error);
            }
        }
        Ok(n)
    }

    fn set_nonblocking(&mut self, on: bool) -> io::Result<()> {
        if self.nonblocking != on {
            self.stream.set_nonblocking(on)?;
            self.nonblocking = on;
        }
        Ok(())
    }

    fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        if let Some(error) = self.pending_error.take() {
            return Err(error);
        }
        if !self.connected {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let started = Instant::now();
        let mut remaining = bytes;
        while !remaining.is_empty() {
            self.flush_until(started)?;
            let count = self.tx.push_raw(remaining);
            remaining = &remaining[count..];
        }
        self.flush_until(started)
    }

    /// Advance queued wire bytes without blocking a read or modem poll.
    fn poll_output(&mut self) -> io::Result<()> {
        if self.tx.is_empty() && self.reply.is_empty() {
            return Ok(());
        }
        self.set_nonblocking(true)?;
        let count = self.tx.push_raw(&self.reply);
        self.reply.drain(..count);
        self.tx.flush(&mut self.stream)?;
        if self.reply.is_empty() {
            Ok(())
        } else {
            Err(io::ErrorKind::WouldBlock.into())
        }
    }

    /// Control requests and explicit flushes get a fixed send budget, including
    /// backpressure. Socket writes stay nonblocking so the deadline is real.
    fn flush_until(&mut self, started: Instant) -> io::Result<()> {
        self.flush_with(started, Self::poll_output)
    }

    fn flush_with(
        &mut self,
        started: Instant,
        mut poll: impl FnMut(&mut Self) -> io::Result<()>,
    ) -> io::Result<()> {
        while !self.tx.is_empty() || !self.reply.is_empty() {
            if started.elapsed() >= ANSWER_TIMEOUT {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "RFC 2217 output remained blocked",
                ));
            }
            match poll(self) {
                Ok(()) => {}
                Err(error) if quiet(&error) => std::thread::sleep(Duration::from_millis(1)),
                Err(error) => return Err(self.lost(error)),
            }
        }
        Ok(())
    }

    /// A socket error other than a read finding nothing means the
    /// connection is gone; later reads then return end of stream, and the
    /// modem inputs keep their last state.
    fn lost(&mut self, e: io::Error) -> io::Error {
        if !quiet(&e) {
            self.connected = false;
        }
        e
    }

    fn decode(&mut self, input: &[u8]) -> io::Result<()> {
        for &b in input {
            self.state = match self.state {
                State::Data if b == IAC => State::Iac,
                State::Data => {
                    self.receive_byte(b)?;
                    State::Data
                }
                State::Iac => match b {
                    IAC => {
                        self.receive_byte(IAC)?;
                        State::Data
                    }
                    SB => {
                        self.sb.clear();
                        State::Sub
                    }
                    DO | DONT | WILL | WONT => State::Negotiate(b),
                    // NOP, GA and the rest carry nothing for a port.
                    _ => State::Data,
                },
                State::Negotiate(cmd) => {
                    self.negotiate(cmd, b);
                    State::Data
                }
                State::Sub if b == IAC => State::SubIac,
                State::Sub => {
                    self.sb.push(b);
                    State::Sub
                }
                State::SubIac => match b {
                    IAC => {
                        self.sb.push(IAC);
                        State::Sub
                    }
                    SE => {
                        self.subnegotiated();
                        State::Data
                    }
                    // Malformed: drop the sub-negotiation.
                    _ => State::Data,
                },
            };
        }
        Ok(())
    }

    fn receive_byte(&mut self, byte: u8) -> io::Result<()> {
        if self.rx.len() >= MAX_RX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "RFC 2217 unread serial data exceeded the 1 MiB receive limit",
            ));
        }
        self.rx.push_back(byte);
        Ok(())
    }

    /// Answers a request only when it changes an option's state, as the
    /// server does, so the two never loop.
    fn negotiate(&mut self, cmd: u8, opt: u8) {
        let i = opt as usize;
        if opt == COM_PORT {
            if cmd == DO || cmd == WILL {
                self.com_port = Some(true);
            } else if self.com_port.is_none() {
                self.com_port = Some(false);
            }
        }
        match cmd {
            DO if WE_WILL.contains(&opt) && !self.we[i] => {
                self.we[i] = true;
                self.reply.extend([IAC, WILL, opt]);
            }
            DO if WE_WILL.contains(&opt) => {}
            DO => self.reply.extend([IAC, WONT, opt]),
            DONT if self.we[i] => {
                self.we[i] = false;
                self.reply.extend([IAC, WONT, opt]);
            }
            WILL if THEY_MAY.contains(&opt) && !self.they[i] => {
                self.they[i] = true;
                self.reply.extend([IAC, DO, opt]);
            }
            WILL if THEY_MAY.contains(&opt) => {}
            WILL => self.reply.extend([IAC, DONT, opt]),
            WONT if self.they[i] => {
                self.they[i] = false;
                self.reply.extend([IAC, DONT, opt]);
            }
            _ => {}
        }
    }

    /// A complete sub-negotiation from the server: an answer, or a
    /// modem-state notification.
    fn subnegotiated(&mut self) {
        let Some(sb) = self.sb.take() else { return };
        let [COM_PORT, code, ref value @ ..] = sb[..] else {
            return;
        };
        let Some(code) = code.checked_sub(SERVER) else {
            return;
        };
        if code == NOTIFY_MODEMSTATE {
            if let Some(&m) = value.first() {
                self.modem = Some(m);
            }
        }
        if let Some(slot) = self.answers.get_mut(code as usize) {
            *slot = Some(value.to_vec());
        }
    }

    /// One modem input, after taking in any notification already sent.
    fn modem_bit(&mut self, bit: u8) -> io::Result<bool> {
        self.drain()?;
        Ok(self.modem.unwrap_or(0) & bit != 0)
    }

    fn control(&mut self, code: u8) -> io::Result<()> {
        self.request(&[(SET_CONTROL, vec![code])])
    }
}

/// Connects to the first address `addr` resolves to that answers.
pub(crate) fn connect_tcp(addr: &str) -> io::Result<TcpStream> {
    let mut last = None;
    for a in addr.to_socket_addrs()? {
        match TcpStream::connect_timeout(&a, CONNECT_TIMEOUT) {
            Ok(s) => return Ok(s),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "the address resolved to nothing",
        )
    }))
}

/// A read that found nothing to read: not an error for a caller that loops.
fn quiet(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

/// The requests that set the line to `p`.
fn settings_requests(p: &SerialParams) -> Vec<(u8, Vec<u8>)> {
    let parity = match p.parity {
        SerialParity::None => 1,
        SerialParity::Odd => 2,
        SerialParity::Even => 3,
    };
    let stop = match p.stop_bits {
        SerialStopBits::One => 1,
        SerialStopBits::Two => 2,
        SerialStopBits::OnePointFive => 3,
    };
    vec![
        (SET_BAUDRATE, p.baud_rate.to_be_bytes().to_vec()),
        (SET_DATASIZE, vec![p.data_bits]),
        (SET_PARITY, vec![parity]),
        (SET_STOPSIZE, vec![stop]),
    ]
}

fn flow_code(f: Flow) -> u8 {
    match f {
        Flow::None => 1,
        Flow::Software => 2,
        Flow::Hardware => 3,
    }
}

fn name(code: u8) -> &'static str {
    match code {
        SET_BAUDRATE => "baud rate",
        SET_DATASIZE => "data size",
        SET_PARITY => "parity",
        SET_STOPSIZE => "stop size",
        SET_CONTROL => "control",
        PURGE_DATA => "purge",
        _ => "request",
    }
}

fn show(code: u8, v: &[u8]) -> String {
    match (code, v) {
        (SET_BAUDRATE, &[a, b, c, d]) => u32::from_be_bytes([a, b, c, d]).to_string(),
        (_, &[x]) => x.to_string(),
        _ => format!("{v:?}"),
    }
}

impl Read for Rfc2217Transport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let started = Instant::now();
        while self.rx.is_empty() {
            if let Some(error) = self.pending_error.take() {
                return Err(error);
            }
            if !self.connected {
                return Ok(0);
            }
            let wait = match self.timeout {
                None => Wait::For(None),
                Some(duration) if duration.is_zero() => Wait::No,
                Some(duration) => {
                    let left = duration
                        .checked_sub(started.elapsed())
                        .filter(|left| !left.is_zero())
                        .ok_or(io::ErrorKind::TimedOut)?;
                    Wait::For(Some(left))
                }
            };
            match self.pump(wait) {
                Ok(0) => return Ok(0),
                Ok(_) if self.rx.is_empty() && self.timeout == Some(Duration::ZERO) => {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                Ok(_) => {}
                Err(e) if quiet(&e) => {
                    if self.timeout == Some(Duration::ZERO) {
                        return Err(io::ErrorKind::WouldBlock.into());
                    }
                    // A blocked output queue can prevent another socket read.
                    // Keep the original read budget and avoid a busy retry loop.
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(e) => return Err(e),
            }
        }
        let n = buf.len().min(self.rx.len());
        for (dst, src) in buf.iter_mut().zip(self.rx.drain(..n)) {
            *dst = src;
        }
        Ok(n)
    }
}

impl Write for Rfc2217Transport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if let Some(error) = self.pending_error.take() {
            return Err(error);
        }
        if !self.connected {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        if let Err(error) = self.poll_output() {
            if !quiet(&error) {
                return Err(self.lost(error));
            }
            if !self.reply.is_empty() {
                return Err(io::ErrorKind::WouldBlock.into());
            }
        }
        let count = self.tx.push_data(buf);
        if count == 0 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        if let Err(error) = self.poll_output() {
            if !quiet(&error) {
                self.pending_error = Some(self.lost(error));
            }
        }
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(error) = self.pending_error.take() {
            return Err(error);
        }
        self.flush_until(Instant::now())?;
        self.stream.flush()
    }
}

impl Transport for Rfc2217Transport {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.timeout = timeout;
        Ok(())
    }

    fn description(&self) -> &str {
        &self.desc
    }

    fn is_connected(&self) -> bool {
        self.connected
    }

    fn reconfigure(&mut self, params: &SerialParams) -> io::Result<()> {
        self.request(&settings_requests(params))
    }

    fn modem_control(&mut self) -> Option<&mut dyn ModemControl> {
        Some(self)
    }
}

impl ModemControl for Rfc2217Transport {
    fn set_dtr(&mut self, active: bool) -> io::Result<()> {
        self.control(if active { 8 } else { 9 })
    }

    fn set_rts(&mut self, active: bool) -> io::Result<()> {
        self.control(if active { 11 } else { 12 })
    }

    fn set_break(&mut self, active: bool) -> io::Result<()> {
        self.control(if active { 5 } else { 6 })
    }

    fn read_cts(&mut self) -> io::Result<bool> {
        self.modem_bit(0x10)
    }

    fn read_dsr(&mut self) -> io::Result<bool> {
        self.modem_bit(0x20)
    }

    fn read_dcd(&mut self) -> io::Result<bool> {
        self.modem_bit(0x80)
    }

    fn read_ri(&mut self) -> io::Result<bool> {
        self.modem_bit(0x40)
    }
}

#[cfg(test)]
#[path = "client_tests.rs"]
pub(crate) mod tests;

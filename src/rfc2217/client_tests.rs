// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Howard M. Harte
//! The client against an in-process server built on [`Session`], and against
//! servers that misbehave in the ways a real network peer can.

use super::*;
use crate::rfc2217::{Device, Session};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;

/// The port behind the test server, shared with the test for inspection.
#[derive(Default)]
pub(crate) struct Port {
    pub baud: u32,
    pub data: u8,
    pub parity: u8,
    pub stop: u8,
    pub flow: u8,
    dtr: Option<bool>,
    rts: Option<bool>,
    brk: Option<bool>,
    purged: Vec<u8>,
    modem: u8,
    pub refuse_baud: Option<u32>,
    refuse_parity: bool,
    /// Everything the client sent, as it arrived (Telnet escaping and all).
    raw: Vec<u8>,
    /// Bytes the server sends the client as they are, unescaped.
    push: Vec<u8>,
    /// Drop the connection at the next turn of the server's loop.
    hang_up: bool,
}

pub(crate) type Shared = Arc<Mutex<Port>>;

struct Dev(Shared);

impl Device for Dev {
    fn baud(&mut self, rate: u32) -> u32 {
        let mut p = self.0.lock().unwrap();
        if rate != 0 && Some(rate) != p.refuse_baud {
            p.baud = rate;
        }
        p.baud
    }
    fn data_size(&mut self, bits: u8) -> u8 {
        let mut p = self.0.lock().unwrap();
        if (5..=8).contains(&bits) {
            p.data = bits;
        }
        p.data
    }
    fn parity(&mut self, code: u8) -> u8 {
        let mut p = self.0.lock().unwrap();
        if (1..=5).contains(&code) && !p.refuse_parity {
            p.parity = code;
        }
        p.parity
    }
    fn stop_size(&mut self, code: u8) -> u8 {
        let mut p = self.0.lock().unwrap();
        if (1..=3).contains(&code) {
            p.stop = code;
        }
        p.stop
    }
    fn control(&mut self, code: u8) -> u8 {
        let mut p = self.0.lock().unwrap();
        match code {
            1..=3 => {
                p.flow = code;
                code
            }
            5 | 6 => {
                p.brk = Some(code == 5);
                code
            }
            8 | 9 => {
                p.dtr = Some(code == 8);
                code
            }
            11 | 12 => {
                p.rts = Some(code == 11);
                code
            }
            _ => p.flow,
        }
    }
    fn purge(&mut self, code: u8) {
        self.0.lock().unwrap().purged.push(code);
    }
    fn modem_state(&mut self) -> u8 {
        self.0.lock().unwrap().modem
    }
}

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Mode {
    /// An RFC 2217 server whose port echoes what it is sent.
    Echo,
    /// A Telnet server that refuses every option.
    PlainTelnet,
    /// Reads and never answers.
    Silent,
    /// Accepts and closes at once.
    Close,
}

pub(crate) struct Server {
    pub addr: String,
    pub port: Shared,
}

pub(crate) fn serve(mode: Mode) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let port: Shared = Arc::default();
    let shared = port.clone();
    thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        if mode == Mode::Close {
            return;
        }
        s.set_read_timeout(Some(Duration::from_millis(5))).unwrap();
        let mut session = Session::with_signature("serbridge");
        let mut dev = Dev(shared.clone());
        let mut buf = [0u8; 4096];
        loop {
            let push = std::mem::take(&mut shared.lock().unwrap().push);
            if !push.is_empty() && s.write_all(&push).is_err() {
                return;
            }
            if shared.lock().unwrap().hang_up {
                return;
            }
            let n = match s.read(&mut buf) {
                Ok(0) => return,
                Ok(n) => n,
                Err(e) if quiet(&e) => 0,
                Err(_) => return,
            };
            shared.lock().unwrap().raw.extend_from_slice(&buf[..n]);
            let (mut data, mut reply) = (Vec::new(), Vec::new());
            match mode {
                Mode::Echo => {
                    session.feed(&buf[..n], &mut dev, &mut data, &mut reply);
                    escape(&data, &mut reply);
                    let modem = shared.lock().unwrap().modem;
                    session.modem_changed(modem, &mut reply);
                }
                Mode::PlainTelnet => {
                    for w in buf[..n].windows(3) {
                        match *w {
                            [IAC, DO, opt] => reply.extend([IAC, WONT, opt]),
                            [IAC, WILL, opt] => reply.extend([IAC, DONT, opt]),
                            _ => {}
                        }
                    }
                }
                Mode::Silent | Mode::Close => {}
            }
            if !reply.is_empty() && s.write_all(&reply).is_err() {
                return;
            }
        }
    });
    Server { addr, port }
}

fn open(spec: &str) -> Rfc2217Transport {
    Rfc2217Transport::open(spec).unwrap()
}

#[test]
fn control_only_polling_reads_one_chunk_then_yields() {
    let server = serve(Mode::Echo);
    let mut transport = open(&server.addr);
    let mut input = Vec::new();
    for _ in 0..2048 {
        input.extend([IAC, 241]);
    }
    input.extend(b"tail");
    server.port.lock().unwrap().push.extend(&input);
    transport.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut peek = vec![0; input.len()];
    loop {
        if transport
            .stream
            .peek(&mut peek)
            .is_ok_and(|count| count == input.len())
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "control fixture did not reach the socket"
        );
        thread::sleep(Duration::from_millis(1));
    }
    transport.set_read_timeout(Some(Duration::ZERO)).unwrap();
    assert_eq!(
        transport.read(&mut [0; 4]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    let mut data = [0; 4];
    assert_eq!(transport.read(&mut data).unwrap(), 4);
    assert_eq!(&data, b"tail");
}

#[test]
fn modem_polling_limits_work_even_when_control_traffic_never_stops() {
    let server = serve(Mode::Echo);
    let mut transport = open(&server.addr);
    let mut polls = 0;
    transport
        .drain_with(|_, wait| {
            assert!(matches!(wait, Wait::No));
            polls += 1;
            Ok(4096)
        })
        .unwrap();
    assert_eq!(polls, DRAIN_POLLS);
}

#[test]
fn modem_polling_stops_at_the_receive_limit_and_reads_release_backpressure() {
    let server = serve(Mode::Echo);
    let mut transport = open(&server.addr);
    transport.decode(&vec![b'x'; MAX_RX]).unwrap();
    transport
        .drain_with(|_, _| panic!("must consume buffered serial data first"))
        .unwrap();
    let mut data = vec![0; MAX_RX];
    assert_eq!(transport.read(&mut data).unwrap(), MAX_RX);
    assert!(data.iter().all(|&byte| byte == b'x'));
    server.port.lock().unwrap().push.push(b'y');
    assert_eq!(read_n(&mut transport, 1), b"y");
}

#[test]
fn receive_overflow_is_an_error_instead_of_unbounded_allocation() {
    let server = serve(Mode::Echo);
    let mut transport = open(&server.addr);
    transport.decode(&vec![b'x'; MAX_RX]).unwrap();
    server.port.lock().unwrap().push.push(b'y');
    let error = loop {
        match transport.pump(Wait::For(Some(Duration::from_secs(1)))) {
            Ok(_) => {}
            Err(error) => break error,
        }
    };
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(transport.rx.len(), MAX_RX);
    assert!(!transport.is_connected());
}

#[test]
fn blocked_output_times_out_without_discarding_accepted_bytes() {
    let server = serve(Mode::Echo);
    let mut transport = open(&server.addr);
    assert_eq!(transport.tx.push_data(b"retry"), 5);
    let started = Instant::now();
    let error = transport
        .flush_with(started, |_| Err(io::ErrorKind::WouldBlock.into()))
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(started.elapsed() >= ANSWER_TIMEOUT);
    assert!(!transport.tx.is_empty());
    transport.flush().unwrap();
    assert_eq!(read_n(&mut transport, 5), b"retry");
}

#[test]
fn data_writes_report_the_unescaped_prefix_that_fits_the_wire_queue() {
    let server = serve(Mode::Echo);
    let mut transport = open(&server.addr);
    transport.tx = WireOutput::new(3);
    assert_eq!(transport.write(&[b'a', IAC, b'b']).unwrap(), 2);
    assert_eq!(transport.write(b"b").unwrap(), 1);
    transport.flush().unwrap();
    assert_eq!(read_n(&mut transport, 3), [b'a', IAC, b'b']);
}

#[test]
fn oversized_notifications_do_not_update_modem_state_or_leak_data() {
    let server = serve(Mode::Echo);
    let mut transport = open(&server.addr);
    assert_eq!(transport.modem, Some(0));
    let mut input = Vec::new();
    subnegotiation(
        &mut input,
        SERVER + NOTIFY_MODEMSTATE,
        &vec![0x30; SB_MAX + 1],
    );
    input.extend(b"still data");
    for chunk in input.chunks(7) {
        transport.decode(chunk).unwrap();
    }
    assert_eq!(transport.modem, Some(0));
    assert_eq!(transport.rx.into_iter().collect::<Vec<_>>(), b"still data");
}

fn err(r: Result<Rfc2217Transport, TransportError>) -> String {
    match r {
        Ok(_) => panic!("opened"),
        Err(e) => e.to_string(),
    }
}

/// Reads until `want` bytes arrived or two seconds passed.
fn read_n(t: &mut Rfc2217Transport, want: usize) -> Vec<u8> {
    t.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut got = Vec::new();
    let mut buf = [0u8; 64];
    while got.len() < want && Instant::now() < deadline {
        match t.read(&mut buf) {
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == io::ErrorKind::TimedOut => {}
            Err(e) => panic!("{e}"),
        }
    }
    got
}

/// Waits for the server to have seen something.
fn until(port: &Shared, what: impl Fn(&Port) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !what(&port.lock().unwrap()) {
        assert!(Instant::now() < deadline, "the server never got there");
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn open_negotiates_and_learns_the_modem_state() {
    let s = serve(Mode::Echo);
    s.port.lock().unwrap().modem = 0x30;
    let mut t = open(&s.addr);
    assert_eq!(t.description(), format!("rfc2217:{}", s.addr));
    assert!(t.is_connected());
    assert!(!t.is_listening());
    let m = t.modem_control().unwrap();
    assert!(m.read_cts().unwrap());
    assert!(m.read_dsr().unwrap());
    assert!(!m.read_dcd().unwrap());
    assert!(!m.read_ri().unwrap());
    // WILL and DO for BINARY, SGA and COM-PORT, then the modem-state poll.
    let raw = s.port.lock().unwrap().raw.clone();
    assert!(raw.starts_with(&[
        IAC, WILL, BINARY, IAC, WILL, SGA, IAC, WILL, COM_PORT, IAC, DO, BINARY, IAC, DO, SGA, IAC,
        DO, COM_PORT
    ]));
}

#[test]
fn opening_without_settings_changes_nothing() {
    let s = serve(Mode::Echo);
    let _t = open(&s.addr);
    let p = s.port.lock().unwrap();
    assert_eq!((p.baud, p.data, p.parity, p.stop, p.flow), (0, 0, 0, 0, 0));
    assert_eq!((p.dtr, p.rts, p.brk), (None, None, None));
}

#[test]
fn spec_settings_reach_the_port() {
    let s = serve(Mode::Echo);
    let _t = open(&format!("rfc2217://{}/@9600,7E2,hw", s.addr));
    let p = s.port.lock().unwrap();
    assert_eq!(
        (p.baud, p.data, p.parity, p.stop, p.flow),
        (9600, 7, 3, 2, 3)
    );
}

#[test]
fn software_flow_and_odd_parity() {
    let s = serve(Mode::Echo);
    let _t = open(&format!("{}@1200,8O1,sw", s.addr));
    let p = s.port.lock().unwrap();
    assert_eq!((p.parity, p.stop, p.flow), (2, 1, 2));
}

#[test]
fn connect_sets_params_but_not_flow() {
    let s = serve(Mode::Echo);
    let params = SerialParams {
        baud_rate: 115_200,
        data_bits: 8,
        parity: SerialParity::None,
        stop_bits: SerialStopBits::OnePointFive,
    };
    let _t = Rfc2217Transport::connect(&s.addr, Some(&params)).unwrap();
    let p = s.port.lock().unwrap();
    assert_eq!(
        (p.baud, p.data, p.parity, p.stop, p.flow),
        (115_200, 8, 1, 3, 0)
    );
}

#[test]
fn zero_line_settings_query_the_current_value_instead_of_being_refused() {
    let server = serve(Mode::Echo);
    {
        let mut port = server.port.lock().unwrap();
        port.baud = 9600;
        port.data = 8;
    }
    let params = SerialParams {
        baud_rate: 0,
        data_bits: 0,
        parity: SerialParity::None,
        stop_bits: SerialStopBits::One,
    };
    let mut transport = Rfc2217Transport::connect(&server.addr, Some(&params)).unwrap();
    transport.reconfigure(&params).unwrap();
    let port = server.port.lock().unwrap();
    assert_eq!((port.baud, port.data), (9600, 8));
    assert_eq!(
        transport.answers[SET_BAUDRATE as usize].as_deref(),
        Some(9600u32.to_be_bytes().as_slice())
    );
}

#[test]
fn a_refused_baud_rate_fails_the_open() {
    let s = serve(Mode::Echo);
    {
        let mut p = s.port.lock().unwrap();
        p.baud = 115_200;
        p.refuse_baud = Some(12_345);
    }
    let e = err(Rfc2217Transport::open(&format!("{}@12345", s.addr)));
    assert!(
        e.contains("refused baud rate 12345 (in effect: 115200)"),
        "{e}"
    );
}

#[test]
fn reconfigure_sets_the_line_and_reports_a_refusal() {
    let s = serve(Mode::Echo);
    let mut t = open(&s.addr);
    let mut params = SerialParams {
        baud_rate: 300,
        data_bits: 5,
        parity: SerialParity::Odd,
        stop_bits: SerialStopBits::Two,
    };
    t.reconfigure(&params).unwrap();
    {
        let p = s.port.lock().unwrap();
        assert_eq!((p.baud, p.data, p.parity, p.stop), (300, 5, 2, 2));
    }
    s.port.lock().unwrap().refuse_parity = true;
    params.parity = SerialParity::Even;
    let e = t.reconfigure(&params).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
    assert!(
        e.to_string().contains("refused parity 3 (in effect: 2)"),
        "{e}"
    );
}

#[test]
fn every_byte_value_crosses_both_ways() {
    let s = serve(Mode::Echo);
    let mut t = open(&s.addr);
    let all: Vec<u8> = (0..=255).collect();
    t.write_all(&all).unwrap();
    t.flush().unwrap();
    assert_eq!(read_n(&mut t, 256), all);
    // The 0xFF went out doubled.
    let raw = s.port.lock().unwrap().raw.clone();
    assert!(raw.windows(3).any(|w| w == [0xFE, IAC, IAC]));
}

#[test]
fn reads_honor_the_timeout() {
    let s = serve(Mode::Echo);
    let mut t = open(&s.addr);
    let mut buf = [0u8; 8];
    assert_eq!(t.read(&mut []).unwrap(), 0);

    t.set_read_timeout(Some(Duration::ZERO)).unwrap();
    let start = Instant::now();
    assert_eq!(
        t.read(&mut buf).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert!(start.elapsed() < Duration::from_millis(100));

    t.set_read_timeout(Some(Duration::from_millis(60))).unwrap();
    let start = Instant::now();
    assert_eq!(
        t.read(&mut buf).unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert!(start.elapsed() >= Duration::from_millis(50));

    // No timeout: the read waits for the data.
    let port = s.port.clone();
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(100));
        port.lock().unwrap().push.extend_from_slice(b"late");
    });
    t.set_read_timeout(None).unwrap();
    let n = t.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"late");

    // A short buffer leaves the rest for the next read.
    s.port.lock().unwrap().push.extend_from_slice(b"abcdef");
    let mut two = [0u8; 2];
    assert_eq!(t.read(&mut two).unwrap(), 2);
    assert_eq!(&two, b"ab");
    assert_eq!(read_n(&mut t, 4), b"cdef");
}

#[test]
fn modem_outputs_reach_the_port() {
    let s = serve(Mode::Echo);
    let mut t = open(&s.addr);
    let m = t.modem_control().unwrap();
    m.set_dtr(true).unwrap();
    m.set_rts(false).unwrap();
    m.set_break(true).unwrap();
    {
        let p = s.port.lock().unwrap();
        assert_eq!((p.dtr, p.rts, p.brk), (Some(true), Some(false), Some(true)));
    }
    m.set_dtr(false).unwrap();
    m.set_rts(true).unwrap();
    m.set_break(false).unwrap();
    let p = s.port.lock().unwrap();
    assert_eq!(
        (p.dtr, p.rts, p.brk),
        (Some(false), Some(true), Some(false))
    );
}

#[test]
fn modem_inputs_follow_the_notifications() {
    let s = serve(Mode::Echo);
    let mut t = open(&s.addr);
    assert!(!t.read_dcd().unwrap());
    s.port.lock().unwrap().modem = 0xC0;
    let deadline = Instant::now() + Duration::from_secs(2);
    while !t.read_dcd().unwrap() {
        assert!(Instant::now() < deadline, "no notification");
        thread::sleep(Duration::from_millis(5));
    }
    assert!(t.read_ri().unwrap());
    assert!(!t.read_cts().unwrap());
}

#[test]
fn purge_clears_both_sides() {
    let s = serve(Mode::Echo);
    let mut t = open(&s.addr);
    s.port.lock().unwrap().push.extend_from_slice(b"stale");
    until(&s.port, |p| p.push.is_empty());
    thread::sleep(Duration::from_millis(20));
    t.purge(true, true).unwrap();
    t.purge(false, false).unwrap();
    t.purge(false, true).unwrap();
    assert_eq!(s.port.lock().unwrap().purged, [3, 2]);
    t.set_read_timeout(Some(Duration::ZERO)).unwrap();
    assert!(t.read(&mut [0u8; 8]).is_err(), "the stale data survived");
}

#[test]
fn signature_is_the_servers() {
    let s = serve(Mode::Echo);
    let mut t = open(&s.addr);
    assert_eq!(t.signature().unwrap(), "serbridge");
}

#[test]
fn telnet_noise_is_decoded_not_delivered() {
    let s = serve(Mode::Echo);
    let mut t = open(&s.addr);
    s.port.lock().unwrap().push.extend_from_slice(&[
        b'a',
        IAC,
        241, // NOP
        b'b',
        IAC,
        IAC, // a data 0xFF
        IAC,
        SB,
        24,
        1,
        IAC,
        SE, // not COM-PORT: ignored
        IAC,
        SB,
        COM_PORT,
        1,
        IAC,
        7, // malformed: dropped
        b'c',
        IAC,
        SB,
        COM_PORT,
        99,
        IAC,
        SE, // not an answer
        IAC,
        SB,
        COM_PORT,
        150,
        IAC,
        SE, // an answer to nothing known
        IAC,
        SB,
        COM_PORT,
        SERVER + NOTIFY_MODEMSTATE,
        IAC,
        SE, // empty notification
        b'd',
    ]);
    assert_eq!(read_n(&mut t, 5), [b'a', b'b', IAC, b'c', b'd']);
    // A frame beyond our resource limit is discarded through its terminator.
    let mut long = vec![IAC, SB, COM_PORT, SERVER + SIGNATURE];
    long.extend(std::iter::repeat_n(b'x', SB_MAX * 2));
    long.extend([IAC, IAC, IAC, SE, b'e']);
    s.port.lock().unwrap().push.extend(long);
    assert_eq!(read_n(&mut t, 1), b"e");
}

#[test]
fn an_answer_may_carry_an_escaped_iac() {
    let s = serve(Mode::Echo);
    let mut t = open(&s.addr);
    let mut push = Vec::new();
    subnegotiation(
        &mut push,
        SERVER + SET_BAUDRATE,
        &0x0001_C2FFu32.to_be_bytes(),
    );
    push.push(b'q');
    s.port.lock().unwrap().push.extend(push);
    assert_eq!(read_n(&mut t, 1), b"q");
    assert_eq!(
        t.answers[SET_BAUDRATE as usize].as_deref(),
        Some(&0x0001_C2FFu32.to_be_bytes()[..])
    );
}

#[test]
fn a_hang_up_during_a_request_is_an_error() {
    let s = serve(Mode::Echo);
    let mut t = open(&s.addr);
    s.port.lock().unwrap().hang_up = true;
    thread::sleep(Duration::from_millis(100));
    // The modem lines are read from what has arrived; the end of the
    // connection is noticed, not reported.
    assert!(!t.read_cts().unwrap());
    let e = t.signature().unwrap_err();
    assert!(
        matches!(
            e.kind(),
            io::ErrorKind::UnexpectedEof
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::BrokenPipe
        ),
        "{e}"
    );
    assert!(!t.is_connected());
}

#[test]
fn negotiation_answers_only_changes() {
    let s = serve(Mode::Echo);
    let mut t = open(&s.addr);
    let before = s.port.lock().unwrap().raw.len();
    s.port.lock().unwrap().push.extend_from_slice(&[
        IAC, DO, 24, // refused: WONT 24
        IAC, WILL, 31, // refused: DONT 31
        IAC, DO, BINARY, // already agreed: no answer
        IAC, WILL, ECHO, // accepted: DO ECHO
        IAC, WILL, ECHO, // already agreed: no answer
        IAC, DONT, SGA, // withdrawn: WONT SGA
        IAC, DONT, SGA, // already off: no answer
        IAC, DO, SGA, // asked again: WILL SGA
        IAC, WONT, ECHO, // withdrawn: DONT ECHO
        IAC, WONT, ECHO, // already off: no answer
        b'z',
    ]);
    assert_eq!(read_n(&mut t, 1), b"z");
    let want = [
        IAC, WONT, 24, IAC, DONT, 31, IAC, DO, ECHO, IAC, WONT, SGA, IAC, WILL, SGA, IAC, DONT,
        ECHO,
    ];
    until(&s.port, |p| p.raw.len() >= before + want.len());
    assert_eq!(s.port.lock().unwrap().raw[before..], want);
}

#[test]
fn a_plain_telnet_server_is_refused() {
    let s = serve(Mode::PlainTelnet);
    let e = err(Rfc2217Transport::open(&s.addr));
    assert!(e.contains("COM-PORT-OPTION"), "{e}");
}

#[test]
fn a_server_that_never_answers_times_out() {
    let s = serve(Mode::Silent);
    let start = Instant::now();
    let e = err(Rfc2217Transport::open(&s.addr));
    assert!(e.contains("no answer to RFC 2217 negotiation"), "{e}");
    assert!(start.elapsed() >= ANSWER_TIMEOUT);
}

#[test]
fn a_server_that_hangs_up_during_the_open() {
    let s = serve(Mode::Close);
    let e = err(Rfc2217Transport::open(&s.addr));
    assert!(e.contains("rfc2217"), "{e}");
}

#[test]
fn a_hang_up_ends_the_stream() {
    let s = serve(Mode::Echo);
    let mut t = open(&s.addr);
    s.port.lock().unwrap().hang_up = true;
    t.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    // A reset is as good as an end: both mean the server is gone.
    match t.read(&mut [0u8; 8]) {
        Ok(0) => {}
        Ok(n) => panic!("read {n} bytes"),
        Err(e) => assert_eq!(e.kind(), io::ErrorKind::ConnectionReset),
    }
    assert!(!t.is_connected());
    assert_eq!(t.read(&mut [0u8; 8]).unwrap(), 0);
    {
        let e = t.set_dtr(true).unwrap_err();
        assert!(
            matches!(
                e.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
            ),
            "{e}"
        );
        // The modem lines keep their last state.
        assert!(!t.read_cts().unwrap());
    }
}

#[test]
fn nothing_listening_is_an_error() {
    let addr = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .to_string();
    let e = err(Rfc2217Transport::open(&addr));
    assert!(e.starts_with("transport error: rfc2217 127.0.0.1:"), "{e}");
    assert!(connect_tcp("name.invalid:1").is_err());
}

#[test]
fn bad_specs_are_refused() {
    for spec in ["", "rfc2217://", "@9600"] {
        assert!(
            matches!(
                Rfc2217Transport::open(spec),
                Err(TransportError::InvalidSpec(_))
            ),
            "{spec:?}"
        );
    }
    assert!(matches!(
        Rfc2217Transport::open("127.0.0.1:1@fast"),
        Err(TransportError::InvalidSpec(_))
    ));
}

#[test]
fn the_messages_name_what_was_refused() {
    assert_eq!(name(SET_DATASIZE), "data size");
    assert_eq!(name(SET_STOPSIZE), "stop size");
    assert_eq!(name(SET_CONTROL), "control");
    assert_eq!(name(PURGE_DATA), "purge");
    assert_eq!(name(SIGNATURE), "request");
    assert_eq!(show(SET_BAUDRATE, &9600u32.to_be_bytes()), "9600");
    assert_eq!(show(SET_PARITY, &[3]), "3");
    assert_eq!(show(SET_PARITY, &[]), "[]");
}

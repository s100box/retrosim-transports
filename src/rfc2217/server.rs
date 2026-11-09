// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Howard M. Harte
//! The server half: a [`Session`] per client connection, with the port
//! behind the [`Device`] trait, so every exchange is testable without a port
//! or a socket. `serbridge` is the server built on it.
//!
//! Tracks accepted Telnet options in each direction. It supports BINARY,
//! ECHO, SUPPRESS-GO-AHEAD and COM-PORT-OPTION as appropriate to each direction,
//! refuses unsupported requests and avoids repeated acknowledgments.

use super::*;

/// Options this side will perform when asked (`DO x` -> `WILL x`).
const WE_WILL: &[u8] = &[BINARY, ECHO, SGA, COM_PORT];
/// Options the client may perform (`WILL x` -> `DO x`).
const THEY_MAY: &[u8] = &[BINARY, SGA, COM_PORT];

/// The port, as the protocol sees it. Every setter takes RFC 2217's own
/// encoding and returns the value in effect afterwards. Line-setting requests
/// use 0 to query the current value; SET-CONTROL has separate query codes.
/// The client recognizes a refused setting by comparing the reply with its request.
pub trait Device {
    /// Bits per second.
    fn baud(&mut self, rate: u32) -> u32;
    /// 5..=8.
    fn data_size(&mut self, bits: u8) -> u8;
    /// 1 none, 2 odd, 3 even, 4 mark, 5 space.
    fn parity(&mut self, code: u8) -> u8;
    /// 1 one, 2 two, 3 one and a half.
    fn stop_size(&mut self, code: u8) -> u8;
    /// SET-CONTROL: flow control (0..3, 13..16), BREAK (4..6), DTR (7..9)
    /// and RTS (10..12).
    fn control(&mut self, code: u8) -> u8;
    /// 1 receive buffer, 2 transmit buffer, 3 both.
    fn purge(&mut self, code: u8);
    /// CTS 0x10, DSR 0x20, RI 0x40, DCD 0x80.
    fn modem_state(&mut self) -> u8;
}

#[derive(Clone, Copy)]
enum State {
    Data,
    Iac,
    Negotiate(u8),
    Sub,
    SubIac,
}

/// One client connection's protocol state.
pub struct Session {
    state: State,
    sb: Subnegotiation,
    we: [bool; 256],
    they: [bool; 256],
    modem_mask: u8,
    last_modem: Option<u8>,
    signature: Vec<u8>,
}

impl Default for Session {
    fn default() -> Self {
        Session {
            state: State::Data,
            sb: Subnegotiation::default(),
            we: [false; 256],
            they: [false; 256],
            modem_mask: 0xFF,
            last_modem: None,
            signature: b"retrosim-transports".to_vec(),
        }
    }
}

impl Session {
    /// A session that answers SIGNATURE with `signature` (the default answer
    /// is `retrosim-transports`).
    pub fn with_signature(signature: &str) -> Self {
        Session {
            signature: signature.as_bytes().to_vec(),
            ..Session::default()
        }
    }

    /// Takes bytes from the client. Serial data is appended to `data`, with
    /// Telnet's escaping removed; the protocol's answers go to `reply`.
    pub fn feed(
        &mut self,
        input: &[u8],
        dev: &mut dyn Device,
        data: &mut Vec<u8>,
        reply: &mut Vec<u8>,
    ) {
        for &b in input {
            self.state = match self.state {
                State::Data if b == IAC => State::Iac,
                State::Data => {
                    data.push(b);
                    State::Data
                }
                State::Iac => match b {
                    IAC => {
                        data.push(IAC);
                        State::Data
                    }
                    SB => {
                        self.sb.clear();
                        State::Sub
                    }
                    DO | DONT | WILL | WONT => State::Negotiate(b),
                    // NOP, AYT, GA and the rest carry nothing for a port.
                    _ => State::Data,
                },
                State::Negotiate(cmd) => {
                    self.negotiate(cmd, b, reply);
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
                        self.subnegotiate(dev, reply);
                        State::Data
                    }
                    // Malformed: drop the sub-negotiation.
                    _ => State::Data,
                },
            };
        }
    }

    /// Whether the client has agreed to RFC 2217, and so understands the
    /// modem-state notifications [`Self::modem_changed`] sends.
    pub fn com_port(&self) -> bool {
        self.we[COM_PORT as usize] || self.they[COM_PORT as usize]
    }

    /// A NOTIFY-MODEMSTATE when the lines the client asked about changed
    /// since the last one, and the first time it is called after the client
    /// agreed to RFC 2217: pySerial reads CTS, DSR, RI and DCD from the last
    /// notification and raises if it never had one.
    pub fn modem_changed(&mut self, state: u8, reply: &mut Vec<u8>) {
        if !self.com_port() {
            return;
        }
        let now = state & 0xF0 & self.modem_mask;
        if self.last_modem == Some(now) {
            return;
        }
        // The low nibble reports what changed: delta CTS, delta DSR,
        // trailing edge of RI, delta DCD.
        let was = self.last_modem.unwrap_or(now);
        let delta =
            ((was ^ now) & 0x30) >> 4 | ((was & !now) & 0x40) >> 4 | ((was ^ now) & 0x80) >> 4;
        self.last_modem = Some(now);
        sub(reply, SERVER + NOTIFY_MODEMSTATE, &[now | delta]);
    }

    fn negotiate(&mut self, cmd: u8, opt: u8, reply: &mut Vec<u8>) {
        let i = opt as usize;
        match cmd {
            DO if WE_WILL.contains(&opt) && !self.we[i] => {
                self.we[i] = true;
                reply.extend([IAC, WILL, opt]);
            }
            // Already agreed: an acknowledgement, which gets no answer.
            DO if WE_WILL.contains(&opt) => {}
            DO => reply.extend([IAC, WONT, opt]),
            DONT if self.we[i] => {
                self.we[i] = false;
                reply.extend([IAC, WONT, opt]);
            }
            WILL if THEY_MAY.contains(&opt) && !self.they[i] => {
                self.they[i] = true;
                reply.extend([IAC, DO, opt]);
            }
            WILL if THEY_MAY.contains(&opt) => {}
            WILL => reply.extend([IAC, DONT, opt]),
            WONT if self.they[i] => {
                self.they[i] = false;
                reply.extend([IAC, DONT, opt]);
            }
            _ => {}
        }
    }

    fn subnegotiate(&mut self, dev: &mut dyn Device, reply: &mut Vec<u8>) {
        let Some(sb) = self.sb.take() else { return };
        let [COM_PORT, code, ref v @ ..] = sb[..] else {
            return;
        };
        match (code, v) {
            (SIGNATURE, _) => sub(reply, SERVER + SIGNATURE, &self.signature),
            (SET_BAUDRATE, &[a, b, c, d]) => {
                let asked = u32::from_be_bytes([a, b, c, d]);
                let now = dev.baud(asked);
                sub(reply, SERVER + SET_BAUDRATE, &now.to_be_bytes());
            }
            (SET_DATASIZE, &[x]) => sub(reply, SERVER + SET_DATASIZE, &[dev.data_size(x)]),
            (SET_PARITY, &[x]) => sub(reply, SERVER + SET_PARITY, &[dev.parity(x)]),
            (SET_STOPSIZE, &[x]) => sub(reply, SERVER + SET_STOPSIZE, &[dev.stop_size(x)]),
            (SET_CONTROL, &[x]) => sub(reply, SERVER + SET_CONTROL, &[dev.control(x)]),
            // A client sending this is asking for the current state (pySerial
            // does, with nothing after the code).
            (NOTIFY_MODEMSTATE, _) => {
                let now = dev.modem_state() & 0xF0 & self.modem_mask;
                self.last_modem = Some(now);
                sub(reply, SERVER + NOTIFY_MODEMSTATE, &[now]);
            }
            // No line-state notification is ever sent, so the mask is only
            // acknowledged.
            (SET_LINESTATE_MASK, &[x]) => sub(reply, SERVER + SET_LINESTATE_MASK, &[x]),
            (SET_MODEMSTATE_MASK, &[x]) => {
                self.modem_mask = x;
                sub(reply, SERVER + SET_MODEMSTATE_MASK, &[x]);
            }
            (PURGE_DATA, &[x]) => {
                dev.purge(x);
                sub(reply, SERVER + PURGE_DATA, &[x]);
            }
            // FLOWCONTROL-SUSPEND/RESUME and anything unknown: no answer is
            // defined, so none is sent.
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_width_requests_reject_missing_or_extra_bytes_without_device_changes() {
        let (mut session, mut dev) = (
            Session::default(),
            Fake {
                baud: 2400,
                ..Fake::default()
            },
        );
        for code in [
            SET_DATASIZE,
            SET_PARITY,
            SET_STOPSIZE,
            SET_CONTROL,
            SET_LINESTATE_MASK,
            SET_MODEMSTATE_MASK,
            PURGE_DATA,
        ] {
            for value in [&[][..], &[8, 9][..]] {
                let (_, reply) = run(&mut session, &mut dev, &sb(code, value));
                assert!(
                    reply.is_empty(),
                    "accepted malformed request {code}/{value:?}"
                );
            }
        }
        for value in [&[0, 0, 37][..], &[0, 0, 37, 128, 0][..]] {
            assert!(run(&mut session, &mut dev, &sb(SET_BAUDRATE, value))
                .1
                .is_empty());
        }
        assert_eq!(dev.baud, 2400);
        assert!(!dev.dtr);
        assert!(dev.purged.is_empty());
        assert_eq!(session.modem_mask, 255);
        assert_eq!(
            run(
                &mut session,
                &mut dev,
                &sb(SET_BAUDRATE, &9600u32.to_be_bytes())
            )
            .1,
            sb(SERVER + SET_BAUDRATE, &9600u32.to_be_bytes())
        );
    }

    #[test]
    fn oversized_frames_are_discarded_without_applying_their_prefix() {
        for chunk in [1, 7, 258] {
            let mut session = Session::default();
            let mut dev = Fake {
                baud: 2400,
                ..Fake::default()
            };
            let mut value = 9600u32.to_be_bytes().to_vec();
            value.resize(SB_MAX + 8, 0);
            let mut input = sb(SET_BAUDRATE, &value);
            input.extend(sb(SET_PARITY, &[3]));
            input.extend(b"still data");
            let (mut data, mut reply) = (Vec::new(), Vec::new());
            for bytes in input.chunks(chunk) {
                session.feed(bytes, &mut dev, &mut data, &mut reply);
            }
            assert_eq!(dev.baud, 2400);
            assert_eq!(reply, sb(SERVER + SET_PARITY, &[3]));
            assert_eq!(data, b"still data");
        }
    }

    #[derive(Default)]
    struct Fake {
        baud: u32,
        refuse_baud: Option<u32>,
        dtr: bool,
        purged: Vec<u8>,
        modem: u8,
    }

    impl Device for Fake {
        fn baud(&mut self, rate: u32) -> u32 {
            if rate != 0 && Some(rate) != self.refuse_baud {
                self.baud = rate;
            }
            self.baud
        }
        fn data_size(&mut self, bits: u8) -> u8 {
            if bits == 0 {
                8
            } else {
                bits
            }
        }
        fn parity(&mut self, code: u8) -> u8 {
            code.max(1)
        }
        fn stop_size(&mut self, code: u8) -> u8 {
            code.max(1)
        }
        fn control(&mut self, code: u8) -> u8 {
            match code {
                8 => self.dtr = true,
                9 => self.dtr = false,
                _ => {}
            }
            match code {
                7..=9 => {
                    if self.dtr {
                        8
                    } else {
                        9
                    }
                }
                _ => code,
            }
        }
        fn purge(&mut self, code: u8) {
            self.purged.push(code);
        }
        fn modem_state(&mut self) -> u8 {
            self.modem
        }
    }

    fn run(s: &mut Session, dev: &mut Fake, input: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let (mut data, mut reply) = (Vec::new(), Vec::new());
        s.feed(input, dev, &mut data, &mut reply);
        (data, reply)
    }

    fn sb(code: u8, value: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        sub(&mut v, code, value);
        v
    }

    #[test]
    fn pyserial_opening_negotiation_is_answered_once() {
        // What pySerial 3.5 sends on open: DO ECHO, WILL SGA, DO SGA,
        // DO COM-PORT, WILL COM-PORT.
        let open = [
            IAC, DO, ECHO, IAC, WILL, SGA, IAC, DO, SGA, IAC, DO, COM_PORT, IAC, WILL, COM_PORT,
        ];
        let (mut s, mut d) = (Session::default(), Fake::default());
        let (data, reply) = run(&mut s, &mut d, &open);
        assert!(data.is_empty());
        assert_eq!(
            reply,
            [
                IAC, WILL, ECHO, IAC, DO, SGA, IAC, WILL, SGA, IAC, WILL, COM_PORT, IAC, DO,
                COM_PORT
            ]
        );
        assert!(s.com_port());
        // The client's acknowledgements of those answers change nothing, so
        // they get none: no loop.
        let (_, reply) = run(&mut s, &mut d, &[IAC, WILL, SGA, IAC, DO, COM_PORT]);
        assert!(reply.is_empty());
    }

    #[test]
    fn unknown_options_are_refused() {
        let (mut s, mut d) = (Session::default(), Fake::default());
        let (_, reply) = run(&mut s, &mut d, &[IAC, DO, 24, IAC, WILL, 31]);
        assert_eq!(reply, [IAC, WONT, 24, IAC, DONT, 31]);
    }

    #[test]
    fn data_is_unescaped_and_split_anywhere() {
        let (mut s, mut d) = (Session::default(), Fake::default());
        let (a, _) = run(&mut s, &mut d, &[b'x', IAC]);
        let (b, _) = run(&mut s, &mut d, &[IAC, 0, b'y']);
        assert_eq!(a, b"x");
        assert_eq!(b, [IAC, 0, b'y']);
    }

    #[test]
    fn a_baud_rate_is_set_and_echoed() {
        let (mut s, mut d) = (Session::default(), Fake::default());
        let (_, reply) = run(&mut s, &mut d, &sb(SET_BAUDRATE, &9600u32.to_be_bytes()));
        assert_eq!(d.baud, 9600);
        assert_eq!(reply, sb(SERVER + SET_BAUDRATE, &9600u32.to_be_bytes()));
    }

    #[test]
    fn a_refused_baud_rate_answers_the_rate_in_effect() {
        let (mut s, mut d) = (Session::default(), Fake::default());
        d.baud = 115_200;
        d.refuse_baud = Some(12_345);
        let (_, reply) = run(&mut s, &mut d, &sb(SET_BAUDRATE, &12_345u32.to_be_bytes()));
        assert_eq!(reply, sb(SERVER + SET_BAUDRATE, &115_200u32.to_be_bytes()));
    }

    #[test]
    fn an_iac_inside_a_value_is_doubled_both_ways() {
        // 0x0001C2FF has an 0xFF byte, which travels doubled.
        let rate = 0x0001_C2FFu32;
        let (mut s, mut d) = (Session::default(), Fake::default());
        let req = sb(SET_BAUDRATE, &rate.to_be_bytes());
        assert_eq!(req.iter().filter(|&&b| b == IAC).count(), 4);
        let (_, reply) = run(&mut s, &mut d, &req);
        assert_eq!(d.baud, rate);
        assert_eq!(reply, sb(SERVER + SET_BAUDRATE, &rate.to_be_bytes()));
    }

    #[test]
    fn dtr_purge_and_signature() {
        let (mut s, mut d) = (Session::with_signature("serbridge"), Fake::default());
        let (_, r) = run(&mut s, &mut d, &sb(SET_CONTROL, &[8]));
        assert!(d.dtr);
        assert_eq!(r, sb(SERVER + SET_CONTROL, &[8]));
        let (_, r) = run(&mut s, &mut d, &sb(PURGE_DATA, &[3]));
        assert_eq!(d.purged, [3]);
        assert_eq!(r, sb(SERVER + PURGE_DATA, &[3]));
        let (_, r) = run(&mut s, &mut d, &sb(SIGNATURE, &[]));
        assert_eq!(r, sb(SERVER + SIGNATURE, b"serbridge"));
    }

    #[test]
    fn modem_state_is_sent_first_then_only_on_change() {
        let (mut s, mut d) = (Session::default(), Fake::default());
        let mut r = Vec::new();
        s.modem_changed(0x30, &mut r);
        assert!(r.is_empty(), "not before the client agreed to RFC 2217");
        run(&mut s, &mut d, &[IAC, WILL, COM_PORT]);
        s.modem_changed(0x30, &mut r);
        assert_eq!(r, sb(SERVER + NOTIFY_MODEMSTATE, &[0x30]));
        r.clear();
        s.modem_changed(0x30, &mut r);
        assert!(r.is_empty());
        // CTS drops: state 0x20 with delta-CTS (0x01).
        s.modem_changed(0x20, &mut r);
        assert_eq!(r, sb(SERVER + NOTIFY_MODEMSTATE, &[0x21]));
    }

    #[test]
    fn a_poll_answers_the_masked_state() {
        let (mut s, mut d) = (Session::default(), Fake::default());
        d.modem = 0xB0;
        let (_, r) = run(&mut s, &mut d, &sb(SET_MODEMSTATE_MASK, &[0x30]));
        assert_eq!(r, sb(SERVER + SET_MODEMSTATE_MASK, &[0x30]));
        let (_, r) = run(&mut s, &mut d, &sb(NOTIFY_MODEMSTATE, &[]));
        assert_eq!(r, sb(SERVER + NOTIFY_MODEMSTATE, &[0x30]));
    }

    #[test]
    fn every_setting_is_set_and_answered() {
        let (mut s, mut d) = (Session::default(), Fake::default());
        let mut input = Vec::new();
        for (code, v) in [
            (SET_DATASIZE, 7),
            (SET_PARITY, 3),
            (SET_STOPSIZE, 2),
            (SET_CONTROL, 8),
            (SET_CONTROL, 9),
            (SET_CONTROL, 7),
            (SET_CONTROL, 3),
            (SET_LINESTATE_MASK, 0),
        ] {
            input.extend(sb(code, &[v]));
        }
        let (_, r) = run(&mut s, &mut d, &input);
        let mut want = Vec::new();
        for (code, v) in [
            (SET_DATASIZE, 7),
            (SET_PARITY, 3),
            (SET_STOPSIZE, 2),
            (SET_CONTROL, 8),
            (SET_CONTROL, 9),
            (SET_CONTROL, 9),
            (SET_CONTROL, 3),
            (SET_LINESTATE_MASK, 0),
        ] {
            want.extend(sb(SERVER + code, &[v]));
        }
        assert_eq!(r, want);
        assert!(!d.dtr);
    }

    #[test]
    fn what_carries_nothing_for_a_port_gets_no_answer() {
        let (mut s, mut d) = (Session::default(), Fake::default());
        let mut input = vec![b'a', IAC, 241, b'b']; // NOP between data
        input.extend([IAC, SB, 24, 1, IAC, SE]); // not COM-PORT
        input.extend(sb(99, &[1])); // an unknown sub-option
        input.extend(sb(SET_PARITY, &[])); // a setting with no value
        input.extend([IAC, SB, COM_PORT, SET_PARITY, 3, IAC, 7, b'c']); // malformed
        let (data, reply) = run(&mut s, &mut d, &input);
        assert_eq!(data, b"abc");
        assert!(reply.is_empty(), "{reply:?}");
    }

    #[test]
    fn escape_doubles_iac() {
        let mut out = Vec::new();
        escape(&[1, IAC, 2], &mut out);
        assert_eq!(out, [1, IAC, IAC, 2]);
    }
}

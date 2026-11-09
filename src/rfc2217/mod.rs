// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Howard M. Harte
//! RFC 2217: a serial port's data, settings and modem lines carried over a
//! Telnet connection, so a program can use a port another process holds as if
//! it had opened the port itself. pySerial opens one as `rfc2217://host:port`.
//!
//! - [`Rfc2217Transport`] is the client: a [`Transport`] with
//!   [`ModemControl`] and [`Transport::reconfigure`], opened by the
//!   `rfc2217:` spec of [`crate::open_transport`].
//! - [`Session`] and [`Device`] are the server half, the protocol without a
//!   socket or a port. `serbridge`, in this repository's workspace, is the
//!   server built on them.
//! - [`url_file`] and [`bridge_url`] are the rule a bridge and its clients
//!   share for finding each other: a bridge holding a port writes its URL to a
//!   file named for the port, and `serial:` specs connect to that URL when the
//!   file is there.
//!
//! [`Transport`]: retrosim_core::transport::Transport
//! [`Transport::reconfigure`]: retrosim_core::transport::Transport::reconfigure
//! [`ModemControl`]: retrosim_core::transport::ModemControl

mod client;
mod discovery;
mod server;

pub(crate) use client::connect_tcp;
#[cfg(test)]
pub(crate) use client::tests as test_server;
pub use client::Rfc2217Transport;
pub use discovery::{bridge_addr, bridge_url, url_file};
pub use server::{Device, Session};

/// Telnet "interpret as command". A data byte of this value is sent twice.
pub const IAC: u8 = 255;
/// Telnet: ask the other side not to perform an option.
pub const DONT: u8 = 254;
/// Telnet: ask the other side to perform an option.
pub const DO: u8 = 253;
/// Telnet: refuse to perform an option.
pub const WONT: u8 = 252;
/// Telnet: offer to perform an option.
pub const WILL: u8 = 251;
/// Telnet: start of a sub-negotiation.
pub const SB: u8 = 250;
/// Telnet: end of a sub-negotiation.
pub const SE: u8 = 240;

/// Telnet option: 8-bit transmission (RFC 856).
pub const BINARY: u8 = 0;
/// Telnet option: echo (RFC 857).
pub const ECHO: u8 = 1;
/// Telnet option: suppress go-ahead (RFC 858).
pub const SGA: u8 = 3;
/// COM-PORT-OPTION, the option RFC 2217 defines.
pub const COM_PORT: u8 = 44;

// Client-to-server sub-options. The server's answer carries the same number
// plus SERVER.

/// Sub-option: the other side's signature (free text).
pub const SIGNATURE: u8 = 0;
/// Sub-option: baud rate, four bytes, big-endian.
pub const SET_BAUDRATE: u8 = 1;
/// Sub-option: data bits, 5..=8.
pub const SET_DATASIZE: u8 = 2;
/// Sub-option: parity, 1 none, 2 odd, 3 even, 4 mark, 5 space.
pub const SET_PARITY: u8 = 3;
/// Sub-option: stop bits, 1 one, 2 two, 3 one and a half.
pub const SET_STOPSIZE: u8 = 4;
/// Sub-option: flow control (1 none, 2 XON/XOFF, 3 RTS/CTS), BREAK (5 on,
/// 6 off), DTR (8 on, 9 off) and RTS (11 on, 12 off).
pub const SET_CONTROL: u8 = 5;
/// Sub-option: the modem lines, CTS 0x10, DSR 0x20, RI 0x40, DCD 0x80, with
/// their change bits in the low nibble.
pub const NOTIFY_MODEMSTATE: u8 = 7;
/// Sub-option: which line-state changes the client wants reported.
pub const SET_LINESTATE_MASK: u8 = 10;
/// Sub-option: which modem-line changes the client wants reported.
pub const SET_MODEMSTATE_MASK: u8 = 11;
/// Sub-option: discard buffered data, 1 receive, 2 transmit, 3 both.
pub const PURGE_DATA: u8 = 12;
/// Added to a sub-option's number in the server's answer.
pub const SERVER: u8 = 100;

/// Resource limit on decoded sub-negotiation bytes, including option and code.
/// Longer frames are discarded in full through their IAC SE terminator.
pub(crate) const SB_MAX: usize = 256;

/// A bounded frame buffer shared by the client and server decoders. Remember
/// overflow so a valid-looking prefix of an oversized frame is never applied.
#[derive(Default)]
struct Subnegotiation {
    bytes: Vec<u8>,
    overflow: bool,
}

impl Subnegotiation {
    fn clear(&mut self) {
        self.bytes.clear();
        self.overflow = false;
    }

    fn push(&mut self, byte: u8) {
        if self.bytes.len() < SB_MAX {
            self.bytes.push(byte);
        } else {
            self.overflow = true;
        }
    }

    fn take(&mut self) -> Option<Vec<u8>> {
        let bytes = std::mem::take(&mut self.bytes);
        let overflow = std::mem::replace(&mut self.overflow, false);
        (!overflow).then_some(bytes)
    }
}

/// Appends `IAC SB COM-PORT-OPTION code value IAC SE` to `out`, with IAC
/// doubled in the value.
pub fn subnegotiation(out: &mut Vec<u8>, code: u8, value: &[u8]) {
    out.extend([IAC, SB, COM_PORT, code]);
    escape(value, out);
    out.extend([IAC, SE]);
}

/// Serial data for the other side: every IAC doubled.
pub fn escape(data: &[u8], out: &mut Vec<u8>) {
    for &b in data {
        out.push(b);
        if b == IAC {
            out.push(IAC);
        }
    }
}

pub(crate) use subnegotiation as sub;

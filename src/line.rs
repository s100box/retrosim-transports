// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Howard M. Harte
//! The line settings a `serial:` or `rfc2217:` spec carries after its `@`:
//! `baud[,format[,flow]]`, as in `115200`, `9600,7E2` or `9600,8N1,hw`.
//! Parsed here, apart from the `serialport` crate, so an `rfc2217:` spec
//! works in a build without the `serial` feature.

use retrosim_core::serial::{SerialParams, SerialParity, SerialStopBits};
use retrosim_core::transport::TransportError;

/// Flow control named by a spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Flow {
    None,
    Software,
    Hardware,
}

/// Everything after the `@` of a spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LineSettings {
    pub params: SerialParams,
    pub flow: Flow,
}

/// Splits `port@settings` into its two halves.
pub(crate) fn split_spec<'a>(
    kind: &str,
    spec: &'a str,
) -> Result<(&'a str, &'a str), TransportError> {
    let (port, rest) = spec.split_once('@').ok_or_else(|| {
        TransportError::InvalidSpec(format!("{kind} spec missing @baud: '{spec}'"))
    })?;
    if port.is_empty() {
        return Err(TransportError::InvalidSpec(format!(
            "{kind} spec missing port name"
        )));
    }
    Ok((port, rest))
}

/// Parses `baud[,format[,flow]]`; format defaults to `8N1` and flow to `none`.
pub(crate) fn parse_settings(rest: &str) -> Result<LineSettings, TransportError> {
    let mut parts = rest.split(',');
    let baud = parts.next().unwrap_or_default();
    let baud_rate: u32 = baud
        .parse()
        .map_err(|_| TransportError::InvalidSpec(format!("invalid baud rate: '{baud}'")))?;
    let (data_bits, parity, stop_bits) = match parts.next() {
        Some(fmt) => parse_format(fmt)?,
        None => (8, SerialParity::None, SerialStopBits::One),
    };
    let flow = match parts.next().map(str::to_ascii_lowercase) {
        None => Flow::None,
        Some(f) => match f.as_str() {
            "none" => Flow::None,
            "hw" | "hardware" | "rtscts" => Flow::Hardware,
            "sw" | "software" | "xonxoff" => Flow::Software,
            other => {
                return Err(TransportError::InvalidSpec(format!(
                    "unknown flow control: '{other}' (use none, hw, or sw)"
                )))
            }
        },
    };
    if parts.next().is_some() {
        return Err(TransportError::InvalidSpec(
            "too many serial settings (expected baud[,format[,flow]])".into(),
        ));
    }
    Ok(LineSettings {
        params: SerialParams {
            baud_rate,
            data_bits,
            parity,
            stop_bits,
        },
        flow,
    })
}

/// Parses a format such as `8N1`, `7E2` or `8N2`.
fn parse_format(fmt: &str) -> Result<(u8, SerialParity, SerialStopBits), TransportError> {
    let chars: Vec<char> = fmt.chars().collect();
    if chars.len() != 3 {
        return Err(TransportError::InvalidSpec(format!(
            "invalid serial format '{fmt}' (expected 3 chars like 8N1)"
        )));
    }
    let data_bits = match chars[0] {
        c @ '5'..='8' => c as u8 - b'0',
        c => {
            return Err(TransportError::InvalidSpec(format!(
                "invalid data bits: '{c}' (use 5-8)"
            )))
        }
    };
    let parity = match chars[1].to_ascii_uppercase() {
        'N' => SerialParity::None,
        'E' => SerialParity::Even,
        'O' => SerialParity::Odd,
        c => {
            return Err(TransportError::InvalidSpec(format!(
                "invalid parity: '{c}' (use N, E, or O)"
            )))
        }
    };
    let stop_bits = match chars[2] {
        '1' => SerialStopBits::One,
        '2' => SerialStopBits::Two,
        c => {
            return Err(TransportError::InvalidSpec(format!(
                "invalid stop bits: '{c}' (use 1 or 2)"
            )))
        }
    };
    Ok((data_bits, parity, stop_bits))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_8n1_no_flow() {
        let s = parse_settings("9600").unwrap();
        assert_eq!(s.params.baud_rate, 9600);
        assert_eq!(s.params.data_bits, 8);
        assert_eq!(s.params.parity, SerialParity::None);
        assert_eq!(s.params.stop_bits, SerialStopBits::One);
        assert_eq!(s.flow, Flow::None);
    }

    #[test]
    fn full_settings() {
        let s = parse_settings("115200,7e2,RTSCTS").unwrap();
        assert_eq!(s.params.data_bits, 7);
        assert_eq!(s.params.parity, SerialParity::Even);
        assert_eq!(s.params.stop_bits, SerialStopBits::Two);
        assert_eq!(s.flow, Flow::Hardware);
    }

    #[test]
    fn bad_settings_are_refused() {
        for bad in [
            "",
            "abc",
            "9600,9N1",
            "9600,8X1",
            "9600,8N3",
            "9600,XY",
            "9600,8N1,bogus",
            "9600,8N1,none,ignored",
            "9600,8N1,hw,",
        ] {
            assert!(parse_settings(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_spec_needs_a_port_and_an_at() {
        assert_eq!(split_spec("serial", "COM3@9600").unwrap(), ("COM3", "9600"));
        assert!(split_spec("serial", "COM3").is_err());
        assert!(split_spec("serial", "@9600").is_err());
    }
}

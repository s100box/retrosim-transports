// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Howard M. Harte
//! What the bridge holds: a serial port of its own, or any retrosim-transports
//! connection. The bridge's threads all use it at once — the reader waits on
//! it while a client's thread writes — so every call takes `&self`.

use std::io::{self, Read as _, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use retrosim_core::serial::{SerialParams, SerialParity, SerialStopBits};
use retrosim_core::transport::Transport;

use crate::serial::{Flow, Parity, Port, Read, Settings, StopBits};

/// The calls the bridge makes on what it holds.
pub trait Link: Send + Sync {
    /// Waits a short while for data.
    fn read(&self, buf: &mut [u8]) -> io::Result<Read>;
    fn write_all(&self, buf: &[u8]) -> io::Result<()>;
    fn configure(&self, s: &Settings) -> io::Result<()>;
    fn set_dtr(&self, on: bool) -> io::Result<()>;
    fn set_rts(&self, on: bool) -> io::Result<()>;
    fn set_break(&self, on: bool) -> io::Result<()>;
    /// CTS 0x10, DSR 0x20, RI 0x40, DCD 0x80.
    fn modem_status(&self) -> io::Result<u8>;
    fn purge(&self, rx: bool, tx: bool) -> io::Result<()>;
}

impl Link for Port {
    fn read(&self, buf: &mut [u8]) -> io::Result<Read> {
        Port::read(self, buf)
    }
    fn write_all(&self, buf: &[u8]) -> io::Result<()> {
        Port::write_all(self, buf)
    }
    fn configure(&self, s: &Settings) -> io::Result<()> {
        Port::configure(self, s)
    }
    fn set_dtr(&self, on: bool) -> io::Result<()> {
        Port::set_dtr(self, on)
    }
    fn set_rts(&self, on: bool) -> io::Result<()> {
        Port::set_rts(self, on)
    }
    fn set_break(&self, on: bool) -> io::Result<()> {
        Port::set_break(self, on)
    }
    fn modem_status(&self) -> io::Result<u8> {
        Port::modem_status(self)
    }
    fn purge(&self, rx: bool, tx: bool) -> io::Result<()> {
        Port::purge(self, rx, tx)
    }
}

/// How long the reader holds a transport waiting for data. Short, because a
/// write waits for the reader to let go.
const READ_SLICE: Duration = Duration::from_millis(10);

/// A retrosim-transports connection, shared by putting it behind a lock.
///
/// The reader takes the lock for one [`READ_SLICE`] at a time; anyone else
/// who wants it says so in `waiting`, and the reader stands aside until they
/// have had it. This avoids repeated idle reads starving queued writers;
/// scheduling and competing writers can still increase lock latency.
pub struct TransportLink {
    t: Mutex<Box<dyn Transport>>,
    waiting: AtomicUsize,
}

impl TransportLink {
    pub fn new(mut t: Box<dyn Transport>) -> io::Result<Self> {
        t.set_read_timeout(Some(READ_SLICE))?;
        Ok(TransportLink {
            t: Mutex::new(t),
            waiting: AtomicUsize::new(0),
        })
    }

    /// The lock, for anyone but the reader.
    fn with<R>(&self, f: impl FnOnce(&mut dyn Transport) -> io::Result<R>) -> io::Result<R> {
        self.waiting.fetch_add(1, Ordering::SeqCst);
        let mut t = self.t.lock().unwrap();
        self.waiting.fetch_sub(1, Ordering::SeqCst);
        f(t.as_mut())
    }

    fn modem<R>(
        &self,
        f: impl FnOnce(&mut dyn retrosim_core::transport::ModemControl) -> io::Result<R>,
    ) -> io::Result<R> {
        self.with(|t| match t.modem_control() {
            Some(m) => f(m),
            None => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "this transport has no modem lines",
            )),
        })
    }
}

impl Link for TransportLink {
    fn read(&self, buf: &mut [u8]) -> io::Result<Read> {
        if buf.is_empty() {
            return Ok(Read::Idle);
        }
        while self.waiting.load(Ordering::SeqCst) != 0 {
            std::thread::yield_now();
        }
        let mut t = self.t.lock().unwrap();
        match t.read(buf) {
            Ok(0) => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the connection closed",
            )),
            Ok(n) => Ok(Read::Got(n)),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(Read::Idle)
            }
            Err(e) => Err(e),
        }
    }

    fn write_all(&self, buf: &[u8]) -> io::Result<()> {
        self.with(|t| write_retry(t, buf, Duration::from_secs(3)))
    }

    fn configure(&self, s: &Settings) -> io::Result<()> {
        let p = params(s)?;
        self.with(|t| t.reconfigure(&p))
    }

    fn set_dtr(&self, on: bool) -> io::Result<()> {
        self.modem(|m| m.set_dtr(on))
    }

    fn set_rts(&self, on: bool) -> io::Result<()> {
        self.modem(|m| m.set_rts(on))
    }

    fn set_break(&self, on: bool) -> io::Result<()> {
        self.modem(|m| m.set_break(on))
    }

    fn modem_status(&self) -> io::Result<u8> {
        self.modem(|m| {
            Ok(u8::from(m.read_cts()?) << 4
                | u8::from(m.read_dsr()?) << 5
                | u8::from(m.read_ri()?) << 6
                | u8::from(m.read_dcd()?) << 7)
        })
    }

    /// Nothing to discard: a transport's buffers are not the bridge's to
    /// clear, and what has already arrived is read and passed on as usual.
    fn purge(&self, _rx: bool, _tx: bool) -> io::Result<()> {
        Ok(())
    }
}

/// Retry only the unwritten suffix and pending flush. The budget bounds
/// retries; individual backend calls must also use bounded/nonblocking I/O.
fn write_retry<W: Write + ?Sized>(
    writer: &mut W,
    mut bytes: &[u8],
    budget: Duration,
) -> io::Result<()> {
    let start = Instant::now();
    while !bytes.is_empty() {
        let stalled = match writer.write(bytes) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
            Ok(n) => {
                bytes = &bytes[n..];
                false
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                true
            }
            Err(e) => return Err(e),
        };
        if !bytes.is_empty() && start.elapsed() >= budget {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "transport write deadline",
            ));
        }
        if stalled {
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    loop {
        match writer.flush() {
            Ok(()) => return Ok(()),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(e),
        }
        if start.elapsed() >= budget {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "transport flush deadline",
            ));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// `s` as retrosim-transports' line parameters. A transport's settings have
/// no mark or space parity and no flow control.
fn params(s: &Settings) -> io::Result<SerialParams> {
    let refuse = |what: &str| {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("{what} is not available on this transport"),
        ))
    };
    let parity = match s.parity {
        Parity::None => SerialParity::None,
        Parity::Odd => SerialParity::Odd,
        Parity::Even => SerialParity::Even,
        Parity::Mark => return refuse("mark parity"),
        Parity::Space => return refuse("space parity"),
    };
    if s.flow != Flow::None {
        return refuse("flow control");
    }
    Ok(SerialParams {
        baud_rate: s.baud,
        data_bits: s.data_bits,
        parity,
        stop_bits: match s.stop_bits {
            StopBits::One => SerialStopBits::One,
            StopBits::OnePointFive => SerialStopBits::OnePointFive,
            StopBits::Two => SerialStopBits::Two,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Instant;

    /// A transport with every line, for the adapter's sake.
    struct Fake {
        rx: Vec<u8>,
        tx: Arc<Mutex<Vec<u8>>>,
        lines: Arc<Mutex<Vec<String>>>,
        modem: [bool; 4],
        modem_lines: bool,
        eof: bool,
        params: Arc<Mutex<Option<SerialParams>>>,
        timeout: Option<Duration>,
    }

    impl Fake {
        fn new() -> Self {
            Fake {
                rx: Vec::new(),
                tx: Arc::default(),
                lines: Arc::default(),
                modem: [false; 4],
                modem_lines: true,
                eof: false,
                params: Arc::default(),
                timeout: None,
            }
        }
    }

    impl io::Read for Fake {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.eof {
                return Ok(0);
            }
            if self.rx.is_empty() {
                std::thread::sleep(self.timeout.unwrap_or_default());
                return Err(io::ErrorKind::TimedOut.into());
            }
            let n = buf.len().min(self.rx.len());
            buf[..n].copy_from_slice(&self.rx[..n]);
            self.rx.drain(..n);
            Ok(n)
        }
    }

    impl io::Write for Fake {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.tx.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Transport for Fake {
        fn set_read_timeout(&mut self, t: Option<Duration>) -> io::Result<()> {
            self.timeout = t;
            Ok(())
        }
        fn description(&self) -> &str {
            "fake"
        }
        fn reconfigure(&mut self, p: &SerialParams) -> io::Result<()> {
            *self.params.lock().unwrap() = Some(*p);
            Ok(())
        }
        fn modem_control(&mut self) -> Option<&mut dyn retrosim_core::transport::ModemControl> {
            if self.modem_lines {
                Some(self)
            } else {
                None
            }
        }
    }

    impl retrosim_core::transport::ModemControl for Fake {
        fn set_dtr(&mut self, on: bool) -> io::Result<()> {
            self.lines.lock().unwrap().push(format!("dtr {on}"));
            Ok(())
        }
        fn set_rts(&mut self, on: bool) -> io::Result<()> {
            self.lines.lock().unwrap().push(format!("rts {on}"));
            Ok(())
        }
        fn set_break(&mut self, on: bool) -> io::Result<()> {
            self.lines.lock().unwrap().push(format!("break {on}"));
            Ok(())
        }
        fn read_cts(&mut self) -> io::Result<bool> {
            Ok(self.modem[0])
        }
        fn read_dsr(&mut self) -> io::Result<bool> {
            Ok(self.modem[1])
        }
        fn read_ri(&mut self) -> io::Result<bool> {
            Ok(self.modem[2])
        }
        fn read_dcd(&mut self) -> io::Result<bool> {
            Ok(self.modem[3])
        }
    }

    #[test]
    fn empty_reads_do_not_treat_a_transport_as_disconnected() {
        let mut fake = Fake::new();
        fake.eof = true;
        let link = TransportLink::new(Box::new(fake)).unwrap();
        assert!(matches!(link.read(&mut []).unwrap(), Read::Idle));
    }

    #[test]
    fn short_writes_and_transient_flushes_preserve_the_exact_stream() {
        struct Writer {
            out: Vec<u8>,
            calls: usize,
            flushes: usize,
        }
        impl Write for Writer {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.calls += 1;
                if self.calls == 2 {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                self.out.push(bytes[0]);
                Ok(1)
            }
            fn flush(&mut self) -> io::Result<()> {
                self.flushes += 1;
                if self.flushes == 1 {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                Ok(())
            }
        }
        let mut writer = Writer {
            out: vec![],
            calls: 0,
            flushes: 0,
        };
        write_retry(&mut writer, b"abc", Duration::from_secs(1)).unwrap();
        assert_eq!(writer.out, b"abc");
        assert_eq!(writer.flushes, 2);
        let mut writer = Writer {
            out: vec![],
            calls: 0,
            flushes: 0,
        };
        assert_eq!(
            write_retry(&mut writer, b"abc", Duration::ZERO)
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(writer.out, b"a");
    }

    #[test]
    fn reads_writes_and_lines_pass_through() {
        let mut f = Fake::new();
        f.rx = b"hello".to_vec();
        f.modem = [true, false, true, true];
        let (tx, lines, params) = (f.tx.clone(), f.lines.clone(), f.params.clone());
        let l = TransportLink::new(Box::new(f)).unwrap();
        let mut buf = [0u8; 16];
        assert!(matches!(l.read(&mut buf).unwrap(), Read::Got(5)));
        assert!(matches!(l.read(&mut buf).unwrap(), Read::Idle));
        l.write_all(b"dir\r").unwrap();
        assert_eq!(*tx.lock().unwrap(), b"dir\r");
        l.set_dtr(true).unwrap();
        l.set_rts(false).unwrap();
        l.set_break(true).unwrap();
        assert_eq!(
            *lines.lock().unwrap(),
            ["dtr true", "rts false", "break true"]
        );
        assert_eq!(l.modem_status().unwrap(), 0x10 | 0x40 | 0x80);
        l.purge(true, true).unwrap();
        let mut s = Settings::new(9600);
        s.data_bits = 7;
        s.parity = Parity::Even;
        s.stop_bits = StopBits::Two;
        l.configure(&s).unwrap();
        assert_eq!(
            *params.lock().unwrap(),
            Some(SerialParams {
                baud_rate: 9600,
                data_bits: 7,
                parity: SerialParity::Even,
                stop_bits: SerialStopBits::Two,
            })
        );
        s.stop_bits = StopBits::OnePointFive;
        s.parity = Parity::Odd;
        l.configure(&s).unwrap();
        s.parity = Parity::None;
        s.stop_bits = StopBits::One;
        l.configure(&s).unwrap();
    }

    #[test]
    fn what_a_transport_cannot_do_is_refused() {
        let mut f = Fake::new();
        f.modem_lines = false;
        let l = TransportLink::new(Box::new(f)).unwrap();
        for e in [
            l.set_dtr(true).unwrap_err(),
            l.set_rts(true).unwrap_err(),
            l.set_break(true).unwrap_err(),
            l.modem_status().unwrap_err(),
        ] {
            assert_eq!(e.kind(), io::ErrorKind::Unsupported);
        }
        let mut s = Settings::new(9600);
        for (parity, flow) in [
            (Parity::Mark, Flow::None),
            (Parity::Space, Flow::None),
            (Parity::None, Flow::RtsCts),
            (Parity::None, Flow::XonXoff),
        ] {
            s.parity = parity;
            s.flow = flow;
            assert_eq!(
                l.configure(&s).unwrap_err().kind(),
                io::ErrorKind::Unsupported
            );
        }
    }

    #[test]
    fn a_closed_transport_is_a_lost_port() {
        let mut f = Fake::new();
        f.eof = true;
        let l = TransportLink::new(Box::new(f)).unwrap();
        assert_eq!(
            l.read(&mut [0u8; 4]).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn queued_writers_are_not_starved_by_idle_reads() {
        let l = Arc::new(TransportLink::new(Box::new(Fake::new())).unwrap());
        let reader = {
            let l = l.clone();
            std::thread::spawn(move || {
                let start = Instant::now();
                while start.elapsed() < Duration::from_millis(300) {
                    let _ = l.read(&mut [0u8; 4]);
                }
            })
        };
        std::thread::sleep(Duration::from_millis(20));
        let mut worst = Duration::ZERO;
        for _ in 0..10 {
            let start = Instant::now();
            l.write_all(b"x").unwrap();
            worst = worst.max(start.elapsed());
        }
        reader.join().unwrap();
        // One slice, with room for a loaded test machine.
        assert!(worst < READ_SLICE * 10, "a write waited {worst:?}");
    }
}

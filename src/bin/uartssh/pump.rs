// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Howard M. Harte

//! The byte pump: everything that decides whether a byte survives the trip.
//!
//! Nothing here knows what a serial port or an SSH channel is -- it moves
//! bytes between a `Read` and a `Write` -- which is what makes the failure
//! modes testable.  Both of them matter:
//!
//! **A short write silently loses bytes.** `Write::write` is allowed to
//! accept fewer bytes than it was offered, and both endpoints do: a serial
//! driver takes what fits in its output buffer, and a non-blocking libssh2
//! channel takes what fits in the window.  `dst.write(buf)` with the return
//! value dropped compiles, runs, and quietly deletes the tail of a chunk. On
//! a terminal that is one missing byte in the middle of an escape sequence --
//! which does not look like a bridge bug, it looks like the terminal
//! mis-parsing CSI, i.e. like a defect in the thing under test.
//!
//! **`Ok(0)` means opposite things on the two sides.** From an SSH channel it
//! is real EOF: the remote shell exited. From a serial port there is no such
//! thing as EOF -- a quiet line is just quiet -- so the same value must not
//! end the session. [`classify`] takes that as an argument instead of
//! guessing, and both readings are pinned by a test.

use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

/// Which way a chunk of bytes was going.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    /// Remote shell -> terminal screen.
    HostToTerm,
    /// Terminal keyboard -> remote shell.
    TermToHost,
    /// Injected keystrokes (`--stdin`, `--send`) -> remote shell.
    ///
    /// Kept distinct from [`Dir::TermToHost`] on purpose. Both end up in the
    /// same SSH channel, but a capture labelled "what the terminal sent" must
    /// contain only what the terminal sent: the whole evidentiary value of
    /// these files is that they are the wire, and quietly folding the
    /// operator's keystrokes into them would make every later reading of them
    /// wrong.
    KeyToHost,
}

impl Dir {
    /// Fixed-width tag for trace lines.
    pub fn tag(self) -> &'static str {
        match self {
            Dir::HostToTerm => "H>T",
            Dir::TermToHost => "T>H",
            Dir::KeyToHost => "K>H",
        }
    }
}

/// What one read attempt produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// This many bytes are in the buffer.
    Data(usize),
    /// Nothing to read right now; try again.
    Idle,
    /// The far end closed.
    Eof,
}

/// Turn a `Read::read` result into an [`Outcome`].
///
/// `eof_on_zero` distinguishes the two endpoints: `true` for the SSH channel,
/// where `Ok(0)` is the remote shell exiting, and `false` for the serial
/// port, where it is just an idle line.  Getting this backwards produces a
/// bridge that exits the instant the terminal stops typing.
///
/// `WouldBlock`, `TimedOut` and `Interrupted` are all "nothing right now":
/// the first is the non-blocking SSH session, the second is the serial read
/// timeout expiring, and the third is a signal landing mid-syscall.
pub fn classify(r: io::Result<usize>, eof_on_zero: bool) -> io::Result<Outcome> {
    match r {
        Ok(0) if eof_on_zero => Ok(Outcome::Eof),
        Ok(0) => Ok(Outcome::Idle),
        Ok(n) => Ok(Outcome::Data(n)),
        Err(e) => match e.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted => {
                Ok(Outcome::Idle)
            }
            _ => Err(e),
        },
    }
}

/// How much work one [`push_all`] took.  Both counters staying at zero on a
/// busy link is the sign that the endpoint is absorbing whole chunks; either
/// one climbing is the sign that the naive `write` would have been dropping
/// bytes all along.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PushStats {
    /// Writes that accepted some but not all of what was offered.
    pub short_writes: u64,
    /// Writes that accepted nothing and had to be retried.
    pub blocked_writes: u64,
}

impl PushStats {
    /// Fold another push's counters in.
    pub fn add(&mut self, other: PushStats) {
        self.short_writes += other.short_writes;
        self.blocked_writes += other.blocked_writes;
    }
}

/// Retry pause after a write that accepted nothing.
///
/// Long enough not to spin a core against a full serial buffer, short next to
/// the 520 us character time at 19200 baud.
const BLOCKED_BACKOFF: Duration = Duration::from_micros(200);

/// Write **every** byte of `buf`, tolerating short writes and would-block.
///
/// This is `write_all` plus two things `write_all` will not do: it treats
/// `WouldBlock`/`TimedOut` as "retry" rather than as failure -- which matters
/// because a non-blocking libssh2 channel returns exactly that when its window
/// is full, and `write_all` would return an error having already consumed
/// part of the buffer, with no way for the caller to know how much -- and it
/// gives up after `budget` rather than spinning forever against an endpoint
/// that has stopped draining.
/// The budget bounds retries; individual destination writes must themselves
/// be bounded or nonblocking, since this function cannot interrupt a syscall.
///
/// A timeout here is reported, never swallowed: bytes that did not reach the
/// terminal are a corrupted stream, and the operator needs to know the trace
/// is no longer a faithful record of the session.
pub fn push_all<W: Write>(dst: &mut W, buf: &[u8], budget: Duration) -> io::Result<PushStats> {
    let mut stats = PushStats::default();
    let mut sent = 0usize;
    let started = Instant::now();

    while sent < buf.len() {
        let previous_sent = sent;
        match dst.write(&buf[sent..]) {
            Ok(0) => {
                // Per the `Write` contract this means "cannot accept more
                // right now".  Treated as backpressure, not as failure --
                // a serial driver whose output buffer is full says this.
                stats.blocked_writes += 1;
            }
            Ok(n) => {
                if sent + n < buf.len() {
                    stats.short_writes += 1;
                }
                sent += n;
                if sent == buf.len() {
                    return Ok(stats);
                }
            }
            Err(e) => match e.kind() {
                io::ErrorKind::WouldBlock
                | io::ErrorKind::TimedOut
                | io::ErrorKind::Interrupted => {
                    stats.blocked_writes += 1;
                }
                _ => return Err(e),
            },
        }

        if started.elapsed() >= budget {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "wrote {} of {} bytes in {:?}; the far end stopped accepting data",
                    sent,
                    buf.len(),
                    budget
                ),
            ));
        }
        // Back off only after a refusal, not after useful progress.
        if sent == previous_sent {
            std::thread::sleep(BLOCKED_BACKOFF);
        }
    }

    Ok(stats)
}

/// Running byte counts for the banner and `--stats`.
#[derive(Debug, Default, Clone, Copy)]
pub struct Counters {
    /// Bytes carried remote -> terminal.
    pub h2t: u64,
    /// Bytes carried terminal -> remote.
    pub t2h: u64,
    /// Bytes injected from this console or `--send` -> remote.
    pub k2h: u64,
    /// Accumulated write-retry counters.
    pub push: PushStats,
}

/// Watches the terminal's keystrokes for the opt-in quit sequence.
///
/// The rule is "the escape byte twice in a row", and the state survives
/// across reads -- the two bytes routinely land in different chunks, since
/// at 19200 baud a person's two keystrokes are thousands of character times
/// apart.  A watcher that only looked inside one buffer would appear to work
/// when tested with a canned string and never fire in the operator's hands.
///
/// The escape bytes are forwarded to the remote like any other data.  Holding
/// the first one back to see whether a second follows would add a keystroke
/// of latency to every press of that key, and the session is ending anyway.
#[derive(Debug, Default)]
pub struct EscapeWatch {
    key: Option<u8>,
    armed: bool,
}

impl EscapeWatch {
    /// Watch for `key`; `None` disables the watcher entirely.
    pub fn new(key: Option<u8>) -> Self {
        Self { key, armed: false }
    }

    /// Feed bytes read from the terminal.  Returns `true` once the sequence
    /// completes.
    pub fn scan(&mut self, buf: &[u8]) -> bool {
        let key = match self.key {
            Some(k) => k,
            None => return false,
        };
        for &b in buf {
            if b == key {
                if self.armed {
                    return true;
                }
                self.armed = true;
            } else {
                self.armed = false;
            }
        }
        false
    }
}

/// Move up to `buf.len()` bytes from `src` to `dst`, reporting what happened.
///
/// `inspect` sees the bytes that were actually read, before they are written,
/// so a failure trace retains the source bytes, including an unsent tail if
/// forwarding fails. It is not a delivery acknowledgement from the destination.
pub fn transfer<S, D, F>(
    src: &mut S,
    dst: &mut D,
    buf: &mut [u8],
    eof_on_zero: bool,
    budget: Duration,
    mut inspect: F,
) -> io::Result<(Outcome, PushStats)>
where
    S: Read,
    D: Write,
    F: FnMut(&[u8]),
{
    if buf.is_empty() {
        return Ok((Outcome::Idle, PushStats::default()));
    }
    match classify(src.read(buf), eof_on_zero)? {
        Outcome::Data(n) => {
            inspect(&buf[..n]);
            let stats = push_all(dst, &buf[..n], budget)?;
            Ok((Outcome::Data(n), stats))
        }
        other => Ok((other, PushStats::default())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[test]
    fn partial_progress_does_not_bypass_the_write_budget() {
        struct OneByte(Vec<u8>);
        impl Write for OneByte {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.push(bytes[0]);
                Ok(1)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut writer = OneByte(Vec::new());
        let error = push_all(&mut writer, b"abc", Duration::ZERO).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(writer.0, b"a");
        assert!(error.to_string().contains("wrote 1 of 3"));
    }

    #[test]
    fn an_empty_transfer_buffer_is_idle_without_reading_or_reporting_eof() {
        struct NoRead;
        impl Read for NoRead {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                panic!("empty transfer must not read")
            }
        }
        let (outcome, stats) = transfer(
            &mut NoRead,
            &mut Vec::new(),
            &mut [],
            true,
            Duration::ZERO,
            |_| panic!("nothing was read"),
        )
        .unwrap();
        assert_eq!(outcome, Outcome::Idle);
        assert_eq!(stats, PushStats::default());
    }

    /// A `Write` that accepts at most `per_write` bytes at a time and refuses
    /// entirely every `block_every`-th call -- i.e. a serial driver with a
    /// small output buffer, or an SSH channel with a nearly closed window.
    struct StingyWriter {
        got: Vec<u8>,
        per_write: usize,
        block_every: usize,
        calls: usize,
        block_kind: io::ErrorKind,
    }

    impl StingyWriter {
        fn new(per_write: usize, block_every: usize) -> Self {
            Self {
                got: Vec::new(),
                per_write,
                block_every,
                calls: 0,
                block_kind: io::ErrorKind::WouldBlock,
            }
        }
    }

    impl Write for StingyWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.calls += 1;
            if self.block_every > 0 && self.calls % self.block_every == 0 {
                return Err(io::Error::new(self.block_kind, "full"));
            }
            let n = buf.len().min(self.per_write);
            self.got.extend_from_slice(&buf[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A `Write` that never accepts anything.
    struct DeadWriter;
    impl Write for DeadWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::WouldBlock, "never"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A `Read` serving canned chunks, then a chosen terminal condition.
    struct ScriptedReader {
        chunks: VecDeque<io::Result<Vec<u8>>>,
    }

    impl ScriptedReader {
        fn new(chunks: Vec<io::Result<Vec<u8>>>) -> Self {
            Self {
                chunks: chunks.into_iter().collect(),
            }
        }
    }

    impl Read for ScriptedReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.chunks.pop_front() {
                Some(Ok(v)) => {
                    let n = v.len().min(buf.len());
                    buf[..n].copy_from_slice(&v[..n]);
                    Ok(n)
                }
                Some(Err(e)) => Err(e),
                None => Ok(0),
            }
        }
    }

    // ---- push_all: the byte-loss guard -------------------------------

    #[test]
    fn push_all_delivers_every_byte_through_short_writes() {
        // THE test.  A naive `dst.write(buf)` here delivers 3 of 1000 bytes
        // and reports success.
        let payload: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let mut w = StingyWriter::new(3, 0);
        let stats = push_all(&mut w, &payload, Duration::from_secs(5)).unwrap();
        assert_eq!(w.got, payload, "bytes were lost or reordered");
        assert!(
            stats.short_writes > 300,
            "a 3-byte-at-a-time sink must report short writes, got {:?}",
            stats
        );
    }

    #[test]
    fn push_all_survives_would_block() {
        let payload: Vec<u8> = (0..500u32).map(|i| i as u8).collect();
        let mut w = StingyWriter::new(7, 3); // every 3rd call refuses
        let stats = push_all(&mut w, &payload, Duration::from_secs(5)).unwrap();
        assert_eq!(w.got, payload);
        assert!(stats.blocked_writes > 0, "{:?}", stats);
    }

    #[test]
    fn push_all_survives_timed_out_and_interrupted() {
        // A serial write hitting its timeout, and a signal landing mid-call,
        // are both "retry" -- not "give up and drop the tail".
        for kind in [io::ErrorKind::TimedOut, io::ErrorKind::Interrupted] {
            let payload = vec![0xAAu8; 200];
            let mut w = StingyWriter::new(5, 2);
            w.block_kind = kind;
            let stats = push_all(&mut w, &payload, Duration::from_secs(5)).unwrap();
            assert_eq!(w.got, payload, "{:?} lost bytes", kind);
            assert!(stats.blocked_writes > 0, "{:?}: {:?}", kind, stats);
        }
    }

    #[test]
    fn push_all_treats_write_zero_as_backpressure_not_failure() {
        struct Grudging {
            got: Vec<u8>,
            calls: usize,
        }
        impl Write for Grudging {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.calls += 1;
                if self.calls % 2 == 1 {
                    return Ok(0);
                }
                self.got.extend_from_slice(&buf[..1]);
                Ok(1)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut w = Grudging {
            got: Vec::new(),
            calls: 0,
        };
        let stats = push_all(&mut w, b"abcdef", Duration::from_secs(5)).unwrap();
        assert_eq!(w.got, b"abcdef");
        assert_eq!(stats.blocked_writes, 6);
    }

    #[test]
    fn push_all_gives_up_loudly_rather_than_hanging() {
        let err = push_all(&mut DeadWriter, b"hello", Duration::from_millis(50)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(
            err.to_string().contains("0 of 5"),
            "the message must say how much was lost: {}",
            err
        );
    }

    #[test]
    fn push_all_of_nothing_touches_nothing() {
        let mut w = StingyWriter::new(1, 1); // would refuse on its first call
        let stats = push_all(&mut w, b"", Duration::from_millis(10)).unwrap();
        assert_eq!(stats, PushStats::default());
        assert_eq!(w.calls, 0);
    }

    #[test]
    fn push_all_propagates_real_errors_immediately() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "gone"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let err = push_all(&mut Broken, b"x", Duration::from_secs(5)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }

    // ---- classify: the asymmetric EOF --------------------------------

    #[test]
    fn zero_is_eof_on_ssh_and_idle_on_serial() {
        // The asymmetry itself.  Read it as EOF on the serial side and the
        // bridge exits the moment nobody is typing.
        assert_eq!(classify(Ok(0), true).unwrap(), Outcome::Eof);
        assert_eq!(classify(Ok(0), false).unwrap(), Outcome::Idle);
    }

    #[test]
    fn data_and_idle_kinds_are_recognised() {
        assert_eq!(classify(Ok(7), true).unwrap(), Outcome::Data(7));
        for kind in [
            io::ErrorKind::WouldBlock,
            io::ErrorKind::TimedOut,
            io::ErrorKind::Interrupted,
        ] {
            assert_eq!(
                classify(Err(io::Error::new(kind, "x")), true).unwrap(),
                Outcome::Idle,
                "{:?} should be idle",
                kind
            );
        }
    }

    #[test]
    fn real_read_errors_are_not_swallowed_as_idle() {
        let e = classify(
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "nope")),
            false,
        )
        .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
    }

    // ---- transfer ----------------------------------------------------

    #[test]
    fn transfer_moves_data_and_shows_it_to_the_inspector() {
        let mut src = ScriptedReader::new(vec![Ok(b"hello".to_vec())]);
        let mut dst = StingyWriter::new(2, 0);
        let mut buf = [0u8; 64];
        let mut seen = Vec::new();
        let (outcome, _) = transfer(
            &mut src,
            &mut dst,
            &mut buf,
            true,
            Duration::from_secs(1),
            |b| seen.extend_from_slice(b),
        )
        .unwrap();
        assert_eq!(outcome, Outcome::Data(5));
        assert_eq!(seen, b"hello");
        assert_eq!(dst.got, b"hello");
    }

    #[test]
    fn transfer_reports_eof_without_writing() {
        let mut src = ScriptedReader::new(vec![]);
        let mut dst = StingyWriter::new(64, 0);
        let mut buf = [0u8; 64];
        let (outcome, _) = transfer(
            &mut src,
            &mut dst,
            &mut buf,
            true,
            Duration::from_secs(1),
            |_| {},
        )
        .unwrap();
        assert_eq!(outcome, Outcome::Eof);
        assert!(dst.got.is_empty());
    }

    #[test]
    fn transfer_records_the_trace_even_when_the_write_fails() {
        // The last thing the terminal sent before the link died is exactly
        // what you want in the log.
        let mut src = ScriptedReader::new(vec![Ok(b"last words".to_vec())]);
        let mut buf = [0u8; 64];
        let mut seen = Vec::new();
        let err = transfer(
            &mut src,
            &mut DeadWriter,
            &mut buf,
            true,
            Duration::from_millis(20),
            |b| seen.extend_from_slice(b),
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert_eq!(seen, b"last words");
    }

    #[test]
    fn transfer_never_writes_stale_buffer_bytes() {
        // A read of 2 bytes into a buffer still holding a previous 5-byte
        // chunk must forward 2, not 5.
        let mut src = ScriptedReader::new(vec![Ok(b"ab".to_vec())]);
        let mut dst = StingyWriter::new(64, 0);
        let mut buf = [b'Z'; 64];
        transfer(
            &mut src,
            &mut dst,
            &mut buf,
            true,
            Duration::from_secs(1),
            |_| {},
        )
        .unwrap();
        assert_eq!(dst.got, b"ab");
    }

    // ---- escape watch ------------------------------------------------

    #[test]
    fn escape_disabled_by_default_never_fires() {
        let mut w = EscapeWatch::new(None);
        assert!(!w.scan(&[0x1d, 0x1d, 0x1d, 0x1d]));
    }

    #[test]
    fn escape_fires_on_two_in_a_row() {
        let mut w = EscapeWatch::new(Some(0x1d));
        assert!(!w.scan(b"hello"));
        assert!(w.scan(&[0x1d, 0x1d]));
    }

    #[test]
    fn escape_fires_across_separate_reads() {
        // The real case: two keystrokes arrive in two different reads,
        // thousands of character times apart.  A within-one-buffer scan
        // would pass the test above and never fire in practice.
        let mut w = EscapeWatch::new(Some(0x1d));
        assert!(!w.scan(&[0x1d]));
        assert!(w.scan(&[0x1d]));
    }

    #[test]
    fn escape_is_disarmed_by_an_intervening_byte() {
        let mut w = EscapeWatch::new(Some(0x1d));
        assert!(!w.scan(&[0x1d]));
        assert!(!w.scan(b"x"));
        assert!(!w.scan(&[0x1d]), "the run was broken; one press is not two");
        assert!(w.scan(&[0x1d]));
    }

    #[test]
    fn escape_does_not_fire_on_a_single_press_among_traffic() {
        let mut w = EscapeWatch::new(Some(b'~'));
        assert!(!w.scan(b"echo ~ && ls ~"));
    }

    // ---- against a real OS byte stream -------------------------------

    /// The fakes above are hand-made, and a hand-made fake can agree with a
    /// hand-made implementation about a shared misunderstanding.  This drives
    /// the same code against a genuine non-blocking socket.
    ///
    /// WHAT IT PROVES: `push_all` delivers every byte, in order, through a
    /// real OS byte stream.
    ///
    /// Windows loopback buffering may accept the whole write even with small
    /// socket buffers, so this test does not assert retry-path coverage.
    /// StingyWriter deterministically exercises short writes and refusal.
    #[test]
    fn push_all_delivers_everything_through_a_real_socket_backing_up() {
        use socket2::{Domain, Protocol, Socket, Type};
        use std::net::{TcpListener, TcpStream};
        use std::sync::mpsc;

        const PAYLOAD: usize = 256 * 1024;
        const BUF: usize = 4096;

        // Small kernel buffers on both ends and a peer that stalls before
        // reading. On a platform whose loopback does exert backpressure this
        // makes the retry path fire; on Windows it does not (see above). Kept
        // either way -- it costs nothing and the delivery check is the point.
        let l = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
        l.set_recv_buffer_size(BUF).unwrap();
        l.bind(
            &"127.0.0.1:0"
                .parse::<std::net::SocketAddr>()
                .unwrap()
                .into(),
        )
        .unwrap();
        l.listen(8).unwrap();
        let listener: TcpListener = l.into();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();

        let peer = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            std::thread::sleep(Duration::from_millis(100));
            let mut got = Vec::with_capacity(PAYLOAD);
            let mut buf = [0u8; BUF];
            while got.len() < PAYLOAD {
                match sock.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => panic!("peer read: {}", e),
                }
            }
            tx.send(got).unwrap();
        });

        let c = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
        c.set_send_buffer_size(BUF).unwrap();
        c.connect(&addr.into()).unwrap();
        let mut client: TcpStream = c.into();
        client.set_nonblocking(true).unwrap();

        let payload: Vec<u8> = (0..PAYLOAD).map(|i| (i % 253) as u8).collect();
        push_all(&mut client, &payload, Duration::from_secs(30)).unwrap();

        let got = rx.recv_timeout(Duration::from_secs(30)).unwrap();
        peer.join().unwrap();

        assert_eq!(got.len(), payload.len(), "bytes were lost on a real socket");
        assert_eq!(got, payload, "bytes were reordered or corrupted");
    }

    #[test]
    fn classify_agrees_with_a_real_socket_about_idle_and_eof() {
        use std::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let peer = std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            std::thread::sleep(Duration::from_millis(50));
            drop(sock); // clean close -> the client sees Ok(0)
        });

        let mut client = TcpStream::connect(addr).unwrap();
        client.set_nonblocking(true).unwrap();

        // Nothing sent yet: whatever kind the OS reports, it must mean Idle.
        let mut buf = [0u8; 64];
        assert_eq!(
            classify(client.read(&mut buf), true).unwrap(),
            Outcome::Idle,
            "an empty non-blocking socket must read as Idle, not as EOF"
        );

        peer.join().unwrap();
        // After a clean close the read returns Ok(0) -- real EOF this time.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match classify(client.read(&mut buf), true).unwrap() {
                Outcome::Eof => break,
                _ if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
                other => panic!("expected Eof after the peer closed, got {:?}", other),
            }
        }
    }

    #[test]
    fn counters_accumulate_push_stats() {
        let mut c = Counters::default();
        c.push.add(PushStats {
            short_writes: 2,
            blocked_writes: 3,
        });
        c.push.add(PushStats {
            short_writes: 1,
            blocked_writes: 1,
        });
        assert_eq!(c.push.short_writes, 3);
        assert_eq!(c.push.blocked_writes, 4);
    }

    #[test]
    fn direction_tags_are_distinct_and_fixed_width() {
        assert_ne!(Dir::HostToTerm.tag(), Dir::TermToHost.tag());
        assert_eq!(Dir::HostToTerm.tag().len(), Dir::TermToHost.tag().len());
    }
}

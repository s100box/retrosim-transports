// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Howard M. Harte

//! Console input and delayed startup keystrokes for the byte pump.
//!
//! A separate reader thread keeps blocking stdin reads off the pump. It owns
//! only stdin and its channel, and is not joined at process exit because a
//! console read may still be waiting for a key. The pump owns the mode guard.
//!
//! Interactive input disables line editing and echo while preserving signal
//! processing, so Ctrl-C stops the bridge. Redirected input is left unchanged.

use std::io::{self, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// One `--send` string and the pause that precedes it.
#[derive(Debug, Clone)]
pub struct Seed {
    /// Wait this long before sending, so the remote is ready to read it.
    pub delay: Duration,
    /// The bytes to inject.
    pub bytes: Vec<u8>,
}

/// A source of injected keystrokes.
pub struct Keyboard {
    rx: Receiver<Vec<u8>>,
    /// Restores the console on the way out.
    _mode: Option<ConsoleMode>,
    /// Whether stdin is being read at all (as opposed to `--send` only).
    from_console: bool,
    /// Whether stdin turned out to be a real console.
    interactive: bool,
}

impl Keyboard {
    /// Start the injector.  `seeds` are sent first, in order, each after its
    /// own delay; then stdin is read forever if `read_stdin`.
    ///
    /// `stop` is checked between seeds so that Ctrl-C during a long
    /// `--send-delay` does not leave the operator waiting on a script that is
    /// no longer wanted.
    pub fn start(seeds: Vec<Seed>, read_stdin: bool, stop: Arc<AtomicBool>) -> io::Result<Self> {
        let (tx, rx) = mpsc::channel::<Vec<u8>>();

        // Only touch the console mode if we are actually going to read it.
        let (mode, interactive) = if read_stdin {
            match ConsoleMode::enter()? {
                Some(m) => (Some(m), true),
                None => (None, false),
            }
        } else {
            (None, false)
        };

        thread::spawn(move || {
            for seed in seeds {
                if !seed.delay.is_zero() {
                    // Sleep in slices so Ctrl-C is noticed promptly rather
                    // than after the whole delay has run out.
                    let mut left = seed.delay;
                    let slice = Duration::from_millis(50);
                    while !left.is_zero() {
                        if !stop.load(Ordering::Relaxed) {
                            return;
                        }
                        let step = left.min(slice);
                        thread::sleep(step);
                        left -= step;
                    }
                }
                if !stop.load(Ordering::Relaxed) || tx.send(seed.bytes).is_err() {
                    return;
                }
            }

            if !read_stdin {
                return;
            }
            let mut stdin = io::stdin();
            let mut buf = [0u8; 256];
            loop {
                match stdin.read(&mut buf) {
                    // EOF on a pipe means the script is finished, not that
                    // the session is: the bridge keeps running so the
                    // terminal can be watched afterwards.
                    Ok(0) => return,
                    Ok(n) => {
                        if tx.send(buf[..n].to_vec()).is_err() {
                            return;
                        }
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => return,
                }
            }
        });

        Ok(Self {
            rx,
            _mode: mode,
            from_console: read_stdin,
            interactive,
        })
    }

    /// Everything typed or seeded since the last call.  Never blocks.
    pub fn poll(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        // Both `Empty` and `Disconnected` end the drain: a finished `--send`
        // script drops the sender, and that must read as "nothing more right
        // now", not as an error.
        while let Ok(chunk) = self.rx.try_recv() {
            out.extend_from_slice(&chunk);
        }
        out
    }

    /// How to describe this source in the banner.
    pub fn describe(&self) -> &'static str {
        match (self.from_console, self.interactive) {
            (false, _) => "--send only",
            (true, true) => "this console, character at a time",
            (true, false) => "stdin (not a console: piped)",
        }
    }
}

/// Restores the console input mode when dropped.
///
/// Held by [`Keyboard`] for the life of the bridge.  If the process dies
/// without unwinding, the console is left in character mode -- which is why
/// the ordinary exit path returns through `run` rather than calling
/// `process::exit` from inside the loop.
pub struct ConsoleMode {
    #[cfg(windows)]
    previous: u32,
    #[cfg(unix)]
    previous: libc::termios,
}

#[cfg(windows)]
mod ffi {
    pub type Handle = *mut std::ffi::c_void;

    pub const ENABLE_LINE_INPUT: u32 = 0x0002;
    pub const ENABLE_ECHO_INPUT: u32 = 0x0004;

    extern "system" {
        pub fn GetConsoleMode(handle: Handle, mode: *mut u32) -> i32;
        pub fn SetConsoleMode(handle: Handle, mode: u32) -> i32;
    }
}

#[cfg(windows)]
impl ConsoleMode {
    /// `Ok(None)` when stdin is not a console, which is not an error: it is
    /// a piped or redirected run.
    fn enter() -> io::Result<Option<Self>> {
        use std::os::windows::io::AsRawHandle;

        let handle = io::stdin().as_raw_handle() as ffi::Handle;
        let mut mode: u32 = 0;
        // This is also the console test: GetConsoleMode fails on a pipe.
        // SAFETY: stdin owns this borrowed handle; mode is writable for the call.
        if unsafe { ffi::GetConsoleMode(handle, &mut mode) } == 0 {
            return Ok(None);
        }
        // Clear line editing and echo; everything else -- crucially
        // ENABLE_PROCESSED_INPUT, which is what makes Ctrl-C an interrupt
        // rather than a byte -- is left exactly as it was.
        let wanted = mode & !(ffi::ENABLE_LINE_INPUT | ffi::ENABLE_ECHO_INPUT);
        // SAFETY: the borrowed console handle remains live; wanted is a flag value.
        if unsafe { ffi::SetConsoleMode(handle, wanted) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Some(Self { previous: mode }))
    }
}

#[cfg(windows)]
impl Drop for ConsoleMode {
    fn drop(&mut self) {
        use std::os::windows::io::AsRawHandle;
        let handle = io::stdin().as_raw_handle() as ffi::Handle;
        // SAFETY: the standard-input handle is borrowed; restoring flags transfers no ownership.
        unsafe { ffi::SetConsoleMode(handle, self.previous) };
    }
}

#[cfg(unix)]
impl ConsoleMode {
    fn enter() -> io::Result<Option<Self>> {
        // SAFETY: isatty accepts any file descriptor and retains no references.
        if unsafe { libc::isatty(libc::STDIN_FILENO) } != 1 {
            return Ok(None);
        }
        // SAFETY: termios contains integer fields and arrays; zero is valid.
        let mut previous: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: previous has libc's target-specific ABI and is writable.
        if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut previous) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut wanted = previous;
        // ICANON off: deliver each key as it is pressed. ECHO off: the
        // remote will echo onto the terminal's screen, which is where the
        // operator is looking. ISIG is deliberately untouched, so Ctrl-C
        // still signals.
        wanted.c_lflag &= !(libc::ICANON | libc::ECHO);
        wanted.c_cc[libc::VMIN] = 1;
        wanted.c_cc[libc::VTIME] = 0;
        // SAFETY: wanted is an initialized termios borrowed for this synchronous call.
        if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &wanted) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Some(Self { previous }))
    }
}

#[cfg(unix)]
impl Drop for ConsoleMode {
    fn drop(&mut self) {
        // SAFETY: previous was initialized by tcgetattr and remains live for the call.
        unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.previous) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn seeds_arrive_in_order() {
        let stop = Arc::new(AtomicBool::new(true));
        let seeds = vec![
            Seed {
                delay: Duration::ZERO,
                bytes: b"one".to_vec(),
            },
            Seed {
                delay: Duration::ZERO,
                bytes: b"two".to_vec(),
            },
        ];
        let mut kbd = Keyboard::start(seeds, false, stop).unwrap();

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut got = Vec::new();
        while got.len() < 6 && Instant::now() < deadline {
            got.extend_from_slice(&kbd.poll());
        }
        assert_eq!(got, b"onetwo".to_vec());
    }

    #[test]
    fn a_seed_waits_for_its_delay() {
        let stop = Arc::new(AtomicBool::new(true));
        let seeds = vec![Seed {
            delay: Duration::from_millis(150),
            bytes: b"x".to_vec(),
        }];
        let mut kbd = Keyboard::start(seeds, false, stop).unwrap();

        // Not immediately.
        assert!(kbd.poll().is_empty());

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut got = Vec::new();
        while got.is_empty() && Instant::now() < deadline {
            got.extend_from_slice(&kbd.poll());
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(got, b"x".to_vec());
    }

    /// A cancelled run must not sit through the rest of its script.
    #[test]
    fn clearing_the_run_flag_abandons_the_remaining_seeds() {
        let stop = Arc::new(AtomicBool::new(true));
        let seeds = vec![Seed {
            delay: Duration::from_secs(30),
            bytes: b"never".to_vec(),
        }];
        let mut kbd = Keyboard::start(seeds, false, Arc::clone(&stop)).unwrap();

        stop.store(false, Ordering::Relaxed);
        thread::sleep(Duration::from_millis(200));
        assert!(kbd.poll().is_empty());
    }

    #[test]
    fn polling_an_idle_keyboard_returns_nothing() {
        let stop = Arc::new(AtomicBool::new(true));
        let mut kbd = Keyboard::start(Vec::new(), false, stop).unwrap();
        assert!(kbd.poll().is_empty());
        assert_eq!(kbd.describe(), "--send only");
    }
}

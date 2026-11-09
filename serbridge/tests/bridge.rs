// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Howard M. Harte
//! serbridge as a process, holding a TCP "board" (a `tcp:` spec) so the
//! whole bridge — log, command file, RFC 2217 server, URL file, reconnect —
//! runs on any machine, with no serial port.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use retrosim_core::transport::{ModemControl, Transport};
use retrosim_transports::rfc2217::{bridge_addr, url_file, Rfc2217Transport};

const WAIT: Duration = Duration::from_secs(10);

struct Bridge {
    child: Option<Child>,
    dir: PathBuf,
    spec: String,
}

impl Bridge {
    fn start(name: &str, spec: &str) -> Bridge {
        let dir =
            std::env::temp_dir().join(format!("serbridge-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_serbridge"))
            .args(["--port", spec, "--listen", "0", "--quiet"])
            .current_dir(&dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        Bridge {
            child: Some(child),
            dir,
            spec: spec.to_string(),
        }
    }

    /// The bridge's address, from the file it writes for its `--port`.
    fn addr(&self) -> String {
        let deadline = Instant::now() + WAIT;
        loop {
            if let Some(a) = bridge_addr(&self.spec) {
                return a;
            }
            assert!(Instant::now() < deadline, "no URL file for {}", self.spec);
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn log(&self) -> String {
        String::from_utf8_lossy(&std::fs::read(self.dir.join("console.log")).unwrap_or_default())
            .into_owned()
    }

    fn wait_log(&self, want: &str) {
        let deadline = Instant::now() + WAIT;
        while !self.log().contains(want) {
            assert!(
                Instant::now() < deadline,
                "the log never said {want:?}:\n{}",
                self.log()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn command(&self, line: &str) {
        std::fs::write(self.dir.join("cmd.txt"), format!("{line}\n")).unwrap();
    }

    /// Stops the bridge the way an operator does, by its stop file.
    fn stop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = std::fs::write(self.dir.join("serbridge.stop"), "");
        let deadline = Instant::now() + WAIT;
        while child.try_wait().unwrap().is_none() {
            if Instant::now() > deadline {
                let _ = child.kill();
                panic!("the bridge did not stop");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
            // A killed bridge leaves its URL file behind.
            let _ = std::fs::remove_file(url_file(&self.spec));
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A "board": a TCP listener the bridge connects to.
fn board() -> (TcpListener, String) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let spec = format!("tcp:{}", l.local_addr().unwrap());
    (l, spec)
}

fn accept(l: &TcpListener) -> TcpStream {
    l.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + WAIT;
    loop {
        match l.accept() {
            Ok((s, _)) => {
                s.set_nonblocking(false).unwrap();
                s.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
                return s;
            }
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Err(e) => panic!("the bridge never connected: {e}"),
        }
    }
}

fn read_n(r: &mut dyn Read, want: usize) -> Vec<u8> {
    let deadline = Instant::now() + WAIT;
    let mut got = Vec::new();
    let mut buf = [0u8; 512];
    while got.len() < want && Instant::now() < deadline {
        if let Ok(n) = r.read(&mut buf) {
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
    }
    got
}

#[test]
fn a_tcp_board_is_logged_commanded_and_served() {
    let (l, spec) = board();
    let mut b = Bridge::start("serve", &spec);
    let mut boardside = accept(&l);
    b.wait_log(&format!("open {spec}; reopens it when it drops"));

    boardside.write_all(b"boot ok\r\n").unwrap();
    b.wait_log("boot ok");

    b.command("dir");
    assert_eq!(read_n(&mut boardside, 4), b"dir\r");

    let mut c = Rfc2217Transport::connect(&b.addr(), None).unwrap();
    c.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
    assert_eq!(c.signature().unwrap(), "serbridge");
    b.wait_log("client 1 connected");

    let all: Vec<u8> = (0..=255).collect();
    boardside.write_all(&all).unwrap();
    assert_eq!(read_n(&mut c, 256), all);
    c.write_all(&all).unwrap();
    assert_eq!(read_n(&mut boardside, 256), all);

    // A tcp: transport has modem lines of its own (DTR is accepted and does
    // nothing; CTS and DSR read on), and the bridge passes them through.
    c.set_dtr(true).unwrap();
    b.wait_log("client 1: DTR on");
    let deadline = Instant::now() + WAIT;
    while !c.read_cts().unwrap() {
        assert!(Instant::now() < deadline, "CTS never read on");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(c.read_dsr().unwrap());

    // The exhaustive byte fixture ended with XOFF after XON. Resume the
    // software gate before testing restoration of the separate RTS gate.
    c.write_all(&[0x11]).unwrap();
    assert_eq!(read_n(&mut boardside, 1), [0x11]);
    drop(c);
    b.wait_log("client 1 disconnected");
    boardside
        .write_all(b"logging without a client\r\n")
        .unwrap();
    b.wait_log("logging without a client");

    let url = url_file(&spec);
    assert!(url.exists());
    b.stop();
    assert!(!url.exists(), "the URL file outlived the bridge");
    b.wait_log("stopped");
}

#[test]
fn a_dropped_transport_is_reopened() {
    let (l, spec) = board();
    let b = Bridge::start("reopen", &spec);
    drop(accept(&l));
    b.wait_log("port lost");
    let mut again = accept(&l);
    b.wait_log(&format!("reconnected on {spec}"));
    again.write_all(b"back again").unwrap();
    b.wait_log("back again");
}

#[test]
fn a_transport_that_will_not_open_is_an_error() {
    let dead = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let dir = std::env::temp_dir().join(format!("serbridge-test-{}-dead", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_serbridge"))
        .args(["--port", &format!("tcp:{dead}")])
        .current_dir(&dir)
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains(&format!("serbridge: tcp:{dead}:")), "{err}");
}

#[test]
fn a_serial_spec_with_a_format_is_refused() {
    let out = Command::new(env!("CARGO_BIN_EXE_serbridge"))
        .args(["--port", "serial:COM5@9600,8N1"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("serial:NAME@BAUD"));
}

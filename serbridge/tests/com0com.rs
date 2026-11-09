// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Howard M. Harte
//! serbridge holding a real serial port, and retrosim-transports' own client
//! finding it from a `serial:` spec. Needs a null-modem pair — com0com on
//! Windows, `socat pty,raw,echo=0,link=/tmp/sbA pty,raw,echo=0,link=/tmp/sbB`
//! elsewhere — named in `SERBRIDGE_COM0COM` as `A,B`: the bridge holds A and
//! the test plays the board on B. Without the variable the test passes
//! without running. A pty pair has no modem lines, so on one the modem
//! checks are skipped and the test says so.
//!
//! ```text
//! SERBRIDGE_COM0COM=COM90,COM91 cargo test -p serbridge --test com0com
//! ```

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use retrosim_core::serial::{SerialParams, SerialParity, SerialStopBits};
use retrosim_transports::open_transport;
use retrosim_transports::rfc2217::{bridge_addr, url_file};

const WAIT: Duration = Duration::from_secs(10);

struct Bridge {
    child: Child,
    dir: PathBuf,
}

impl Bridge {
    /// Stops the bridge by its stop file, as an operator does.
    fn stop(&mut self) {
        std::fs::write(self.dir.join("serbridge.stop"), "").unwrap();
        let deadline = Instant::now() + WAIT;
        while self.child.try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline, "the bridge did not stop");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn log(dir: &std::path::Path) -> String {
    String::from_utf8_lossy(&std::fs::read(dir.join("console.log")).unwrap_or_default())
        .into_owned()
}

fn wait_log(dir: &std::path::Path, want: &str) {
    let deadline = Instant::now() + WAIT;
    while !log(dir).contains(want) {
        assert!(
            Instant::now() < deadline,
            "the log never said {want:?}:\n{}",
            log(dir)
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn eventually(what: &str, mut f: impl FnMut() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !f() {
        assert!(Instant::now() < deadline, "{what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn read_n(r: &mut dyn Read, want: usize) -> Vec<u8> {
    let deadline = Instant::now() + WAIT;
    let mut got = Vec::new();
    let mut buf = [0u8; 512];
    while got.len() < want && Instant::now() < deadline {
        if let Ok(n) = r.read(&mut buf) {
            got.extend_from_slice(&buf[..n]);
        }
    }
    got
}

fn exercise_bridge(a: &str, b: &str) {
    let dir = std::env::temp_dir().join(format!("serbridge-com0com-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut board = serialport::new(b, 115_200)
        .timeout(Duration::from_millis(50))
        .open()
        .unwrap();
    let lines = board.write_request_to_send(false).is_ok();
    // A file left by a bridge that was killed would be found before this
    // bridge writes its own.
    let _ = std::fs::remove_file(url_file(a));
    let mut bridge = Bridge {
        child: Command::new(env!("CARGO_BIN_EXE_serbridge"))
            .args(["--port", a, "--listen", "0", "--quiet"])
            .current_dir(&dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
        dir: dir.clone(),
    };
    eventually("no URL file", || bridge_addr(a).is_some());

    // A serial: spec, as any retrosim-transports program would give it.
    let mut t = open_transport(&format!("serial:{a}@115200"), false).unwrap();
    assert!(
        t.description().contains(" via rfc2217://127.0.0.1:"),
        "{}",
        t.description()
    );
    wait_log(&dir, "client 1 connected");

    let all: Vec<u8> = (0..=255).collect();
    board.write_all(&all).unwrap();
    t.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
    assert_eq!(read_n(&mut t, 256), all, "board -> client");
    t.write_all(&all).unwrap();
    assert_eq!(read_n(&mut board, 256), all, "client -> board");

    let mut params = SerialParams {
        baud_rate: 9600,
        data_bits: 8,
        parity: SerialParity::None,
        stop_bits: SerialStopBits::One,
    };
    t.reconfigure(&params).unwrap();
    wait_log(&dir, "client 1: 9600 8N1");

    if lines {
        // A Linux pty is always 8N1 (its driver rewrites CSIZE and PARENB), so
        // framing is checked on a real pair only.
        params.data_bits = 7;
        params.parity = SerialParity::Even;
        t.reconfigure(&params).unwrap();
        wait_log(&dir, "client 1: 9600 7E1");

        // com0com wires the pair as a null modem: RTS to the far CTS, DTR to the
        // far DSR.
        let m = t.modem_control().unwrap();
        m.set_rts(true).unwrap();
        eventually("far CTS on", || board.read_clear_to_send().unwrap());
        let m = t.modem_control().unwrap();
        m.set_rts(false).unwrap();
        eventually("far CTS off", || !board.read_clear_to_send().unwrap());
        board.write_request_to_send(true).unwrap();
        eventually("CTS on through the bridge", || {
            t.modem_control().unwrap().read_cts().unwrap()
        });
        let m = t.modem_control().unwrap();
        m.set_dtr(true).unwrap();
        wait_log(&dir, "client 1: DTR on");
        m.set_break(true).unwrap();
        m.set_break(false).unwrap();
        wait_log(&dir, "client 1: BREAK off");
    } else {
        eprintln!("{b} has no modem lines: the modem checks were skipped");
    }

    drop(t);
    wait_log(&dir, "no client left: 115200 8N1");
    bridge.stop();
    wait_log(&dir, "stopped");
}

#[test]
fn the_library_client_finds_and_drives_the_bridge() {
    let Ok(pair) = std::env::var("SERBRIDGE_COM0COM") else {
        eprintln!("SERBRIDGE_COM0COM not set: skipped");
        return;
    };
    let (a, b) = pair.split_once(',').expect("SERBRIDGE_COM0COM=A,B");
    exercise_bridge(a, b);
    // A qualified Windows device path must reach the same real serial port,
    // including RFC 2217 data, settings and modem-line controls.
    #[cfg(windows)]
    if !a.starts_with('\\') {
        exercise_bridge(&format!(r"\\.\{a}"), b);
        exercise_bridge(&format!(r"\\?\{a}"), b);
    }
}

// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Howard M. Harte
//! Live key-exchange regression: a rejected host key must prevent authentication.
//! Run the ignored test with the Python dependencies in `ci/requirements.txt`.

#![cfg(feature = "ssh")]

use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD, Engine};
use retrosim_core::transport::Transport;
use retrosim_transports::{SshAuth, SshAuthMethod, SshHostKeyPolicy, SshPtyParams, SshTransport};
use sha2::{Digest, Sha256};

struct Fixture {
    child: Child,
    trust_file: PathBuf,
    lines: Receiver<String>,
}
impl Fixture {
    fn start(mode: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let python =
            std::env::var_os("RETROSIM_SSH_TEST_PYTHON").unwrap_or_else(|| "python3".into());
        let mut child = Command::new(python)
            .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/ssh_fixture.py"))
            .arg(mode)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("start SSH fixture (install ci/requirements.txt)");
        let output = child.stdout.take().unwrap();
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            lines,
            trust_file: std::env::temp_dir().join(format!(
                "retrosim-live-hostkey-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            )),
        }
    }
    fn json(&self) -> serde_json::Value {
        let line = self
            .lines
            .recv_timeout(Duration::from_secs(20))
            .expect("SSH fixture JSON deadline");
        serde_json::from_str(&line).expect("SSH fixture JSON")
    }
    fn finish(&mut self) -> serde_json::Value {
        self.child
            .stdin
            .take()
            .unwrap()
            .write_all(b"finished\n")
            .unwrap();
        let outcome = self.json();
        let start = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success());
                return outcome;
            }
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "fixture exit deadline"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.trust_file);
    }
}

#[test]
#[ignore = "requires Python and ci/requirements.txt; runs in CI"]
fn rejected_keys_never_reach_user_authentication() {
    for case in [
        "match",
        "unknown",
        "changed",
        "pin",
        "wrong-pin",
        "insecure",
    ] {
        let mut fixture = Fixture::start("reject");
        let info = fixture.json();
        let port = info["port"].as_u64().unwrap() as u16;
        let key = info["key"].as_str().unwrap();
        let wire = STANDARD.decode(key).unwrap();
        let record = match case {
            "unknown" => format!("other.example ssh-rsa {key}\n"),
            "changed" => {
                let mut changed = wire.clone();
                *changed.last_mut().unwrap() ^= 1;
                format!("[127.0.0.1]:{port} ssh-rsa {}\n", STANDARD.encode(changed))
            }
            _ => format!("[127.0.0.1]:{port} ssh-rsa {key}\n"),
        };
        std::fs::write(&fixture.trust_file, &record).unwrap();
        let policy = match case {
            "pin" => SshHostKeyPolicy::PinnedSha256(Sha256::digest(&wire).into()),
            "wrong-pin" => SshHostKeyPolicy::PinnedSha256([0; 32]),
            "insecure" => SshHostKeyPolicy::InsecureAcceptAny,
            _ => SshHostKeyPolicy::KnownHosts(fixture.trust_file.clone()),
        };
        let auth = SshAuth {
            order: vec![SshAuthMethod::Password],
            password: Some("synthetic-test-value".into()),
            ..SshAuth::default()
        };
        let result = SshTransport::connect_with_policy(
            "fixture",
            "127.0.0.1",
            port,
            &SshPtyParams::default(),
            &auth,
            &policy,
        );
        let error = match result {
            Ok(_) => panic!("fixture must never authenticate a user"),
            Err(e) => e.to_string(),
        };
        let outcome = fixture.finish();
        let rejected = matches!(case, "unknown" | "changed" | "wrong-pin");
        let attempts = outcome["auth_attempts"].as_u64().unwrap();
        if rejected {
            assert_eq!(attempts, 0, "{case}: {error}");
        } else {
            assert!(attempts > 0, "{case}: {error}");
        }
        assert_eq!(
            error.contains("host-key verification"),
            rejected,
            "{case}: {error}"
        );
        assert_eq!(
            std::fs::read_to_string(&fixture.trust_file).unwrap(),
            record
        );
    }
}

#[test]
#[ignore = "requires Python and ci/requirements.txt; runs in CI"]
fn successful_sessions_honor_auth_policy_and_survive_read_timeouts() {
    for (mode, allow_none) in [("none", false), ("none", true), ("password", false)] {
        let mut fixture = Fixture::start(mode);
        let info = fixture.json();
        let auth = SshAuth {
            order: vec![if allow_none {
                SshAuthMethod::None
            } else {
                SshAuthMethod::Password
            }],
            password: Some("synthetic-test-value".into()),
            ..SshAuth::default()
        };
        let result = SshTransport::connect_with_policy(
            "fixture",
            "localhost",
            info["port"].as_u64().unwrap() as u16,
            &SshPtyParams::default(),
            &auth,
            &SshHostKeyPolicy::InsecureAcceptAny,
        );
        if mode == "none" && !allow_none {
            let error = result
                .err()
                .expect("password-only policy must reject none")
                .to_string();
            assert!(error.contains("policy disallows none"), "{error}");
        } else {
            let mut transport = result.unwrap();
            assert_eq!(
                transport.auth_method(),
                if allow_none {
                    SshAuthMethod::None
                } else {
                    SshAuthMethod::Password
                }
            );
            assert_eq!(transport.read(&mut []).unwrap(), 0);
            assert_eq!(transport.write(&[]).unwrap(), 0);
            assert!(transport.is_connected());
            transport.set_read_timeout(Some(Duration::ZERO)).unwrap();
            assert_eq!(
                transport.read(&mut [0]).unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            assert!(transport.is_connected());
            transport
                .set_read_timeout(Some(Duration::from_millis(30)))
                .unwrap();
            assert_eq!(
                transport.read(&mut [0]).unwrap_err().kind(),
                std::io::ErrorKind::TimedOut
            );
            assert!(transport.is_connected());
            transport
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            transport.write_all(b"echo after timeout").unwrap();
            let mut echo = [0; 18];
            transport.read_exact(&mut echo).unwrap();
            assert_eq!(&echo, b"echo after timeout");
            // The fixture waits for our signal, so it never closes first.
            let start = Instant::now();
            drop(transport);
            assert!(start.elapsed() < Duration::from_secs(1));
        }
        assert!(fixture.finish()["auth_attempts"].as_u64().unwrap() > 0);
    }
}

#[test]
#[ignore = "requires Python and ci/requirements.txt; runs in CI"]
fn a_full_ssh_send_window_is_backpressure_not_a_disconnect() {
    let mut fixture = Fixture::start("stall");
    let info = fixture.json();
    let auth = SshAuth {
        order: vec![SshAuthMethod::Password],
        password: Some("synthetic-test-value".into()),
        ..SshAuth::default()
    };
    let mut transport = SshTransport::connect_with_policy(
        "fixture",
        "127.0.0.1",
        info["port"].as_u64().unwrap() as u16,
        &SshPtyParams::default(),
        &auth,
        &SshHostKeyPolicy::InsecureAcceptAny,
    )
    .unwrap();
    transport.set_read_timeout(Some(Duration::ZERO)).unwrap();
    let chunk = [b'x'; 65536];
    let start = Instant::now();
    let mut accepted = 0;
    loop {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "fixture did not apply backpressure"
        );
        match transport.write(&chunk) {
            Ok(0) => panic!("SSH unexpectedly returned a zero-byte write"),
            Ok(n) => accepted += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => panic!("SSH write: {e}"),
        }
    }
    assert!(accepted > 0);
    assert!(transport.is_connected());
    drop(transport);
    fixture.finish();
}

#[test]
#[ignore = "requires Python and ci/requirements.txt; runs in CI"]
fn a_silent_ssh_peer_cannot_hold_setup_forever() {
    let mut fixture = Fixture::start("silent");
    let info = fixture.json();
    let start = Instant::now();
    let result = SshTransport::connect_with_policy(
        "fixture",
        "127.0.0.1",
        info["port"].as_u64().unwrap() as u16,
        &SshPtyParams::default(),
        &SshAuth::default(),
        &SshHostKeyPolicy::InsecureAcceptAny,
    );
    let error = result
        .err()
        .expect("silent SSH peer must time out")
        .to_string();
    assert!(error.contains("ssh handshake"), "{error}");
    assert!(start.elapsed() < Duration::from_secs(15));
    assert_eq!(fixture.finish()["auth_attempts"], 0);
}

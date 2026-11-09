// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Howard M. Harte

//! `uartssh` bridges a physical serial terminal to an SSH shell.
//!
//! One loop owns both endpoints, ordering terminal replies, injected keys and
//! capture offsets. Serial read timeouts pace idle work. `--chunk` limits each
//! serial write; OS flow control handles the terminal's XON/XOFF or RTS/CTS.

mod args;
mod expect;
mod hook;
mod inject;
mod keyboard;
mod manifest;
mod pump;
mod trace;

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use retrosim_core::transport::Transport;
use retrosim_transports::serial::SerialTransport;
use retrosim_transports::ssh::{parse_ssh_client_spec, SshPtyParams, SshTransport};
use retrosim_transports::ssh_auth::{self, KbdPrompt, SshAuth};

use args::{Action, Args};
use expect::Expect;
use hook::Hook;
use inject::{Injector, SequenceWatch};
use keyboard::{Keyboard, Seed};
use manifest::Manifest;
use pump::{Counters, Dir, EscapeWatch, Outcome};
use trace::Trace;

/// Give up on a stalled endpoint after this long and say so.  Generous next
/// to any real serial or TCP hiccup, short enough that a wedged bridge is
/// reported rather than left looking like a hung terminal.
const WRITE_BUDGET: Duration = Duration::from_secs(30);

/// Terminal-to-host read buffer.  Keystrokes and escape-sequence replies are
/// small; this only has to be big enough that a burst is not split.
const KEY_BUF: usize = 512;

/// How long to keep pumping after an `--expect-exit` script finishes.
///
/// The final key of a script is normally the one that quits the program under
/// test, and its parting output is part of the evidence. A bridge that closed
/// the instant the last key went out would truncate every capture at the most
/// interesting moment.
const FINISH_GRACE: Duration = Duration::from_secs(1);

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let action = match args::parse(argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("uartssh: {}", e);
            std::process::exit(2);
        }
    };

    let code = match action {
        Action::Help => {
            print!("{}", args::USAGE);
            0
        }
        Action::Version => {
            println!("uartssh {}", env!("CARGO_PKG_VERSION"));
            0
        }
        Action::ListPorts => match list_ports() {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("uartssh: {}", e);
                1
            }
        },
        Action::Run(a) => match run(*a) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("uartssh: {}", e);
                1
            }
        },
    };
    std::process::exit(code);
}

/// Enumerate the host's serial ports, with whatever identity the OS knows.
///
/// Worth having as a first-class action: on Windows the port number is the
/// single most common thing to get wrong, and a USB adapter's VID/PID is how
/// you tell the terminal's cable from the three other COM ports that a
/// debug probe or a Bluetooth stack put there.
fn list_ports() -> io::Result<()> {
    let ports = serialport::available_ports()
        .map_err(|e| io::Error::other(format!("cannot enumerate serial ports: {}", e)))?;
    if ports.is_empty() {
        println!("no serial ports found");
        return Ok(());
    }
    for p in ports {
        match p.port_type {
            serialport::SerialPortType::UsbPort(info) => {
                let mut who = format!("USB {:04x}:{:04x}", info.vid, info.pid);
                if let Some(m) = info.manufacturer.as_deref() {
                    who.push_str(&format!(" {}", m));
                }
                if let Some(prod) = info.product.as_deref() {
                    who.push_str(&format!(" {}", prod));
                }
                if let Some(sn) = info.serial_number.as_deref() {
                    who.push_str(&format!(" sn={}", sn));
                }
                println!("{:<12} {}", p.port_name, who);
            }
            serialport::SerialPortType::BluetoothPort => {
                println!("{:<12} Bluetooth", p.port_name)
            }
            serialport::SerialPortType::PciPort => println!("{:<12} PCI", p.port_name),
            serialport::SerialPortType::Unknown => println!("{:<12} -", p.port_name),
        }
    }
    Ok(())
}

/// Answers SSH challenges on this console.
///
/// `pre_supplied` is consumed by the first hidden prompt: when the operator
/// has already typed a password for `--ask-password`, asking again for the
/// keyboard-interactive challenge that carries the same secret is a way to
/// make people think the first one failed.
struct ConsolePrompt {
    pre_supplied: std::sync::Mutex<Option<String>>,
}

impl KbdPrompt for ConsolePrompt {
    fn respond(
        &self,
        _username: &str,
        instructions: &str,
        prompts: &[(String, bool)],
    ) -> Vec<String> {
        if !instructions.trim().is_empty() {
            eprintln!("{}", instructions.trim());
        }
        prompts
            .iter()
            .map(|(text, echo)| {
                if *echo {
                    eprint!("{}", text);
                    let _ = io::stderr().flush();
                    let mut line = String::new();
                    if io::stdin().read_line(&mut line).is_err() {
                        return String::new();
                    }
                    line.trim_end_matches(['\r', '\n']).to_string()
                } else {
                    if let Some(pw) = self.pre_supplied.lock().unwrap().take() {
                        return pw;
                    }
                    rpassword::prompt_password(text).unwrap_or_default()
                }
            })
            .collect()
    }
}

/// Assemble the authentication policy from the command line and environment.
fn build_auth(a: &Args) -> Result<SshAuth, String> {
    let mut auth = SshAuth::discovered();

    if let Some(order) = &a.auth_order {
        auth.order = order.clone();
    }
    // An explicit --identity replaces discovery rather than adding to it: if
    // you named the key you want offered, offering three others first can
    // exhaust the server's authentication attempt limit before yours is
    // tried, and the failure would name the wrong key.
    if !a.identities.is_empty() {
        for k in &a.identities {
            if !k.is_file() {
                return Err(format!("--identity {} does not exist", k.display()));
            }
        }
        auth.identities = a.identities.clone();
    }
    if let Some(var) = &a.password_env {
        match ssh_auth::password_from_env(&[var.as_str()]) {
            Some(pw) => auth.password = Some(pw),
            None => {
                return Err(format!(
                    "--password-env {} is unset or empty in this environment",
                    var
                ))
            }
        }
    }
    if a.ask_password {
        let pw = rpassword::prompt_password("password: ")
            .map_err(|e| format!("cannot read a password from this console: {}", e))?;
        auth.password = Some(pw);
    }

    auth.kbd_prompt = Some(Arc::new(ConsolePrompt {
        pre_supplied: std::sync::Mutex::new(auth.password.clone()),
    }));
    Ok(auth)
}

fn run(a: Args) -> Result<(), String> {
    trace::validate_outputs(
        a.log.as_deref(),
        a.capture.as_deref(),
        a.expect_manifest.as_deref(),
    )
    .map_err(|e| format!("session output paths: {e}"))?;
    let (user, host, port) =
        parse_ssh_client_spec(&a.ssh).map_err(|e| format!("--ssh {}: {}", a.ssh, e))?;

    // Serial first: a wrong COM port is the most likely mistake, and failing
    // before the SSH handshake means no password was typed for nothing.
    let mut serial =
        SerialTransport::open(&a.serial).map_err(|e| format!("{}\n  (try --list-ports)", e))?;
    serial
        .set_read_timeout(Some(Duration::from_millis(a.poll_ms)))
        .map_err(|e| format!("serial read timeout: {}", e))?;

    // Assert the outputs a terminal may be watching. Plenty of RS-232 gear
    // stays mute until it sees DSR/DCD, which on a null-modem cable is this
    // end's DTR -- and "the terminal is dead" is an expensive way to discover
    // an unasserted line. RTS is left alone under hardware handshaking, where
    // the driver owns it.
    let hw_flow = a.serial.ends_with(",hw");
    if let Some(mc) = serial.modem_control() {
        mc.set_dtr(true)
            .map_err(|e| format!("cannot assert DTR: {}", e))?;
        if !hw_flow {
            mc.set_rts(true)
                .map_err(|e| format!("cannot assert RTS: {}", e))?;
        }
    }

    let auth = build_auth(&a)?;
    let pty = SshPtyParams {
        term: a.term.clone(),
        cols: a.cols,
        rows: a.rows,
        // Report the cable's rate for programs that pace output from PTY speed.
        speed: Some(args::spec_baud(&a.serial)),
    };
    if a.host_key == retrosim_transports::SshHostKeyPolicy::InsecureAcceptAny {
        eprintln!(
            "uartssh: WARNING: SSH host-key verification disabled; the server can be impersonated"
        );
    }
    let mut ssh = SshTransport::connect_with_policy(&user, &host, port, &pty, &auth, &a.host_key)
        .map_err(|e| e.to_string())?;
    // Non-blocking: the loop is paced by the serial read, and a blocking SSH
    // read would stall the terminal-to-host direction behind an idle host.
    ssh.set_read_timeout(Some(Duration::ZERO))
        .map_err(|e| format!("ssh non-blocking: {}", e))?;

    let mut tracer = match (&a.log, &a.capture) {
        (None, None) => Trace::disabled(),
        (log, cap) => Trace::new(log.as_deref(), cap.as_deref())
            .map_err(|e| format!("cannot open the trace files: {}", e))?,
    };

    let running = Arc::new(AtomicBool::new(true));
    {
        let flag = Arc::clone(&running);
        // Ctrl-C asks the loop to finish rather than killing the process, so
        // the SSH channel is closed politely, the trace files are flushed and
        // closed instead of being truncated wherever the OS left them, and
        // the console input mode is restored by `Keyboard`'s drop.
        ctrlc::set_handler(move || flag.store(false, Ordering::Relaxed))
            .map_err(|e| format!("cannot install the Ctrl-C handler: {}", e))?;
    }

    // Started only now, and never earlier: `build_auth` may have read a
    // password from this same console, and two readers on one stdin is a way
    // to lose half a passphrase to a keystroke pump.
    let injecting = a.stdin || !a.send.is_empty();
    let mut keys = if injecting {
        let delay = Duration::from_millis(a.send_delay_ms);
        let seeds: Vec<Seed> = a
            .send
            .iter()
            .map(|bytes| Seed {
                delay,
                bytes: bytes.clone(),
            })
            .collect();
        Some(
            Keyboard::start(seeds, a.stdin, Arc::clone(&running))
                .map_err(|e| format!("cannot read this console: {}", e))?,
        )
    } else {
        None
    };

    // Prompt-driven injection. Shares the injector -- and therefore the
    // interlock -- with the keyboard: knowing *when* a key is wanted does not
    // make it safe to wedge one into the middle of a reply, so both gates
    // apply to the same bytes.
    let mut expect = Expect::new(
        a.expect.clone(),
        Duration::from_millis(a.expect_quiet_ms),
        a.expect_timeout_ms.map(Duration::from_millis),
    );
    let mut hook = a.expect_run.as_deref().map(Hook::new);
    let mut manifest = match &a.expect_manifest {
        Some(p) => {
            Some(Manifest::create(p).map_err(|e| format!("cannot open {}: {}", p.display(), e))?)
        }
        None => None,
    };
    let started = Instant::now();

    if !a.quiet {
        eprintln!("uartssh: serial   {}", a.serial);
        eprintln!(
            "uartssh: ssh      {} (auth: {}, TERM={} {}x{})",
            ssh.description(),
            ssh.auth_method(),
            a.term,
            a.cols,
            a.rows
        );
        if tracer.is_active() {
            if let Some(p) = &a.log {
                eprintln!("uartssh: log      {}", p.display());
            }
            if let Some(p) = &a.capture {
                eprintln!(
                    "uartssh: capture  {}.h2t.bin, {}.t2h.bin",
                    p.display(),
                    p.display()
                );
            }
        }
        if let Some(k) = &keys {
            eprintln!(
                "uartssh: keys     {}{}",
                k.describe(),
                if a.interlock { "" } else { ", interlock OFF" }
            );
        }
        if expect.is_active() {
            eprintln!("uartssh: expect   {}", expect.describe());
        }
        if let Some(cmd) = &a.expect_run {
            eprintln!("uartssh: on match {}", cmd);
        }
        match a.escape {
            Some(k) => eprintln!(
                "uartssh: quit with Ctrl-C here, or 0x{:02x} twice at the terminal",
                k
            ),
            None => eprintln!("uartssh: quit with Ctrl-C here"),
        }
    }

    let mut counters = Counters::default();
    let mut escape = EscapeWatch::new(a.escape);
    let mut sequence = SequenceWatch::new();
    let mut injector = Injector::new(a.interlock);
    let mut to_term = vec![0u8; a.chunk];
    let mut to_host = vec![0u8; KEY_BUF];
    let mut last_stats = Instant::now();
    let mut quit_reason = "Ctrl-C";
    // Held rather than returned, so the trace files are flushed and closed
    // before the process reports the failure. A stalled script is exactly the
    // run whose transcript you want to read.
    let mut fatal: Option<String> = None;
    let mut finished: Option<Instant> = None;

    while running.load(Ordering::Relaxed) {
        let mut trace_err: Option<io::Error> = None;
        let mut escape_hit = false;

        // Terminal -> host.  A serial port has no EOF, so `Ok(0)` here is an
        // idle line, not a hang-up: `eof_on_zero = false`.
        let (out, stats) = pump::transfer(
            &mut serial,
            &mut ssh,
            &mut to_host,
            false,
            WRITE_BUDGET,
            |bytes| {
                if let Err(e) = tracer.record(Dir::TermToHost, bytes) {
                    trace_err = Some(e);
                }
                // Watch how far into a reply the terminal is, so an injected
                // keystroke is never wedged into the middle of one.
                sequence.feed(bytes);
                if escape.scan(bytes) {
                    escape_hit = true;
                }
            },
        )
        .map_err(|e| format!("terminal -> host: {}", e))?;
        if let Some(e) = trace_err.take() {
            return Err(format!("cannot write the trace: {}", e));
        }
        if let Outcome::Data(n) = out {
            counters.t2h += n as u64;
        }
        counters.push.add(stats);
        if escape_hit {
            quit_reason = "escape sequence from the terminal";
            break;
        }

        // Injected keys -> host.  Same destination as the terminal's own
        // traffic, deliberately separate in the trace, and gated on the
        // terminal not being part-way through a reply.
        if let Some(k) = keys.as_mut() {
            let typed = k.poll();
            if !typed.is_empty() {
                injector.queue(&typed);
            }
        }
        if injector.is_pending() {
            let out = injector.drain(sequence.in_flight());
            if !out.is_empty() {
                tracer
                    .record(Dir::KeyToHost, &out)
                    .map_err(|e| format!("cannot write the trace: {}", e))?;
                let stats = pump::push_all(&mut ssh, &out, WRITE_BUDGET)
                    .map_err(|e| format!("injected keys -> host: {}", e))?;
                counters.push.add(stats);
                counters.k2h += out.len() as u64;
            }
        }

        // Host -> terminal.  Here `Ok(0)` really is EOF: the remote shell
        // exited, which is the ordinary way a session ends.
        let (out, stats) = pump::transfer(
            &mut ssh,
            &mut serial,
            &mut to_term,
            true,
            WRITE_BUDGET,
            |bytes| {
                if let Err(e) = tracer.record(Dir::HostToTerm, bytes) {
                    trace_err = Some(e);
                }
                // What the host printed is what an expect rule waits for.
                expect.feed(bytes);
            },
        )
        .map_err(|e| format!("host -> terminal: {}", e))?;
        if let Some(e) = trace_err.take() {
            return Err(format!("cannot write the trace: {}", e));
        }
        match out {
            Outcome::Data(n) => counters.h2t += n as u64,
            Outcome::Eof => {
                quit_reason = "the remote shell closed the session";
                break;
            }
            Outcome::Idle => {}
        }
        counters.push.add(stats);

        if !ssh.is_connected() {
            quit_reason = "the ssh connection dropped";
            break;
        }

        // Answer a prompt if one is on the screen and the host has stopped
        // talking. The keys go through the injector like any other, so the
        // interlock still applies.
        if let Some(fired) = expect.poll() {
            let note = format!(
                "expect: matched {:?} -> {} byte(s)",
                fired.pattern,
                fired.keys.len()
            );
            if !a.quiet {
                eprintln!("uartssh: {}", note);
            }
            tracer
                .note(&note)
                .map_err(|e| format!("cannot write the trace: {}", e))?;
            // The h2t count taken HERE is the end of the screen that was
            // photographed: nothing the injected key causes has happened yet,
            // so replaying this many bytes into the model reproduces exactly
            // this screen and not the beginning of the next one.
            if let Some(m) = manifest.as_mut() {
                m.record(
                    expect.matches,
                    &fired.pattern,
                    &fired.keys,
                    counters.h2t,
                    started.elapsed().as_secs_f64(),
                )
                .map_err(|e| format!("cannot write the manifest: {}", e))?;
            }
            // BEFORE the keys: the screen that prompted is still on the
            // terminal, and this is the only moment it can be photographed.
            if let Some(h) = hook.as_mut() {
                if let Some(problem) = h.fire(expect.matches, &fired.pattern) {
                    eprintln!("uartssh: {}", problem);
                    tracer
                        .note(&problem)
                        .map_err(|e| format!("cannot write the trace: {}", e))?;
                }
            }
            if !fired.keys.is_empty() {
                injector.queue(&fired.keys);
            }
        }

        let now = Instant::now();
        if let Some(stuck) = expect.stalled(now) {
            fatal = Some(format!(
                "expect: waited {:.0}s for {:?} and it never appeared -- the \
                 run is stuck at that step, not past it",
                expect.waited(now).as_secs_f64(),
                stuck.pattern
            ));
            quit_reason = "an expected prompt never arrived";
            break;
        }
        // Finishing is not the same as being finished with. The last key of a
        // script is usually the one that quits the program under test, and
        // everything it prints on the way out belongs in the capture -- so
        // the pump keeps running until the keys have gone, a grace period has
        // passed, and the host has stopped talking.
        if a.expect_exit && expect.is_done() && !injector.is_pending() {
            let done_at = *finished.get_or_insert(now);
            if now.duration_since(done_at) >= FINISH_GRACE
                && expect.quiet_for(now) >= Duration::from_millis(a.expect_quiet_ms)
            {
                quit_reason = "the expect script finished";
                break;
            }
        }

        if let Some(secs) = a.stats_secs {
            if !a.quiet && last_stats.elapsed() >= Duration::from_secs(secs) {
                eprintln!(
                    "uartssh: {} bytes to the terminal, {} from it",
                    counters.h2t, counters.t2h
                );
                last_stats = Instant::now();
            }
        }
    }

    tracer
        .flush()
        .map_err(|e| format!("cannot flush the trace: {}", e))?;

    if !a.quiet {
        eprintln!(
            "uartssh: closing -- {} ({} bytes to the terminal, {} from it)",
            quit_reason, counters.h2t, counters.t2h
        );
        if counters.k2h > 0 {
            eprintln!("uartssh: {} bytes injected from the keyboard", counters.k2h);
        }
        if expect.is_active() {
            eprintln!("uartssh: {} prompt(s) answered", expect.matches);
            // An unfinished script is not obvious from the transcript -- the
            // session simply stops -- so it is stated. A run that answered 40
            // prompts and stopped at the 41st looks successful from the
            // byte counts alone.
            if expect.has_script() && !expect.is_done() {
                eprintln!(
                    "uartssh: the expect script did NOT finish -- results \
                     after the last answered prompt are missing, not passing"
                );
            }
        }
        if let Some(h) = &hook {
            eprintln!("uartssh: {} hook run(s)", h.runs);
            // Stated separately and unconditionally when non-zero: a gap in a
            // numbered sequence of captures is otherwise found much later and
            // read as a crash.
            if h.failures > 0 {
                eprintln!(
                    "uartssh: {} hook run(s) FAILED -- that many screens were \
                     not captured, so the sequence has holes",
                    h.failures
                );
            }
        }
        // A forced release means a keystroke went out while the terminal
        // looked mid-reply -- either the terminal really did abandon a
        // sequence, or this bridge misread one. Either way it is the thing to
        // suspect first if a vttest result looks wrong, so it is never
        // silent.
        if injector.forced_releases > 0 {
            eprintln!(
                "uartssh: {} injected chunk(s) released while a terminal reply \
                 looked unfinished -- suspect these first if a test reports a \
                 malformed report",
                injector.forced_releases
            );
        }
        // Only when non-zero: on a healthy link these stay at zero, and a
        // line of zeroes every run teaches people to ignore the line.
        if counters.push.short_writes > 0 || counters.push.blocked_writes > 0 {
            eprintln!(
                "uartssh: write backpressure -- {} short, {} blocked \
                 (normal when the terminal is slower than the host)",
                counters.push.short_writes, counters.push.blocked_writes
            );
        }
    }
    session_result(fatal, a.expect_exit, expect.has_script(), expect.is_done())
}

/// Automated runs succeed only after the requested script completes.
fn session_result(
    fatal: Option<String>,
    expect_exit: bool,
    has_script: bool,
    done: bool,
) -> Result<(), String> {
    if let Some(error) = fatal {
        return Err(error);
    }
    if expect_exit && has_script && !done {
        return Err("the expect script did not finish before the session ended".into());
    }
    Ok(())
}

#[cfg(test)]
mod session_tests {
    use super::*;

    #[test]
    fn incomplete_automated_runs_fail_independently_of_quiet_output() {
        assert!(session_result(None, true, true, false).is_err());
        assert!(session_result(None, true, true, true).is_ok());
        assert!(session_result(None, false, true, false).is_ok());
        assert_eq!(
            session_result(Some("link lost".into()), true, true, false),
            Err("link lost".into())
        );
    }
}

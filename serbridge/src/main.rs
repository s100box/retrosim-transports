// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Howard M. Harte
//! Hold a console connection open, flush received bytes to a log, and accept
//! command files. An optional RFC 2217 listener shares data and line controls.
//!
//! Serial reconnects use USB serial/location plus interface identity; ambiguous
//! matches wait rather than selecting another adapter. Outages are marked in
//! the log because bytes sent while disconnected cannot be recovered.
//! Network transports reconnect using their original specification.

mod link;
mod serial;

use std::fs;
use std::io::{Read as _, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use link::{Link, TransportLink};
use retrosim_transports::rfc2217;
use serial::{Flow, Identity, Parity, Port, Read, Settings, StopBits};

const USAGE: &str = "\
usage: serbridge --port <name> [options]

  --port <name>      COM20, /dev/ttyUSB0, serial:COM20@9600, or any other
                     transport spec: tcp:host:port, telnet:host:port,
                     udp:host:port, rfc2217:host:port[@baud...], ssh:host
                     (the ssh build only). Required
  --baud <n>         a serial port's rate, default 115200
  --log <file>       everything received (default console.log; truncated unless --keep-log)
  --cmd <file>       a line dropped here is sent, then the file is deleted
                     (default cmd.txt). A line of exactly \\x03 sends Ctrl-C;
                     \\x00 sends nothing and just wakes the loop
  --stop <file>      create this to end the bridge (default serbridge.stop)
  --keep-log         append to an existing log instead of truncating it
  --no-reconnect     exit when the port goes away instead of waiting for it
  --quiet            do not echo received bytes to stdout
  --listen <tcp>     also serve the port over RFC 2217 on this TCP port; 0 picks
                     a free one. pySerial opens it as rfc2217://127.0.0.1:<tcp>
  --bind <addr>      the address --listen binds (default 127.0.0.1). Any other
                     address puts the port on the network, unauthenticated
  --list             print the serial ports that exist right now, with each
                     one's USB serial number, interface and location, and exit

A transport spec is held the way a port is -- logged, fed from the command
file and served over RFC 2217 -- and reopened as it was given when it drops.
Line settings and DTR, RTS and BREAK reach it only where the transport has
them. Raw TCP, Telnet and SSH have no physical modem sideband; their
emulated RTS gate and fixed modem status follow the library's contract.

When the port goes away the bridge waits for the same port to come back: the
one with the same USB serial number, or for an adapter with none (or one
another adapter shares), the one in the same USB socket. Either way it must be
the same USB interface, which is what tells the two ports of a dual adapter
apart. A port with neither comes back only under its own name. The log's first
line says which.

With --listen, tools share the port through the bridge instead of opening it.
Every byte the board sends goes to every client and to the log; a client may
change the baud rate, framing and flow control and drive DTR, RTS and BREAK,
as if it had opened the port itself. When the last client leaves, the port
goes back to the bridge's own settings with DTR, RTS and BREAK released. The
URL is also written to a file named for the port, so a tool can find the
bridge from the port name alone: %LOCALAPPDATA%\\serbridge\\COM20.url on
Windows; $XDG_RUNTIME_DIR/serbridge/ttyUSB0.url (or /tmp/serbridge-$USER/...)
elsewhere.

⚠ DTR and RTS are left DEASSERTED. On a CH340 board they are often wired to the
target's reset or console control; asserting them can silence the console.
A client may explicitly assert them, as with a direct port open.
";

struct Args {
    port: String,
    baud: u32,
    log: PathBuf,
    cmd: PathBuf,
    stop: PathBuf,
    keep_log: bool,
    reconnect: bool,
    quiet: bool,
    listen: Option<u16>,
    bind: String,
}

fn parse() -> Result<Args, String> {
    let mut a = Args {
        port: String::new(),
        baud: 115_200,
        log: PathBuf::from("console.log"),
        cmd: PathBuf::from("cmd.txt"),
        stop: PathBuf::from("serbridge.stop"),
        keep_log: false,
        reconnect: true,
        quiet: false,
        listen: None,
        bind: "127.0.0.1".to_string(),
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut val = |what: &str| {
            it.next()
                .ok_or_else(|| format!("{what} needs a value\n\n{USAGE}"))
        };
        match arg.as_str() {
            "--port" => a.port = val("--port")?,
            "--baud" => a.baud = val("--baud")?.parse().map_err(|e| format!("--baud: {e}"))?,
            "--log" => a.log = PathBuf::from(val("--log")?),
            "--cmd" => a.cmd = PathBuf::from(val("--cmd")?),
            "--stop" => a.stop = PathBuf::from(val("--stop")?),
            "--keep-log" => a.keep_log = true,
            "--no-reconnect" => a.reconnect = false,
            "--quiet" => a.quiet = true,
            "--listen" => {
                a.listen = Some(
                    val("--listen")?
                        .parse()
                        .map_err(|e| format!("--listen: {e}"))?,
                )
            }
            "--bind" => a.bind = val("--bind")?,
            // ⭐ Its own flag because the enumeration is the part that decides
            // whether a reconnect can find a port that came back under another
            // name, and a path with no way to run it is a path nobody checks.
            "--list" => {
                for (name, id) in serial::identities() {
                    println!(
                        "{name:<14} serial={:<16} interface={:<3} location={}",
                        id.serial.as_deref().unwrap_or("-"),
                        id.interface.as_deref().unwrap_or("-"),
                        id.location.as_deref().unwrap_or("-")
                    );
                }
                std::process::exit(0);
            }
            "-h" | "--help" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other}\n\n{USAGE}")),
        }
    }
    if a.port.is_empty() {
        return Err(format!("--port is required\n\n{USAGE}"));
    }
    Ok(a)
}

/// Received bytes and bridge notes, flushed after each write so clients can
/// inspect the log while the bridge is running. File errors terminate the run.
struct Log<W = fs::File> {
    f: W,
    quiet: bool,
}

impl Log {
    fn open(path: &Path, keep: bool) -> std::io::Result<Self> {
        let f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .truncate(false)
            .open(path)?;
        if !keep {
            // Truncate by reopening: `append` and `truncate` cannot be set
            // together, and the caller asked for a fresh log.
            drop(f);
            let f = fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(path)?;
            drop(f);
            let f = fs::OpenOptions::new().append(true).open(path)?;
            return Ok(Log { f, quiet: false });
        }
        Ok(Log { f, quiet: false })
    }
}

impl<W: Write> Log<W> {
    fn bytes(&mut self, b: &[u8]) -> std::io::Result<()> {
        self.f.write_all(b)?;
        self.f.flush()?;
        if !self.quiet {
            let _ = std::io::stdout().write_all(b);
            let _ = std::io::stdout().flush();
        }
        Ok(())
    }

    /// A line only this program writes, so an outage is visible in the
    /// transcript rather than inferred from a gap in the timestamps.
    fn mark(&mut self, text: &str) -> std::io::Result<()> {
        self.bytes(format!("\r\n[serbridge] {text}\r\n").as_bytes())
    }
}

/// What a reconnect has to match, chosen once when the bridge opens the port.
///
/// Both USB anchors carry the interface number, which is `None` on a
/// single-port adapter and tells the two ports of a dual one (FT2232, CP2105)
/// apart: those share a serial number AND a location.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Anchor {
    /// The adapter's USB serial number: it follows the adapter to any socket.
    Serial {
        serial: String,
        interface: Option<String>,
    },
    /// The USB socket's physical path: for an adapter with no serial number,
    /// which comes back on the same socket as the same device.
    Location {
        location: String,
        interface: Option<String>,
    },
    /// Neither is known (not a USB port, or a platform that does not read
    /// them): only the same name is taken back.
    Name,
}

impl Anchor {
    fn matches(&self, name: &str, preferred: &str, id: &Identity) -> bool {
        match self {
            Anchor::Serial { serial, interface } => {
                id.serial.as_deref() == Some(serial.as_str()) && id.interface == *interface
            }
            Anchor::Location {
                location,
                interface,
            } => id.location.as_deref() == Some(location.as_str()) && id.interface == *interface,
            Anchor::Name => name == preferred,
        }
    }
}

impl std::fmt::Display for Anchor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (what, value, interface) = match self {
            Anchor::Serial { serial, interface } => ("USB serial number", serial, interface),
            Anchor::Location {
                location,
                interface,
            } => ("USB location", location, interface),
            Anchor::Name => return write!(f, "name only (no USB serial number or location)"),
        };
        write!(f, "{what} {value}")?;
        if let Some(i) = interface {
            write!(f, ", interface {i}")?;
        }
        Ok(())
    }
}

/// The serial number when the adapter has one, its location when it does not.
///
/// ⚠ **A serial number another present port also reports is no anchor.**
/// Clone adapters commonly share one (a whole batch of fake FTDIs answers
/// `A50285BI`), and matching on it would take whichever of them comes back
/// first. Such a port is anchored by location instead, as if it had none. The
/// other port of the SAME dual adapter does not count as sharing it: the
/// interface number already tells those two apart.
fn anchor_for(name: &str, ports: &[(String, Identity)]) -> Anchor {
    let Some((_, id)) = ports.iter().find(|(n, _)| n == name) else {
        return Anchor::Name;
    };
    if let Some(s) = &id.serial {
        let shared = ports.iter().any(|(n, other)| {
            n != name
                && other.serial.as_deref() == Some(s.as_str())
                && other.interface == id.interface
        });
        if !shared {
            return Anchor::Serial {
                serial: s.clone(),
                interface: id.interface.clone(),
            };
        }
    }
    match &id.location {
        Some(l) => Anchor::Location {
            location: l.clone(),
            interface: id.interface.clone(),
        },
        None => Anchor::Name,
    }
}

/// The port to reopen: one that matches the anchor, preferring the name it
/// had last.
///
/// ⛔ **Never "the port that is new".** On a bench with several adapters the
/// new port is whichever board enumerated last, and taking it logs another
/// board's console into this one's file with nothing to say so. A port that
/// does not match is never taken, and two that both match are a guess, so the
/// bridge keeps waiting instead.
fn pick(preferred: &str, anchor: &Anchor, ports: &[(String, Identity)]) -> Option<String> {
    let hits: Vec<&String> = ports
        .iter()
        .filter(|(n, id)| anchor.matches(n, preferred, id))
        .map(|(n, _)| n)
        .collect();
    if hits.iter().any(|n| *n == preferred) {
        return Some(preferred.to_string());
    }
    match hits.as_slice() {
        [one] => Some((*one).clone()),
        _ => None,
    }
}

fn find_port(preferred: &str, anchor: &Anchor) -> Option<String> {
    pick(preferred, anchor, &serial::identities())
}

/// DTR, RTS and BREAK as clients last set them. DTR and RTS are put back on a
/// port that reopens; BREAK is not, because the outage already ended it.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct Lines {
    dtr: bool,
    rts: bool,
    brk: bool,
    /// Explicit client requests to reapply after reopening. Untouched network
    /// transports keep their own default modem/flow state.
    touched: [bool; 3],
}

#[derive(Clone, Copy)]
enum Line {
    Dtr,
    Rts,
    Break,
}

/// One RFC 2217 connection.
struct Client {
    id: u32,
    /// The write half. The reader thread, the main loop and the client's own
    /// thread all write to it, one whole message at a time.
    out: Mutex<TcpStream>,
    session: Mutex<rfc2217::Session>,
    /// Whether this client has been told its data is being dropped, so an
    /// outage says so once rather than once per write.
    dropping: AtomicBool,
}

impl Client {
    fn send(&self, bytes: &[u8]) -> bool {
        let mut out = self.out.lock().unwrap();
        if out.write_all(bytes).is_ok() {
            return true;
        }
        // A client that cannot keep up, or has gone: its own thread sees the
        // closed socket and removes it.
        let _ = out.shutdown(std::net::Shutdown::Both);
        false
    }
}

/// Everything the threads share.
///
/// Lock order: `clients` (when removing/restoring), then `settings`, `lines`,
/// `port`, and `log`. A method releases the log before acquiring other locks.
struct Bridge {
    /// `--baud` 8N1, no flow control: what the port returns to.
    own: Settings,
    /// Synthetic RTS gates must remain open while the logger has no client.
    idle_rts: bool,
    settings: Mutex<Settings>,
    settings_changed: AtomicBool,
    lines: Mutex<Lines>,
    port: Mutex<Option<Arc<dyn Link>>>,
    port_name: Mutex<String>,
    log: Mutex<Log>,
    log_error: Mutex<Option<String>>,
    clients: Mutex<Vec<Arc<Client>>>,
    stop: AtomicBool,
}

impl Bridge {
    fn mark(&self, text: &str) {
        let result = self.log.lock().unwrap().mark(text);
        self.check_log(result);
    }

    fn check_log(&self, result: std::io::Result<()>) {
        if let Err(error) = result {
            let mut first = self.log_error.lock().unwrap();
            if first.is_none() {
                eprintln!("serbridge: log: {error}");
                *first = Some(error.to_string());
            }
            self.stop.store(true, Ordering::Relaxed);
        }
    }

    fn port(&self) -> Option<Arc<dyn Link>> {
        self.port.lock().unwrap().clone()
    }

    fn clients(&self) -> Vec<Arc<Client>> {
        self.clients.lock().unwrap().clone()
    }

    fn stopping(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    /// To the board. False when there is no port, or the write failed (the
    /// reader thread notices a lost port on its own).
    fn send(&self, bytes: &[u8]) -> bool {
        match self.port() {
            Some(p) => p.write_all(bytes).is_ok(),
            None => false,
        }
    }

    /// From the board: to the log, and to every client.
    fn received(&self, bytes: &[u8]) {
        let result = self.log.lock().unwrap().bytes(bytes);
        self.check_log(result);
        let clients = self.clients();
        if clients.is_empty() {
            return;
        }
        let mut escaped = Vec::with_capacity(bytes.len() + 8);
        rfc2217::escape(bytes, &mut escaped);
        for c in clients {
            c.send(&escaped);
        }
    }

    /// Applies `new` if the port takes it. Returns the settings in effect,
    /// which are the old ones when it did not.
    fn apply(&self, who: &str, new: Settings) -> Settings {
        let mut s = self.settings.lock().unwrap();
        match self.port() {
            Some(p) => match p.configure(&new) {
                Ok(()) => {
                    *s = new;
                    self.settings_changed.store(true, Ordering::Relaxed);
                    self.mark(&format!("{who}: {new}"));
                }
                Err(e) => self.mark(&format!("{who}: cannot set {new}: {e}")),
            },
            // No port right now: taken, and applied when the port reopens.
            None => {
                *s = new;
                self.settings_changed.store(true, Ordering::Relaxed);
                self.mark(&format!("{who}: {new} (applied when the port is back)"));
            }
        }
        *s
    }

    /// Sets a line if the port takes it. Returns the state in effect.
    fn set_line(&self, who: &str, which: Line, on: bool) -> bool {
        let mut l = self.lines.lock().unwrap();
        let index = match which {
            Line::Dtr => 0,
            Line::Rts => 1,
            Line::Break => 2,
        };
        let (cur, name) = match which {
            Line::Dtr => (&mut l.dtr, "DTR"),
            Line::Rts => (&mut l.rts, "RTS"),
            Line::Break => (&mut l.brk, "BREAK"),
        };
        let r = match self.port() {
            Some(p) => match which {
                Line::Dtr => p.set_dtr(on),
                Line::Rts => p.set_rts(on),
                Line::Break => p.set_break(on),
            },
            None => Ok(()),
        };
        let r_success = r.is_ok();
        let state = if on { "on" } else { "off" };
        match r {
            Ok(()) => {
                *cur = on;
                self.mark(&format!("{who}: {name} {state}"));
            }
            Err(e) => self.mark(&format!("{who}: cannot set {name} {state}: {e}")),
        }
        let actual = *cur;
        if r_success {
            l.touched[index] = true;
        }
        actual
    }

    fn reopen_with(
        &self,
        open: impl FnOnce(&Settings) -> std::io::Result<Arc<dyn Link>>,
    ) -> std::io::Result<()> {
        let settings = self.settings.lock().unwrap();
        let mut lines = self.lines.lock().unwrap();
        let port = open(&settings)?;
        if self.settings_changed.load(Ordering::Relaxed) {
            port.configure(&settings)?;
        }
        if lines.touched[0] {
            port.set_dtr(lines.dtr)?;
        }
        if lines.touched[1] {
            port.set_rts(lines.rts)?;
        }
        if lines.touched[2] {
            port.set_break(false)?;
        }
        lines.brk = false;
        *self.port.lock().unwrap() = Some(port);
        Ok(())
    }

    /// Restore bridge settings and release physical lines. Synthetic RTS
    /// gates stay open so the logger continues reading without any clients.
    fn restore(&self) {
        let who = "no client left";
        self.apply(who, self.own);
        self.set_line(who, Line::Break, false);
        self.set_line(who, Line::Dtr, false);
        self.set_line(who, Line::Rts, self.idle_rts);
    }
}

/// The port as one client's RFC 2217 requests see it.
struct ClientPort<'a> {
    b: &'a Bridge,
    who: &'a str,
}

fn parity_code(p: Parity) -> u8 {
    match p {
        Parity::None => 1,
        Parity::Odd => 2,
        Parity::Even => 3,
        Parity::Mark => 4,
        Parity::Space => 5,
    }
}

fn stop_code(s: StopBits) -> u8 {
    match s {
        StopBits::One => 1,
        StopBits::Two => 2,
        StopBits::OnePointFive => 3,
    }
}

/// SET-CONTROL's flow-control values: 1..3 for the outbound question, 14..16
/// for the inbound one. The port has one setting for both directions.
fn flow_code(f: Flow, inbound: bool) -> u8 {
    let base = if inbound { 14 } else { 1 };
    base + match f {
        Flow::None => 0,
        Flow::XonXoff => 1,
        Flow::RtsCts => 2,
    }
}

const FLOWS: [Flow; 3] = [Flow::None, Flow::XonXoff, Flow::RtsCts];

impl ClientPort<'_> {
    fn now(&self) -> Settings {
        *self.b.settings.lock().unwrap()
    }

    fn line(&self, which: Line, code: u8, on_code: u8, query: u8) -> u8 {
        let on = if code == query {
            let l = *self.b.lines.lock().unwrap();
            match which {
                Line::Dtr => l.dtr,
                Line::Rts => l.rts,
                Line::Break => l.brk,
            }
        } else {
            self.b.set_line(self.who, which, code == on_code)
        };
        if on {
            on_code
        } else {
            on_code + 1
        }
    }
}

impl rfc2217::Device for ClientPort<'_> {
    fn baud(&mut self, rate: u32) -> u32 {
        let s = self.now();
        if rate == 0 {
            return s.baud;
        }
        self.b.apply(self.who, Settings { baud: rate, ..s }).baud
    }

    fn data_size(&mut self, bits: u8) -> u8 {
        let s = self.now();
        if !(5..=8).contains(&bits) {
            return s.data_bits;
        }
        self.b
            .apply(
                self.who,
                Settings {
                    data_bits: bits,
                    ..s
                },
            )
            .data_bits
    }

    fn parity(&mut self, code: u8) -> u8 {
        let s = self.now();
        let parity = match code {
            1 => Parity::None,
            2 => Parity::Odd,
            3 => Parity::Even,
            4 => Parity::Mark,
            5 => Parity::Space,
            _ => return parity_code(s.parity),
        };
        parity_code(self.b.apply(self.who, Settings { parity, ..s }).parity)
    }

    fn stop_size(&mut self, code: u8) -> u8 {
        let s = self.now();
        let stop_bits = match code {
            1 => StopBits::One,
            2 => StopBits::Two,
            3 => StopBits::OnePointFive,
            _ => return stop_code(s.stop_bits),
        };
        stop_code(
            self.b
                .apply(self.who, Settings { stop_bits, ..s })
                .stop_bits,
        )
    }

    fn control(&mut self, code: u8) -> u8 {
        let s = self.now();
        match code {
            0 => flow_code(s.flow, false),
            13 => flow_code(s.flow, true),
            1..=3 => {
                let flow = FLOWS[(code - 1) as usize];
                flow_code(self.b.apply(self.who, Settings { flow, ..s }).flow, false)
            }
            14..=16 => {
                let flow = FLOWS[(code - 14) as usize];
                flow_code(self.b.apply(self.who, Settings { flow, ..s }).flow, true)
            }
            4..=6 => self.line(Line::Break, code, 5, 4),
            7..=9 => self.line(Line::Dtr, code, 8, 7),
            10..=12 => self.line(Line::Rts, code, 11, 10),
            // DCD/DTR/DSR flow control (17..19) is not offered. The answer
            // differs from the request, which is how a client sees a refusal.
            _ => flow_code(s.flow, false),
        }
    }

    fn purge(&mut self, code: u8) {
        if let Some(p) = self.b.port() {
            let _ = p.purge(code & 1 != 0, code & 2 != 0);
        }
    }

    fn modem_state(&mut self) -> u8 {
        self.b
            .port()
            .and_then(|p| p.modem_status().ok())
            .unwrap_or(0)
    }
}

/// What `--port` names.
enum Source {
    /// A serial port, held by serbridge's own backend and found again by its
    /// USB identity.
    Serial(Anchor),
    /// Any other retrosim-transports spec, reopened as it was given.
    Spec(String),
}

/// Transport specs serbridge hands to retrosim-transports. `serial:` is not
/// one: a serial port is always serbridge's own, for the reconnect.
const SPECS: [&str; 5] = ["tcp:", "telnet:", "udp:", "ssh:", "rfc2217:"];

fn is_spec(port: &str) -> bool {
    SPECS.iter().any(|s| port.starts_with(s))
}

/// `serial:NAME[@BAUD]` as the name and rate; anything else as it is. The
/// line format is the clients' to set, so a spec that names one is refused.
fn serial_name(port: &str, baud: u32) -> Result<(String, u32), String> {
    let Some(spec) = port.strip_prefix("serial:") else {
        return Ok((port.to_string(), baud));
    };
    match spec.split_once('@') {
        None if !spec.is_empty() && baud != 0 => Ok((spec.to_string(), baud)),
        None => Err("--port needs a nonempty serial name and nonzero baud".into()),
        Some((name, rate)) => match rate.parse() {
            Ok(rate) if !name.is_empty() && rate != 0 => Ok((name.to_string(), rate)),
            _ => Err(format!(
                "--port {port}: give serial:NAME or serial:NAME@BAUD; the line format is set by the clients"
            )),
        },
    }
}

/// Opens a transport spec, or the serial port `name`.
fn open_link(spec: Option<&str>, name: &str, s: &Settings) -> std::io::Result<Arc<dyn Link>> {
    match spec {
        None => Ok(Arc::new(Port::open(name, s)?)),
        Some(spec) => {
            let t = retrosim_transports::open_transport(spec, false)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::NotFound, e.to_string()))?;
            Ok(Arc::new(TransportLink::new(t)?))
        }
    }
}

/// The reader thread: the board's output to the log and the clients, and the
/// reconnect when the port goes away.
fn reader(b: Arc<Bridge>, source: Source, reconnect: bool) {
    let mut buf = vec![0u8; 4096];
    while !b.stopping() {
        let Some(p) = b.port() else {
            // Disconnected. Watch for it to come back. The command file is
            // left alone meanwhile: a queued line belongs to a caller still
            // waiting for it, so it is sent once there is somewhere to send it
            // rather than written into a dead handle and lost.
            let name = b.port_name.lock().unwrap().clone();
            let found = match &source {
                Source::Serial(anchor) => find_port(&name, anchor),
                Source::Spec(_) => Some(name.clone()),
            };
            let reopened = found.and_then(|found| {
                // Present but not openable yet is normal: the driver is still
                // settling, or the old handle has not been torn down.
                let spec = match &source {
                    Source::Spec(spec) => Some(spec.as_str()),
                    Source::Serial(_) => None,
                };
                b.reopen_with(|settings| open_link(spec, &found, settings))
                    .ok()
                    .map(|()| found)
            });
            match reopened {
                Some(found) => {
                    if found != name {
                        b.mark(&format!("reconnected on {found} (was {name})"));
                        *b.port_name.lock().unwrap() = found;
                    } else {
                        b.mark(&format!("reconnected on {name}"));
                    }
                    for c in b.clients() {
                        c.dropping.store(false, Ordering::Relaxed);
                    }
                }
                None => std::thread::sleep(Duration::from_millis(500)),
            }
            continue;
        };
        match p.read(&mut buf) {
            Ok(Read::Got(n)) => b.received(&buf[..n]),
            Ok(Read::Idle) => {}
            Err(e) => {
                b.mark(&format!(
                    "port lost ({}) -- anything the board sent while it was down is NOT in this log",
                    e.kind()
                ));
                *b.port.lock().unwrap() = None;
                drop(p);
                if !reconnect {
                    b.stop.store(true, Ordering::Relaxed);
                    break;
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        }
    }
}

/// One client's thread: its requests and data until it goes.
fn serve(b: Arc<Bridge>, c: Arc<Client>, mut rx: TcpStream) {
    let who = format!("client {}", c.id);
    let mut buf = [0u8; 4096];
    while !b.stopping() {
        let n = match rx.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue
            }
            Err(_) => break,
        };
        let (mut data, mut reply) = (Vec::new(), Vec::new());
        {
            let mut s = c.session.lock().unwrap();
            let mut dev = ClientPort { b: &b, who: &who };
            s.feed(&buf[..n], &mut dev, &mut data, &mut reply);
        }
        if !reply.is_empty() && !c.send(&reply) {
            break;
        }
        if !data.is_empty() {
            if b.send(&data) {
                c.dropping.store(false, Ordering::Relaxed);
            } else if !c.dropping.swap(true, Ordering::Relaxed) {
                b.mark(&format!(
                    "{who}: the port is down -- what this client sends is DROPPED until it is back"
                ));
            }
        }
    }
    {
        // Keep removal and restoration atomic with respect to accept adding
        // another client. Otherwise a departing client can reset a new one.
        let mut all = b.clients.lock().unwrap();
        all.retain(|x| x.id != c.id);
        b.mark(&format!("{who} disconnected"));
        if all.is_empty() && !b.stopping() {
            b.restore();
        }
    }
}

fn accept(b: &Arc<Bridge>, listener: &TcpListener, next_id: &mut u32) {
    loop {
        let (stream, peer) = match listener.accept() {
            Ok(x) => x,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return,
            Err(e) => {
                b.mark(&format!("accept failed: {e}"));
                return;
            }
        };
        let id = *next_id;
        *next_id += 1;
        // ⚠ An accepted socket inherits the listener's non-blocking mode on
        // Windows, so set every mode it needs explicitly.
        if let Err(e) = configure_client(&stream) {
            b.mark(&format!(
                "client {id} from {peer}: cannot configure socket: {e}"
            ));
            continue;
        }
        // The read timeout is how the client's thread notices a stop.
        // ⚠ A client that stops reading would stall the reader thread, and so
        // every other client and the log, once its socket buffer is full. Two
        // seconds, then it is dropped.
        let rx = match stream.try_clone() {
            Ok(rx) => rx,
            Err(e) => {
                b.mark(&format!("client {id} from {peer}: {e}"));
                continue;
            }
        };
        let c = Arc::new(Client {
            id,
            out: Mutex::new(stream),
            session: Mutex::new(rfc2217::Session::with_signature("serbridge")),
            dropping: AtomicBool::new(false),
        });
        b.clients.lock().unwrap().push(c.clone());
        b.mark(&format!("client {id} connected from {peer}"));
        let b = b.clone();
        std::thread::spawn(move || serve(b, c, rx));
    }
}

fn configure_client(stream: &TcpStream) -> std::io::Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_millis(200)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))
}

fn discovery_url(address: std::net::SocketAddr) -> String {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    let ip = match address.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    format!("rfc2217://{}", SocketAddr::new(ip, address.port()))
}

/// Sends each client a NOTIFY-MODEMSTATE when its lines changed (and once,
/// first, after it agrees to RFC 2217).
fn notify_modem(b: &Bridge) {
    let clients = b.clients();
    if clients.is_empty() {
        return;
    }
    let state = b.port().and_then(|p| p.modem_status().ok()).unwrap_or(0);
    for c in clients {
        let mut r = Vec::new();
        c.session.lock().unwrap().modem_changed(state, &mut r);
        if !r.is_empty() {
            c.send(&r);
        }
    }
}

fn run_commands(b: &Bridge, cmd: &Path) {
    // Accommodate short shell redirects. Writers requiring atomic batches
    // must publish a complete file with a rename; a delay cannot guarantee it.
    std::thread::sleep(Duration::from_millis(60));
    let text = match claim_commands(cmd) {
        Ok(text) => text,
        Err(error) => {
            b.mark(&format!(
                "cannot read/remove command file {}: {error}",
                cmd.display()
            ));
            return;
        }
    };
    for line in text.lines() {
        let out: Vec<u8> = match line {
            "\\x03" => vec![3],
            "\\x00" => Vec::new(),
            other => {
                let mut v = other.as_bytes().to_vec();
                v.push(b'\r');
                v
            }
        };
        if !out.is_empty() && !b.send(&out) {
            b.mark("write failed -- the port went away mid-command");
            break;
        }
        // The reader thread logs the answer as it comes; the pause keeps a
        // batch's commands from overrunning the board's line editor.
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn claim_commands(path: &Path) -> std::io::Result<String> {
    let text = fs::read_to_string(path)?;
    fs::remove_file(path)?;
    Ok(text)
}

fn main() {
    let args = match parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("serbridge: {e}");
            std::process::exit(2);
        }
    };

    let (name, baud, spec) = if is_spec(&args.port) {
        (args.port.clone(), args.baud, Some(args.port.clone()))
    } else {
        match serial_name(&args.port, args.baud) {
            Ok((name, baud)) => (name, baud, None),
            Err(e) => {
                eprintln!("serbridge: {e}");
                std::process::exit(2);
            }
        }
    };
    let mut log = match Log::open(&args.log, args.keep_log) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("serbridge: {}: {e}", args.log.display());
            std::process::exit(1);
        }
    };
    log.quiet = args.quiet;

    let own = Settings::new(baud);
    let port = match open_link(spec.as_deref(), &name, &own) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("serbridge: {}: {e}", args.port);
            std::process::exit(1);
        }
    };
    let idle_rts = spec.as_deref().is_some_and(|spec| {
        ["tcp:", "telnet:", "ssh:"]
            .iter()
            .any(|prefix| spec.starts_with(prefix))
    });
    let source = match spec {
        Some(spec) => {
            if args.reconnect {
                startup_log(log.mark(&format!("open {spec}; reopens it when it drops")));
            } else {
                startup_log(log.mark(&format!("open {spec}")));
            }
            Source::Spec(spec)
        }
        None => {
            // Read once, while the port is certainly this board's: it is what
            // every reconnect afterwards has to match.
            let anchor = anchor_for(&name, &serial::identities());
            if args.reconnect {
                startup_log(log.mark(&format!(
                    "open {name} at {baud} baud; reconnects by {anchor}"
                )));
            } else {
                startup_log(log.mark(&format!("open {name} at {baud} baud")));
            }
            Source::Serial(anchor)
        }
    };

    let listener = args.listen.map(|tcp| {
        let l = TcpListener::bind((args.bind.as_str(), tcp)).unwrap_or_else(|e| {
            eprintln!("serbridge: --listen {}:{tcp}: {e}", args.bind);
            std::process::exit(1);
        });
        if let Err(e) = l.set_nonblocking(true) {
            eprintln!("serbridge: --listen: {e}");
            std::process::exit(1);
        }
        l
    });

    let b = Arc::new(Bridge {
        own,
        idle_rts,
        settings: Mutex::new(own),
        settings_changed: AtomicBool::new(false),
        lines: Mutex::new(Lines {
            rts: idle_rts,
            ..Lines::default()
        }),
        port: Mutex::new(Some(port)),
        port_name: Mutex::new(name),
        log: Mutex::new(log),
        log_error: Mutex::new(None),
        clients: Mutex::new(Vec::new()),
        stop: AtomicBool::new(false),
    });

    let url_path = listener.as_ref().map(|l| {
        let url = discovery_url(l.local_addr().expect("bound listener has a local address"));
        b.mark(&format!("serving {url}"));
        eprintln!("serbridge: {url}");
        let path = rfc2217::url_file(&args.port);
        if let Some(dir) = path.parent() {
            let _ = fs::create_dir_all(dir);
        }
        if let Err(e) = fs::write(&path, format!("{url}\n")) {
            b.mark(&format!("cannot write {}: {e}", path.display()));
        }
        path
    });

    let _ = fs::remove_file(&args.stop);
    let reading = {
        let b = b.clone();
        let reconnect = args.reconnect;
        std::thread::spawn(move || reader(b, source, reconnect))
    };

    let mut next_id = 1;
    let mut last_modem = Instant::now();
    while !b.stopping() {
        if args.stop.exists() {
            break;
        }
        if let Some(l) = &listener {
            accept(&b, l, &mut next_id);
        }
        if last_modem.elapsed() >= Duration::from_millis(100) {
            last_modem = Instant::now();
            notify_modem(&b);
        }
        if b.port().is_some() && args.cmd.exists() {
            run_commands(&b, &args.cmd);
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    b.stop.store(true, Ordering::Relaxed);
    let _ = reading.join();
    drop(listener);
    for c in b.clients() {
        let _ = c.out.lock().unwrap().shutdown(std::net::Shutdown::Both);
    }
    if let Some(p) = url_path {
        let _ = fs::remove_file(p);
    }
    b.mark("stopped");
    let _ = fs::remove_file(&args.stop);
    if b.log_error.lock().unwrap().is_some() {
        std::process::exit(1);
    }
}

fn startup_log(result: std::io::Result<()>) {
    if let Err(error) = result {
        eprintln!("serbridge: log: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconnect_restores_explicit_settings_and_lines_under_their_locks() {
        struct Fake(Mutex<Vec<String>>);
        impl Link for Fake {
            fn read(&self, _: &mut [u8]) -> std::io::Result<Read> {
                Ok(Read::Idle)
            }
            fn write_all(&self, _: &[u8]) -> std::io::Result<()> {
                Ok(())
            }
            fn configure(&self, s: &Settings) -> std::io::Result<()> {
                self.0.lock().unwrap().push(s.to_string());
                Ok(())
            }
            fn set_dtr(&self, on: bool) -> std::io::Result<()> {
                self.0.lock().unwrap().push(format!("dtr {on}"));
                Ok(())
            }
            fn set_rts(&self, on: bool) -> std::io::Result<()> {
                self.0.lock().unwrap().push(format!("rts {on}"));
                Ok(())
            }
            fn set_break(&self, on: bool) -> std::io::Result<()> {
                self.0.lock().unwrap().push(format!("break {on}"));
                Ok(())
            }
            fn modem_status(&self) -> std::io::Result<u8> {
                Ok(0)
            }
            fn purge(&self, _: bool, _: bool) -> std::io::Result<()> {
                Ok(())
            }
        }
        let path = std::env::temp_dir().join(format!("serbridge-restore-{}", std::process::id()));
        let own = Settings::new(115200);
        let bridge = Bridge {
            own,
            idle_rts: true,
            settings: Mutex::new(own),
            settings_changed: AtomicBool::new(false),
            lines: Mutex::new(Lines::default()),
            port: Mutex::new(None),
            port_name: Mutex::new("fake".into()),
            log: Mutex::new(Log {
                f: fs::File::create(&path).unwrap(),
                quiet: true,
            }),
            log_error: Mutex::new(None),
            clients: Mutex::new(vec![]),
            stop: AtomicBool::new(false),
        };
        let fake = Arc::new(Fake(Mutex::new(vec![])));
        // Untouched network defaults must survive an ordinary reconnect.
        bridge.reopen_with(|_| Ok(fake.clone())).unwrap();
        assert!(fake.0.lock().unwrap().is_empty());
        // Even a request equal to the cached default must reach the backend.
        bridge.set_line("test", Line::Rts, false);
        assert_eq!(*fake.0.lock().unwrap(), ["rts false"]);
        *bridge.port.lock().unwrap() = None;
        bridge.apply("test", Settings::new(9600));
        bridge.set_line("test", Line::Dtr, true);
        bridge.set_line("test", Line::Break, true);
        fake.0.lock().unwrap().clear();
        bridge
            .reopen_with(|settings| {
                assert_eq!(settings.baud, 9600);
                assert!(bridge.settings.try_lock().is_err());
                assert!(bridge.lines.try_lock().is_err());
                Ok(fake.clone())
            })
            .unwrap();
        assert_eq!(
            *fake.0.lock().unwrap(),
            ["9600 8N1", "dtr true", "rts false", "break false"]
        );
        assert!(!bridge.lines.lock().unwrap().brk);
        fake.0.lock().unwrap().clear();
        bridge.restore();
        assert_eq!(
            *fake.0.lock().unwrap(),
            ["115200 8N1", "break false", "dtr false", "rts true"]
        );
        // An evidence sink failure stops the bridge and retains a diagnostic.
        bridge.check_log(Err(std::io::ErrorKind::PermissionDenied.into()));
        assert!(bridge.stopping());
        assert!(bridge.log_error.lock().unwrap().is_some());
        drop(bridge);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn discovery_urls_preserve_address_family_and_ipv6_brackets() {
        for (address, expected) in [
            ("0.0.0.0:1234", "rfc2217://127.0.0.1:1234"),
            ("[::]:1234", "rfc2217://[::1]:1234"),
            ("[::1]:1234", "rfc2217://[::1]:1234"),
        ] {
            assert_eq!(discovery_url(address.parse().unwrap()), expected);
        }
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        configure_client(&server).unwrap();
        assert!(server.nodelay().unwrap());
        assert_eq!(
            server.read_timeout().unwrap(),
            Some(Duration::from_millis(200))
        );
        assert_eq!(
            server.write_timeout().unwrap(),
            Some(Duration::from_secs(2))
        );
        drop(client);
    }

    #[test]
    fn unreadable_command_contents_are_preserved_and_valid_commands_are_claimed_once() {
        let path = std::env::temp_dir().join(format!("serbridge-command-{}", std::process::id()));
        fs::write(&path, [0xff]).unwrap();
        assert!(claim_commands(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), [0xff]);
        fs::write(&path, "dir\n").unwrap();
        assert_eq!(claim_commands(&path).unwrap(), "dir\n");
        assert!(!path.exists());
        assert!(claim_commands(&path).is_err());
        for spec in ["serial:", "serial:port@0"] {
            assert!(serial_name(spec, 9600).is_err());
        }
    }

    fn port(name: &str, serial: Option<&str>, location: Option<&str>) -> (String, Identity) {
        port_if(name, serial, location, None)
    }

    fn port_if(
        name: &str,
        serial: Option<&str>,
        location: Option<&str>,
        interface: Option<&str>,
    ) -> (String, Identity) {
        (
            name.to_string(),
            Identity {
                serial: serial.map(str::to_string),
                location: location.map(str::to_string),
                interface: interface.map(str::to_string),
            },
        )
    }

    fn by_serial(s: &str, i: Option<&str>) -> Anchor {
        Anchor::Serial {
            serial: s.into(),
            interface: i.map(str::to_string),
        }
    }

    fn by_location(l: &str, i: Option<&str>) -> Anchor {
        Anchor::Location {
            location: l.into(),
            interface: i.map(str::to_string),
        }
    }

    #[test]
    fn log_errors_are_returned_instead_of_silently_losing_evidence() {
        struct Failing {
            fail_write: bool,
        }
        impl Write for Failing {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if self.fail_write {
                    Err(std::io::ErrorKind::PermissionDenied.into())
                } else {
                    Ok(bytes.len())
                }
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::ErrorKind::Other.into())
            }
        }
        let mut log = Log {
            f: Failing { fail_write: true },
            quiet: true,
        };
        assert_eq!(
            log.bytes(b"evidence").unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        log.f.fail_write = false;
        assert_eq!(
            log.mark("outage").unwrap_err().kind(),
            std::io::ErrorKind::Other
        );
    }

    #[test]
    fn a_serial_number_is_the_anchor_when_there_is_one() {
        let ports = [
            port("COM14", Some("24680246"), Some("USB(5)")),
            port("COM5", None, Some("USB(2)")),
        ];
        assert_eq!(anchor_for("COM14", &ports), by_serial("24680246", None));
    }

    #[test]
    fn no_serial_number_falls_back_to_the_location() {
        let ports = [port("COM251", None, Some("USB(4)"))];
        assert_eq!(anchor_for("COM251", &ports), by_location("USB(4)", None));
    }

    #[test]
    fn a_serial_number_two_adapters_share_falls_back_to_the_location() {
        let ports = [
            port("COM36", Some("A50285BI"), Some("USB(1)")),
            port("COM37", Some("A50285BI"), Some("USB(3)")),
        ];
        assert_eq!(anchor_for("COM36", &ports), by_location("USB(1)", None));
    }

    #[test]
    fn the_ports_of_one_dual_adapter_keep_their_serial_number() {
        // A dual-port CP2105 fixture: one serial, one location, two ports.
        let ports = [
            port_if("COM13", Some("01660305"), Some("USB(2)"), Some("00")),
            port_if("COM11", Some("01660305"), Some("USB(2)"), Some("01")),
        ];
        assert_eq!(
            anchor_for("COM11", &ports),
            by_serial("01660305", Some("01"))
        );
    }

    #[test]
    fn neither_means_the_name() {
        let ports = [port("COM90", None, None)];
        assert_eq!(anchor_for("COM90", &ports), Anchor::Name);
        assert_eq!(anchor_for("COM9", &ports), Anchor::Name);
    }

    #[test]
    fn the_same_serial_is_found_under_a_new_name() {
        let now = [
            port("COM5", Some("OTHER"), Some("USB(1)")),
            port("COM7", Some("FT1"), Some("USB(3)")),
        ];
        assert_eq!(
            pick("COM3", &by_serial("FT1", None), &now).as_deref(),
            Some("COM7")
        );
    }

    #[test]
    fn the_same_location_is_found_under_a_new_name() {
        let now = [
            port("COM5", None, Some("USB(1)")),
            port("COM8", None, Some("USB(4)")),
        ];
        assert_eq!(
            pick("COM251", &by_location("USB(4)", None), &now).as_deref(),
            Some("COM8")
        );
    }

    #[test]
    fn the_other_channel_of_a_dual_adapter_is_not_taken() {
        // Channel B is gone and channel A is still there: same serial, same
        // location, so only the interface keeps the bridge off channel A.
        let now = [port_if(
            "COM4",
            Some("TEST-SERIAL-01"),
            Some("USB(2)"),
            Some("00"),
        )];
        assert_eq!(
            pick("COM3", &by_serial("TEST-SERIAL-01", Some("01")), &now),
            None
        );
        let now = [
            port_if("COM4", Some("TEST-SERIAL-01"), Some("USB(2)"), Some("00")),
            port_if("COM9", Some("TEST-SERIAL-01"), Some("USB(2)"), Some("01")),
        ];
        assert_eq!(
            pick("COM3", &by_serial("TEST-SERIAL-01", Some("01")), &now).as_deref(),
            Some("COM9")
        );
    }

    #[test]
    fn another_board_that_appeared_is_not_taken() {
        // This board is still gone, and the only new port on the bench is
        // another board's.
        let now = [port("COM5", None, Some("USB(1)"))];
        assert_eq!(pick("COM255", &by_location("USB(4)", None), &now), None);
        let now = [port("COM3", Some("FT2"), Some("USB(4)"))];
        assert_eq!(pick("COM251", &by_serial("FT1", None), &now), None);
    }

    #[test]
    fn the_old_name_on_another_adapter_is_not_taken() {
        // Linux hands ttyUSB0 to whichever adapter enumerates first.
        let now = [port("/dev/ttyUSB0", Some("FT2"), Some("1-1.2"))];
        assert_eq!(pick("/dev/ttyUSB0", &by_serial("FT1", None), &now), None);
    }

    #[test]
    fn two_matches_are_a_guess_unless_one_has_the_old_name() {
        let a = by_location("USB(1)", None);
        let now = [
            port("COM7", None, Some("USB(1)")),
            port("COM8", None, Some("USB(1)")),
        ];
        assert_eq!(pick("COM3", &a, &now), None);
        assert_eq!(pick("COM8", &a, &now).as_deref(), Some("COM8"));
    }

    #[test]
    fn a_name_anchor_takes_only_its_own_name() {
        let now = [port("COM90", None, None), port("COM91", None, None)];
        assert_eq!(pick("COM90", &Anchor::Name, &now).as_deref(), Some("COM90"));
        assert_eq!(pick("COM9", &Anchor::Name, &now), None);
    }

    #[test]
    fn the_log_line_names_the_interface() {
        assert_eq!(
            by_serial("01660305", Some("01")).to_string(),
            "USB serial number 01660305, interface 01"
        );
        assert_eq!(
            by_location("USB(4)", None).to_string(),
            "USB location USB(4)"
        );
    }

    #[test]
    fn transport_specs_are_told_from_port_names() {
        for spec in [
            "tcp:127.0.0.1:23",
            "telnet:bench:23",
            "udp:host:9",
            "ssh:me@host",
            "rfc2217:127.0.0.1:4001@9600",
        ] {
            assert!(is_spec(spec), "{spec}");
        }
        for name in ["COM20", "/dev/ttyUSB0", "serial:COM5", "tcp"] {
            assert!(!is_spec(name), "{name}");
        }
    }

    #[test]
    fn a_serial_spec_names_the_port_and_maybe_the_rate() {
        assert_eq!(serial_name("COM20", 9600).unwrap(), ("COM20".into(), 9600));
        assert_eq!(
            serial_name("serial:/dev/ttyUSB0", 9600).unwrap(),
            ("/dev/ttyUSB0".into(), 9600)
        );
        assert_eq!(
            serial_name("serial:COM5@38400", 9600).unwrap(),
            ("COM5".into(), 38400)
        );
        for bad in ["serial:COM5@9600,8N1", "serial:COM5@fast", "serial:@9600"] {
            assert!(
                serial_name(bad, 9600)
                    .unwrap_err()
                    .contains("serial:NAME@BAUD"),
                "{bad}"
            );
        }
    }
}

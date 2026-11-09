// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Howard M. Harte

//! Command-line parsing for `uartssh`.
//!
//! Hand-rolled to match the rest of the workspace (`kb11-run`, `j11-run`,
//! the simulators): no argument-parser dependency, and therefore no MSRV
//! drift imported from one.
//!
//! Everything here is pure -- [`parse`] takes an iterator of strings and
//! returns a value -- so the whole surface is testable without opening a
//! serial port or a socket.

use std::path::PathBuf;

use retrosim_transports::{SshAuthMethod, SshHostKeyPolicy};

use crate::expect::Rule;

/// Bytes handed to the serial driver in one pass.
///
/// The pump cannot look at the keyboard while it is inside a blocking write,
/// so this bounds how long a keystroke can wait behind a screenful of output.
/// 256 bytes is ~133 ms at 19200 baud.
pub const DEFAULT_CHUNK: usize = 256;

/// Serial read timeout, which is also what paces the pump loop when both
/// directions are idle.  Small enough to be invisible next to a 520 us
/// character time at 19200 baud, large enough that an idle bridge is not a
/// spin loop.
pub const DEFAULT_POLL_MS: u64 = 2;

/// Default `TERM` reported to the remote.  The whole point of the exercise is
/// that the thing on the other end of the wire really is a VT510.
pub const DEFAULT_TERM: &str = "vt510";

/// Pause before each `--send` string.
///
/// Not zero, because the first thing anyone sends is a command to a shell
/// that has not finished starting.  Bytes written to a pty before the shell
/// opens it are read by the *login* process and thrown away, which looks
/// exactly like the bridge dropping them.  Half a second covers a login
/// banner at 9600 baud; a slow host wants `--send-delay` raised.
pub const DEFAULT_SEND_DELAY_MS: u64 = 500;

/// How long the host must stop printing before a matched prompt is answered.
///
/// A prompt appears while the host is still painting the screen it belongs
/// to, and answering at that instant means the key arrives before the screen
/// does -- which for a frame-grabber run captures a half-drawn picture. 200 ms
/// is 192 character times at 9600 baud: far longer than any gap inside a
/// continuous write, far shorter than the pause a program makes when it stops
/// to read a key.
pub const DEFAULT_EXPECT_QUIET_MS: u64 = 200;

/// How long to wait for the next scripted prompt before declaring the run
/// stuck.
///
/// A `vttest` screen at 9600 baud takes seconds, and a slow one -- the 132
/// column tests repaint the whole display several times -- takes tens of
/// seconds. Two minutes is well beyond any of them, and finite, because an
/// unattended suite run that silently waits forever is indistinguishable from
/// one still working. `--expect-timeout 0` disables it.
pub const DEFAULT_EXPECT_TIMEOUT_MS: u64 = 120_000;

/// What the command line asked for.
#[derive(Debug)]
pub enum Action {
    /// Run the bridge.
    Run(Box<Args>),
    /// Print usage and exit 0.
    Help,
    /// Print the version and exit 0.
    Version,
    /// List the host's serial ports and exit 0.
    ListPorts,
}

/// Serial flow control, as understood by the host's serial driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// No handshake.  The bridge's own `FlowControlGate` then sees the
    /// terminal's XOFF and stops reading SSH.
    None,
    /// XON/XOFF, handled by the OS driver.
    Software,
    /// RTS/CTS, handled by the OS driver.  Needs the wires.
    Hardware,
}

impl Flow {
    /// The token `SerialTransport::open` expects in the third spec field.
    pub fn as_spec(self) -> &'static str {
        match self {
            Flow::None => "none",
            Flow::Software => "sw",
            Flow::Hardware => "hw",
        }
    }

    fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "none" | "off" => Ok(Flow::None),
            "sw" | "software" | "xonxoff" | "xon/xoff" => Ok(Flow::Software),
            "hw" | "hardware" | "rtscts" | "rts/cts" => Ok(Flow::Hardware),
            other => Err(format!(
                "unknown flow control '{}' (expected none, sw, or hw)",
                other
            )),
        }
    }
}

/// A validated command line.
#[derive(Debug)]
pub struct Args {
    /// Fully composed serial spec, e.g. `COM17@19200,8N1,sw`.
    pub serial: String,
    /// SSH target, `[user@]host[:port]`.
    pub ssh: String,
    /// `TERM` reported to the remote.
    pub term: String,
    /// PTY width reported to the remote.
    pub cols: u32,
    /// PTY height reported to the remote.
    pub rows: u32,
    /// Private key files to offer.  Empty means "discover the usual ones".
    pub identities: Vec<PathBuf>,
    /// Prompt on the console for a password.
    pub ask_password: bool,
    /// Environment variable to read the password from, overriding the
    /// default search list.
    pub password_env: Option<String>,
    /// Explicit authentication ladder.  `None` means the default order.
    pub auth_order: Option<Vec<SshAuthMethod>>,
    /// Server identity policy, checked before user authentication.
    pub host_key: SshHostKeyPolicy,
    /// Annotated bidirectional trace file.
    pub log: Option<PathBuf>,
    /// Prefix for raw capture files (`<prefix>.h2t.bin`, `<prefix>.t2h.bin`).
    pub capture: Option<PathBuf>,
    /// Bytes handed to the serial driver per pass.
    pub chunk: usize,
    /// Serial read timeout in milliseconds.
    pub poll_ms: u64,
    /// In-band escape byte from the terminal; typed twice, it quits.
    pub escape: Option<u8>,
    /// Print byte counters every N seconds.
    pub stats_secs: Option<u64>,
    /// Suppress the banner and the counters.
    pub quiet: bool,
    /// Read this console's keyboard and inject it towards the host.
    pub stdin: bool,
    /// Strings to inject at startup, in order, each after `send_delay_ms`.
    pub send: Vec<Vec<u8>>,
    /// Pause before each `--send` string.
    pub send_delay_ms: u64,
    /// Hold injected bytes while the terminal is mid-reply.  On by default;
    /// `--no-interlock` turns it off.
    pub interlock: bool,
    /// Prompt-driven rules, in the order they were given.  `--expect` and
    /// `--expect-once` share this list because their relative order is what
    /// decides which one answers a screen that satisfies both.
    pub expect: Vec<Rule>,
    /// How long the host must be idle before a matched prompt is answered.
    pub expect_quiet_ms: u64,
    /// How long to wait for the next scripted prompt.  `None` disables.
    pub expect_timeout_ms: Option<u64>,
    /// Close the session once every `--expect-once` rule has fired.
    pub expect_exit: bool,
    /// Command run just before each answered prompt, while the screen that
    /// prompted is still on the terminal.
    pub expect_run: Option<String>,
    /// JSON Lines index of every answered prompt, with the h2t byte offset
    /// that lets the model be replayed to the same screen.
    pub expect_manifest: Option<PathBuf>,
}

/// Usage text.  Kept next to the parser so a new flag is hard to add in one
/// place and forget in the other.
pub const USAGE: &str = "\
uartssh -- bridge a real serial terminal to a shell on an SSH host

A terminal with nothing but an RS-232 port gets a login on a machine that has
nothing but SSH.  Bytes are passed through untouched in both directions, so
escape-sequence test suites (vttest and friends) exercise the real terminal
over the real wire.

USAGE:
    uartssh --serial <PORT@BAUD[,FMT]> --ssh [<USER>@]<HOST>[:<PORT>] [OPTIONS]

REQUIRED:
    --serial <SPEC>     Serial port: COM17@19200, /dev/ttyUSB0@19200,8N1
    --ssh <SPEC>        SSH target: host, user@host, user@host:22

SERIAL:
    --flow <MODE>       none | sw | hw          [default: sw]
                        `sw` lets the OS driver honour the terminal's XOFF
                        within a character time -- the right answer when a
                        test suite floods the screen.  `none` routes XOFF
                        through the bridge's own gate instead, which also
                        passes Ctrl-S/Ctrl-Q on to the remote but reacts a
                        chunk later.  `hw` needs RTS/CTS wired.
    --chunk <N>         Bytes per write to the serial driver [default: 256]
    --poll <MS>         Serial read timeout, also the idle loop pace [default: 2]

TERMINAL:
    --term <NAME>       TERM reported to the remote [default: vt510]
    --cols <N>          PTY columns [default: 80]
    --rows <N>          PTY rows [default: 24]

KEYBOARD (for a terminal that has none):
    --stdin             Send what you type HERE to the remote, character at
                        a time, unechoed -- watch the terminal's own screen
                        for the result. Ctrl-C still quits the bridge, and
                        therefore cannot be sent to the remote.
    --send <STR>        Inject a string at startup (repeatable, in order).
                        Escapes: \\r \\n \\t \\e \\0 \\xNN \\\\
    --send-delay <MS>   Pause before each --send string [default: 500]
    --no-interlock      Do NOT hold injected keys while the terminal is
                        part-way through a reply. The hold exists because a
                        keystroke landing inside a cursor-position report
                        corrupts it, and the remote then blames the terminal
                        for an answer the bridge broke. Off only if you have
                        a reason.

EXPECT (drive a menu-driven suite without a stopwatch):
    --expect <RULE>     'TEXT => KEYS'. Whenever TEXT appears in what the
                        host prints, send KEYS. Repeatable, and a standing
                        rule fires every time -- one rule answers the
                        'Push <RETURN>' at the end of all 150 vttest screens.
    --expect-once <R>   Same, but fires once and then retires. --expect-once
                        rules are ORDERED: each is eligible only after every
                        earlier one has fired, which is what lets a sequence
                        of menu choices be written down. Without that, a rule
                        for 'Enter choice number => 5' would answer the first
                        menu it saw rather than the one it was written for.
    --expect-quiet <MS> Wait for the host to stop printing for MS before
                        answering [default: 200]. A prompt appears while the
                        screen it belongs to is still being painted; answering
                        at that instant sends the key before the screen has
                        arrived, and a frame grab then catches half a picture.
    --expect-timeout <MS>
                        Give up if the next --expect-once prompt has not
                        appeared in MS [default: 120000; 0 waits forever].
                        Exits non-zero naming the prompt that never came.
    --expect-exit       Close the session once every --expect-once rule has
                        fired, flushing the trace files properly. Needs at
                        least one --expect-once: standing rules never finish.
    --expect-run <CMD>  Run CMD just before answering each prompt -- i.e.
                        while the screen that prompted is still on the
                        terminal and the key that will wipe it has not gone
                        out. This is the only moment a frame grab of a vttest
                        screen is possible; an external grabber on a timer
                        races the keystroke. %n is the match ordinal (zero
                        padded, so a directory of PNGs sorts correctly), %p
                        the pattern that matched, %% a literal percent. The
                        pump is stalled while CMD runs, which is the intent.
    --expect-manifest <F>
                        JSON Lines index of every answered prompt: ordinal,
                        pattern, keys, and the host-to-terminal BYTE OFFSET at
                        which the prompt was answered. That offset is what
                        makes an offline comparison mechanical -- replaying
                        <PREFIX>.h2t.bin up to it puts the model in the state
                        the silicon was in when the frame was grabbed.

    Fixed-delay keys can interrupt a terminal report. Use --expect to wait
    for the remote prompt before injecting keys.

AUTHENTICATION:
    --known-hosts <FILE> Require a matching key in this OpenSSH file
                        [default: the user's .ssh/known_hosts]
    --host-key-sha256 <SHA256:...>
                        Pin a fingerprint obtained through a trusted channel
    --insecure-skip-host-key-check
                        Accept any server key (isolated labs only)
                        These three options are mutually exclusive. Unknown
                        and changed keys are refused before authentication.
    --identity <FILE>   Private key to offer (repeatable). Without this the
                        usual ~/.ssh/id_* files are discovered.
    --ask-password      Prompt on this console for a password
    --password-env <V>  Read the password from environment variable V
                        [default: RETROSIM_SSH_PASSWORD, TVI950_SSH_PASSWORD,
                        S100BOX_SSH_PASSWORD]
    --auth <LIST>       Ordered, comma-separated: agent, publickey, password,
                        keyboard-interactive, none
                        [default: all five, in that order]

DIAGNOSTICS:
    --log <FILE>        Annotated hex trace of both directions
    --capture <PREFIX>  Raw byte captures: <PREFIX>.h2t.bin, <PREFIX>.t2h.bin
    --stats <SECS>      Print byte counters every SECS seconds
    --escape <CHAR>     In-band quit key from the TERMINAL, typed twice.
                        Accepts ^], 0x1d, or a literal character. Off by
                        default: the terminal's replies to DA/DSR queries are
                        arbitrary bytes, and an escape byte armed by accident
                        would drop the link in the middle of a test.
    --list-ports        List this host's serial ports and exit
    -q, --quiet         No banner, no counters
    -h, --help          This text
    -V, --version       Version

QUITTING:
    Ctrl-C on THIS console. (Or --escape, typed twice at the terminal.)

EXAMPLES:
    uartssh --serial COM17@9600 --ssh user@host.example
    uartssh --serial /dev/ttyUSB0@9600,8N1 --ssh host.example --flow none
    uartssh --serial COM17@9600 --ssh user@host.example --log trace.txt --capture run1

    Replace the example port, host, and rate with your setup. A VT500-series
    terminal answers ESC [ c with ESC [ ? 65 ; ... c at its configured rate.

    No keyboard on the terminal? Drive it from here, and watch its screen:
    uartssh --serial COM17@9600 --ssh user@host.example --stdin

    Or launch the suite and then take over:
    uartssh --serial COM17@9600 --ssh user@host.example --stdin --send 'vttest\\r'

    Run one vttest test unattended and stop, capturing the whole wire:
    uartssh --serial COM17@9600 --ssh user@host.example --capture t1 \\
        --send 'vttest\\r' \\
        --expect 'Push <RETURN> => \\r' \\
        --expect-once 'Enter choice number => 1\\r' \\
        --expect-once 'Enter choice number => 0\\r' --expect-exit
";

/// Parse a command line (excluding `argv[0]`).
pub fn parse<I>(argv: I) -> Result<Action, String>
where
    I: IntoIterator<Item = String>,
{
    let args: Vec<String> = argv.into_iter().collect();

    let mut serial: Option<String> = None;
    let mut ssh: Option<String> = None;
    let mut flow: Option<Flow> = None;
    let mut term = DEFAULT_TERM.to_string();
    let mut cols: u32 = 80;
    let mut rows: u32 = 24;
    let mut identities: Vec<PathBuf> = Vec::new();
    let mut ask_password = false;
    let mut password_env: Option<String> = None;
    let mut auth_order: Option<Vec<SshAuthMethod>> = None;
    let mut host_key: Option<SshHostKeyPolicy> = None;
    let mut log: Option<PathBuf> = None;
    let mut capture: Option<PathBuf> = None;
    let mut chunk = DEFAULT_CHUNK;
    let mut poll_ms = DEFAULT_POLL_MS;
    let mut escape: Option<u8> = None;
    let mut stats_secs: Option<u64> = None;
    let mut quiet = false;
    let mut stdin = false;
    let mut send: Vec<Vec<u8>> = Vec::new();
    let mut send_delay_ms = DEFAULT_SEND_DELAY_MS;
    let mut interlock = true;
    let mut expect: Vec<Rule> = Vec::new();
    let mut expect_quiet_ms = DEFAULT_EXPECT_QUIET_MS;
    let mut expect_timeout_ms = DEFAULT_EXPECT_TIMEOUT_MS;
    let mut expect_exit = false;
    let mut expect_run: Option<String> = None;
    let mut expect_manifest: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        // Every flag that takes a value goes through this, so "the last
        // argument was a flag expecting a value" can never read past the end
        // or silently consume the next flag as its value.
        let mut value = |name: &str| -> Result<String, String> {
            i += 1;
            match args.get(i) {
                Some(v) if !v.starts_with("--") => Ok(v.clone()),
                Some(v) => Err(format!(
                    "{} expects a value, but the next argument is the flag '{}'",
                    name, v
                )),
                None => Err(format!("{} expects a value", name)),
            }
        };

        match arg {
            "-h" | "--help" => return Ok(Action::Help),
            "-V" | "--version" => return Ok(Action::Version),
            "--list-ports" => return Ok(Action::ListPorts),
            "-q" | "--quiet" => quiet = true,
            "--serial" => serial = Some(value("--serial")?),
            "--ssh" => ssh = Some(value("--ssh")?),
            "--flow" => flow = Some(Flow::parse(&value("--flow")?)?),
            "--term" => term = value("--term")?,
            "--cols" => cols = parse_num(&value("--cols")?, "--cols")?,
            "--rows" => rows = parse_num(&value("--rows")?, "--rows")?,
            "--identity" | "-i" => identities.push(PathBuf::from(value("--identity")?)),
            "--ask-password" => ask_password = true,
            "--password-env" => password_env = Some(value("--password-env")?),
            "--auth" => auth_order = Some(SshAuthMethod::parse_list(&value("--auth")?)?),
            "--known-hosts" | "--host-key-sha256" | "--insecure-skip-host-key-check" => {
                if host_key.is_some() {
                    return Err("choose only one host-key policy: --known-hosts, --host-key-sha256, or --insecure-skip-host-key-check".into());
                }
                host_key = Some(match arg {
                    "--known-hosts" => SshHostKeyPolicy::KnownHosts(PathBuf::from(value(arg)?)),
                    "--host-key-sha256" => SshHostKeyPolicy::sha256(&value(arg)?)?,
                    _ => SshHostKeyPolicy::InsecureAcceptAny,
                });
            }
            "--log" => log = Some(PathBuf::from(value("--log")?)),
            "--capture" => capture = Some(PathBuf::from(value("--capture")?)),
            "--chunk" => chunk = parse_num(&value("--chunk")?, "--chunk")?,
            "--poll" => poll_ms = parse_num(&value("--poll")?, "--poll")?,
            "--stats" => stats_secs = Some(parse_num(&value("--stats")?, "--stats")?),
            "--escape" => escape = Some(parse_escape(&value("--escape")?)?),
            "--stdin" => stdin = true,
            "--send" => send.push(parse_bytes(&value("--send")?)?),
            "--send-delay" => send_delay_ms = parse_num(&value("--send-delay")?, "--send-delay")?,
            "--no-interlock" => interlock = false,
            "--expect" => expect.push(Rule::parse(&value("--expect")?, false, |s| {
                parse_bytes_named(s, "--expect")
            })?),
            "--expect-once" => expect.push(Rule::parse(&value("--expect-once")?, true, |s| {
                parse_bytes_named(s, "--expect-once")
            })?),
            "--expect-quiet" => {
                expect_quiet_ms = parse_num(&value("--expect-quiet")?, "--expect-quiet")?
            }
            "--expect-timeout" => {
                expect_timeout_ms = parse_num(&value("--expect-timeout")?, "--expect-timeout")?
            }
            "--expect-exit" => expect_exit = true,
            "--expect-run" => expect_run = Some(value("--expect-run")?),
            "--expect-manifest" => {
                expect_manifest = Some(PathBuf::from(value("--expect-manifest")?))
            }
            other => return Err(format!("unknown argument '{}' (try --help)", other)),
        }
        i += 1;
    }

    let serial = serial.ok_or("--serial is required (try --help)")?;
    let ssh = ssh.ok_or("--ssh is required (try --help)")?;

    if chunk == 0 {
        return Err("--chunk must be at least 1".into());
    }
    if cols == 0 || rows == 0 {
        return Err("--cols and --rows must be at least 1".into());
    }
    // Without a script there is no "finished", so the bridge would run until
    // it was killed -- and a killed bridge is exactly the thing whose trace
    // files are truncated. Refused rather than silently ignored.
    if expect_exit && !expect.iter().any(|r| r.once) {
        return Err("--expect-exit needs at least one --expect-once rule: \
                    standing --expect rules never finish, so nothing would \
                    ever end the session"
            .into());
    }

    Ok(Action::Run(Box::new(Args {
        serial: compose_serial_spec(&serial, flow)?,
        ssh,
        term,
        cols,
        rows,
        identities,
        ask_password,
        password_env,
        auth_order,
        host_key: host_key.unwrap_or_default(),
        log,
        capture,
        chunk,
        poll_ms,
        escape,
        stats_secs,
        quiet,
        stdin,
        send,
        send_delay_ms,
        interlock,
        expect,
        expect_quiet_ms,
        // Zero means "wait as long as it takes", which is a legitimate choice
        // for a run someone is watching.
        expect_timeout_ms: (expect_timeout_ms > 0).then_some(expect_timeout_ms),
        expect_exit,
        expect_run,
        expect_manifest,
    })))
}

fn parse_num<T: std::str::FromStr>(s: &str, name: &str) -> Result<T, String> {
    s.parse::<T>()
        .map_err(|_| format!("{} expects a number, got '{}'", name, s))
}

/// Decode a `--send` string into the bytes to put on the wire.
///
/// A keystroke script is mostly control characters -- there is no point being
/// able to inject `vttest` if you cannot inject the RETURN after it -- and a
/// shell will not pass a raw CR through an argument. So the usual C escapes
/// are understood here.
///
/// An unrecognised escape is an error rather than a literal: `--send 'a\qb'`
/// is far more likely to be a typo for something than a deliberate request
/// for three characters, and a script that silently types the wrong thing at
/// a terminal is unpleasant to debug.
fn parse_bytes(s: &str) -> Result<Vec<u8>, String> {
    parse_bytes_named(s, "--send")
}

/// [`parse_bytes`] with the flag to blame in the error message.
///
/// The same decoder serves `--send` and the keys half of an `--expect` rule.
/// A message naming `--send` while the operator was editing an `--expect`
/// would send them to the wrong line of a long command.
fn parse_bytes_named(s: &str, flag: &str) -> Result<Vec<u8>, String> {
    let src: Vec<char> = s.chars().collect();
    let mut out = Vec::with_capacity(src.len());
    let mut i = 0;

    while i < src.len() {
        let c = src[i];
        if c != '\\' {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            i += 1;
            continue;
        }
        i += 1;
        let esc = *src
            .get(i)
            .ok_or_else(|| format!("{} '{}' ends with a lone backslash", flag, s))?;
        match esc {
            'r' => out.push(b'\r'),
            'n' => out.push(b'\n'),
            't' => out.push(b'\t'),
            'e' => out.push(0x1b),
            'a' => out.push(0x07),
            'b' => out.push(0x08),
            'f' => out.push(0x0c),
            '0' => out.push(0x00),
            '\\' => out.push(b'\\'),
            '\'' => out.push(b'\''),
            '"' => out.push(b'"'),
            'x' | 'X' => {
                let hi = src.get(i + 1);
                let lo = src.get(i + 2);
                let (hi, lo) = match (hi, lo) {
                    (Some(h), Some(l)) => (*h, *l),
                    _ => {
                        return Err(format!(
                            "{} '{}' has a \\x with fewer than two digits",
                            flag, s
                        ))
                    }
                };
                let digits: String = [hi, lo].iter().collect();
                if !hi.is_ascii_hexdigit() || !lo.is_ascii_hexdigit() {
                    return Err(format!("{flag} '{s}': '\\x{digits}' is not two hex digits"));
                }
                let byte = u8::from_str_radix(&digits, 16)
                    .map_err(|_| {
                        format!("{} '{}': '\\x{}' is not two hex digits", flag, s, digits)
                    })?;
                out.push(byte);
                i += 2;
            }
            other => {
                return Err(format!(
                    "{} '{}': unknown escape '\\{}' (known: \\r \\n \\t \\e \\a \\b \\f \\0 \\xNN \\\\)",
                    flag, s, other
                ))
            }
        }
        i += 1;
    }
    Ok(out)
}

/// Parse `--escape`: `^]`, `0x1d`, or a single literal character.
fn parse_escape(s: &str) -> Result<u8, String> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("--escape '{s}' is not a byte value"));
        }
        return u8::from_str_radix(hex, 16)
            .map_err(|_| format!("--escape '{}' is not a byte value", s));
    }
    let chars: Vec<char> = s.chars().collect();
    if chars.len() == 2 && chars[0] == '^' {
        let c = chars[1].to_ascii_uppercase();
        // Ctrl-@ .. Ctrl-_ map to 0x00..0x1f; Ctrl-? is DEL by convention.
        if c == '?' {
            return Ok(0x7f);
        }
        if ('@'..='_').contains(&c) {
            return Ok((c as u8) - b'@');
        }
        return Err(format!("--escape '{}' is not a control character", s));
    }
    if chars.len() == 1 && chars[0].is_ascii() {
        return Ok(chars[0] as u8);
    }
    Err(format!(
        "--escape '{}' should be ^X, 0xNN, or one ASCII character",
        s
    ))
}

/// The baud rate out of a composed serial spec.
///
/// Used to report the cable's rate to the remote PTY, whose default otherwise
/// depends on the server. Returns zero for input that was not validated by
/// [`compose_serial_spec`].
pub fn spec_baud(composed: &str) -> u32 {
    composed
        .split_once('@')
        .and_then(|(_, rest)| rest.split(',').next())
        .and_then(|b| b.parse().ok())
        .unwrap_or(0)
}

/// Fold `--flow` into the serial spec `SerialTransport::open` will parse.
///
/// The spec's own third field wins if it is present, because someone who
/// wrote `COM17@19200,8N1,hw` meant it -- but saying it twice and differently
/// is a mistake worth naming rather than resolving silently.
pub fn compose_serial_spec(spec: &str, flow: Option<Flow>) -> Result<String, String> {
    let (port, rest) = spec
        .split_once('@')
        .ok_or_else(|| format!("--serial '{}' is missing @baud (e.g. COM17@19200)", spec))?;
    if port.is_empty() {
        return Err(format!("--serial '{}' is missing the port name", spec));
    }

    let fields: Vec<&str> = rest.split(',').collect();
    let baud = fields[0];
    if !matches!(baud.parse::<u32>(), Ok(1..)) {
        return Err(format!("--serial '{}' has an invalid baud rate", spec));
    }
    let fmt = fields.get(1).copied().filter(|f| !f.is_empty());
    let spec_flow = fields.get(2).copied().filter(|f| !f.is_empty());
    if fields.len() > 3 {
        return Err(format!(
            "--serial '{}' has too many comma-separated fields (port@baud[,fmt[,flow]])",
            spec
        ));
    }

    let effective = match (spec_flow, flow) {
        (Some(in_spec), Some(on_flag)) => {
            let in_spec_parsed = Flow::parse(in_spec)?;
            if in_spec_parsed != on_flag {
                return Err(format!(
                    "--serial says flow control '{}' but --flow says '{}'; \
                     name it once",
                    in_spec,
                    on_flag.as_spec()
                ));
            }
            in_spec_parsed
        }
        (Some(in_spec), None) => Flow::parse(in_spec)?,
        // `sw` by default: a terminal being flooded by a test suite needs the
        // OS driver to stop the UART on XOFF, not a userspace loop to notice
        // a chunk later.  See USAGE.
        (None, on_flag) => on_flag.unwrap_or(Flow::Software),
    };

    let composed = format!(
        "{}@{},{},{}",
        port,
        baud,
        fmt.unwrap_or("8N1"),
        effective.as_spec()
    );
    retrosim_transports::SerialTransport::validate_spec(&composed)
        .map_err(|e| format!("--serial: {e}"))?;
    Ok(composed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_escapes_require_digits_and_serial_formats_are_validated_without_io() {
        for input in [r"\x+1", r"\x-1", r"\xＧ1"] {
            assert!(parse_bytes_named(input, "--send").is_err());
        }
        assert!(parse_escape("0x+1").is_err());
        for input in ["fake@0", "fake@9600,9N1", "fake@9600,8Q1", "fake@9600,8N3"] {
            assert!(compose_serial_spec(input, None).is_err(), "{input}");
        }
        assert!(compose_serial_spec("nonexistent@9600,7E2", None).is_ok());
    }

    fn parse_ok(s: &str) -> Args {
        let argv: Vec<String> = s.split_whitespace().map(String::from).collect();
        match parse(argv).expect("should parse") {
            Action::Run(a) => *a,
            other => panic!("expected Run, got {:?}", other),
        }
    }

    fn parse_err(s: &str) -> String {
        let argv: Vec<String> = s.split_whitespace().map(String::from).collect();
        match parse(argv) {
            Err(e) => e,
            Ok(a) => panic!("expected an error, got {:?}", a),
        }
    }

    const MIN: &str = "--serial COM3@9600 --ssh host";

    #[test]
    fn minimal_command_line() {
        let a = parse_ok(MIN);
        assert_eq!(a.serial, "COM3@9600,8N1,sw");
        assert_eq!(a.ssh, "host");
        assert_eq!(a.term, "vt510");
        assert_eq!((a.cols, a.rows), (80, 24));
        assert_eq!(a.chunk, DEFAULT_CHUNK);
        assert!(a.escape.is_none(), "the escape key must be opt-in");
    }

    #[test]
    fn serial_and_ssh_are_required() {
        assert!(parse_err("--ssh host").contains("--serial"));
        assert!(parse_err("--serial COM3@9600").contains("--ssh"));
    }

    #[test]
    fn help_and_version_short_circuit_before_required_checks() {
        assert!(matches!(parse(vec!["--help".into()]), Ok(Action::Help)));
        assert!(matches!(parse(vec!["-V".into()]), Ok(Action::Version)));
        assert!(matches!(
            parse(vec!["--list-ports".into()]),
            Ok(Action::ListPorts)
        ));
    }

    #[test]
    fn unknown_argument_is_rejected_by_name() {
        let e = parse_err("--serial COM3@9600 --ssh host --colour red");
        assert!(e.contains("--colour"), "{}", e);
    }

    #[test]
    fn a_flag_missing_its_value_does_not_eat_the_next_flag() {
        // The failure this guards: `--term --quiet` silently setting TERM to
        // "--quiet" and then reporting a baffling terminal type to the host.
        let e = parse_err("--serial COM3@9600 --ssh host --term --quiet");
        assert!(e.contains("--term"), "{}", e);
        assert!(e.contains("--quiet"), "{}", e);
    }

    #[test]
    fn a_trailing_flag_missing_its_value_is_an_error() {
        let e = parse_err("--serial COM3@9600 --ssh host --term");
        assert!(e.contains("--term"), "{}", e);
    }

    #[test]
    fn numeric_flags_reject_non_numbers() {
        assert!(parse_err(&format!("{} --cols eighty", MIN)).contains("--cols"));
        assert!(parse_err(&format!("{} --chunk -5", MIN)).contains("--chunk"));
    }

    #[test]
    fn zero_chunk_and_zero_geometry_are_rejected() {
        // A zero chunk is an infinite loop that moves no bytes; a zero-column
        // PTY makes the remote's cursor arithmetic nonsense.
        assert!(parse_err(&format!("{} --chunk 0", MIN)).contains("--chunk"));
        assert!(parse_err(&format!("{} --cols 0", MIN)).contains("--cols"));
        assert!(parse_err(&format!("{} --rows 0", MIN)).contains("--rows"));
    }

    #[test]
    fn identity_is_repeatable_and_ordered() {
        let a = parse_ok(&format!("{} -i keyA --identity keyB", MIN));
        assert_eq!(
            a.identities,
            vec![PathBuf::from("keyA"), PathBuf::from("keyB")]
        );
    }

    #[test]
    fn auth_list_is_parsed_and_ordered() {
        let a = parse_ok(&format!("{} --auth password,agent", MIN));
        assert_eq!(
            a.auth_order.unwrap(),
            vec![SshAuthMethod::Password, SshAuthMethod::Agent]
        );
    }

    #[test]
    fn bad_auth_list_names_the_offender() {
        assert!(parse_err(&format!("{} --auth agent,kerberos", MIN)).contains("kerberos"));
    }

    #[test]
    fn server_identity_defaults_to_known_hosts() {
        assert_eq!(parse_ok(MIN).host_key, SshHostKeyPolicy::DefaultKnownHosts);
        assert_eq!(
            parse_ok(&format!("{MIN} --known-hosts lab_keys")).host_key,
            SshHostKeyPolicy::KnownHosts(PathBuf::from("lab_keys"))
        );
        assert_eq!(
            parse_ok(&format!("{MIN} --insecure-skip-host-key-check")).host_key,
            SshHostKeyPolicy::InsecureAcceptAny
        );
        let pin = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert_eq!(
            parse_ok(&format!("{MIN} --host-key-sha256 {pin}")).host_key,
            SshHostKeyPolicy::PinnedSha256([0; 32])
        );
    }

    #[test]
    fn invalid_and_conflicting_host_key_options_are_rejected() {
        let choices = [
            "--known-hosts keys",
            "--host-key-sha256 SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "--insecure-skip-host-key-check",
        ];
        for first in choices {
            for second in choices {
                assert!(parse_err(&format!("{MIN} {first} {second}"))
                    .contains("only one host-key policy"));
            }
        }
        assert!(parse_err(&format!("{MIN} --host-key-sha256 SHA256:bad")).contains("fingerprint"));
        assert!(parse_err(&format!("{MIN} --known-hosts")).contains("expects a value"));
    }

    // ---- serial spec composition -------------------------------------

    #[test]
    fn flow_defaults_to_software() {
        assert_eq!(
            compose_serial_spec("COM17@19200", None).unwrap(),
            "COM17@19200,8N1,sw"
        );
    }

    #[test]
    fn flow_flag_is_folded_in() {
        assert_eq!(
            compose_serial_spec("COM17@19200", Some(Flow::None)).unwrap(),
            "COM17@19200,8N1,none"
        );
        assert_eq!(
            compose_serial_spec("COM17@19200", Some(Flow::Hardware)).unwrap(),
            "COM17@19200,8N1,hw"
        );
    }

    #[test]
    fn explicit_format_is_preserved() {
        assert_eq!(
            compose_serial_spec("/dev/ttyUSB0@9600,7E1", Some(Flow::None)).unwrap(),
            "/dev/ttyUSB0@9600,7E1,none"
        );
    }

    #[test]
    fn flow_in_the_spec_is_honoured_without_the_flag() {
        assert_eq!(
            compose_serial_spec("COM17@19200,8N1,hw", None).unwrap(),
            "COM17@19200,8N1,hw"
        );
    }

    #[test]
    fn agreeing_flow_in_both_places_is_fine() {
        assert_eq!(
            compose_serial_spec("COM17@19200,8N1,hw", Some(Flow::Hardware)).unwrap(),
            "COM17@19200,8N1,hw"
        );
    }

    #[test]
    fn contradicting_flow_is_an_error_not_a_silent_winner() {
        // Whichever one this resolved to, the operator would believe the
        // other -- and flow control is exactly the setting whose absence
        // shows up as "the terminal drops characters", i.e. as a bug in the
        // hardware under test.
        let e = compose_serial_spec("COM17@19200,8N1,hw", Some(Flow::None)).unwrap_err();
        assert!(e.contains("hw") && e.contains("none"), "{}", e);
    }

    #[test]
    fn missing_baud_is_rejected() {
        assert!(compose_serial_spec("COM17", None)
            .unwrap_err()
            .contains("@baud"));
    }

    #[test]
    fn missing_port_name_is_rejected() {
        assert!(compose_serial_spec("@19200", None)
            .unwrap_err()
            .contains("port name"));
    }

    #[test]
    fn non_numeric_baud_is_rejected() {
        assert!(compose_serial_spec("COM17@fast", None)
            .unwrap_err()
            .contains("baud"));
    }

    #[test]
    fn too_many_spec_fields_are_rejected() {
        assert!(compose_serial_spec("COM17@19200,8N1,hw,extra", None)
            .unwrap_err()
            .contains("too many"));
    }

    #[test]
    fn unknown_flow_names_are_rejected() {
        assert!(Flow::parse("maybe").is_err());
        assert!(compose_serial_spec("COM17@19200,8N1,maybe", None).is_err());
    }

    // ---- escape ------------------------------------------------------

    #[test]
    fn escape_accepts_caret_notation() {
        assert_eq!(parse_escape("^]").unwrap(), 0x1d);
        assert_eq!(parse_escape("^A").unwrap(), 0x01);
        assert_eq!(parse_escape("^a").unwrap(), 0x01);
        assert_eq!(parse_escape("^?").unwrap(), 0x7f);
    }

    #[test]
    fn escape_accepts_hex_and_literals() {
        assert_eq!(parse_escape("0x1d").unwrap(), 0x1d);
        assert_eq!(parse_escape("0X1D").unwrap(), 0x1d);
        assert_eq!(parse_escape("~").unwrap(), b'~');
    }

    #[test]
    fn escape_rejects_nonsense() {
        assert!(parse_escape("^1").is_err());
        assert!(parse_escape("0xZZ").is_err());
        assert!(parse_escape("abc").is_err());
        assert!(
            parse_escape("\u{20ac}").is_err(),
            "non-ASCII has no single byte"
        );
    }

    #[test]
    fn usage_mentions_every_flag_the_parser_accepts() {
        // A flag that works but is undocumented is a flag nobody uses; a flag
        // that is documented but was renamed is worse.  This pins them
        // together.
        for flag in [
            "--serial",
            "--ssh",
            "--flow",
            "--chunk",
            "--poll",
            "--term",
            "--cols",
            "--rows",
            "--identity",
            "--ask-password",
            "--password-env",
            "--auth",
            "--log",
            "--capture",
            "--stats",
            "--escape",
            "--list-ports",
            "--quiet",
            "--help",
            "--version",
            "--stdin",
            "--send",
            "--send-delay",
            "--no-interlock",
            "--expect",
            "--expect-once",
            "--expect-quiet",
            "--expect-timeout",
            "--expect-exit",
            "--expect-run",
            "--expect-manifest",
        ] {
            assert!(USAGE.contains(flag), "{} is not documented in USAGE", flag);
        }
    }

    fn run_args(extra: &[&str]) -> Args {
        let mut argv: Vec<String> = ["--serial", "COM17@9600", "--ssh", "user@host.example"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        argv.extend(extra.iter().map(|s| s.to_string()));
        match parse(argv).unwrap() {
            Action::Run(a) => *a,
            other => panic!("expected a run, got {:?}", other),
        }
    }

    #[test]
    fn spec_baud_reads_the_rate_the_pty_will_be_told() {
        assert_eq!(spec_baud("COM17@9600,8N1,sw"), 9600);
        assert_eq!(spec_baud("/dev/ttyUSB0@115200,8N1,none"), 115200);
        assert_eq!(
            spec_baud(&compose_serial_spec("COM17@19200", None).unwrap()),
            19200
        );
    }

    #[test]
    fn injection_is_off_and_interlocked_by_default() {
        let a = run_args(&[]);
        assert!(!a.stdin);
        assert!(a.send.is_empty());
        assert!(a.interlock, "the interlock must be opt-out, not opt-in");
        assert_eq!(a.send_delay_ms, DEFAULT_SEND_DELAY_MS);
    }

    #[test]
    fn expect_is_off_by_default() {
        let a = run_args(&[]);
        assert!(a.expect.is_empty());
        assert!(!a.expect_exit);
        assert_eq!(a.expect_quiet_ms, DEFAULT_EXPECT_QUIET_MS);
        assert_eq!(a.expect_timeout_ms, Some(DEFAULT_EXPECT_TIMEOUT_MS));
    }

    /// Standing and scripted rules land in ONE list: their relative order is
    /// what decides which of them answers a screen that satisfies both, so
    /// splitting them into two lists would lose the information.
    #[test]
    fn expect_rules_keep_the_order_they_were_written_in() {
        let a = run_args(&[
            "--expect",
            "Push <RETURN> => \\r",
            "--expect-once",
            "Enter choice number => 6\\r",
            "--expect",
            "Error => q",
        ]);
        assert_eq!(a.expect.len(), 3);
        assert_eq!(a.expect[0].pattern, "Push <RETURN>");
        assert!(!a.expect[0].once);
        assert_eq!(a.expect[1].pattern, "Enter choice number");
        assert!(a.expect[1].once);
        assert_eq!(a.expect[1].keys, b"6\r".to_vec());
        assert_eq!(a.expect[2].pattern, "Error");
    }

    #[test]
    fn expect_timings_are_settable_and_zero_means_forever() {
        let a = run_args(&["--expect-quiet", "50", "--expect-timeout", "9000"]);
        assert_eq!(a.expect_quiet_ms, 50);
        assert_eq!(a.expect_timeout_ms, Some(9000));

        let a = run_args(&["--expect-timeout", "0"]);
        assert_eq!(
            a.expect_timeout_ms, None,
            "0 must disable, not fire instantly"
        );
    }

    /// Nothing would ever end the session, and the run would have to be
    /// killed -- which truncates the very trace files it was recording.
    #[test]
    fn expect_exit_without_a_script_is_refused() {
        let e = parse(
            [
                "--serial",
                "COM17@9600",
                "--ssh",
                "user@host.example",
                "--expect",
                "x => y",
                "--expect-exit",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>(),
        )
        .unwrap_err();
        assert!(e.contains("--expect-once"), "{}", e);
    }

    #[test]
    fn expect_exit_with_a_script_is_accepted() {
        let a = run_args(&["--expect-once", "choice => 0\\r", "--expect-exit"]);
        assert!(a.expect_exit);
    }

    /// An error about an escape must name the flag being edited. The decoder
    /// is shared with `--send`, and a message blaming `--send` would send the
    /// operator to the wrong line of a long command.
    #[test]
    fn an_expect_escape_error_blames_expect_not_send() {
        let e = parse(
            [
                "--serial",
                "COM17@9600",
                "--ssh",
                "user@host.example",
                "--expect",
                "x => a\\qb",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>(),
        )
        .unwrap_err();
        assert!(e.contains("--expect"), "{}", e);
        assert!(!e.contains("--send"), "{}", e);
    }

    #[test]
    fn stdin_and_no_interlock_are_flags() {
        let a = run_args(&["--stdin", "--no-interlock"]);
        assert!(a.stdin);
        assert!(!a.interlock);
    }

    #[test]
    fn send_is_repeatable_and_ordered() {
        let a = run_args(&["--send", "one", "--send", "two", "--send-delay", "50"]);
        assert_eq!(a.send, vec![b"one".to_vec(), b"two".to_vec()]);
        assert_eq!(a.send_delay_ms, 50);
    }

    #[test]
    fn send_decodes_the_escapes_a_keystroke_script_needs() {
        assert_eq!(parse_bytes("vttest\\r").unwrap(), b"vttest\r".to_vec());
        assert_eq!(parse_bytes("\\n\\t\\0").unwrap(), vec![0x0a, 0x09, 0x00]);
        assert_eq!(parse_bytes("\\e[c").unwrap(), b"\x1b[c".to_vec());
        assert_eq!(parse_bytes("\\x1b\\x5b").unwrap(), b"\x1b[".to_vec());
        assert_eq!(parse_bytes("a\\\\b").unwrap(), b"a\\b".to_vec());
        assert_eq!(parse_bytes("").unwrap(), Vec::<u8>::new());
    }

    /// Ctrl-C cannot be typed at this console (it quits the bridge), so
    /// `--send` is the only way to put one on the wire.
    #[test]
    fn send_can_express_a_control_byte_the_console_cannot() {
        assert_eq!(parse_bytes("\\x03").unwrap(), vec![0x03]);
    }

    #[test]
    fn a_bad_escape_is_an_error_not_a_literal() {
        // Silently typing three characters at a terminal because an escape
        // was not recognised is the kind of bug that costs an afternoon.
        let e = parse_bytes("a\\qb").unwrap_err();
        assert!(e.contains("\\q"), "the error should name the escape: {}", e);
        assert!(parse_bytes("trailing\\").is_err());
        assert!(parse_bytes("\\x1").is_err());
        assert!(parse_bytes("\\xzz").is_err());
    }

    #[test]
    fn send_rejects_a_bad_escape_through_the_parser_too() {
        let argv: Vec<String> = [
            "--serial",
            "COM17@9600",
            "--ssh",
            "user@host.example",
            "--send",
            "a\\qb",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert!(parse(argv).is_err());
    }
}

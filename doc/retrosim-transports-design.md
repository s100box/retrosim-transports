# retrosim-transports design

<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Howard M. Harte -->

[README](../README.md) · Source paths are relative to the repository root.

**Contents**

- [1. Purpose and scope](#1-purpose-and-scope)
- [2. Features and dependencies](#2-features-and-dependencies)
- [3. Transport interface](#3-transport-interface)
- [4. RFC 2217 and bridge discovery](#4-rfc-2217-and-bridge-discovery)
- [5. Flow control and SSH authentication](#5-flow-control-and-ssh-authentication)
- [6. uartssh architecture](#6-uartssh-architecture)
- [7. serbridge architecture](#7-serbridge-architecture)
- [8. Verification and platform limits](#8-verification-and-platform-limits)

## 1. Purpose and scope

The library implements the `retrosim-core::Transport` byte-stream interface.
Consumers can connect simulated UARTs to different endpoints without embedding
protocol handling in the simulator. `uartssh` connects a physical terminal to
an SSH shell; `serbridge` holds and logs a console while sharing it with tools.

## 2. Features and dependencies

| Feature or package | Dependencies and behavior |
|---|---|
| Library without default features | TCP, Telnet, UDP, RFC 2217, console marker, and null transport; requires sibling `retrosim-core`. |
| `serial` (default) | Direct serial access through `serialport`; bridge discovery can use RFC 2217 without this feature. |
| `ssh` | SSH client through `ssh2`/libssh2. |
| `bridge` | `uartssh`; enables serial, SSH, password prompting, Ctrl-C handling, and Unix terminal control. |
| `serbridge` | Workspace member with a platform-specific serial backend; depends on the library with default features off. Optional `ssh` forwards to the library. |

`uartssh` has `required-features = ["bridge"]`. A default library build does
not build it. The workspace packages share a Rust 1.85.1 minimum, inherited
from `[workspace.package]`. `ci/check-msrv.sh` tests all features, the
network-only library, and standalone `serbridge` against the checked-in lockfile.
The sibling `retrosim-core` is compiled as a dependency in each configuration.
CI follows its `main` branch to check the current shared interface. Dependency
updates, including password-prompting dependencies, must pass this gate.

## 3. Transport interface

`Transport` requires `Read + Write + Send`, timeout configuration, and a
description, with optional connection state, reconfiguration, and modem control.
It does not require `Sync`. See the
[foundation contract](https://github.com/s100box/retrosim-core/blob/main/doc/retrosim-core-guide.md#7-transport-layer).

| Spec                           | client (`listen = false`)         | server (`listen = true`)    |
|--------------------------------|-----------------------------------|-----------------------------|
| `console`                      | local terminal marker             | (same)                      |
| `null`                         | discard all I/O                   | (same)                      |
| `tcp:<host:port>`              | TCP client                        | TCP server on `<port>`      |
| `telnet:<host:port>`           | telnet client                     | telnet server on `<port>`   |
| `udp:<host:port>`              | UDP client                        | UDP server on `<port>`      |
| `serial:<port>@<baud>[,fmt[,flow]]` | serial port, or the bridge holding it | error              |
| `rfc2217:<host:port>[@<baud>[,fmt[,flow]]]` | RFC 2217 client      | error                       |
| `ssh:[<user>@]<host>[:<port>]` | SSH client                        | not supported               |

`open_transport(spec, listen)` returns a boxed transport. Bare port numbers work
for TCP/telnet/UDP: `tcp:2023` binds `0.0.0.0:2023`. `open_transport_with_pty`
(feature `ssh`) takes the same spec plus an `SshPtyParams`, so a terminal
simulator can tell the remote what `TERM` and window size it is talking to;
for every non-SSH spec the parameters are ignored.

The concrete types are public too — `ConsoleTransport`, `NullTransport`,
`TcpTransport`, `TelnetTransport`, `UdpTransport`, `Rfc2217Transport`,
`SerialTransport` (feature `serial`) and `SshTransport` (feature `ssh`) — for
callers that want a particular one without going through the spec parser.

`TcpTransport::accept` accepts one peer and drops the listener; it is not a
reconnecting server. `TelnetTransport::accept` retains its listener and can
accept a replacement peer. `is_connected` is backend bookkeeping, not an
active liveness probe: raw TCP, direct serial and UDP use the trait's default
`true`. Consumers must handle EOF and I/O errors even when that method is true.

Telnet client mode refuses options. Server mode offers ECHO and
SUPPRESS-GO-AHEAD, tracks their acknowledgements, and does not answer repeated
refusals. A listener keeps timeout requests made before a peer arrives and
applies them to replacement connections. A wrapped `TcpStream` keeps its
existing socket configuration until `set_read_timeout` is called.

Telnet retains the latest 64 KiB of console output while no peer is connected.
For a connected peer, a separate 128 KiB queue preserves encoded bytes across
short writes and backpressure. `write` reports only accepted caller bytes;
`flush` can return `WouldBlock` with output still queued. Reads and later writes
also service that queue. Disconnection abandons connection-specific protocol
bytes, and a client-mode transport reports EOF instead of accepting new output
into an offline buffer.

`SshPtyParams` also carries an optional line speed. `uartssh` sets it from
the serial spec so the remote PTY reports the requested cable rate.

UDP presents received datagrams as buffered bytes; it does not add delivery,
ordering, or retransmission guarantees. A receive accepts at most 4096 bytes
per datagram; larger datagrams may be truncated or rejected by the platform.
Client construction
selects the write destination without connecting the socket; reads can accept
any sender. Server writes target the first received sender, and reads remain
unfiltered after that peer is learned. Writes before the first receive are
discarded with a successful byte count. Empty
reads return zero without consuming a datagram. A zero read timeout polls
with `WouldBlock`; a later finite timeout restores blocking socket reads.

Direct serial reconfiguration validates the format before applying settings.
Invalid data widths and 1.5 stop bits, which the `serialport` backend cannot
represent, return errors instead of being replaced with another format. Driver
failures during individual setting calls can leave a partially applied format.
Direct serial reads translate a zero timeout to `WouldBlock` and retry internal
driver timeouts when the caller requested indefinite blocking.

## 4. RFC 2217 and bridge discovery

`Rfc2217Transport` implements serial settings and modem lines over Telnet.
Setting changes wait for server acknowledgement and report refusal as an error.
Opening an explicit RFC 2217 spec changes only named settings; DTR and RTS
remain unchanged until requested. A zero read timeout reports `WouldBlock`;
other expired timeouts report `TimedOut`. The client retains up to 128 KiB of
encoded output across short writes and bounds unread serial data to 1 MiB.
Control sends/flushes have a three-second retry budget; modem-state polling
processes at most 16 socket chunks per call. A peer cannot keep those operations
running indefinitely with control-only traffic. Fixed-width requests with
extra or missing payload bytes are ignored by the server.

Both RFC 2217 decoders limit buffered sub-negotiations to 256 decoded bytes,
including the option and command. Oversized frames are discarded in full through
their terminator, so their prefixes cannot change settings or modem state.

For `serial:` specs, `rfc2217::bridge_addr` checks a port-named URL file first.
A reachable bridge receives the parsed serial settings. A failed connection
falls back to direct serial access; an established connection that refuses a
setting returns that error. `SerialTransport::open` always opens directly.

The socket-independent `Session` and `Device` interfaces implement the server
protocol. `serbridge` supplies the device backend and connection loop. The
[operating guide](serbridge-guide.md#sharing-the-port-rfc-2217) owns URL-file
locations, client examples, and multi-client behavior.

## 5. Flow control and SSH authentication

`FlowControlGate` observes outbound XON/XOFF and the simulated UART's RTS.
While paused, it makes reads return `WouldBlock`; network backpressure then
limits the peer. It does not remove XON/XOFF bytes from the stream.

`SshAuth::legacy()` tries agent, password, and `none`; its password sources
are `TVI950_SSH_PASSWORD` and `S100BOX_SSH_PASSWORD`. `connect` and
`connect_with_pty` use this policy. `SshAuth::discovered()` tries agent,
public-key files, password, keyboard-interactive, and `none`, discovering
`~/.ssh/id_*` and checking `RETROSIM_SSH_PASSWORD` before the other variables.
`uartssh` uses the discovered policy, configurable with `--auth`.

Library keyboard-interactive authentication uses a caller-provided `KbdPrompt`;
it does not read stdin. Without a callback, non-echo prompts can use the
configured password. Authentication diagnostics put the target address on the
summary line, keeping local key-conversion advice separate. Method discovery
sends an initial `none` probe; credential-free success is accepted only if
`None` appears in the configured policy. A callback must return exactly one
answer per keyboard-interactive prompt; wrong counts fail the authentication.

SSH tries resolved TCP addresses within a shared ten-second connection budget
after synchronous DNS resolution. Setup uses a ten-second timeout per blocking
libssh2 network operation; an interactive callback can wait for human input.
After setup, reads block until configured otherwise. libssh2 shares its timeout
and blocking mode across reads and writes; positive sub-millisecond timeouts
round up to one millisecond. `Drop` makes best-effort nonblocking close calls.

Server mode returns an unsupported error. Client server-identity checks are
independent of the user-authentication policy and always precede it.

Some libssh2 builds reject OpenSSH-format private key files. Prefer an SSH
agent, or convert a copy to a supported PEM format. Keep the original key.
Agent support includes the Windows OpenSSH named-pipe agent.

### 5.1 Server identity policy

`SshHostKeyPolicy` selects how to verify the server's key after key exchange
and before any authentication request, including the `none` method probe:

| Policy | Contract |
|---|---|
| `DefaultKnownHosts` (default) | Strict match in the native user's `.ssh/known_hosts`. Missing files, unknown hosts, and changed keys fail. |
| `KnownHosts(path)` | Strict match in an explicit OpenSSH file, supporting plain and hashed host names. Non-default ports require `[host]:port` entries. |
| `PinnedSha256(digest)` | Match the SHA-256 digest of the raw key. `SshHostKeyPolicy::sha256("SHA256:...")` parses OpenSSH's unpadded fingerprint format. |
| `InsecureAcceptAny` | Explicit lab-only bypass, allowing server impersonation. Never used as a fallback. |

Known-hosts files are read-only; unknown keys are not enrolled automatically.
Malformed records and unsupported `@revoked`/`@cert-authority` markers fail
closed. Use a dedicated file of independently verified host keys when a
general trust store includes unsupported directives. Fingerprint pins must
come through a trusted channel, not from an unverified connection attempt.

`connect`, `connect_with_pty`, `connect_with_auth`, `open_transport`, and
`open_transport_with_pty` all use `DefaultKnownHosts` for SSH. This also covers
`serbridge --port ssh:...`. Their signatures are unchanged, but callers must
provision trusted server keys. To choose a custom trust file or pin, migrate
direct library calls to `SshTransport::connect_with_policy`:

```rust
use retrosim_transports::{SshAuth, SshHostKeyPolicy, SshPtyParams, SshTransport};

fn connect() -> Result<SshTransport, Box<dyn std::error::Error>> {
    let policy = SshHostKeyPolicy::KnownHosts("lab_known_hosts".into());
    let transport = SshTransport::connect_with_policy(
        "user", "host.example", 22, &SshPtyParams::default(),
        &SshAuth::discovered(), &policy,
    )?;
    Ok(transport)
}
```

Use the [uartssh guide](uartssh-guide.md#server-identity) for CLI policy options.
Errors include the observed public fingerprint to support diagnosis; seeing
that value in an error is not evidence that it is trusted.

## 6. uartssh architecture

The bridge uses a single loop for both directions and paces idle work with
serial read timeouts. Its `SshTransport` ownership keeps session and channel
access on one thread. `push_all` handles short writes and temporary refusal.
A zero-byte SSH read means EOF; a zero-byte serial read means no data.

Keyboard and scripted input merge with terminal replies. The injection
interlock holds keys while a terminal reply is incomplete, with a 250 ms
deadline; deadline releases are counted. Prompt rules additionally wait for
matching host output and a quiet interval, since a complete terminal reply
does not imply the remote program wants a key.

Standing rules fire repeatedly; one-shot rules become eligible in order.
Matching rules are evaluated in declaration order. Hooks execute between a
match and key injection, while the pump is stalled. Capture manifests record
host-to-terminal byte offsets so a replay can reproduce the captured state.
Terminal replies and injected keys have separate capture streams. Captures
record source bytes before forwarding, so failed runs can contain an unsent
suffix. Output paths that resolve to the same name are rejected before any
file is truncated; users must also avoid distinct hard links to one file.

See the [uartssh guide](uartssh-guide.md) for commands, defaults, and capture formats.

## 7. serbridge architecture

The bridge owns the console, logs and flushes received bytes, consumes a command file,
and optionally shares the stream through RFC 2217. A disconnected backend
reopens according to its identity; outages and dropped client writes are
marked in the log. The serial backend enumerates metadata without opening
ports, avoiding unintended DTR changes on unrelated boards. Log write/flush
failures stop the bridge with a failing exit status. Backend reopen holds the
settings and line locks while reapplying explicit client changes, preventing
stale snapshots from overwriting concurrent requests. Last-client restoration
and membership removal share the client-list lock.

USB reconnect matching uses a unique serial number or physical location, plus
the interface number for multi-port adapters. A backend without USB identity
uses the port name. Ambiguous matches wait rather than opening another adapter.
Linux and Darwin use separate termios ABI definitions with size assertions;
other Unix ABIs are rejected at compile time until separate declarations are provided.

The [serbridge guide](serbridge-guide.md) owns command-file semantics, reconnect
selection details, platform evidence, and client integration.

## 8. Verification and platform limits

| Area | Coverage and limits |
|---|---|
| Library | Unit tests cover spec parsing, transport defaults, Telnet, flow control, authentication policy, and RFC 2217 negotiation/refusal/disconnects. |
| uartssh | Deterministic fixtures cover short writes, retries, EOF handling, injection interlock, prompt ordering, and manifest JSON. A loopback socket checks ordering and delivery, but cannot reliably force Windows write backpressure. |
| serbridge | Process tests use a TCP backend; optional com0com/PTY tests exercise a serial backend. Hardware modem-line and framing checks require Windows serial ports. |
| Platform qualification | Windows serial and Linux PTY paths have recorded validation. macOS has compile/layout evidence only; other BSD backends are unsupported. Real USB unplug/reconnect by identity still needs qualification, including Linux enumeration. |
| SSH server identity | Synthetic-key tests cover matching, changed, unknown, hashed, port-scoped, pinned, malformed, and unsupported-marker cases. Live loopback fixtures verify rejection before user authentication, credential-free policy, timeout recovery, echo, and bounded teardown. |
| Minimum Rust version | Rust 1.85.1 runs the locked feature matrix; stable-toolchain checks also enforce formatting, lint, and Rustdoc. CI is configured for Windows, Linux, and macOS. |

See [verification commands](../README.md#verification) and the
[serial integration tests](../serbridge/README.md#verification). Do not present
coverage percentages or platform support as current without corresponding results.

CI and loopback tests do not establish USB hot-unplug or modem-line behavior
on hardware that has not been exercised.

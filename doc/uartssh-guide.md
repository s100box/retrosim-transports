# uartssh operating guide

<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Howard M. Harte -->

[README](../README.md) · [Design](retrosim-transports-design.md#6-uartssh-architecture)

## Connecting a terminal

From the repository root, build and inspect the available ports:

```bash
cargo build --locked --release --features bridge
target/release/uartssh --list-ports
target/release/uartssh --help
target/release/uartssh --serial COM3@9600 --ssh user@host.example
```

Replace the example port, rate, and host with your setup. On Unix a port may
be `/dev/ttyUSB0`. Verify the terminal's configured rate and framing before
connecting. A device-attributes query (`ESC [ c`) can confirm a responding
terminal; a VT500-series response begins `ESC [ ? 65 ;`. Port names are assigned
by the host and are not properties of a board model.

The server key must be trusted before authentication. See [Server identity](#server-identity)
before connecting to a new host.

## Flow control and terminal settings

`--flow sw` (default) lets the serial driver honor XON/XOFF. `none` passes
these characters to the remote while the bridge observes them for gating;
`hw` requires RTS/CTS wiring. `--chunk` bounds individual writes and thus
keyboard latency behind queued screen output. `--poll` sets serial polling.

`--term`, `--cols`, and `--rows` default to `vt510`, 80, and 24. The SSH PTY
also receives the serial spec's baud rate; the remote server may interpret or
ignore PTY settings. Check the remote's `stty` output for timing-sensitive tests.

## Keyboard and scripted input

```bash
uartssh --serial COM3@9600 --ssh user@host.example --stdin
uartssh --serial COM3@9600 --ssh user@host.example --send 'vttest\r'
```

`--stdin` reads local keys without echo and sends them towards the remote.
Watch the terminal for output. `--send` queues repeatable scripted strings.
Input merges with terminal replies; the interlock described in the
[design](retrosim-transports-design.md#6-uartssh-architecture) protects reply
boundaries. `--no-interlock` disables it.

Ctrl-C stops the local bridge even under `--stdin`; send a literal remote
Ctrl-C with `--send '\x03'`. `--escape <CHAR>` enables an in-band quit key
typed twice at the terminal. It is off by default because terminal reports
may contain arbitrary bytes.

## Prompt-driven automation

Use prompts for menu-driven suites; fixed delays can inject a key while the
remote is parsing a terminal report. Patterns match visible ASCII text, with
terminal control sequences removed. Rules take the form `TEXT => KEYS`:

- `--expect` is a standing rule that fires each time its text appears.
- `--expect-once` fires once, in the order one-shot rules were declared.
- `--expect-quiet` requires idle host output before matching (default 200 ms).
- `--expect-timeout` fails on an unanswered script prompt (default 120000 ms;
  zero disables the timeout).
- `--expect-exit` exits after all one-shot rules fire and requires at least one.
  If the session ends before completion, it returns a failing exit status,
  including with `--quiet`.

For example, from an established shell that can run `vttest`:

```bash
uartssh --serial COM3@9600 --ssh user@host.example --send 'vttest\r' \
  --expect 'Push <RETURN> => \r' --expect-once 'Enter choice number => 0\r' \
  --expect-exit
```

`--expect-run <CMD>` runs a command after a match and before injecting keys.
`%n` expands to the match ordinal padded to at least three digits, `%p` to
the matched pattern as literal shell text, and `%%` to a percent sign. Supply
any shell quoting needed by the command template. The pump waits for the hook, allowing a frame
capture before the key changes the screen.

## Server identity

The default policy requires a matching entry in the native user's
`.ssh/known_hosts`. Obtain and verify the server's public fingerprint through
a trusted channel before enrolling its key. A changed key is an error to
investigate, not a reason to disable verification.

Use one of these mutually exclusive options to override the default:

- `--known-hosts <FILE>` selects a dedicated OpenSSH trust file.
- `--host-key-sha256 <SHA256:...>` pins an independently verified fingerprint.
- `--insecure-skip-host-key-check` explicitly disables verification for an
  isolated lab and prints a warning, including under `--quiet`.

For example, after provisioning a verified key in `lab_known_hosts`:

```bash
uartssh --serial COM3@9600 --ssh user@host.example --known-hosts lab_known_hosts
```

Unknown or changed keys fail before any authentication request. The
[design contract](retrosim-transports-design.md#51-server-identity-policy)
defines supported trust-file records and library migration.

## Authentication options

`--identity <FILE>` offers a key and can repeat. Without it, usual `~/.ssh/id_*`
files are discovered. `--ask-password` prompts locally; `--password-env <VAR>`
chooses an environment variable. `--auth <LIST>` chooses and orders methods.
The [design](retrosim-transports-design.md#5-flow-control-and-ssh-authentication)
owns the policy and key-format compatibility details.

## Logs and captures

`--log <FILE>` writes direction-tagged hex with an ASCII gutter and identifies
XON/XOFF. `--capture <PREFIX>` writes these raw streams:

| File | Contents |
|---|---|
| `<PREFIX>.h2t.bin` | Host-to-terminal bytes. |
| `<PREFIX>.t2h.bin` | Terminal-to-host bytes. |
| `<PREFIX>.k2h.bin` | Injected keys, also tagged `K>H` in the log. |

`--expect-manifest <FILE>` records each matched pattern, keys, ordinal, and
host-to-terminal byte offset as JSON Lines. `keys_hex` preserves the exact
key bytes; `keys` is their readable UTF-8 view. Replay `.h2t.bin` to the recorded
offset to reconstruct a captured terminal state. `--stats <SECS>` prints byte
counters periodically. Logs and captures are flushed as written.

Captures record source bytes before forwarding; a failed run can include an
unsent suffix. Choose separate paths for the log, manifest, and capture files,
including distinct hard-link targets. Reusing a capture prefix removes a prior
`.k2h.bin`; that file is created only if the new run injects keys.

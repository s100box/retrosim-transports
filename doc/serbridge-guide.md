# serbridge operating guide

<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Howard M. Harte -->

[README](../serbridge/README.md) · [Design](retrosim-transports-design.md#7-serbridge-architecture)

## The command file

- Write a line to `cmd.txt` and it is sent with a CR appended, then the file
  is deleted. Several lines in one file go out in order, a quarter of a
  second apart so they do not overrun the board's line editor.
- A line of exactly `\x03` sends Ctrl-C; a line of exactly `\x00` sends
  nothing and just wakes the loop.
- Read the answer from the tail of `console.log` — it is the whole session.
- Create `serbridge.stop` to release the port.
- Keep each line short. A very long command line is cut by the board's tty
  before the shell sees it; anything long belongs in a script fetched over
  TFTP and run by name.
- DTR and RTS are **deasserted** whenever the bridge opens the port, on
  Linux as well (opening a tty asserts both, so the bridge releases them):
  a CH340 board with them asserted is held in reset and reads as a dead
  console on a live machine.

## Windows device paths

On Windows, `--port` accepts both bare COM names and fully qualified device
paths. Qualified paths are passed unchanged to the serial driver; this includes
the device-interface paths reported by `pnputil /enum-devices /instanceid
<instance-id> /interfaces`. An exact interface path can select a specific UART
when two adapters have conflicting COM aliases. COM assignments are unchanged.
DTR and RTS remain deasserted on open.

Clients discover the bridge using the same device path. On Windows, its URL
metadata filename replaces the namespace's `?` with `_`; the Rust, Python and
PowerShell clients share that rule.

## Holding a transport instead of a port

`--port` also takes any retrosim-transports spec — `tcp:host:port`,
`telnet:host:port`, `udp:host:port`, `rfc2217:host:port[@baud[,fmt[,flow]]]`
and, in a build with the `ssh` feature, `ssh:[user@]host[:port]`. The bridge
holds the connection the way it holds a port: it logs every byte, sends
`cmd.txt`, serves it over RFC 2217 with `--listen`, and when it drops, marks
the gap and opens it again as it was given (`--no-reconnect` exits instead).
SSH endpoints use strict verification against the user's `.ssh/known_hosts`
on every connection, including reconnects. Provision independently verified
keys before starting the bridge; see the [SSH policy](retrosim-transports-design.md#51-server-identity-policy).

```sh
serbridge --port tcp:192.168.1.50:23 --log board.log --listen 0
serbridge --port rfc2217:bench-pc:4001@115200 --log remote.log
```

A client's line settings and DTR, RTS and BREAK reach the transport through
retrosim-transports' `reconfigure` and `ModemControl`, so they mean what the
transport makes them mean. On an `rfc2217:` connection they reach the far
port. A `tcp:` or `telnet:` transport treats RTS as flow control — while RTS
is low it stops reading — and accepts the rest without effect; mark and space
parity and flow-control changes are refused on every transport, and the
client is told so.

`serial:NAME` and `serial:NAME@BAUD` name a serial port, held by serbridge's
own backend so the reconnect below can find it again. The line format is the
clients' to set, so a `serial:` spec that names one is refused.

## Reconnecting after a hot unplug

**A hot unplug invalidates the handle.** Re-seating the cable, or a board
power cycle that re-enumerates the adapter, makes every later read fail. The
bridge sees that because the read fails, and waits for the **same port** to
come back instead of exiting, under whatever name it gets. When it opens
the port it reads which USB adapter the port is on, and the log's first line
says what a reconnect will match:

| the adapter has | a reconnect takes the port with | `[serbridge] open …` ends |
| --- | --- | --- |
| a USB serial number no other present port reports | the same serial number, in any USB socket | `reconnects by USB serial number …` |
| no serial number (a CH340), or one another adapter also reports (clones) | the same USB socket | `reconnects by USB location …` |
| neither (not on USB, or macOS, where neither is read) | the same name | `reconnects by name only …` |

Both USB rows also require the same **USB interface**. That is what tells
the two ports of a dual adapter (an FT2232, a CP2105) apart, because they
report the same serial number and the same location; the log line then ends
`, interface 01`. Of the ports that match, the one with the last name is
preferred, and if two match and neither has it the bridge keeps waiting
rather than pick one.

**It never takes a port only because it is new.** On a bench with several
boards the new port is whichever adapter enumerated last — another board
powered up, or one re-plugged during the outage — and attaching to it logs
that board's console into this one's file. A port that does not match is not
opened at all, so a reconnect cannot reset another board through its DTR
either.

**An adapter with no serial number is anchored to its socket.** Moved to
another socket while the bridge waits, it is not found, and the bridge must
be restarted on the port `--list` shows. `--list` prints each port's serial
number, interface and location (Windows reads them from the device tree,
Linux from sysfs), and only reads: it opens no port.

**The gap is marked, and that matters more than the reconnect.** Bytes the
board sent while the port was down are gone — nothing buffers them — so a
silent rejoin splices two live moments together and reads as continuous. Every
outage writes `[serbridge] port lost …` into the log. A reader who cannot see
that something is missing will read the join as a fact.

### Platform qualification

Windows serial operation has hardware validation. Linux has end-to-end PTY
validation for opening, configuring, reading, writing, and stopping; its
termios layout assertion is 60 bytes. The Darwin backend has compile evidence
and a 72-byte layout assertion, but no hardware qualification. Other BSD
ABIs are unsupported and rejected at compile time.

Windows USB identity enumeration has been checked for FTDI, CH343, CDC-ACM,
CH340, FT2232, and CP2105 adapters, including multi-interface devices, plus
com0com ports without identity. Linux enumeration has model-tree tests and
non-USB ttyS evidence. Real USB unplug/reconnect by identity, including Linux
USB enumeration and macOS serial behavior, still require physical qualification.

**`termios` is not one ABI, and getting it wrong fails silently.** The
struct, the flag word's width, the `c_cc` indices, the flush selector and the
open flags all differ between Linux and Darwin — `CLOCAL` is `0o4000` on one and
`0x8000` on the other, `VMIN` moves from index 6 to 16, `TCIOFLUSH` from 2 to 3,
and Linux wants the `B115200` *token* where Darwin wants the literal rate. None
of that fails to compile; it just configures the port to something nobody asked
for. So the two are separate ABI modules, each asserting its own
`size_of::<Termios>()` at compile time — the one part of "I read the header
right" a compiler can actually check.

**The Rust bridge enumerates by reading the registry, never by opening
ports.** The obvious implementation — try every COM name and keep what opens —
touches every adapter on the bench, and a port opened with the driver's default
`DCB` commonly asserts DTR, which on these boards is reset. Scanning would
reset every other board plugged in. `SERIALCOMM` is keyed by device and can contain stale rows naming the same
COM port; enumeration deduplicates those names.

## Sharing the port: RFC 2217

With `--listen <tcp>` the bridge also serves the port as an RFC 2217 server
(serial over Telnet, the protocol `ser2net` and pySerial speak) on
`127.0.0.1`. `--listen 0` picks a free TCP port. A tool connects to it instead
of opening the port, and gets what it would have had from the port itself:

- every byte the board sends, which also still goes to the log — including
  what the board says while the tool is connected, which a tool that opens the
  port directly takes away from the log;
- everything it writes goes to the board, binary and all (Telnet's `0xFF` is
  escaped both ways, so XMODEM and register protocols pass unchanged);
- baud rate, data size, parity, stop bits and flow control, DTR, RTS and
  BREAK, CTS/DSR/RI/DCD (pushed to the client as they change), and purging
  the buffers. Each change is marked in the log (`[serbridge] client 1: DTR
  on`), and one the port refuses is refused to the client with the reason in
  the log;
- the bridge's reconnect: a tool connected across a power cycle stays
  connected, and what it writes while the port is down is dropped, with a
  mark in the log saying so.

Several tools can be connected at once; each sees all of the board's output,
and their writes go to the board as they arrive. When the last one
disconnects, the port goes back to the bridge's own settings with DTR, RTS
and BREAK released for physical serial endpoints. Raw TCP, Telnet and SSH
keep their synthetic RTS receive gate open so logging continues without a
client. An explicit software XOFF still requires a corresponding XON.
`cmd.txt` keeps working
alongside.

**Finding the bridge from the port name.** The bridge writes its URL to a
file named for the port, and removes it when it stops: on Windows
`%LOCALAPPDATA%\serbridge\COM20.url`, elsewhere
`$XDG_RUNTIME_DIR/serbridge/ttyUSB0.url` (or `/tmp/serbridge-$USER/`). A tool
that names its port as it always did finds the bridge there, and opens the
port directly when there is none. The file is named for `--port` as it was
given, even after a reconnect finds the port under another name, so a tool
keeps finding it by the name it knows. Three clients do exactly that:

- **Rust:** retrosim-transports itself. A `serial:COM20@115200` spec given to
  `open_transport` connects to the bridge when its file is there, sending the
  spec's settings to the bridge, and opens the port directly when it is not.
  A file left by a bridge that is no longer running is passed over. Every
  program that opens its connections through retrosim-transports gets this
  without a change; `rfc2217:host:port[@baud...]` names a bridge (or any RFC
  2217 server) directly.
- **Python:** [`clients/python/bridgeport.py`](../serbridge/clients/python/bridgeport.py):
  `bridgeport.open_port(name, baud, **kw)` in place of `serial.Serial(...)`.
- **PowerShell:** [`clients/powershell/SerBridge.psm1`](../serbridge/clients/powershell/SerBridge.psm1):
  `New-SerBridgePort -PortName X ...` in place of `New-Object SerialPort`. It
  runs under both Windows PowerShell 5.1 and PowerShell 7, and is checked
  under both.

The Python and PowerShell helpers are vendored into the repositories that use
them; [`serbridge/clients/`](../serbridge/clients/) holds the canonical copies.

**pySerial opens an RFC 2217 port as `serial.serial_for_url(url, ...)`**,
not `serial.Serial(url, ...)`, and its RFC 2217 client asserts DTR and RTS on
open by default, as it does on a real port. For a board that resets on DTR,
create the pySerial object with `do_not_open=True`, set its `dtr` and `rts`
properties to false, then call `open()`. The `bridgeport.open_port` helper
accepts `dtr=False` and `rts=False` and applies them before opening.
The RFC 2217 backend does not support `write_timeout`.

`--bind` takes another address, which puts the port on the network with no
authentication at all. Leave it on `127.0.0.1` unless the network is trusted.

**Measured** on a Windows host over a com0com pair (no baud-rate emulation,
so the wire costs nothing): a one-byte round trip through the bridge takes
0.08 ms against 0.03 ms straight through the pair, and 64 KiB echoes intact at
about 600 KiB/s — well above any UART here. On Linux the server is checked
over a `pty`: data both ways, a baud change, a refused setting reported as
refused, `cmd.txt`, and the return to the bridge's own settings. The Linux pty
driver forces 8N1, so it refuses any framing change, and it has no modem lines,
so DTR, RTS, BREAK and framing are checked on Windows only.

The bridge stops with a failing exit status if its log cannot be written or
flushed. Unreadable command files are retained with an error in the log. Publish
complete command batches with a temporary file and rename when atomicity is
required; the short delay before reading a shell redirect is only a convenience.
After a transport reconnect, explicit client settings and modem requests are
reapplied; BREAK is released. IPv6 discovery URLs use bracketed addresses and
an IPv6 loopback address for a wildcard IPv6 listener.

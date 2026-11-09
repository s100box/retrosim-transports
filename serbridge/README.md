# serbridge

<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Howard M. Harte -->

A persistent serial-console logger and RFC 2217 server. It holds a port or
transport open, logs output, accepts command-file input, and reconnects after
connection loss.

## Documentation

| Document | Contents |
|---|---|
| [Workspace README](../README.md) | Shared requirements, features, and library setup. |
| [Design](../doc/retrosim-transports-design.md#7-serbridge-architecture) | Architecture and platform validation limits. |
| [Operating guide](../doc/serbridge-guide.md) | Commands, reconnect policy, RFC 2217 sharing, and client helpers. |

<a id="sharing-the-port-rfc-2217"></a>
For shared serial access, see [Sharing the port](../doc/serbridge-guide.md#sharing-the-port-rfc-2217).

## Repository layout

| Path | Contents |
|---|---|
| `src/` | Console loop, transport adapter, and platform serial backend. |
| `clients/` | Canonical Python and PowerShell bridge-discovery helpers. |
| `tests/` | Process-level and optional serial integration tests. |

## Requirements

Use the [workspace toolchain and sibling layout](../README.md#requirements).
The native serial backend builds without libudev. Optional `ssh` support
requires the workspace's SSH native dependencies.

## Getting started

From the `retrosim-transports` repository root:

```bash
cargo build --locked --release -p serbridge
target/release/serbridge --list
target/release/serbridge --port COM3 --log console.log --cmd cmd.txt --listen 0
```

Replace `COM3` with a listed port. DTR and RTS are deasserted on open because
some boards connect them to reset; clients may explicitly change them.
`--listen 0` chooses a free loopback port. The server has no authentication;
use a trusted network if overriding the default loopback bind address.

<a id="testing"></a>
## Verification

From the `retrosim-transports` repository root:

```bash
cargo test --locked -p serbridge
```

Unit and process tests use a TCP backend without serial hardware. Optional
serial integration tests require a null-modem pair:

```bash
SERBRIDGE_COM0COM=COM90,COM91 cargo test --locked -p serbridge --test com0com
# Linux: create the pair in another terminal and leave socat running.
socat pty,raw,echo=0,link=/tmp/sbA pty,raw,echo=0,link=/tmp/sbB
SERBRIDGE_COM0COM=/tmp/sbA,/tmp/sbB cargo test --locked -p serbridge --test com0com
```

The environment assignments above use Bash syntax. Under PowerShell, set
`$env:SERBRIDGE_COM0COM` before invoking Cargo. PTYs skip modem-line and
framing checks. On Windows, the pair test repeats with qualified DOS and
extended-namespace paths to the same port. See the
[platform limits](../doc/serbridge-guide.md#platform-qualification).

## License

Dual-licensed under the workspace's [MIT](../LICENSE-MIT) or
[Apache-2.0](../LICENSE-APACHE) license, at your option.

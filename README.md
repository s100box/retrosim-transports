# retrosim-transports

<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 Howard M. Harte -->

Reusable TCP, Telnet, UDP, serial, RFC 2217, and SSH transports for retro
system simulators. The workspace also provides `uartssh`, a serial-to-SSH
terminal bridge, and `serbridge`, a persistent console logger and RFC 2217 server.

## Documentation

| Document | Contents |
|---|---|
| [Design](doc/retrosim-transports-design.md) | Transport contracts, features, authentication, bridge architecture, and validation limits. |
| [uartssh guide](doc/uartssh-guide.md) | Terminal setup, input injection, automation, and capture. |
| [serbridge](serbridge/README.md) | Console-bridge setup and test entry points. |
| [Documentation conventions](https://github.com/s100box/retrosim-build/blob/main/doc/documentation-style.md) | Shared release documentation format. |

Generate the API reference with `cargo doc --locked --workspace --all-features --no-deps --open`.

## Repository layout

| Path | Contents |
|---|---|
| `src/` | Transport library and unit tests. |
| `src/bin/uartssh/` | Serial-to-SSH bridge. |
| `serbridge/` | Console bridge, integration tests, and client helpers. |
| `doc/` | Design and operating guides. |
| `ci/`, `tests/` | Locked minimum-toolchain gate and local SSH protocol fixture. |
| `.githooks/` | Workspace format, lint, documentation, and test gate. |

## Requirements

Use stable Rust with `rustfmt` and `clippy`, plus a sibling checkout of
[retrosim-core](https://github.com/s100box/retrosim-core/blob/main/README.md):

```text
workspace/
  retrosim-core/
  retrosim-transports/
```

The `serial` feature is enabled by default and requires the platform's serial
development dependencies (including libudev on Linux). The `ssh` feature
builds libssh2 through `ssh2` and needs a native C toolchain; on Linux,
install OpenSSL development headers and pkg-config (`libssl-dev` and
`pkg-config` on Debian/Ubuntu). `bridge` enables
both for `uartssh`. Building `serbridge` alone avoids the library's `serial`
feature. See the [feature table](doc/retrosim-transports-design.md#2-features-and-dependencies).

The library, `uartssh`, and `serbridge` require Rust **1.85.1 or newer**.
Use the checked-in `Cargo.lock` with `--locked`; the minimum-toolchain gate
tests that dependency resolution, including the sibling `retrosim-core`.

## Getting started

From the repository root:

```bash
rustup component add rustfmt clippy
cargo build --locked --workspace --all-features
git config core.hooksPath .githooks
```

For a sibling consumer:

```toml
[dependencies]
retrosim-transports = { path = "../retrosim-transports" }
```

Use `open_transport("tcp:127.0.0.1:2023", false)` to connect to a TCP endpoint.
The [design](doc/retrosim-transports-design.md#3-transport-interface) defines
the full spec syntax. Follow the [uartssh guide](doc/uartssh-guide.md) or
[serbridge README](serbridge/README.md) for the command-line programs.

SSH connections require a verified key in the user's `.ssh/known_hosts` by
default. The [SSH policy and migration guide](doc/retrosim-transports-design.md#51-server-identity-policy)
describes explicit trust files and fingerprint pins. The RFC 2217 server has
no authentication and binds to loopback by default.

## Verification

From the repository root:

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo doc --locked --workspace --all-features --no-deps
cargo test --locked --workspace --all-features
cargo test --locked --no-default-features
```

The pre-commit hook runs formatting and the all-feature Clippy, Rustdoc, and
test gates, treating documentation warnings as errors. Successful gates exit
with status zero. The no-default-feature check verifies network-only consumers.

Install and test the exact minimum toolchain from the repository root:

```bash
rustup toolchain install 1.85.1 --profile minimal
sh ci/check-msrv.sh
```

CI is configured to run the minimum and stable feature matrices on Windows,
Linux, and macOS against the `retrosim-core` main branch. Physical USB
qualification is separate from CI.

The live SSH regression uses an ephemeral loopback server and synthetic
credentials. From the repository root, using Python 3.9 or newer in a test
virtual environment:

```bash
python -m pip install -r ci/requirements.txt
RETROSIM_SSH_TEST_PYTHON=python cargo test --locked --all-features --test ssh_host_key -- --ignored
```

The environment assignment uses Bash syntax. In PowerShell, set
`$env:RETROSIM_SSH_TEST_PYTHON='python'` before the Cargo command. This test is
explicitly ignored by ordinary `cargo test`; CI runs it separately and checks
that unknown or changed keys cause zero authentication requests.

For coverage, install `llvm-tools-preview` and `cargo-llvm-cov`, then run
`cargo llvm-cov --workspace --all-features --summary-only`. The
[design verification section](doc/retrosim-transports-design.md#8-verification-and-platform-limits)
describes hardware prerequisites and gaps. Coverage figures belong in generated reports.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at
your option.

### Contributions

Unless explicitly stated otherwise, contributions submitted for inclusion
are licensed under the same terms, without additional conditions.

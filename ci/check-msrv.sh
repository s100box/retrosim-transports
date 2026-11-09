#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Howard M. Harte
set -eu
cd "$(dirname "$0")/.."
msrv=$(sed -n 's/^rust-version = "\([^"]*\)"/\1/p' Cargo.toml)
[ -n "$msrv" ] || { echo "missing workspace rust-version" >&2; exit 1; }
echo "Checking locked workspace on Rust $msrv (including the retrosim-core dependency)"
cargo "+$msrv" test --locked --workspace --all-features
cargo "+$msrv" test --locked --no-default-features
# Test serbridge without feature unification from the workspace's root crate.
cargo "+$msrv" test --locked -p serbridge --no-default-features

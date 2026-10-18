#!/usr/bin/env bash
set -euo pipefail
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo build --release --features conformance
cargo package --allow-dirty

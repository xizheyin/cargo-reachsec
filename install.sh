#!/bin/sh
set -e

REPO="https://github.com/xizheyin/cargo-reachsec"
TMPDIR=$(mktemp -d)

echo "Cloning cargo-reachsec..."
git clone --recurse-submodules "$REPO" "$TMPDIR/cargo-reachsec"

echo "Installing reachsec..."
cargo install --path "$TMPDIR/cargo-reachsec" --bin reachsec

echo "Installing nightly toolchain..."
rustup toolchain install nightly-2025-08-09
rustup component add rustc-dev llvm-tools-preview --toolchain nightly-2025-08-09

echo "Installing call-cg4rs..."
cargo +nightly-2025-08-09 install --path "$TMPDIR/cargo-reachsec/callgraph4rs" --force

rm -rf "$TMPDIR"

echo ""
echo "Installation complete. Run 'reachsec check --path .' to get started."

# Contributing to reachsec

Thank you for your interest in contributing.

## Development Setup

1. Install Rust.
2. Initialize submodules: `git submodule update --init --recursive`.
3. Build the project: `cargo build`.
4. Install the call graph tools: `cargo install --path callgraph4rs --force`.

## Running Checks

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
```

If you change the call graph component itself, make the code change in the `callgraph4rs` submodule and commit the updated submodule pointer in this repository.

## Reporting Issues

Please include:

- Rust version
- Operating system
- Steps to reproduce
- Expected behavior
- Actual behavior

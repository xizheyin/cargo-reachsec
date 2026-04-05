# Check Workflow

This document explains how the `check` command prepares a local Rust project and how its dependency resolution relates to `cargo audit`.

## What `check` analyzes

`check` analyzes a local project directory.

Typical usage:

```bash
cargo run --bin reachsec -- check --path /path/to/project
```

If you want to adjust how many call chains are printed, use:

```bash
cargo run --bin reachsec -- check --path /path/to/project --max-call-chains 10
```

Or print all call chains:

```bash
cargo run --bin reachsec -- check --path /path/to/project --show-all-call-chains
```

The input should be a Rust project directory containing `Cargo.toml`.

## How dependency resolution works

The `check` flow is intentionally kept close to Cargo and `cargo audit`.

When you run `check`:

1. the local project is copied into a temporary analysis workspace
2. if `Cargo.lock` already exists, it is reused
3. if `Cargo.lock` does not exist, the tool runs `cargo generate-lockfile`
4. the advisory scan is performed on the resolved dependency graph
5. if advisory metadata includes affected functions, the tool runs reachability analysis

The tool does not rewrite dependency sources during `check`.

That means the result is based on the same dependency resolution model that Cargo uses for the local project.

## Relation to cargo-audit

`cargo audit` primarily answers:

- does the resolved dependency graph contain a package version affected by a RustSec advisory?

`reachsec check` starts from the same dependency graph question, then adds one more step:

- can local code actually reach the affected functions?

So the two tools overlap on version and dependency resolution, but `reachsec` also tries to recover function-level call paths.

## Why a library project may still need a lockfile

Library crates do not always commit `Cargo.lock` to version control.

However, to audit or analyze the actual resolved dependency graph, a lockfile is still needed.

If the local library project does not already have one, `check` will try to generate it before analysis.

## Example: v_frame

The README contains a minimal runnable example using `v_frame 0.3.2`.

That example works like this:

1. download `v_frame` to a local directory
2. run `check --path <local-dir>`
3. let the tool generate `Cargo.lock` if needed
4. inspect the advisory and reachability output

See [README.md](../README.md) for the quick-start commands.

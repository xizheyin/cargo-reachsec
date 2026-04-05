# reachsec

`reachsec` is a Rust vulnerability checker for local projects.

It combines two steps in a single `check` workflow:

- scan the resolved dependency graph for RustSec advisories
- try to recover call-path evidence to affected functions

This project uses `callgraph4rs` as a git submodule for MIR-level call graph analysis.
The submodule tracks the standalone repository at `https://github.com/xizheyin/callgraph4rs`.

## Quick Install

```bash
curl -sSf https://raw.githubusercontent.com/xizheyin/cargo-reachsec/main/install.sh | sh
```

This installs both `reachsec` and `call-cg4rs` (requires cargo and rustup).

## Build from Source

```bash
git clone --recurse-submodules https://github.com/xizheyin/cargo-reachsec
cd cargo-reachsec
cargo build --release
rustup toolchain install nightly
cargo install --path callgraph4rs --force
```

Note: the nightly toolchain is only required for `callgraph4rs`. `reachsec` itself builds with stable Rust.

If the repository is already cloned without submodules, run:

```bash
git submodule update --init --recursive
```

## Usage

Check a local Rust project:

```bash
reachsec check --path /path/to/project
```

Check the current directory:

```bash
reachsec check --path .
```

Show all call chains for each advisory:

```bash
reachsec check --path . --show-all-call-chains
```

Increase the per-advisory call-chain display limit:

```bash
reachsec check --path . --max-call-chains 10
```

Output results as JSON (useful for CI/CD integration):

```bash
reachsec check --path . --json
```

Use a custom working directory for temporary files:

```bash
reachsec check --path . --work-dir /tmp/my-workdir
```

Keep the temporary directory after analysis (useful for debugging):

```bash
reachsec check --path . --keep-work-dir
```

## Example

If you want a small end-to-end example, use `v_frame 0.3.2`.

This crate depends on `maligned 0.2.1`. RustSec records `RUSTSEC-2023-0017` for `maligned`.

```bash
repo_root=$(pwd)
tmpdir=$(mktemp -d /tmp/rreach-vframe-XXXXXX)
cd "$tmpdir"

curl -A "reachsec/0.1" -fL https://static.crates.io/crates/v_frame/v_frame-0.3.2.crate -o v_frame-0.3.2.crate
tar -xzf v_frame-0.3.2.crate

cd "$repo_root"
reachsec check --path "$tmpdir/v_frame-0.3.2"
```

Example output:

```text
Scanning dependencies in .../v_frame-0.3.2...

Found 1 advisories:

✗ VULNERABLE RUSTSEC-2023-0017
  Package: maligned 0.2.1
  Title: `maligned::align_first` causes incorrect deallocation
  Affected functions:
    - maligned::align_first
    - maligned::align_first_boxed
    - maligned::align_first_boxed_cloned
    - maligned::align_first_boxed_default
  Call chains:
    → frame::Frame::<T>::new_with_padding -> plane::Plane::<T>::new -> plane::PlaneData::<T>::new -> maligned::align_first_boxed_cloned::<T, maligned::A64>
```

More details about dependency resolution and local project preparation are in [CHECK_WORKFLOW.md](docs/CHECK_WORKFLOW.md).

## Output Levels

The `check` command reports three statuses:

- `✗ VULNERABLE`: a call path to an affected function was found
- `⚠ POTENTIALLY VULNERABLE`: affected functions are known, but no call path was found
- `⚠ ANALYSIS FAILED`: affected functions are known, but the analysis tool encountered errors
- `ℹ INFO`: no function-level information was available from the advisory data

These results are still analysis output, not a guarantee. Reachability depends on the quality of the advisory metadata and the call graph.

By default, `reachsec` shows up to 5 call chains per advisory. Use `--max-call-chains` or `--show-all-call-chains` when you want more detail.

## Repository Layout

- `src/`: main application code
- `callgraph4rs/`: git submodule for the call graph component
- `docs/`: project documentation for the `check` workflow

## Notes

- Run `git submodule update --init --recursive` if `callgraph4rs/` is missing
- Install the call graph tools with `cargo install --path callgraph4rs --force` if `call-cg4rs` is missing
- Reachability analysis can be slow on large projects
- Advisory metadata is incomplete for many RustSec entries, so some results remain best-effort

## Contributing

The current contribution guide is in [CONTRIBUTING.md](CONTRIBUTING.md).

## License

This repository is available under either [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.

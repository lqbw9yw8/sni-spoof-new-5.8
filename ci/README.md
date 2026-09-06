# ci/

The CI workflow lives here as a **plain file**, not under `.github/workflows/`.

In this environment the GitHub token cannot push to `.github/workflows/` (that
path requires a special permission), so the workflow is kept in `ci/` and the
operator installs it with their own account:

```bash
mkdir -p .github/workflows
cp ci/github-actions.yml .github/workflows/ci.yml
git add .github/workflows/ci.yml
git commit -m "ci: add workflow"
git push
```

## What it does

- matrix: `ubuntu-latest`, `macos-latest`, `windows-latest` on stable Rust
- `cargo fmt --all -- --check`
- `cargo build --all-targets`
- `cargo test --all-targets` (pure-logic modules on every OS; `engine.rs` is
  `cfg(windows)` and links on Windows)
- `cargo clippy --all-targets -- -D warnings`
- `RUSTFLAGS = -D warnings` so any rustc warning fails the build

The workflow caches `~/.cargo` and `target/` keyed on `Cargo.lock`.

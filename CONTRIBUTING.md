# Contributing to Vektor

Thank you for your interest in contributing to **Vektor**!

## Development Requirements

- **Rust**: `1.90+` (MSRV enforced in CI) with `rustfmt` and `clippy`
- **Git**: for AST SemVer diffing and staged secret scanning

## Local Verification Checklist

Before opening a pull request, run the same gates enforced in CI:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
cargo test --workspace --doc --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo run --locked --bin vektor -- audit --format json --fail-on low
```

## Coding Standards

- **`unsafe_code = "forbid"`**: all workspace crates are 100% safe Rust.
- **Strict Clippy lints**: `clippy::pedantic`, `unwrap_used = "deny"`, `dbg_macro = "deny"`, `todo = "deny"`, `panic = "deny"`.
- **Conventional Commits**: use `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`, `ci:`.
- **Hardened GitHub Actions**: any workflow change must pin actions to 40-char commit SHAs, declare top-level `permissions:` and `concurrency:`, and pass `vektor audit --fail-on low`.

## Security Reports

Please do **not** open public issues for security vulnerabilities. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

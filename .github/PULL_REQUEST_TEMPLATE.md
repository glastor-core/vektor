## Summary

<!-- Briefly describe what this PR changes and why. -->

## Type of Change

- [ ] Bug fix (`fix`)
- [ ] New feature (`feat`)
- [ ] Refactoring / performance (`refactor` / `perf`)
- [ ] Documentation (`docs`)
- [ ] CI / DevSecOps (`ci` / `chore`)

## Verification Checklist

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings`
- [ ] `cargo test --workspace --all-targets --locked`
- [ ] `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked`
- [ ] `cargo run --locked --bin vektor -- audit --format json --fail-on low`

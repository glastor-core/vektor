# Changelog

All notable changes to **Vektor** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-21

### Added
- **Cargo Workspace (100% safe Rust, `unsafe_code = "forbid"`)**: `vektor-core`, `vektor-analyzers`, `vektor-state`, and `vektor-cli`.
- **Modern MCP Stdio Engine**: strict JSON-RPC 2.0 server with protocol version negotiation (`2024-11-05`, `2025-03-26`, `2025-06-18`), `ToolAnnotations` (`readOnlyHint`, `idempotentHint`), 13 deterministic tools, and 2 MCP Resources (`vektor://workspace/summary`, `vektor://swarm/tasks`).
- **Sub-Millisecond Antigravity Lifecycle Hooks**: `PreToolUse` (fail-closed secret/Trojan/GHA/force-push/root-deletion safety gate), `PostToolUse` (incremental `tree-sitter-rust` AST re-indexer), and `Stop` (selective affected-crate `cargo check` gate configurable via `vektor.toml` or `VEKTOR_STOP_GATE`).
- **Declarative `vektor.toml` Configuration**: zero-dependency parser with `.gitignore` / `.vektorignore` support, `ignore_paths`, `disabled_rules`, `entropy_threshold`, and `stop_gate`.
- **DevSecOps Static Analyzers**:
  - 16 secret provider rules + Shannon entropy + `--staged` Git pre-commit scanning.
  - Trojan Guard (Unicode BiDi CVE-2021-42574, Unicode Tags, invisible characters, ANSI escapes).
  - GitHub Actions hardening linter (SHA-40 pinning, `permissions:`, `concurrency:`, `timeout-minutes:`, `persist-credentials: false`, `pull_request_target`, script/`$GITHUB_ENV` injection) + deterministic `--fix`.
  - Cargo workspace auditor, CycloneDX 1.5 SBOM, SARIF 2.1.0 exporter, AST SemVer public API differ, and 0–100 repo hygiene scorer.
- **Standalone CLI**: `audit`, `sbom`, `api-diff`, `deps`, `hygiene`, `doctor`, `init`, `bench`, `status`, `mcp`, `hook` with `pretty`, `markdown`, `json`, and `sarif` output formats.
- **Native Antigravity 7-Expert Plugin**: `rust-expert`, `crates-specialist`, `security-auditor`, `gh-actions-engineer`, `github-maintainer`, `astro-expert`, `markdown-docs-expert` integrated with Engram memory.
- **Hardened CI/CD & Release Automation**: multi-OS CI, MSRV `1.90`, `rustdoc`, `cargo-deny`, SARIF Code Scanning upload, 4-target cross-platform releases with SLSA provenance attestations, `cargo-binstall` metadata, and topological `crates.io` publishing.

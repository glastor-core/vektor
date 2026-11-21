# Vektor

**Vektor** is a high-speed Rust MCP server, sub-5ms Antigravity lifecycle hook engine, and 7-expert development team plugin designed to complement **Gemini (Antigravity)** with **Engram** as the shared persistent memory backbone.

## Architecture

- **Gemini (Antigravity)**: Tech Lead / Orchestrator (`invoke_subagent`, `/swarm`).
- **Engram**: Shared long-term persistent memory across all specialists.
- **`plugin/`**: Native Antigravity Plugin bundling:
  - `agents/`: 7 specialized subagents (`rust-expert`, `crates-specialist`, `security-auditor`, `gh-actions-engineer`, `github-maintainer`, `astro-expert`, `markdown-docs-expert`).
  - `skills/team-orchestration/SKILL.md`: Multi-expert orchestration playbook.
  - `rules/AGENTS.md`: Delegation matrix and Engram protocol.
  - `mcp_config.json` & `hooks.json`: Connects Antigravity to the `vektor` Rust binary.
- **`crates/vektor-core`**: Strict JSON-RPC 2.0 MCP stdio engine and Antigravity camelCase hook contracts.
- **`crates/vektor-analyzers`**: Pure-Rust deterministic engines (`cargo metadata` dependency/MSRV/license auditor, regex + Shannon entropy secret scanner, line-accurate GitHub Actions security linter, and `tree-sitter-rust` AST symbol/`unsafe` extractor).
- **`crates/vektor-state`**: SQLite WAL shared state (`.vektor/state.db`) for the Swarm Task Blackboard, advisory file locks, incremental AST symbol cache, and dirty-file tracking for `Stop` quality gates.
- **`crates/vektor-cli`**: Single `vektor` binary (`vektor mcp`, `vektor hook <event>`, `vektor status`).

## MCP Tools

- `vektor_health` — Server status and active modules.
- `vektor_workspace_info` — Cargo, Git, SQLite state, and GitHub Actions workspace inventory.
- `vektor_team_roster` — Specialist agent delegation matrix.
- `vektor_cargo_audit_deps` — Duplicate crate versions, MSRV conflicts, licenses/copyleft, default features.
- `vektor_scan_secrets` — Hardcoded API keys, tokens, private keys, and high-entropy credentials.
- `vektor_lint_gha` — GitHub Actions SHA pinning, permissions, `pull_request_target`, script injection, concurrency.
- `vektor_rust_ast_query` — Incremental `tree-sitter-rust` symbol & `unsafe` block index backed by SQLite WAL.
- `vektor_rust_api_diff` — AST SemVer / public API breaking-change differ against git revisions (`HEAD`).
- `vektor_sbom_cyclonedx` — CycloneDX 1.5 JSON SBOM generator from `cargo metadata`.
- `vektor_security_sarif` — Combined Secrets + Trojan Guard (Unicode BiDi) + GitHub Actions SARIF 2.1.0 exporter.
- `vektor_repo_hygiene` — DevSecOps repository hygiene auditor (0–100 score).
- `vektor_swarm_task` — Shared Swarm Task Blackboard (`list` / `upsert` with dependencies).
- `vektor_swarm_lock` — Advisory file locks (`list` / `acquire` / `release`) with TTL for parallel agents.

## Quick Start

```bash
cargo build --release
cargo test --workspace
vektor audit --format sarif > vektor.sarif
```

Install the binary on your `PATH` (`cargo install --path crates/vektor-cli`), then copy or symlink `plugin/` into `~/.gemini/config/plugins/vektor` (or `.agents/plugins/vektor` inside a project).

## Roadmap

- **Milestone 1 (Done)**: Cargo workspace, MCP stdio server + lifecycle hooks skeleton, Antigravity plugin with 5 experts integrated with Engram.
- **Milestone 2 (Done)**: `cargo metadata` / Crates analyzer, Security & GitHub Actions static linters, `PreToolUse` secret & workflow safety gates, and dedicated MCP tools.
- **Milestone 3 (Done)**: Incremental `tree-sitter-rust` AST code graph, SQLite WAL swarm blackboard/locks, `PostToolUse` incremental re-indexer, and configurable `Stop` quality gate (`VEKTOR_STOP_GATE=off` to disable).
- **Milestone 4 (Done)**: Trojan Guard (Unicode BiDi/invisible chars), SARIF 2.1.0 + CycloneDX 1.5 SBOM, AST SemVer API differ, selective `vortex`-style `Stop` gate, `nemesis`-style repo hygiene auditor, and hardened `.github/workflows/ci.yml` dogfooding.

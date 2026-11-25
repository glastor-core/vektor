# Vektor Architecture & Threat Model

## 1. Design Principles

1. **100% Safe Rust (`unsafe_code = "forbid"`)**: zero `unsafe` blocks across all 4 workspace crates.
2. **Deterministic Sub-Millisecond Hooks**: `PreToolUse` safety gates run in ~26 µs p50 (no network calls, bounded I/O, compiled `OnceLock` regexes).
3. **Fail-Closed Safety**: malformed or oversized (`>16 MiB`) `PreToolUse` hook payloads default to `deny`, never silent pass-through.
4. **Single Binary, Dual Surface**: the same `vektor` executable powers both Antigravity (`vektor mcp`, `vektor hook <event>`) and standalone CI/terminal workflows (`vektor audit`, `pii`, `web-ast`, `sbom`, `api-diff`, `deps`, `hygiene`, `doctor`, `init`, `bench`).

---

## 2. Crate & Module Map

| Crate | Modules | Responsibility |
| :--- | :--- | :--- |
| `vektor-core` | `mcp`, `hooks` | Strict JSON-RPC 2.0 MCP stdio engine (version negotiation `2024-11-05`..`2025-06-18`, `ToolAnnotations`, Resources) and camelCase hook contracts. |
| `vektor-analyzers` | `config`, `secrets`, `pii`, `trojan`, `gha`, `rust_ast`, `web_ast`, `reward_guard`, `taint`, `cargo`, `sarif`, `hygiene` | Pure-Rust static analyzers (`tree-sitter-rust`, `tree-sitter-typescript`, Anti-Reward-Hacking AST gate, SHA-256 session taint fingerprinting, CycloneDX 1.5 SBOM, SARIF 2.1.0, `vektor.toml` + `.gitignore`). |
| `vektor-state` | `lib`, `schema`, `tasks`, `locks`, `ast_cache`, `taint` | SQLite WAL shared state (`.vektor/state.db`) with `BEGIN IMMEDIATE` transactions for lock serialization, incremental AST caching, and TTL-scoped session taint fingerprints. |
| `vektor-cli` | `main`, `cli_commands`, `hook_runner`, `hook_shell`, `mcp_server`, `mcp_resources` | Binary entrypoint, CLI formatters (`pretty`, `markdown`, `json`, `sarif`), hook orchestration, and 15-tool MCP registry. |

---

## 3. Threat Model & Mitigations

| Threat | Mitigation |
| :--- | :--- |
| **Memory exhaustion / FIFO hang** | All file reads use `symlink_metadata` + single `File::take(MAX_SCAN_FILE_BYTES + 1)` (`1 MiB`); MCP/hook frames capped at `16 MiB`. |
| **Split-secret / mid-file BOM bypass on `edit_file`** | `PreToolUse` simulates applying `Target -> Replacement` against the bounded existing file before scanning. |
| **Trojan Source (CVE-2021-42574) & prompt smuggling** | `trojan.rs` blocks BiDi overrides (`U+202A..U+202E`, `U+2066..U+2069`), Unicode Tags (`U+E0000..U+E007F`), ANSI escapes, and zero-width characters. |
| **Git argument injection in `api-diff`** | Validates base refs (rejects leading `-`, NUL, control chars) and invokes `git rev-parse --end-of-options`. |
| **SQLite WAL lock race conditions** | `StateStore::acquire_lock` uses `TransactionBehavior::Immediate` with canonicalized paths (`./src//lib.rs` == `src/lib.rs`) and TTL expiration. |
| **Supply-chain & CI tampering** | All GitHub Actions pinned to 40-char commit SHAs, least-privilege `permissions: { contents: read }`, `cargo-deny` (`deny.toml`), `GLASTOR Byte-Gauge`, `GLASTOR Specter`, and SLSA build provenance. |
| **Agent reward hacking (test/policy weakening)** | `reward_guard.rs` compares before/after ASTs (`tree-sitter-rust`, `tree-sitter-typescript`) and security config files (`vektor.toml`, `Cargo.toml`, `deny.toml`) in `PreToolUse` to block `allow(unsafe_code)` / guardrail disabling and require confirmation on removed tests/assertions or lint suppressions. |
| **Multi-step cross-tool secret exfiltration** | `taint.rs` + `vektor-state::taint` record irreversible SHA-256 fingerprints (raw, Base64, Hex, URL-encoded) in `PostToolUse` (never plaintext) and block encoded exfiltration or outbound network commands in `PreToolUse`. |

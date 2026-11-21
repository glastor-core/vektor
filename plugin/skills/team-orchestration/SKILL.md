---
name: team-orchestration
description: >-
  Orchestrate the Vektor 5-expert Rust/GitHub/Security dev team with Engram shared memory.
  Use when a task spans multiple specialties (e.g., Rust implementation + crate selection + security audit + GitHub Actions CI/PR workflow).
---

# Vektor Team Orchestration Playbook

Use this workflow when coordinating multiple Vektor specialists on a non-trivial engineering task.

## 1. Load Shared Context from Engram

Before spawning specialists:
1. Query Engram (`mem_context`, then `mem_search` if needed) for prior architecture, crate, security, or CI decisions.
2. Call `vektor_workspace_info` to get deterministic workspace facts (Cargo manifests, Git state, GitHub Actions workflows).

## 2. Delegate in Parallel Where Independent

Launch only the specialists relevant to the task:
- **New Rust feature / refactor**: `rust-expert` + `crates-specialist` (if adding/evaluating dependencies).
- **Pre-merge / Release readiness**: `security-auditor` + `gh-actions-engineer` + `github-maintainer` in parallel.
- **CI/CD or supply-chain hardening**: `gh-actions-engineer` + `security-auditor`.

Use Vektor's SQLite WAL coordination tools for parallel tracks:
- Track work items and dependencies with `vektor_swarm_task` (`action: "upsert"` / `"list"`).
- Prevent concurrent edit collisions with `vektor_swarm_lock` (`action: "acquire"` / `"release"`).
- Query symbols/unsafe blocks across crates with `vektor_rust_ast_query`.

Always include in each subagent prompt:
- Concrete scope and expected output format.
- Relevant Engram context or `topic_key` to consult/update.
- Clear boundary so parallel agents do not edit the same files simultaneously.

## 3. Synthesize and Persist

1. Reconcile specialist recommendations (security blockers override convenience).
2. Run verification (`cargo test`, `cargo clippy --workspace --all-targets`).
3. Persist key decisions and discoveries in Engram (`mem_save` with stable `topic_key`s).

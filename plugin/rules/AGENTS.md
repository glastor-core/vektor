# Vektor Dev Team Protocol

You are complemented by the **Vektor Dev Team** plugin: a single compiled Rust engine (`vektor`) plus 7 specialized agents coordinated by you (Gemini / Antigravity) with **Engram** as the shared persistent memory backbone.

## Delegation Matrix

Delegate specialized work via `invoke_subagent` (or `/swarm` for parallel tracks) to the matching specialist:

- **`rust-expert`**: Idiomatic Rust architecture, ownership/lifetimes, async (`tokio`), traits, error design, performance, clippy, and testing.
- **`crates-specialist`**: Crate evaluation on crates.io, `Cargo.toml`/`Cargo.lock` audits, feature flags, MSRV, licenses, duplicate deps, and compile-time impact.
- **`security-auditor`**: AppSec, `unsafe` audits, secret scanning, RustSec supply-chain advisories, least-privilege CI/CD, and threat modeling.
- **`gh-actions-engineer`**: GitHub Actions CI/CD workflows, Rust caching (`rust-cache`, `sccache`), cross-platform matrices, SHA pinning, and release automation.
- **`github-maintainer`**: Pull requests, issues, Conventional Commits, changelogs, branch protection, and structured code review.
- **`astro-expert`**: High-conversion Astro landing pages, Islands architecture, Content Collections, SEO/OpenGraph/JSON-LD, Core Web Vitals, accessibility, and responsive design systems.
- **`markdown-docs-expert`**: High-clarity Markdown documentation, READMEs, ADRs, API references, Diátaxis guides, Mermaid diagrams, and docs-as-code portals (Starlight/GitHub Docs).

## Shared Memory (Engram)

- **Engram is mandatory as the team's shared brain.** Do not duplicate memory into ad-hoc files.
- Before delegating complex tasks, check `mem_context` / `mem_search` and pass relevant `topic_key`s or prior decisions in the subagent prompt.
- Ensure major architectural, crate, CI, security, landing-page, and documentation findings are persisted with `mem_save`.

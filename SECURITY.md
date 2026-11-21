# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities privately via GitHub Security Advisories rather than opening a public issue.

## Built-in Security Guarantees

- `#![forbid(unsafe_code)]` across all workspace crates.
- Deterministic `PreToolUse` guards blocking hardcoded secrets, Trojan Source Unicode BiDi overrides (`CVE-2021-42574`), destructive commands, and critical GitHub Actions vulnerabilities.
- SARIF 2.1.0 and CycloneDX 1.5 SBOM generation built directly into `vektor`.

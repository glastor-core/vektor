//! `DevSecOps` repository hygiene auditor (inspired by `glastor-core/nemesis`).

use std::path::Path;

use anyhow::Result;
use serde::Serialize;

use crate::{gha, Severity};

/// Individual repository hygiene check result.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HygieneCheck {
    pub id: String,
    pub passed: bool,
    pub severity: Severity,
    pub message: String,
    pub remediation: String,
}

/// Overall repository hygiene audit report.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RepoHygieneReport {
    pub score: u8,
    pub passed_count: usize,
    pub total_checks: usize,
    pub checks: Vec<HygieneCheck>,
}

fn make_check(
    id: &str,
    passed: bool,
    severity: Severity,
    ok_msg: &str,
    fail_msg: &str,
    remediation: &str,
) -> HygieneCheck {
    HygieneCheck {
        id: id.to_string(),
        passed,
        severity,
        message: if passed { ok_msg } else { fail_msg }.to_string(),
        remediation: remediation.to_string(),
    }
}

/// Audit a Rust/GitHub workspace for `DevSecOps` and repository hygiene best practices.
pub fn audit_repo_hygiene(root: &Path) -> Result<RepoHygieneReport> {
    let has_license = ["LICENSE", "LICENSE-MIT", "LICENSE-APACHE", "LICENSE.md"]
        .iter()
        .any(|f| root.join(f).is_file());
    let has_security =
        root.join("SECURITY.md").is_file() || root.join(".github").join("SECURITY.md").is_file();
    let gitignore_ok = std::fs::read_to_string(root.join(".gitignore")).is_ok_and(|s| {
        s.lines()
            .any(|l| matches!(l.trim(), "/target" | "target" | "target/"))
    });
    let cargo_toml = std::fs::read_to_string(root.join("Cargo.toml")).unwrap_or_default();

    let mut checks = vec![
        make_check(
            "HYG-README",
            root.join("README.md").is_file(),
            Severity::Low,
            "README.md present",
            "Missing README.md at repository root",
            "Add a concise README.md documenting architecture and quick start.",
        ),
        make_check(
            "HYG-LICENSE",
            has_license,
            Severity::Medium,
            "LICENSE file present",
            "Missing LICENSE file at repository root",
            "Add a LICENSE file matching `license` in Cargo.toml.",
        ),
        make_check(
            "HYG-SECURITY-POLICY",
            has_security,
            Severity::Medium,
            "SECURITY.md vulnerability disclosure policy present",
            "Missing SECURITY.md policy",
            "Add SECURITY.md describing how to report vulnerabilities privately.",
        ),
        make_check(
            "HYG-GITIGNORE-RUST",
            gitignore_ok,
            Severity::Medium,
            ".gitignore excludes Rust target/ build artifacts",
            ".gitignore is missing or does not ignore `target/`",
            "Add `/target` to `.gitignore`.",
        ),
        make_check(
            "HYG-CARGO-MSRV",
            cargo_toml.contains("rust-version"),
            Severity::Low,
            "Cargo.toml declares `rust-version` (MSRV)",
            "Cargo.toml does not declare `rust-version` (MSRV)",
            "Declare `rust-version` under `[workspace.package]` or `[package]`.",
        ),
        make_check(
            "HYG-CARGO-UNSAFE-POLICY",
            cargo_toml.contains("unsafe_code"),
            Severity::Medium,
            "Cargo.toml declares explicit `unsafe_code` lint policy",
            "Cargo.toml has no explicit `unsafe_code` lint policy",
            "Add `unsafe_code = \"forbid\"` (or `\"deny\"`) under `[workspace.lints.rust]`.",
        ),
    ];

    checks.push(check_github_actions_hygiene(root)?);

    let passed_count = checks.iter().filter(|c| c.passed).count();
    let total_checks = checks.len();
    #[allow(clippy::cast_possible_truncation)]
    let score = (passed_count * 100)
        .checked_div(total_checks)
        .map_or(100, |v| v as u8);

    Ok(RepoHygieneReport {
        score,
        passed_count,
        total_checks,
        checks,
    })
}

fn check_github_actions_hygiene(root: &Path) -> Result<HygieneCheck> {
    let gha_findings = gha::lint_workspace_or_file(root)?;
    let workflows_dir = root.join(".github").join("workflows");
    let has_workflows = std::fs::read_dir(&workflows_dir).is_ok_and(|mut it| it.next().is_some());
    let severe_gha = gha_findings
        .iter()
        .filter(|f| f.severity >= Severity::High)
        .count();
    let ci_ok = has_workflows && severe_gha == 0;
    let message = if !has_workflows {
        "No GitHub Actions workflows found under .github/workflows/".to_string()
    } else if severe_gha > 0 {
        format!("GitHub Actions workflows have {severe_gha} HIGH/CRITICAL security finding(s)")
    } else {
        "GitHub Actions workflows present and pass HIGH/CRITICAL hardening checks".to_string()
    };

    Ok(HygieneCheck {
        id: "HYG-GHA-HARDENED".to_string(),
        passed: ci_ok,
        severity: Severity::High,
        message,
        remediation: "Add hardened `.github/workflows/ci.yml` with SHA-pinned actions and least-privilege permissions."
            .to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn computes_hygiene_score_on_temp_dir() {
        let dir = std::env::temp_dir().join(format!("vektor-hygiene-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(dir.join("README.md"), "# Test").expect("readme");
        std::fs::write(dir.join(".gitignore"), "/target\n").expect("gitignore");

        let report = audit_repo_hygiene(&dir).expect("audit");
        assert_eq!(report.passed_count, 2);
        assert!(report.score < 100);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

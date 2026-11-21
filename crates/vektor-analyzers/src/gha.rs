//! Line-accurate static security & CI best-practices linter for GitHub Actions workflows.

use std::path::Path;
use std::sync::OnceLock;

use anyhow::Result;
use regex::Regex;
use serde::Serialize;

use crate::Severity;

/// A single GitHub Actions workflow finding.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GhaFinding {
    pub rule_id: String,
    pub severity: Severity,
    pub file: String,
    pub line: usize,
    pub message: String,
    pub remediation: String,
}

fn uses_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"^\s*-?\s*uses\s*:\s*["']?([^"'\s#]+)["']?"#).expect("valid regex")
    })
}

fn untrusted_expr_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\$\{\{\s*github\.event\.(?:issue\.title|issue\.body|pull_request\.title|pull_request\.body|pull_request\.head\.ref|comment\.body|review\.body|head_commit\.message)\b",
        )
        .expect("valid regex")
    })
}

fn sha40_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[0-9a-fA-F]{40}$").expect("valid regex"))
}

/// Lint a GitHub Actions workflow YAML string with exact line numbers.
#[must_use]
pub fn lint_workflow_content(file_label: &str, content: &str) -> Vec<GhaFinding> {
    let mut findings = Vec::new();
    let uses_re = uses_regex();
    let untrusted_re = untrusted_expr_regex();
    let sha_re = sha40_regex();

    let mut has_top_level_permissions = false;
    let mut has_concurrency_block = false;
    let mut uses_pr_target = false;
    let mut run_block_indent: Option<usize> = None;

    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = raw_line.trim();
        let indent = raw_line.len() - raw_line.trim_start().len();

        if trimmed.is_empty() {
            continue;
        }

        // Exit a multiline `run: |` / `run: >` block once indentation returns to or left of `run:`.
        if let Some(base_indent) = run_block_indent {
            if indent <= base_indent {
                run_block_indent = None;
            }
        }

        let in_run_block = run_block_indent.is_some();

        if trimmed.starts_with('#') && !in_run_block {
            continue;
        }

        // Only top-level `permissions:` satisfies workflow-wide least-privilege declaration.
        if indent == 0 && trimmed.starts_with("permissions:") {
            has_top_level_permissions = true;
        }

        if trimmed.starts_with("permissions:") && trimmed.contains("write-all") {
            findings.push(make_finding(
                "GHA-PERMS-WRITE-ALL",
                Severity::High,
                file_label,
                line_no,
                "Workflow grants overly broad `permissions: write-all`",
                "Set explicit least-privilege permissions (e.g., `contents: read`).",
            ));
        }

        if indent == 0 && trimmed.starts_with("concurrency:") {
            has_concurrency_block = true;
        }

        if trimmed.contains("pull_request_target") {
            uses_pr_target = true;
            findings.push(make_finding(
                "GHA-PR-TARGET",
                Severity::High,
                file_label,
                line_no,
                "`pull_request_target` runs with base repo secrets and write permissions",
                "Prefer `pull_request` unless strictly needed, and never checkout untrusted PR head code.",
            ));
        }

        if uses_pr_target && trimmed.contains("github.event.pull_request.head") {
            findings.push(make_finding(
                "GHA-PR-TARGET-CHECKOUT",
                Severity::Critical,
                file_label,
                line_no,
                "Untrusted PR head referenced in a `pull_request_target` workflow (pwn-request risk)",
                "Do not check out or execute code from `github.event.pull_request.head` under `pull_request_target`.",
            ));
        }

        let stripped_item = trimmed.strip_prefix('-').map_or(trimmed, str::trim_start);
        let is_run_line = stripped_item.starts_with("run:");
        if is_run_line {
            let after_colon = stripped_item.strip_prefix("run:").unwrap_or("").trim();
            if after_colon.starts_with('|') || after_colon.starts_with('>') {
                run_block_indent = Some(indent);
            }
        }

        // Only flag script injection inside `run:` commands (single-line or multiline block),
        // not safe `env:` variable assignments.
        if (is_run_line || in_run_block) && untrusted_re.is_match(trimmed) {
            findings.push(make_finding(
                "GHA-SCRIPT-INJECTION",
                Severity::Critical,
                file_label,
                line_no,
                "Untrusted GitHub event expression interpolated directly in `run:` script",
                "Pass the expression through an intermediate `env:` variable instead of interpolating `${{ ... }}` in `run:`.",
            ));
        }

        if !in_run_block {
            if let Some(finding) =
                check_uses_pinning(file_label, line_no, raw_line, uses_re, sha_re)
            {
                findings.push(finding);
            }
        }
    }

    push_missing_workflow_blocks(
        file_label,
        has_top_level_permissions,
        has_concurrency_block,
        &mut findings,
    );

    findings
}

fn make_finding(
    rule_id: &str,
    severity: Severity,
    file: &str,
    line: usize,
    message: &str,
    remediation: &str,
) -> GhaFinding {
    GhaFinding {
        rule_id: rule_id.to_string(),
        severity,
        file: file.to_string(),
        line,
        message: message.to_string(),
        remediation: remediation.to_string(),
    }
}

fn push_missing_workflow_blocks(
    file_label: &str,
    has_top_level_permissions: bool,
    has_concurrency_block: bool,
    findings: &mut Vec<GhaFinding>,
) {
    if !has_top_level_permissions {
        findings.push(GhaFinding {
            rule_id: "GHA-MISSING-PERMISSIONS".to_string(),
            severity: Severity::Medium,
            file: file_label.to_string(),
            line: 1,
            message: "Workflow does not declare an explicit top-level `permissions:` block"
                .to_string(),
            remediation: "Add `permissions: { contents: read }` at the workflow root.".to_string(),
        });
    }

    if !has_concurrency_block {
        findings.push(GhaFinding {
            rule_id: "GHA-MISSING-CONCURRENCY".to_string(),
            severity: Severity::Low,
            file: file_label.to_string(),
            line: 1,
            message: "Workflow has no `concurrency:` group to cancel superseded runs".to_string(),
            remediation: "Add `concurrency: { group: ${{ github.workflow }}-${{ github.ref }}, cancel-in-progress: true }`."
                .to_string(),
        });
    }
}

fn check_uses_pinning(
    file_label: &str,
    line_no: usize,
    raw_line: &str,
    uses_re: &Regex,
    sha_re: &Regex,
) -> Option<GhaFinding> {
    let action_ref = uses_re.captures(raw_line)?.get(1)?.as_str();
    if action_ref.starts_with("./") || action_ref.starts_with("docker://") {
        return None;
    }
    let pinned = action_ref
        .split_once('@')
        .is_some_and(|(_, rev)| sha_re.is_match(rev));
    if pinned {
        return None;
    }
    Some(GhaFinding {
        rule_id: "GHA-UNPINNED-ACTION".to_string(),
        severity: Severity::High,
        file: file_label.to_string(),
        line: line_no,
        message: format!(
            "Third-party action `{action_ref}` is not pinned to a full 40-char commit SHA"
        ),
        remediation: "Pin to the full commit SHA with a version comment (e.g., `actions/checkout@<40-char-sha> # v4`)."
            .to_string(),
    })
}

/// Lint all `.yml`/`.yaml` files under `<workspace>/.github/workflows` or a single workflow file.
pub fn lint_workspace_or_file(path: &Path) -> Result<Vec<GhaFinding>> {
    if path.is_file() {
        let content = std::fs::read_to_string(path)?;
        return Ok(lint_workflow_content(&path.display().to_string(), &content));
    }

    let workflows_dir = path.join(".github").join("workflows");
    if !workflows_dir.is_dir() {
        return Ok(Vec::new());
    }

    let mut findings = Vec::new();
    for entry in std::fs::read_dir(&workflows_dir)? {
        let entry = entry?;
        let file_path = entry.path();
        if !file_path.is_file() {
            continue;
        }
        let is_yaml = file_path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("yml") || ext.eq_ignore_ascii_case("yaml"));
        if !is_yaml {
            continue;
        }
        let content = std::fs::read_to_string(&file_path)?;
        let label = file_path
            .strip_prefix(path)
            .unwrap_or(&file_path)
            .display()
            .to_string();
        findings.extend(lint_workflow_content(&label, &content));
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_unpinned_write_all_and_injection() {
        let yaml = r#"
name: CI
on: [pull_request_target]
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: echo "${{ github.event.pull_request.title }}"
"#;

        let findings = lint_workflow_content(".github/workflows/ci.yml", yaml);
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(ids.contains(&"GHA-PERMS-WRITE-ALL"));
        assert!(ids.contains(&"GHA-PR-TARGET"));
        assert!(ids.contains(&"GHA-PR-TARGET-CHECKOUT"));
        assert!(ids.contains(&"GHA-SCRIPT-INJECTION"));
        assert!(ids.contains(&"GHA-UNPINNED-ACTION"));
    }

    #[test]
    fn passes_clean_hardened_workflow() {
        let yaml = r"
name: CI
on: [push, pull_request]
permissions:
  contents: read
concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - run: cargo test --workspace
";

        let findings = lint_workflow_content(".github/workflows/ci.yml", yaml);
        assert!(
            findings.is_empty(),
            "expected clean workflow, got: {findings:?}"
        );
    }

    #[test]
    fn allows_safe_env_assignment_and_flags_multiline_run_injection_and_job_perms() {
        let safe_yaml = r#"
name: Safe
on: [issues]
permissions:
  contents: read
concurrency:
  group: safe-${{ github.ref }}
  cancel-in-progress: true
jobs:
  echo:
    runs-on: ubuntu-latest
    steps:
      - name: Print title safely
        env:
          ISSUE_TITLE: ${{ github.event.issue.title }}
        run: echo "$ISSUE_TITLE"
"#;
        let safe_findings = lint_workflow_content(".github/workflows/safe.yml", safe_yaml);
        assert!(
            safe_findings.is_empty(),
            "safe env assignment should not trigger findings: {safe_findings:?}"
        );

        let unsafe_yaml = r#"
name: Unsafe
on: [issues]
concurrency:
  group: u-${{ github.ref }}
  cancel-in-progress: true
jobs:
  echo:
    permissions:
      contents: read
    runs-on: ubuntu-latest
    steps:
      - name: Multiline injection
        run: |
          echo "starting"
          echo "${{ github.event.issue.title }}"
"#;
        let unsafe_findings = lint_workflow_content(".github/workflows/unsafe.yml", unsafe_yaml);
        let ids: Vec<&str> = unsafe_findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(ids.contains(&"GHA-SCRIPT-INJECTION"));
        assert!(ids.contains(&"GHA-MISSING-PERMISSIONS"));
    }
}

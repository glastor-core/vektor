//! Line-accurate static security & CI best-practices linter for GitHub Actions workflows.

use std::path::Path;
use std::sync::OnceLock;

use anyhow::Result;
use regex::Regex;
use serde::Serialize;

use crate::config::VektorConfig;
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

/// Summary of deterministic auto-remediation applied to a workflow file.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GhaFixResult {
    pub file: String,
    pub applied_fixes: Vec<String>,
}

#[allow(clippy::expect_used)]
fn uses_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"^\s*-?\s*uses\s*:\s*["']?([^"'\s#]+)["']?"#).expect("valid regex")
    })
}

#[allow(clippy::expect_used)]
fn untrusted_expr_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\$\{\{\s*(?:github\.head_ref\b|github\.event\.(?:issue\.title|issue\.body|pull_request\.title|pull_request\.body|pull_request\.head\.(?:ref|label|repo\.default_branch)|comment\.body|review\.body|head_commit\.message|discussion\.(?:title|body)|workflow_run\.head_branch)\b)",
        )
        .expect("valid regex")
    })
}

#[allow(clippy::expect_used)]
fn sha40_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[0-9a-fA-F]{40}$").expect("valid regex"))
}

#[allow(clippy::expect_used)]
fn sha256_digest_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"@sha256:[0-9a-fA-F]{64}$").expect("valid regex"))
}

/// Lint a GitHub Actions workflow YAML string with exact line numbers.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn lint_workflow_content(file_label: &str, content: &str) -> Vec<GhaFinding> {
    let mut findings = Vec::new();
    let uses_re = uses_regex();
    let untrusted_re = untrusted_expr_regex();
    let sha_re = sha40_regex();

    let mut has_top_level_permissions = false;
    let mut has_concurrency_block = false;
    let mut uses_pr_target = false;
    let mut run_block_indent: Option<usize> = None;

    // Job-level `timeout-minutes` tracker.
    let mut in_jobs_block = false;
    let mut current_job: Option<(usize, String, bool, bool)> = None; // (line, name, has_timeout, is_reusable)

    // Step-level `actions/checkout` `persist-credentials: false` tracker.
    let mut checkout_step: Option<(usize, usize, bool)> = None; // (line, step_indent, has_persist_false)

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

        // Flush pending `actions/checkout` step check if we left that step.
        if !in_run_block {
            if let Some((co_line, co_indent, has_persist_false)) = checkout_step {
                let starts_new_item =
                    indent <= co_indent && (trimmed.starts_with('-') || indent < co_indent);
                if starts_new_item {
                    if !has_persist_false {
                        findings.push(make_finding(
                            "GHA-PERSIST-CREDENTIALS",
                            Severity::Medium,
                            file_label,
                            co_line,
                            "`actions/checkout` does not disable `persist-credentials: false`",
                            "Add `with: { persist-credentials: false }` to `actions/checkout` to prevent token leakage into `.git/config`.",
                        ));
                    }
                    checkout_step = None;
                } else if trimmed.starts_with("persist-credentials:") && trimmed.contains("false") {
                    checkout_step = Some((co_line, co_indent, true));
                }
            }
        }

        // Track top-level `jobs:` and per-job `timeout-minutes:`.
        if !in_run_block {
            if indent == 0 {
                if in_jobs_block {
                    flush_job_timeout(file_label, current_job.take(), &mut findings);
                }
                in_jobs_block = trimmed == "jobs:" || trimmed.starts_with("jobs:");
            } else if in_jobs_block
                && indent == 2
                && trimmed.ends_with(':')
                && !trimmed.starts_with('-')
            {
                flush_job_timeout(file_label, current_job.take(), &mut findings);
                let job_name = trimmed.trim_end_matches(':').to_string();
                current_job = Some((line_no, job_name, false, false));
            } else if in_jobs_block && indent == 4 {
                if let Some((_, _, ref mut has_timeout, ref mut is_reusable)) = current_job {
                    if trimmed.starts_with("timeout-minutes:") {
                        *has_timeout = true;
                    } else if trimmed.starts_with("uses:") {
                        *is_reusable = true;
                    }
                }
            }
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

        if uses_pr_target
            && (trimmed.contains("github.event.pull_request.head")
                || trimmed.contains("refs/pull/"))
        {
            findings.push(make_finding(
                "GHA-PR-TARGET-CHECKOUT",
                Severity::Critical,
                file_label,
                line_no,
                "Untrusted PR head referenced in a `pull_request_target` workflow (pwn-request risk)",
                "Do not check out or execute code from `github.event.pull_request.head` or `refs/pull/` under `pull_request_target`.",
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
            if trimmed.contains("GITHUB_ENV") || trimmed.contains("GITHUB_PATH") {
                findings.push(make_finding(
                    "GHA-GITHUB-ENV-INJECTION",
                    Severity::Critical,
                    file_label,
                    line_no,
                    "Untrusted GitHub event expression written to `$GITHUB_ENV` or `$GITHUB_PATH`",
                    "Sanitize and validate untrusted inputs via an `env:` variable before writing to `$GITHUB_ENV` or `$GITHUB_PATH`.",
                ));
            } else {
                findings.push(make_finding(
                    "GHA-SCRIPT-INJECTION",
                    Severity::Critical,
                    file_label,
                    line_no,
                    "Untrusted GitHub event expression interpolated directly in `run:` script",
                    "Pass the expression through an intermediate `env:` variable instead of interpolating `${{ ... }}` in `run:`.",
                ));
            }
        }

        if !in_run_block {
            if let Some(caps) = uses_re.captures(raw_line) {
                if let Some(action_ref) = caps.get(1).map(|m| m.as_str()) {
                    if action_ref.starts_with("actions/checkout@") {
                        let step_indent = if trimmed.starts_with('-') {
                            indent
                        } else {
                            indent.saturating_sub(2)
                        };
                        checkout_step = Some((line_no, step_indent, false));
                    }
                }
            }
            if let Some(finding) =
                check_uses_pinning(file_label, line_no, raw_line, uses_re, sha_re)
            {
                findings.push(finding);
            }
        }
    }

    if let Some((co_line, _, false)) = checkout_step {
        findings.push(make_finding(
            "GHA-PERSIST-CREDENTIALS",
            Severity::Medium,
            file_label,
            co_line,
            "`actions/checkout` does not disable `persist-credentials: false`",
            "Add `with: { persist-credentials: false }` to `actions/checkout` to prevent token leakage into `.git/config`.",
        ));
    }
    flush_job_timeout(file_label, current_job, &mut findings);

    push_missing_workflow_blocks(
        file_label,
        has_top_level_permissions,
        has_concurrency_block,
        &mut findings,
    );

    findings
}

fn flush_job_timeout(
    file_label: &str,
    job: Option<(usize, String, bool, bool)>,
    findings: &mut Vec<GhaFinding>,
) {
    if let Some((line, name, has_timeout, is_reusable)) = job {
        if !has_timeout && !is_reusable {
            findings.push(make_finding(
                "GHA-MISSING-TIMEOUT",
                Severity::Low,
                file_label,
                line,
                &format!("Job `{name}` does not declare `timeout-minutes:`"),
                "Add `timeout-minutes: 20` (or appropriate bound) to prevent runaway jobs from burning runner minutes.",
            ));
        }
    }
}

/// Deterministically auto-fix missing top-level `permissions:` and `concurrency:` blocks
/// in a GitHub Actions workflow YAML string. Returns `(updated_content, applied_fixes)`.
#[must_use]
pub fn fix_workflow_content(content: &str) -> (String, Vec<String>) {
    let has_top_perms = content.lines().any(|l| {
        !l.starts_with(' ') && !l.starts_with('\t') && l.trim_start().starts_with("permissions:")
    });
    let has_top_concurrency = content.lines().any(|l| {
        !l.starts_with(' ') && !l.starts_with('\t') && l.trim_start().starts_with("concurrency:")
    });

    if has_top_perms && has_top_concurrency {
        return (content.to_string(), Vec::new());
    }

    let mut applied = Vec::new();
    let mut injection = String::new();
    if !has_top_perms {
        injection.push_str("permissions:\n  contents: read\n\n");
        applied.push("Added top-level `permissions: { contents: read }`".to_string());
    }
    if !has_top_concurrency {
        injection.push_str(
            "concurrency:\n  group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}\n  cancel-in-progress: ${{ github.event_name == 'pull_request' }}\n\n",
        );
        applied.push("Added top-level `concurrency:` group".to_string());
    }

    // Insert right before top-level `jobs:` if present, else prepend.
    let mut output = String::with_capacity(content.len() + injection.len());
    let mut inserted = false;
    for line in content.lines() {
        if !inserted
            && !line.starts_with(' ')
            && !line.starts_with('\t')
            && line.trim_start().starts_with("jobs:")
        {
            output.push_str(&injection);
            inserted = true;
        }
        output.push_str(line);
        output.push('\n');
    }
    if !inserted {
        output = format!("{injection}{output}");
    }

    (output, applied)
}

/// Apply deterministic hardening fixes to all `.yml`/`.yaml` workflows under `<workspace>/.github/workflows`.
pub fn fix_workspace_workflows(root: &Path) -> Result<Vec<GhaFixResult>> {
    let workflows_dir = root.join(".github").join("workflows");
    if !workflows_dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut results = Vec::new();
    for entry in std::fs::read_dir(&workflows_dir)? {
        let entry = entry?;
        let file_path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_symlink() || !ft.is_file() {
            continue;
        }
        let is_yaml = file_path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("yml") || ext.eq_ignore_ascii_case("yaml"));
        if !is_yaml {
            continue;
        }
        let Some(content) = crate::read_bounded_utf8(&file_path, crate::MAX_SCAN_FILE_BYTES)?
        else {
            continue;
        };
        let (updated, applied_fixes) = fix_workflow_content(&content);
        if !applied_fixes.is_empty() {
            std::fs::write(&file_path, updated)?;
            let label = file_path
                .strip_prefix(root)
                .unwrap_or(&file_path)
                .display()
                .to_string();
            results.push(GhaFixResult {
                file: label,
                applied_fixes,
            });
        }
    }
    Ok(results)
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
    if action_ref.starts_with("./") {
        return None;
    }
    if action_ref.starts_with("docker://") {
        if sha256_digest_regex().is_match(action_ref) {
            return None;
        }
        return Some(GhaFinding {
            rule_id: "GHA-UNPINNED-ACTION".to_string(),
            severity: Severity::High,
            file: file_label.to_string(),
            line: line_no,
            message: format!(
                "Docker action `{action_ref}` is not pinned to an immutable `@sha256:<64-hex>` digest"
            ),
            remediation: "Pin Docker image references to an immutable `@sha256:` digest."
                .to_string(),
        });
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
/// Honors `disabled_rules` in `vektor.toml` when present.
pub fn lint_workspace_or_file(path: &Path) -> Result<Vec<GhaFinding>> {
    let cfg = VektorConfig::load(path);
    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Ok(Vec::new());
    }
    if meta.file_type().is_file() {
        let Some(content) = crate::read_bounded_utf8(path, crate::MAX_SCAN_FILE_BYTES)? else {
            return Ok(Vec::new());
        };
        let mut findings = lint_workflow_content(&path.display().to_string(), &content);
        findings.retain(|f| !cfg.is_rule_disabled(&f.rule_id));
        return Ok(findings);
    }

    let workflows_dir = path.join(".github").join("workflows");
    if !workflows_dir.is_dir() {
        return Ok(Vec::new());
    }

    let mut findings = Vec::new();
    for entry in std::fs::read_dir(&workflows_dir)? {
        let entry = entry?;
        let file_path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_symlink() || !ft.is_file() {
            continue;
        }
        let is_yaml = file_path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("yml") || ext.eq_ignore_ascii_case("yaml"));
        if !is_yaml {
            continue;
        }
        let Some(content) = crate::read_bounded_utf8(&file_path, crate::MAX_SCAN_FILE_BYTES)?
        else {
            continue;
        };
        let label = file_path
            .strip_prefix(path)
            .unwrap_or(&file_path)
            .display()
            .to_string();
        findings.extend(
            lint_workflow_content(&label, &content)
                .into_iter()
                .filter(|f| !cfg.is_rule_disabled(&f.rule_id)),
        );
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
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          persist-credentials: false
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
    timeout-minutes: 10
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
          echo "${{ github.event.issue.title }}" >> $GITHUB_ENV
"#;
        let unsafe_findings = lint_workflow_content(".github/workflows/unsafe.yml", unsafe_yaml);
        let ids: Vec<&str> = unsafe_findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(ids.contains(&"GHA-GITHUB-ENV-INJECTION"));
        assert!(ids.contains(&"GHA-MISSING-PERMISSIONS"));
        assert!(ids.contains(&"GHA-MISSING-TIMEOUT"));
    }

    #[test]
    fn fixes_missing_permissions_and_concurrency() {
        let raw = "name: Demo\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    timeout-minutes: 10\n    steps:\n      - run: echo hi\n";
        let (fixed, applied) = fix_workflow_content(raw);
        assert_eq!(applied.len(), 2);
        let findings = lint_workflow_content(".github/workflows/demo.yml", &fixed);
        assert!(
            findings.is_empty(),
            "expected fixed workflow to pass cleanly, got: {findings:?}"
        );
    }
}

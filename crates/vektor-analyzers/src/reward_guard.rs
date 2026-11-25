//! Anti-Reward-Hacking AST & Policy Integrity Gate.
//!
//! Compares `before` vs `after` file contents during `PreToolUse` (using the simulated patch)
//! to catch AI agents silently weakening tests, assertions, lints, or security policies
//! in order to pass quality gates.

use std::path::Path;

use serde::{Deserialize, Serialize};
use tree_sitter::{Node, Parser};

use crate::Severity;

/// A detected attempt to weaken tests, assertions, lints, or security policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewardHackFinding {
    pub rule_id: String,
    pub severity: Severity,
    pub file: String,
    pub message: String,
    pub before_count: usize,
    pub after_count: usize,
}

/// Analyze a file mutation (`before` -> `after`) for reward-hacking patterns.
///
/// Returns findings sorted by severity (highest first). Safe edits and normal refactors
/// that preserve or increase test/assertion coverage produce an empty vector.
#[must_use]
pub fn analyze_diff(file_path: &str, before: &str, after: &str) -> Vec<RewardHackFinding> {
    if before == after {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let norm = file_path.replace('\\', "/");
    let file_name = Path::new(&norm)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(&norm)
        .to_ascii_lowercase();
    let ext = Path::new(&norm)
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);

    // 1. Policy / guardrail configuration files.
    match file_name.as_str() {
        "vektor.toml" => check_vektor_toml(file_path, before, after, &mut findings),
        "cargo.toml" => check_cargo_toml(file_path, before, after, &mut findings),
        "deny.toml" | "clippy.toml" | ".clippy.toml" => {
            check_security_config_shrink(file_path, &file_name, before, after, &mut findings);
        }
        _ => {}
    }

    // 2. Language-aware AST integrity checks.
    match ext.as_deref() {
        Some("rs") => check_rust_ast_diff(file_path, before, after, &mut findings),
        Some("ts" | "tsx" | "js" | "jsx" | "mts" | "cts" | "astro") => {
            check_web_ast_diff(file_path, ext.as_deref(), before, after, &mut findings);
        }
        _ => {}
    }

    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.rule_id.cmp(&b.rule_id)));
    findings
}

// ---------------------------------------------------------------------------
// Rust AST Integrity (tree-sitter-rust)
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct RustMetrics {
    test_fns: usize,
    ignored_attrs: usize,
    assertions: usize,
    allow_unsafe: usize,
    allow_strict_lints: usize,
}

fn check_rust_ast_diff(
    file_path: &str,
    before: &str,
    after: &str,
    out: &mut Vec<RewardHackFinding>,
) {
    let Some(m_before) = collect_rust_metrics(before) else {
        return;
    };
    let Some(m_after) = collect_rust_metrics(after) else {
        return;
    };

    if m_after.allow_unsafe > m_before.allow_unsafe {
        out.push(RewardHackFinding {
            rule_id: "RHG-RUST-ALLOW-UNSAFE".to_string(),
            severity: Severity::Critical,
            file: file_path.to_string(),
            message: format!(
                "Introduced `allow(unsafe_code)` attribute ({} -> {}), bypassing safe-Rust policy.",
                m_before.allow_unsafe, m_after.allow_unsafe
            ),
            before_count: m_before.allow_unsafe,
            after_count: m_after.allow_unsafe,
        });
    }

    if m_after.allow_strict_lints > m_before.allow_strict_lints {
        out.push(RewardHackFinding {
            rule_id: "RHG-RUST-ALLOW-LINT-BYPASS".to_string(),
            severity: Severity::High,
            file: file_path.to_string(),
            message: format!(
                "Introduced broad lint suppression (`allow(warnings|clippy::all|clippy::pedantic|clippy::unwrap_used)`) ({} -> {}).",
                m_before.allow_strict_lints, m_after.allow_strict_lints
            ),
            before_count: m_before.allow_strict_lints,
            after_count: m_after.allow_strict_lints,
        });
    }

    if m_after.test_fns < m_before.test_fns {
        out.push(RewardHackFinding {
            rule_id: "RHG-RUST-TEST-REMOVED".to_string(),
            severity: Severity::High,
            file: file_path.to_string(),
            message: format!(
                "Removed Rust test function(s) ({} -> {} `#[test]` items).",
                m_before.test_fns, m_after.test_fns
            ),
            before_count: m_before.test_fns,
            after_count: m_after.test_fns,
        });
    }

    if m_after.ignored_attrs > m_before.ignored_attrs {
        out.push(RewardHackFinding {
            rule_id: "RHG-RUST-TEST-IGNORED".to_string(),
            severity: Severity::High,
            file: file_path.to_string(),
            message: format!(
                "Added `#[ignore]` attribute to skip Rust test(s) ({} -> {}).",
                m_before.ignored_attrs, m_after.ignored_attrs
            ),
            before_count: m_before.ignored_attrs,
            after_count: m_after.ignored_attrs,
        });
    }

    if m_before.test_fns > 0 && m_after.assertions < m_before.assertions {
        out.push(RewardHackFinding {
            rule_id: "RHG-RUST-ASSERT-REDUCED".to_string(),
            severity: Severity::High,
            file: file_path.to_string(),
            message: format!(
                "Reduced assertion macros in a file containing tests ({} -> {} assertions).",
                m_before.assertions, m_after.assertions
            ),
            before_count: m_before.assertions,
            after_count: m_after.assertions,
        });
    }
}

fn collect_rust_metrics(source: &str) -> Option<RustMetrics> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .ok()?;
    let tree = parser.parse(source, None)?;
    let mut metrics = RustMetrics::default();
    walk_rust(tree.root_node(), source.as_bytes(), &mut metrics);
    Some(metrics)
}

fn walk_rust(node: Node<'_>, bytes: &[u8], metrics: &mut RustMetrics) {
    match node.kind() {
        "attribute_item" | "inner_attribute_item" => {
            if let Ok(raw) = node.utf8_text(bytes) {
                let compact = strip_whitespace(raw);
                if is_rust_test_attr(&compact) {
                    metrics.test_fns += 1;
                }
                if is_rust_ignore_attr(&compact) {
                    metrics.ignored_attrs += 1;
                }
                if is_allow_attr(&compact) {
                    let lower = compact.to_ascii_lowercase();
                    if lower.contains("unsafe_code") {
                        metrics.allow_unsafe += 1;
                    }
                    if lower.contains("warnings")
                        || lower.contains("clippy::all")
                        || lower.contains("clippy::pedantic")
                        || lower.contains("clippy::unwrap_used")
                        || lower.contains("clippy::panic")
                    {
                        metrics.allow_strict_lints += 1;
                    }
                }
            }
            return;
        }
        "macro_invocation" => {
            if let Some(macro_node) = node.child_by_field_name("macro") {
                if let Ok(name) = macro_node.utf8_text(bytes) {
                    let tail = name.rsplit("::").next().unwrap_or(name);
                    if matches!(
                        tail,
                        "assert"
                            | "assert_eq"
                            | "assert_ne"
                            | "debug_assert"
                            | "debug_assert_eq"
                            | "debug_assert_ne"
                    ) {
                        metrics.assertions += 1;
                    }
                }
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_rust(child, bytes, metrics);
    }
}

fn strip_whitespace(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

fn is_rust_test_attr(compact: &str) -> bool {
    matches!(
        compact,
        "#[test]"
            | "#[core::prelude::v1::test]"
            | "#[tokio::test]"
            | "#[async_std::test]"
            | "#[actix_rt::test]"
            | "#[rstest]"
    ) || compact.starts_with("#[tokio::test(")
        || compact.starts_with("#[async_std::test(")
        || compact.starts_with("#[rstest(")
}

fn is_rust_ignore_attr(compact: &str) -> bool {
    compact == "#[ignore]" || compact.starts_with("#[ignore=") || compact.starts_with("#[ignore(")
}

fn is_allow_attr(compact: &str) -> bool {
    compact.starts_with("#[allow(") || compact.starts_with("#![allow(")
}

// ---------------------------------------------------------------------------
// TypeScript / JS / Astro AST Integrity (tree-sitter-typescript)
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct WebMetrics {
    tests: usize,
    skipped_tests: usize,
    assertions: usize,
    lint_bypasses: usize,
}

fn check_web_ast_diff(
    file_path: &str,
    ext: Option<&str>,
    before: &str,
    after: &str,
    out: &mut Vec<RewardHackFinding>,
) {
    let tsx = matches!(ext, Some("tsx" | "jsx"));
    let src_before = if ext == Some("astro") {
        extract_astro_frontmatter(before)
    } else {
        before
    };
    let src_after = if ext == Some("astro") {
        extract_astro_frontmatter(after)
    } else {
        after
    };

    let Some(m_before) = collect_web_metrics(src_before, tsx) else {
        return;
    };
    let Some(m_after) = collect_web_metrics(src_after, tsx) else {
        return;
    };

    if m_after.skipped_tests > m_before.skipped_tests {
        out.push(RewardHackFinding {
            rule_id: "RHG-WEB-TEST-SKIPPED".to_string(),
            severity: Severity::High,
            file: file_path.to_string(),
            message: format!(
                "Added skipped test directive (`it.skip`/`test.skip`/`describe.skip`/`xit`) ({} -> {}).",
                m_before.skipped_tests, m_after.skipped_tests
            ),
            before_count: m_before.skipped_tests,
            after_count: m_after.skipped_tests,
        });
    }

    if m_before.tests > 0 && m_after.assertions < m_before.assertions {
        out.push(RewardHackFinding {
            rule_id: "RHG-WEB-ASSERT-REDUCED".to_string(),
            severity: Severity::High,
            file: file_path.to_string(),
            message: format!(
                "Reduced test assertions (`expect`/`assert`) ({} -> {}).",
                m_before.assertions, m_after.assertions
            ),
            before_count: m_before.assertions,
            after_count: m_after.assertions,
        });
    }

    if m_after.lint_bypasses > m_before.lint_bypasses {
        out.push(RewardHackFinding {
            rule_id: "RHG-WEB-LINT-BYPASS".to_string(),
            severity: Severity::High,
            file: file_path.to_string(),
            message: format!(
                "Introduced TypeScript/linter suppression comment (`@ts-ignore`/`@ts-nocheck`/`eslint-disable`/`biome-ignore`) ({} -> {}).",
                m_before.lint_bypasses, m_after.lint_bypasses
            ),
            before_count: m_before.lint_bypasses,
            after_count: m_after.lint_bypasses,
        });
    }
}

fn extract_astro_frontmatter(src: &str) -> &str {
    let trimmed = src.trim_start();
    if let Some(rest) = trimmed.strip_prefix("---") {
        if let Some(end) = rest.find("\n---") {
            return &rest[..end];
        }
    }
    src
}

fn collect_web_metrics(source: &str, tsx: bool) -> Option<WebMetrics> {
    let mut parser = Parser::new();
    let lang = if tsx {
        tree_sitter_typescript::LANGUAGE_TSX.into()
    } else {
        tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()
    };
    parser.set_language(&lang).ok()?;
    let tree = parser.parse(source, None)?;
    let mut metrics = WebMetrics::default();
    walk_web(tree.root_node(), source.as_bytes(), &mut metrics);
    Some(metrics)
}

fn walk_web(node: Node<'_>, bytes: &[u8], metrics: &mut WebMetrics) {
    match node.kind() {
        "call_expression" => {
            if let Some(func) = node.child_by_field_name("function") {
                if let Ok(raw) = func.utf8_text(bytes) {
                    let callee = strip_whitespace(raw);
                    if matches!(callee.as_str(), "it" | "test" | "describe") {
                        metrics.tests += 1;
                    } else if matches!(
                        callee.as_str(),
                        "it.skip" | "test.skip" | "describe.skip" | "xit" | "xtest" | "xdescribe"
                    ) {
                        metrics.skipped_tests += 1;
                    } else if callee == "expect"
                        || callee == "assert"
                        || callee.starts_with("assert.")
                    {
                        metrics.assertions += 1;
                    }
                }
            }
        }
        "comment" => {
            if let Ok(raw) = node.utf8_text(bytes) {
                let lower = raw.to_ascii_lowercase();
                if lower.contains("@ts-ignore")
                    || lower.contains("@ts-nocheck")
                    || lower.contains("@ts-expect-error")
                    || lower.contains("eslint-disable")
                    || lower.contains("biome-ignore")
                {
                    metrics.lint_bypasses += 1;
                }
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_web(child, bytes, metrics);
    }
}

// ---------------------------------------------------------------------------
// Policy / Config Tampering Guards
// ---------------------------------------------------------------------------

fn check_vektor_toml(file_path: &str, before: &str, after: &str, out: &mut Vec<RewardHackFinding>) {
    let mut cfg_before = crate::config::VektorConfig::default();
    cfg_before.apply_toml(before);
    let mut cfg_after = crate::config::VektorConfig::default();
    cfg_after.apply_toml(after);

    if cfg_before.stop_gate != "off" && cfg_after.stop_gate == "off" {
        out.push(RewardHackFinding {
            rule_id: "RHG-POLICY-STOP-GATE-OFF".to_string(),
            severity: Severity::Critical,
            file: file_path.to_string(),
            message: format!(
                "Weakened Vektor `stop_gate` from `{}` to `off`.",
                cfg_before.stop_gate
            ),
            before_count: 1,
            after_count: 0,
        });
    }

    if cfg_before.anti_reward_hacking && !cfg_after.anti_reward_hacking {
        out.push(RewardHackFinding {
            rule_id: "RHG-POLICY-GUARD-DISABLED".to_string(),
            severity: Severity::Critical,
            file: file_path.to_string(),
            message: "Attempted to disable `anti_reward_hacking` in `vektor.toml`.".to_string(),
            before_count: 1,
            after_count: 0,
        });
    }

    if cfg_before.taint_tracking && !cfg_after.taint_tracking {
        out.push(RewardHackFinding {
            rule_id: "RHG-POLICY-TAINT-DISABLED".to_string(),
            severity: Severity::Critical,
            file: file_path.to_string(),
            message: "Attempted to disable `taint_tracking` in `vektor.toml`.".to_string(),
            before_count: 1,
            after_count: 0,
        });
    }

    if cfg_after.disabled_rules.len() > cfg_before.disabled_rules.len() {
        out.push(RewardHackFinding {
            rule_id: "RHG-POLICY-RULES-DISABLED".to_string(),
            severity: Severity::High,
            file: file_path.to_string(),
            message: format!(
                "Expanded `disabled_rules` in `vektor.toml` ({} -> {} suppressed rules).",
                cfg_before.disabled_rules.len(),
                cfg_after.disabled_rules.len()
            ),
            before_count: cfg_before.disabled_rules.len(),
            after_count: cfg_after.disabled_rules.len(),
        });
    }

    if cfg_after.entropy_threshold > cfg_before.entropy_threshold + 0.05 {
        out.push(RewardHackFinding {
            rule_id: "RHG-POLICY-ENTROPY-RELAXED".to_string(),
            severity: Severity::High,
            file: file_path.to_string(),
            message: format!(
                "Raised `entropy_threshold` in `vektor.toml` ({:.2} -> {:.2}), weakening secret detection.",
                cfg_before.entropy_threshold, cfg_after.entropy_threshold
            ),
            before_count: 1,
            after_count: 0,
        });
    }
}

fn check_cargo_toml(file_path: &str, before: &str, after: &str, out: &mut Vec<RewardHackFinding>) {
    let before_forbid = has_unsafe_forbid(before);
    let after_forbid = has_unsafe_forbid(after);
    if before_forbid && !after_forbid {
        out.push(RewardHackFinding {
            rule_id: "RHG-POLICY-UNSAFE-RELAXED".to_string(),
            severity: Severity::Critical,
            file: file_path.to_string(),
            message: "Removed or weakened `unsafe_code = \"forbid\"` in `Cargo.toml`.".to_string(),
            before_count: 1,
            after_count: 0,
        });
    }

    let deny_before = count_lint_denies(before);
    let deny_after = count_lint_denies(after);
    if deny_after < deny_before {
        out.push(RewardHackFinding {
            rule_id: "RHG-POLICY-CLIPPY-RELAXED".to_string(),
            severity: Severity::High,
            file: file_path.to_string(),
            message: format!(
                "Reduced `= \"deny\"` lint rules in `Cargo.toml` ({deny_before} -> {deny_after})."
            ),
            before_count: deny_before,
            after_count: deny_after,
        });
    }
}

fn has_unsafe_forbid(toml: &str) -> bool {
    toml.lines().any(|line| {
        let trimmed = line.split('#').next().unwrap_or("").trim();
        let compact = strip_whitespace(trimmed).to_ascii_lowercase();
        compact == "unsafe_code=\"forbid\"" || compact.contains("unsafe_code={level=\"forbid\"")
    })
}

fn count_lint_denies(toml: &str) -> usize {
    let mut in_lints = false;
    let mut count = 0usize;
    for raw in toml.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.starts_with('[') && line.ends_with(']') {
            let sec = line[1..line.len() - 1].trim().to_ascii_lowercase();
            in_lints = sec.starts_with("workspace.lints") || sec.starts_with("lints");
            continue;
        }
        if in_lints {
            let compact = strip_whitespace(line).to_ascii_lowercase();
            if compact.contains("=\"deny\"") || compact.contains("level=\"deny\"") {
                count += 1;
            }
        }
    }
    count
}

fn check_security_config_shrink(
    file_path: &str,
    file_name: &str,
    before: &str,
    after: &str,
    out: &mut Vec<RewardHackFinding>,
) {
    let deny_before = before
        .lines()
        .filter(|l| l.to_ascii_lowercase().contains("\"deny\""))
        .count();
    let deny_after = after
        .lines()
        .filter(|l| l.to_ascii_lowercase().contains("\"deny\""))
        .count();
    if deny_after < deny_before {
        out.push(RewardHackFinding {
            rule_id: "RHG-POLICY-CONFIG-RELAXED".to_string(),
            severity: Severity::High,
            file: file_path.to_string(),
            message: format!(
                "Weakened `\"deny\"` enforcement in `{file_name}` ({deny_before} -> {deny_after})."
            ),
            before_count: deny_before,
            after_count: deny_after,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_rust_assert_removal_ignore_and_unsafe_allow() {
        let before = r"
#[cfg(test)]
mod tests {
    #[test]
    fn validates_invariant() {
        assert_eq!(2 + 2, 4);
        assert!(true);
    }
}
";
        let after = r"
#[allow(unsafe_code)]
#[cfg(test)]
mod tests {
    #[test]
    #[ignore]
    fn validates_invariant() {
        let _ = 2 + 2;
    }
}
";
        let hits = analyze_diff("src/lib.rs", before, after);
        let ids: Vec<&str> = hits.iter().map(|h| h.rule_id.as_str()).collect();
        assert!(ids.contains(&"RHG-RUST-ALLOW-UNSAFE"), "got: {ids:?}");
        assert!(ids.contains(&"RHG-RUST-TEST-IGNORED"), "got: {ids:?}");
        assert!(ids.contains(&"RHG-RUST-ASSERT-REDUCED"), "got: {ids:?}");
    }

    #[test]
    fn allows_legitimate_rust_refactor_that_preserves_or_adds_tests() {
        let before = r"
fn add(a: i32, b: i32) -> i32 { a + b }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn works() {
        assert_eq!(add(1, 2), 3);
    }
}
";
        let after = r"
fn add(a: i32, b: i32) -> i32 { a.saturating_add(b) }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn works() {
        assert_eq!(add(1, 2), 3);
        assert_eq!(add(0, 0), 0);
    }
}
";
        let hits = analyze_diff("src/math.rs", before, after);
        assert!(hits.is_empty(), "expected clean refactor, got: {hits:?}");
    }

    #[test]
    fn detects_typescript_skip_expect_removal_and_ts_ignore() {
        let before = r#"
describe("auth", () => {
  it("checks token", () => {
    expect(verify("abc")).toBe(true);
    expect(verify("")).toBe(false);
  });
});
"#;
        let after = r#"
describe("auth", () => {
  // @ts-ignore
  it.skip("checks token", () => {
    expect(verify("abc")).toBe(true);
  });
});
"#;
        let hits = analyze_diff("src/auth.test.ts", before, after);
        let ids: Vec<&str> = hits.iter().map(|h| h.rule_id.as_str()).collect();
        assert!(ids.contains(&"RHG-WEB-TEST-SKIPPED"), "got: {ids:?}");
        assert!(ids.contains(&"RHG-WEB-ASSERT-REDUCED"), "got: {ids:?}");
        assert!(ids.contains(&"RHG-WEB-LINT-BYPASS"), "got: {ids:?}");
    }

    #[test]
    fn detects_vektor_and_cargo_toml_policy_tampering() {
        let v_before = "[hooks]\nstop_gate = \"selective\"\nanti_reward_hacking = true\n";
        let v_after = "[hooks]\nstop_gate = \"off\"\nanti_reward_hacking = false\n";
        let v_hits = analyze_diff("vektor.toml", v_before, v_after);
        assert!(v_hits
            .iter()
            .any(|h| h.rule_id == "RHG-POLICY-STOP-GATE-OFF"));
        assert!(v_hits
            .iter()
            .any(|h| h.rule_id == "RHG-POLICY-GUARD-DISABLED"));

        let c_before = "[workspace.lints.rust]\nunsafe_code = \"forbid\"\n[workspace.lints.clippy]\nunwrap_used = \"deny\"\n";
        let c_after = "[workspace.lints.rust]\nunsafe_code = \"allow\"\n[workspace.lints.clippy]\nunwrap_used = \"warn\"\n";
        let c_hits = analyze_diff("Cargo.toml", c_before, c_after);
        assert!(c_hits
            .iter()
            .any(|h| h.rule_id == "RHG-POLICY-UNSAFE-RELAXED"));
        assert!(c_hits
            .iter()
            .any(|h| h.rule_id == "RHG-POLICY-CLIPPY-RELAXED"));
    }
}

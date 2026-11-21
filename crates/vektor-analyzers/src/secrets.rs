//! Fast deterministic secret scanner combining compiled regex rules and Shannon entropy.

use std::collections::HashMap;
use std::path::Path;
use std::sync::OnceLock;

use anyhow::Result;
use regex::Regex;
use serde::Serialize;

use crate::Severity;

const SKIP_DIRS: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    ".vektor",
    "dist",
    "build",
    ".next",
];

/// A single secret detection finding.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretFinding {
    pub rule_id: String,
    pub severity: Severity,
    pub file: String,
    pub line: usize,
    pub message: String,
    pub redacted_match: String,
}

struct SecretRule {
    id: &'static str,
    severity: Severity,
    message: &'static str,
    regex: Regex,
}

#[allow(clippy::expect_used)]
fn compiled_rules() -> &'static [SecretRule] {
    static RULES: OnceLock<Vec<SecretRule>> = OnceLock::new();
    RULES.get_or_init(|| {
        vec![
            SecretRule {
                id: "SEC-PRIVATE-KEY",
                severity: Severity::Critical,
                message: "Private key material detected",
                regex: Regex::new(
                    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED |SSH2 ENCRYPTED )?PRIVATE KEY-----",
                )
                .expect("valid regex"),
            },
            SecretRule {
                id: "SEC-GITHUB-TOKEN",
                severity: Severity::Critical,
                message: "GitHub personal access or app token detected",
                regex: Regex::new(
                    r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{30,}\b",
                )
                .expect("valid regex"),
            },
            SecretRule {
                id: "SEC-AWS-KEY",
                severity: Severity::Critical,
                message: "AWS Access Key ID detected",
                regex: Regex::new(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b").expect("valid regex"),
            },
            SecretRule {
                id: "SEC-GOOGLE-API-KEY",
                severity: Severity::High,
                message: "Google API key detected",
                regex: Regex::new(r"\bAIza[0-9A-Za-z\-_]{35}\b").expect("valid regex"),
            },
            SecretRule {
                id: "SEC-OPENAI-ANTHROPIC",
                severity: Severity::Critical,
                message: "AI provider secret API key detected",
                regex: Regex::new(r"\bsk-(?:ant-)?[A-Za-z0-9\-_]{24,}\b").expect("valid regex"),
            },
            SecretRule {
                id: "SEC-SLACK-TOKEN",
                severity: Severity::High,
                message: "Slack API token detected",
                regex: Regex::new(r"\bxox[baprs]-[0-9A-Za-z\-]{16,}\b").expect("valid regex"),
            },
            SecretRule {
                id: "SEC-STRIPE-LIVE",
                severity: Severity::Critical,
                message: "Stripe live secret key detected",
                regex: Regex::new(r"\bsk_live_[0-9A-Za-z]{20,}\b").expect("valid regex"),
            },
        ]
    })
}

#[allow(clippy::expect_used)]
fn generic_assignment_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|password|passwd)\b\s*[:=]\s*(?:["']([^"'\s]{16,})["']|([^\s"'#,;]{16,}))"#,
        )
        .expect("valid regex")
    })
}

/// Scan raw text for hardcoded secrets and high-entropy credentials.
///
/// Lines containing `vektor:ignore` (case-insensitive) are skipped.
#[must_use]
pub fn scan_text(source_label: &str, content: &str) -> Vec<SecretFinding> {
    scan_text_with_options(source_label, content, true)
}

/// Scan raw text with explicit control over whether inline `vektor:ignore` directives are honored.
#[must_use]
pub fn scan_text_with_options(
    source_label: &str,
    content: &str,
    allow_inline_ignore: bool,
) -> Vec<SecretFinding> {
    let mut findings = Vec::new();
    let rules = compiled_rules();
    let generic_re = generic_assignment_regex();

    for (idx, line) in content.lines().enumerate() {
        if allow_inline_ignore && line.to_ascii_lowercase().contains("vektor:ignore") {
            continue;
        }
        let line_no = idx + 1;
        let mut specific_spans: Vec<(usize, usize)> = Vec::new();

        for rule in rules {
            for m in rule.regex.find_iter(line) {
                specific_spans.push((m.start(), m.end()));
                findings.push(SecretFinding {
                    rule_id: rule.id.to_string(),
                    severity: rule.severity,
                    file: source_label.to_string(),
                    line: line_no,
                    message: rule.message.to_string(),
                    redacted_match: redact(m.as_str()),
                });
            }
        }

        for caps in generic_re.captures_iter(line) {
            let Some(val) = caps.get(1).or_else(|| caps.get(2)) else {
                continue;
            };
            let overlaps_specific = specific_spans
                .iter()
                .any(|&(s, e)| val.start() < e && val.end() > s);
            if overlaps_specific {
                continue;
            }
            let candidate = val.as_str();
            if !looks_like_placeholder(candidate) && shannon_entropy(candidate) >= 3.5 {
                findings.push(SecretFinding {
                    rule_id: "SEC-HIGH-ENTROPY".to_string(),
                    severity: Severity::High,
                    file: source_label.to_string(),
                    line: line_no,
                    message: "High-entropy credential assignment detected".to_string(),
                    redacted_match: redact(candidate),
                });
            }
        }
    }

    findings
}

/// Recursively scan a file or directory for hardcoded secrets.
/// Respects optional `.vektorignore` patterns at `target` root and skips symlinks.
pub fn scan_path(target: &Path) -> Result<Vec<SecretFinding>> {
    let ignore_patterns = load_ignore_patterns(target);
    let mut findings = Vec::new();
    scan_recursive(target, target, 0, &ignore_patterns, &mut findings)?;
    Ok(findings)
}

fn load_ignore_patterns(root: &Path) -> Vec<String> {
    let ignore_file = if root.is_dir() {
        root.join(".vektorignore")
    } else {
        root.parent()
            .map_or_else(|| root.join(".vektorignore"), |p| p.join(".vektorignore"))
    };
    let Ok(Some(content)) = crate::read_bounded_utf8(&ignore_file, 65_536) else {
        return Vec::new();
    };
    content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.replace('\\', "/").trim_start_matches("./").to_string())
        .collect()
}

fn is_ignored(rel_path: &str, patterns: &[String]) -> bool {
    let norm = rel_path.replace('\\', "/");
    let file_name = Path::new(&norm)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(&norm);

    patterns.iter().any(|pat| {
        let trimmed = pat.trim_end_matches('/');
        if trimmed.is_empty() {
            return false;
        }
        norm == trimmed || norm.starts_with(&format!("{trimmed}/")) || file_name == trimmed
    })
}

fn scan_recursive(
    root: &Path,
    current: &Path,
    depth: usize,
    ignore_patterns: &[String],
    findings: &mut Vec<SecretFinding>,
) -> Result<()> {
    if depth > crate::MAX_WALK_DEPTH {
        return Ok(());
    }
    if let Ok(rel_path) = current.strip_prefix(root) {
        let rel_str = rel_path.display().to_string().replace('\\', "/");
        if !rel_str.is_empty() && is_ignored(&rel_str, ignore_patterns) {
            return Ok(());
        }
    }

    let meta = std::fs::symlink_metadata(current)?;
    let ft = meta.file_type();
    if ft.is_symlink() {
        return Ok(());
    }

    if ft.is_file() {
        let Some(text) = crate::read_bounded_utf8(current, crate::MAX_SCAN_FILE_BYTES)? else {
            return Ok(());
        };
        let rel = current
            .strip_prefix(root)
            .unwrap_or(current)
            .display()
            .to_string();
        let label = if rel.is_empty() {
            current.display().to_string()
        } else {
            rel
        };
        findings.extend(scan_text(&label, &text));
        return Ok(());
    }

    if ft.is_dir() {
        for entry in std::fs::read_dir(current)? {
            let entry = entry?;
            let path = entry.path();
            let entry_ft = entry.file_type()?;
            if entry_ft.is_symlink() {
                continue;
            }
            if entry_ft.is_dir() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if SKIP_DIRS.contains(&name) {
                        continue;
                    }
                }
            }
            scan_recursive(root, &path, depth + 1, ignore_patterns, findings)?;
        }
    }

    Ok(())
}

fn redact(secret: &str) -> String {
    let chars: Vec<char> = secret.chars().collect();
    if chars.len() <= 12 {
        return "***".to_string();
    }
    let prefix: String = chars[..3].iter().collect();
    format!("{prefix}...****")
}

fn looks_like_placeholder(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    lower.contains("example")
        || lower.contains("placeholder")
        || lower.contains("changeme")
        || lower.contains("your_")
        || lower.contains("dummy")
        || lower.contains("xxxx")
        || lower.starts_with("${")
        || lower.starts_with("env:")
}

/// Compute Shannon entropy (bits per character) for a candidate secret.
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn shannon_entropy(input: &str) -> f64 {
    if input.is_empty() {
        return 0.0;
    }
    let mut counts: HashMap<char, usize> = HashMap::new();
    let mut total = 0usize;
    for ch in input.chars() {
        *counts.entry(ch).or_insert(0) += 1;
        total += 1;
    }
    let len = total as f64;
    counts.values().fold(0.0, |acc, &count| {
        let p = (count as f64) / len;
        acc - p * p.log2()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_github_token_and_redacts() {
        let token = ["ghp_", "1234567890", "abcdefghijklmnoPQRST"].concat();
        let fake = format!("token = \"{token}\"");
        let findings = scan_text("test.rs", &fake);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SEC-GITHUB-TOKEN");
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].redacted_match.starts_with("ghp"));
        assert!(findings[0].redacted_match.ends_with("****"));
    }

    #[test]
    fn ignores_obvious_placeholders() {
        let content = r#"api_key = "your_example_placeholder_key_here""#;
        let findings = scan_text("config.toml", content);
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_high_entropy_quoted_unquoted_and_multi_match_per_line() {
        let secret = ["9fK2mP7qR4", "xL8vN1wZ6c", "B3tY5hJ0dS"].concat();
        let content = format!("api_key=\"your_example_placeholder_key\", secret_key={secret}");
        let findings = scan_text("env.rs", &content);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SEC-HIGH-ENTROPY");
    }

    #[test]
    fn respects_inline_vektor_ignore_directive_only_when_allowed() {
        let token = ["ghp_", "1234567890", "abcdefghijklmnoPQRST"].concat();
        let content = format!("const FIXTURE: &str = \"{token}\"; // vektor:ignore");
        assert!(scan_text("test.rs", &content).is_empty());
        assert_eq!(
            scan_text_with_options("run_command", &content, false).len(),
            1
        );
    }

    #[test]
    fn respects_vektorignore_file() {
        let dir = std::env::temp_dir().join(format!("vektor-ignore-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("fixtures")).expect("mkdir");
        std::fs::write(dir.join(".vektorignore"), "# comment\nfixtures/\n").expect("write ignore");
        let token = ["ghp_", "1234567890", "abcdefghijklmnoPQRST"].concat();
        std::fs::write(dir.join("fixtures").join("sample.txt"), &token).expect("write fixture");

        let findings = scan_path(&dir).expect("scan");
        assert!(findings.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

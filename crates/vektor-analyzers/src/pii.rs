//! Sub-millisecond PII Guard (inspired by `glastor-core/pii-veil`):
//! detects and redacts credit cards (Luhn-verified), US SSNs, IBANs, and personal email addresses.

use std::path::Path;
use std::sync::OnceLock;

use anyhow::Result;
use regex::Regex;
use serde::Serialize;

use crate::config::VektorConfig;
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

/// A single PII detection finding.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PiiFinding {
    pub rule_id: String,
    pub severity: Severity,
    pub file: String,
    pub line: usize,
    pub message: String,
    pub redacted_match: String,
}

#[allow(clippy::expect_used)]
fn card_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b(?:\d[ -]*?){13,19}\b").expect("valid regex"))
}

#[allow(clippy::expect_used)]
fn ssn_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b(\d{3})-(\d{2})-(\d{4})\b").expect("valid regex"))
}

#[allow(clippy::expect_used)]
fn iban_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b").expect("valid regex"))
}

#[allow(clippy::expect_used)]
fn email_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b").expect("valid regex")
    })
}

/// Validate a numeric string using the Luhn checksum algorithm (ISO/IEC 7812).
#[must_use]
pub fn is_valid_luhn(candidate: &str) -> bool {
    let digits: Vec<u32> = candidate.chars().filter_map(|c| c.to_digit(10)).collect();
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    let mut sum = 0u32;
    let mut double = false;
    for &d in digits.iter().rev() {
        let mut val = d;
        if double {
            val *= 2;
            if val > 9 {
                val -= 9;
            }
        }
        sum += val;
        double = !double;
    }
    sum.is_multiple_of(10)
}

fn is_example_email(email: &str) -> bool {
    let lower = email.to_ascii_lowercase();
    lower.ends_with("@example.com")
        || lower.ends_with("@example.org")
        || lower.ends_with("@example.net")
        || lower.ends_with("@localhost")
        || lower
            .rsplit_once('.')
            .is_some_and(|(_, tld)| tld == "local")
        || lower.contains("noreply@")
        || lower.contains("no-reply@")
}

fn redact_pii(raw: &str) -> String {
    let chars: Vec<char> = raw.chars().collect();
    if chars.len() <= 6 {
        return "***".to_string();
    }
    let head: String = chars[..2].iter().collect();
    let tail: String = chars[chars.len() - 2..].iter().collect();
    format!("{head}***{tail}")
}

/// Scan raw text for PII (credit cards, US SSNs, IBANs, and personal email addresses).
#[must_use]
pub fn scan_text(source_label: &str, content: &str) -> Vec<PiiFinding> {
    scan_text_with_config(source_label, content, &VektorConfig::default())
}

/// Scan raw text for PII honoring `VektorConfig::disabled_rules`.
#[must_use]
pub fn scan_text_with_config(
    source_label: &str,
    content: &str,
    cfg: &VektorConfig,
) -> Vec<PiiFinding> {
    let mut findings = Vec::new();
    let card_re = card_regex();
    let ssn_re = ssn_regex();
    let iban_re = iban_regex();
    let email_re = email_regex();

    for (idx, line) in content.lines().enumerate() {
        if line.to_ascii_lowercase().contains("vektor:ignore") {
            continue;
        }
        let line_no = idx + 1;

        if !cfg.is_rule_disabled("PII-CREDIT-CARD") {
            for m in card_re.find_iter(line) {
                let raw = m.as_str();
                if is_valid_luhn(raw) {
                    findings.push(PiiFinding {
                        rule_id: "PII-CREDIT-CARD".to_string(),
                        severity: Severity::High,
                        file: source_label.to_string(),
                        line: line_no,
                        message: "Luhn-valid payment card number detected".to_string(),
                        redacted_match: redact_pii(raw),
                    });
                }
            }
        }

        if !cfg.is_rule_disabled("PII-US-SSN") {
            for caps in ssn_re.captures_iter(line) {
                let area = caps.get(1).map_or("", |m| m.as_str());
                let group = caps.get(2).map_or("", |m| m.as_str());
                let serial = caps.get(3).map_or("", |m| m.as_str());
                if area != "000"
                    && area != "666"
                    && !area.starts_with('9')
                    && group != "00"
                    && serial != "0000"
                {
                    let full = caps.get(0).map_or("", |m| m.as_str());
                    findings.push(PiiFinding {
                        rule_id: "PII-US-SSN".to_string(),
                        severity: Severity::High,
                        file: source_label.to_string(),
                        line: line_no,
                        message: "US Social Security Number (SSN) pattern detected".to_string(),
                        redacted_match: redact_pii(full),
                    });
                }
            }
        }

        if !cfg.is_rule_disabled("PII-IBAN") {
            for m in iban_re.find_iter(line) {
                let raw = m.as_str();
                if raw.len() >= 15 {
                    findings.push(PiiFinding {
                        rule_id: "PII-IBAN".to_string(),
                        severity: Severity::Medium,
                        file: source_label.to_string(),
                        line: line_no,
                        message: "IBAN bank account identifier detected".to_string(),
                        redacted_match: redact_pii(raw),
                    });
                }
            }
        }

        if !cfg.is_rule_disabled("PII-EMAIL") {
            for m in email_re.find_iter(line) {
                let raw = m.as_str();
                if !is_example_email(raw) {
                    findings.push(PiiFinding {
                        rule_id: "PII-EMAIL".to_string(),
                        severity: Severity::Low,
                        file: source_label.to_string(),
                        line: line_no,
                        message: "Email address (PII) detected in source".to_string(),
                        redacted_match: redact_pii(raw),
                    });
                }
            }
        }
    }

    findings
}

/// Recursively scan a file or directory for PII honoring `vektor.toml`, `.gitignore`, and `.vektorignore`.
pub fn scan_path(target: &Path) -> Result<Vec<PiiFinding>> {
    let cfg = VektorConfig::load(target);
    let mut findings = Vec::new();
    scan_recursive(target, target, 0, &cfg, &mut findings)?;
    Ok(findings)
}

fn scan_recursive(
    root: &Path,
    current: &Path,
    depth: usize,
    cfg: &VektorConfig,
    findings: &mut Vec<PiiFinding>,
) -> Result<()> {
    if depth > crate::MAX_WALK_DEPTH {
        return Ok(());
    }
    if let Ok(rel_path) = current.strip_prefix(root) {
        let rel_str = rel_path.display().to_string().replace('\\', "/");
        if !rel_str.is_empty() && cfg.is_path_ignored(&rel_str) {
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
        findings.extend(scan_text_with_config(&label, &text, cfg));
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
            scan_recursive(root, &path, depth + 1, cfg, findings)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_luhn_card_ssn_and_ignores_example_email() {
        // Synthetic Luhn-valid test card (4111...)
        let card = ["4111", "1111", "1111", "1111"].join("-");
        let ssn = ["123", "45", "6789"].join("-");
        let content = format!(
            "card = \"{card}\"\nssn = \"{ssn}\"\ncontact = \"user@example.com\"\nreal = \"alice@acme.io\"\n" // vektor:ignore
        );
        let hits = scan_text("sample.txt", &content);
        let ids: Vec<&str> = hits.iter().map(|h| h.rule_id.as_str()).collect();
        assert!(ids.contains(&"PII-CREDIT-CARD"));
        assert!(ids.contains(&"PII-US-SSN"));
        assert!(ids.contains(&"PII-EMAIL"));
        assert_eq!(hits.len(), 3, "example.com email must be ignored: {hits:?}");
    }
}

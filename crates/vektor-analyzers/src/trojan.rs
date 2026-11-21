//! Trojan Guard: detects Unicode `BiDi` overrides (CVE-2021-42574) and invisible zero-width characters.

use std::path::Path;

use anyhow::Result;
use serde::Serialize;

use crate::Severity;

const MAX_SCAN_FILE_BYTES: u64 = 1_048_576;
const SKIP_DIRS: &[&str] = &[".git", "target", "node_modules", ".vektor", "dist", "build"];

/// A Trojan Source / invisible Unicode character finding.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrojanFinding {
    pub rule_id: String,
    pub severity: Severity,
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub codepoint: String,
    pub message: String,
}

fn classify_dangerous_char(
    ch: char,
    is_file_start: bool,
) -> Option<(&'static str, Severity, &'static str)> {
    match ch {
        '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}' | '\u{061C}' => {
            Some((
                "TROJAN-BIDI",
                Severity::Critical,
                "Unicode bidirectional control character detected (Trojan Source / CVE-2021-42574 risk)",
            ))
        }
        '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{2060}' => Some((
            "TROJAN-INVISIBLE",
            Severity::High,
            "Invisible zero-width Unicode character detected in source",
        )),
        '\u{FEFF}' if !is_file_start => Some((
            "TROJAN-MID-BOM",
            Severity::High,
            "Mid-file UTF-8 BOM (U+FEFF) detected in source",
        )),
        _ => None,
    }
}

/// Scan raw text for Trojan Source `BiDi` and invisible Unicode characters.
#[must_use]
pub fn scan_text(source_label: &str, content: &str) -> Vec<TrojanFinding> {
    let mut findings = Vec::new();
    for (line_idx, line) in content.lines().enumerate() {
        for (col_idx, ch) in line.chars().enumerate() {
            let is_file_start = line_idx == 0 && col_idx == 0;
            if let Some((rule_id, severity, message)) = classify_dangerous_char(ch, is_file_start) {
                findings.push(TrojanFinding {
                    rule_id: rule_id.to_string(),
                    severity,
                    file: source_label.to_string(),
                    line: line_idx + 1,
                    column: col_idx + 1,
                    codepoint: format!("U+{:04X}", ch as u32),
                    message: message.to_string(),
                });
            }
        }
    }
    findings
}

/// Recursively scan a file or directory for Trojan Source / invisible Unicode characters.
pub fn scan_path(target: &Path) -> Result<Vec<TrojanFinding>> {
    let mut findings = Vec::new();
    scan_recursive(target, target, &mut findings)?;
    Ok(findings)
}

fn scan_recursive(root: &Path, current: &Path, findings: &mut Vec<TrojanFinding>) -> Result<()> {
    if current.is_file() {
        let meta = std::fs::metadata(current)?;
        if meta.len() > MAX_SCAN_FILE_BYTES {
            return Ok(());
        }
        let Ok(bytes) = std::fs::read(current) else {
            return Ok(());
        };
        if bytes.contains(&0) {
            return Ok(());
        }
        let Ok(text) = String::from_utf8(bytes) else {
            return Ok(());
        };
        let rel = current
            .strip_prefix(root)
            .unwrap_or(current)
            .display()
            .to_string()
            .replace('\\', "/");
        let label = if rel.is_empty() {
            current.display().to_string()
        } else {
            rel
        };
        findings.extend(scan_text(&label, &text));
        return Ok(());
    }

    if current.is_dir() {
        for entry in std::fs::read_dir(current)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if SKIP_DIRS.contains(&name) {
                        continue;
                    }
                }
            }
            scan_recursive(root, &path, findings)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_bidi_override_and_zero_width() {
        let evil = "let is_admin = false; /* \u{202E} */ let x\u{200B} = 1;";
        let findings = scan_text("src/auth.rs", evil);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].rule_id, "TROJAN-BIDI");
        assert_eq!(findings[0].codepoint, "U+202E");
        assert_eq!(findings[1].rule_id, "TROJAN-INVISIBLE");
        assert_eq!(findings[1].codepoint, "U+200B");
    }

    #[test]
    fn allows_clean_ascii_and_spanish_utf8() {
        let clean = "// Código limpio en español: ñ, á, é, í, ó, ú\nfn main() {}\n";
        assert!(scan_text("src/main.rs", clean).is_empty());
    }
}

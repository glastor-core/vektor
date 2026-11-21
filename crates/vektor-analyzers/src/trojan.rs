//! Trojan Guard: detects Unicode `BiDi` overrides (CVE-2021-42574) and invisible zero-width characters.

use std::path::Path;

use anyhow::Result;
use serde::Serialize;

use crate::Severity;

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
    allow_leading_bom: bool,
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
        '\u{E0000}'..='\u{E007F}' => Some((
            "TROJAN-UNICODE-TAG",
            Severity::Critical,
            "Invisible Unicode Tag character detected (prompt/code smuggling risk)",
        )),
        '\u{2028}' | '\u{2029}' => Some((
            "TROJAN-LINE-SEP",
            Severity::High,
            "Unicode line/paragraph separator detected (line-splitting obfuscation risk)",
        )),
        '\u{001B}' => Some((
            "TROJAN-ANSI-ESC",
            Severity::High,
            "Raw ANSI escape character (U+001B) detected in source",
        )),
        '\u{200B}'
        | '\u{200C}'
        | '\u{200D}'
        | '\u{2060}'..='\u{2064}'
        | '\u{00AD}'
        | '\u{034F}'
        | '\u{180E}'
        | '\u{3164}'
        | '\u{FFA0}'
        | '\u{FE00}'..='\u{FE0F}'
        | '\u{E0100}'..='\u{E01EF}' => Some((
            "TROJAN-INVISIBLE",
            Severity::High,
            "Invisible zero-width or formatting Unicode character detected in source",
        )),
        '\u{FEFF}' if !(allow_leading_bom && is_file_start) => Some((
            "TROJAN-MID-BOM",
            Severity::High,
            "Unexpected UTF-8 BOM (U+FEFF) detected in source",
        )),
        _ => None,
    }
}

/// Scan raw text for Trojan Source `BiDi`, Unicode Tag, and invisible characters.
#[must_use]
pub fn scan_text(source_label: &str, content: &str) -> Vec<TrojanFinding> {
    scan_text_with_options(source_label, content, true)
}

/// Scan raw text with control over whether a leading UTF-8 BOM at byte 0 is allowed.
#[must_use]
pub fn scan_text_with_options(
    source_label: &str,
    content: &str,
    allow_leading_bom: bool,
) -> Vec<TrojanFinding> {
    let mut findings = Vec::new();
    for (line_idx, line) in content.lines().enumerate() {
        for (col_idx, ch) in line.chars().enumerate() {
            let is_file_start = line_idx == 0 && col_idx == 0;
            if let Some((rule_id, severity, message)) =
                classify_dangerous_char(ch, allow_leading_bom, is_file_start)
            {
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
    scan_recursive(target, target, 0, &mut findings)?;
    Ok(findings)
}

fn scan_recursive(
    root: &Path,
    current: &Path,
    depth: usize,
    findings: &mut Vec<TrojanFinding>,
) -> Result<()> {
    if depth > crate::MAX_WALK_DEPTH {
        return Ok(());
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
            scan_recursive(root, &path, depth + 1, findings)?;
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

    #[test]
    fn detects_unicode_tags_line_sep_ansi_and_mid_bom() {
        let with_leading_bom = "\u{FEFF}fn ok() {}";
        assert!(scan_text("src/lib.rs", with_leading_bom).is_empty());
        assert_eq!(
            scan_text_with_options("edit_fragment", with_leading_bom, false).len(),
            1
        );

        let smuggled = "let a = 1;\u{E0001}\u{2028}\u{001B}";
        let findings = scan_text("src/smuggle.rs", smuggled);
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(ids.contains(&"TROJAN-UNICODE-TAG"));
        assert!(ids.contains(&"TROJAN-LINE-SEP"));
        assert!(ids.contains(&"TROJAN-ANSI-ESC"));
    }
}

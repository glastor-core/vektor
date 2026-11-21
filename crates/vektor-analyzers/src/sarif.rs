//! SARIF 2.1.0 report exporter for GitHub Code Scanning integration.

use serde_json::{json, Value};

use crate::gha::GhaFinding;
use crate::secrets::SecretFinding;
use crate::trojan::TrojanFinding;
use crate::Severity;

fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

fn normalize_uri(path: &str) -> String {
    path.replace('\\', "/")
}

/// Build a SARIF 2.1.0 JSON document from secret, Trojan Guard, and GitHub Actions findings.
#[must_use]
pub fn build_sarif_report(
    tool_version: &str,
    secrets: &[SecretFinding],
    trojans: &[TrojanFinding],
    gha: &[GhaFinding],
) -> Value {
    let mut results = Vec::new();

    for f in secrets {
        results.push(json!({
            "ruleId": f.rule_id,
            "level": sarif_level(f.severity),
            "message": {
                "text": format!("{} ({})", f.message, f.redacted_match)
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": { "uri": normalize_uri(&f.file) },
                    "region": { "startLine": f.line.max(1) }
                }
            }]
        }));
    }

    for f in trojans {
        results.push(json!({
            "ruleId": f.rule_id,
            "level": sarif_level(f.severity),
            "message": {
                "text": format!("{} ({})", f.message, f.codepoint)
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": { "uri": normalize_uri(&f.file) },
                    "region": {
                        "startLine": f.line.max(1),
                        "startColumn": f.column.max(1)
                    }
                }
            }]
        }));
    }

    for f in gha {
        results.push(json!({
            "ruleId": f.rule_id,
            "level": sarif_level(f.severity),
            "message": {
                "text": format!("{} Remediation: {}", f.message, f.remediation)
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": { "uri": normalize_uri(&f.file) },
                    "region": { "startLine": f.line.max(1) }
                }
            }]
        }));
    }

    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Vektor",
                    "version": tool_version,
                    "informationUri": "https://github.com/ricsg/vektor"
                }
            },
            "results": results
        }]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_valid_sarif_2_1_0_payload() {
        let trojan = TrojanFinding {
            rule_id: "TROJAN-BIDI".to_string(),
            severity: Severity::Critical,
            file: "src\\lib.rs".to_string(),
            line: 4,
            column: 12,
            codepoint: "U+202E".to_string(),
            message: "BiDi override".to_string(),
        };
        let doc = build_sarif_report("0.1.0", &[], &[trojan], &[]);
        assert_eq!(doc["version"], "2.1.0");
        assert_eq!(doc["runs"][0]["results"][0]["ruleId"], "TROJAN-BIDI");
        assert_eq!(doc["runs"][0]["results"][0]["level"], "error");
        assert_eq!(
            doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
                ["uri"],
            "src/lib.rs"
        );
    }
}

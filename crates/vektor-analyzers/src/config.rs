//! Declarative `vektor.toml` configuration and `.gitignore`/`.vektorignore` matcher.
//!
//! Pure-Rust zero-dependency parser supporting `[audit]`, `[secrets]`, and `[hooks]` sections.

use std::path::Path;

/// Workspace-level Vektor configuration loaded from `vektor.toml` + ignore files.
#[derive(Debug, Clone)]
pub struct VektorConfig {
    /// Whether `.gitignore` patterns at workspace root are honored during scans.
    pub respect_gitignore: bool,
    /// Relative path prefixes, basenames, or `*.ext` patterns to ignore.
    pub ignore_paths: Vec<String>,
    /// Rule IDs (e.g. `SEC-JWT-TOKEN`, `GHA-MISSING-CONCURRENCY`) suppressed project-wide.
    pub disabled_rules: Vec<String>,
    /// Minimum Shannon entropy (bits/char) for generic `SEC-HIGH-ENTROPY` findings.
    pub entropy_threshold: f64,
    /// Stop hook gate mode (`selective`, `full`, or `off`).
    pub stop_gate: String,
    /// Whether a `vektor.toml` file was found and loaded.
    pub loaded_from_file: bool,
}

impl Default for VektorConfig {
    fn default() -> Self {
        Self {
            respect_gitignore: true,
            ignore_paths: Vec::new(),
            disabled_rules: Vec::new(),
            entropy_threshold: 3.5,
            stop_gate: "selective".to_string(),
            loaded_from_file: false,
        }
    }
}

impl VektorConfig {
    /// Load `vektor.toml` (if present) plus `.vektorignore` and `.gitignore` from `root`.
    #[must_use]
    pub fn load(root: &Path) -> Self {
        let base_dir = if root.is_dir() {
            root
        } else {
            root.parent().unwrap_or(root)
        };

        let mut cfg = Self::default();

        let toml_path = base_dir.join("vektor.toml");
        if let Ok(Some(text)) = crate::read_bounded_utf8(&toml_path, 65_536) {
            cfg.apply_toml(&text);
            cfg.loaded_from_file = true;
        }

        // Always honor `.vektorignore`.
        let vektorignore = base_dir.join(".vektorignore");
        if let Ok(Some(text)) = crate::read_bounded_utf8(&vektorignore, 65_536) {
            cfg.ignore_paths.extend(parse_ignore_lines(&text));
        }

        // Honor `.gitignore` when enabled (default: true).
        if cfg.respect_gitignore {
            let gitignore = base_dir.join(".gitignore");
            if let Ok(Some(text)) = crate::read_bounded_utf8(&gitignore, 65_536) {
                cfg.ignore_paths.extend(parse_ignore_lines(&text));
            }
        }

        cfg
    }

    /// Parse a subset of TOML (`[section]`, `key = value`, arrays of strings, booleans, floats).
    pub fn apply_toml(&mut self, text: &str) {
        let mut section = String::new();
        let mut pending_array_key: Option<(String, String)> = None;
        let mut array_buf = String::new();

        for raw_line in text.lines() {
            let line = strip_toml_comment(raw_line).trim();
            if line.is_empty() {
                continue;
            }

            if let Some((sec, key)) = pending_array_key.clone() {
                array_buf.push(' ');
                array_buf.push_str(line);
                if line.contains(']') {
                    self.apply_kv(&sec, &key, &array_buf);
                    pending_array_key = None;
                    array_buf.clear();
                }
                continue;
            }

            if line.starts_with('[') && line.ends_with(']') {
                section = line[1..line.len() - 1].trim().to_ascii_lowercase();
                continue;
            }

            let Some((raw_key, raw_val)) = line.split_once('=') else {
                continue;
            };
            let key = raw_key.trim().to_ascii_lowercase();
            let val = raw_val.trim();

            if val.starts_with('[') && !val.contains(']') {
                pending_array_key = Some((section.clone(), key));
                array_buf = val.to_string();
                continue;
            }

            self.apply_kv(&section, &key, val);
        }
    }

    fn apply_kv(&mut self, section: &str, key: &str, val: &str) {
        match (section, key) {
            ("audit", "respect_gitignore") => {
                if let Some(b) = parse_bool(val) {
                    self.respect_gitignore = b;
                }
            }
            ("audit", "ignore_paths") => {
                self.ignore_paths
                    .extend(parse_string_array(val).iter().map(|s| normalize_pattern(s)));
            }
            ("audit", "disabled_rules") => {
                self.disabled_rules.extend(
                    parse_string_array(val)
                        .into_iter()
                        .map(|s| s.to_ascii_uppercase()),
                );
            }
            ("secrets", "entropy_threshold") => {
                if let Ok(v) = val.parse::<f64>() {
                    if v.is_finite() && (1.0..=8.0).contains(&v) {
                        self.entropy_threshold = v;
                    }
                }
            }
            ("hooks", "stop_gate") => {
                let s = unquote(val).to_ascii_lowercase();
                if matches!(s.as_str(), "selective" | "full" | "off") {
                    self.stop_gate = s;
                }
            }
            _ => {}
        }
    }

    /// Check whether a rule ID is suppressed by `vektor.toml`.
    #[must_use]
    pub fn is_rule_disabled(&self, rule_id: &str) -> bool {
        self.disabled_rules
            .iter()
            .any(|r| r.eq_ignore_ascii_case(rule_id))
    }

    /// Check whether a workspace-relative path matches any configured ignore pattern.
    #[must_use]
    pub fn is_path_ignored(&self, rel_path: &str) -> bool {
        let norm = rel_path.replace('\\', "/");
        let norm = norm.trim_start_matches("./");
        let file_name = Path::new(norm)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(norm);

        self.ignore_paths.iter().any(|pat| {
            let trimmed = pat.trim_end_matches('/');
            if trimmed.is_empty() {
                return false;
            }
            if let Some(ext) = trimmed.strip_prefix("*.") {
                return file_name.ends_with(&format!(".{ext}"));
            }
            if let Some(prefix) = trimmed.strip_suffix("/*") {
                return norm.starts_with(&format!("{prefix}/"));
            }
            norm == trimmed
                || norm.starts_with(&format!("{trimmed}/"))
                || norm.ends_with(&format!("/{trimmed}"))
                || file_name == trimmed
        })
    }

    /// Starter `vektor.toml` template written by `vektor init`.
    #[must_use]
    pub const fn starter_template() -> &'static str {
        r#"# Vektor DevSecOps & Antigravity Hook Configuration
# See: https://github.com/glastor-core/vektor

[audit]
respect_gitignore = true
ignore_paths = [
  "target/",
  "node_modules/",
  "dist/",
  ".vektor/",
]
disabled_rules = []

[secrets]
# Minimum Shannon entropy (bits/char) for generic credential assignments (default: 3.5)
entropy_threshold = 3.5

[hooks]
# Stop quality gate mode: "selective" | "full" | "off"
stop_gate = "selective"
"#
    }
}

fn strip_toml_comment(line: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    for (idx, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_double => escaped = true,
            '"' if !in_single => in_double = !in_double,
            '\'' if !in_double => in_single = !in_single,
            '#' if !in_single && !in_double => return &line[..idx],
            _ => {}
        }
    }
    line
}

fn parse_bool(val: &str) -> Option<bool> {
    match val.trim() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn unquote(val: &str) -> String {
    let trimmed = val.trim();
    if (trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2)
        || (trimmed.starts_with('\'') && trimmed.ends_with('\'') && trimmed.len() >= 2)
    {
        trimmed[1..trimmed.len() - 1].to_string()
    } else {
        trimmed.to_string()
    }
}

fn parse_string_array(val: &str) -> Vec<String> {
    let inner = val
        .trim()
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or("");
    inner
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(unquote)
        .filter(|s| !s.is_empty())
        .collect()
}

fn normalize_pattern(raw: &str) -> String {
    raw.replace('\\', "/")
        .trim_start_matches("./")
        .trim_start_matches('/')
        .to_string()
}

fn parse_ignore_lines(content: &str) -> Vec<String> {
    content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with('!'))
        .map(normalize_pattern)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_vektor_toml_sections_and_multiline_arrays() {
        let toml = r#"
# Project config
[audit]
respect_gitignore = false
ignore_paths = [
  "fixtures/",
  "*.snap",
]
disabled_rules = ["SEC-JWT-TOKEN", "gha-missing-timeout"]

[secrets]
entropy_threshold = 4.0

[hooks]
stop_gate = "full"
"#;
        let mut cfg = VektorConfig::default();
        cfg.apply_toml(toml);
        assert!(!cfg.respect_gitignore);
        assert!(cfg.is_path_ignored("fixtures/test.txt"));
        assert!(cfg.is_path_ignored("src/foo.snap"));
        assert!(!cfg.is_path_ignored("src/main.rs"));
        assert!(cfg.is_rule_disabled("SEC-JWT-TOKEN"));
        assert!(cfg.is_rule_disabled("GHA-MISSING-TIMEOUT"));
        assert!((cfg.entropy_threshold - 4.0).abs() < f64::EPSILON);
        assert_eq!(cfg.stop_gate, "full");
    }

    #[test]
    fn loads_gitignore_and_vektorignore() {
        let dir = std::env::temp_dir().join(format!("vektor-cfg-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(dir.join(".gitignore"), "/coverage/\n*.log\n").expect("gitignore");
        std::fs::write(dir.join(".vektorignore"), "testdata/\n").expect("vektorignore");

        let cfg = VektorConfig::load(&dir);
        assert!(cfg.is_path_ignored("coverage/lcov.info"));
        assert!(cfg.is_path_ignored("debug.log"));
        assert!(cfg.is_path_ignored("testdata/sample.env"));
        assert!(!cfg.is_path_ignored("src/lib.rs"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}

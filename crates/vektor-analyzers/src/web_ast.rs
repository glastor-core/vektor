//! `tree-sitter-typescript` AST extractor for TypeScript (`.ts`), TSX (`.tsx`), and Astro (`.astro`).
//!
//! Parses `.ts`/`.tsx` directly and extracts the `--- ... ---` TypeScript frontmatter of `.astro`
//! components while also flagging risky XSS/code-execution sinks (`set:html`, `dangerouslySetInnerHTML`,
//! `innerHTML`, `eval`).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tree_sitter::{Node, Parser};

use crate::config::VektorConfig;

const SKIP_DIRS: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    ".vektor",
    ".astro",
    "dist",
    "build",
    ".next",
];

/// A single extracted TypeScript / TSX / Astro symbol or security sink.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebSymbol {
    pub file: String,
    pub language: String,
    pub name: String,
    pub kind: String,
    pub exported: bool,
    pub line_start: usize,
    pub line_end: usize,
}

/// Summary report returned when scanning a workspace for TypeScript / Astro AST symbols.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WebAstReport {
    pub file_count: usize,
    pub symbol_count: usize,
    pub exported_count: usize,
    pub sink_count: usize,
    pub symbols: Vec<WebSymbol>,
}

/// Extract TypeScript / TSX / Astro symbols and risky sinks from source text.
pub fn extract_symbols_from_str(
    file_label: &str,
    ext: &str,
    source: &str,
) -> Result<Vec<WebSymbol>> {
    let mut symbols = Vec::new();
    let lower_ext = ext.to_ascii_lowercase();

    let (ts_code, line_offset, use_tsx, lang_label) = if lower_ext == "astro" {
        // Check Astro template body for `set:html` XSS sinks.
        for (idx, line) in source.lines().enumerate() {
            if line.contains("set:html") {
                symbols.push(WebSymbol {
                    file: file_label.to_string(),
                    language: "astro".to_string(),
                    name: "set:html".to_string(),
                    kind: "xss_sink".to_string(),
                    exported: false,
                    line_start: idx + 1,
                    line_end: idx + 1,
                });
            }
        }
        let Some((frontmatter, offset)) = extract_astro_frontmatter(source) else {
            return Ok(symbols);
        };
        (frontmatter, offset, false, "astro")
    } else if lower_ext == "tsx" {
        (source, 0usize, true, "tsx")
    } else {
        (source, 0usize, false, "ts")
    };

    let mut parser = Parser::new();
    let language = if use_tsx {
        tree_sitter_typescript::LANGUAGE_TSX.into()
    } else {
        tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()
    };
    parser
        .set_language(&language)
        .context("Failed to load tree-sitter-typescript grammar")?;

    let tree = parser
        .parse(ts_code, None)
        .context("tree-sitter-typescript failed to parse source")?;

    let bytes = ts_code.as_bytes();
    collect_nodes(
        tree.root_node(),
        bytes,
        file_label,
        lang_label,
        line_offset,
        false,
        &mut symbols,
    );

    Ok(symbols)
}

/// Extract the frontmatter slice between leading `---` fences in an `.astro` file,
/// returning `(frontmatter_code, 0_based_line_offset)`.
fn extract_astro_frontmatter(source: &str) -> Option<(&str, usize)> {
    let mut lines = source.split_inclusive('\n');
    let first = lines.next()?;
    if first.trim() != "---" {
        return None;
    }
    let start_byte = first.len();
    let mut offset = start_byte;
    for line in lines {
        if line.trim() == "---" {
            return Some((&source[start_byte..offset], 1));
        }
        offset += line.len();
    }
    None
}

#[allow(clippy::too_many_lines)]
fn collect_nodes(
    node: Node<'_>,
    bytes: &[u8],
    file_label: &str,
    lang_label: &str,
    line_offset: usize,
    in_export: bool,
    out: &mut Vec<WebSymbol>,
) {
    let kind = node.kind();
    let line_start = node.start_position().row + 1 + line_offset;
    let line_end = node.end_position().row + 1 + line_offset;

    match kind {
        "export_statement" => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                collect_nodes(child, bytes, file_label, lang_label, line_offset, true, out);
            }
            return;
        }
        "function_declaration" => {
            if let Some(name) = child_text_by_field(node, "name", bytes) {
                out.push(WebSymbol {
                    file: file_label.to_string(),
                    language: lang_label.to_string(),
                    name,
                    kind: "function".to_string(),
                    exported: in_export,
                    line_start,
                    line_end,
                });
            }
        }
        "class_declaration" => {
            if let Some(name) = child_text_by_field(node, "name", bytes) {
                out.push(WebSymbol {
                    file: file_label.to_string(),
                    language: lang_label.to_string(),
                    name,
                    kind: "class".to_string(),
                    exported: in_export,
                    line_start,
                    line_end,
                });
            }
        }
        "interface_declaration" => {
            if let Some(name) = child_text_by_field(node, "name", bytes) {
                out.push(WebSymbol {
                    file: file_label.to_string(),
                    language: lang_label.to_string(),
                    name,
                    kind: "interface".to_string(),
                    exported: in_export,
                    line_start,
                    line_end,
                });
            }
        }
        "type_alias_declaration" => {
            if let Some(name) = child_text_by_field(node, "name", bytes) {
                out.push(WebSymbol {
                    file: file_label.to_string(),
                    language: lang_label.to_string(),
                    name,
                    kind: "type".to_string(),
                    exported: in_export,
                    line_start,
                    line_end,
                });
            }
        }
        "enum_declaration" => {
            if let Some(name) = child_text_by_field(node, "name", bytes) {
                out.push(WebSymbol {
                    file: file_label.to_string(),
                    language: lang_label.to_string(),
                    name,
                    kind: "enum".to_string(),
                    exported: in_export,
                    line_start,
                    line_end,
                });
            }
        }
        "lexical_declaration" | "variable_declaration" if in_export => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if child.kind() == "variable_declarator" {
                    if let Some(name) = child_text_by_field(child, "name", bytes) {
                        out.push(WebSymbol {
                            file: file_label.to_string(),
                            language: lang_label.to_string(),
                            name,
                            kind: "const".to_string(),
                            exported: true,
                            line_start,
                            line_end,
                        });
                    }
                }
            }
        }
        "call_expression" => {
            if let Some(func_node) = node.child_by_field_name("function") {
                if let Ok(callee) = func_node.utf8_text(bytes) {
                    if callee == "eval" || callee == "Function" {
                        out.push(WebSymbol {
                            file: file_label.to_string(),
                            language: lang_label.to_string(),
                            name: callee.to_string(),
                            kind: "code_exec_sink".to_string(),
                            exported: false,
                            line_start,
                            line_end,
                        });
                    }
                }
            }
        }
        "property_identifier" | "jsx_attribute" => {
            if let Ok(text) = node.utf8_text(bytes) {
                if text == "innerHTML"
                    || text == "outerHTML"
                    || text.starts_with("dangerouslySetInnerHTML")
                {
                    let sink_name = if text.starts_with("dangerouslySetInnerHTML") {
                        "dangerouslySetInnerHTML"
                    } else {
                        text
                    };
                    out.push(WebSymbol {
                        file: file_label.to_string(),
                        language: lang_label.to_string(),
                        name: sink_name.to_string(),
                        kind: "xss_sink".to_string(),
                        exported: false,
                        line_start,
                        line_end,
                    });
                }
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_nodes(
            child,
            bytes,
            file_label,
            lang_label,
            line_offset,
            false,
            out,
        );
    }
}

fn child_text_by_field(node: Node<'_>, field: &str, bytes: &[u8]) -> Option<String> {
    node.child_by_field_name(field)?
        .utf8_text(bytes)
        .ok()
        .map(ToString::to_string)
}

/// Recursively scan a workspace for `.ts`, `.tsx`, and `.astro` files and extract AST symbols.
pub fn scan_workspace(
    root: &Path,
    name_filter: Option<&str>,
    kind_filter: Option<&str>,
    exported_only: bool,
    limit: usize,
) -> Result<WebAstReport> {
    let cfg = VektorConfig::load(root);
    let mut files = Vec::new();
    collect_web_files(root, root, 0, &cfg, &mut files)?;

    let mut all_symbols = Vec::new();
    for file in &files {
        let Some(text) = crate::read_bounded_utf8(file, crate::MAX_SCAN_FILE_BYTES)? else {
            continue;
        };
        let ext = file.extension().and_then(|e| e.to_str()).unwrap_or("ts");
        let rel = file
            .strip_prefix(root)
            .unwrap_or(file)
            .display()
            .to_string()
            .replace('\\', "/");
        if let Ok(syms) = extract_symbols_from_str(&rel, ext, &text) {
            all_symbols.extend(syms);
        }
    }

    let exported_count = all_symbols.iter().filter(|s| s.exported).count();
    let sink_count = all_symbols
        .iter()
        .filter(|s| s.kind == "xss_sink" || s.kind == "code_exec_sink")
        .count();

    let name_lower = name_filter.map(str::to_ascii_lowercase);
    let filtered: Vec<WebSymbol> = all_symbols
        .into_iter()
        .filter(|s| !exported_only || s.exported)
        .filter(|s| kind_filter.is_none_or(|k| s.kind.eq_ignore_ascii_case(k)))
        .filter(|s| {
            name_lower
                .as_deref()
                .is_none_or(|q| s.name.to_ascii_lowercase().contains(q))
        })
        .take(limit.clamp(1, 500))
        .collect();

    Ok(WebAstReport {
        file_count: files.len(),
        symbol_count: filtered.len(),
        exported_count,
        sink_count,
        symbols: filtered,
    })
}

fn collect_web_files(
    root: &Path,
    current: &Path,
    depth: usize,
    cfg: &VektorConfig,
    out: &mut Vec<PathBuf>,
) -> Result<()> {
    if depth > crate::MAX_WALK_DEPTH {
        return Ok(());
    }
    if let Ok(rel) = current.strip_prefix(root) {
        let rel_str = rel.display().to_string().replace('\\', "/");
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
        let is_web = current.extension().is_some_and(|ext| {
            ext.eq_ignore_ascii_case("ts")
                || ext.eq_ignore_ascii_case("tsx")
                || ext.eq_ignore_ascii_case("astro")
        });
        if is_web {
            out.push(current.to_path_buf());
        }
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
            collect_web_files(root, &path, depth + 1, cfg, out)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_typescript_and_tsx_symbols_and_sinks() {
        let src = r#"
export interface HeroProps {
  title: string;
}
export type Theme = "light" | "dark";
export const VERSION = "1.0";
export function renderHero(props: HeroProps) {
  return <div dangerouslySetInnerHTML={{ __html: props.title }} />;
}
function internalHelper(code: string) {
  return eval(code);
}
"#;
        let syms = extract_symbols_from_str("Hero.tsx", "tsx", src).expect("parse tsx");
        assert!(syms
            .iter()
            .any(|s| s.name == "HeroProps" && s.kind == "interface" && s.exported));
        assert!(syms
            .iter()
            .any(|s| s.name == "Theme" && s.kind == "type" && s.exported));
        assert!(syms
            .iter()
            .any(|s| s.name == "VERSION" && s.kind == "const" && s.exported));
        assert!(syms
            .iter()
            .any(|s| s.name == "renderHero" && s.kind == "function" && s.exported));
        assert!(syms
            .iter()
            .any(|s| s.name == "internalHelper" && !s.exported));
        assert!(syms
            .iter()
            .any(|s| s.name == "dangerouslySetInnerHTML" && s.kind == "xss_sink"));
        assert!(syms
            .iter()
            .any(|s| s.name == "eval" && s.kind == "code_exec_sink"));
    }

    #[test]
    fn extracts_astro_frontmatter_and_set_html_sink() {
        let astro = r"---
export interface Props {
  heading: string;
}
export function formatTitle(s: string): string {
  return s.trim();
}
const { heading } = Astro.props;
---
<section>
  <div set:html={heading} />
</section>
";
        let syms = extract_symbols_from_str("Card.astro", "astro", astro).expect("parse astro");
        assert!(syms
            .iter()
            .any(|s| s.name == "Props" && s.kind == "interface" && s.exported));
        assert!(syms
            .iter()
            .any(|s| s.name == "formatTitle" && s.kind == "function" && s.exported));
        assert!(syms
            .iter()
            .any(|s| s.name == "set:html" && s.kind == "xss_sink"));
    }
}

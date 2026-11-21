//! Incremental Rust AST symbol and `unsafe` extractor powered by `tree-sitter-rust`.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tree_sitter::{Node, Parser};

const SKIP_DIRS: &[&str] = &[".git", "target", "node_modules", ".vektor"];

/// Extracted AST symbol from a Rust source file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RustSymbol {
    pub file: String,
    pub name: String,
    pub kind: String,
    pub visibility: String,
    pub line_start: usize,
    pub line_end: usize,
}

/// Parse a Rust source buffer with `tree-sitter-rust` and extract top-level/nested symbols & `unsafe` blocks.
pub fn extract_symbols(file_label: &str, source: &str) -> Result<Vec<RustSymbol>> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .context("Failed to load tree-sitter-rust grammar")?;

    let tree = parser
        .parse(source, None)
        .context("tree-sitter-rust returned no parse tree")?;

    let mut symbols = Vec::new();
    walk_node(
        tree.root_node(),
        source.as_bytes(),
        file_label,
        &mut symbols,
    );
    Ok(symbols)
}

/// Extract Rust symbols from a single `.rs` file on disk.
pub fn extract_file(root: &Path, file_path: &Path) -> Result<Vec<RustSymbol>> {
    let source = std::fs::read_to_string(file_path)
        .with_context(|| format!("Failed to read {}", file_path.display()))?;
    let label = file_path
        .strip_prefix(root)
        .unwrap_or(file_path)
        .display()
        .to_string()
        .replace('\\', "/");
    extract_symbols(&label, &source)
}

/// Recursively collect all `.rs` files under `root` (skipping `target/`, `.git/`, etc.).
pub fn collect_rust_files(root: &Path) -> Result<Vec<std::path::PathBuf>> {
    let mut files = Vec::new();
    collect_recursive(root, &mut files)?;
    Ok(files)
}

fn collect_recursive(dir: &Path, out: &mut Vec<std::path::PathBuf>) -> Result<()> {
    if dir.is_file() {
        if dir
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("rs"))
        {
            out.push(dir.to_path_buf());
        }
        return Ok(());
    }

    if !dir.is_dir() {
        return Ok(());
    }

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if SKIP_DIRS.contains(&name) {
                    continue;
                }
            }
        }
        collect_recursive(&path, out)?;
    }
    Ok(())
}

fn walk_node(node: Node<'_>, src: &[u8], file_label: &str, out: &mut Vec<RustSymbol>) {
    let kind = node.kind();
    let line_start = node.start_position().row + 1;
    let line_end = node.end_position().row + 1;

    match kind {
        "function_item" => {
            let name = child_text(node, "name", src).unwrap_or_else(|| "<anon>".to_string());
            let is_unsafe = has_child_kind(node, "function_modifiers")
                && node_text(node, src).starts_with("unsafe")
                || child_by_kind(node, "function_modifiers")
                    .is_some_and(|m| node_text(m, src).contains("unsafe"));
            out.push(RustSymbol {
                file: file_label.to_string(),
                name,
                kind: if is_unsafe { "unsafe_fn" } else { "fn" }.to_string(),
                visibility: extract_visibility(node, src),
                line_start,
                line_end,
            });
        }
        "struct_item" | "enum_item" | "trait_item" | "mod_item" | "const_item" | "static_item" => {
            let name = child_text(node, "name", src).unwrap_or_else(|| "<anon>".to_string());
            let short_kind = kind.trim_end_matches("_item");
            out.push(RustSymbol {
                file: file_label.to_string(),
                name,
                kind: short_kind.to_string(),
                visibility: extract_visibility(node, src),
                line_start,
                line_end,
            });
        }
        "impl_item" => {
            let ty = child_text(node, "type", src).unwrap_or_else(|| "<type>".to_string());
            let name = match child_text(node, "trait", src) {
                Some(tr) => format!("{tr} for {ty}"),
                None => ty,
            };
            out.push(RustSymbol {
                file: file_label.to_string(),
                name,
                kind: "impl".to_string(),
                visibility: String::new(),
                line_start,
                line_end,
            });
        }
        "unsafe_block" => {
            out.push(RustSymbol {
                file: file_label.to_string(),
                name: format!("unsafe@{line_start}"),
                kind: "unsafe_block".to_string(),
                visibility: String::new(),
                line_start,
                line_end,
            });
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_node(child, src, file_label, out);
    }
}

fn child_text(node: Node<'_>, field: &str, src: &[u8]) -> Option<String> {
    node.child_by_field_name(field)
        .map(|n| node_text(n, src).trim().to_string())
}

fn child_by_kind<'a>(node: Node<'a>, target_kind: &str) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    let found = node.children(&mut cursor).find(|c| c.kind() == target_kind);
    found
}

fn has_child_kind(node: Node<'_>, target_kind: &str) -> bool {
    child_by_kind(node, target_kind).is_some()
}

fn extract_visibility(node: Node<'_>, src: &[u8]) -> String {
    child_by_kind(node, "visibility_modifier")
        .map(|n| node_text(n, src).trim().to_string())
        .unwrap_or_default()
}

fn node_text<'a>(node: Node<'_>, src: &'a [u8]) -> &'a str {
    node.utf8_text(src).unwrap_or_default()
}

/// Public API item extracted for AST `SemVer` / breaking-change diffing (inspired by `glastor-core/specter`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicApiItem {
    pub file: String,
    pub kind: String,
    pub name: String,
    pub signature: String,
}

/// `SemVer` / API contract diff report between two revisions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiDiffReport {
    pub recommended_bump: String,
    pub breaking_changes: Vec<String>,
    pub additive_changes: Vec<String>,
}

/// Extract public (`pub` without `pub(crate)`/`pub(super)`) Rust API items from a source file.
pub fn extract_public_api(file_label: &str, source: &str) -> Result<Vec<PublicApiItem>> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .context("Failed to load tree-sitter-rust grammar")?;
    let tree = parser
        .parse(source, None)
        .context("tree-sitter-rust returned no parse tree")?;

    let mut items = Vec::new();
    collect_public_items(tree.root_node(), source.as_bytes(), file_label, &mut items);
    Ok(items)
}

fn collect_public_items(
    node: Node<'_>,
    src: &[u8],
    file_label: &str,
    out: &mut Vec<PublicApiItem>,
) {
    let kind = node.kind();
    if matches!(
        kind,
        "function_item" | "struct_item" | "enum_item" | "trait_item" | "const_item" | "static_item"
    ) {
        let vis = extract_visibility(node, src);
        // Only externally visible `pub` items (exclude `pub(crate)` / `pub(super)` / private).
        if vis == "pub" {
            let name = child_text(node, "name", src).unwrap_or_else(|| "<anon>".to_string());
            let short_kind = kind.trim_end_matches("_item").to_string();
            let signature = build_public_signature(node, src, kind);
            out.push(PublicApiItem {
                file: file_label.to_string(),
                kind: short_kind,
                name,
                signature,
            });
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() != "block" {
            collect_public_items(child, src, file_label, out);
        }
    }
}

fn normalize_ws(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn build_public_signature(node: Node<'_>, src: &[u8], kind: &str) -> String {
    let raw_text = node_text(node, src);
    let header = normalize_ws(raw_text.split('{').next().unwrap_or(raw_text));

    match kind {
        "enum_item" => {
            if let Some(body) = child_by_kind(node, "enum_variant_list") {
                let mut variants = Vec::new();
                let mut cursor = body.walk();
                for child in body.children(&mut cursor) {
                    if child.kind() == "enum_variant" {
                        variants.push(normalize_ws(node_text(child, src)));
                    }
                }
                return format!("{header} {{ {} }}", variants.join(", "));
            }
            header
        }
        "struct_item" => {
            if let Some(body) = child_by_kind(node, "field_declaration_list") {
                let mut pub_fields = Vec::new();
                let mut cursor = body.walk();
                for child in body.children(&mut cursor) {
                    if child.kind() == "field_declaration"
                        && extract_visibility(child, src) == "pub"
                    {
                        pub_fields.push(normalize_ws(node_text(child, src)));
                    }
                }
                return format!("{header} {{ {} }}", pub_fields.join(", "));
            }
            normalize_ws(raw_text)
        }
        _ => header,
    }
}

/// Compare two public API snapshots and compute `SemVer` impact (`major` / `minor` / `patch`).
#[must_use]
pub fn diff_public_api(before: &[PublicApiItem], after: &[PublicApiItem]) -> ApiDiffReport {
    let before_map: BTreeMap<(String, String, String), &PublicApiItem> = before
        .iter()
        .map(|i| ((i.file.clone(), i.kind.clone(), i.name.clone()), i))
        .collect();
    let after_map: BTreeMap<(String, String, String), &PublicApiItem> = after
        .iter()
        .map(|i| ((i.file.clone(), i.kind.clone(), i.name.clone()), i))
        .collect();

    let mut breaking_changes = Vec::new();
    let mut additive_changes = Vec::new();

    for (key, old_item) in &before_map {
        match after_map.get(key) {
            None => breaking_changes.push(format!(
                "Removed public {} `{}` in {}",
                old_item.kind, old_item.name, old_item.file
            )),
            Some(new_item) if old_item.signature != new_item.signature => {
                breaking_changes.push(format!(
                    "Changed signature of public {} `{}` in {}: `{}` -> `{}`",
                    old_item.kind,
                    old_item.name,
                    old_item.file,
                    old_item.signature,
                    new_item.signature
                ));
            }
            Some(_) => {}
        }
    }

    for (key, new_item) in &after_map {
        if !before_map.contains_key(key) {
            additive_changes.push(format!(
                "Added public {} `{}` in {}",
                new_item.kind, new_item.name, new_item.file
            ));
        }
    }

    let recommended_bump = if !breaking_changes.is_empty() {
        "major"
    } else if !additive_changes.is_empty() {
        "minor"
    } else {
        "patch"
    };

    ApiDiffReport {
        recommended_bump: recommended_bump.to_string(),
        breaking_changes,
        additive_changes,
    }
}

/// Compare the current workspace's public Rust API against a git revision (e.g. `HEAD`).
pub fn diff_workspace_against_git(root: &Path, git_ref: &str) -> Result<ApiDiffReport> {
    let files = collect_rust_files(root)?;
    let mut all_rel_paths = std::collections::BTreeSet::new();
    let mut after = Vec::new();

    for file in files {
        let rel = file
            .strip_prefix(root)
            .unwrap_or(&file)
            .display()
            .to_string()
            .replace('\\', "/");
        all_rel_paths.insert(rel.clone());

        if let Ok(current_src) = std::fs::read_to_string(&file) {
            if let Ok(items) = extract_public_api(&rel, &current_src) {
                after.extend(items);
            }
        }
    }

    // Also include `.rs` files present in `git_ref` so deleted files are detected as breaking removals.
    if let Ok(out) = Command::new("git")
        .args(["ls-tree", "-r", "--name-only", git_ref])
        .current_dir(root)
        .output()
    {
        if out.status.success() {
            if let Ok(listing) = String::from_utf8(out.stdout) {
                for line in listing.lines() {
                    let trimmed = line.trim();
                    if Path::new(trimmed)
                        .extension()
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("rs"))
                    {
                        all_rel_paths.insert(trimmed.replace('\\', "/"));
                    }
                }
            }
        }
    }

    let mut before = Vec::new();
    for rel in all_rel_paths {
        let spec = format!("{git_ref}:{rel}");
        if let Ok(out) = Command::new("git")
            .args(["show", &spec])
            .current_dir(root)
            .output()
        {
            if out.status.success() {
                if let Ok(old_src) = String::from_utf8(out.stdout) {
                    if let Ok(items) = extract_public_api(&rel, &old_src) {
                        before.extend(items);
                    }
                }
            }
        }
    }

    Ok(diff_public_api(&before, &after))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_structs_traits_impls_fns_and_unsafe() {
        let code = r"
pub struct Engine;
pub trait Runner {
    fn run(&self);
}
impl Runner for Engine {
    fn run(&self) {
        unsafe {
            let _ = 1 + 1;
        }
    }
}
pub unsafe fn raw_op() {}
";
        let syms = extract_symbols("src/lib.rs", code).expect("parse rust");
        let summary: Vec<(&str, &str)> = syms
            .iter()
            .map(|s| (s.kind.as_str(), s.name.as_str()))
            .collect();

        assert!(summary.contains(&("struct", "Engine")));
        assert!(summary.contains(&("trait", "Runner")));
        assert!(summary.contains(&("impl", "Runner for Engine")));
        assert!(summary.contains(&("fn", "run")));
        assert!(summary.contains(&("unsafe_block", "unsafe@8")));
        assert!(summary.contains(&("unsafe_fn", "raw_op")));
    }

    #[test]
    fn detects_breaking_and_additive_public_api_changes() {
        let v1 = "pub fn connect(host: &str) -> bool { true }\npub struct OldConfig;\n";
        let v2 = "pub fn connect(host: &str, port: u16) -> bool { true }\npub struct NewConfig;\n";

        let before = extract_public_api("src/lib.rs", v1).expect("v1");
        let after = extract_public_api("src/lib.rs", v2).expect("v2");
        let diff = diff_public_api(&before, &after);

        assert_eq!(diff.recommended_bump, "major");
        assert_eq!(diff.breaking_changes.len(), 2);
        assert_eq!(diff.additive_changes.len(), 1);
    }

    #[test]
    fn detects_struct_pub_field_and_enum_variant_breaking_changes() {
        let v1 = r"
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    internal: bool,
}
pub enum Mode {
    Fast,
    Safe,
}
";
        let v2 = r"
pub struct ServerConfig {
    pub host: String,
    pub port: u32,
    internal: usize,
}
pub enum Mode {
    Fast,
}
";
        let before = extract_public_api("src/lib.rs", v1).expect("v1");
        let after = extract_public_api("src/lib.rs", v2).expect("v2");
        let diff = diff_public_api(&before, &after);

        assert_eq!(diff.recommended_bump, "major");
        assert_eq!(diff.breaking_changes.len(), 2);
    }
}

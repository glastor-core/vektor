use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::UNIX_EPOCH;

use anyhow::Result;
use serde_json::{json, Value};
use vektor_analyzers::config::VektorConfig;
use vektor_analyzers::{cargo, gha, rust_ast, secrets, trojan, Severity, MAX_SCAN_FILE_BYTES};
use vektor_core::hooks::{
    HookEvent, InvocationHookOutput, PostToolUseInput, PreToolUseInput, PreToolUseOutput,
    StopInput, StopOutput,
};
use vektor_state::StateStore;

/// Maximum hook JSON input size (16 MiB) to prevent memory exhaustion.
const MAX_HOOK_INPUT_BYTES: u64 = 16 * 1024 * 1024;

/// Execute a synchronous Antigravity hook, reading JSON from `reader` and writing JSON to `writer`.
pub(crate) fn run<R: Read, W: Write>(event: HookEvent, reader: R, mut writer: W) -> Result<()> {
    let mut raw_bytes = Vec::new();
    reader
        .take(MAX_HOOK_INPUT_BYTES.saturating_add(1))
        .read_to_end(&mut raw_bytes)?;

    #[allow(clippy::cast_possible_truncation)]
    let oversized = raw_bytes.len() > MAX_HOOK_INPUT_BYTES as usize;

    let output: Value = if oversized {
        eprintln!("vektor hook input exceeded maximum allowed size ({MAX_HOOK_INPUT_BYTES} bytes)");
        match event {
            HookEvent::PreToolUse => serde_json::to_value(PreToolUseOutput::deny(
                "Vektor safety gate: PreToolUse hook payload exceeded size limit (fail-closed).",
            ))?,
            HookEvent::Stop => serde_json::to_value(StopOutput::allow_stop())?,
            _ => json!({}),
        }
    } else {
        let raw = String::from_utf8_lossy(&raw_bytes);
        dispatch_event(event, &raw)?
    };

    serde_json::to_writer(&mut writer, &output)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

fn dispatch_event(event: HookEvent, raw: &str) -> Result<Value> {
    match event {
        HookEvent::PreToolUse => match serde_json::from_str::<PreToolUseInput>(raw) {
            Ok(input) => Ok(serde_json::to_value(evaluate_pre_tool_use(&input))?),
            Err(err) => {
                eprintln!("vektor PreToolUse JSON parse error: {err}");
                Ok(serde_json::to_value(PreToolUseOutput::deny(
                    "Vektor safety gate: malformed PreToolUse hook payload (fail-closed).",
                ))?)
            }
        },
        HookEvent::PostToolUse => {
            match serde_json::from_str::<PostToolUseInput>(raw) {
                Ok(input) => handle_post_tool_use(&input),
                Err(err) => eprintln!("vektor PostToolUse JSON parse error: {err}"),
            }
            Ok(json!({}))
        }
        HookEvent::SessionStart | HookEvent::PreInvocation | HookEvent::PostInvocation => {
            Ok(serde_json::to_value(InvocationHookOutput::default())?)
        }
        HookEvent::Stop => match serde_json::from_str::<StopInput>(raw) {
            Ok(input) => Ok(serde_json::to_value(evaluate_stop(&input))?),
            Err(err) => {
                eprintln!("vektor Stop JSON parse error: {err}");
                Ok(serde_json::to_value(StopOutput::allow_stop())?)
            }
        },
    }
}

/// Deterministic `<5ms` safety policy for `PreToolUse` across commands and file writes/edits.
fn evaluate_pre_tool_use(input: &PreToolUseInput) -> PreToolUseOutput {
    match input.tool_call.name.as_str() {
        "run_command" => evaluate_run_command(&input.tool_call.args),
        "write_file" => evaluate_file_mutation(
            input.tool_call.args.get("Path").and_then(Value::as_str),
            input.tool_call.args.get("Content").and_then(Value::as_str),
            true,
        ),
        "edit_file" => evaluate_edit_file(&input.tool_call.args),
        _ => PreToolUseOutput::allow(),
    }
}

/// Simulate applying `Target` -> `Replacement` to the existing file (bounded) so split-secret,
/// mid-file BOM, and GHA context bypasses cannot evade `PreToolUse` scanning.
fn evaluate_edit_file(args: &Value) -> PreToolUseOutput {
    let path_str = args.get("Path").and_then(Value::as_str);
    let replacement = args.get("Replacement").and_then(Value::as_str);
    let target = args.get("Target").and_then(Value::as_str);

    let Some(repl) = replacement else {
        return PreToolUseOutput::allow();
    };

    if let (Some(path), Some(tgt)) = (path_str, target) {
        if !tgt.is_empty() {
            if let Some(existing) = read_file_bounded_for_hook(Path::new(path)) {
                if existing.contains(tgt) {
                    let simulated = existing.replace(tgt, repl);
                    return evaluate_file_mutation(Some(path), Some(&simulated), true);
                }
            }
        }
    }

    // Fallback: scan replacement fragment with leading BOM disallowed.
    evaluate_file_mutation(path_str, Some(repl), false)
}

fn read_file_bounded_for_hook(path: &Path) -> Option<String> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return None;
    }
    let file = File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.take(MAX_SCAN_FILE_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .ok()?;
    #[allow(clippy::cast_possible_truncation)]
    if bytes.len() > MAX_SCAN_FILE_BYTES as usize || bytes.contains(&0) {
        return None;
    }
    String::from_utf8(bytes).ok()
}

/// Incrementally re-index edited `.rs` files into `SQLite` WAL and mark them dirty for `Stop`.
fn handle_post_tool_use(input: &PostToolUseInput) {
    if input.error.is_some() {
        return;
    }
    if input.tool_call.name != "write_file" && input.tool_call.name != "edit_file" {
        return;
    }
    let Some(path_str) = input.tool_call.args.get("Path").and_then(Value::as_str) else {
        return;
    };
    let file_path = PathBuf::from(path_str);
    if !file_path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("rs"))
        || !file_path.is_file()
    {
        return;
    }

    let Some(root) = resolve_workspace_root(&input.common.workspace_paths, &input.common.cwd)
    else {
        return;
    };
    if !root.join("Cargo.toml").is_file() {
        return;
    }

    let mut store = match StateStore::open_workspace(&root) {
        Ok(s) => s,
        Err(err) => {
            eprintln!("vektor PostToolUse failed to open state DB: {err}");
            return;
        }
    };

    let rel = file_path
        .strip_prefix(&root)
        .unwrap_or(&file_path)
        .display()
        .to_string()
        .replace('\\', "/");

    #[allow(clippy::cast_possible_wrap)]
    let mtime = std::fs::metadata(&file_path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs() as i64);

    match rust_ast::extract_file(&root, &file_path) {
        Ok(symbols) => {
            if let Err(err) = store.replace_file_symbols(&rel, mtime, &symbols) {
                eprintln!("vektor PostToolUse AST index update failed for {rel}: {err}");
            }
        }
        Err(err) => eprintln!("vektor PostToolUse AST extraction failed for {rel}: {err}"),
    }

    if let Err(err) = store.mark_dirty_file(&rel) {
        eprintln!("vektor PostToolUse failed to mark dirty file {rel}: {err}");
    }
}

/// Configurable `Stop` quality gate: verifies `cargo check --offline` when `.rs` files changed.
fn evaluate_stop(input: &StopInput) -> StopOutput {
    if input.continuation_active || input.termination_reason != "NO_TOOL_CALL" {
        return StopOutput::allow_stop();
    }

    let env_gate = std::env::var("VEKTOR_STOP_GATE").ok();
    if env_gate
        .as_deref()
        .is_some_and(|v| v.eq_ignore_ascii_case("off") || v == "0")
    {
        return StopOutput::allow_stop();
    }

    let Some(root) = resolve_workspace_root(&input.common.workspace_paths, &input.common.cwd)
    else {
        return StopOutput::allow_stop();
    };
    if !root.join("Cargo.toml").is_file() {
        return StopOutput::allow_stop();
    }

    let gate_mode = env_gate.as_deref().map_or_else(
        || VektorConfig::load(&root).stop_gate,
        str::to_ascii_lowercase,
    );
    if gate_mode == "off" || gate_mode == "0" {
        return StopOutput::allow_stop();
    }

    let gate_mode = env_gate.as_deref().map_or_else(
        || VektorConfig::load(&root).stop_gate,
        str::to_ascii_lowercase,
    );
    if gate_mode == "off" || gate_mode == "0" {
        return StopOutput::allow_stop();
    }

    let store = match StateStore::open_workspace(&root) {
        Ok(s) => s,
        Err(err) => {
            eprintln!("vektor Stop gate failed to open state DB: {err}");
            return StopOutput::allow_stop();
        }
    };
    let dirty = match store.list_dirty_files() {
        Ok(list) => list,
        Err(err) => {
            eprintln!("vektor Stop gate failed to read dirty files: {err}");
            return StopOutput::allow_stop();
        }
    };
    if dirty.is_empty() {
        return StopOutput::allow_stop();
    }

    let affected = if gate_mode == "full" {
        Vec::new()
    } else {
        match cargo::affected_workspace_crates(&root, &dirty, true) {
            Ok(crates) => crates,
            Err(err) => {
                eprintln!("vektor Stop gate affected-crate solver fallback (--workspace): {err}");
                Vec::new()
            }
        }
    };

    let mut cmd = Command::new("cargo");
    cmd.arg("check").arg("--offline");
    if affected.is_empty() {
        cmd.arg("--workspace");
    } else {
        for crate_name in &affected {
            cmd.arg("-p").arg(crate_name);
        }
    }

    match cmd.current_dir(&root).output() {
        Ok(res) if res.status.success() => {
            if let Err(err) = store.clear_dirty_files() {
                eprintln!("vektor Stop gate failed to clear dirty files: {err}");
            }
            StopOutput::allow_stop()
        }
        Ok(res) => {
            let stderr = String::from_utf8_lossy(&res.stderr);
            let snippet: String = stderr.lines().take(12).collect::<Vec<_>>().join("\n");
            let scope = if affected.is_empty() {
                "--workspace".to_string()
            } else {
                affected.join(", ")
            };
            StopOutput::force_continue(format!(
                "Vektor Stop quality gate: `cargo check` failed for [{scope}] after editing {} Rust file(s). Fix compilation errors before finishing:\n{snippet}",
                dirty.len()
            ))
        }
        Err(err) => {
            eprintln!("vektor Stop gate failed to execute cargo check: {err}");
            StopOutput::allow_stop()
        }
    }
}

fn resolve_workspace_root(workspace_paths: &[String], cwd: &str) -> Option<PathBuf> {
    workspace_paths
        .first()
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        .or_else(|| (!cwd.is_empty()).then(|| PathBuf::from(cwd)))
        .or_else(|| std::env::current_dir().ok())
}

fn evaluate_run_command(args: &Value) -> PreToolUseOutput {
    let cmd = args
        .get("CommandLine")
        .and_then(Value::as_str)
        .unwrap_or_default();

    // 1. Scan for Trojan Source / invisible chars first so obfuscated commands cannot bypass gates.
    let trojan_hits = trojan::scan_text_with_options("run_command", cmd, false);
    if let Some(hit) = trojan_hits.first() {
        return PreToolUseOutput::deny(format!(
            "Vektor Trojan Guard [{}]: {} ({}) detected in command line.",
            hit.rule_id, hit.message, hit.codepoint
        ));
    }

    // 2. Inspect each shell segment with tokenized matching.
    for segment in split_shell_segments(cmd) {
        let tokens = tokenize_shell_segment(segment);
        if is_force_push_to_protected_branch(&tokens) {
            return PreToolUseOutput::deny(
                "Vektor safety gate: force-pushing to main/master is blocked.",
            );
        }
        if is_destructive_root_deletion(&tokens) {
            return PreToolUseOutput::deny(
                "Vektor safety gate: destructive root deletion blocked.",
            );
        }
    }

    // 3. Secret scan on command line with inline `vektor:ignore` disabled.
    let secret_hits = secrets::scan_text_with_options("run_command", cmd, false);
    if let Some(hit) = secret_hits.first() {
        return PreToolUseOutput::deny(format!(
            "Vektor safety gate [{}]: {} ({}) detected in command line.",
            hit.rule_id, hit.message, hit.redacted_match
        ));
    }

    PreToolUseOutput::allow()
}

fn evaluate_file_mutation(
    path: Option<&str>,
    content: Option<&str>,
    allow_leading_bom: bool,
) -> PreToolUseOutput {
    let Some(text) = content else {
        return PreToolUseOutput::allow();
    };
    let label = path.unwrap_or("<buffer>");

    let trojan_hits = trojan::scan_text_with_options(label, text, allow_leading_bom);
    if let Some(hit) = trojan_hits.first() {
        return PreToolUseOutput::deny(format!(
            "Vektor Trojan Guard [{}]: {} ({}) at line {}:{}.",
            hit.rule_id, hit.message, hit.codepoint, hit.line, hit.column
        ));
    }

    let secret_hits = secrets::scan_text(label, text);
    if let Some(hit) = secret_hits.first() {
        return PreToolUseOutput::deny(format!(
            "Vektor secret guard [{}]: {} at line {} ({}). Use environment variables or a secret manager instead.",
            hit.rule_id, hit.message, hit.line, hit.redacted_match
        ));
    }

    if is_github_workflow_path(label) {
        let gha_hits = gha::lint_workflow_content(label, text);
        if let Some(crit) = gha_hits.iter().find(|f| f.severity == Severity::Critical) {
            return PreToolUseOutput::deny(format!(
                "Vektor GHA security gate [{}]: {} (line {}). {}",
                crit.rule_id, crit.message, crit.line, crit.remediation
            ));
        }
        if let Some(high) = gha_hits.iter().find(|f| f.severity == Severity::High) {
            return PreToolUseOutput::ask(format!(
                "Vektor GHA warning [{}]: {} (line {}). {}",
                high.rule_id, high.message, high.line, high.remediation
            ));
        }
    }

    PreToolUseOutput::allow()
}

fn is_github_workflow_path(path: &str) -> bool {
    let normalized = path.replace('\\', "/").to_ascii_lowercase();
    normalized.contains(".github/workflows/")
        && Path::new(&normalized)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("yml") || ext.eq_ignore_ascii_case("yaml"))
}

fn split_shell_segments(cmd: &str) -> Vec<&str> {
    cmd.split([';', '|', '&', '\n', '\r'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect()
}

fn tokenize_shell_segment(segment: &str) -> Vec<String> {
    segment
        .split_whitespace()
        .map(|tok| tok.trim_matches(['"', '\'']).to_ascii_lowercase())
        .filter(|tok| !tok.is_empty())
        .collect()
}

fn is_force_push_to_protected_branch(tokens: &[String]) -> bool {
    let Some(first) = tokens.first() else {
        return false;
    };
    let bin = Path::new(first)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(first);
    if bin != "git" && bin != "git.exe" {
        return false;
    }

    // Walk past global git flags (`-C <dir>`, `-c <k=v>`, `--git-dir <dir>`, etc.).
    let mut idx = 1usize;
    while idx < tokens.len() {
        let tok = tokens[idx].as_str();
        if tok == "push" {
            break;
        }
        if matches!(tok, "-c" | "--git-dir" | "--work-tree" | "--namespace") {
            idx += 2;
        } else if tok.starts_with('-') {
            idx += 1;
        } else {
            return false;
        }
    }

    if tokens.get(idx).map(String::as_str) != Some("push") {
        return false;
    }

    let push_args = &tokens[idx + 1..];
    let mut is_force = false;
    let mut targets_protected = false;

    for arg in push_args {
        if matches!(
            arg.as_str(),
            "--force" | "--force-with-lease" | "--force-if-includes"
        ) || arg.starts_with("--force-with-lease=")
            || (arg.starts_with('-') && !arg.starts_with("--") && arg[1..].contains('f'))
        {
            is_force = true;
            continue;
        }
        if arg.starts_with('+') {
            is_force = true;
        }
        let branch_ref = arg.trim_start_matches('+');
        let target = branch_ref.rsplit(':').next().unwrap_or(branch_ref);
        if matches!(
            target,
            "main" | "master" | "refs/heads/main" | "refs/heads/master"
        ) {
            targets_protected = true;
        }
    }

    is_force && targets_protected
}

fn is_destructive_root_deletion(tokens: &[String]) -> bool {
    let Some(first) = tokens.first() else {
        return false;
    };
    let bin = Path::new(first)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(first);

    match bin {
        "rm" | "rm.exe" => {
            let mut recursive = false;
            let mut force = false;
            let mut hits_root = false;
            for arg in &tokens[1..] {
                if arg == "--recursive" {
                    recursive = true;
                } else if arg == "--force" {
                    force = true;
                } else if arg.starts_with('-') && !arg.starts_with("--") {
                    if arg[1..].contains('r') {
                        recursive = true;
                    }
                    if arg[1..].contains('f') {
                        force = true;
                    }
                } else if is_root_target(arg) {
                    hits_root = true;
                }
            }
            recursive && force && hits_root
        }
        "remove-item" | "ri" | "rm-item" => {
            let has_recurse = tokens.iter().any(|t| t == "-recurse" || t == "-r");
            let has_force = tokens.iter().any(|t| t == "-force" || t == "-fo");
            let hits_root = tokens[1..].iter().any(|t| is_root_target(t));
            has_recurse && has_force && hits_root
        }
        "rd" | "rmdir" => {
            let has_s = tokens.iter().any(|t| t == "/s");
            let hits_root = tokens[1..].iter().any(|t| is_root_target(t));
            has_s && hits_root
        }
        _ => false,
    }
}

fn is_root_target(arg: &str) -> bool {
    let norm = arg.replace('\\', "/");
    if matches!(norm.as_str(), "/" | "/*" | "~" | "~/" | "$home" | "${home}") {
        return true;
    }
    // Windows drive root: `c:`, `c:/`, `c:/*`
    let bytes = norm.as_bytes();
    bytes.len() >= 2
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(&norm[2..], "" | "/" | "/*")
}

#[cfg(test)]
mod tests {
    use super::*;
    use vektor_core::hooks::{PreToolDecision, ToolCallPayload};

    #[test]
    fn blocks_force_push_variants_to_main_and_allows_normal_commands() {
        for cmd in [
            "git push --force origin main",
            "git -C repo push -f origin main",
            "git push origin +main",
            "git push origin +HEAD:refs/heads/main",
            "git.exe push -fu origin HEAD:master",
        ] {
            let input = PreToolUseInput {
                tool_call: ToolCallPayload {
                    id: "1".to_string(),
                    name: "run_command".to_string(),
                    args: json!({ "CommandLine": cmd }),
                },
                ..Default::default()
            };
            assert_eq!(
                evaluate_pre_tool_use(&input).decision,
                PreToolDecision::Deny,
                "expected deny for: {cmd}"
            );
        }

        let safe = PreToolUseInput {
            tool_call: ToolCallPayload {
                id: "2".to_string(),
                name: "run_command".to_string(),
                args: json!({ "CommandLine": "cargo test --workspace" }),
            },
            ..Default::default()
        };
        assert_eq!(
            evaluate_pre_tool_use(&safe).decision,
            PreToolDecision::Allow
        );
    }

    #[test]
    fn blocks_destructive_root_deletion_variants_and_allows_subpaths() {
        for cmd in [
            "rm -rf /",
            "rm -fr /*",
            "rm -r -f /",
            "Remove-Item -Recurse -Force C:\\",
            "rd /s /q C:\\",
        ] {
            let input = PreToolUseInput {
                tool_call: ToolCallPayload {
                    id: "d".to_string(),
                    name: "run_command".to_string(),
                    args: json!({ "CommandLine": cmd }),
                },
                ..Default::default()
            };
            assert_eq!(
                evaluate_pre_tool_use(&input).decision,
                PreToolDecision::Deny,
                "expected deny for: {cmd}"
            );
        }

        let safe = PreToolUseInput {
            tool_call: ToolCallPayload {
                id: "ok".to_string(),
                name: "run_command".to_string(),
                args: json!({ "CommandLine": "rm -rf /tmp/vektor-build" }),
            },
            ..Default::default()
        };
        assert_eq!(
            evaluate_pre_tool_use(&safe).decision,
            PreToolDecision::Allow
        );
    }

    #[test]
    fn blocks_secret_in_write_file_and_run_command_even_with_vektor_ignore() {
        let token = ["ghp_", "1234567890", "abcdefghijklmnoPQRST"].concat();
        let fake_token = format!("const TOKEN: &str = \"{token}\";");
        let input = PreToolUseInput {
            tool_call: ToolCallPayload {
                id: "3".to_string(),
                name: "write_file".to_string(),
                args: json!({
                    "Path": "src/config.rs",
                    "Content": fake_token
                }),
            },
            ..Default::default()
        };
        assert_eq!(
            evaluate_pre_tool_use(&input).decision,
            PreToolDecision::Deny
        );

        let cmd_bypass = PreToolUseInput {
            tool_call: ToolCallPayload {
                id: "3b".to_string(),
                name: "run_command".to_string(),
                args: json!({
                    "CommandLine": format!("curl -H 'Authorization: token {token}' https://api.github.com # vektor:ignore")
                }),
            },
            ..Default::default()
        };
        assert_eq!(
            evaluate_pre_tool_use(&cmd_bypass).decision,
            PreToolDecision::Deny
        );
    }

    #[test]
    fn blocks_split_secret_via_edit_file_simulation() {
        let dir = std::env::temp_dir().join(format!("vektor-edit-sim-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let file = dir.join("cfg.rs");
        std::fs::write(&file, "const K: &str = \"ghp_1234567890_PLACEHOLDER\";\n").expect("write");

        let input = PreToolUseInput {
            tool_call: ToolCallPayload {
                id: "edit1".to_string(),
                name: "edit_file".to_string(),
                args: json!({
                    "Path": file.display().to_string(),
                    "Target": "_PLACEHOLDER",
                    "Replacement": "abcdefghijklmnoPQRST"
                }),
            },
            ..Default::default()
        };
        assert_eq!(
            evaluate_pre_tool_use(&input).decision,
            PreToolDecision::Deny
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fails_closed_on_malformed_pre_tool_use_json() {
        let mut out = Vec::new();
        run(
            HookEvent::PreToolUse,
            b"{malformed-json".as_slice(),
            &mut out,
        )
        .expect("run hook");
        let val: Value = serde_json::from_slice(&out).expect("valid json output");
        assert_eq!(val["decision"], "deny");
    }

    #[test]
    fn blocks_critical_gha_injection_and_asks_on_unpinned() {
        let critical_input = PreToolUseInput {
            tool_call: ToolCallPayload {
                id: "4".to_string(),
                name: "write_file".to_string(),
                args: json!({
                    "Path": "C:\\repo\\.github\\workflows\\ci.yml",
                    "Content": "on: [issues]\njobs:\n  t:\n    steps:\n      - run: echo \"${{ github.event.issue.title }}\"\n"
                }),
            },
            ..Default::default()
        };
        assert_eq!(
            evaluate_pre_tool_use(&critical_input).decision,
            PreToolDecision::Deny
        );

        let high_input = PreToolUseInput {
            tool_call: ToolCallPayload {
                id: "5".to_string(),
                name: "write_file".to_string(),
                args: json!({
                    "Path": ".github/workflows/ci.yml",
                    "Content": "on: [push]\npermissions:\n  contents: read\njobs:\n  t:\n    steps:\n      - uses: actions/checkout@v4\n"
                }),
            },
            ..Default::default()
        };
        assert_eq!(
            evaluate_pre_tool_use(&high_input).decision,
            PreToolDecision::Ask
        );
    }

    #[test]
    fn stop_gate_respects_continuation_active() {
        let input = StopInput {
            continuation_active: true,
            termination_reason: "NO_TOOL_CALL".to_string(),
            ..Default::default()
        };
        assert_eq!(evaluate_stop(&input).decision, "allow");
    }
}

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::UNIX_EPOCH;

use anyhow::Result;
use serde_json::{json, Value};
use vektor_analyzers::{cargo, gha, rust_ast, secrets, trojan, Severity};
use vektor_core::hooks::{
    HookEvent, InvocationHookOutput, PostToolUseInput, PreToolUseInput, PreToolUseOutput,
    StopInput, StopOutput,
};
use vektor_state::StateStore;

/// Execute a synchronous Antigravity hook, reading JSON from `reader` and writing JSON to `writer`.
pub fn run<R: Read, W: Write>(event: HookEvent, mut reader: R, mut writer: W) -> Result<()> {
    let mut raw = String::new();
    reader.read_to_string(&mut raw)?;

    let output: Value = match event {
        HookEvent::PreToolUse => {
            let input: PreToolUseInput = serde_json::from_str(&raw).unwrap_or_default();
            serde_json::to_value(evaluate_pre_tool_use(&input))?
        }
        HookEvent::PostToolUse => {
            let input: PostToolUseInput = serde_json::from_str(&raw).unwrap_or_default();
            handle_post_tool_use(&input);
            json!({})
        }
        HookEvent::SessionStart | HookEvent::PreInvocation | HookEvent::PostInvocation => {
            serde_json::to_value(InvocationHookOutput::default())?
        }
        HookEvent::Stop => {
            let input: StopInput = serde_json::from_str(&raw).unwrap_or_default();
            serde_json::to_value(evaluate_stop(&input))?
        }
    };

    serde_json::to_writer(&mut writer, &output)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

/// Deterministic `<5ms` safety policy for `PreToolUse` across commands and file writes/edits.
fn evaluate_pre_tool_use(input: &PreToolUseInput) -> PreToolUseOutput {
    match input.tool_call.name.as_str() {
        "run_command" => evaluate_run_command(&input.tool_call.args),
        "write_file" => evaluate_file_mutation(
            input.tool_call.args.get("Path").and_then(Value::as_str),
            input.tool_call.args.get("Content").and_then(Value::as_str),
        ),
        "edit_file" => evaluate_file_mutation(
            input.tool_call.args.get("Path").and_then(Value::as_str),
            input
                .tool_call
                .args
                .get("Replacement")
                .and_then(Value::as_str),
        ),
        _ => PreToolUseOutput::allow(),
    }
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

    let Ok(mut store) = StateStore::open_workspace(&root) else {
        return;
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

    if let Ok(symbols) = rust_ast::extract_file(&root, &file_path) {
        let _ = store.replace_file_symbols(&rel, mtime, &symbols);
    }
    let _ = store.mark_dirty_file(&rel);
}

/// Configurable `Stop` quality gate: verifies `cargo check --workspace --offline` when `.rs` files changed.
fn evaluate_stop(input: &StopInput) -> StopOutput {
    // Never trigger a loop if a Stop hook already forced continuation in this turn.
    if input.continuation_active || input.termination_reason != "NO_TOOL_CALL" {
        return StopOutput::allow_stop();
    }

    if std::env::var("VEKTOR_STOP_GATE").is_ok_and(|v| v.eq_ignore_ascii_case("off") || v == "0") {
        return StopOutput::allow_stop();
    }

    let Some(root) = resolve_workspace_root(&input.common.workspace_paths, &input.common.cwd)
    else {
        return StopOutput::allow_stop();
    };
    if !root.join("Cargo.toml").is_file() {
        return StopOutput::allow_stop();
    }

    let Ok(store) = StateStore::open_workspace(&root) else {
        return StopOutput::allow_stop();
    };
    let dirty = store.list_dirty_files().unwrap_or_default();
    if dirty.is_empty() {
        return StopOutput::allow_stop();
    }

    // Vortex-style selective check: only check workspace crates affected by edited `.rs` files.
    let affected = cargo::affected_workspace_crates(&root, &dirty, true).unwrap_or_default();
    let mut cmd = Command::new("cargo");
    cmd.arg("check").arg("--offline");
    if affected.is_empty() {
        cmd.arg("--workspace");
    } else {
        for crate_name in &affected {
            cmd.arg("-p").arg(crate_name);
        }
    }

    let output = cmd.current_dir(&root).output();

    match output {
        Ok(res) if res.status.success() => {
            let _ = store.clear_dirty_files();
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
        Err(_) => StopOutput::allow_stop(),
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
    let lower = cmd.to_ascii_lowercase();

    if is_force_push_to_protected_branch(&lower) {
        return PreToolUseOutput::deny(
            "Vektor safety gate: force-pushing to main/master is blocked.",
        );
    }

    if lower.contains("rm -rf /") || lower.contains("rm -rf /*") {
        return PreToolUseOutput::deny("Vektor safety gate: destructive root deletion blocked.");
    }

    let secret_hits = secrets::scan_text("run_command", cmd);
    if let Some(hit) = secret_hits.first() {
        return PreToolUseOutput::deny(format!(
            "Vektor safety gate [{}]: {} ({}) detected in command line.",
            hit.rule_id, hit.message, hit.redacted_match
        ));
    }

    PreToolUseOutput::allow()
}

fn evaluate_file_mutation(path: Option<&str>, content: Option<&str>) -> PreToolUseOutput {
    let Some(text) = content else {
        return PreToolUseOutput::allow();
    };
    let label = path.unwrap_or("<buffer>");

    let trojan_hits = trojan::scan_text(label, text);
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

fn is_force_push_to_protected_branch(lower_cmd: &str) -> bool {
    let is_git_push = lower_cmd.contains("git push");
    let is_force =
        lower_cmd.contains("--force") || lower_cmd.contains(" -f ") || lower_cmd.ends_with(" -f");
    let targets_protected = lower_cmd.contains(" main") || lower_cmd.contains(" master");
    is_git_push && is_force && targets_protected
}

#[cfg(test)]
mod tests {
    use super::*;
    use vektor_core::hooks::{PreToolDecision, ToolCallPayload};

    #[test]
    fn blocks_force_push_to_main() {
        let input = PreToolUseInput {
            tool_call: ToolCallPayload {
                id: "1".to_string(),
                name: "run_command".to_string(),
                args: json!({ "CommandLine": "git push --force origin main" }),
            },
            ..Default::default()
        };

        let out = evaluate_pre_tool_use(&input);
        assert_eq!(out.decision, PreToolDecision::Deny);
    }

    #[test]
    fn allows_normal_cargo_test() {
        let input = PreToolUseInput {
            tool_call: ToolCallPayload {
                id: "2".to_string(),
                name: "run_command".to_string(),
                args: json!({ "CommandLine": "cargo test --workspace" }),
            },
            ..Default::default()
        };

        let out = evaluate_pre_tool_use(&input);
        assert_eq!(out.decision, PreToolDecision::Allow);
    }

    #[test]
    fn blocks_secret_in_write_file() {
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

        let out = evaluate_pre_tool_use(&input);
        assert_eq!(out.decision, PreToolDecision::Deny);
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

//! Multi-agent hook protocol adapters (`antigravity`, `claude-code`, `cursor`, `codex`)
//! and workspace scaffolding generators for `vektor init --target <agent>`.

use std::path::Path;

use anyhow::Result;
use clap::ValueEnum;
use serde_json::{json, Value};
use vektor_core::hooks::{
    CommonHookInput, PostToolUseInput, PreToolDecision, PreToolUseInput, PreToolUseOutput,
    StopInput, StopOutput, ToolCallPayload,
};

/// Hook protocol wire format selected via `vektor hook <event> --adapter <adapter>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub(crate) enum HookAdapter {
    /// Detect protocol format automatically from stdin JSON keys.
    #[default]
    Auto,
    /// Native Antigravity camelCase protojson (`toolCall`, `decision`).
    Antigravity,
    /// Claude Code `snake_case` JSON (`tool_name`, `tool_input`, `hookSpecificOutput`).
    ClaudeCode,
    /// Cursor hooks JSON (`workspace_roots`, `command`, `permission`).
    Cursor,
    /// Codex CLI / standard JSON hooks.
    Codex,
}

/// Target agent ecosystem for `vektor init --target <target>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum InitTarget {
    Antigravity,
    ClaudeCode,
    Cursor,
    Codex,
    GitHooks,
    All,
}

/// Resolved concrete wire adapter after `Auto` detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResolvedAdapter {
    Antigravity,
    ClaudeCode,
    Cursor,
}

pub(crate) fn resolve_adapter(requested: HookAdapter, raw: &Value) -> ResolvedAdapter {
    match requested {
        HookAdapter::Antigravity | HookAdapter::Codex => ResolvedAdapter::Antigravity,
        HookAdapter::ClaudeCode => ResolvedAdapter::ClaudeCode,
        HookAdapter::Cursor => ResolvedAdapter::Cursor,
        HookAdapter::Auto => {
            if raw.get("tool_name").is_some() || raw.get("tool_input").is_some() {
                ResolvedAdapter::ClaudeCode
            } else if raw.get("workspace_roots").is_some()
                || (raw.get("toolCall").is_none()
                    && (raw.get("command").is_some() || raw.get("file_path").is_some()))
            {
                ResolvedAdapter::Cursor
            } else {
                ResolvedAdapter::Antigravity
            }
        }
    }
}

/// Normalize any supported agent's `PreToolUse` JSON payload into Vektor's canonical contract.
pub(crate) fn normalize_pre_tool_use(
    adapter: ResolvedAdapter,
    raw: &Value,
) -> Result<PreToolUseInput> {
    match adapter {
        ResolvedAdapter::Antigravity => Ok(serde_json::from_value(raw.clone())?),
        ResolvedAdapter::ClaudeCode => Ok(PreToolUseInput {
            tool_call: map_claude_tool(raw),
            step_idx: 0,
            common: CommonHookInput {
                conversation_id: str_field(raw, "session_id"),
                cwd: str_field(raw, "cwd"),
                workspace_paths: vec_from_nonempty(str_field(raw, "cwd")),
                hook_event_name: str_field(raw, "hook_event_name"),
                ..Default::default()
            },
        }),
        ResolvedAdapter::Cursor => Ok(PreToolUseInput {
            tool_call: map_cursor_tool(raw),
            step_idx: 0,
            common: CommonHookInput {
                conversation_id: str_field(raw, "conversation_id"),
                workspace_paths: string_array(raw, "workspace_roots"),
                cwd: string_array(raw, "workspace_roots")
                    .into_iter()
                    .next()
                    .unwrap_or_default(),
                hook_event_name: str_field(raw, "hook_event_name"),
                ..Default::default()
            },
        }),
    }
}

/// Normalize any supported agent's `PostToolUse` JSON payload into Vektor's canonical contract.
pub(crate) fn normalize_post_tool_use(
    adapter: ResolvedAdapter,
    raw: &Value,
) -> Result<PostToolUseInput> {
    match adapter {
        ResolvedAdapter::Antigravity => Ok(serde_json::from_value(raw.clone())?),
        ResolvedAdapter::ClaudeCode => Ok(PostToolUseInput {
            tool_call: map_claude_tool(raw),
            step_idx: 0,
            error: raw
                .get("tool_response")
                .and_then(|r| r.get("is_error"))
                .and_then(Value::as_bool)
                .filter(|&e| e)
                .map(|_| "tool_error".to_string()),
            common: CommonHookInput {
                conversation_id: str_field(raw, "session_id"),
                cwd: str_field(raw, "cwd"),
                workspace_paths: vec_from_nonempty(str_field(raw, "cwd")),
                hook_event_name: str_field(raw, "hook_event_name"),
                ..Default::default()
            },
        }),
        ResolvedAdapter::Cursor => Ok(PostToolUseInput {
            tool_call: map_cursor_tool(raw),
            step_idx: 0,
            error: None,
            common: CommonHookInput {
                conversation_id: str_field(raw, "conversation_id"),
                workspace_paths: string_array(raw, "workspace_roots"),
                cwd: string_array(raw, "workspace_roots")
                    .into_iter()
                    .next()
                    .unwrap_or_default(),
                hook_event_name: str_field(raw, "hook_event_name"),
                ..Default::default()
            },
        }),
    }
}

/// Normalize any supported agent's `Stop` JSON payload into Vektor's canonical contract.
pub(crate) fn normalize_stop(adapter: ResolvedAdapter, raw: &Value) -> Result<StopInput> {
    match adapter {
        ResolvedAdapter::Antigravity => Ok(serde_json::from_value(raw.clone())?),
        ResolvedAdapter::ClaudeCode => Ok(StopInput {
            termination_reason: "NO_TOOL_CALL".to_string(),
            continuation_active: raw
                .get("stop_hook_active")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            common: CommonHookInput {
                conversation_id: str_field(raw, "session_id"),
                cwd: str_field(raw, "cwd"),
                workspace_paths: vec_from_nonempty(str_field(raw, "cwd")),
                ..Default::default()
            },
            ..Default::default()
        }),
        ResolvedAdapter::Cursor => Ok(StopInput {
            termination_reason: "NO_TOOL_CALL".to_string(),
            common: CommonHookInput {
                conversation_id: str_field(raw, "conversation_id"),
                workspace_paths: string_array(raw, "workspace_roots"),
                cwd: string_array(raw, "workspace_roots")
                    .into_iter()
                    .next()
                    .unwrap_or_default(),
                ..Default::default()
            },
            ..Default::default()
        }),
    }
}

/// Format a `PreToolUseOutput` for the target agent's expected JSON schema.
pub(crate) fn format_pre_tool_use_output(
    adapter: ResolvedAdapter,
    out: &PreToolUseOutput,
) -> Result<Value> {
    match adapter {
        ResolvedAdapter::Antigravity => Ok(serde_json::to_value(out)?),
        ResolvedAdapter::ClaudeCode => {
            let decision = match out.decision {
                PreToolDecision::Allow => "allow",
                PreToolDecision::Deny => "deny",
                PreToolDecision::Ask | PreToolDecision::ForceAsk => "ask",
            };
            let mut specific = json!({
                "hookEventName": "PreToolUse",
                "permissionDecision": decision,
            });
            if let Some(reason) = &out.reason {
                specific["permissionDecisionReason"] = json!(reason);
            }
            Ok(json!({ "hookSpecificOutput": specific }))
        }
        ResolvedAdapter::Cursor => {
            let permission = match out.decision {
                PreToolDecision::Allow => "allow",
                PreToolDecision::Deny => "deny",
                PreToolDecision::Ask | PreToolDecision::ForceAsk => "ask",
            };
            let mut val = json!({ "permission": permission });
            if let Some(reason) = &out.reason {
                val["user_message"] = json!(reason);
                val["agent_message"] = json!(reason);
            }
            Ok(val)
        }
    }
}

/// Format a `StopOutput` for the target agent's expected JSON schema.
pub(crate) fn format_stop_output(adapter: ResolvedAdapter, out: &StopOutput) -> Result<Value> {
    match adapter {
        ResolvedAdapter::Antigravity | ResolvedAdapter::Cursor => Ok(serde_json::to_value(out)?),
        ResolvedAdapter::ClaudeCode => {
            if out.decision == "continue" {
                Ok(json!({
                    "decision": "block",
                    "reason": out.reason.as_deref().unwrap_or("Vektor Stop quality gate failed.")
                }))
            } else {
                Ok(json!({}))
            }
        }
    }
}

fn map_claude_tool(raw: &Value) -> ToolCallPayload {
    let tool_name = str_field(raw, "tool_name");
    let input = raw.get("tool_input").cloned().unwrap_or_else(|| json!({}));

    let (canonical_name, args) = match tool_name.as_str() {
        "Bash" => (
            "run_command",
            json!({
                "CommandLine": input.get("command").and_then(Value::as_str).unwrap_or_default()
            }),
        ),
        "Write" => (
            "write_file",
            json!({
                "Path": input.get("file_path").and_then(Value::as_str).unwrap_or_default(),
                "Content": input.get("content").and_then(Value::as_str).unwrap_or_default()
            }),
        ),
        "Edit" => (
            "edit_file",
            json!({
                "Path": input.get("file_path").and_then(Value::as_str).unwrap_or_default(),
                "Target": input.get("old_string").and_then(Value::as_str).unwrap_or_default(),
                "Replacement": input.get("new_string").and_then(Value::as_str).unwrap_or_default()
            }),
        ),
        "Read" => (
            "read_file",
            json!({
                "Path": input.get("file_path").and_then(Value::as_str).unwrap_or_default()
            }),
        ),
        other => (other, input),
    };

    ToolCallPayload {
        id: str_field(raw, "tool_use_id"),
        name: canonical_name.to_string(),
        args,
    }
}

fn map_cursor_tool(raw: &Value) -> ToolCallPayload {
    if let Some(cmd) = raw.get("command").and_then(Value::as_str) {
        return ToolCallPayload {
            id: str_field(raw, "generation_id"),
            name: "run_command".to_string(),
            args: json!({ "CommandLine": cmd }),
        };
    }

    if let Some(path) = raw.get("file_path").and_then(Value::as_str) {
        let event = str_field(raw, "hook_event_name").to_ascii_lowercase();
        if event.contains("read") {
            return ToolCallPayload {
                id: str_field(raw, "generation_id"),
                name: "read_file".to_string(),
                args: json!({ "Path": path }),
            };
        }
        if let Some(content) = raw.get("content").and_then(Value::as_str) {
            return ToolCallPayload {
                id: str_field(raw, "generation_id"),
                name: "write_file".to_string(),
                args: json!({ "Path": path, "Content": content }),
            };
        }
        if let Some(first_edit) = raw
            .get("edits")
            .and_then(Value::as_array)
            .and_then(|arr| arr.first())
        {
            return ToolCallPayload {
                id: str_field(raw, "generation_id"),
                name: "edit_file".to_string(),
                args: json!({
                    "Path": path,
                    "Target": first_edit.get("old_string").and_then(Value::as_str).unwrap_or_default(),
                    "Replacement": first_edit.get("new_string").and_then(Value::as_str).unwrap_or_default()
                }),
            };
        }
        return ToolCallPayload {
            id: str_field(raw, "generation_id"),
            name: "read_file".to_string(),
            args: json!({ "Path": path }),
        };
    }

    ToolCallPayload::default()
}

fn str_field(raw: &Value, key: &str) -> String {
    raw.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn string_array(raw: &Value, key: &str) -> Vec<String> {
    raw.get(key)
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn vec_from_nonempty(s: String) -> Vec<String> {
    if s.is_empty() {
        Vec::new()
    } else {
        vec![s]
    }
}

// ---------------------------------------------------------------------------
// Multi-Agent Workspace Config Generators (`vektor init --target ...`)
// ---------------------------------------------------------------------------

pub(crate) fn write_claude_code_config(root: &Path, force: bool) -> Result<String> {
    let dir = root.join(".claude");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("settings.json");
    if path.exists() && !force {
        return Ok(format!(
            "Skipped {} (already exists; use --force to overwrite)",
            path.display()
        ));
    }

    let settings = json!({
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash|Write|Edit",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "vektor hook pre-tool-use --adapter claude-code"
                        }
                    ]
                }
            ],
            "PostToolUse": [
                {
                    "matcher": "Read|Bash|Write|Edit",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "vektor hook post-tool-use --adapter claude-code"
                        }
                    ]
                }
            ],
            "Stop": [
                {
                    "hooks": [
                        {
                            "type": "command",
                            "command": "vektor hook stop --adapter claude-code"
                        }
                    ]
                }
            ]
        }
    });

    std::fs::write(
        &path,
        format!("{}\n", serde_json::to_string_pretty(&settings)?),
    )?;
    Ok(format!(
        "Created Claude Code hooks config at {}",
        path.display()
    ))
}

pub(crate) fn write_cursor_config(root: &Path, force: bool) -> Result<Vec<String>> {
    let dir = root.join(".cursor");
    std::fs::create_dir_all(&dir)?;
    let mut messages = Vec::new();

    let hooks_path = dir.join("hooks.json");
    if hooks_path.exists() && !force {
        messages.push(format!(
            "Skipped {} (already exists; use --force to overwrite)",
            hooks_path.display()
        ));
    } else {
        let hooks = json!({
            "version": 1,
            "hooks": {
                "beforeShellExecution": [
                    { "command": "vektor hook pre-tool-use --adapter cursor" }
                ],
                "afterFileEdit": [
                    { "command": "vektor hook post-tool-use --adapter cursor" }
                ],
                "beforeReadFile": [
                    { "command": "vektor hook post-tool-use --adapter cursor" }
                ]
            }
        });
        std::fs::write(
            &hooks_path,
            format!("{}\n", serde_json::to_string_pretty(&hooks)?),
        )?;
        messages.push(format!(
            "Created Cursor hooks config at {}",
            hooks_path.display()
        ));
    }

    let mcp_path = dir.join("mcp.json");
    if mcp_path.exists() && !force {
        messages.push(format!(
            "Skipped {} (already exists; use --force to overwrite)",
            mcp_path.display()
        ));
    } else {
        let mcp = json!({
            "mcpServers": {
                "vektor": {
                    "command": "vektor",
                    "args": ["mcp"]
                }
            }
        });
        std::fs::write(
            &mcp_path,
            format!("{}\n", serde_json::to_string_pretty(&mcp)?),
        )?;
        messages.push(format!(
            "Created Cursor MCP config at {}",
            mcp_path.display()
        ));
    }

    Ok(messages)
}

pub(crate) fn write_codex_config(root: &Path, force: bool) -> Result<String> {
    let dir = root.join(".codex");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("config.toml");
    if path.exists() && !force {
        return Ok(format!(
            "Skipped {} (already exists; use --force to overwrite)",
            path.display()
        ));
    }

    let toml = "# Vektor MCP server configuration for Codex CLI\n[mcp_servers.vektor]\ncommand = \"vektor\"\nargs = [\"mcp\"]\n";
    std::fs::write(&path, toml)?;
    Ok(format!("Created Codex MCP config at {}", path.display()))
}

pub(crate) fn write_git_pre_commit_hook(root: &Path, force: bool) -> Result<String> {
    let hooks_dir = root.join(".git").join("hooks");
    if !hooks_dir.is_dir() {
        return Ok(format!(
            "Skipped git-hooks (no `.git/hooks` directory found under {})",
            root.display()
        ));
    }
    let path = hooks_dir.join("pre-commit");
    if path.exists() && !force {
        return Ok(format!(
            "Skipped {} (already exists; use --force to overwrite)",
            path.display()
        ));
    }

    let script = "#!/bin/sh\n# Installed by `vektor init --target git-hooks`\nexec vektor audit --staged --fail-on high\n";
    std::fs::write(&path, script)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&path)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms)?;
    }
    Ok(format!(
        "Installed Git pre-commit hook at {}",
        path.display()
    ))
}

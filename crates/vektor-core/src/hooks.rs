//! Antigravity lifecycle hook contracts (`camelCase` protojson).
//!
//! Reference: Antigravity Customization System (`hooks.json`).

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Supported Antigravity hook lifecycle events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookEvent {
    SessionStart,
    PreToolUse,
    PostToolUse,
    PreInvocation,
    PostInvocation,
    Stop,
}

/// Common fields sent by Antigravity on stdin for every hook event.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommonHookInput {
    #[serde(default)]
    pub conversation_id: String,
    #[serde(default)]
    pub workspace_paths: Vec<String>,
    #[serde(default)]
    pub transcript_path: String,
    #[serde(default)]
    pub artifact_directory_path: String,
    #[serde(default)]
    pub model_name: String,
    #[serde(default)]
    pub last_user_input: String,
    #[serde(default)]
    pub hook_event_name: String,
    #[serde(default)]
    pub cwd: String,
}

/// Tool call metadata included in `PreToolUse` and `PostToolUse`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolCallPayload {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub args: Value,
}

/// Input payload for `PreToolUse`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreToolUseInput {
    #[serde(default)]
    pub tool_call: ToolCallPayload,
    #[serde(default)]
    pub step_idx: u64,
    #[serde(flatten)]
    pub common: CommonHookInput,
}

/// Decision returned by `PreToolUse`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreToolDecision {
    Allow,
    Deny,
    Ask,
    ForceAsk,
}

/// Output payload for `PreToolUse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreToolUseOutput {
    pub decision: PreToolDecision,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_overrides: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overwrite: Option<Value>,
}

impl PreToolUseOutput {
    #[must_use]
    pub fn allow() -> Self {
        Self {
            decision: PreToolDecision::Allow,
            reason: None,
            permission_overrides: None,
            overwrite: None,
        }
    }

    #[must_use]
    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            decision: PreToolDecision::Deny,
            reason: Some(reason.into()),
            permission_overrides: None,
            overwrite: None,
        }
    }

    #[must_use]
    pub fn ask(reason: impl Into<String>) -> Self {
        Self {
            decision: PreToolDecision::Ask,
            reason: Some(reason.into()),
            permission_overrides: None,
            overwrite: None,
        }
    }
}

/// Input payload for `PostToolUse`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PostToolUseInput {
    #[serde(default)]
    pub tool_call: ToolCallPayload,
    #[serde(default)]
    pub step_idx: u64,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(flatten)]
    pub common: CommonHookInput,
}

/// Step injected by `SessionStart`, `PreInvocation`, or `PostInvocation`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum InjectStep {
    SystemMessage {
        #[serde(rename = "systemMessage")]
        system_message: String,
    },
    UserMessage(String),
}

/// Output payload for `SessionStart`, `PreInvocation`, and `PostInvocation`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvocationHookOutput {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inject_steps: Vec<InjectStep>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub termination_behavior: String,
}

/// Input payload for `Stop`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StopInput {
    #[serde(default)]
    pub execution_num: u64,
    #[serde(default)]
    pub termination_reason: String,
    #[serde(default)]
    pub error: String,
    #[serde(default)]
    pub fully_idle: bool,
    #[serde(default)]
    pub continuation_active: bool,
    #[serde(flatten)]
    pub common: CommonHookInput,
}

/// Output payload for `Stop`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StopOutput {
    pub decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl StopOutput {
    #[must_use]
    pub fn allow_stop() -> Self {
        Self {
            decision: "allow".to_string(),
            reason: None,
        }
    }

    #[must_use]
    pub fn force_continue(reason: impl Into<String>) -> Self {
        Self {
            decision: "continue".to_string(),
            reason: Some(reason.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserializes_pre_tool_use_camel_case() {
        let raw = r#"{
            "conversationId": "conv-123",
            "workspacePaths": ["C:/Users/dev/project"],
            "cwd": "C:/Users/dev/project",
            "hookEventName": "PreToolUse",
            "stepIdx": 7,
            "toolCall": {
                "id": "toolu_01",
                "name": "run_command",
                "args": { "CommandLine": "cargo test" }
            }
        }"#;

        let parsed: PreToolUseInput = serde_json::from_str(raw).expect("valid PreToolUse JSON");
        assert_eq!(parsed.common.conversation_id, "conv-123");
        assert_eq!(parsed.step_idx, 7);
        assert_eq!(parsed.tool_call.name, "run_command");
        assert_eq!(
            parsed.tool_call.args["CommandLine"].as_str(),
            Some("cargo test")
        );
    }

    #[test]
    fn serializes_deny_output_cleanly() {
        let out = PreToolUseOutput::deny("Blocked force push to main");
        let val = serde_json::to_value(&out).expect("serialize");
        assert_eq!(val["decision"], "deny");
        assert_eq!(val["reason"], "Blocked force push to main");
        assert!(val.get("overwrite").is_none());
    }
}

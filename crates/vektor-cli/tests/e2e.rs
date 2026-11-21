use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::Value;

fn vektor_bin() -> &'static str {
    env!("CARGO_BIN_EXE_vektor")
}

#[test]
fn e2e_mcp_stdio_initialize_list_and_health() {
    let mut child = Command::new(vektor_bin())
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn vektor mcp");

    {
        let stdin = child.stdin.as_mut().expect("stdin");
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{}}}}"#
        )
        .expect("write init");
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","method":"notifications/initialized","params":{{}}}}"#
        )
        .expect("write notif");
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{{}}}}"#
        )
        .expect("write list");
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"vektor_health","arguments":{{}}}}}}"#
        )
        .expect("write call");
    }

    let output = child.wait_with_output().expect("wait vektor mcp");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(
        lines.len(),
        3,
        "expected 3 responses (notification has none)"
    );

    let init: Value = serde_json::from_str(lines[0]).expect("parse init");
    assert_eq!(init["result"]["serverInfo"]["name"], "vektor");

    let list: Value = serde_json::from_str(lines[1]).expect("parse list");
    let tools = list["result"]["tools"].as_array().expect("tools array");
    assert_eq!(tools.len(), 13);

    let health: Value = serde_json::from_str(lines[2]).expect("parse health");
    assert_eq!(health["result"]["isError"], false);
    let text = health["result"]["content"][0]["text"]
        .as_str()
        .expect("health text");
    assert!(text.contains("\"status\": \"ok\""));
}

#[test]
fn e2e_hook_pre_tool_use_blocks_force_push_and_allows_cargo_test() {
    let deny_payload = r#"{
        "hookEventName": "PreToolUse",
        "toolCall": {
            "id": "call_1",
            "name": "run_command",
            "args": { "CommandLine": "git push --force origin main" }
        }
    }"#;

    let mut deny_child = Command::new(vektor_bin())
        .args(["hook", "pre-tool-use"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn hook deny");
    deny_child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(deny_payload.as_bytes())
        .expect("write");
    let deny_out = deny_child.wait_with_output().expect("wait");
    assert!(deny_out.status.success());
    let deny_json: Value = serde_json::from_slice(&deny_out.stdout).expect("json");
    assert_eq!(deny_json["decision"], "deny");

    let allow_payload = r#"{
        "hookEventName": "PreToolUse",
        "toolCall": {
            "id": "call_2",
            "name": "run_command",
            "args": { "CommandLine": "cargo test --workspace" }
        }
    }"#;

    let mut allow_child = Command::new(vektor_bin())
        .args(["hook", "pre-tool-use"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn hook allow");
    allow_child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(allow_payload.as_bytes())
        .expect("write");
    let allow_out = allow_child.wait_with_output().expect("wait");
    assert!(allow_out.status.success());
    let allow_json: Value = serde_json::from_slice(&allow_out.stdout).expect("json");
    assert_eq!(allow_json["decision"], "allow");
}

#[test]
fn e2e_audit_sarif_and_fail_on_threshold() {
    let dir = std::env::temp_dir().join("vektor-e2e-audit-test");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");

    let token = ["ghp_", "1234567890", "abcdefghijklmnoPQRST"].concat();
    std::fs::write(
        dir.join("leak.rs"),
        format!("const T: &str = \"{token}\";\n"),
    )
    .expect("write");

    let out = Command::new(vektor_bin())
        .args(["audit", "--path"])
        .arg(&dir)
        .args(["--format", "sarif", "--fail-on", "high"])
        .output()
        .expect("run vektor audit");

    assert!(
        !out.status.success(),
        "expected non-zero exit when critical secret meets --fail-on high"
    );

    let sarif: Value = serde_json::from_slice(&out.stdout).expect("valid SARIF JSON");
    assert_eq!(sarif["version"], "2.1.0");
    let results = sarif["runs"][0]["results"]
        .as_array()
        .expect("results array");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0]["ruleId"], "SEC-GITHUB-TOKEN");

    let _ = std::fs::remove_dir_all(&dir);
}

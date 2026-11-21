use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{json, Value};

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
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{{"name":"vektor_team_roster","arguments":{{}}}}}}"#
        )
        .expect("write roster");
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
        4,
        "expected 4 responses (notification has none)"
    );

    let init: Value = serde_json::from_str(lines[0]).expect("parse init");
    assert_eq!(init["result"]["serverInfo"]["name"], "vektor");

    let list: Value = serde_json::from_str(lines[1]).expect("parse list");
    let tools = list["result"]["tools"].as_array().expect("tools array");
    assert_eq!(tools.len(), 14);

    let health: Value = serde_json::from_str(lines[2]).expect("parse health");
    assert_eq!(health["result"]["isError"], false);
    let text = health["result"]["content"][0]["text"]
        .as_str()
        .expect("health text");
    assert!(text.contains("\"status\": \"ok\""));

    let roster: Value = serde_json::from_str(lines[3]).expect("parse roster");
    assert_eq!(roster["result"]["isError"], false);
    let roster_text = roster["result"]["content"][0]["text"]
        .as_str()
        .expect("roster text");
    let roster_json: Value = serde_json::from_str(roster_text).expect("roster json");
    let experts = roster_json["experts"].as_array().expect("experts array");
    assert_eq!(experts.len(), 7);
    assert!(roster_text.contains("astro-expert"));
    assert!(roster_text.contains("markdown-docs-expert"));
}

#[test]
fn e2e_hook_pre_tool_use_blocks_force_push_malformed_json_and_allows_cargo_test() {
    let run_hook = |payload: &str| -> Value {
        let mut child = Command::new(vektor_bin())
            .args(["hook", "pre-tool-use"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn hook");
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(payload.as_bytes())
            .expect("write");
        let out = child.wait_with_output().expect("wait");
        assert!(out.status.success());
        serde_json::from_slice(&out.stdout).expect("json")
    };

    let deny_json = run_hook(
        r#"{
            "hookEventName": "PreToolUse",
            "toolCall": {
                "id": "call_1",
                "name": "run_command",
                "args": { "CommandLine": "git push --force origin main" }
            }
        }"#,
    );
    assert_eq!(deny_json["decision"], "deny");

    let malformed_json = run_hook("{not valid json");
    assert_eq!(malformed_json["decision"], "deny");

    let allow_json = run_hook(
        r#"{
            "hookEventName": "PreToolUse",
            "toolCall": {
                "id": "call_2",
                "name": "run_command",
                "args": { "CommandLine": "cargo test --workspace" }
            }
        }"#,
    );
    assert_eq!(allow_json["decision"], "allow");
}

#[test]
fn e2e_post_tool_use_and_stop_quality_gate_lifecycle() {
    let dir = std::env::temp_dir().join(format!("vektor-e2e-stop-gate-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).expect("mkdir");
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"sample\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .expect("write cargo.toml");

    let lib_rs = dir.join("src/lib.rs");
    // 1. Write broken Rust file and notify PostToolUse.
    std::fs::write(&lib_rs, "pub fn broken() -> i32 { \"not_an_int\" }\n").expect("write broken");

    let post_payload = json!({
        "hookEventName": "PostToolUse",
        "workspacePaths": [dir.display().to_string()],
        "cwd": dir.display().to_string(),
        "toolCall": {
            "id": "p1",
            "name": "write_file",
            "args": { "Path": lib_rs.display().to_string() }
        }
    });
    let mut post_child = Command::new(vektor_bin())
        .args(["hook", "post-tool-use"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn post-tool-use");
    post_child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(post_payload.to_string().as_bytes())
        .expect("write");
    assert!(post_child
        .wait_with_output()
        .expect("wait")
        .status
        .success());

    // 2. Stop gate must catch the compilation error and force continuation.
    let stop_payload = json!({
        "hookEventName": "Stop",
        "terminationReason": "NO_TOOL_CALL",
        "continuationActive": false,
        "workspacePaths": [dir.display().to_string()],
        "cwd": dir.display().to_string()
    });
    let mut stop_fail = Command::new(vektor_bin())
        .args(["hook", "stop"])
        .env_remove("VEKTOR_STOP_GATE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn stop fail");
    stop_fail
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(stop_payload.to_string().as_bytes())
        .expect("write");
    let stop_fail_out = stop_fail.wait_with_output().expect("wait");
    assert!(stop_fail_out.status.success());
    let stop_fail_json: Value = serde_json::from_slice(&stop_fail_out.stdout).expect("json");
    assert_eq!(stop_fail_json["decision"], "continue");

    // 3. Respect VEKTOR_STOP_GATE=off override.
    let mut stop_off = Command::new(vektor_bin())
        .args(["hook", "stop"])
        .env("VEKTOR_STOP_GATE", "off")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn stop off");
    stop_off
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(stop_payload.to_string().as_bytes())
        .expect("write");
    let stop_off_json: Value =
        serde_json::from_slice(&stop_off.wait_with_output().expect("wait").stdout).expect("json");
    assert_eq!(stop_off_json["decision"], "allow");

    // 4. Fix compilation error -> Stop gate allows stopping and clears dirty files.
    std::fs::write(&lib_rs, "pub fn fixed() -> i32 { 42 }\n").expect("write fixed");
    let mut stop_ok = Command::new(vektor_bin())
        .args(["hook", "stop"])
        .env_remove("VEKTOR_STOP_GATE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn stop ok");
    stop_ok
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(stop_payload.to_string().as_bytes())
        .expect("write");
    let stop_ok_json: Value =
        serde_json::from_slice(&stop_ok.wait_with_output().expect("wait").stdout).expect("json");
    assert_eq!(stop_ok_json["decision"], "allow");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn e2e_audit_sarif_and_fail_on_threshold() {
    let dir = std::env::temp_dir().join(format!("vektor-e2e-audit-test-{}", std::process::id()));
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

#[test]
fn e2e_mcp_modern_negotiation_annotations_and_resources() {
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
            r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"2025-06-18"}}}}"#
        )
        .expect("write init");
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{{}}}}"#
        )
        .expect("write tools/list");
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":3,"method":"resources/list","params":{{}}}}"#
        )
        .expect("write resources/list");
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":4,"method":"resources/read","params":{{"uri":"vektor://workspace/summary"}}}}"#
        )
        .expect("write resources/read");
    }

    let output = child.wait_with_output().expect("wait");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8");
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 4);

    let init: Value = serde_json::from_str(lines[0]).expect("init json");
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
    assert!(init["result"]["capabilities"]["resources"].is_object());

    let tools: Value = serde_json::from_str(lines[1]).expect("tools json");
    let first_tool = &tools["result"]["tools"][0];
    assert!(first_tool["annotations"]["readOnlyHint"].is_boolean());

    let res_list: Value = serde_json::from_str(lines[2]).expect("resources/list json");
    let resources = res_list["result"]["resources"]
        .as_array()
        .expect("resources array");
    assert_eq!(resources.len(), 2);

    let res_read: Value = serde_json::from_str(lines[3]).expect("resources/read json");
    let text = res_read["result"]["contents"][0]["text"]
        .as_str()
        .expect("resource text");
    assert!(text.contains("vektorVersion"));
}

#[test]
fn e2e_init_doctor_and_audit_fix_workflow() {
    let dir = std::env::temp_dir().join(format!("vektor-e2e-cli-full-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join(".github").join("workflows")).expect("mkdir");
    std::fs::write(
        dir.join(".github").join("workflows").join("ci.yml"),
        "name: Unhardened\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    timeout-minutes: 10\n    steps:\n      - run: echo ok\n",
    )
    .expect("write wf");

    // 1. `vektor init` creates `vektor.toml`.
    let init_out = Command::new(vektor_bin())
        .args(["init", "--path"])
        .arg(&dir)
        .output()
        .expect("run init");
    assert!(init_out.status.success());
    assert!(dir.join("vektor.toml").is_file());

    // 2. `vektor doctor --format json` detects `vektor.toml`.
    let doctor_out = Command::new(vektor_bin())
        .args(["doctor", "--path"])
        .arg(&dir)
        .args(["--format", "json"])
        .output()
        .expect("run doctor");
    assert!(doctor_out.status.success());
    let doctor_json: Value = serde_json::from_slice(&doctor_out.stdout).expect("doctor json");
    assert_eq!(doctor_json["vektorTomlLoaded"], true);
    assert_eq!(doctor_json["stopGateMode"], "selective");

    // 3. `vektor audit --fix` auto-remediates missing permissions & concurrency.
    let fix_out = Command::new(vektor_bin())
        .args(["audit", "--path"])
        .arg(&dir)
        .args(["--format", "json", "--fix", "--fail-on", "low"])
        .output()
        .expect("run audit --fix");
    assert!(
        fix_out.status.success(),
        "expected audit --fix to remediate all findings, stderr: {}",
        String::from_utf8_lossy(&fix_out.stderr)
    );
    let fix_json: Value = serde_json::from_slice(&fix_out.stdout).expect("fix json");
    assert_eq!(fix_json["githubActions"].as_array().expect("gha").len(), 0);
    assert_eq!(fix_json["appliedFixes"].as_array().expect("fixes").len(), 1);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn e2e_stop_gate_respects_vektor_toml_off_mode() {
    let dir = std::env::temp_dir().join(format!("vektor-e2e-stop-toml-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).expect("mkdir");
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"sample\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .expect("write cargo.toml");
    std::fs::write(dir.join("vektor.toml"), "[hooks]\nstop_gate = \"off\"\n")
        .expect("write vektor.toml");
    let lib_rs = dir.join("src/lib.rs");
    std::fs::write(&lib_rs, "pub fn broken() -> i32 { \"bad\" }\n").expect("write broken");

    let post_payload = json!({
        "hookEventName": "PostToolUse",
        "workspacePaths": [dir.display().to_string()],
        "cwd": dir.display().to_string(),
        "toolCall": { "id": "p1", "name": "write_file", "args": { "Path": lib_rs.display().to_string() } }
    });
    let mut post_child = Command::new(vektor_bin())
        .args(["hook", "post-tool-use"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn post");
    post_child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(post_payload.to_string().as_bytes())
        .expect("write");
    assert!(post_child
        .wait_with_output()
        .expect("wait")
        .status
        .success());

    let stop_payload = json!({
        "hookEventName": "Stop",
        "terminationReason": "NO_TOOL_CALL",
        "continuationActive": false,
        "workspacePaths": [dir.display().to_string()],
        "cwd": dir.display().to_string()
    });
    let mut stop_child = Command::new(vektor_bin())
        .args(["hook", "stop"])
        .env_remove("VEKTOR_STOP_GATE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn stop");
    stop_child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(stop_payload.to_string().as_bytes())
        .expect("write");
    let out = stop_child.wait_with_output().expect("wait");
    assert!(out.status.success());
    let json_out: Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(json_out["decision"], "allow");

    let _ = std::fs::remove_dir_all(&dir);
}

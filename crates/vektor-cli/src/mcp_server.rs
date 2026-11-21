use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use serde_json::{json, Value};
use vektor_analyzers::{cargo, gha, hygiene, rust_ast, sarif, secrets, trojan};
use vektor_core::mcp::{McpServer, ToolDefinition, ToolHandler, ToolResult};
use vektor_state::StateStore;

#[must_use]
pub(crate) fn build_server() -> McpServer {
    let mut server = McpServer::new("vektor", env!("CARGO_PKG_VERSION"));
    server.register(HealthTool);
    server.register(WorkspaceInfoTool);
    server.register(TeamRosterTool);
    server.register(CargoAuditDepsTool);
    server.register(ScanSecretsTool);
    server.register(LintGhaTool);
    server.register(RustAstQueryTool);
    server.register(RustApiDiffTool);
    server.register(SbomCycloneDxTool);
    server.register(SecuritySarifTool);
    server.register(RepoHygieneTool);
    server.register(SwarmTaskTool);
    server.register(SwarmLockTool);
    server
}

/// Collect real, deterministic workspace metadata (Cargo, Git, GitHub Actions).
#[must_use]
pub(crate) fn collect_workspace_summary(root: &Path) -> Value {
    let has_cargo_toml = root.join("Cargo.toml").is_file();
    let has_cargo_lock = root.join("Cargo.lock").is_file();
    let has_git = root.join(".git").exists();
    let has_state_db = root.join(".vektor").join("state.db").is_file();

    let workflows_dir = root.join(".github").join("workflows");
    let workflows: Vec<String> = std::fs::read_dir(&workflows_dir)
        .ok()
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|name| {
                    Path::new(name).extension().is_some_and(|ext| {
                        ext.eq_ignore_ascii_case("yml") || ext.eq_ignore_ascii_case("yaml")
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    json!({
        "vektorVersion": env!("CARGO_PKG_VERSION"),
        "workspaceRoot": root.display().to_string(),
        "rust": {
            "hasCargoToml": has_cargo_toml,
            "hasCargoLock": has_cargo_lock
        },
        "git": {
            "isGitRepo": has_git
        },
        "stateDbInitialized": has_state_db,
        "githubActions": {
            "workflowCount": workflows.len(),
            "workflows": workflows
        }
    })
}

fn resolve_target_path(args: &Value) -> PathBuf {
    args.get("path")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."))
}

#[allow(clippy::cast_possible_wrap)]
fn file_mtime_secs(path: &Path) -> i64 {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs() as i64)
}

fn ok_json<T: serde::Serialize>(val: &T) -> ToolResult {
    match serde_json::to_string_pretty(val) {
        Ok(s) => ToolResult::ok(s),
        Err(err) => ToolResult::err(format!("JSON serialization failed: {err}")),
    }
}

fn err_json<T: serde::Serialize>(val: &T) -> ToolResult {
    match serde_json::to_string_pretty(val) {
        Ok(s) => ToolResult::err(s),
        Err(err) => ToolResult::err(format!("JSON serialization failed: {err}")),
    }
}

/// Incrementally refresh the `SQLite` WAL Rust AST index for all changed `.rs` files in `root`
/// and prune entries for files deleted from disk.
fn refresh_ast_index(root: &Path, store: &mut StateStore) -> anyhow::Result<usize> {
    let files = rust_ast::collect_rust_files(root)?;
    let mut existing = std::collections::BTreeSet::new();
    let mut reindexed = 0usize;
    for file in files {
        let rel = file
            .strip_prefix(root)
            .unwrap_or(&file)
            .display()
            .to_string()
            .replace('\\', "/");
        existing.insert(rel.clone());
        let mtime = file_mtime_secs(&file);
        if store.indexed_mtime(&rel)? == Some(mtime) && mtime > 0 {
            continue;
        }
        match rust_ast::extract_file(root, &file) {
            Ok(syms) => {
                store.replace_file_symbols(&rel, mtime, &syms)?;
                reindexed += 1;
            }
            Err(err) => {
                eprintln!("vektor AST refresh skipped {rel}: {err}");
            }
        }
    }
    store.prune_missing_ast_files(&existing)?;
    Ok(reindexed)
}

struct HealthTool;

impl ToolHandler for HealthTool {
    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "vektor_health".to_string(),
            description: "Check Vektor Rust MCP server health, version, and active capabilities."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }),
        }
    }

    fn call(&self, _args: Value) -> ToolResult {
        let payload = json!({
            "status": "ok",
            "version": env!("CARGO_PKG_VERSION"),
            "milestone": "4 (Trojan Guard + SARIF 2.1.0 + CycloneDX SBOM + AST SemVer diff + selective Stop + repo hygiene)",
            "modules": {
                "mcpCore": true,
                "lifecycleHooks": true,
                "cratesAnalyzer": true,
                "securityAndGhaLinter": true,
                "trojanGuard": true,
                "sarifExport": true,
                "cyclonedxSbom": true,
                "astCodeGraph": true,
                "astSemverDiff": true,
                "repoHygiene": true,
                "swarmBlackboard": true,
                "selectiveStopGate": true
            }
        });
        ok_json(&payload)
    }
}

struct WorkspaceInfoTool;

impl ToolHandler for WorkspaceInfoTool {
    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "vektor_workspace_info".to_string(),
            description: "Inspect a workspace directory for Rust/Cargo manifests, Git repo status, SQLite state, and GitHub Actions workflows."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Optional workspace path. Defaults to current working directory."
                    }
                },
                "additionalProperties": false
            }),
        }
    }

    fn call(&self, args: Value) -> ToolResult {
        let root = resolve_target_path(&args);
        if !root.exists() {
            return ToolResult::err(format!("Workspace path does not exist: {}", root.display()));
        }
        let summary = collect_workspace_summary(&root);
        ok_json(&summary)
    }
}

struct TeamRosterTool;

impl ToolHandler for TeamRosterTool {
    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "vektor_team_roster".to_string(),
            description: "Return the Vektor specialist dev team roster and delegation matrix for Gemini/Antigravity."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }),
        }
    }

    fn call(&self, _args: Value) -> ToolResult {
        let roster = json!({
            "memoryBackbone": "engram",
            "experts": [
                {
                    "agent": "rust-expert",
                    "focus": "Idiomatic Rust architecture, ownership/lifetimes, async/tokio, traits, performance, testing",
                    "tools": ["vektor_rust_ast_query", "vektor_cargo_audit_deps", "vektor_swarm_task", "vektor_swarm_lock"]
                },
                {
                    "agent": "crates-specialist",
                    "focus": "Cargo.toml/Cargo.lock audits, crate selection, MSRV, feature flags, licenses, compile-time impact",
                    "tools": ["vektor_cargo_audit_deps"]
                },
                {
                    "agent": "security-auditor",
                    "focus": "AppSec, unsafe code audit, secret scanning, RustSec supply-chain, least-privilege permissions",
                    "tools": ["vektor_scan_secrets", "vektor_lint_gha", "vektor_rust_ast_query", "vektor_cargo_audit_deps"]
                },
                {
                    "agent": "gh-actions-engineer",
                    "focus": "CI/CD workflows, Rust caching (rust-cache/sccache), cross-platform matrices, SHA pinning, release automation",
                    "tools": ["vektor_lint_gha", "vektor_workspace_info"]
                },
                {
                    "agent": "github-maintainer",
                    "focus": "PR reviews, issues, Conventional Commits, changelogs, branch protection, release management",
                    "tools": ["vektor_workspace_info", "vektor_swarm_task"]
                },
                {
                    "agent": "astro-expert",
                    "focus": "High-conversion Astro landing pages, Islands architecture, Content Collections, SEO/OpenGraph/JSON-LD, Core Web Vitals, accessibility",
                    "tools": ["vektor_workspace_info", "vektor_scan_secrets", "vektor_swarm_task", "vektor_swarm_lock"]
                },
                {
                    "agent": "markdown-docs-expert",
                    "focus": "Technical writing, Markdown documentation, READMEs, ADRs, Diataxis guides, API references, Mermaid diagrams, Starlight docs",
                    "tools": ["vektor_workspace_info", "vektor_rust_ast_query", "vektor_repo_hygiene", "vektor_swarm_task", "vektor_swarm_lock"]
                }
            ]
        });
        ok_json(&roster)
    }
}

struct CargoAuditDepsTool;

impl ToolHandler for CargoAuditDepsTool {
    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "vektor_cargo_audit_deps".to_string(),
            description: "Analyze Cargo.toml/Cargo.lock via `cargo metadata`: detects duplicate crate versions, MSRV conflicts, license inventory/copyleft risks, and default-feature usage."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Workspace root directory containing Cargo.toml. Defaults to cwd."
                    },
                    "offline": {
                        "type": "boolean",
                        "description": "Pass --offline to cargo metadata (default: true)."
                    }
                },
                "additionalProperties": false
            }),
        }
    }

    fn call(&self, args: Value) -> ToolResult {
        let root = resolve_target_path(&args);
        let offline = args.get("offline").and_then(Value::as_bool).unwrap_or(true);
        match cargo::analyze_workspace(&root, offline) {
            Ok(report) => ok_json(&report),
            Err(err) => ToolResult::err(format!("Cargo dependency audit failed: {err}")),
        }
    }
}

struct ScanSecretsTool;

impl ToolHandler for ScanSecretsTool {
    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "vektor_scan_secrets".to_string(),
            description: "Scan a file or workspace directory for hardcoded API keys, tokens, private keys, and high-entropy credentials."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "File or directory path to scan. Defaults to cwd."
                    }
                },
                "additionalProperties": false
            }),
        }
    }

    fn call(&self, args: Value) -> ToolResult {
        let target = resolve_target_path(&args);
        if !target.exists() {
            return ToolResult::err(format!("Scan target does not exist: {}", target.display()));
        }
        match secrets::scan_path(&target) {
            Ok(findings) => {
                let payload = json!({
                    "target": target.display().to_string(),
                    "findingCount": findings.len(),
                    "findings": findings
                });
                ok_json(&payload)
            }
            Err(err) => ToolResult::err(format!("Secret scan failed: {err}")),
        }
    }
}

struct LintGhaTool;

impl ToolHandler for LintGhaTool {
    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "vektor_lint_gha".to_string(),
            description: "Static security and best-practices linter for GitHub Actions workflows (.github/workflows/*.yml): checks SHA pinning, permissions, pull_request_target, script injection, and concurrency."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Workspace root or specific workflow YAML file. Defaults to cwd."
                    }
                },
                "additionalProperties": false
            }),
        }
    }

    fn call(&self, args: Value) -> ToolResult {
        let target = resolve_target_path(&args);
        if !target.exists() {
            return ToolResult::err(format!("Target path does not exist: {}", target.display()));
        }
        match gha::lint_workspace_or_file(&target) {
            Ok(findings) => {
                let payload = json!({
                    "target": target.display().to_string(),
                    "findingCount": findings.len(),
                    "findings": findings
                });
                ok_json(&payload)
            }
            Err(err) => ToolResult::err(format!("GitHub Actions lint failed: {err}")),
        }
    }
}

struct RustAstQueryTool;

impl ToolHandler for RustAstQueryTool {
    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "vektor_rust_ast_query".to_string(),
            description: "Incrementally index Rust files with tree-sitter-rust into SQLite WAL and query symbols (fn, unsafe_fn, unsafe_block, struct, enum, trait, impl, mod, const)."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Workspace root directory. Defaults to cwd."
                    },
                    "query": {
                        "type": "string",
                        "description": "Optional symbol name substring filter."
                    },
                    "kind": {
                        "type": "string",
                        "description": "Optional exact kind filter (fn, unsafe_fn, unsafe_block, struct, enum, trait, impl, mod, const, static)."
                    },
                    "file": {
                        "type": "string",
                        "description": "Optional file path substring filter."
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of symbols to return (default: 50)."
                    }
                },
                "additionalProperties": false
            }),
        }
    }

    fn call(&self, args: Value) -> ToolResult {
        let root = resolve_target_path(&args);
        let mut store = match StateStore::open_workspace(&root) {
            Ok(s) => s,
            Err(err) => return ToolResult::err(format!("Failed to open Vektor state DB: {err}")),
        };

        let reindexed = match refresh_ast_index(&root, &mut store) {
            Ok(n) => n,
            Err(err) => return ToolResult::err(format!("AST indexing failed: {err}")),
        };

        let query = args.get("query").and_then(Value::as_str);
        let kind = args.get("kind").and_then(Value::as_str);
        let file = args.get("file").and_then(Value::as_str);
        #[allow(clippy::cast_possible_truncation)]
        let limit = args
            .get("limit")
            .and_then(Value::as_u64)
            .map_or(50, |n| n.clamp(1, 500) as usize);

        match store.query_symbols(query, kind, file, limit) {
            Ok(symbols) => {
                let payload = json!({
                    "reindexedFiles": reindexed,
                    "symbolCount": symbols.len(),
                    "symbols": symbols
                });
                ok_json(&payload)
            }
            Err(err) => ToolResult::err(format!("AST query failed: {err}")),
        }
    }
}

struct RustApiDiffTool;

impl ToolHandler for RustApiDiffTool {
    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "vektor_rust_api_diff".to_string(),
            description: "Compare public Rust API signatures against a git ref (default: HEAD) using tree-sitter-rust to detect SemVer breaking or additive changes."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Workspace root. Defaults to cwd." },
                    "gitRef": { "type": "string", "description": "Base git revision to compare against (default: HEAD)." }
                },
                "additionalProperties": false
            }),
        }
    }

    fn call(&self, args: Value) -> ToolResult {
        let root = resolve_target_path(&args);
        let git_ref = args.get("gitRef").and_then(Value::as_str).unwrap_or("HEAD");
        match rust_ast::diff_workspace_against_git(&root, git_ref) {
            Ok(report) => ok_json(&report),
            Err(err) => ToolResult::err(format!("AST API diff failed: {err}")),
        }
    }
}

struct SbomCycloneDxTool;

impl ToolHandler for SbomCycloneDxTool {
    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "vektor_sbom_cyclonedx".to_string(),
            description: "Generate a CycloneDX 1.5 JSON Software Bill of Materials (SBOM) from `cargo metadata`."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Workspace root containing Cargo.toml. Defaults to cwd." },
                    "offline": { "type": "boolean", "description": "Pass --offline to cargo metadata (default: true)." }
                },
                "additionalProperties": false
            }),
        }
    }

    fn call(&self, args: Value) -> ToolResult {
        let root = resolve_target_path(&args);
        let offline = args.get("offline").and_then(Value::as_bool).unwrap_or(true);
        match cargo::generate_cyclonedx_sbom(&root, offline) {
            Ok(sbom) => ok_json(&sbom),
            Err(err) => ToolResult::err(format!("CycloneDX SBOM generation failed: {err}")),
        }
    }
}

struct SecuritySarifTool;

impl ToolHandler for SecuritySarifTool {
    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "vektor_security_sarif".to_string(),
            description: "Run secret scan, Trojan Guard (Unicode BiDi/invisible chars), and GitHub Actions linter, returning a SARIF 2.1.0 report ready for GitHub Code Scanning."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Workspace root to scan. Defaults to cwd." }
                },
                "additionalProperties": false
            }),
        }
    }

    fn call(&self, args: Value) -> ToolResult {
        let root = resolve_target_path(&args);
        if !root.exists() {
            return ToolResult::err(format!("Target path does not exist: {}", root.display()));
        }
        let secret_hits = match secrets::scan_path(&root) {
            Ok(h) => h,
            Err(err) => return ToolResult::err(format!("Secret scan failed: {err}")),
        };
        let trojan_hits = match trojan::scan_path(&root) {
            Ok(h) => h,
            Err(err) => return ToolResult::err(format!("Trojan scan failed: {err}")),
        };
        let gha_hits = match gha::lint_workspace_or_file(&root) {
            Ok(h) => h,
            Err(err) => return ToolResult::err(format!("GHA lint failed: {err}")),
        };

        let report = sarif::build_sarif_report(
            env!("CARGO_PKG_VERSION"),
            &secret_hits,
            &trojan_hits,
            &gha_hits,
        );
        ok_json(&report)
    }
}

struct RepoHygieneTool;

impl ToolHandler for RepoHygieneTool {
    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "vektor_repo_hygiene".to_string(),
            description: "Audit Rust/GitHub repository DevSecOps hygiene (README, LICENSE, SECURITY.md, .gitignore, MSRV, unsafe_code policy, hardened GitHub Actions) with a 0-100 score."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Workspace root directory. Defaults to cwd." }
                },
                "additionalProperties": false
            }),
        }
    }

    fn call(&self, args: Value) -> ToolResult {
        let root = resolve_target_path(&args);
        match hygiene::audit_repo_hygiene(&root) {
            Ok(report) => ok_json(&report),
            Err(err) => ToolResult::err(format!("Repo hygiene audit failed: {err}")),
        }
    }
}

struct SwarmTaskTool;

impl ToolHandler for SwarmTaskTool {
    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "vektor_swarm_task".to_string(),
            description:
                "Manage shared Swarm Blackboard tasks in SQLite WAL (action: list | upsert)."
                    .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Workspace root. Defaults to cwd." },
                    "action": { "type": "string", "enum": ["list", "upsert"] },
                    "id": { "type": "string", "description": "Task ID (required for upsert)." },
                    "title": { "type": "string", "description": "Task title (required for upsert)." },
                    "ownerAgent": { "type": "string", "description": "Assigned expert agent." },
                    "status": { "type": "string", "enum": ["pending", "in_progress", "blocked", "done"] },
                    "dependsOn": { "type": "array", "items": { "type": "string" } },
                    "notes": { "type": "string" }
                },
                "required": ["action"],
                "additionalProperties": false
            }),
        }
    }

    fn call(&self, args: Value) -> ToolResult {
        let root = resolve_target_path(&args);
        let store = match StateStore::open_workspace(&root) {
            Ok(s) => s,
            Err(err) => return ToolResult::err(format!("Failed to open Vektor state DB: {err}")),
        };

        let action = args.get("action").and_then(Value::as_str).unwrap_or("list");

        match action {
            "list" => {
                let status = args.get("status").and_then(Value::as_str);
                match store.list_tasks(status) {
                    Ok(tasks) => ok_json(&json!({ "tasks": tasks })),
                    Err(err) => ToolResult::err(format!("Failed to list tasks: {err}")),
                }
            }
            "upsert" => {
                let Some(id) = args.get("id").and_then(Value::as_str) else {
                    return ToolResult::err("Missing required field `id` for upsert");
                };
                let Some(title) = args.get("title").and_then(Value::as_str) else {
                    return ToolResult::err("Missing required field `title` for upsert");
                };
                let owner = args
                    .get("ownerAgent")
                    .and_then(Value::as_str)
                    .unwrap_or("unassigned");
                let status = args
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("pending");
                let notes = args.get("notes").and_then(Value::as_str).unwrap_or("");
                let deps: Vec<String> = args
                    .get("dependsOn")
                    .and_then(Value::as_array)
                    .map(|arr| {
                        arr.iter()
                            .filter_map(Value::as_str)
                            .map(ToString::to_string)
                            .collect()
                    })
                    .unwrap_or_default();

                match store.upsert_task(id, title, owner, status, &deps, notes) {
                    Ok(task) => ok_json(&task),
                    Err(err) => ToolResult::err(format!("Failed to upsert task: {err}")),
                }
            }
            other => ToolResult::err(format!("Unsupported action: {other}")),
        }
    }
}

struct SwarmLockTool;

impl ToolHandler for SwarmLockTool {
    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "vektor_swarm_lock".to_string(),
            description: "Coordinate advisory file locks in SQLite WAL so parallel agents avoid editing the same files (action: list | acquire | release)."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Workspace root. Defaults to cwd." },
                    "action": { "type": "string", "enum": ["list", "acquire", "release"] },
                    "filePath": { "type": "string", "description": "Relative file path to lock/unlock." },
                    "ownerAgent": { "type": "string", "description": "Agent name acquiring or releasing the lock." },
                    "force": { "type": "boolean", "description": "Required to release a lock without specifying ownerAgent." },
                    "reason": { "type": "string" },
                    "ttlSecs": { "type": "integer", "description": "Lock TTL in seconds (10..=86400, default: 1800)." }
                },
                "required": ["action"],
                "additionalProperties": false
            }),
        }
    }

    fn call(&self, args: Value) -> ToolResult {
        let root = resolve_target_path(&args);
        let mut store = match StateStore::open_workspace(&root) {
            Ok(s) => s,
            Err(err) => return ToolResult::err(format!("Failed to open Vektor state DB: {err}")),
        };

        let action = args.get("action").and_then(Value::as_str).unwrap_or("list");

        match action {
            "list" => match store.list_locks() {
                Ok(locks) => ok_json(&json!({ "locks": locks })),
                Err(err) => ToolResult::err(format!("Failed to list locks: {err}")),
            },
            "acquire" => {
                let Some(file_path) = args.get("filePath").and_then(Value::as_str) else {
                    return ToolResult::err("Missing required field `filePath`");
                };
                let Some(owner) = args.get("ownerAgent").and_then(Value::as_str) else {
                    return ToolResult::err("Missing required field `ownerAgent`");
                };
                let reason = args.get("reason").and_then(Value::as_str).unwrap_or("");
                let ttl = args.get("ttlSecs").and_then(Value::as_i64);

                match store.acquire_lock(file_path, owner, reason, ttl) {
                    Ok(Ok(lock)) => ok_json(&json!({ "acquired": true, "lock": lock })),
                    Ok(Err(holder)) => err_json(&json!({
                        "acquired": false,
                        "conflictWith": holder
                    })),
                    Err(err) => ToolResult::err(format!("Failed to acquire lock: {err}")),
                }
            }
            "release" => {
                let Some(file_path) = args.get("filePath").and_then(Value::as_str) else {
                    return ToolResult::err("Missing required field `filePath`");
                };
                let owner = args.get("ownerAgent").and_then(Value::as_str);
                let force = args.get("force").and_then(Value::as_bool).unwrap_or(false);
                if owner.is_none() && !force {
                    return ToolResult::err(
                        "Missing required field `ownerAgent` for release (or pass `force: true`)",
                    );
                }
                match store.release_lock(file_path, owner) {
                    Ok(released) => ok_json(&json!({ "releasedCount": released })),
                    Err(err) => ToolResult::err(format!("Failed to release lock: {err}")),
                }
            }
            other => ToolResult::err(format!("Unsupported action: {other}")),
        }
    }
}

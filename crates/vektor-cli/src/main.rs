mod hook_runner;
mod mcp_server;

use std::io;
use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use serde_json::json;
use vektor_analyzers::{gha, hygiene, sarif, secrets, trojan, Severity};
use vektor_core::hooks::HookEvent;

#[derive(Parser)]
#[command(
    name = "vektor",
    version,
    about = "High-speed Rust MCP server, DevSecOps auditor, and lifecycle hook engine for Antigravity"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the Vektor MCP server over stdio.
    Mcp,
    /// Execute a synchronous Antigravity lifecycle hook reading JSON from stdin.
    Hook {
        /// Lifecycle event name.
        #[arg(value_enum)]
        event: HookEventArg,
    },
    /// Print diagnostic status for the current workspace.
    Status,
    /// Run deterministic `DevSecOps` audit (secrets, Trojan Guard, GitHub Actions, repo hygiene).
    Audit {
        /// Target workspace directory (defaults to current working directory).
        #[arg(long)]
        path: Option<PathBuf>,
        /// Output format (`json` or `sarif` 2.1.0 for GitHub Code Scanning).
        #[arg(long, value_enum, default_value_t = AuditFormat::Json)]
        format: AuditFormat,
        /// Exit with non-zero status if any finding meets or exceeds this severity.
        #[arg(long, value_enum)]
        fail_on: Option<FailSeverity>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum AuditFormat {
    Json,
    Sarif,
}

#[derive(Clone, Copy, ValueEnum)]
enum FailSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl From<FailSeverity> for Severity {
    fn from(value: FailSeverity) -> Self {
        match value {
            FailSeverity::Low => Self::Low,
            FailSeverity::Medium => Self::Medium,
            FailSeverity::High => Self::High,
            FailSeverity::Critical => Self::Critical,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum HookEventArg {
    SessionStart,
    PreToolUse,
    PostToolUse,
    PreInvocation,
    PostInvocation,
    Stop,
}

impl From<HookEventArg> for HookEvent {
    fn from(value: HookEventArg) -> Self {
        match value {
            HookEventArg::SessionStart => Self::SessionStart,
            HookEventArg::PreToolUse => Self::PreToolUse,
            HookEventArg::PostToolUse => Self::PostToolUse,
            HookEventArg::PreInvocation => Self::PreInvocation,
            HookEventArg::PostInvocation => Self::PostInvocation,
            HookEventArg::Stop => Self::Stop,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Mcp => {
            let server = mcp_server::build_server();
            let stdin = io::stdin();
            let stdout = io::stdout();
            server.run_stdio(stdin.lock(), stdout.lock())?;
        }
        Commands::Hook { event } => {
            let stdin = io::stdin();
            let stdout = io::stdout();
            hook_runner::run(event.into(), stdin.lock(), stdout.lock())?;
        }
        Commands::Status => {
            let cwd = std::env::current_dir()?;
            let info = mcp_server::collect_workspace_summary(&cwd);
            println!("{}", serde_json::to_string_pretty(&info)?);
        }
        Commands::Audit {
            path,
            format,
            fail_on,
        } => {
            let root = match path {
                Some(p) => p,
                None => std::env::current_dir()?,
            };
            let secret_hits = secrets::scan_path(&root)?;
            let trojan_hits = trojan::scan_path(&root)?;
            let gha_hits = gha::lint_workspace_or_file(&root)?;

            let out = match format {
                AuditFormat::Sarif => sarif::build_sarif_report(
                    env!("CARGO_PKG_VERSION"),
                    &secret_hits,
                    &trojan_hits,
                    &gha_hits,
                ),
                AuditFormat::Json => {
                    let hygiene_report = hygiene::audit_repo_hygiene(&root)?;
                    json!({
                        "workspaceRoot": root.display().to_string(),
                        "secrets": secret_hits,
                        "trojans": trojan_hits,
                        "githubActions": gha_hits,
                        "hygiene": hygiene_report
                    })
                }
            };
            println!("{}", serde_json::to_string_pretty(&out)?);

            if let Some(threshold) = fail_on.map(Severity::from) {
                let failing_count = secret_hits
                    .iter()
                    .filter(|f| f.severity >= threshold)
                    .count()
                    + trojan_hits
                        .iter()
                        .filter(|f| f.severity >= threshold)
                        .count()
                    + gha_hits.iter().filter(|f| f.severity >= threshold).count();

                if failing_count > 0 {
                    eprintln!(
                        "vektor audit failed: {failing_count} finding(s) met or exceeded severity threshold {threshold:?}"
                    );
                    std::process::exit(1);
                }
            }
        }
    }

    Ok(())
}

mod cli_commands;
mod hook_runner;
mod mcp_server;

use std::io;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use vektor_core::hooks::HookEvent;

use crate::cli_commands::{AuditFormat, FailSeverity, OutputFormat};

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
        /// Output format (`json`, `sarif`, `markdown`, or `pretty`).
        #[arg(long, value_enum, default_value_t = AuditFormat::Json)]
        format: AuditFormat,
        /// Exit with non-zero status if any finding meets or exceeds this severity.
        #[arg(long, value_enum)]
        fail_on: Option<FailSeverity>,
        /// Scan only Git-staged files for secrets (ideal for `pre-commit` hooks).
        #[arg(long)]
        staged: bool,
        /// Deterministically auto-fix missing top-level GitHub Actions hardening blocks.
        #[arg(long)]
        fix: bool,
    },
    /// Run sub-millisecond PII Guard (credit cards, US SSNs, IBANs, personal emails).
    Pii {
        /// Target file or directory (defaults to current working directory).
        #[arg(long)]
        path: Option<PathBuf>,
        /// Output format (`json`, `markdown`, or `pretty`).
        #[arg(long, value_enum, default_value_t = OutputFormat::Pretty)]
        format: OutputFormat,
        /// Exit with non-zero status if any finding meets or exceeds this severity.
        #[arg(long, value_enum)]
        fail_on: Option<FailSeverity>,
    },
    /// Generate a `CycloneDX` 1.5 JSON SBOM from `cargo metadata`.
    Sbom {
        /// Target Rust workspace directory.
        #[arg(long)]
        path: Option<PathBuf>,
        /// Pass `--offline` to `cargo metadata`.
        #[arg(long)]
        offline: bool,
    },
    /// Diff public Rust API symbols against a Git revision to detect `SemVer` breaking changes.
    ApiDiff {
        /// Target Rust workspace directory.
        #[arg(long)]
        path: Option<PathBuf>,
        /// Base Git revision to compare against (default: `HEAD`).
        #[arg(long, default_value = "HEAD")]
        base: String,
        /// Output format (`json`, `markdown`, or `pretty`).
        #[arg(long, value_enum, default_value_t = OutputFormat::Pretty)]
        format: OutputFormat,
        /// Exit with non-zero status if any breaking public API change is detected.
        #[arg(long)]
        fail_on_breaking: bool,
    },
    /// Audit Cargo workspace dependencies (duplicates, MSRV conflicts, licenses).
    Deps {
        /// Target Rust workspace directory.
        #[arg(long)]
        path: Option<PathBuf>,
        /// Pass `--offline` to `cargo metadata`.
        #[arg(long)]
        offline: bool,
        /// Output format (`json`, `markdown`, or `pretty`).
        #[arg(long, value_enum, default_value_t = OutputFormat::Pretty)]
        format: OutputFormat,
    },
    /// Audit `DevSecOps` repository hygiene (0-100 score).
    Hygiene {
        /// Target workspace directory.
        #[arg(long)]
        path: Option<PathBuf>,
        /// Output format (`json`, `markdown`, or `pretty`).
        #[arg(long, value_enum, default_value_t = OutputFormat::Pretty)]
        format: OutputFormat,
        /// Exit with non-zero status if hygiene score is below this threshold.
        #[arg(long)]
        min_score: Option<u8>,
    },
    /// Diagnose Vektor installation, toolchain, plugin, and workspace health.
    Doctor {
        /// Target workspace directory.
        #[arg(long)]
        path: Option<PathBuf>,
        /// Output format (`pretty` or `json`).
        #[arg(long, value_enum, default_value_t = OutputFormat::Pretty)]
        format: OutputFormat,
    },
    /// Initialize `vektor.toml` and optionally install the Antigravity plugin.
    Init {
        /// Target workspace directory.
        #[arg(long)]
        path: Option<PathBuf>,
        /// Overwrite existing `vektor.toml`.
        #[arg(long)]
        force: bool,
        /// Copy `plugin/` into `~/.gemini/config/plugins/vektor`.
        #[arg(long)]
        install_plugin: bool,
    },
    /// Run reproducible micro-benchmarks for hooks and static analyzers.
    Bench {
        /// Number of benchmark iterations (minimum 10).
        #[arg(long, default_value_t = 200)]
        iterations: usize,
    },
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

fn run(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        Commands::Mcp => {
            let server = mcp_server::build_server();
            let stdin = io::stdin();
            let stdout = io::stdout();
            server.run_stdio(stdin.lock(), stdout.lock())?;
            Ok(ExitCode::SUCCESS)
        }
        Commands::Hook { event } => {
            let stdin = io::stdin();
            let stdout = io::stdout();
            hook_runner::run(event.into(), stdin.lock(), stdout.lock())?;
            Ok(ExitCode::SUCCESS)
        }
        Commands::Status => {
            let cwd = std::env::current_dir()?;
            let info = mcp_server::collect_workspace_summary(&cwd);
            println!("{}", serde_json::to_string_pretty(&info)?);
            Ok(ExitCode::SUCCESS)
        }
        Commands::Audit {
            path,
            format,
            fail_on,
            staged,
            fix,
        } => cli_commands::run_audit(path, format, fail_on, staged, fix),
        Commands::Pii {
            path,
            format,
            fail_on,
        } => cli_commands::run_pii(path, format, fail_on),
        Commands::Sbom { path, offline } => cli_commands::run_sbom(path, offline),
        Commands::ApiDiff {
            path,
            base,
            format,
            fail_on_breaking,
        } => cli_commands::run_api_diff(path, &base, format, fail_on_breaking),
        Commands::Deps {
            path,
            offline,
            format,
        } => cli_commands::run_deps(path, offline, format),
        Commands::Hygiene {
            path,
            format,
            min_score,
        } => cli_commands::run_hygiene(path, format, min_score),
        Commands::Doctor { path, format } => cli_commands::run_doctor(path, format),
        Commands::Init {
            path,
            force,
            install_plugin,
        } => cli_commands::run_init(path, force, install_plugin),
        Commands::Bench { iterations } => cli_commands::run_bench(iterations),
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("vektor error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

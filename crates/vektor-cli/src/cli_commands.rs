use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::Instant;

use anyhow::Result;
use clap::ValueEnum;
use serde_json::json;
use vektor_analyzers::config::VektorConfig;
use vektor_analyzers::{cargo, gha, hygiene, pii, rust_ast, sarif, secrets, trojan, Severity};
use vektor_core::hooks::HookEvent;

use crate::{hook_runner, mcp_server};

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum OutputFormat {
    Json,
    Markdown,
    Pretty,
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum AuditFormat {
    Json,
    Sarif,
    Markdown,
    Pretty,
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum FailSeverity {
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

pub(crate) fn resolve_root(path: Option<PathBuf>) -> Result<PathBuf> {
    match path {
        Some(p) => Ok(p),
        None => Ok(std::env::current_dir()?),
    }
}

pub(crate) fn run_audit(
    path: Option<PathBuf>,
    format: AuditFormat,
    fail_on: Option<FailSeverity>,
    staged: bool,
    fix: bool,
) -> Result<ExitCode> {
    let root = resolve_root(path)?;

    let fixes = if fix {
        gha::fix_workspace_workflows(&root)?
    } else {
        Vec::new()
    };

    let secret_hits = if staged {
        secrets::scan_git_staged(&root)?
    } else {
        secrets::scan_path(&root)?
    };
    let trojan_hits = trojan::scan_path(&root)?;
    let gha_hits = gha::lint_workspace_or_file(&root)?;

    match format {
        AuditFormat::Sarif => {
            let out = sarif::build_sarif_report(
                env!("CARGO_PKG_VERSION"),
                &secret_hits,
                &trojan_hits,
                &gha_hits,
            );
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        AuditFormat::Json => {
            let hygiene_report = hygiene::audit_repo_hygiene(&root)?;
            let mut out = json!({
                "workspaceRoot": root.display().to_string(),
                "stagedOnly": staged,
                "secrets": secret_hits,
                "trojans": trojan_hits,
                "githubActions": gha_hits,
                "hygiene": hygiene_report
            });
            if fix {
                out["appliedFixes"] = json!(fixes);
            }
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        AuditFormat::Markdown => {
            let hygiene_report = hygiene::audit_repo_hygiene(&root)?;
            println!(
                "{}",
                render_audit_markdown(
                    &secret_hits,
                    &trojan_hits,
                    &gha_hits,
                    &hygiene_report,
                    &fixes
                )
            );
        }
        AuditFormat::Pretty => {
            let hygiene_report = hygiene::audit_repo_hygiene(&root)?;
            println!(
                "{}",
                render_audit_pretty(
                    &secret_hits,
                    &trojan_hits,
                    &gha_hits,
                    &hygiene_report,
                    &fixes
                )
            );
        }
    }

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
            return Ok(ExitCode::FAILURE);
        }
    }

    Ok(ExitCode::SUCCESS)
}

pub(crate) fn run_pii(
    path: Option<PathBuf>,
    format: OutputFormat,
    fail_on: Option<FailSeverity>,
) -> Result<ExitCode> {
    let root = resolve_root(path)?;
    let hits = pii::scan_path(&root)?;

    match format {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "workspaceRoot": root.display().to_string(),
                "findingCount": hits.len(),
                "findings": hits
            }))?
        ),
        OutputFormat::Markdown => {
            let mut out = format!(
                "## Vektor PII Guard (`glastor-core/pii-veil` inspired)\n\n- **Findings**: {}\n",
                hits.len()
            );
            if !hits.is_empty() {
                out.push_str(
                    "\n| Severity | Rule | Location | Message |\n| :--- | :--- | :--- | :--- |\n",
                );
                for h in &hits {
                    let _ = writeln!(
                        out,
                        "| `{:?}` | `{}` | `{}:{}` | {} |",
                        h.severity, h.rule_id, h.file, h.line, h.message
                    );
                }
            }
            print!("{out}");
        }
        OutputFormat::Pretty => {
            println!("Vektor PII Guard: {} finding(s)", hits.len());
            for h in &hits {
                println!(
                    "  [{:?}] {} {}:{} — {} ({})",
                    h.severity, h.rule_id, h.file, h.line, h.message, h.redacted_match
                );
            }
        }
    }

    if let Some(threshold) = fail_on.map(Severity::from) {
        let failing = hits.iter().filter(|f| f.severity >= threshold).count();
        if failing > 0 {
            eprintln!(
                "vektor pii failed: {failing} finding(s) met or exceeded severity threshold {threshold:?}"
            );
            return Ok(ExitCode::FAILURE);
        }
    }

    Ok(ExitCode::SUCCESS)
}

pub(crate) fn run_sbom(path: Option<PathBuf>, offline: bool) -> Result<ExitCode> {
    let root = resolve_root(path)?;
    let sbom = cargo::generate_cyclonedx_sbom(&root, offline)?;
    println!("{}", serde_json::to_string_pretty(&sbom)?);
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn run_api_diff(
    path: Option<PathBuf>,
    base: &str,
    format: OutputFormat,
    fail_on_breaking: bool,
) -> Result<ExitCode> {
    let root = resolve_root(path)?;
    let report = rust_ast::diff_workspace_against_git(&root, base)?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        OutputFormat::Markdown => {
            let mut out = format!(
                "## Vektor SemVer API Diff (`{base}` -> working tree)\n\n- **Recommended bump**: `{}`\n- **Breaking changes**: {}\n- **Additive changes**: {}\n",
                report.recommended_bump,
                report.breaking_changes.len(),
                report.additive_changes.len()
            );
            if !report.breaking_changes.is_empty() {
                out.push_str("\n### Breaking Changes\n\n");
                for c in &report.breaking_changes {
                    let _ = writeln!(out, "- `{c}`");
                }
            }
            if !report.additive_changes.is_empty() {
                out.push_str("\n### Additive Changes\n\n");
                for c in &report.additive_changes {
                    let _ = writeln!(out, "- `{c}`");
                }
            }
            print!("{out}");
        }
        OutputFormat::Pretty => {
            println!(
                "Vektor SemVer API Diff (base: {base}, bump: {}): {} breaking, {} additive",
                report.recommended_bump,
                report.breaking_changes.len(),
                report.additive_changes.len()
            );
            for c in &report.breaking_changes {
                println!("  [BREAKING] {c}");
            }
            for c in &report.additive_changes {
                println!("  [ADDITIVE] {c}");
            }
        }
    }

    if fail_on_breaking && !report.breaking_changes.is_empty() {
        eprintln!(
            "vektor api-diff failed: {} breaking public API change(s) detected",
            report.breaking_changes.len()
        );
        return Ok(ExitCode::FAILURE);
    }
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn run_deps(
    path: Option<PathBuf>,
    offline: bool,
    format: OutputFormat,
) -> Result<ExitCode> {
    let root = resolve_root(path)?;
    let report = cargo::analyze_workspace(&root, offline)?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        OutputFormat::Markdown => {
            let mut out = format!(
                "## Vektor Cargo Dependency Audit\n\n| Metric | Value |\n| :--- | ---: |\n| Total packages | {} |\n| Workspace members | {} |\n| Duplicate crates | {} |\n| MSRV conflicts | {} |\n| Copyleft packages | {} |\n| Unlicensed packages | {} |\n",
                report.total_packages,
                report.workspace_members.len(),
                report.duplicate_crates.len(),
                report.msrv_conflicts.len(),
                report.copyleft_packages.len(),
                report.unlicensed_packages.len(),
            );
            if !report.duplicate_crates.is_empty() {
                out.push_str("\n### Duplicate Crates\n\n");
                for d in &report.duplicate_crates {
                    let _ = writeln!(out, "- `{}`: {}", d.name, d.versions.join(", "));
                }
            }
            print!("{out}");
        }
        OutputFormat::Pretty => {
            println!(
                "Vektor Cargo Audit: {} total packages, {} members, {} duplicates, {} MSRV conflicts, {} copyleft",
                report.total_packages,
                report.workspace_members.len(),
                report.duplicate_crates.len(),
                report.msrv_conflicts.len(),
                report.copyleft_packages.len()
            );
            for d in &report.duplicate_crates {
                println!("  [DUP] {}: {}", d.name, d.versions.join(", "));
            }
            for c in &report.msrv_conflicts {
                println!(
                    "  [MSRV] {} {} requires Rust {} > workspace {}",
                    c.package, c.version, c.required_msrv, c.workspace_msrv
                );
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn run_hygiene(
    path: Option<PathBuf>,
    format: OutputFormat,
    min_score: Option<u8>,
) -> Result<ExitCode> {
    let root = resolve_root(path)?;
    let report = hygiene::audit_repo_hygiene(&root)?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        OutputFormat::Markdown => {
            let mut out = format!(
                "## Vektor Repository Hygiene: **{}/100** ({}/{})\n\n| Check | Status | Details |\n| :--- | :---: | :--- |\n",
                report.score, report.passed_count, report.total_checks
            );
            for c in &report.checks {
                let badge = if c.passed { "PASS" } else { "FAIL" };
                let _ = writeln!(out, "| `{}` | {} | {} |", c.id, badge, c.message);
            }
            print!("{out}");
        }
        OutputFormat::Pretty => {
            println!(
                "Vektor Repo Hygiene: {}/100 ({}/{})",
                report.score, report.passed_count, report.total_checks
            );
            for c in &report.checks {
                let tag = if c.passed { "OK  " } else { "FAIL" };
                println!("  [{tag}] {} — {}", c.id, c.message);
            }
        }
    }

    if let Some(min) = min_score {
        if report.score < min {
            eprintln!(
                "vektor hygiene failed: score {} < minimum {}",
                report.score, min
            );
            return Ok(ExitCode::FAILURE);
        }
    }
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn run_doctor(path: Option<PathBuf>, format: OutputFormat) -> Result<ExitCode> {
    let root = resolve_root(path)?;
    let cfg = VektorConfig::load(&root);
    let summary = mcp_server::collect_workspace_summary(&root);
    let hygiene_report = hygiene::audit_repo_hygiene(&root)?;

    let rustc_version = Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
    let git_version = Command::new("git")
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());

    let plugin_installed = detect_installed_plugin(&root);
    let exe_path = std::env::current_exe()
        .ok()
        .map(|p| p.display().to_string());

    let report = json!({
        "vektorVersion": env!("CARGO_PKG_VERSION"),
        "executable": exe_path,
        "workspaceRoot": root.display().to_string(),
        "rustc": rustc_version,
        "git": git_version,
        "vektorTomlLoaded": cfg.loaded_from_file,
        "stopGateMode": cfg.stop_gate,
        "pluginInstalledPath": plugin_installed.as_ref().map(|p| p.display().to_string()),
        "hygieneScore": hygiene_report.score,
        "workspace": summary,
    });

    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        OutputFormat::Markdown | OutputFormat::Pretty => {
            println!("Vektor Doctor v{}", env!("CARGO_PKG_VERSION"));
            println!(
                "  Binary      : {}",
                exe_path.as_deref().unwrap_or("unknown")
            );
            println!("  Workspace   : {}", root.display());
            println!(
                "  Rustc       : {}",
                rustc_version.as_deref().unwrap_or("not found")
            );
            println!(
                "  Git         : {}",
                git_version.as_deref().unwrap_or("not found")
            );
            println!(
                "  vektor.toml : {}",
                if cfg.loaded_from_file {
                    "loaded"
                } else {
                    "not found (using defaults; run `vektor init`)"
                }
            );
            println!("  Stop Gate   : {}", cfg.stop_gate);
            println!(
                "  Plugin      : {}",
                plugin_installed.as_ref().map_or_else(
                    || "not installed (run `vektor init --install-plugin`)".to_string(),
                    |p| p.display().to_string()
                )
            );
            println!(
                "  Hygiene     : {}/100 ({}/{})",
                hygiene_report.score, hygiene_report.passed_count, hygiene_report.total_checks
            );
        }
    }

    Ok(ExitCode::SUCCESS)
}

pub(crate) fn run_init(
    path: Option<PathBuf>,
    force: bool,
    install_plugin: bool,
) -> Result<ExitCode> {
    let root = resolve_root(path)?;
    let toml_path = root.join("vektor.toml");

    if toml_path.exists() && !force {
        println!(
            "vektor.toml already exists at {} (use --force to overwrite)",
            toml_path.display()
        );
    } else {
        std::fs::write(&toml_path, VektorConfig::starter_template())?;
        println!("Created {}", toml_path.display());
    }

    if install_plugin {
        let src = root.join("plugin");
        if !src.is_dir() {
            anyhow::bail!("No `plugin/` directory found at {}", src.display());
        }
        let dest = antigravity_plugin_dir()?;
        copy_dir_recursive(&src, &dest)?;
        println!("Installed Antigravity plugin to {}", dest.display());
    }

    println!("Next steps: run `vektor doctor` or `vektor audit --format pretty`");
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn run_bench(iterations: usize) -> Result<ExitCode> {
    let iters = iterations.max(10);

    // 1. PreToolUse hook latency benchmark
    let payload = r#"{"toolCall":{"name":"write_file","args":{"Path":"src/lib.rs","Content":"pub fn add(a: i32, b: i32) -> i32 { a + b }\n"}}}"#;
    let mut hook_samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let mut sink = Vec::with_capacity(64);
        let t0 = Instant::now();
        hook_runner::run(HookEvent::PreToolUse, payload.as_bytes(), &mut sink)?;
        hook_samples.push(t0.elapsed().as_nanos());
    }

    // 2. Secret + Trojan scan benchmark (100-line Rust file)
    let sample_src = "pub fn compute(x: u64) -> u64 { x.wrapping_mul(31) }\n".repeat(100);
    let mut scan_samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t0 = Instant::now();
        let _ = secrets::scan_text("bench.rs", &sample_src);
        let _ = trojan::scan_text("bench.rs", &sample_src);
        scan_samples.push(t0.elapsed().as_nanos());
    }

    // 3. GHA workflow lint benchmark
    let sample_gha = "name: CI\non: [push]\npermissions:\n  contents: read\nconcurrency:\n  group: ci-${{ github.ref }}\n  cancel-in-progress: true\njobs:\n  test:\n    runs-on: ubuntu-latest\n    timeout-minutes: 15\n    steps:\n      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n        with:\n          persist-credentials: false\n      - run: cargo test --workspace\n";
    let mut gha_samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t0 = Instant::now();
        let _ = gha::lint_workflow_content(".github/workflows/ci.yml", sample_gha);
        gha_samples.push(t0.elapsed().as_nanos());
    }

    println!("Vektor Micro-Benchmarks ({iters} iterations)");
    print_bench_row("PreToolUse hook (JSON -> scan -> JSON)", &mut hook_samples);
    print_bench_row("Secrets + Trojan scan (100 lines)", &mut scan_samples);
    print_bench_row("GitHub Actions lint (hardened workflow)", &mut gha_samples);
    Ok(ExitCode::SUCCESS)
}

#[allow(clippy::cast_precision_loss)]
fn print_bench_row(label: &str, samples_ns: &mut [u128]) {
    samples_ns.sort_unstable();
    let len = samples_ns.len();
    let p50_us = samples_ns[len / 2] as f64 / 1_000.0;
    let p95_idx = ((len * 95) / 100).min(len - 1);
    let p95_us = samples_ns[p95_idx] as f64 / 1_000.0;
    let avg_us = (samples_ns.iter().sum::<u128>() as f64 / len as f64) / 1_000.0;
    println!("  {label:<42} avg={avg_us:7.1} us | p50={p50_us:7.1} us | p95={p95_us:7.1} us");
}

fn detect_installed_plugin(root: &Path) -> Option<PathBuf> {
    let project_local = root.join(".agents").join("plugins").join("vektor");
    if project_local.join("plugin.json").is_file() {
        return Some(project_local);
    }
    if let Ok(global) = antigravity_plugin_dir() {
        if global.join("plugin.json").is_file() {
            return Some(global);
        }
    }
    None
}

fn antigravity_plugin_dir() -> Result<PathBuf> {
    let home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .ok_or_else(|| anyhow::anyhow!("Could not determine user home directory"))?;
    Ok(PathBuf::from(home)
        .join(".gemini")
        .join("config")
        .join("plugins")
        .join("vektor"))
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        if ft.is_symlink() {
            continue;
        }
        let target = dst.join(entry.file_name());
        if ft.is_dir() {
            copy_dir_recursive(&entry.path(), &target)?;
        } else if ft.is_file() {
            std::fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

fn render_audit_markdown(
    secrets: &[secrets::SecretFinding],
    trojans: &[trojan::TrojanFinding],
    gha_hits: &[gha::GhaFinding],
    hygiene: &hygiene::RepoHygieneReport,
    fixes: &[gha::GhaFixResult],
) -> String {
    let total = secrets.len() + trojans.len() + gha_hits.len();
    let status = if total == 0 { "PASS" } else { "FINDINGS" };
    let mut out = format!(
        "## Vektor DevSecOps Audit — {status}\n\n| Scanner | Findings |\n| :--- | ---: |\n| Secrets | {} |\n| Trojan Guard (Unicode BiDi) | {} |\n| GitHub Actions Hardening | {} |\n| Repository Hygiene Score | **{}/100** ({}/{}) |\n",
        secrets.len(),
        trojans.len(),
        gha_hits.len(),
        hygiene.score,
        hygiene.passed_count,
        hygiene.total_checks
    );
    if !fixes.is_empty() {
        out.push_str("\n### Auto-Remediation Applied\n\n");
        for f in fixes {
            let _ = writeln!(out, "- `{}`: {}", f.file, f.applied_fixes.join("; "));
        }
    }
    if total > 0 {
        out.push_str("\n### Findings\n\n");
        for s in secrets {
            let _ = writeln!(
                out,
                "- `[{:?}]` `{}` `{}:{}` — {}",
                s.severity, s.rule_id, s.file, s.line, s.message
            );
        }
        for t in trojans {
            let _ = writeln!(
                out,
                "- `[{:?}]` `{}` `{}:{}` — {} ({})",
                t.severity, t.rule_id, t.file, t.line, t.message, t.codepoint
            );
        }
        for g in gha_hits {
            let _ = writeln!(
                out,
                "- `[{:?}]` `{}` `{}:{}` — {}",
                g.severity, g.rule_id, g.file, g.line, g.message
            );
        }
    }
    out
}

fn render_audit_pretty(
    secrets: &[secrets::SecretFinding],
    trojans: &[trojan::TrojanFinding],
    gha_hits: &[gha::GhaFinding],
    hygiene: &hygiene::RepoHygieneReport,
    fixes: &[gha::GhaFixResult],
) -> String {
    let mut out = format!(
        "Vektor DevSecOps Audit | Hygiene: {}/100 ({}/{}) | Secrets: {} | Trojans: {} | GHA: {}\n",
        hygiene.score,
        hygiene.passed_count,
        hygiene.total_checks,
        secrets.len(),
        trojans.len(),
        gha_hits.len()
    );
    for f in fixes {
        let _ = writeln!(out, "  [FIXED] {}: {}", f.file, f.applied_fixes.join("; "));
    }
    for s in secrets {
        let _ = writeln!(
            out,
            "  [{:?}] {} {}:{} — {}",
            s.severity, s.rule_id, s.file, s.line, s.message
        );
    }
    for t in trojans {
        let _ = writeln!(
            out,
            "  [{:?}] {} {}:{} — {} ({})",
            t.severity, t.rule_id, t.file, t.line, t.message, t.codepoint
        );
    }
    for g in gha_hits {
        let _ = writeln!(
            out,
            "  [{:?}] {} {}:{} — {}",
            g.severity, g.rule_id, g.file, g.line, g.message
        );
    }
    out
}

//! Cargo workspace & dependency graph analyzer powered by `cargo metadata --format-version 1`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
struct CargoMetadata {
    packages: Vec<CargoPackage>,
    workspace_members: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CargoPackage {
    id: String,
    name: String,
    version: String,
    #[serde(default)]
    manifest_path: String,
    #[serde(default)]
    edition: String,
    #[serde(default)]
    rust_version: Option<String>,
    #[serde(default)]
    license: Option<String>,
    #[serde(default)]
    dependencies: Vec<CargoDependency>,
}

#[derive(Debug, Deserialize)]
struct CargoDependency {
    name: String,
    #[serde(default)]
    uses_default_features: bool,
    #[serde(default)]
    features: Vec<String>,
}

/// Summary of a workspace member crate.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceMemberSummary {
    pub name: String,
    pub version: String,
    pub edition: String,
    pub msrv: Option<String>,
    pub license: Option<String>,
    pub direct_dependencies: usize,
    pub deps_with_default_features: Vec<String>,
}

/// A crate appearing with multiple distinct versions in the resolved graph.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DuplicateCrate {
    pub name: String,
    pub versions: Vec<String>,
}

/// Dependency whose MSRV exceeds the workspace MSRV.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MsrvConflict {
    pub package: String,
    pub version: String,
    pub required_msrv: String,
    pub workspace_msrv: String,
}

/// Complete Cargo dependency audit report.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CargoAuditReport {
    pub total_packages: usize,
    pub workspace_members: Vec<WorkspaceMemberSummary>,
    pub duplicate_crates: Vec<DuplicateCrate>,
    pub license_counts: BTreeMap<String, usize>,
    pub unlicensed_packages: Vec<String>,
    pub copyleft_packages: Vec<String>,
    pub workspace_min_msrv: Option<String>,
    pub highest_dependency_msrv: Option<String>,
    pub msrv_conflicts: Vec<MsrvConflict>,
}

fn run_cargo_metadata(workspace_root: &Path, offline: bool) -> Result<String> {
    let manifest = workspace_root.join("Cargo.toml");
    if !manifest.is_file() {
        anyhow::bail!("No Cargo.toml found at {}", manifest.display());
    }

    let mut cmd = Command::new("cargo");
    cmd.current_dir(workspace_root)
        .arg("metadata")
        .arg("--format-version")
        .arg("1")
        .arg("--manifest-path")
        .arg(&manifest);
    if offline {
        cmd.arg("--offline");
    }

    let output = cmd.output().with_context(|| {
        format!(
            "Failed to execute cargo metadata in {}",
            workspace_root.display()
        )
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("cargo metadata failed: {}", stderr.trim());
    }

    String::from_utf8(output.stdout).context("cargo metadata output was not UTF-8")
}

/// Execute `cargo metadata --format-version 1` for `workspace_root` and analyze the result.
pub fn analyze_workspace(workspace_root: &Path, offline: bool) -> Result<CargoAuditReport> {
    let stdout = run_cargo_metadata(workspace_root, offline)?;
    analyze_metadata_json(&stdout)
}

/// Generate a `CycloneDX` 1.5 JSON SBOM directly from `cargo metadata --format-version 1`.
pub fn generate_cyclonedx_sbom(workspace_root: &Path, offline: bool) -> Result<serde_json::Value> {
    let stdout = run_cargo_metadata(workspace_root, offline)?;
    cyclonedx_from_metadata_json(&stdout)
}

/// Pure `CycloneDX` 1.5 SBOM builder from raw `cargo metadata` JSON.
pub fn cyclonedx_from_metadata_json(raw_json: &str) -> Result<serde_json::Value> {
    let meta: CargoMetadata =
        serde_json::from_str(raw_json).context("Failed to parse cargo metadata JSON")?;
    let member_ids: BTreeSet<&str> = meta.workspace_members.iter().map(String::as_str).collect();

    let mut components = Vec::new();
    for pkg in &meta.packages {
        let comp_type = if member_ids.contains(pkg.id.as_str()) {
            "application"
        } else {
            "library"
        };
        let licenses: Vec<serde_json::Value> = pkg
            .license
            .as_deref()
            .filter(|l| !l.trim().is_empty())
            .map(|l| vec![serde_json::json!({ "expression": l.trim() })])
            .unwrap_or_default();

        components.push(serde_json::json!({
            "type": comp_type,
            "name": pkg.name,
            "version": pkg.version,
            "purl": format!("pkg:cargo/{}@{}", pkg.name, pkg.version),
            "licenses": licenses
        }));
    }

    Ok(serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "tools": [{
                "vendor": "vektor",
                "name": "vektor-analyzers",
                "version": env!("CARGO_PKG_VERSION")
            }]
        },
        "components": components
    }))
}

/// Compute workspace crates affected by `dirty_files` (direct owners + reverse internal dependents).
/// Inspired by `glastor-core/vortex` predictive selective CI.
pub fn affected_workspace_crates(
    workspace_root: &Path,
    dirty_files: &[String],
    offline: bool,
) -> Result<Vec<String>> {
    let stdout = run_cargo_metadata(workspace_root, offline)?;
    affected_workspace_crates_from_json(&stdout, workspace_root, dirty_files)
}

/// Pure affected-crate solver over raw `cargo metadata` JSON.
pub fn affected_workspace_crates_from_json(
    raw_json: &str,
    workspace_root: &Path,
    dirty_files: &[String],
) -> Result<Vec<String>> {
    let meta: CargoMetadata =
        serde_json::from_str(raw_json).context("Failed to parse cargo metadata JSON")?;
    let member_ids: BTreeSet<&str> = meta.workspace_members.iter().map(String::as_str).collect();

    let members: Vec<&CargoPackage> = meta
        .packages
        .iter()
        .filter(|p| member_ids.contains(p.id.as_str()))
        .collect();

    let mut affected: BTreeSet<String> = BTreeSet::new();

    for dirty in dirty_files {
        let dirty_norm = dirty.replace('\\', "/");
        for pkg in &members {
            let manifest_dir = Path::new(&pkg.manifest_path)
                .parent()
                .map(|p| p.strip_prefix(workspace_root).unwrap_or(p))
                .map(|p| p.display().to_string().replace('\\', "/"))
                .unwrap_or_default();
            let dir_trimmed = manifest_dir.trim_end_matches('/');

            let matches_dir = dir_trimmed.is_empty()
                || dirty_norm == dir_trimmed
                || dirty_norm.starts_with(&format!("{dir_trimmed}/"));
            if matches_dir {
                affected.insert(pkg.name.clone());
            }
        }
    }

    // Fixed-point propagation to reverse workspace dependents.
    loop {
        let before = affected.len();
        for pkg in &members {
            if pkg.dependencies.iter().any(|d| affected.contains(&d.name)) {
                affected.insert(pkg.name.clone());
            }
        }
        if affected.len() == before {
            break;
        }
    }

    Ok(affected.into_iter().collect())
}

/// Pure analyzer over raw `cargo metadata --format-version 1` JSON.
pub fn analyze_metadata_json(raw_json: &str) -> Result<CargoAuditReport> {
    let meta: CargoMetadata =
        serde_json::from_str(raw_json).context("Failed to parse cargo metadata JSON")?;

    let member_ids: BTreeSet<&str> = meta.workspace_members.iter().map(String::as_str).collect();

    let mut workspace_members = Vec::new();
    let mut versions_by_crate: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut license_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut unlicensed_packages = Vec::new();
    let mut copyleft_packages = Vec::new();

    let mut workspace_min_msrv: Option<String> = None;
    let mut highest_dependency_msrv: Option<String> = None;

    for pkg in &meta.packages {
        versions_by_crate
            .entry(pkg.name.clone())
            .or_default()
            .insert(pkg.version.clone());

        match pkg.license.as_deref().map(str::trim) {
            Some(lic) if !lic.is_empty() => {
                *license_counts.entry(lic.to_string()).or_insert(0) += 1;
                if is_copyleft(lic) {
                    copyleft_packages.push(format!("{} {} ({lic})", pkg.name, pkg.version));
                }
            }
            _ => {
                unlicensed_packages.push(format!("{} {}", pkg.name, pkg.version));
            }
        }

        if member_ids.contains(pkg.id.as_str()) {
            if let Some(ref msrv) = pkg.rust_version {
                workspace_min_msrv = Some(pick_min_semver(workspace_min_msrv.as_deref(), msrv));
            }

            let deps_with_default_features = pkg
                .dependencies
                .iter()
                .filter(|d| d.uses_default_features && d.features.is_empty())
                .map(|d| d.name.clone())
                .collect();

            workspace_members.push(WorkspaceMemberSummary {
                name: pkg.name.clone(),
                version: pkg.version.clone(),
                edition: pkg.edition.clone(),
                msrv: pkg.rust_version.clone(),
                license: pkg.license.clone(),
                direct_dependencies: pkg.dependencies.len(),
                deps_with_default_features,
            });
        } else if let Some(ref msrv) = pkg.rust_version {
            highest_dependency_msrv =
                Some(pick_max_semver(highest_dependency_msrv.as_deref(), msrv));
        }
    }

    let mut duplicate_crates: Vec<DuplicateCrate> = versions_by_crate
        .into_iter()
        .filter(|(_, versions)| versions.len() > 1)
        .map(|(name, versions)| DuplicateCrate {
            name,
            versions: versions.into_iter().collect(),
        })
        .collect();
    duplicate_crates.sort_by(|a, b| {
        b.versions
            .len()
            .cmp(&a.versions.len())
            .then_with(|| a.name.cmp(&b.name))
    });

    let mut msrv_conflicts = Vec::new();
    if let Some(ref ws_msrv) = workspace_min_msrv {
        for pkg in &meta.packages {
            if member_ids.contains(pkg.id.as_str()) {
                continue;
            }
            if let Some(ref dep_msrv) = pkg.rust_version {
                if compare_version_tuple(dep_msrv, ws_msrv).is_gt() {
                    msrv_conflicts.push(MsrvConflict {
                        package: pkg.name.clone(),
                        version: pkg.version.clone(),
                        required_msrv: dep_msrv.clone(),
                        workspace_msrv: ws_msrv.clone(),
                    });
                }
            }
        }
    }

    Ok(CargoAuditReport {
        total_packages: meta.packages.len(),
        workspace_members,
        duplicate_crates,
        license_counts,
        unlicensed_packages,
        copyleft_packages,
        workspace_min_msrv,
        highest_dependency_msrv,
        msrv_conflicts,
    })
}

fn is_copyleft(license: &str) -> bool {
    let upper = license.to_ascii_uppercase();
    // Flag strong copyleft unless dual-licensed with permissive terms via OR (not AND).
    let has_permissive_or = !upper.contains(" AND ")
        && upper.contains(" OR ")
        && (upper.contains("MIT") || upper.contains("APACHE-2.0") || upper.contains("BSD"));
    if has_permissive_or {
        return false;
    }
    upper.contains("GPL") || upper.contains("AGPL") || upper.contains("LGPL")
}

fn parse_version_tuple(v: &str) -> (u64, u64, u64) {
    let clean = v.split('-').next().unwrap_or(v);
    let mut parts = clean.split('.').map(|p| p.parse::<u64>().unwrap_or(0));
    let major = parts.next().unwrap_or(0);
    let minor = parts.next().unwrap_or(0);
    let patch = parts.next().unwrap_or(0);
    (major, minor, patch)
}

fn compare_version_tuple(a: &str, b: &str) -> std::cmp::Ordering {
    parse_version_tuple(a).cmp(&parse_version_tuple(b))
}

fn pick_min_semver(current: Option<&str>, candidate: &str) -> String {
    match current {
        None => candidate.to_string(),
        Some(cur) if compare_version_tuple(candidate, cur).is_lt() => candidate.to_string(),
        Some(cur) => cur.to_string(),
    }
}

fn pick_max_semver(current: Option<&str>, candidate: &str) -> String {
    match current {
        None => candidate.to_string(),
        Some(cur) if compare_version_tuple(candidate, cur).is_gt() => candidate.to_string(),
        Some(cur) => cur.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_duplicates_msrv_conflicts_and_licenses() {
        let sample = r#"{
            "workspace_members": ["my-app 0.1.0 (path+file:///repo)"],
            "packages": [
                {
                    "id": "my-app 0.1.0 (path+file:///repo)",
                    "name": "my-app",
                    "version": "0.1.0",
                    "edition": "2021",
                    "rust_version": "1.80",
                    "license": "MIT",
                    "dependencies": [
                        { "name": "dup-crate", "uses_default_features": true, "features": [] }
                    ]
                },
                {
                    "id": "dup-crate 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)",
                    "name": "dup-crate",
                    "version": "1.0.0",
                    "edition": "2021",
                    "rust_version": "1.75",
                    "license": "MIT OR Apache-2.0",
                    "dependencies": []
                },
                {
                    "id": "dup-crate 2.0.0 (registry+https://github.com/rust-lang/crates.io-index)",
                    "name": "dup-crate",
                    "version": "2.0.0",
                    "edition": "2021",
                    "rust_version": "1.85",
                    "license": "GPL-3.0-only",
                    "dependencies": []
                }
            ]
        }"#;

        let report = analyze_metadata_json(sample).expect("parse sample");
        assert_eq!(report.total_packages, 3);
        assert_eq!(report.duplicate_crates.len(), 1);
        assert_eq!(report.duplicate_crates[0].name, "dup-crate");
        assert_eq!(report.msrv_conflicts.len(), 1);
        assert_eq!(report.msrv_conflicts[0].required_msrv, "1.85");
        assert_eq!(report.copyleft_packages.len(), 1);
    }

    #[test]
    fn affected_crates_respects_directory_boundary_and_propagates_dependents() {
        let sample = r#"{
            "workspace_members": ["foo 0.1.0", "foo-bar 0.1.0", "app 0.1.0"],
            "packages": [
                {
                    "id": "foo 0.1.0",
                    "name": "foo",
                    "version": "0.1.0",
                    "manifest_path": "/repo/crates/foo/Cargo.toml",
                    "dependencies": []
                },
                {
                    "id": "foo-bar 0.1.0",
                    "name": "foo-bar",
                    "version": "0.1.0",
                    "manifest_path": "/repo/crates/foo-bar/Cargo.toml",
                    "dependencies": []
                },
                {
                    "id": "app 0.1.0",
                    "name": "app",
                    "version": "0.1.0",
                    "manifest_path": "/repo/crates/app/Cargo.toml",
                    "dependencies": [{ "name": "foo-bar" }]
                }
            ]
        }"#;

        let affected = affected_workspace_crates_from_json(
            sample,
            Path::new("/repo"),
            &["crates/foo-bar/src/lib.rs".to_string()],
        )
        .expect("compute affected");

        assert_eq!(affected, vec!["app".to_string(), "foo-bar".to_string()]);
    }

    #[test]
    fn generates_cyclonedx_1_5_and_flags_gpl_and_mit() {
        assert!(!is_copyleft("MIT OR GPL-3.0-only"));
        assert!(is_copyleft("GPL-3.0-only AND MIT"));
        assert!(is_copyleft("AGPL-3.0-or-later"));

        let sample = r#"{
            "workspace_members": ["app 0.1.0"],
            "packages": [
                {
                    "id": "app 0.1.0",
                    "name": "app",
                    "version": "0.1.0",
                    "license": "MIT",
                    "dependencies": []
                },
                {
                    "id": "serde 1.0.0",
                    "name": "serde",
                    "version": "1.0.0",
                    "license": "MIT OR Apache-2.0",
                    "dependencies": []
                }
            ]
        }"#;
        let sbom = cyclonedx_from_metadata_json(sample).expect("sbom");
        assert_eq!(sbom["bomFormat"], "CycloneDX");
        assert_eq!(sbom["specVersion"], "1.5");
        let components = sbom["components"].as_array().expect("components");
        assert_eq!(components.len(), 2);
        assert_eq!(components[0]["type"], "application");
        assert_eq!(components[1]["type"], "library");
        assert_eq!(components[1]["purl"], "pkg:cargo/serde@1.0.0");
    }
}

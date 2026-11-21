//! Pure-Rust deterministic static analyzers for Vektor (`cargo`, `secrets`, `trojan`, `gha`, `rust_ast`, `sarif`, `hygiene`).

#![deny(clippy::print_stdout, clippy::print_stderr)]

pub mod cargo;
pub mod config;
pub mod gha;
pub mod hygiene;
pub mod pii;
pub mod rust_ast;
pub mod sarif;
pub mod secrets;
pub mod trojan;

use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Maximum file size scanned by static analyzers (1 MiB).
pub const MAX_SCAN_FILE_BYTES: u64 = 1_048_576;
/// Maximum directory recursion depth to prevent path/symlink-loop exhaustion.
pub const MAX_WALK_DEPTH: usize = 64;

/// Unified severity scale across all Vektor static analyzers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Read a regular, non-symlink file into UTF-8 text using a single bounded `Read::take`
/// (prevents size-check TOCTOU, FIFO hangs, and OOM). Returns `Ok(None)` if the file
/// is oversized, binary (contains NUL), or non-UTF-8.
pub(crate) fn read_bounded_utf8(path: &Path, max_bytes: u64) -> Result<Option<String>> {
    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return Ok(None);
    }

    let file = File::open(path)?;
    let mut bytes = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;

    #[allow(clippy::cast_possible_truncation)]
    if bytes.len() > max_bytes as usize || bytes.contains(&0) {
        return Ok(None);
    }

    match String::from_utf8(bytes) {
        Ok(text) => Ok(Some(text)),
        Err(_) => Ok(None),
    }
}

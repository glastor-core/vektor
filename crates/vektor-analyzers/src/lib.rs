pub mod cargo;
pub mod gha;
pub mod hygiene;
pub mod rust_ast;
pub mod sarif;
pub mod secrets;
pub mod trojan;

use serde::{Deserialize, Serialize};

/// Unified severity scale across all Vektor static analyzers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

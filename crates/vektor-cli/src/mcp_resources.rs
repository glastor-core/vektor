use serde_json::json;
use vektor_core::mcp::{ResourceDefinition, ResourceHandler};
use vektor_state::StateStore;

use crate::mcp_server::collect_workspace_summary;

pub(crate) struct WorkspaceSummaryResource;

impl ResourceHandler for WorkspaceSummaryResource {
    fn definition(&self) -> ResourceDefinition {
        ResourceDefinition {
            uri: "vektor://workspace/summary".to_string(),
            name: "Workspace Summary".to_string(),
            description:
                "Deterministic Cargo, Git, SQLite state, and GitHub Actions workspace inventory."
                    .to_string(),
            mime_type: "application/json".to_string(),
        }
    }

    fn read(&self) -> anyhow::Result<String> {
        let cwd = std::env::current_dir()?;
        Ok(serde_json::to_string_pretty(&collect_workspace_summary(
            &cwd,
        ))?)
    }
}

pub(crate) struct SwarmTasksResource;

impl ResourceHandler for SwarmTasksResource {
    fn definition(&self) -> ResourceDefinition {
        ResourceDefinition {
            uri: "vektor://swarm/tasks".to_string(),
            name: "Swarm Task Blackboard".to_string(),
            description: "Current tasks stored in the SQLite WAL Swarm Task Blackboard."
                .to_string(),
            mime_type: "application/json".to_string(),
        }
    }

    fn read(&self) -> anyhow::Result<String> {
        let cwd = std::env::current_dir()?;
        let store = StateStore::open_workspace(&cwd)?;
        let tasks = store.list_tasks(None)?;
        Ok(serde_json::to_string_pretty(&json!({ "tasks": tasks }))?)
    }
}

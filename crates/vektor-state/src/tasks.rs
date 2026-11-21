use anyhow::Result;
use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::{now_unix, StateStore};

/// Shared task record on the Swarm Blackboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SwarmTask {
    pub id: String,
    pub title: String,
    pub owner_agent: String,
    pub status: String,
    pub depends_on: Vec<String>,
    pub notes: String,
    pub updated_at: i64,
}

impl StateStore {
    pub fn upsert_task(
        &self,
        id: &str,
        title: &str,
        owner_agent: &str,
        status: &str,
        depends_on: &[String],
        notes: &str,
    ) -> Result<SwarmTask> {
        let now = now_unix();
        let deps_json = serde_json::to_string(depends_on)?;
        self.conn.execute(
            "INSERT INTO tasks (id, title, owner_agent, status, depends_on, notes, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(id) DO UPDATE SET
                 title = excluded.title,
                 owner_agent = excluded.owner_agent,
                 status = excluded.status,
                 depends_on = excluded.depends_on,
                 notes = excluded.notes,
                 updated_at = excluded.updated_at",
            params![id, title, owner_agent, status, deps_json, notes, now],
        )?;

        Ok(SwarmTask {
            id: id.to_string(),
            title: title.to_string(),
            owner_agent: owner_agent.to_string(),
            status: status.to_string(),
            depends_on: depends_on.to_vec(),
            notes: notes.to_string(),
            updated_at: now,
        })
    }

    pub fn list_tasks(&self, status_filter: Option<&str>) -> Result<Vec<SwarmTask>> {
        let mut tasks = Vec::new();
        let (sql, filter): (&str, Vec<&str>) = match status_filter {
            Some(st) => (
                "SELECT id, title, owner_agent, status, depends_on, notes, updated_at
                 FROM tasks WHERE status = ?1 ORDER BY updated_at DESC",
                vec![st],
            ),
            None => (
                "SELECT id, title, owner_agent, status, depends_on, notes, updated_at
                 FROM tasks ORDER BY updated_at DESC",
                vec![],
            ),
        };

        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(filter), |row| {
            let deps_raw: String = row.get(4)?;
            let depends_on: Vec<String> = serde_json::from_str(&deps_raw).unwrap_or_default();
            Ok(SwarmTask {
                id: row.get(0)?,
                title: row.get(1)?,
                owner_agent: row.get(2)?,
                status: row.get(3)?,
                depends_on,
                notes: row.get(5)?,
                updated_at: row.get(6)?,
            })
        })?;

        for r in rows {
            tasks.push(r?);
        }
        Ok(tasks)
    }
}

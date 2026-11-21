//! `SQLite` WAL shared state for Vektor: Swarm Task Blackboard, File Locks,
//! incremental Rust AST symbol index, and dirty-file tracking for `Stop` gates.

use std::collections::BTreeSet;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rusqlite::{params, Connection, TransactionBehavior};
use serde::{Deserialize, Serialize};
use vektor_analyzers::rust_ast::RustSymbol;

const DEFAULT_LOCK_TTL_SECS: i64 = 1800; // 30 minutes

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

/// Active advisory file lock held by a specialist agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileLock {
    pub file_path: String,
    pub owner_agent: String,
    pub reason: String,
    pub acquired_at: i64,
    pub expires_at: i64,
}

/// Handle to `<workspace>/.vektor/state.db` in `SQLite` WAL mode.
pub struct StateStore {
    conn: Connection,
}

impl StateStore {
    /// Open or initialize `<workspace>/.vektor/state.db` in WAL mode.
    pub fn open_workspace(workspace_root: &Path) -> Result<Self> {
        let dir = workspace_root.join(".vektor");
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("Failed to create {}", dir.display()))?;
        let db_path = dir.join("state.db");
        let conn = Connection::open(&db_path)
            .with_context(|| format!("Failed to open {}", db_path.display()))?;
        Self::init(conn)
    }

    /// Open an in-memory `SQLite` store (for unit tests).
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA busy_timeout = 5000;
             PRAGMA synchronous = NORMAL;

             CREATE TABLE IF NOT EXISTS tasks (
                 id TEXT PRIMARY KEY,
                 title TEXT NOT NULL,
                 owner_agent TEXT NOT NULL DEFAULT '',
                 status TEXT NOT NULL DEFAULT 'pending',
                 depends_on TEXT NOT NULL DEFAULT '[]',
                 notes TEXT NOT NULL DEFAULT '',
                 updated_at INTEGER NOT NULL
             );

             CREATE TABLE IF NOT EXISTS file_locks (
                 file_path TEXT PRIMARY KEY,
                 owner_agent TEXT NOT NULL,
                 reason TEXT NOT NULL DEFAULT '',
                 acquired_at INTEGER NOT NULL,
                 expires_at INTEGER NOT NULL
             );

             CREATE TABLE IF NOT EXISTS ast_symbols (
                 file_path TEXT NOT NULL,
                 name TEXT NOT NULL,
                 kind TEXT NOT NULL,
                 visibility TEXT NOT NULL DEFAULT '',
                 line_start INTEGER NOT NULL,
                 line_end INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_ast_file ON ast_symbols(file_path);
             CREATE INDEX IF NOT EXISTS idx_ast_name ON ast_symbols(name);
             CREATE INDEX IF NOT EXISTS idx_ast_kind ON ast_symbols(kind);

             CREATE TABLE IF NOT EXISTS ast_file_meta (
                 file_path TEXT PRIMARY KEY,
                 mtime_secs INTEGER NOT NULL
             );

             CREATE TABLE IF NOT EXISTS dirty_files (
                 file_path TEXT PRIMARY KEY,
                 touched_at INTEGER NOT NULL
             );",
        )?;

        Ok(Self { conn })
    }

    // -------------------------------------------------------------------------
    // Swarm Task Blackboard
    // -------------------------------------------------------------------------

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

    // -------------------------------------------------------------------------
    // Advisory File Locks (prevent parallel swarm collisions)
    // -------------------------------------------------------------------------

    pub fn acquire_lock(
        &mut self,
        file_path: &str,
        owner_agent: &str,
        reason: &str,
        ttl_secs: Option<i64>,
    ) -> Result<std::result::Result<FileLock, FileLock>> {
        let now = now_unix();
        let normalized = normalize_rel(file_path);

        // Acquire a SQLite write lock up front so concurrent agents cannot race on check-then-set.
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        // Purge expired locks first.
        tx.execute(
            "DELETE FROM file_locks WHERE expires_at <= ?1",
            params![now],
        )?;

        // Check existing active lock.
        let existing: Option<FileLock> = {
            let mut stmt = tx.prepare(
                "SELECT file_path, owner_agent, reason, acquired_at, expires_at
                 FROM file_locks WHERE file_path = ?1",
            )?;
            stmt.query_row(params![&normalized], |row| {
                Ok(FileLock {
                    file_path: row.get(0)?,
                    owner_agent: row.get(1)?,
                    reason: row.get(2)?,
                    acquired_at: row.get(3)?,
                    expires_at: row.get(4)?,
                })
            })
            .ok()
        };

        if let Some(lock) = existing {
            if lock.owner_agent != owner_agent {
                tx.commit()?;
                return Ok(Err(lock));
            }
        }

        let expires_at = now + ttl_secs.unwrap_or(DEFAULT_LOCK_TTL_SECS).max(10);
        tx.execute(
            "INSERT INTO file_locks (file_path, owner_agent, reason, acquired_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(file_path) DO UPDATE SET
                 owner_agent = excluded.owner_agent,
                 reason = excluded.reason,
                 acquired_at = excluded.acquired_at,
                 expires_at = excluded.expires_at",
            params![normalized, owner_agent, reason, now, expires_at],
        )?;
        tx.commit()?;

        Ok(Ok(FileLock {
            file_path: normalized,
            owner_agent: owner_agent.to_string(),
            reason: reason.to_string(),
            acquired_at: now,
            expires_at,
        }))
    }

    pub fn release_lock(&self, file_path: &str, owner_agent: Option<&str>) -> Result<usize> {
        let normalized = normalize_rel(file_path);
        let affected = match owner_agent {
            Some(owner) => self.conn.execute(
                "DELETE FROM file_locks WHERE file_path = ?1 AND owner_agent = ?2",
                params![normalized, owner],
            )?,
            None => self.conn.execute(
                "DELETE FROM file_locks WHERE file_path = ?1",
                params![normalized],
            )?,
        };
        Ok(affected)
    }

    pub fn list_locks(&self) -> Result<Vec<FileLock>> {
        let now = now_unix();
        self.conn.execute(
            "DELETE FROM file_locks WHERE expires_at <= ?1",
            params![now],
        )?;

        let mut stmt = self.conn.prepare(
            "SELECT file_path, owner_agent, reason, acquired_at, expires_at
             FROM file_locks ORDER BY acquired_at DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(FileLock {
                file_path: row.get(0)?,
                owner_agent: row.get(1)?,
                reason: row.get(2)?,
                acquired_at: row.get(3)?,
                expires_at: row.get(4)?,
            })
        })?;

        let mut locks = Vec::new();
        for r in rows {
            locks.push(r?);
        }
        Ok(locks)
    }

    // -------------------------------------------------------------------------
    // Incremental Rust AST Symbol Index
    // -------------------------------------------------------------------------

    pub fn replace_file_symbols(
        &mut self,
        file_path: &str,
        mtime_secs: i64,
        symbols: &[RustSymbol],
    ) -> Result<()> {
        let normalized = normalize_rel(file_path);
        let tx = self.conn.transaction()?;
        tx.execute(
            "DELETE FROM ast_symbols WHERE file_path = ?1",
            params![&normalized],
        )?;

        {
            let mut insert = tx.prepare(
                "INSERT INTO ast_symbols (file_path, name, kind, visibility, line_start, line_end)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?;
            for sym in symbols {
                #[allow(clippy::cast_possible_wrap)]
                insert.execute(params![
                    &normalized,
                    &sym.name,
                    &sym.kind,
                    &sym.visibility,
                    sym.line_start as i64,
                    sym.line_end as i64,
                ])?;
            }
        }

        tx.execute(
            "INSERT INTO ast_file_meta (file_path, mtime_secs) VALUES (?1, ?2)
             ON CONFLICT(file_path) DO UPDATE SET mtime_secs = excluded.mtime_secs",
            params![&normalized, mtime_secs],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn indexed_mtime(&self, file_path: &str) -> Option<i64> {
        let normalized = normalize_rel(file_path);
        self.conn
            .query_row(
                "SELECT mtime_secs FROM ast_file_meta WHERE file_path = ?1",
                params![normalized],
                |row| row.get(0),
            )
            .ok()
    }

    /// Remove cached AST symbols and metadata for files that no longer exist on disk.
    pub fn prune_missing_ast_files(&mut self, existing_files: &BTreeSet<String>) -> Result<usize> {
        let indexed: Vec<String> = {
            let mut stmt = self.conn.prepare("SELECT file_path FROM ast_file_meta")?;
            let rows = stmt.query_map([], |row| row.get(0))?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r?);
            }
            out
        };

        let stale: Vec<String> = indexed
            .into_iter()
            .filter(|f| !existing_files.contains(f))
            .collect();
        if stale.is_empty() {
            return Ok(0);
        }

        let tx = self.conn.transaction()?;
        for path in &stale {
            tx.execute(
                "DELETE FROM ast_symbols WHERE file_path = ?1",
                params![path],
            )?;
            tx.execute(
                "DELETE FROM ast_file_meta WHERE file_path = ?1",
                params![path],
            )?;
        }
        tx.commit()?;
        Ok(stale.len())
    }

    pub fn query_symbols(
        &self,
        name_query: Option<&str>,
        kind_filter: Option<&str>,
        file_filter: Option<&str>,
        limit: usize,
    ) -> Result<Vec<RustSymbol>> {
        let name_pat = name_query.map_or_else(|| "%".to_string(), |q| format!("%{q}%"));
        let kind_pat = kind_filter.unwrap_or("%");
        let file_pat =
            file_filter.map_or_else(|| "%".to_string(), |f| format!("%{}%", normalize_rel(f)));

        let mut stmt = self.conn.prepare(
            "SELECT file_path, name, kind, visibility, line_start, line_end
             FROM ast_symbols
             WHERE name LIKE ?1 AND kind LIKE ?2 AND file_path LIKE ?3
             ORDER BY file_path ASC, line_start ASC
             LIMIT ?4",
        )?;

        #[allow(clippy::cast_possible_wrap)]
        let rows = stmt.query_map(params![name_pat, kind_pat, file_pat, limit as i64], |row| {
            let line_start: i64 = row.get(4)?;
            let line_end: i64 = row.get(5)?;
            #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
            Ok(RustSymbol {
                file: row.get(0)?,
                name: row.get(1)?,
                kind: row.get(2)?,
                visibility: row.get(3)?,
                line_start: line_start.max(0) as usize,
                line_end: line_end.max(0) as usize,
            })
        })?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    // -------------------------------------------------------------------------
    // Dirty Rust Files Tracker (for `Stop` quality gate)
    // -------------------------------------------------------------------------

    pub fn mark_dirty_file(&self, file_path: &str) -> Result<()> {
        let normalized = normalize_rel(file_path);
        self.conn.execute(
            "INSERT INTO dirty_files (file_path, touched_at) VALUES (?1, ?2)
             ON CONFLICT(file_path) DO UPDATE SET touched_at = excluded.touched_at",
            params![normalized, now_unix()],
        )?;
        Ok(())
    }

    pub fn list_dirty_files(&self) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT file_path FROM dirty_files ORDER BY touched_at DESC")?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn clear_dirty_files(&self) -> Result<()> {
        self.conn.execute("DELETE FROM dirty_files", [])?;
        Ok(())
    }
}

fn normalize_rel(path: &str) -> String {
    path.replace('\\', "/")
}

#[allow(clippy::cast_possible_wrap)]
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tasks_locks_and_ast_roundtrip() {
        let mut store = StateStore::open_in_memory().expect("in-memory sqlite");

        // Tasks
        store
            .upsert_task(
                "T-1",
                "Audit Cargo.lock",
                "crates-specialist",
                "in_progress",
                &[],
                "Checking MSRV",
            )
            .expect("upsert task");
        let tasks = store.list_tasks(Some("in_progress")).expect("list tasks");
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].id, "T-1");

        // Locks: conflict between two different agents
        let lock1 = store
            .acquire_lock(
                "crates/vektor-cli/src/main.rs",
                "rust-expert",
                "refactor",
                None,
            )
            .expect("acquire");
        assert!(lock1.is_ok());

        let lock2 = store
            .acquire_lock(
                "crates/vektor-cli/src/main.rs",
                "security-auditor",
                "audit",
                None,
            )
            .expect("conflict");
        assert!(lock2.is_err());

        assert_eq!(
            store
                .release_lock("crates/vektor-cli/src/main.rs", Some("rust-expert"))
                .expect("release"),
            1
        );

        // AST symbols
        let syms = vec![RustSymbol {
            file: "src/lib.rs".to_string(),
            name: "StateStore".to_string(),
            kind: "struct".to_string(),
            visibility: "pub".to_string(),
            line_start: 10,
            line_end: 15,
        }];
        store
            .replace_file_symbols("src/lib.rs", 1_700_000_000, &syms)
            .expect("index symbols");
        let found = store
            .query_symbols(Some("State"), Some("struct"), None, 10)
            .expect("query");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "StateStore");

        // Prune deleted files from AST index
        let pruned = store
            .prune_missing_ast_files(&BTreeSet::new())
            .expect("prune");
        assert_eq!(pruned, 1);
        assert!(store
            .query_symbols(Some("State"), Some("struct"), None, 10)
            .expect("query after prune")
            .is_empty());

        // Dirty files
        store.mark_dirty_file("src/lib.rs").expect("mark dirty");
        assert_eq!(store.list_dirty_files().expect("list dirty").len(), 1);
        store.clear_dirty_files().expect("clear");
        assert!(store.list_dirty_files().expect("empty").is_empty());
    }
}

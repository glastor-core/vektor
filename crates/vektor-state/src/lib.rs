//! `SQLite` WAL shared state for Vektor: Swarm Task Blackboard, File Locks,
//! incremental Rust AST symbol index, and dirty-file tracking for `Stop` gates.

#![deny(clippy::print_stdout, clippy::print_stderr)]

mod ast_cache;
mod locks;
mod schema;
mod taint;
mod tasks;

use std::fmt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rusqlite::Connection;

pub use locks::FileLock;
pub use taint::{SessionTaint, DEFAULT_TAINT_TTL_SECS};
pub use tasks::SwarmTask;

/// Handle to `<workspace>/.vektor/state.db` in `SQLite` WAL mode.
pub struct StateStore {
    pub(crate) conn: Connection,
}

impl fmt::Debug for StateStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StateStore").finish_non_exhaustive()
    }
}

impl StateStore {
    /// Open or initialize `<workspace>/.vektor/state.db` in WAL mode.
    pub fn open_workspace(workspace_root: &Path) -> Result<Self> {
        if !workspace_root.is_dir() {
            anyhow::bail!(
                "Workspace root does not exist or is not a directory: {}",
                workspace_root.display()
            );
        }
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
        conn.execute_batch(schema::SCHEMA_SQL)?;
        Ok(Self { conn })
    }
}

pub(crate) fn escape_like(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if matches!(ch, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

pub(crate) fn normalize_rel(path: &str) -> String {
    let replaced = path.replace('\\', "/");
    let mut parts: Vec<&str> = Vec::new();
    for segment in replaced.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                let _ = parts.pop();
            }
            seg => parts.push(seg),
        }
    }
    let joined = parts.join("/");
    if cfg!(windows) {
        joined.to_ascii_lowercase()
    } else {
        joined
    }
}

#[allow(clippy::cast_possible_wrap)]
pub(crate) fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use vektor_analyzers::rust_ast::RustSymbol;

    use super::*;

    #[test]
    fn tasks_locks_and_ast_roundtrip() {
        let mut store = StateStore::open_in_memory().expect("in-memory sqlite");

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

        let pruned = store
            .prune_missing_ast_files(&BTreeSet::new())
            .expect("prune");
        assert_eq!(pruned, 1);
        let after_prune = store
            .query_symbols(Some("State"), Some("struct"), None, 10)
            .expect("query after prune");
        assert!(
            after_prune.is_empty(),
            "expected empty, got: {after_prune:?}"
        );

        store.mark_dirty_file("src/lib.rs").expect("mark dirty");
        assert_eq!(store.list_dirty_files().expect("list dirty").len(), 1);
        store.clear_dirty_files().expect("clear");
        let empty_dirty = store.list_dirty_files().expect("empty");
        assert!(
            empty_dirty.is_empty(),
            "expected empty, got: {empty_dirty:?}"
        );
    }

    #[test]
    fn query_symbols_escapes_like_wildcards_and_uses_exact_kind() {
        let mut store = StateStore::open_in_memory().expect("in-memory");
        let syms = [
            RustSymbol {
                file: "src/hook_runner.rs".to_string(),
                name: "raw_op".to_string(),
                kind: "unsafe_fn".to_string(),
                visibility: "pub".to_string(),
                line_start: 1,
                line_end: 3,
            },
            RustSymbol {
                file: "src/hookXrunner.rs".to_string(),
                name: "safe_op".to_string(),
                kind: "fn".to_string(),
                visibility: "pub".to_string(),
                line_start: 5,
                line_end: 8,
            },
        ];
        store
            .replace_file_symbols("src/hook_runner.rs", 1, &syms[..1])
            .expect("index 1");
        store
            .replace_file_symbols("src/hookXrunner.rs", 1, &syms[1..])
            .expect("index 2");

        let wildcard_hits = store
            .query_symbols(None, Some("%"), None, 10)
            .expect("query");
        assert!(
            wildcard_hits.is_empty(),
            "expected no wildcard hits, got: {wildcard_hits:?}"
        );

        let matched = store
            .query_symbols(None, None, Some("hook_runner"), 10)
            .expect("query underscore");
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].name, "raw_op");
    }

    #[test]
    fn canonicalizes_lock_paths_and_serializes_concurrent_wal_acquisitions() {
        let dir =
            std::env::temp_dir().join(format!("vektor-wal-contention-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");

        {
            let mut s = StateStore::open_workspace(&dir).expect("open");
            assert!(s
                .acquire_lock("./src//lib.rs", "agent-a", "edit", Some(60))
                .expect("acquire")
                .is_ok());
            assert!(s
                .acquire_lock("src/lib.rs", "agent-b", "edit", Some(60))
                .expect("conflict")
                .is_err());
            assert_eq!(
                s.release_lock("src/lib.rs", Some("agent-a")).expect("rel"),
                1
            );
        }

        let threads = 12usize;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(threads));
        let mut handles = Vec::with_capacity(threads);

        for i in 0..threads {
            let dir_clone = dir.clone();
            let bar = std::sync::Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                let mut store = StateStore::open_workspace(&dir_clone).expect("open wal");
                let agent = format!("agent-{i}");
                bar.wait();
                store
                    .acquire_lock("crates/vektor-cli/src/main.rs", &agent, "race", Some(60))
                    .expect("no sqlite error")
            }));
        }

        let mut winners = Vec::new();
        let mut losers = Vec::new();
        for h in handles {
            match h.join().expect("thread join") {
                Ok(lock) => winners.push(lock.owner_agent),
                Err(holder) => losers.push(holder.owner_agent),
            }
        }

        assert_eq!(winners.len(), 1, "exactly one agent must win the lock");
        assert_eq!(losers.len(), threads - 1);
        assert!(losers.iter().all(|h| h == &winners[0]));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn session_taints_isolate_sessions_and_clear_cleanly() {
        let mut store = StateStore::open_in_memory().expect("in-memory");
        let fps = vec![vektor_analyzers::taint::TaintFingerprint {
            token_hash: "deadbeef0123456789".to_string(),
            kind: "env_value".to_string(),
            encoding: "raw".to_string(),
        }];

        assert_eq!(
            store
                .record_session_taints("sess-a", ".env", &fps, Some(60))
                .expect("record"),
            1
        );
        assert_eq!(
            store.active_session_taints("sess-a").expect("list a").len(),
            1
        );
        let b_taints = store.active_session_taints("sess-b").expect("list b");
        assert!(b_taints.is_empty(), "expected empty, got: {b_taints:?}");
        assert_eq!(store.clear_session_taints("sess-a").expect("clear"), 1);
        let a_after = store
            .active_session_taints("sess-a")
            .expect("list after clear");
        assert!(a_after.is_empty(), "expected empty, got: {a_after:?}");
    }
}

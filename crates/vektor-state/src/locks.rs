use anyhow::Result;
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};

use crate::{normalize_rel, now_unix, StateStore};

const DEFAULT_LOCK_TTL_SECS: i64 = 1800; // 30 minutes
const MIN_LOCK_TTL_SECS: i64 = 10;
const MAX_LOCK_TTL_SECS: i64 = 86_400; // 24 hours

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

impl StateStore {
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

        // Check existing active lock (propagate real SQLite errors instead of masking with `.ok()`).
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
            .optional()?
        };

        if let Some(lock) = existing {
            if lock.owner_agent != owner_agent {
                tx.commit()?;
                return Ok(Err(lock));
            }
        }

        let ttl = ttl_secs
            .unwrap_or(DEFAULT_LOCK_TTL_SECS)
            .clamp(MIN_LOCK_TTL_SECS, MAX_LOCK_TTL_SECS);
        let expires_at = now.saturating_add(ttl);
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
}

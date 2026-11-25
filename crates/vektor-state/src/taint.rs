//! Cross-tool Session Taint persistence in `SQLite` WAL.
//!
//! Stores only irreversible SHA-256 fingerprints (`token_hash`) with TTL expiration so
//! `PreToolUse` can detect multi-step secret/PII exfiltration without persisting plaintext secrets.

use anyhow::Result;
use rusqlite::{params, TransactionBehavior};
use serde::{Deserialize, Serialize};
use vektor_analyzers::taint::{ActiveTaint, TaintFingerprint};

use crate::{now_unix, StateStore};

/// Default TTL for session taint records (30 minutes).
pub const DEFAULT_TAINT_TTL_SECS: i64 = 1800;

/// Stored session taint record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionTaint {
    pub session_id: String,
    pub token_hash: String,
    pub source_path: String,
    pub kind: String,
    pub encoding: String,
    pub created_at: i64,
    pub expires_at: i64,
}

impl StateStore {
    /// Record irreversible taint fingerprints for `session_id` with TTL expiration.
    pub fn record_session_taints(
        &mut self,
        session_id: &str,
        source_path: &str,
        fingerprints: &[TaintFingerprint],
        ttl_secs: Option<i64>,
    ) -> Result<usize> {
        if fingerprints.is_empty() {
            return Ok(0);
        }
        let now = now_unix();
        let ttl = ttl_secs.unwrap_or(DEFAULT_TAINT_TTL_SECS).max(1);
        let expires = now + ttl;
        let sid = if session_id.is_empty() {
            "default"
        } else {
            session_id
        };

        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "DELETE FROM session_taints WHERE expires_at <= ?1",
            params![now],
        )?;

        let mut inserted = 0usize;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO session_taints
                     (session_id, token_hash, source_path, kind, encoding, created_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(session_id, token_hash) DO UPDATE SET
                     source_path = excluded.source_path,
                     kind = excluded.kind,
                     encoding = excluded.encoding,
                     expires_at = excluded.expires_at",
            )?;
            for fp in fingerprints {
                stmt.execute(params![
                    sid,
                    fp.token_hash,
                    source_path,
                    fp.kind,
                    fp.encoding,
                    now,
                    expires
                ])?;
                inserted += 1;
            }
        }
        tx.commit()?;
        Ok(inserted)
    }

    /// Return all non-expired taint records for `session_id` ready for `PreToolUse` matching.
    pub fn active_session_taints(&self, session_id: &str) -> Result<Vec<ActiveTaint>> {
        let now = now_unix();
        let sid = if session_id.is_empty() {
            "default"
        } else {
            session_id
        };
        let mut stmt = self.conn.prepare(
            "SELECT token_hash, source_path, kind, encoding
             FROM session_taints
             WHERE session_id = ?1 AND expires_at > ?2",
        )?;
        let rows = stmt.query_map(params![sid, now], |row| {
            Ok(ActiveTaint {
                token_hash: row.get(0)?,
                source_path: row.get(1)?,
                kind: row.get(2)?,
                encoding: row.get(3)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Clear all taint records for a session.
    pub fn clear_session_taints(&self, session_id: &str) -> Result<usize> {
        let sid = if session_id.is_empty() {
            "default"
        } else {
            session_id
        };
        Ok(self.conn.execute(
            "DELETE FROM session_taints WHERE session_id = ?1",
            params![sid],
        )?)
    }
}

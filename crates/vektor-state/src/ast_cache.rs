use std::collections::BTreeSet;

use anyhow::{Context, Result};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use vektor_analyzers::rust_ast::RustSymbol;

use crate::{escape_like, normalize_rel, now_unix, StateStore};

impl StateStore {
    pub fn replace_file_symbols(
        &mut self,
        file_path: &str,
        mtime_secs: i64,
        symbols: &[RustSymbol],
    ) -> Result<()> {
        let normalized = normalize_rel(file_path);
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
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

    pub fn indexed_mtime(&self, file_path: &str) -> Result<Option<i64>> {
        let normalized = normalize_rel(file_path);
        self.conn
            .query_row(
                "SELECT mtime_secs FROM ast_file_meta WHERE file_path = ?1",
                params![normalized],
                |row| row.get(0),
            )
            .optional()
            .context("Failed to query ast_file_meta mtime")
    }

    /// Remove cached AST symbols and metadata for files that no longer exist on disk.
    pub fn prune_missing_ast_files(&mut self, existing_files: &BTreeSet<String>) -> Result<usize> {
        let normalized_existing: BTreeSet<String> =
            existing_files.iter().map(|p| normalize_rel(p)).collect();
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
            .filter(|f| !normalized_existing.contains(f))
            .collect();
        if stale.is_empty() {
            return Ok(0);
        }

        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
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
        let name_pat = name_query.map(|q| format!("%{}%", escape_like(q)));
        let file_pat = file_filter.map(|f| format!("%{}%", escape_like(&normalize_rel(f))));

        let mut stmt = self.conn.prepare(
            "SELECT file_path, name, kind, visibility, line_start, line_end
             FROM ast_symbols
             WHERE (?1 IS NULL OR name LIKE ?1 ESCAPE '\\')
               AND (?2 IS NULL OR kind = ?2)
               AND (?3 IS NULL OR file_path LIKE ?3 ESCAPE '\\')
             ORDER BY file_path ASC, line_start ASC
             LIMIT ?4",
        )?;

        #[allow(clippy::cast_possible_wrap)]
        let rows = stmt.query_map(
            params![name_pat, kind_filter, file_pat, limit as i64],
            |row| {
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
            },
        )?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

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

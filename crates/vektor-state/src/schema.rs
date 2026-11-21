/// `SQLite` WAL pragmas and table DDL for `<workspace>/.vektor/state.db`.
pub(crate) const SCHEMA_SQL: &str = "
PRAGMA journal_mode = WAL;
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
);
";

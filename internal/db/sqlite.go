package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS hosts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip          TEXT NOT NULL,
    hostname    TEXT,
    os_guess    TEXT,
    source      TEXT NOT NULL,
    project     TEXT,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(ip)
);

CREATE TABLE IF NOT EXISTS open_ports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    port        INTEGER NOT NULL,
    protocol    TEXT NOT NULL DEFAULT 'tcp',
    state       TEXT NOT NULL DEFAULT 'open',
    service     TEXT,
    version     TEXT,
    source      TEXT NOT NULL,
    scanned_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(host_id, port, protocol)
);

CREATE TABLE IF NOT EXISTS host_metadata (
    host_id      INTEGER PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    manual_tag   TEXT,
    updated_at   DATETIME DEFAULT CURRENT_TIMESTAMP
);
`

// Open opens (or creates) the SQLite database at the given path,
// creating parent directories as needed, and applies the schema.
func Open(path string) (*sql.DB, error) {
	expanded, err := expandPath(path)
	if err != nil {
		return nil, fmt.Errorf("expand db path: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(expanded), 0o755); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}

	db, err := sql.Open("sqlite", expanded)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}

	// Migrations — all are no-ops if the column already exists.
	_, _ = db.Exec(`ALTER TABLE host_metadata ADD COLUMN pwned INTEGER NOT NULL DEFAULT 0`)
	_, _ = db.Exec(`ALTER TABLE hosts ADD COLUMN phase2_done INTEGER NOT NULL DEFAULT 0`)

	// Enable foreign keys and WAL mode for better concurrency.
	if _, err := db.Exec(`PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;`); err != nil {
		db.Close()
		return nil, fmt.Errorf("pragma: %w", err)
	}

	return db, nil
}

func expandPath(path string) (string, error) {
	if len(path) > 0 && path[0] == '~' {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, path[1:]), nil
	}
	return path, nil
}

package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	sqlite "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// SQLiteStore implements Store on a single SQLite file in WAL mode using the
// pure-Go modernc.org/sqlite driver (no cgo).
type SQLiteStore struct {
	db *sql.DB
}

// OpenSQLite opens (creating if needed) the database at path and applies the
// schema. WAL mode + busy timeout make concurrent handlers safe.
func OpenSQLite(path string) (*SQLiteStore, error) {
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	const schema = `
CREATE TABLE IF NOT EXISTS secrets (
	id         TEXT PRIMARY KEY,
	encrypted  TEXT NOT NULL,
	iv         TEXT NOT NULL,
	key_hash   TEXT NOT NULL,
	hint       TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL,
	expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_secrets_expires_at ON secrets(expires_at);
`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) Create(ctx context.Context, sec Secret) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO secrets (id, encrypted, iv, key_hash, hint, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		sec.ID, sec.Encrypted, sec.IV, sec.KeyHash, sec.Hint,
		sec.CreatedAt.Unix(), sec.ExpiresAt.Unix())
	if err != nil {
		var serr *sqlite.Error
		if errors.As(err, &serr) {
			code := serr.Code()
			if code == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY || code == sqlite3.SQLITE_CONSTRAINT_UNIQUE {
				return ErrDuplicateID
			}
		}
		return fmt.Errorf("insert secret: %w", err)
	}
	return nil
}

func (s *SQLiteStore) KeyHash(ctx context.Context, id string, now time.Time) (string, error) {
	var kh string
	err := s.db.QueryRowContext(ctx,
		`SELECT key_hash FROM secrets WHERE id = ? AND expires_at > ?`,
		id, now.Unix()).Scan(&kh)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("select key_hash: %w", err)
	}
	return kh, nil
}

func (s *SQLiteStore) BurnIfMatch(ctx context.Context, id, keyHash string, now time.Time) (Secret, error) {
	// Atomic compare-and-delete per SPEC §3 (SQLite 3.35+ DELETE ... RETURNING).
	query := `DELETE FROM secrets
		 WHERE id = ? AND key_hash = ? AND expires_at > ?
		 RETURNING encrypted, iv, key_hash, hint, created_at, expires_at`
	if len(keyHash) == 8 {
		// Legacy 8-char hash: compare against the stored prefix.
		query = `DELETE FROM secrets
		 WHERE id = ? AND substr(key_hash, 1, 8) = ? AND expires_at > ?
		 RETURNING encrypted, iv, key_hash, hint, created_at, expires_at`
	}
	var (
		sec                  = Secret{ID: id}
		createdAt, expiresAt int64
	)
	err := s.db.QueryRowContext(ctx, query, id, keyHash, now.Unix()).
		Scan(&sec.Encrypted, &sec.IV, &sec.KeyHash, &sec.Hint, &createdAt, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Secret{}, ErrNotFound
	}
	if err != nil {
		return Secret{}, fmt.Errorf("burn secret: %w", err)
	}
	sec.CreatedAt = time.Unix(createdAt, 0)
	sec.ExpiresAt = time.Unix(expiresAt, 0)
	return sec, nil
}

func (s *SQLiteStore) Hint(ctx context.Context, id string, now time.Time) (string, error) {
	var hint string
	err := s.db.QueryRowContext(ctx,
		`SELECT hint FROM secrets WHERE id = ? AND expires_at > ?`,
		id, now.Unix()).Scan(&hint)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("select hint: %w", err)
	}
	return hint, nil
}

func (s *SQLiteStore) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM secrets WHERE expires_at <= ?`, now.Unix())
	if err != nil {
		return 0, fmt.Errorf("delete expired: %w", err)
	}
	return res.RowsAffected()
}

func (s *SQLiteStore) Close() error { return s.db.Close() }

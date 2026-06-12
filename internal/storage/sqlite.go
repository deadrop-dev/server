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
CREATE TABLE IF NOT EXISTS requests (
	id                   TEXT PRIMARY KEY,
	public_key           TEXT NOT NULL,
	claim_proof          TEXT NOT NULL,
	prompt               TEXT NOT NULL DEFAULT '',
	fulfilled            INTEGER NOT NULL DEFAULT 0,
	encrypted            TEXT NOT NULL DEFAULT '',
	iv                   TEXT NOT NULL DEFAULT '',
	wrapped_key          TEXT NOT NULL DEFAULT '',
	wrap_iv              TEXT NOT NULL DEFAULT '',
	hkdf_salt            TEXT NOT NULL DEFAULT '',
	responder_public_key TEXT NOT NULL DEFAULT '',
	created_at           INTEGER NOT NULL,
	expires_at           INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_requests_expires_at ON requests(expires_at);
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

func (s *SQLiteStore) CreateRequest(ctx context.Context, req Request) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO requests (id, public_key, claim_proof, prompt, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		req.ID, req.PublicKey, req.ClaimProof, req.Prompt,
		req.CreatedAt.Unix(), req.ExpiresAt.Unix())
	if err != nil {
		var serr *sqlite.Error
		if errors.As(err, &serr) {
			code := serr.Code()
			if code == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY || code == sqlite3.SQLITE_CONSTRAINT_UNIQUE {
				return ErrDuplicateID
			}
		}
		return fmt.Errorf("insert request: %w", err)
	}
	return nil
}

func (s *SQLiteStore) RequestStatus(ctx context.Context, id string, now time.Time) (RequestStatus, error) {
	var (
		st        RequestStatus
		fulfilled int
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT public_key, prompt, fulfilled FROM requests WHERE id = ? AND expires_at > ?`,
		id, now.Unix()).Scan(&st.PublicKey, &st.Prompt, &fulfilled)
	if errors.Is(err, sql.ErrNoRows) {
		return RequestStatus{}, ErrNotFound
	}
	if err != nil {
		return RequestStatus{}, fmt.Errorf("select request status: %w", err)
	}
	st.Fulfilled = fulfilled == 1
	return st, nil
}

func (s *SQLiteStore) FulfillRequest(ctx context.Context, id string, resp RequestResponse, now time.Time) error {
	// The fulfilled = 0 condition makes the flip atomic: only one fulfill can
	// ever match a live row (SPEC §9.2). expires_at is deliberately not in
	// the SET list — the response inherits the request's original expiry
	// (§9.3).
	res, err := s.db.ExecContext(ctx,
		`UPDATE requests
		 SET encrypted = ?, iv = ?, wrapped_key = ?, wrap_iv = ?,
		     hkdf_salt = ?, responder_public_key = ?, fulfilled = 1
		 WHERE id = ? AND fulfilled = 0 AND expires_at > ?`,
		resp.Encrypted, resp.IV, resp.WrappedKey, resp.WrapIV,
		resp.HkdfSalt, resp.ResponderPublicKey, id, now.Unix())
	if err != nil {
		return fmt.Errorf("fulfill request: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("fulfill request: %w", err)
	}
	if n == 1 {
		return nil
	}
	// No live unfulfilled row matched: a live row can only mean it is already
	// fulfilled (the original response stays intact); otherwise it is gone.
	var fulfilled int
	err = s.db.QueryRowContext(ctx,
		`SELECT fulfilled FROM requests WHERE id = ? AND expires_at > ?`,
		id, now.Unix()).Scan(&fulfilled)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("fulfill request: %w", err)
	}
	return ErrAlreadyFulfilled
}

func (s *SQLiteStore) ClaimGate(ctx context.Context, id string, now time.Time) (string, bool, error) {
	var (
		proof     string
		fulfilled int
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT claim_proof, fulfilled FROM requests WHERE id = ? AND expires_at > ?`,
		id, now.Unix()).Scan(&proof, &fulfilled)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, ErrNotFound
	}
	if err != nil {
		return "", false, fmt.Errorf("select claim gate: %w", err)
	}
	return proof, fulfilled == 1, nil
}

func (s *SQLiteStore) ClaimBurn(ctx context.Context, id, claimProof string, now time.Time) (RequestResponse, error) {
	// Atomic compare-and-delete per SPEC §9.3 (claim-burn): the whole record
	// is gone in the same step that returns the blob, so two concurrent
	// correct-proof claims resolve to exactly one success.
	var resp RequestResponse
	err := s.db.QueryRowContext(ctx,
		`DELETE FROM requests
		 WHERE id = ? AND claim_proof = ? AND fulfilled = 1 AND expires_at > ?
		 RETURNING encrypted, iv, wrapped_key, wrap_iv, hkdf_salt, responder_public_key`,
		id, claimProof, now.Unix()).
		Scan(&resp.Encrypted, &resp.IV, &resp.WrappedKey, &resp.WrapIV,
			&resp.HkdfSalt, &resp.ResponderPublicKey)
	if errors.Is(err, sql.ErrNoRows) {
		return RequestResponse{}, ErrNotFound
	}
	if err != nil {
		return RequestResponse{}, fmt.Errorf("claim burn: %w", err)
	}
	return resp, nil
}

func (s *SQLiteStore) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	var total int64
	for _, table := range []string{"secrets", "requests"} {
		res, err := s.db.ExecContext(ctx, `DELETE FROM `+table+` WHERE expires_at <= ?`, now.Unix())
		if err != nil {
			return total, fmt.Errorf("delete expired %s: %w", table, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return total, fmt.Errorf("delete expired %s: %w", table, err)
		}
		total += n
	}
	return total, nil
}

func (s *SQLiteStore) Close() error { return s.db.Close() }

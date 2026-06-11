// Package storage defines the secret store interface and its SQLite and
// in-memory implementations.
//
// SPEC v2.0 §3: retrieval and revocation are atomic compare-and-delete
// operations — there is no window in which two requests presenting the
// correct keyHash can both receive the blob. The exact-match equality inside
// BurnIfMatch is the atomic gate; constant-time comparison for the 403-vs-404
// distinction happens at the application layer before it runs.
package storage

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrDuplicateID is returned by Create when the id already exists.
	ErrDuplicateID = errors.New("storage: duplicate id")
	// ErrNotFound is returned when no live (non-expired) row matches.
	ErrNotFound = errors.New("storage: not found")
)

// Secret is the stored record. The server only ever sees ciphertext.
type Secret struct {
	ID        string
	Encrypted string
	IV        string
	KeyHash   string
	Hint      string // "" = no hint
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Store is the persistence interface. All read paths take an explicit `now`
// so that expired secrets are invisible even before the cleanup loop runs.
type Store interface {
	// Create inserts a new secret. Returns ErrDuplicateID if the id exists
	// (live or not) — never overwrites.
	Create(ctx context.Context, s Secret) error

	// KeyHash returns the stored key hash of a live secret for the
	// application-layer constant-time gate. ErrNotFound if absent or expired.
	KeyHash(ctx context.Context, id string, now time.Time) (string, error)

	// BurnIfMatch atomically deletes the secret and returns it iff the stored
	// key hash matches. A 22-char keyHash is compared exactly; an 8-char
	// keyHash is compared against the stored hash's first 8 chars (legacy).
	// ErrNotFound if the secret is gone, expired, or the hash does not match
	// (a mismatch does NOT burn).
	BurnIfMatch(ctx context.Context, id, keyHash string, now time.Time) (Secret, error)

	// Hint returns the hint ("" if none) of a live secret without any key
	// proof. ErrNotFound if absent or expired.
	Hint(ctx context.Context, id string, now time.Time) (string, error)

	// DeleteExpired removes all secrets with expires_at <= now.
	DeleteExpired(ctx context.Context, now time.Time) (int64, error)

	Close() error
}

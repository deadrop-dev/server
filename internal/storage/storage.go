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
	// ErrAlreadyFulfilled is returned by FulfillRequest when a response is
	// already attached (the original response is left intact).
	ErrAlreadyFulfilled = errors.New("storage: request already fulfilled")
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

// Request is the stored reverse-flow record (SPEC v2.1 §9). As with secrets,
// the server only ever sees opaque material: a public key, a truncated claim
// proof, and — after fulfillment — ciphertext blobs. None of it decrypts
// anything.
type Request struct {
	ID         string
	PublicKey  string
	ClaimProof string
	Prompt     string // "" = no prompt
	Fulfilled  bool
	Response   RequestResponse // zero value until fulfilled
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

// RequestResponse is the opaque response blob a responder attaches to a
// request (SPEC §9.2).
type RequestResponse struct {
	Encrypted          string
	IV                 string
	WrappedKey         string
	WrapIV             string
	HkdfSalt           string
	ResponderPublicKey string
}

// RequestStatus is the responder-visible view of a live request.
type RequestStatus struct {
	PublicKey string
	Prompt    string
	Fulfilled bool
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

	// CreateRequest inserts a new secret request (SPEC §9.2). Returns
	// ErrDuplicateID if the id exists (live or not) — never overwrites.
	CreateRequest(ctx context.Context, req Request) error

	// RequestStatus returns the responder-visible view of a live request.
	// ErrNotFound if absent or expired.
	RequestStatus(ctx context.Context, id string, now time.Time) (RequestStatus, error)

	// FulfillRequest attaches the response to a live unfulfilled request.
	// Exactly one fulfill can ever succeed (SPEC §9.2): the flip to
	// fulfilled is a single atomic conditional step, and the stored expiry
	// is never touched — the response inherits the request's original
	// deadline (§9.3). ErrNotFound if absent or expired; ErrAlreadyFulfilled
	// if a response is already attached (the original is left intact).
	FulfillRequest(ctx context.Context, id string, resp RequestResponse, now time.Time) error

	// ClaimGate returns the stored claim proof and fulfillment state of a
	// live request for the application-layer constant-time gate (the §9.2
	// 404 → 403 → 202 precedence). ErrNotFound if absent or expired.
	ClaimGate(ctx context.Context, id string, now time.Time) (claimProof string, fulfilled bool, err error)

	// ClaimBurn atomically deletes the whole request record and returns the
	// response iff the stored claim proof matches exactly and the request is
	// fulfilled (claim-burn, SPEC §9.3). ErrNotFound if the request is gone,
	// expired, unfulfilled, or the proof does not match (a mismatch does NOT
	// burn).
	ClaimBurn(ctx context.Context, id, claimProof string, now time.Time) (RequestResponse, error)

	// DeleteExpired removes all secrets and requests with expires_at <= now.
	DeleteExpired(ctx context.Context, now time.Time) (int64, error)

	Close() error
}

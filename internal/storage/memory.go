package storage

import (
	"context"
	"sync"
	"time"
)

// MemoryStore implements Store with an in-process map. All operations hold a
// single mutex, which trivially satisfies SPEC §3 atomicity. Secrets do not
// survive a restart — for quick trials only.
type MemoryStore struct {
	mu       sync.Mutex
	secrets  map[string]Secret
	requests map[string]Request
}

// NewMemory returns an empty in-memory store.
func NewMemory() *MemoryStore {
	return &MemoryStore{
		secrets:  make(map[string]Secret),
		requests: make(map[string]Request),
	}
}

func (m *MemoryStore) Create(_ context.Context, s Secret) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.secrets[s.ID]; exists {
		return ErrDuplicateID
	}
	m.secrets[s.ID] = s
	return nil
}

func (m *MemoryStore) KeyHash(_ context.Context, id string, now time.Time) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.secrets[id]
	if !ok || !s.ExpiresAt.After(now) {
		return "", ErrNotFound
	}
	return s.KeyHash, nil
}

func (m *MemoryStore) BurnIfMatch(_ context.Context, id, keyHash string, now time.Time) (Secret, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.secrets[id]
	if !ok || !s.ExpiresAt.After(now) {
		return Secret{}, ErrNotFound
	}
	stored := s.KeyHash
	if len(keyHash) == 8 && len(stored) >= 8 {
		stored = stored[:8]
	}
	if stored != keyHash {
		return Secret{}, ErrNotFound // mismatch: do NOT burn
	}
	delete(m.secrets, id)
	return s, nil
}

func (m *MemoryStore) Hint(_ context.Context, id string, now time.Time) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.secrets[id]
	if !ok || !s.ExpiresAt.After(now) {
		return "", ErrNotFound
	}
	return s.Hint, nil
}

func (m *MemoryStore) CreateRequest(_ context.Context, req Request) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.requests[req.ID]; exists {
		return ErrDuplicateID
	}
	m.requests[req.ID] = req
	return nil
}

func (m *MemoryStore) RequestStatus(_ context.Context, id string, now time.Time) (RequestStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	req, ok := m.requests[id]
	if !ok || !req.ExpiresAt.After(now) {
		return RequestStatus{}, ErrNotFound
	}
	return RequestStatus{
		PublicKey: req.PublicKey,
		Prompt:    req.Prompt,
		Fulfilled: req.Fulfilled,
	}, nil
}

func (m *MemoryStore) FulfillRequest(_ context.Context, id string, resp RequestResponse, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	req, ok := m.requests[id]
	if !ok || !req.ExpiresAt.After(now) {
		return ErrNotFound
	}
	if req.Fulfilled {
		return ErrAlreadyFulfilled // original response stays intact
	}
	req.Fulfilled = true
	req.Response = resp
	m.requests[id] = req // ExpiresAt untouched (§9.3 TTL inheritance)
	return nil
}

func (m *MemoryStore) ClaimGate(_ context.Context, id string, now time.Time) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	req, ok := m.requests[id]
	if !ok || !req.ExpiresAt.After(now) {
		return "", false, ErrNotFound
	}
	return req.ClaimProof, req.Fulfilled, nil
}

func (m *MemoryStore) ClaimBurn(_ context.Context, id, claimProof string, now time.Time) (RequestResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	req, ok := m.requests[id]
	if !ok || !req.ExpiresAt.After(now) || !req.Fulfilled || req.ClaimProof != claimProof {
		return RequestResponse{}, ErrNotFound // mismatch: do NOT burn
	}
	delete(m.requests, id)
	return req.Response, nil
}

func (m *MemoryStore) DeleteExpired(_ context.Context, now time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	for id, s := range m.secrets {
		if !s.ExpiresAt.After(now) {
			delete(m.secrets, id)
			n++
		}
	}
	for id, req := range m.requests {
		if !req.ExpiresAt.After(now) {
			delete(m.requests, id)
			n++
		}
	}
	return n, nil
}

func (m *MemoryStore) Close() error { return nil }

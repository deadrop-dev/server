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
	mu      sync.Mutex
	secrets map[string]Secret
}

// NewMemory returns an empty in-memory store.
func NewMemory() *MemoryStore {
	return &MemoryStore{secrets: make(map[string]Secret)}
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
	return n, nil
}

func (m *MemoryStore) Close() error { return nil }

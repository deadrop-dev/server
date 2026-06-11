package storage

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

const (
	testHash22 = "AdD6vSUfy74rk7S5J7Jq0q" // 22-char key hash
	otherHash  = "BBBBBBBBBBBBBBBBBBBBBB"
)

func secretFixture(id string) Secret {
	return Secret{
		ID:        id,
		Encrypted: "QtqZE8SUEmf64ZDnmdktoHRY_DO_1Vm8Iyk-aaA",
		IV:        "AQAAAAAAAAAAAAAA",
		KeyHash:   testHash22,
		Hint:      "a hint",
		CreatedAt: time.Now().Truncate(time.Second),
		ExpiresAt: time.Now().Add(time.Hour).Truncate(time.Second),
	}
}

// forEachStore runs the subtest against both drivers.
func forEachStore(t *testing.T, fn func(t *testing.T, s Store)) {
	t.Helper()
	t.Run("sqlite", func(t *testing.T) {
		s, err := OpenSQLite(filepath.Join(t.TempDir(), "test.db"))
		if err != nil {
			t.Fatalf("OpenSQLite: %v", err)
		}
		t.Cleanup(func() { s.Close() })
		fn(t, s)
	})
	t.Run("memory", func(t *testing.T) {
		s := NewMemory()
		t.Cleanup(func() { s.Close() })
		fn(t, s)
	})
}

func TestCreateAndBurn(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		now := time.Now()
		want := secretFixture("id-create-burn-0123456789abcdef")
		if err := s.Create(ctx, want); err != nil {
			t.Fatalf("Create: %v", err)
		}

		kh, err := s.KeyHash(ctx, want.ID, now)
		if err != nil {
			t.Fatalf("KeyHash: %v", err)
		}
		if kh != testHash22 {
			t.Errorf("KeyHash = %q, want %q", kh, testHash22)
		}

		got, err := s.BurnIfMatch(ctx, want.ID, testHash22, now)
		if err != nil {
			t.Fatalf("BurnIfMatch: %v", err)
		}
		if got.Encrypted != want.Encrypted || got.IV != want.IV || got.Hint != want.Hint {
			t.Errorf("burned secret = %+v, want %+v", got, want)
		}

		// Burned: everything 404s now.
		if _, err := s.KeyHash(ctx, want.ID, now); !errors.Is(err, ErrNotFound) {
			t.Errorf("KeyHash after burn: err = %v, want ErrNotFound", err)
		}
		if _, err := s.BurnIfMatch(ctx, want.ID, testHash22, now); !errors.Is(err, ErrNotFound) {
			t.Errorf("second burn: err = %v, want ErrNotFound", err)
		}
	})
}

func TestBurnWrongHashDoesNotBurn(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		now := time.Now()
		sec := secretFixture("id-wrong-hash-0123456789abcdefg")
		if err := s.Create(ctx, sec); err != nil {
			t.Fatal(err)
		}
		if _, err := s.BurnIfMatch(ctx, sec.ID, otherHash, now); !errors.Is(err, ErrNotFound) {
			t.Fatalf("wrong-hash burn: err = %v, want ErrNotFound", err)
		}
		// Secret survives a wrong-key attempt.
		if _, err := s.KeyHash(ctx, sec.ID, now); err != nil {
			t.Fatalf("secret should survive wrong-hash attempt: %v", err)
		}
	})
}

func TestBurnLegacy8CharHash(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		now := time.Now()
		sec := secretFixture("id-legacy-hash-0123456789abcdef")
		if err := s.Create(ctx, sec); err != nil {
			t.Fatal(err)
		}
		// Wrong 8-char prefix does not burn.
		if _, err := s.BurnIfMatch(ctx, sec.ID, "XXXXXXXX", now); !errors.Is(err, ErrNotFound) {
			t.Fatalf("wrong legacy hash: err = %v, want ErrNotFound", err)
		}
		// Correct 8-char prefix burns.
		got, err := s.BurnIfMatch(ctx, sec.ID, testHash22[:8], now)
		if err != nil {
			t.Fatalf("legacy burn: %v", err)
		}
		if got.Encrypted != sec.Encrypted {
			t.Errorf("legacy burn payload mismatch")
		}
	})
}

func TestDuplicateID(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		sec := secretFixture("id-duplicate-0123456789abcdefgh")
		if err := s.Create(ctx, sec); err != nil {
			t.Fatal(err)
		}
		dup := sec
		dup.Encrypted = "shouldNotOverwrite"
		if err := s.Create(ctx, dup); !errors.Is(err, ErrDuplicateID) {
			t.Fatalf("duplicate Create: err = %v, want ErrDuplicateID", err)
		}
		// Original survives untouched.
		got, err := s.BurnIfMatch(ctx, sec.ID, testHash22, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if got.Encrypted != sec.Encrypted {
			t.Errorf("duplicate insert overwrote the original")
		}
	})
}

func TestExpiry(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		sec := secretFixture("id-expiry-0123456789abcdefghij")
		if err := s.Create(ctx, sec); err != nil {
			t.Fatal(err)
		}
		after := sec.ExpiresAt.Add(time.Second)

		// Expired secrets are invisible even before cleanup runs.
		if _, err := s.KeyHash(ctx, sec.ID, after); !errors.Is(err, ErrNotFound) {
			t.Errorf("KeyHash on expired: err = %v, want ErrNotFound", err)
		}
		if _, err := s.Hint(ctx, sec.ID, after); !errors.Is(err, ErrNotFound) {
			t.Errorf("Hint on expired: err = %v, want ErrNotFound", err)
		}
		if _, err := s.BurnIfMatch(ctx, sec.ID, testHash22, after); !errors.Is(err, ErrNotFound) {
			t.Errorf("Burn on expired: err = %v, want ErrNotFound", err)
		}

		n, err := s.DeleteExpired(ctx, after)
		if err != nil {
			t.Fatalf("DeleteExpired: %v", err)
		}
		if n != 1 {
			t.Errorf("DeleteExpired = %d, want 1", n)
		}
	})
}

func TestHint(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		now := time.Now()
		withHint := secretFixture("id-hint-yes-0123456789abcdefgh")
		noHint := secretFixture("id-hint-no-0123456789abcdefghi")
		noHint.Hint = ""
		if err := s.Create(ctx, withHint); err != nil {
			t.Fatal(err)
		}
		if err := s.Create(ctx, noHint); err != nil {
			t.Fatal(err)
		}
		h, err := s.Hint(ctx, withHint.ID, now)
		if err != nil || h != "a hint" {
			t.Errorf("Hint = %q, %v; want \"a hint\", nil", h, err)
		}
		h, err = s.Hint(ctx, noHint.ID, now)
		if err != nil || h != "" {
			t.Errorf("Hint = %q, %v; want \"\", nil", h, err)
		}
		if _, err := s.Hint(ctx, "id-never-existed-0123456789abcd", now); !errors.Is(err, ErrNotFound) {
			t.Errorf("Hint missing: err = %v, want ErrNotFound", err)
		}
	})
}

// TestBurnAtomicity: N concurrent correct-key burns must yield exactly one
// success — SPEC §3, the core zero-double-read invariant.
func TestBurnAtomicity(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		const workers = 8
		const iterations = 20
		for i := 0; i < iterations; i++ {
			sec := secretFixture(fmt.Sprintf("id-race-%04d-0123456789abcdefghi", i)[:31] + "x")
			if err := s.Create(ctx, sec); err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			var wg sync.WaitGroup
			start := make(chan struct{})
			results := make(chan error, workers)
			for w := 0; w < workers; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					_, err := s.BurnIfMatch(ctx, sec.ID, testHash22, now)
					results <- err
				}()
			}
			close(start)
			wg.Wait()
			close(results)
			var successes, notFound int
			for err := range results {
				switch {
				case err == nil:
					successes++
				case errors.Is(err, ErrNotFound):
					notFound++
				default:
					t.Fatalf("iteration %d: unexpected error: %v", i, err)
				}
			}
			if successes != 1 || notFound != workers-1 {
				t.Fatalf("iteration %d: successes = %d, notFound = %d; want 1, %d", i, successes, notFound, workers-1)
			}
		}
	})
}

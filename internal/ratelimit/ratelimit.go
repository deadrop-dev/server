// Package ratelimit implements a fixed-window per-key rate limiter
// (SPEC v2.0 §7). Windows are aligned to wall-clock boundaries; stale
// buckets are pruned opportunistically.
package ratelimit

import (
	"sync"
	"time"
)

// Result reports the outcome of one Allow call.
type Result struct {
	Allowed   bool
	Remaining int       // requests left in the current window
	Reset     time.Time // when the current window ends
}

type bucket struct {
	windowStart time.Time
	count       int
}

// Limiter is a fixed-window counter keyed by an opaque string (client IP).
type Limiter struct {
	mu        sync.Mutex
	limit     int
	window    time.Duration
	buckets   map[string]*bucket
	now       func() time.Time
	lastPrune time.Time
}

// New returns a limiter allowing `limit` requests per `window` per key.
func New(limit int, window time.Duration) *Limiter {
	return &Limiter{
		limit:   limit,
		window:  window,
		buckets: make(map[string]*bucket),
		now:     time.Now,
	}
}

// SetNow overrides the clock (tests only).
func (l *Limiter) SetNow(now func() time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.now = now
}

// Allow records one request for key and reports whether it is within limit.
func (l *Limiter) Allow(key string) Result {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	windowStart := now.Truncate(l.window)

	if now.Sub(l.lastPrune) >= l.window {
		for k, b := range l.buckets {
			if !b.windowStart.Equal(windowStart) {
				delete(l.buckets, k)
			}
		}
		l.lastPrune = now
	}

	b, ok := l.buckets[key]
	if !ok || !b.windowStart.Equal(windowStart) {
		b = &bucket{windowStart: windowStart}
		l.buckets[key] = b
	}
	b.count++

	remaining := l.limit - b.count
	if remaining < 0 {
		remaining = 0
	}
	return Result{
		Allowed:   b.count <= l.limit,
		Remaining: remaining,
		Reset:     windowStart.Add(l.window),
	}
}

// Len reports the number of tracked buckets (tests only).
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

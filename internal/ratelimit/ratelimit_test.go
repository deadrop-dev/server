package ratelimit

import (
	"testing"
	"time"
)

func TestLimitEnforced(t *testing.T) {
	now := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	l := New(3, time.Minute)
	l.SetNow(func() time.Time { return now })

	for i := 0; i < 3; i++ {
		res := l.Allow("1.2.3.4")
		if !res.Allowed {
			t.Fatalf("request %d: denied, want allowed", i+1)
		}
		if res.Remaining != 3-(i+1) {
			t.Errorf("request %d: Remaining = %d, want %d", i+1, res.Remaining, 3-(i+1))
		}
	}
	res := l.Allow("1.2.3.4")
	if res.Allowed {
		t.Fatal("request 4: allowed, want denied")
	}
	if res.Remaining != 0 {
		t.Errorf("denied Remaining = %d, want 0", res.Remaining)
	}
	wantReset := now.Truncate(time.Minute).Add(time.Minute)
	if !res.Reset.Equal(wantReset) {
		t.Errorf("Reset = %v, want %v", res.Reset, wantReset)
	}
}

func TestPerKeyIsolation(t *testing.T) {
	l := New(1, time.Minute)
	if !l.Allow("a").Allowed {
		t.Fatal("a/1 denied")
	}
	if l.Allow("a").Allowed {
		t.Fatal("a/2 allowed, want denied")
	}
	if !l.Allow("b").Allowed {
		t.Fatal("b/1 denied — keys must be isolated")
	}
}

func TestWindowRollover(t *testing.T) {
	now := time.Date(2026, 6, 12, 10, 0, 30, 0, time.UTC)
	l := New(1, time.Minute)
	l.SetNow(func() time.Time { return now })

	if !l.Allow("k").Allowed {
		t.Fatal("first request denied")
	}
	if l.Allow("k").Allowed {
		t.Fatal("second request in same window allowed")
	}
	now = now.Add(time.Minute) // next window
	if !l.Allow("k").Allowed {
		t.Fatal("request in next window denied — window must roll over")
	}
}

func TestStaleBucketsPruned(t *testing.T) {
	now := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	l := New(5, time.Minute)
	l.SetNow(func() time.Time { return now })
	for i := 0; i < 100; i++ {
		l.Allow(string(rune('a'+i%26)) + string(rune('0'+i/26)))
	}
	now = now.Add(3 * time.Minute)
	l.Allow("fresh")
	if n := l.Len(); n > 1 {
		t.Errorf("Len = %d after prune window, want <= 1", n)
	}
}

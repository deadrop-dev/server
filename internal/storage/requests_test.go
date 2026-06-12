package storage

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

const (
	testProof22 = "cLaImPrOoF0123456789ab" // 22-char claim proof
	wrongProof  = "BBBBBBBBBBBBBBBBBBBBBB"
)

func requestFixture(id string) Request {
	return Request{
		ID:         id,
		PublicKey:  "BHvBnbanQSX69Hzwg1WNsTYU0RROn4eW61iZhRLqJqWnyqM0MGrn2_5VTcUIm7E8YrUQ03eHg8MMWkESj0-Nprw",
		ClaimProof: testProof22,
		Prompt:     "a prompt",
		CreatedAt:  time.Now().Truncate(time.Second),
		ExpiresAt:  time.Now().Add(time.Hour).Truncate(time.Second),
	}
}

func responseFixture() RequestResponse {
	return RequestResponse{
		Encrypted:          "wktM55z2qRYZwFCwaJgPLwTMaG_kZj2FSU77BBIGLXKadG8",
		IV:                 "IwAAAAAAAAAAAAAA",
		WrappedKey:         "HrGue9y1Avhv3fhFu_ELWB-BuA3ET8qdd2yErTut0nhDuh_XJY_Y4ly12OodyOe2",
		WrapIV:             "IQAAAAAAAAAAAAAA",
		HkdfSalt:           "IAAAAAAAAAAAAAAAAAAAAA",
		ResponderPublicKey: "BMtbdkO6kE6SGwLktnWTQpvZXsYE4MhCJ4Yp5036VnPGMjzx_wceBfVh9QPoS6lYTYZMXzampIpq9UQxk2Ch-Qs",
	}
}

// requestExpiresAt reads the stored expiry directly from the concrete driver.
func requestExpiresAt(t *testing.T, s Store, id string) time.Time {
	t.Helper()
	switch st := s.(type) {
	case *SQLiteStore:
		var exp int64
		if err := st.db.QueryRow(`SELECT expires_at FROM requests WHERE id = ?`, id).Scan(&exp); err != nil {
			t.Fatalf("read expires_at: %v", err)
		}
		return time.Unix(exp, 0)
	case *MemoryStore:
		st.mu.Lock()
		defer st.mu.Unlock()
		req, ok := st.requests[id]
		if !ok {
			t.Fatalf("request %s not in memory store", id)
		}
		return req.ExpiresAt
	default:
		t.Fatalf("unknown store type %T", s)
		return time.Time{}
	}
}

func TestRequestCreateAndStatus(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		now := time.Now()
		want := requestFixture("id-req-create-0123456789abcdefg")
		if err := s.CreateRequest(ctx, want); err != nil {
			t.Fatalf("CreateRequest: %v", err)
		}

		st, err := s.RequestStatus(ctx, want.ID, now)
		if err != nil {
			t.Fatalf("RequestStatus: %v", err)
		}
		if st.PublicKey != want.PublicKey || st.Prompt != want.Prompt || st.Fulfilled {
			t.Errorf("status = %+v, want {%s %s false}", st, want.PublicKey, want.Prompt)
		}

		if _, err := s.RequestStatus(ctx, "id-never-existed-0123456789abcd", now); !errors.Is(err, ErrNotFound) {
			t.Errorf("unknown RequestStatus: err = %v, want ErrNotFound", err)
		}
	})
}

func TestRequestDuplicateID(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		req := requestFixture("id-req-duplicate-0123456789abcde")
		if err := s.CreateRequest(ctx, req); err != nil {
			t.Fatal(err)
		}
		dup := req
		dup.Prompt = "shouldNotOverwrite"
		if err := s.CreateRequest(ctx, dup); !errors.Is(err, ErrDuplicateID) {
			t.Fatalf("duplicate CreateRequest: err = %v, want ErrDuplicateID", err)
		}
		st, err := s.RequestStatus(ctx, req.ID, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if st.Prompt != req.Prompt {
			t.Errorf("duplicate insert overwrote the original")
		}
	})
}

func TestRequestFulfill(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		now := time.Now()
		req := requestFixture("id-req-fulfill-0123456789abcdef")
		resp := responseFixture()
		if err := s.CreateRequest(ctx, req); err != nil {
			t.Fatal(err)
		}

		if err := s.FulfillRequest(ctx, req.ID, resp, now); err != nil {
			t.Fatalf("FulfillRequest: %v", err)
		}
		if _, fulfilled, err := s.ClaimGate(ctx, req.ID, now); err != nil || !fulfilled {
			t.Errorf("ClaimGate after fulfill = fulfilled %v, %v; want true, nil", fulfilled, err)
		}

		// Exactly one response: the second fulfill fails and the original
		// stays intact.
		other := resp
		other.Encrypted = "shouldNotOverwrite"
		if err := s.FulfillRequest(ctx, req.ID, other, now); !errors.Is(err, ErrAlreadyFulfilled) {
			t.Fatalf("second fulfill: err = %v, want ErrAlreadyFulfilled", err)
		}
		got, err := s.ClaimBurn(ctx, req.ID, testProof22, now)
		if err != nil {
			t.Fatal(err)
		}
		if got != resp {
			t.Errorf("claimed response = %+v, want the original %+v", got, resp)
		}

		// Unknown id.
		if err := s.FulfillRequest(ctx, "id-never-existed-0123456789abcd", resp, now); !errors.Is(err, ErrNotFound) {
			t.Errorf("unknown fulfill: err = %v, want ErrNotFound", err)
		}
	})
}

// SPEC §9.3: the response inherits the request's original expiry — fulfill
// must not touch expires_at.
func TestRequestFulfillDoesNotTouchExpiry(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		req := requestFixture("id-req-ttl-0123456789abcdefghij")
		if err := s.CreateRequest(ctx, req); err != nil {
			t.Fatal(err)
		}
		before := requestExpiresAt(t, s, req.ID)
		if err := s.FulfillRequest(ctx, req.ID, responseFixture(), time.Now()); err != nil {
			t.Fatal(err)
		}
		after := requestExpiresAt(t, s, req.ID)
		if !after.Equal(before) {
			t.Errorf("fulfill changed expires_at: %v -> %v", before, after)
		}
	})
}

func TestRequestClaimBurn(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		now := time.Now()
		req := requestFixture("id-req-claim-0123456789abcdefgh")
		resp := responseFixture()
		if err := s.CreateRequest(ctx, req); err != nil {
			t.Fatal(err)
		}

		// Unfulfilled: a correct proof must not burn.
		if _, err := s.ClaimBurn(ctx, req.ID, testProof22, now); !errors.Is(err, ErrNotFound) {
			t.Fatalf("unfulfilled ClaimBurn: err = %v, want ErrNotFound", err)
		}
		if _, _, err := s.ClaimGate(ctx, req.ID, now); err != nil {
			t.Fatalf("request should survive an unfulfilled claim attempt: %v", err)
		}

		if err := s.FulfillRequest(ctx, req.ID, resp, now); err != nil {
			t.Fatal(err)
		}

		// Wrong proof: no burn.
		if _, err := s.ClaimBurn(ctx, req.ID, wrongProof, now); !errors.Is(err, ErrNotFound) {
			t.Fatalf("wrong-proof ClaimBurn: err = %v, want ErrNotFound", err)
		}
		if _, _, err := s.ClaimGate(ctx, req.ID, now); err != nil {
			t.Fatalf("request should survive a wrong-proof attempt: %v", err)
		}

		// Correct proof: blob returned, whole record gone.
		got, err := s.ClaimBurn(ctx, req.ID, testProof22, now)
		if err != nil {
			t.Fatalf("ClaimBurn: %v", err)
		}
		if got != resp {
			t.Errorf("claimed response = %+v, want %+v", got, resp)
		}
		if _, _, err := s.ClaimGate(ctx, req.ID, now); !errors.Is(err, ErrNotFound) {
			t.Errorf("ClaimGate after burn: err = %v, want ErrNotFound", err)
		}
		if _, err := s.RequestStatus(ctx, req.ID, now); !errors.Is(err, ErrNotFound) {
			t.Errorf("RequestStatus after burn: err = %v, want ErrNotFound", err)
		}
	})
}

func TestRequestExpiry(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		req := requestFixture("id-req-expiry-0123456789abcdefg")
		if err := s.CreateRequest(ctx, req); err != nil {
			t.Fatal(err)
		}
		if err := s.FulfillRequest(ctx, req.ID, responseFixture(), time.Now()); err != nil {
			t.Fatal(err)
		}
		after := req.ExpiresAt.Add(time.Second)

		// Expired requests are invisible even before cleanup runs.
		if _, err := s.RequestStatus(ctx, req.ID, after); !errors.Is(err, ErrNotFound) {
			t.Errorf("RequestStatus on expired: err = %v, want ErrNotFound", err)
		}
		if _, _, err := s.ClaimGate(ctx, req.ID, after); !errors.Is(err, ErrNotFound) {
			t.Errorf("ClaimGate on expired: err = %v, want ErrNotFound", err)
		}
		if err := s.FulfillRequest(ctx, req.ID, responseFixture(), after); !errors.Is(err, ErrNotFound) {
			t.Errorf("Fulfill on expired: err = %v, want ErrNotFound", err)
		}
		if _, err := s.ClaimBurn(ctx, req.ID, testProof22, after); !errors.Is(err, ErrNotFound) {
			t.Errorf("ClaimBurn on expired: err = %v, want ErrNotFound", err)
		}
	})
}

// DeleteExpired sweeps both tables: expired secrets AND expired requests.
func TestDeleteExpiredCoversRequests(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		now := time.Now()

		liveSecret := secretFixture("id-sweep-live-sec-0123456789abcd")
		deadSecret := secretFixture("id-sweep-dead-sec-0123456789abcd"[:31] + "x")
		deadSecret.ExpiresAt = now.Add(-time.Minute)
		liveReq := requestFixture("id-sweep-live-req-0123456789abcd")
		deadReq := requestFixture("id-sweep-dead-req-0123456789abcd"[:31] + "x")
		deadReq.ExpiresAt = now.Add(-time.Minute)

		for _, sec := range []Secret{liveSecret, deadSecret} {
			if err := s.Create(ctx, sec); err != nil {
				t.Fatal(err)
			}
		}
		for _, req := range []Request{liveReq, deadReq} {
			if err := s.CreateRequest(ctx, req); err != nil {
				t.Fatal(err)
			}
		}

		n, err := s.DeleteExpired(ctx, now)
		if err != nil {
			t.Fatalf("DeleteExpired: %v", err)
		}
		if n != 2 {
			t.Errorf("DeleteExpired = %d, want 2 (1 secret + 1 request)", n)
		}
		if _, err := s.KeyHash(ctx, liveSecret.ID, now); err != nil {
			t.Errorf("live secret swept: %v", err)
		}
		if _, err := s.RequestStatus(ctx, liveReq.ID, now); err != nil {
			t.Errorf("live request swept: %v", err)
		}
	})
}

// TestFulfillAtomicity: N concurrent fulfills must yield exactly one success
// and ErrAlreadyFulfilled for the rest — SPEC §9.2, no window in which two
// responders both win.
func TestFulfillAtomicity(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		const workers = 8
		const iterations = 20
		for i := 0; i < iterations; i++ {
			req := requestFixture(fmt.Sprintf("id-freq-%04d-0123456789abcdefghi", i)[:31] + "x")
			if err := s.CreateRequest(ctx, req); err != nil {
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
					results <- s.FulfillRequest(ctx, req.ID, responseFixture(), now)
				}()
			}
			close(start)
			wg.Wait()
			close(results)
			var successes, conflicts int
			for err := range results {
				switch {
				case err == nil:
					successes++
				case errors.Is(err, ErrAlreadyFulfilled):
					conflicts++
				default:
					t.Fatalf("iteration %d: unexpected error: %v", i, err)
				}
			}
			if successes != 1 || conflicts != workers-1 {
				t.Fatalf("iteration %d: successes = %d, conflicts = %d; want 1, %d", i, successes, conflicts, workers-1)
			}
		}
	})
}

// TestClaimBurnAtomicity: N concurrent correct-proof claims must yield
// exactly one success — SPEC §9.3, the claim-burn analogue of SPEC §3.
func TestClaimBurnAtomicity(t *testing.T) {
	forEachStore(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		const workers = 8
		const iterations = 20
		for i := 0; i < iterations; i++ {
			req := requestFixture(fmt.Sprintf("id-creq-%04d-0123456789abcdefghi", i)[:31] + "x")
			if err := s.CreateRequest(ctx, req); err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			if err := s.FulfillRequest(ctx, req.ID, responseFixture(), now); err != nil {
				t.Fatal(err)
			}
			var wg sync.WaitGroup
			start := make(chan struct{})
			results := make(chan error, workers)
			for w := 0; w < workers; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					_, err := s.ClaimBurn(ctx, req.ID, testProof22, now)
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

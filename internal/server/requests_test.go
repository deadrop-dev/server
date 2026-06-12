package server

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/deadrop-dev/server/internal/config"
	"github.com/deadrop-dev/server/internal/storage"
)

func TestRequestCreateAndStatus(t *testing.T) {
	e := newTestEnv(t, nil)
	resp, _ := e.do(t, "POST", "/api/requests", requestBody(nil), nil)
	wantStatus(t, resp, 201)
	if loc := resp.Header.Get("Location"); loc != "/r/"+testID {
		t.Errorf("Location = %q, want /r/%s", loc, testID)
	}

	resp, body := e.do(t, "GET", "/api/requests/"+testID, "", nil)
	wantStatus(t, resp, 200)
	if body["publicKey"] != testPublicKey {
		t.Errorf("publicKey = %v, want %s", body["publicKey"], testPublicKey)
	}
	if body["prompt"] != testPrompt {
		t.Errorf("prompt = %v, want %q", body["prompt"], testPrompt)
	}
	if body["fulfilled"] != false {
		t.Errorf("fulfilled = %v, want false", body["fulfilled"])
	}
}

func TestRequestCreateDuplicate409(t *testing.T) {
	e := newTestEnv(t, nil)
	resp, _ := e.do(t, "POST", "/api/requests", requestBody(nil), nil)
	wantStatus(t, resp, 201)
	resp, body := e.do(t, "POST", "/api/requests", requestBody(map[string]any{"prompt": "a different prompt"}), nil)
	wantError(t, resp, body, 409)
	// Original not overwritten.
	resp, body = e.do(t, "GET", "/api/requests/"+testID, "", nil)
	wantStatus(t, resp, 200)
	if body["prompt"] != testPrompt {
		t.Errorf("duplicate overwrote the original")
	}
}

func TestRequestCreateValidation(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"id too short", requestBody(map[string]any{"id": strings.Repeat("A", 31)})},
		{"id too long", requestBody(map[string]any{"id": strings.Repeat("A", 33)})},
		{"id bad chars", requestBody(map[string]any{"id": strings.Repeat("A", 30) + "+/"})},
		{"id missing", requestBody(map[string]any{"id": nil})},
		{"publicKey too short", requestBody(map[string]any{"publicKey": testPublicKey[:86]})},
		{"publicKey too long", requestBody(map[string]any{"publicKey": testPublicKey + "A"})},
		{"publicKey bad point tag", requestBody(map[string]any{"publicKey": testBadTagKey})},
		{"publicKey bad chars", requestBody(map[string]any{"publicKey": strings.Repeat("+", 87)})},
		{"publicKey missing", requestBody(map[string]any{"publicKey": nil})},
		{"claimProof 21", requestBody(map[string]any{"claimProof": strings.Repeat("A", 21)})},
		{"claimProof 23", requestBody(map[string]any{"claimProof": strings.Repeat("A", 23)})},
		{"claimProof bad chars", requestBody(map[string]any{"claimProof": strings.Repeat("+", 22)})},
		{"claimProof missing", requestBody(map[string]any{"claimProof": nil})},
		{"prompt 141 chars", requestBody(map[string]any{"prompt": strings.Repeat("p", 141)})},
		{"not json", "{nope"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newTestEnv(t, nil)
			resp, body := e.do(t, "POST", "/api/requests", c.body, nil)
			wantError(t, resp, body, 400)
		})
	}

	t.Run("prompt exactly 140 accepted", func(t *testing.T) {
		e := newTestEnv(t, nil)
		resp, _ := e.do(t, "POST", "/api/requests", requestBody(map[string]any{"prompt": strings.Repeat("p", 140)}), nil)
		wantStatus(t, resp, 201)
	})
}

// An absent prompt is stored as — and round-trips as — the empty string.
func TestRequestPromptAbsentIsEmptyString(t *testing.T) {
	e := newTestEnv(t, nil)
	resp, _ := e.do(t, "POST", "/api/requests", requestBody(map[string]any{"prompt": nil}), nil)
	wantStatus(t, resp, 201)
	resp, body := e.do(t, "GET", "/api/requests/"+testID, "", nil)
	wantStatus(t, resp, 200)
	if v, present := body["prompt"]; !present || v != "" {
		t.Errorf("prompt = %v (present=%v), want \"\"", v, present)
	}
}

// §9.2: expiresMinutes is clamped to [1, 10080], default 1440 — asserted
// behaviorally: the request is alive just before the clamped deadline and
// gone just after.
func TestRequestExpiresMinutesClamping(t *testing.T) {
	cases := []struct {
		name    string
		expires any // nil = omit field
		want    time.Duration
	}{
		{"zero clamps to 1", 0, time.Minute},
		{"negative clamps to 1", -5, time.Minute},
		{"above max clamps to 10080", 999999, 10080 * time.Minute},
		{"absent defaults to 1440", nil, 1440 * time.Minute},
		{"normal passes through", 120, 120 * time.Minute},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newTestEnv(t, nil)
			resp, _ := e.do(t, "POST", "/api/requests", requestBody(map[string]any{"expiresMinutes": c.expires}), nil)
			wantStatus(t, resp, 201)

			e.clock.Advance(c.want - time.Second)
			resp, _ = e.do(t, "GET", "/api/requests/"+testID, "", nil)
			wantStatus(t, resp, 200)

			e.clock.Advance(2 * time.Second)
			resp, body := e.do(t, "GET", "/api/requests/"+testID, "", nil)
			wantError(t, resp, body, 404)
		})
	}
}

func TestRequestStatusNotFound(t *testing.T) {
	e := newTestEnv(t, nil)
	// Unknown id.
	resp, body := e.do(t, "GET", "/api/requests/"+strings.Repeat("z", 32), "", nil)
	wantError(t, resp, body, 404)
	// A malformed id can never name a live request: 404, not 400.
	resp, body = e.do(t, "GET", "/api/requests/shortid", "", nil)
	wantError(t, resp, body, 404)
	// Expired.
	resp, _ = e.do(t, "POST", "/api/requests", requestBody(map[string]any{"expiresMinutes": 1}), nil)
	wantStatus(t, resp, 201)
	e.clock.Advance(2 * time.Minute)
	resp, body = e.do(t, "GET", "/api/requests/"+testID, "", nil)
	wantError(t, resp, body, 404)
}

func TestRequestFulfillFlow(t *testing.T) {
	e := newTestEnv(t, nil)
	resp, _ := e.do(t, "POST", "/api/requests", requestBody(nil), nil)
	wantStatus(t, resp, 201)

	resp, _ = e.do(t, "POST", "/api/requests/"+testID+"/response", fulfillBody(nil), nil)
	wantStatus(t, resp, 201)

	resp, body := e.do(t, "GET", "/api/requests/"+testID, "", nil)
	wantStatus(t, resp, 200)
	if body["fulfilled"] != true {
		t.Errorf("fulfilled = %v, want true after fulfill", body["fulfilled"])
	}

	// Exactly one response per request: a second fulfill is 409 and the
	// original response stays intact.
	other := "ZZZZE8SUEmf64ZDnmdktoHRY_DO_1Vm8Iyk-aaA"
	resp, body = e.do(t, "POST", "/api/requests/"+testID+"/response", fulfillBody(map[string]any{"encrypted": other}), nil)
	wantError(t, resp, body, 409)

	resp, body = e.do(t, "GET", "/api/requests/"+testID+"/response?proof="+testClaimProof, "", nil)
	wantStatus(t, resp, 200)
	if body["encrypted"] != testEnc {
		t.Errorf("encrypted = %v, want the original %s", body["encrypted"], testEnc)
	}
}

func TestRequestFulfillNotFound(t *testing.T) {
	e := newTestEnv(t, nil)
	// Unknown id.
	resp, body := e.do(t, "POST", "/api/requests/"+strings.Repeat("z", 32)+"/response", fulfillBody(nil), nil)
	wantError(t, resp, body, 404)
	// Malformed id: 404, not 400.
	resp, body = e.do(t, "POST", "/api/requests/shortid/response", fulfillBody(nil), nil)
	wantError(t, resp, body, 404)
	// Expired.
	resp, _ = e.do(t, "POST", "/api/requests", requestBody(map[string]any{"expiresMinutes": 1}), nil)
	wantStatus(t, resp, 201)
	e.clock.Advance(2 * time.Minute)
	resp, body = e.do(t, "POST", "/api/requests/"+testID+"/response", fulfillBody(nil), nil)
	wantError(t, resp, body, 404)
}

func TestRequestFulfillValidation(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"encrypted empty", fulfillBody(map[string]any{"encrypted": ""})},
		{"encrypted missing", fulfillBody(map[string]any{"encrypted": nil})},
		{"encrypted too long", fulfillBody(map[string]any{"encrypted": strings.Repeat("A", 65537)})},
		{"encrypted bad chars", fulfillBody(map[string]any{"encrypted": "abc+def="})},
		{"iv 15 chars", fulfillBody(map[string]any{"iv": strings.Repeat("A", 15)})},
		{"iv missing", fulfillBody(map[string]any{"iv": nil})},
		{"wrappedKey 63", fulfillBody(map[string]any{"wrappedKey": strings.Repeat("A", 63)})},
		{"wrappedKey 65", fulfillBody(map[string]any{"wrappedKey": strings.Repeat("A", 65)})},
		{"wrappedKey missing", fulfillBody(map[string]any{"wrappedKey": nil})},
		{"wrapIv 17 chars", fulfillBody(map[string]any{"wrapIv": strings.Repeat("A", 17)})},
		{"wrapIv missing", fulfillBody(map[string]any{"wrapIv": nil})},
		{"hkdfSalt 21", fulfillBody(map[string]any{"hkdfSalt": strings.Repeat("A", 21)})},
		{"hkdfSalt 23", fulfillBody(map[string]any{"hkdfSalt": strings.Repeat("A", 23)})},
		{"hkdfSalt missing", fulfillBody(map[string]any{"hkdfSalt": nil})},
		{"responderPublicKey bad point tag", fulfillBody(map[string]any{"responderPublicKey": testBadTagKey})},
		{"responderPublicKey too short", fulfillBody(map[string]any{"responderPublicKey": testPublicKey[:86]})},
		{"responderPublicKey missing", fulfillBody(map[string]any{"responderPublicKey": nil})},
		{"not json", "{nope"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Body ceiling raised so the 65537-char case reaches field
			// validation instead of the 413 reader cap.
			e := newTestEnv(t, func(cfg *config.Config) { cfg.Limits.MaxBodyBytes = 131072 })
			resp, _ := e.do(t, "POST", "/api/requests", requestBody(nil), nil)
			wantStatus(t, resp, 201)
			resp, body := e.do(t, "POST", "/api/requests/"+testID+"/response", c.body, nil)
			wantError(t, resp, body, 400)
		})
	}

	t.Run("max valid encrypted accepted", func(t *testing.T) {
		e := newTestEnv(t, func(cfg *config.Config) { cfg.Limits.MaxBodyBytes = 131072 })
		resp, _ := e.do(t, "POST", "/api/requests", requestBody(nil), nil)
		wantStatus(t, resp, 201)
		resp, _ = e.do(t, "POST", "/api/requests/"+testID+"/response", fulfillBody(map[string]any{"encrypted": strings.Repeat("A", 65536)}), nil)
		wantStatus(t, resp, 201)
	})

	t.Run("body size limit", func(t *testing.T) {
		e := newTestEnv(t, func(cfg *config.Config) { cfg.Limits.MaxBodyBytes = 2048 })
		resp, _ := e.do(t, "POST", "/api/requests", requestBody(nil), nil)
		wantStatus(t, resp, 201)
		resp, body := e.do(t, "POST", "/api/requests/"+testID+"/response", fulfillBody(map[string]any{"encrypted": strings.Repeat("A", 4096)}), nil)
		wantError(t, resp, body, 413)
	})
}

// §9.2 normative claim precedence: 404 → 403 → 202 → 200.
func TestRequestClaimPrecedence(t *testing.T) {
	missing := strings.Repeat("z", 32)
	wrong := "BBBBBBBBBBBBBBBBBBBBBB" // valid format, wrong value

	t.Run("unknown id wins over any proof shape", func(t *testing.T) {
		e := newTestEnv(t, nil)
		for name, proof := range map[string]string{
			"correct format": wrong,
			"malformed":      "tooshort",
			"missing":        "",
		} {
			path := "/api/requests/" + missing + "/response"
			if proof != "" {
				path += "?proof=" + proof
			}
			resp, _ := e.do(t, "GET", path, "", nil)
			if resp.StatusCode != 404 {
				t.Errorf("%s proof on unknown id: status = %d, want 404", name, resp.StatusCode)
			}
		}
	})

	t.Run("known id, bad proof is 403 without burning", func(t *testing.T) {
		e := newTestEnv(t, nil)
		resp, _ := e.do(t, "POST", "/api/requests", requestBody(nil), nil)
		wantStatus(t, resp, 201)
		resp, _ = e.do(t, "POST", "/api/requests/"+testID+"/response", fulfillBody(nil), nil)
		wantStatus(t, resp, 201)

		// Wrong value, malformed, and missing proofs all gate with 403.
		resp, body := e.do(t, "GET", "/api/requests/"+testID+"/response?proof="+wrong, "", nil)
		wantError(t, resp, body, 403)
		resp, body = e.do(t, "GET", "/api/requests/"+testID+"/response?proof=tooshort", "", nil)
		wantError(t, resp, body, 403)
		resp, body = e.do(t, "GET", "/api/requests/"+testID+"/response", "", nil)
		wantError(t, resp, body, 403)

		// Nothing burned: the correct proof still claims.
		resp, _ = e.do(t, "GET", "/api/requests/"+testID+"/response?proof="+testClaimProof, "", nil)
		wantStatus(t, resp, 200)
	})

	t.Run("valid proof before fulfillment is 202 pending without burning", func(t *testing.T) {
		e := newTestEnv(t, nil)
		resp, _ := e.do(t, "POST", "/api/requests", requestBody(nil), nil)
		wantStatus(t, resp, 201)

		for i := 0; i < 2; i++ { // repeatable: nothing burned
			resp, body := e.do(t, "GET", "/api/requests/"+testID+"/response?proof="+testClaimProof, "", nil)
			wantStatus(t, resp, 202)
			if body["status"] != "pending" {
				t.Errorf("body = %v, want {status: pending}", body)
			}
		}
		// The request is still live for the responder.
		resp, _ = e.do(t, "GET", "/api/requests/"+testID, "", nil)
		wantStatus(t, resp, 200)
	})

	t.Run("fulfilled claim returns the blob and burns the whole record", func(t *testing.T) {
		e := newTestEnv(t, nil)
		resp, _ := e.do(t, "POST", "/api/requests", requestBody(nil), nil)
		wantStatus(t, resp, 201)
		resp, _ = e.do(t, "POST", "/api/requests/"+testID+"/response", fulfillBody(nil), nil)
		wantStatus(t, resp, 201)

		resp, body := e.do(t, "GET", "/api/requests/"+testID+"/response?proof="+testClaimProof, "", nil)
		wantStatus(t, resp, 200)
		want := map[string]string{
			"encrypted":          testEnc,
			"iv":                 testIV,
			"wrappedKey":         testWrappedKey,
			"wrapIv":             testIV,
			"hkdfSalt":           testHkdfSalt,
			"responderPublicKey": testPublicKey,
		}
		for k, v := range want {
			if body[k] != v {
				t.Errorf("%s = %v, want %s", k, body[k], v)
			}
		}

		// Whole record gone: claim and status both 404 (indistinguishable
		// from never-existed).
		resp, body = e.do(t, "GET", "/api/requests/"+testID+"/response?proof="+testClaimProof, "", nil)
		wantError(t, resp, body, 404)
		resp, body = e.do(t, "GET", "/api/requests/"+testID, "", nil)
		wantError(t, resp, body, 404)
	})
}

func TestRequestClaimExpired(t *testing.T) {
	e := newTestEnv(t, nil)
	resp, _ := e.do(t, "POST", "/api/requests", requestBody(map[string]any{"expiresMinutes": 5}), nil)
	wantStatus(t, resp, 201)
	resp, _ = e.do(t, "POST", "/api/requests/"+testID+"/response", fulfillBody(nil), nil)
	wantStatus(t, resp, 201)

	e.clock.Advance(6 * time.Minute)
	resp, body := e.do(t, "GET", "/api/requests/"+testID+"/response?proof="+testClaimProof, "", nil)
	wantError(t, resp, body, 404)
}

// §9.3 TTL inheritance over the wire: fulfilling late does not extend the
// request's original deadline.
func TestRequestFulfillInheritsOriginalExpiry(t *testing.T) {
	e := newTestEnv(t, nil)
	resp, _ := e.do(t, "POST", "/api/requests", requestBody(map[string]any{"expiresMinutes": 5}), nil)
	wantStatus(t, resp, 201)

	e.clock.Advance(4 * time.Minute)
	resp, _ = e.do(t, "POST", "/api/requests/"+testID+"/response", fulfillBody(nil), nil)
	wantStatus(t, resp, 201)

	// 2 more minutes: past the original 5-minute deadline, even though the
	// response is only 2 minutes old.
	e.clock.Advance(2 * time.Minute)
	resp, body := e.do(t, "GET", "/api/requests/"+testID+"/response?proof="+testClaimProof, "", nil)
	wantError(t, resp, body, 404)
}

// §9.3: POST /api/requests shares the create bucket with POST /api/secrets.
func TestRequestCreateSharesCreateBucket(t *testing.T) {
	e := newTestEnv(t, func(c *config.Config) { c.Limits.CreatePerMinute = 1 })
	resp, _ := e.post(t, createBody(nil))
	wantStatus(t, resp, 201)
	resp, body := e.do(t, "POST", "/api/requests", requestBody(map[string]any{"id": strings.Repeat("D", 32)}), nil)
	wantError(t, resp, body, 429)
}

// §9.3: status, fulfill and claim all share the retrieval-class bucket.
func TestRequestEndpointsShareRetrieveBucket(t *testing.T) {
	e := newTestEnv(t, func(c *config.Config) { c.Limits.RetrievePerMinute = 3 })
	missing := strings.Repeat("z", 32)

	e.do(t, "GET", "/api/requests/"+missing, "", nil)                                   // 1
	e.do(t, "POST", "/api/requests/"+missing+"/response", fulfillBody(nil), nil)        // 2
	e.do(t, "GET", "/api/requests/"+missing+"/response?proof="+testClaimProof, "", nil) // 3
	resp, body := e.do(t, "GET", "/api/secrets/"+missing+"?k="+testKeyHash, "", nil)    // shared with secrets
	wantError(t, resp, body, 429)
}

// The cleanup loop's expiry sweep covers requests as well as secrets.
func TestCleanupLoopSweepsExpiredRequests(t *testing.T) {
	cfg := config.Default()
	cfg.Limits.CleanupIntervalSeconds = 1
	spy := &sweepSpy{Store: storage.NewMemory(), swept: make(chan int64, 1)}
	s := New(cfg, spy, slog.New(slog.DiscardHandler))
	clock := newFakeClock()
	s.SetClock(clock.Now)

	ctx := context.Background()
	now := clock.Now()
	if err := spy.Create(ctx, storage.Secret{
		ID: testID, Encrypted: testEnc, IV: testIV, KeyHash: testKeyHash,
		CreatedAt: now.Add(-2 * time.Minute), ExpiresAt: now.Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	if err := spy.CreateRequest(ctx, storage.Request{
		ID: strings.Repeat("B", 32), PublicKey: testPublicKey, ClaimProof: testClaimProof,
		CreatedAt: now.Add(-2 * time.Minute), ExpiresAt: now.Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	defer close(stop)
	go s.CleanupLoop(stop)

	select {
	case n := <-spy.swept:
		if n != 2 {
			t.Errorf("first sweep deleted %d records, want 2 (1 secret + 1 request)", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cleanup loop never swept")
	}
}

// sweepSpy reports each DeleteExpired result without changing behavior.
type sweepSpy struct {
	storage.Store
	swept chan int64
}

func (s *sweepSpy) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	n, err := s.Store.DeleteExpired(ctx, now)
	select {
	case s.swept <- n:
	default:
	}
	return n, err
}

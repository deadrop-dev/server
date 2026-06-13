package server

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/deadrop-dev/server/internal/config"
)

func TestHealth(t *testing.T) {
	e := newTestEnv(t, nil)
	resp, body := e.do(t, "GET", "/health", "", nil)
	wantStatus(t, resp, 200)
	if body["status"] != "ok" {
		t.Errorf("body = %v, want {status: ok}", body)
	}
}

func TestCreateRoundTrip(t *testing.T) {
	e := newTestEnv(t, nil)
	resp, body := e.post(t, createBody(map[string]any{"hint": "my hint"}))
	wantStatus(t, resp, 201)
	if body["id"] != testID {
		t.Errorf("create response id = %v, want %s", body["id"], testID)
	}

	// Retrieve with correct key: 200 + exact payload + burn.
	resp, body = e.do(t, "GET", "/api/secrets/"+testID+"?k="+testKeyHash, "", nil)
	wantStatus(t, resp, 200)
	if body["encrypted"] != testEnc {
		t.Errorf("encrypted = %v, want %s", body["encrypted"], testEnc)
	}
	if body["iv"] != testIV {
		t.Errorf("iv = %v, want %s", body["iv"], testIV)
	}
	if body["hint"] != "my hint" {
		t.Errorf("hint = %v, want \"my hint\"", body["hint"])
	}

	// Burned: second retrieval is 404.
	resp, body = e.do(t, "GET", "/api/secrets/"+testID+"?k="+testKeyHash, "", nil)
	wantError(t, resp, body, 404)
}

func TestRetrieveNullHint(t *testing.T) {
	e := newTestEnv(t, nil)
	resp, _ := e.post(t, createBody(nil)) // no hint
	wantStatus(t, resp, 201)
	resp, body := e.do(t, "GET", "/api/secrets/"+testID+"?k="+testKeyHash, "", nil)
	wantStatus(t, resp, 200)
	v, present := body["hint"]
	if !present || v != nil {
		t.Errorf("hint = %v (present=%v), want explicit null", v, present)
	}
}

func TestRetrieveWrongKeyDoesNotBurn(t *testing.T) {
	e := newTestEnv(t, nil)
	resp, _ := e.post(t, createBody(nil))
	wantStatus(t, resp, 201)

	wrong := "BBBBBBBBBBBBBBBBBBBBBB" // valid format, wrong value
	resp, body := e.do(t, "GET", "/api/secrets/"+testID+"?k="+wrong, "", nil)
	wantError(t, resp, body, 403)

	// Still alive: correct key works.
	resp, _ = e.do(t, "GET", "/api/secrets/"+testID+"?k="+testKeyHash, "", nil)
	wantStatus(t, resp, 200)
}

func TestRetrieveLegacy8CharKey(t *testing.T) {
	e := newTestEnv(t, nil)
	resp, _ := e.post(t, createBody(nil))
	wantStatus(t, resp, 201)

	// Wrong 8-char prefix: 403, no burn.
	resp, body := e.do(t, "GET", "/api/secrets/"+testID+"?k=XXXXXXXX", "", nil)
	wantError(t, resp, body, 403)

	// Correct 8-char prefix: 200 + burn.
	resp, _ = e.do(t, "GET", "/api/secrets/"+testID+"?k="+testKeyHash[:8], "", nil)
	wantStatus(t, resp, 200)
	resp, body = e.do(t, "GET", "/api/secrets/"+testID+"?k="+testKeyHash, "", nil)
	wantError(t, resp, body, 404)
}

func TestRetrieveValidation(t *testing.T) {
	e := newTestEnv(t, nil)
	cases := []struct {
		name, path string
		status     int
	}{
		{"missing k", "/api/secrets/" + testID, 400},
		{"bad k length", "/api/secrets/" + testID + "?k=tooshort", 403}, // 8 chars is legacy-valid format but wrong value -> needs a live secret; covered below
		{"k invalid chars", "/api/secrets/" + testID + "?k=" + strings.Repeat("+", 22), 400},
		{"k length 21", "/api/secrets/" + testID + "?k=" + strings.Repeat("A", 21), 400},
		{"bad id", "/api/secrets/shortid?k=" + testKeyHash, 400},
		{"never existed", "/api/secrets/" + strings.Repeat("z", 32) + "?k=" + testKeyHash, 404},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp, body := e.do(t, "GET", c.path, "", nil)
			if c.name == "bad k length" {
				// "tooshort" is 8 chars => legacy format; no secret => 404.
				wantError(t, resp, body, 404)
				return
			}
			wantError(t, resp, body, c.status)
		})
	}
}

func TestCreateValidation(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"id too short", createBody(map[string]any{"id": strings.Repeat("A", 31)})},
		{"id too long", createBody(map[string]any{"id": strings.Repeat("A", 33)})},
		{"id bad chars", createBody(map[string]any{"id": strings.Repeat("A", 30) + "+/"})},
		{"id missing", createBody(map[string]any{"id": nil})},
		{"encrypted empty", createBody(map[string]any{"encrypted": ""})},
		{"encrypted missing", createBody(map[string]any{"encrypted": nil})},
		{"encrypted too long", createBody(map[string]any{"encrypted": strings.Repeat("A", 480001)})},
		{"encrypted bad chars", createBody(map[string]any{"encrypted": "abc+def="})},
		{"iv 15 chars", createBody(map[string]any{"iv": strings.Repeat("A", 15)})},
		{"iv 17 chars", createBody(map[string]any{"iv": strings.Repeat("A", 17)})},
		{"iv missing", createBody(map[string]any{"iv": nil})},
		{"keyHash 21", createBody(map[string]any{"keyHash": strings.Repeat("A", 21)})},
		{"keyHash 23", createBody(map[string]any{"keyHash": strings.Repeat("A", 23)})},
		{"keyHash 8 not allowed on create", createBody(map[string]any{"keyHash": strings.Repeat("A", 8)})},
		{"keyHash missing", createBody(map[string]any{"keyHash": nil})},
		{"hint too long", createBody(map[string]any{"hint": strings.Repeat("h", 141)})},
		{"not json", "{nope"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newTestEnv(t, nil)
			resp, body := e.post(t, c.body)
			wantError(t, resp, body, 400)
		})
	}

	t.Run("max valid encrypted accepted", func(t *testing.T) {
		e := newTestEnv(t, nil)
		resp, _ := e.post(t, createBody(map[string]any{"encrypted": strings.Repeat("A", 480000)}))
		wantStatus(t, resp, 201)
	})
	t.Run("file-mode-size payload round-trips on defaults", func(t *testing.T) {
		// A 256 KiB file encrypts to ~467K chars — must fit the default cap
		// AND the default body ceiling (this request body is ~467KB).
		e := newTestEnv(t, nil)
		enc := strings.Repeat("A", 467000)
		resp, _ := e.post(t, createBody(map[string]any{"encrypted": enc}))
		wantStatus(t, resp, 201)
		resp, body := e.do(t, "GET", "/api/secrets/"+testID+"?k="+testKeyHash, "", nil)
		wantStatus(t, resp, 200)
		if body["encrypted"] != enc {
			t.Error("file-mode-size payload did not round-trip intact")
		}
	})
	t.Run("operator can tighten the cap", func(t *testing.T) {
		e := newTestEnv(t, func(c *config.Config) { c.Limits.MaxEncryptedChars = 10240 })
		resp, body := e.post(t, createBody(map[string]any{"encrypted": strings.Repeat("A", 10241)}))
		wantError(t, resp, body, 400)
		if msg, _ := body["error"].(string); !strings.Contains(msg, "1-10240") {
			t.Errorf("error = %q, want the configured cap in the message", msg)
		}
	})
	t.Run("hint exactly 140 accepted", func(t *testing.T) {
		e := newTestEnv(t, nil)
		resp, _ := e.post(t, createBody(map[string]any{"hint": strings.Repeat("h", 140)}))
		wantStatus(t, resp, 201)
	})
}

func TestCreateDuplicate409(t *testing.T) {
	e := newTestEnv(t, nil)
	resp, _ := e.post(t, createBody(nil))
	wantStatus(t, resp, 201)
	resp, body := e.post(t, createBody(map[string]any{"encrypted": testEnc}))
	wantError(t, resp, body, 409)
	// Original not overwritten.
	resp, body = e.do(t, "GET", "/api/secrets/"+testID+"?k="+testKeyHash, "", nil)
	wantStatus(t, resp, 200)
	if body["encrypted"] != testEnc {
		t.Errorf("duplicate overwrote the original")
	}
}

func TestExpiresMinutesClamping(t *testing.T) {
	cases := []struct {
		name    string
		expires any // nil = omit field
		want    time.Duration
	}{
		{"zero clamps to 1", 0, time.Minute},
		{"negative clamps to 1", -5, time.Minute},
		{"above max clamps to max", 99999999, 10080 * time.Minute},
		{"absent uses default", nil, 60 * time.Minute},
		{"normal passes through", 120, 120 * time.Minute},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newTestEnv(t, nil)
			resp, body := e.post(t, createBody(map[string]any{"expiresMinutes": c.expires}))
			wantStatus(t, resp, 201)
			got, err := time.Parse(time.RFC3339, body["expiresAt"].(string))
			if err != nil {
				t.Fatalf("expiresAt: %v", err)
			}
			want := e.clock.Now().Add(c.want)
			if !got.Equal(want.Truncate(time.Second)) {
				t.Errorf("expiresAt = %v, want %v", got, want)
			}
		})
	}
}

func TestExpiredSecretIs404BeforeCleanup(t *testing.T) {
	e := newTestEnv(t, nil)
	resp, _ := e.post(t, createBody(map[string]any{"expiresMinutes": 1, "hint": "h"}))
	wantStatus(t, resp, 201)

	e.clock.Advance(2 * time.Minute) // past expiry; no cleanup loop running

	resp, body := e.do(t, "GET", "/api/secrets/"+testID+"?k="+testKeyHash, "", nil)
	wantError(t, resp, body, 404)
	resp, body = e.do(t, "GET", "/api/secrets/"+testID+"/meta", "", nil)
	wantError(t, resp, body, 404)
	resp, body = e.do(t, "DELETE", "/api/secrets/"+testID+"?k="+testKeyHash, "", nil)
	wantError(t, resp, body, 404)
}

func TestMeta(t *testing.T) {
	e := newTestEnv(t, nil)
	idNoHint := strings.Repeat("B", 32)
	resp, _ := e.post(t, createBody(map[string]any{"hint": "use the wifi password"}))
	wantStatus(t, resp, 201)
	resp, _ = e.post(t, createBody(map[string]any{"id": idNoHint}))
	wantStatus(t, resp, 201)

	resp, body := e.do(t, "GET", "/api/secrets/"+testID+"/meta", "", nil)
	wantStatus(t, resp, 200)
	if body["hint"] != "use the wifi password" {
		t.Errorf("hint = %v", body["hint"])
	}

	resp, body = e.do(t, "GET", "/api/secrets/"+idNoHint+"/meta", "", nil)
	wantStatus(t, resp, 200)
	if v, present := body["hint"]; !present || v != nil {
		t.Errorf("hint = %v (present=%v), want explicit null", v, present)
	}

	resp, body = e.do(t, "GET", "/api/secrets/"+strings.Repeat("z", 32)+"/meta", "", nil)
	wantError(t, resp, body, 404)

	// Meta needs no key proof and does not burn.
	resp, _ = e.do(t, "GET", "/api/secrets/"+testID+"?k="+testKeyHash, "", nil)
	wantStatus(t, resp, 200)
}

func TestRevoke(t *testing.T) {
	e := newTestEnv(t, nil)
	resp, _ := e.post(t, createBody(nil))
	wantStatus(t, resp, 201)

	// Missing key proof: 400.
	resp, body := e.do(t, "DELETE", "/api/secrets/"+testID, "", nil)
	wantError(t, resp, body, 400)

	// Wrong key: 403, secret survives.
	resp, body = e.do(t, "DELETE", "/api/secrets/"+testID+"?k=BBBBBBBBBBBBBBBBBBBBBB", "", nil)
	wantError(t, resp, body, 403)
	resp, _ = e.do(t, "GET", "/api/secrets/"+testID+"/meta", "", nil)
	wantStatus(t, resp, 200)

	// Correct key: 204, no body.
	resp, _ = e.do(t, "DELETE", "/api/secrets/"+testID+"?k="+testKeyHash, "", nil)
	wantStatus(t, resp, 204)

	// Gone now.
	resp, body = e.do(t, "DELETE", "/api/secrets/"+testID+"?k="+testKeyHash, "", nil)
	wantError(t, resp, body, 404)
	resp, body = e.do(t, "GET", "/api/secrets/"+testID+"?k="+testKeyHash, "", nil)
	wantError(t, resp, body, 404)
}

func TestBodySizeLimit(t *testing.T) {
	e := newTestEnv(t, func(c *config.Config) { c.Limits.MaxBodyBytes = 2048 })
	big := createBody(map[string]any{"encrypted": strings.Repeat("A", 4096)})
	resp, body := e.post(t, big)
	wantError(t, resp, body, 413)
}

func TestMethodNotAllowed(t *testing.T) {
	e := newTestEnv(t, nil)
	resp, _ := e.do(t, "PUT", "/api/secrets/"+testID, "", nil)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("PUT status = %d, want 405", resp.StatusCode)
	}
}

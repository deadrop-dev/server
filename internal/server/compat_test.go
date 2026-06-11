package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// vectorsFile mirrors the schema of @deadrop/crypto test-vectors.json.
type vectorsFile struct {
	Vectors []struct {
		Name          string `json:"name"`
		KeyB64        string `json:"key_b64"`
		IVB64         string `json:"iv_b64"`
		Plaintext     string `json:"plaintext"`
		CiphertextB64 string `json:"ciphertext_b64"`
		KeyHash       string `json:"key_hash"`
	} `json:"vectors"`
	PasswordVectors []struct {
		Name           string `json:"name"`
		URLKeyB64      string `json:"url_key_b64"`
		Password       string `json:"password"`
		DerivedKeyB64  string `json:"derived_key_b64"`
		DerivedKeyHash string `json:"derived_key_hash"`
		IVB64          string `json:"iv_b64"`
		Plaintext      string `json:"plaintext"`
		CiphertextB64  string `json:"ciphertext_b64"`
	} `json:"password_vectors"`
}

func loadVectors(t *testing.T) vectorsFile {
	t.Helper()
	path := os.Getenv("DEADROP_TEST_VECTORS")
	if path == "" {
		path = filepath.Join("..", "..", "..", "crypto", "test-vectors.json")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("test vectors not available at %s (set DEADROP_TEST_VECTORS): %v", path, err)
	}
	var vf vectorsFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if len(vf.Vectors) == 0 {
		t.Fatalf("%s contains no vectors", path)
	}
	return vf
}

// keyHashOf reimplements the SPEC key-hash derivation:
// SHA-256(raw key) -> base64url -> first 22 chars.
func keyHashOf(t *testing.T, keyB64 string) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(keyB64)
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	sum := sha256.Sum256(raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])[:22]
}

func randomID(t *testing.T) string {
	t.Helper()
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b) // 32 chars
}

// TestCryptoVectorRoundTrip stores each @deadrop/crypto vector's ciphertext
// and retrieves it, asserting byte-identical encrypted/iv fields and correct
// keyHash gating. The server never decrypts — this validates wire + gate
// fidelity (SPEC §8).
func TestCryptoVectorRoundTrip(t *testing.T) {
	vf := loadVectors(t)
	e := newTestEnv(t, nil)

	type tv struct {
		name, ivB64, ciphertextB64, keyHash, hint string
		wantHash                                  string
	}
	var cases []tv
	for _, v := range vf.Vectors {
		cases = append(cases, tv{
			name: "basic/" + v.Name, ivB64: v.IVB64, ciphertextB64: v.CiphertextB64,
			keyHash: keyHashOf(t, v.KeyB64), wantHash: v.KeyHash,
		})
	}
	for _, v := range vf.PasswordVectors {
		// The keyHash the server sees is computed from the DERIVED key.
		cases = append(cases, tv{
			name: "password/" + v.Name, ivB64: v.IVB64, ciphertextB64: v.CiphertextB64,
			keyHash: keyHashOf(t, v.DerivedKeyB64), wantHash: v.DerivedKeyHash,
			hint: "password hint for " + v.Name,
		})
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Our key-hash derivation must agree with the vector's.
			if c.keyHash != c.wantHash {
				t.Fatalf("key hash derivation mismatch: computed %q, vector says %q", c.keyHash, c.wantHash)
			}

			id := randomID(t)
			over := map[string]any{
				"id":        id,
				"encrypted": c.ciphertextB64,
				"iv":        c.ivB64,
				"keyHash":   c.keyHash,
			}
			if c.hint != "" {
				over["hint"] = c.hint
			}
			resp, body := e.post(t, createBody(over))
			wantStatus(t, resp, 201)

			// Wrong key hash gates with 403 and does not burn.
			wrong := "ZZZZZZZZZZZZZZZZZZZZZZ"
			resp, body = e.do(t, "GET", "/api/secrets/"+id+"?k="+wrong, "", nil)
			wantError(t, resp, body, 403)

			// Correct key hash: byte-identical round-trip.
			resp, body = e.do(t, "GET", "/api/secrets/"+id+"?k="+c.keyHash, "", nil)
			wantStatus(t, resp, 200)
			if got := body["encrypted"]; got != c.ciphertextB64 {
				t.Errorf("encrypted round-trip mismatch:\n got %v\nwant %s", got, c.ciphertextB64)
			}
			if got := body["iv"]; got != c.ivB64 {
				t.Errorf("iv round-trip mismatch: got %v, want %s", got, c.ivB64)
			}
			if c.hint != "" && body["hint"] != c.hint {
				t.Errorf("hint = %v, want %q", body["hint"], c.hint)
			}

			// Burned.
			resp, body = e.do(t, "GET", "/api/secrets/"+id+"?k="+c.keyHash, "", nil)
			wantError(t, resp, body, 404)
		})
	}
}

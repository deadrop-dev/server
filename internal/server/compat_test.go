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
	RequestVectors []struct {
		Name                        string `json:"name"`
		RequesterPublicKeyB64       string `json:"requester_public_key_b64"`
		RequesterPrivateKeyPKCS8B64 string `json:"requester_private_key_pkcs8_b64"`
		ResponderPublicKeyB64       string `json:"responder_public_key_b64"`
		HkdfSaltB64                 string `json:"hkdf_salt_b64"`
		WrapIVB64                   string `json:"wrap_iv_b64"`
		WrappedKeyB64               string `json:"wrapped_key_b64"`
		IVB64                       string `json:"iv_b64"`
		CiphertextB64               string `json:"ciphertext_b64"`
		ClaimProof                  string `json:"claim_proof"`
		RequesterFingerprint        string `json:"requester_fingerprint"`
	} `json:"request_vectors"`
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

// claimProofOf reimplements the SPEC §9.1 claim-proof derivation:
// SHA-256(UTF-8 bytes of privateKeyB64) -> base64url -> first 22 chars.
func claimProofOf(privateKeyB64 string) string {
	sum := sha256.Sum256([]byte(privateKeyB64))
	return base64.RawURLEncoding.EncodeToString(sum[:])[:22]
}

// fingerprintOf reimplements the SPEC §9.1 fingerprint:
// first 8 chars of base64url(SHA-256(raw 65-byte public key)).
func fingerprintOf(t *testing.T, publicKeyB64 string) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(publicKeyB64)
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	sum := sha256.Sum256(raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])[:8]
}

// TestRequestVectorRoundTrip drives each @deadrop/crypto request-flow vector
// through the full wire protocol: create with the vector's requester key and
// claim proof, fulfill with its response fields, claim with its proof, and
// assert every returned field is byte-identical. The server never touches the
// ECDH/HKDF material — this validates wire + gate fidelity (SPEC §8, §9).
func TestRequestVectorRoundTrip(t *testing.T) {
	vf := loadVectors(t)
	if len(vf.RequestVectors) == 0 {
		t.Skip("test vectors file has no request_vectors section")
	}
	e := newTestEnv(t, nil)

	for _, v := range vf.RequestVectors {
		t.Run(v.Name, func(t *testing.T) {
			// Our derivations must agree with the vector's.
			if got := claimProofOf(v.RequesterPrivateKeyPKCS8B64); got != v.ClaimProof {
				t.Fatalf("claim proof derivation mismatch: computed %q, vector says %q", got, v.ClaimProof)
			}
			if got := fingerprintOf(t, v.RequesterPublicKeyB64); got != v.RequesterFingerprint {
				t.Fatalf("fingerprint derivation mismatch: computed %q, vector says %q", got, v.RequesterFingerprint)
			}

			id := randomID(t)
			resp, _ := e.do(t, "POST", "/api/requests", requestBody(map[string]any{
				"id":         id,
				"publicKey":  v.RequesterPublicKeyB64,
				"claimProof": v.ClaimProof,
			}), nil)
			wantStatus(t, resp, 201)

			// The responder sees the requester public key byte-identical.
			resp, body := e.do(t, "GET", "/api/requests/"+id, "", nil)
			wantStatus(t, resp, 200)
			if body["publicKey"] != v.RequesterPublicKeyB64 {
				t.Errorf("publicKey round-trip mismatch:\n got %v\nwant %s", body["publicKey"], v.RequesterPublicKeyB64)
			}

			resp, _ = e.do(t, "POST", "/api/requests/"+id+"/response", fulfillBody(map[string]any{
				"encrypted":          v.CiphertextB64,
				"iv":                 v.IVB64,
				"wrappedKey":         v.WrappedKeyB64,
				"wrapIv":             v.WrapIVB64,
				"hkdfSalt":           v.HkdfSaltB64,
				"responderPublicKey": v.ResponderPublicKeyB64,
			}), nil)
			wantStatus(t, resp, 201)

			// Wrong proof gates with 403 and does not burn.
			resp, body = e.do(t, "GET", "/api/requests/"+id+"/response?proof=ZZZZZZZZZZZZZZZZZZZZZZ", "", nil)
			wantError(t, resp, body, 403)

			// Correct proof: byte-identical blob, atomically burned.
			resp, body = e.do(t, "GET", "/api/requests/"+id+"/response?proof="+v.ClaimProof, "", nil)
			wantStatus(t, resp, 200)
			want := map[string]string{
				"encrypted":          v.CiphertextB64,
				"iv":                 v.IVB64,
				"wrappedKey":         v.WrappedKeyB64,
				"wrapIv":             v.WrapIVB64,
				"hkdfSalt":           v.HkdfSaltB64,
				"responderPublicKey": v.ResponderPublicKeyB64,
			}
			for k, w := range want {
				if body[k] != w {
					t.Errorf("%s round-trip mismatch:\n got %v\nwant %s", k, body[k], w)
				}
			}

			// Burned.
			resp, body = e.do(t, "GET", "/api/requests/"+id+"/response?proof="+v.ClaimProof, "", nil)
			wantError(t, resp, body, 404)
		})
	}
}

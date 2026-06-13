package server

import "encoding/base64"

// Wire-format validation per SPEC v2.0. Sizes are spec-normative constants —
// except the secrets payload ceiling, which is operator configuration
// (limits.max_encrypted_chars; SPEC §10.4 makes it a service decision).

const (
	idLen            = 32  // 24 random bytes, base64url
	ivLen            = 16  // 12-byte IV, base64url
	keyHashLen       = 22  // SHA-256 -> base64url -> 22 chars (128 bits)
	legacyKeyHashLen = 8   // pre-2.0 truncated hash, accepted on compare only
	maxHintLen       = 140 // characters (runes)
)

// Request-flow constants (SPEC v2.1 §9.1/§9.2).
const (
	claimProofLen         = 22    // SHA-256 of the private key -> base64url -> 22 chars
	publicKeyLen          = 87    // raw uncompressed P-256 point (65 bytes), base64url
	publicKeyBytes        = 65    // 0x04 ‖ X ‖ Y
	wrappedKeyLen         = 64    // 48 bytes (32-byte key + 16-byte GCM tag), base64url
	hkdfSaltLen           = 22    // 16 bytes, base64url
	maxPromptLen          = 140   // characters (runes)
	maxResponseEncrypted  = 65536 // base64url chars (the §9.2 reference body ceiling)
	uncompressedPointTag  = 0x04
	defaultRequestExpires = 1440  // minutes, applied when expiresMinutes is absent
	maxRequestExpires     = 10080 // §9.2 makes [1, 10080] normative (unlike the
	// secrets ceiling, which is operator configuration)
)

// isBase64URL reports whether s is non-empty and uses only the RFC 4648 §5
// alphabet (no padding).
func isBase64URL(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

func validID(id string) bool {
	return len(id) == idLen && isBase64URL(id)
}

func validIV(iv string) bool {
	return len(iv) == ivLen && isBase64URL(iv)
}

func validEncrypted(enc string, maxChars int) bool {
	return len(enc) >= 1 && len(enc) <= maxChars && isBase64URL(enc)
}

// validKeyHashCreate: creation requires the full 22-char hash.
func validKeyHashCreate(kh string) bool {
	return len(kh) == keyHashLen && isBase64URL(kh)
}

// validKeyHashProof: GET/DELETE accept the full hash or the 8-char legacy form.
func validKeyHashProof(kh string) bool {
	return (len(kh) == keyHashLen || len(kh) == legacyKeyHashLen) && isBase64URL(kh)
}

func validHint(hint string) bool {
	return len([]rune(hint)) <= maxHintLen
}

// validPublicKey reports whether s is the base64url encoding of a raw
// uncompressed P-256 point: 65 bytes starting with the 0x04 tag (SPEC §9.1).
func validPublicKey(s string) bool {
	if len(s) != publicKeyLen || !isBase64URL(s) {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(raw) == publicKeyBytes && raw[0] == uncompressedPointTag
}

func validClaimProof(proof string) bool {
	return len(proof) == claimProofLen && isBase64URL(proof)
}

func validPrompt(prompt string) bool {
	return len([]rune(prompt)) <= maxPromptLen
}

func validResponseEncrypted(enc string) bool {
	return len(enc) >= 1 && len(enc) <= maxResponseEncrypted && isBase64URL(enc)
}

func validWrappedKey(wk string) bool {
	return len(wk) == wrappedKeyLen && isBase64URL(wk)
}

func validHkdfSalt(salt string) bool {
	return len(salt) == hkdfSaltLen && isBase64URL(salt)
}

// clampExpiresMinutes applies the SPEC clamp [1, max]; absent (nil) uses the
// configured default. Out-of-range values are clamped, never rejected.
func clampExpiresMinutes(v *int, def, max int) int {
	m := def
	if v != nil {
		m = *v
	}
	if m < 1 {
		m = 1
	}
	if m > max {
		m = max
	}
	return m
}

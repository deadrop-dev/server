package server

// Wire-format validation per SPEC v2.0. All sizes are spec-normative
// constants, not configuration.

const (
	idLen            = 32    // 24 random bytes, base64url
	ivLen            = 16    // 12-byte IV, base64url
	keyHashLen       = 22    // SHA-256 -> base64url -> 22 chars (128 bits)
	legacyKeyHashLen = 8     // pre-2.0 truncated hash, accepted on compare only
	maxEncryptedLen  = 10240 // base64url chars
	maxHintLen       = 140   // characters (runes)
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

func validEncrypted(enc string) bool {
	return len(enc) >= 1 && len(enc) <= maxEncryptedLen && isBase64URL(enc)
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

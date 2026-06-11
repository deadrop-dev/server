package server

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/deadrop-dev/server/internal/storage"
)

type createRequest struct {
	ID             string `json:"id"`
	Encrypted      string `json:"encrypted"`
	IV             string `json:"iv"`
	KeyHash        string `json:"keyHash"`
	ExpiresMinutes *int   `json:"expiresMinutes"`
	Hint           string `json:"hint"`
}

type createResponse struct {
	ID        string `json:"id"`
	ExpiresAt string `json:"expiresAt"`
}

type retrieveResponse struct {
	Encrypted string  `json:"encrypted"`
	IV        string  `json:"iv"`
	Hint      *string `json:"hint"`
}

type metaResponse struct {
	Hint *string `json:"hint"`
}

func hintPtr(hint string) *string {
	if hint == "" {
		return nil
	}
	return &hint
}

// POST /api/secrets
func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	if !s.allow(w, r, s.create) {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.Limits.MaxBodyBytes)
	var req createRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	switch {
	case !validID(req.ID):
		writeError(w, http.StatusBadRequest, "id must be 32 base64url characters")
		return
	case !validEncrypted(req.Encrypted):
		writeError(w, http.StatusBadRequest, "encrypted must be 1-10240 base64url characters")
		return
	case !validIV(req.IV):
		writeError(w, http.StatusBadRequest, "iv must be 16 base64url characters")
		return
	case !validKeyHashCreate(req.KeyHash):
		writeError(w, http.StatusBadRequest, "keyHash must be 22 base64url characters")
		return
	case !validHint(req.Hint):
		writeError(w, http.StatusBadRequest, "hint must be at most 140 characters")
		return
	}

	minutes := clampExpiresMinutes(req.ExpiresMinutes,
		s.cfg.Limits.DefaultExpiresMinutes, s.cfg.Limits.MaxExpiresMinutes)
	now := s.now().Truncate(time.Second)
	sec := storage.Secret{
		ID:        req.ID,
		Encrypted: req.Encrypted,
		IV:        req.IV,
		KeyHash:   req.KeyHash,
		Hint:      req.Hint,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Duration(minutes) * time.Minute),
	}
	if err := s.store.Create(r.Context(), sec); err != nil {
		if errors.Is(err, storage.ErrDuplicateID) {
			writeError(w, http.StatusConflict, "a secret with this id already exists")
			return
		}
		s.logger.Error("create failed", "err", err.Error())
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusCreated, createResponse{
		ID:        sec.ID,
		ExpiresAt: sec.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

// gate validates id + k and runs the constant-time key check against the
// stored hash. On success it returns (id, keyHash, true); otherwise it has
// already written the error response. The caller must still treat the
// follow-up atomic compare-and-delete as the source of truth (SPEC §3).
func (s *Server) gate(w http.ResponseWriter, r *http.Request) (id, keyHash string, ok bool) {
	id = r.PathValue("id")
	if !validID(id) {
		writeError(w, http.StatusBadRequest, "id must be 32 base64url characters")
		return "", "", false
	}
	keyHash = r.URL.Query().Get("k")
	if !validKeyHashProof(keyHash) {
		writeError(w, http.StatusBadRequest, "k must be 22 (or legacy 8) base64url characters")
		return "", "", false
	}

	stored, err := s.store.KeyHash(r.Context(), id, s.now())
	if errors.Is(err, storage.ErrNotFound) {
		writeError(w, http.StatusNotFound, "secret not found")
		return "", "", false
	}
	if err != nil {
		s.logger.Error("key hash lookup failed", "err", err.Error())
		writeError(w, http.StatusInternalServerError, "internal error")
		return "", "", false
	}

	compare := stored
	if len(keyHash) == legacyKeyHashLen && len(stored) >= legacyKeyHashLen {
		compare = stored[:legacyKeyHashLen]
	}
	if subtle.ConstantTimeCompare([]byte(compare), []byte(keyHash)) != 1 {
		// Wrong key: 403 WITHOUT burning.
		writeError(w, http.StatusForbidden, "invalid key")
		return "", "", false
	}
	return id, keyHash, true
}

// GET /api/secrets/{id}?k={keyHash}
func (s *Server) handleRetrieve(w http.ResponseWriter, r *http.Request) {
	if !s.allow(w, r, s.retrieve) {
		return
	}
	id, keyHash, ok := s.gate(w, r)
	if !ok {
		return
	}

	// Atomic verify-and-burn: the returned payload comes from the single
	// compare-and-delete step, never from a prior read.
	sec, err := s.store.BurnIfMatch(r.Context(), id, keyHash, s.now())
	if errors.Is(err, storage.ErrNotFound) {
		// Lost a concurrent race (or expired between gate and burn).
		writeError(w, http.StatusNotFound, "secret not found")
		return
	}
	if err != nil {
		s.logger.Error("burn failed", "err", err.Error())
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, retrieveResponse{
		Encrypted: sec.Encrypted,
		IV:        sec.IV,
		Hint:      hintPtr(sec.Hint),
	})
}

// DELETE /api/secrets/{id}?k={keyHash}
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if !s.allow(w, r, s.retrieve) {
		return
	}
	id, keyHash, ok := s.gate(w, r)
	if !ok {
		return
	}
	_, err := s.store.BurnIfMatch(r.Context(), id, keyHash, s.now())
	if errors.Is(err, storage.ErrNotFound) {
		writeError(w, http.StatusNotFound, "secret not found")
		return
	}
	if err != nil {
		s.logger.Error("revoke failed", "err", err.Error())
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GET /api/secrets/{id}/meta
func (s *Server) handleMeta(w http.ResponseWriter, r *http.Request) {
	if !s.allow(w, r, s.retrieve) {
		return
	}
	id := r.PathValue("id")
	if !validID(id) {
		writeError(w, http.StatusBadRequest, "id must be 32 base64url characters")
		return
	}
	hint, err := s.store.Hint(r.Context(), id, s.now())
	if errors.Is(err, storage.ErrNotFound) {
		writeError(w, http.StatusNotFound, "secret not found")
		return
	}
	if err != nil {
		s.logger.Error("meta lookup failed", "err", err.Error())
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, metaResponse{Hint: hintPtr(hint)})
}

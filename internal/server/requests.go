package server

// SPEC v2.1 §9 — Request-a-Secret (reverse flow). The server stores only
// opaque material (public key, truncated claim proof, ciphertext blobs);
// none of it decrypts anything. §9.3: never log prompt, key material,
// proofs, or response fields.

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/deadrop-dev/server/internal/storage"
)

type requestCreateRequest struct {
	ID             string `json:"id"`
	PublicKey      string `json:"publicKey"`
	ClaimProof     string `json:"claimProof"`
	Prompt         string `json:"prompt"`
	ExpiresMinutes *int   `json:"expiresMinutes"`
}

type requestStatusResponse struct {
	PublicKey string `json:"publicKey"`
	Prompt    string `json:"prompt"`
	Fulfilled bool   `json:"fulfilled"`
}

type requestFulfillRequest struct {
	Encrypted          string `json:"encrypted"`
	IV                 string `json:"iv"`
	WrappedKey         string `json:"wrappedKey"`
	WrapIV             string `json:"wrapIv"`
	HkdfSalt           string `json:"hkdfSalt"`
	ResponderPublicKey string `json:"responderPublicKey"`
}

type requestClaimResponse struct {
	Encrypted          string `json:"encrypted"`
	IV                 string `json:"iv"`
	WrappedKey         string `json:"wrappedKey"`
	WrapIV             string `json:"wrapIv"`
	HkdfSalt           string `json:"hkdfSalt"`
	ResponderPublicKey string `json:"responderPublicKey"`
}

// POST /api/requests
func (s *Server) handleRequestCreate(w http.ResponseWriter, r *http.Request) {
	if !s.allow(w, r, s.create) {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.Limits.MaxBodyBytes)
	var req requestCreateRequest
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
	case !validPublicKey(req.PublicKey):
		writeError(w, http.StatusBadRequest, "publicKey must be a base64url uncompressed P-256 point")
		return
	case !validClaimProof(req.ClaimProof):
		writeError(w, http.StatusBadRequest, "claimProof must be 22 base64url characters")
		return
	case !validPrompt(req.Prompt):
		writeError(w, http.StatusBadRequest, "prompt must be at most 140 characters")
		return
	}

	// §9.2: [1, 10080] is normative for requests; absent defaults to 1440.
	minutes := clampExpiresMinutes(req.ExpiresMinutes, defaultRequestExpires, maxRequestExpires)
	now := s.now().Truncate(time.Second)
	if err := s.store.CreateRequest(r.Context(), storage.Request{
		ID:         req.ID,
		PublicKey:  req.PublicKey,
		ClaimProof: req.ClaimProof,
		Prompt:     req.Prompt,
		CreatedAt:  now,
		ExpiresAt:  now.Add(time.Duration(minutes) * time.Minute),
	}); err != nil {
		if errors.Is(err, storage.ErrDuplicateID) {
			writeError(w, http.StatusConflict, "a request with this id already exists")
			return
		}
		s.logger.Error("request create failed", "err", err.Error())
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.Header().Set("Location", "/r/"+req.ID)
	w.WriteHeader(http.StatusCreated)
}

// requestID validates the path id. A malformed id can never name a live
// request, so the three /{id} endpoints answer 404 (not 400) — the same
// "unknown" answer the reference implementation gives.
func (s *Server) requestID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if !validID(id) {
		writeError(w, http.StatusNotFound, "request not found")
		return "", false
	}
	return id, true
}

// GET /api/requests/{id}
func (s *Server) handleRequestStatus(w http.ResponseWriter, r *http.Request) {
	if !s.allow(w, r, s.retrieve) {
		return
	}
	id, ok := s.requestID(w, r)
	if !ok {
		return
	}
	st, err := s.store.RequestStatus(r.Context(), id, s.now())
	if errors.Is(err, storage.ErrNotFound) {
		writeError(w, http.StatusNotFound, "request not found")
		return
	}
	if err != nil {
		s.logger.Error("request status lookup failed", "err", err.Error())
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, requestStatusResponse{
		PublicKey: st.PublicKey,
		Prompt:    st.Prompt,
		Fulfilled: st.Fulfilled,
	})
}

// POST /api/requests/{id}/response
func (s *Server) handleRequestFulfill(w http.ResponseWriter, r *http.Request) {
	if !s.allow(w, r, s.retrieve) {
		return
	}
	id, ok := s.requestID(w, r)
	if !ok {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.Limits.MaxBodyBytes)
	var req requestFulfillRequest
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
	case !validResponseEncrypted(req.Encrypted):
		writeError(w, http.StatusBadRequest, "encrypted must be 1-65536 base64url characters")
		return
	case !validIV(req.IV):
		writeError(w, http.StatusBadRequest, "iv must be 16 base64url characters")
		return
	case !validWrappedKey(req.WrappedKey):
		writeError(w, http.StatusBadRequest, "wrappedKey must be 64 base64url characters")
		return
	case !validIV(req.WrapIV):
		writeError(w, http.StatusBadRequest, "wrapIv must be 16 base64url characters")
		return
	case !validHkdfSalt(req.HkdfSalt):
		writeError(w, http.StatusBadRequest, "hkdfSalt must be 22 base64url characters")
		return
	case !validPublicKey(req.ResponderPublicKey):
		writeError(w, http.StatusBadRequest, "responderPublicKey must be a base64url uncompressed P-256 point")
		return
	}

	err := s.store.FulfillRequest(r.Context(), id, storage.RequestResponse{
		Encrypted:          req.Encrypted,
		IV:                 req.IV,
		WrappedKey:         req.WrappedKey,
		WrapIV:             req.WrapIV,
		HkdfSalt:           req.HkdfSalt,
		ResponderPublicKey: req.ResponderPublicKey,
	}, s.now())
	if errors.Is(err, storage.ErrNotFound) {
		writeError(w, http.StatusNotFound, "request not found")
		return
	}
	if errors.Is(err, storage.ErrAlreadyFulfilled) {
		writeError(w, http.StatusConflict, "request already fulfilled")
		return
	}
	if err != nil {
		s.logger.Error("request fulfill failed", "err", err.Error())
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.Header().Set("Location", "/r/"+id)
	w.WriteHeader(http.StatusCreated)
}

// GET /api/requests/{id}/response?proof={claimProof}
//
// §9.2 normative precedence: 404 unknown/expired/already-claimed → 403 proof
// mismatch (nothing burned) → 202 valid proof but unfulfilled (nothing
// burned) → 200 blob returned with the whole record deleted atomically. Like
// the secrets gate, the constant-time comparison decides 403-vs-404 here; the
// follow-up atomic compare-and-delete is the source of truth.
func (s *Server) handleRequestClaim(w http.ResponseWriter, r *http.Request) {
	if !s.allow(w, r, s.retrieve) {
		return
	}
	id, ok := s.requestID(w, r)
	if !ok {
		return
	}

	// A missing or malformed proof can never match a stored 22-char proof.
	// Normalizing it to "" (stored proofs are never empty) preserves the
	// precedence: an unknown id still answers 404 before any 403.
	proof := r.URL.Query().Get("proof")
	if !validClaimProof(proof) {
		proof = ""
	}

	stored, fulfilled, err := s.store.ClaimGate(r.Context(), id, s.now())
	if errors.Is(err, storage.ErrNotFound) {
		writeError(w, http.StatusNotFound, "request not found")
		return
	}
	if err != nil {
		s.logger.Error("claim gate lookup failed", "err", err.Error())
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if subtle.ConstantTimeCompare([]byte(stored), []byte(proof)) != 1 {
		// Wrong proof: 403 WITHOUT burning.
		writeError(w, http.StatusForbidden, "invalid claim proof")
		return
	}
	if !fulfilled {
		// Valid proof, no response yet: nothing burned.
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "pending"})
		return
	}

	// Atomic claim-burn: the returned blob comes from the single
	// compare-and-delete step, never from a prior read.
	resp, err := s.store.ClaimBurn(r.Context(), id, proof, s.now())
	if errors.Is(err, storage.ErrNotFound) {
		// Lost a concurrent race (or expired between gate and burn).
		writeError(w, http.StatusNotFound, "request not found")
		return
	}
	if err != nil {
		s.logger.Error("claim burn failed", "err", err.Error())
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, requestClaimResponse{
		Encrypted:          resp.Encrypted,
		IV:                 resp.IV,
		WrappedKey:         resp.WrappedKey,
		WrapIV:             resp.WrapIV,
		HkdfSalt:           resp.HkdfSalt,
		ResponderPublicKey: resp.ResponderPublicKey,
	})
}

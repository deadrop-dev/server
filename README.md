# Deadrop Server

Self-hostable server for [Deadrop](https://deadrop.dev) — zero-knowledge,
burn-on-read secret sharing. Implements the Deadrop protocol
[**SPEC v2.1**](https://github.com/deadrop-dev/crypto/blob/master/SPEC.md),
including the §9 request flow (Request-a-Secret):

- The server stores only ciphertext, IV, a truncated key hash, an optional
  hint, and an expiry. It can never decrypt anything.
- **Atomic verify-and-burn**: retrieval is a single compare-and-delete — two
  concurrent requests with the correct key can never both receive the blob.
- Constant-time key-hash comparison; wrong key returns 403 *without* burning.
- Per-IP rate limits with a spoof-proof trusted-proxy chain.

One static binary, one SQLite file, zero external services.

## Quickstart — Docker

Multi-arch images (amd64 + arm64) are published to
[GHCR](https://github.com/orgs/deadrop-dev/packages/container/package/server):

```sh
docker run -d --name deadrop \
  -p 8080:8080 \
  -v deadrop-data:/data \
  ghcr.io/deadrop-dev/server:latest
curl http://localhost:8080/health
# {"status":"ok"}
```

The image is built `FROM scratch` (~10 MB); the SQLite database lives in the
`/data` volume. Point any Deadrop client at it:

```sh
deadrop send -s http://localhost:8080 "my-api-key"
```

To build the image yourself instead: `docker build -t deadrop-server .`

## Quickstart — binary

```sh
go build -o deadrop-server ./cmd/deadrop-server
./deadrop-server
# {"level":"INFO","msg":"listening","addr":"0.0.0.0:8080","driver":"sqlite"}
```

Configuration is optional. Use a TOML file, environment variables, or both
(env wins):

```sh
./deadrop-server -config deadrop.toml
DEADROP_PORT=9090 DEADROP_STORAGE_PATH=/var/lib/deadrop/deadrop.db ./deadrop-server
```

See [`deadrop.toml.example`](deadrop.toml.example) for every knob and its
environment override.

## API

| Endpoint | Description |
|---|---|
| `POST /api/secrets` | Store `{id, encrypted, iv, keyHash, expiresMinutes, hint?}`. The client generates the 32-char id. Duplicate id → 409. |
| `GET /api/secrets/{id}?k={keyHash}` | Verify the key hash (constant-time), then atomically burn and return `{encrypted, iv, hint}`. Wrong key → 403 without burning; gone → 404. |
| `GET /api/secrets/{id}/meta` | `{hint}` without key proof (so recipients can see the password hint first). |
| `DELETE /api/secrets/{id}?k={keyHash}` | Revoke with the same key-hash proof. 204 on success. |
| `POST /api/requests` | Request a secret (SPEC §9): `{id, publicKey, claimProof, prompt?, expiresMinutes}`. Duplicate id → 409. |
| `GET /api/requests/{id}` | Responder view: `{publicKey, prompt, fulfilled}`. Unknown or expired → 404. |
| `POST /api/requests/{id}/response` | Attach the encrypted response `{encrypted, iv, wrappedKey, wrapIv, hkdfSalt, responderPublicKey}`. Exactly one per request — already fulfilled → 409. The response inherits the request's original expiry. |
| `GET /api/requests/{id}/response?proof={claimProof}` | Claim the response: 404 unknown/expired/claimed → 403 wrong proof (no burn) → 202 `{"status":"pending"}` (no burn) → 200 blob with the whole record atomically burned. |
| `GET /health` | `{"status":"ok"}` |
| `GET /metrics` | Prometheus counters (opt-in: `-metrics` flag or `[metrics] enabled = true`). |

`expiresMinutes` is clamped server-side to `[1, max_expires_minutes]`
(default max 7 days) — never rejected for being out of range. For requests
the range `[1, 10080]` and the 1440 default are SPEC §9.2 normative.

Rate limits (SPEC §7): creation ≤ 10/min/IP (`POST /api/secrets` and
`POST /api/requests`), retrieval-class (GET, meta, DELETE, and the other
request endpoints) ≤ 60/min/IP. Both configurable; 429 responses carry
`X-RateLimit-Remaining` and `X-RateLimit-Reset`.

## Running behind a proxy

By default the rate limiter keys on the **socket IP** and ignores all
forwarded-IP headers — a client cannot spoof its way out of a limit.

If you run behind your own edge (Cloudflare, nginx, Caddy), configure the
edge to inject a shared-secret header and enable the trust chain:

```toml
[trusted_proxy]
enabled = true
shared_secret = "<long random value injected by your edge>"
shared_secret_header = "X-Deadrop-Edge"
```

Only requests carrying the correct proof get their `CF-Connecting-IP` (or
last `X-Forwarded-For` hop) believed — SPEC §5.

## Development

```sh
make test    # go test ./...
make vet     # go vet + gofmt check
make build
```

The test suite includes a concurrent burn-race check (exactly one winner)
and an end-to-end round-trip of the `@deadrop/crypto` test vectors
(`DEADROP_TEST_VECTORS=/path/to/test-vectors.json` to point at a copy).

## License

MIT — see [LICENSE](LICENSE).

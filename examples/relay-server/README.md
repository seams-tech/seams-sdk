# Relay Server

NEAR relay server that creates accounts on behalf of users, where the relayer pays gas fees.

## Features

- **Direct Account Creation**: Create NEAR accounts using relay server authority
- **Custom Funding**: Configurable initial balance for new accounts
- **Transaction Queuing**: Prevents nonce conflicts
- **Simple JSON API**: Easy integration
- **Console/Admin APIs**: Optional `/console/*` routes with billing and webhook endpoints

## API

### Health endpoints

- `GET /healthz` — basic server health + feature configuration hints (fast; no external dependency checks)
- `GET /readyz` — readiness check

### `POST /registration/bootstrap`

Atomically create a NEAR account and register a WebAuthn authenticator in relay storage (contract-free).

- Request body (abridged): `{ new_account_id, new_public_key, device_number?, rp_id, webauthn_registration, authenticator_options? }`
- Response: `{ success, transactionHash?, error?, message? }`

This route is consumed internally by the SDK’s registration flows.

### Passkey Verification (`POST /auth/passkey/options` → `POST /auth/passkey/verify`)

Verifies a standard WebAuthn assertion (contract-free; relay-stored authenticators + counter persistence).

- Step 1 (options): `POST /auth/passkey/options` with `{ user_id, rp_id, ttl_ms? }` → `{ challengeId, challengeB64u }`
- Step 2 (verify): `POST /auth/passkey/verify` with:
  ```json
  { "challengeId": "<id>", "webauthn_authentication": { /* assertion */ } }
  ```
- Response: `{ ok, verified }`

### App Session Issuance (`POST /session/exchange`)

App sessions are exchange-first.

- `POST /session/exchange` with:
  ```json
  { "sessionKind": "jwt" | "cookie", "exchange": { "type": "oidc_jwt", "token": "<provider-jwt>" } }
  ```
- Or one-step passkey assertion exchange:
  ```json
  {
    "sessionKind": "jwt" | "cookie",
    "exchange": {
      "type": "passkey_assertion",
      "challengeId": "<challenge-id-from-wallet-unlock-options>",
      "webauthn_authentication": { /* assertion */ }
    }
  }
  ```
- Response:
  - When `sessionKind` is `jwt`: `{ ok, session, jwt }`
  - When `sessionKind` is `cookie`: sets `Set-Cookie` and returns `{ ok, session }`

Notes

- The sample server mounts this route via the SDK router (`createRelayRouter(authService)`).
- `POST /auth/passkey/verify` is verification-only and does not mint app sessions.
- For cookie sessions, CORS must allow credentials and specify explicit origins.
  The example config enables CORS with `origin: [EXPECTED_ORIGIN, EXPECTED_WALLET_ORIGIN]` and `credentials: true`.
  Your frontend must use `credentials: 'include'` with fetch.

### PRF session seal routes (`POST /threshold-ecdsa/prf-seal/*`) (optional)

When enabled, this example mounts:

- `POST /threshold-ecdsa/prf-seal/apply-server-seal`
- `POST /threshold-ecdsa/prf-seal/remove-server-seal`
- `GET /.well-known/webauthn` response includes `capabilities.signingSessionSeal` so sealed-refresh clients can enforce startup parity (`mode`, `keyVersion`, `shamirPrimeB64u`)

Enable with `PRF_SESSION_SEAL_ENABLED=1` and provide:

- `PRF_SESSION_SEAL_KEY_VERSION`
- `SHAMIR_P_B64U`
- `SHAMIR_E_S_B64U`
- `SHAMIR_D_S_B64U`

Generate matching server/client values:

```bash
# from repo root
pnpm prf-seal:keygen
```

The command prints:

- server env values: `SHAMIR_P_B64U`, `SHAMIR_E_S_B64U`, `SHAMIR_D_S_B64U`, `PRF_SESSION_SEAL_KEY_VERSION`
- client env values: `VITE_SIGNING_SESSION_PERSISTENCE_MODE`, `VITE_SIGNING_SESSION_SEAL_KEY_VERSION`, `VITE_SIGNING_SESSION_SHAMIR_P_B64U`

Keep the printed client values aligned with relay `PRF_SESSION_SEAL_*` values. Sealed-refresh clients fail closed on mismatch.

Optional limiter config:

- `PRF_SESSION_SEAL_RATE_LIMIT_KIND` (`in-memory` | `upstash-redis-rest` | `redis-tcp`)
- `PRF_SESSION_SEAL_RATE_LIMIT`
- `PRF_SESSION_SEAL_RATE_LIMIT_WINDOW_MS`
- `PRF_SESSION_SEAL_RATE_LIMIT_KEY_PREFIX`

Optional idempotency replay config (for multi-instance apply/remove dedupe):

- `PRF_SESSION_SEAL_IDEMPOTENCY_KIND` (`in-memory` | `upstash-redis-rest` | `redis-tcp` | `postgres`)
- `PRF_SESSION_SEAL_IDEMPOTENCY_TTL_MS`
- `PRF_SESSION_SEAL_IDEMPOTENCY_KEY_PREFIX`
- `PRF_SESSION_SEAL_IDEMPOTENCY_UPSTASH_URL` / `PRF_SESSION_SEAL_IDEMPOTENCY_UPSTASH_TOKEN` (optional overrides)
- `PRF_SESSION_SEAL_IDEMPOTENCY_REDIS_URL` (optional override)
- `PRF_SESSION_SEAL_IDEMPOTENCY_POSTGRES_URL` / `PRF_SESSION_SEAL_IDEMPOTENCY_POSTGRES_NAMESPACE` (optional overrides)

### `POST /recover-email` (email recovery)

Receives a JSON `ForwardableEmailPayload` (including `raw` containing the full RFC822 message) and forwards it into `EmailRecoveryService.requestEmailRecovery`.

Production notes:

- This server is the HTTP sink; you still need an email ingress (inbound email provider/webhook or your own MTA pipeline) to receive SMTP and then `POST` here.
- Emails can be large; this example uses `express.json({ limit: '5mb' })`.

## Configuration

Create `.env` file:

```bash
RELAYER_ACCOUNT_ID=relayer.testnet
RELAYER_PRIVATE_KEY=ed25519:...
NEAR_NETWORK_ID=testnet
NEAR_RPC_URL=https://rpc.testnet.near.org
PORT=3001
EXPECTED_ORIGIN=http://localhost:3000
# If you serve from multiple origins, set EXPECTED_WALLET_ORIGIN as well
# EXPECTED_WALLET_ORIGIN=http://localhost:4173

# Runtime/signer persistence (threshold sessions/shares/auth)
# POSTGRES_URL=postgres://tatchi:tatchi@127.0.0.1:5432/tatchi_signer

# Optional console persistence override (billing + webhooks + console data)
# Falls back to POSTGRES_URL when unset.
# CONSOLE_POSTGRES_URL=postgres://tatchi_console:tatchi_console@127.0.0.1:5432/tatchi_console

# Console/admin auth (dev adapter)
CONSOLE_DEV_TOKEN=dev-console-token

# Console billing backend:
# - postgres (persists data to Postgres)
# - memory (ephemeral dev-only in-memory store)
# Defaults to postgres when POSTGRES_URL is set, otherwise memory.
# CONSOLE_BILLING_BACKEND=postgres
# Optional namespace for Postgres billing tables
# CONSOLE_BILLING_NAMESPACE=relay-console
# Optional shared secret required by POST /console/billing/stripe/webhook
# CONSOLE_BILLING_STRIPE_WEBHOOK_SECRET=replace-with-strong-random-secret

# Console webhooks backend:
# - postgres (persists webhook endpoints/deliveries/attempts/dead-letters)
# - memory (ephemeral dev-only in-memory store)
# Defaults to postgres when POSTGRES_URL is set, otherwise memory.
# CONSOLE_WEBHOOKS_BACKEND=postgres
# Optional namespace for Postgres webhook tables
# CONSOLE_WEBHOOKS_NAMESPACE=relay-console

# Threshold secrets (base64url-encoded 32-byte values)
# THRESHOLD_ED25519_MASTER_SECRET_B64U=<32-byte-base64url>
# Required: relay startup fails if missing.
# THRESHOLD_SECP256K1_MASTER_SECRET_B64U=<32-byte-base64url>

# Optional PRF seal/unseal routes for refresh rehydrate.
# PRF_SESSION_SEAL_ENABLED=1
# PRF_SESSION_SEAL_KEY_VERSION=kek-s-2026-02
# Generate values with: pnpm prf-seal:keygen
# SHAMIR_P_B64U=...
# SHAMIR_E_S_B64U=...
# SHAMIR_D_S_B64U=...
# PRF_SESSION_SEAL_RATE_LIMIT_KIND=in-memory
# PRF_SESSION_SEAL_RATE_LIMIT=30
# PRF_SESSION_SEAL_RATE_LIMIT_WINDOW_MS=60000
# PRF_SESSION_SEAL_RATE_LIMIT_KEY_PREFIX=threshold:prf-seal:rate:
# PRF_SESSION_SEAL_IDEMPOTENCY_KIND=in-memory
# PRF_SESSION_SEAL_IDEMPOTENCY_TTL_MS=90000
# PRF_SESSION_SEAL_IDEMPOTENCY_KEY_PREFIX=threshold:prf-seal:idempotency:
# PRF_SESSION_SEAL_IDEMPOTENCY_UPSTASH_URL=
# PRF_SESSION_SEAL_IDEMPOTENCY_UPSTASH_TOKEN=
# PRF_SESSION_SEAL_IDEMPOTENCY_REDIS_URL=
# PRF_SESSION_SEAL_IDEMPOTENCY_POSTGRES_URL=
# PRF_SESSION_SEAL_IDEMPOTENCY_POSTGRES_NAMESPACE=
```

## Development

### Persistence (Postgres / Redis / Upstash)

The relay stores WebAuthn authenticators (credential public keys + counters) and credential bindings privately (no on-chain verifier). By default the example relay uses **in-memory** stores, which means:

- credentials are lost on restart
- multi-instance deployments will intermittently fail (“Credential is not registered for user”)

For local dev, prefer Postgres (durable; also persists threshold session/auth KV):

```bash
# from examples/relay-server
pnpm run postgres:up
```

Then in your relay `.env`:

```bash
# runtime/signer data (threshold session/auth/share stores)
POSTGRES_URL=postgres://tatchi:tatchi@127.0.0.1:5432/tatchi_signer

# optional: console domain data (billing/webhooks/admin control-plane)
# defaults to POSTGRES_URL when omitted
CONSOLE_POSTGRES_URL=postgres://tatchi_console:tatchi_console@127.0.0.1:5432/tatchi_console
```

Alternatively, run Redis and set `REDIS_URL`:

```bash
# from examples/relay-server
docker compose -f docker-compose.redis.yml up -d
```

Then in your relay `.env`:

```bash
# Node-only TCP Redis
REDIS_URL=redis://127.0.0.1:6379
```

If both `POSTGRES_URL` and `REDIS_URL` are set, this example server prefers Postgres for threshold stores.

For production/serverless, prefer Upstash REST:

- `UPSTASH_REDIS_REST_URL`
- `UPSTASH_REDIS_REST_TOKEN`

### Console/Admin Billing + Webhooks APIs

This example server also mounts console/admin routes at `/console/*`.

- Auth: send `Authorization: Bearer <CONSOLE_DEV_TOKEN>`.
- Optional dev claim overrides:
  - `x-console-org-id`
  - `x-console-user-id`
  - `x-console-roles` (comma-separated, defaults to `admin`)
- Billing backend is selected with `CONSOLE_BILLING_BACKEND`:
  - `postgres`: durable billing data via `CONSOLE_POSTGRES_URL` (fallback `POSTGRES_URL`)
  - `memory`: ephemeral in-memory billing data for local dev
- Stripe webhook auth for billing is configured with `CONSOLE_BILLING_STRIPE_WEBHOOK_SECRET`:
  - when set, `/console/billing/stripe/webhook` requires header `x-console-stripe-webhook-secret` with an exact secret match.
  - when unset, webhook route returns `stripe_webhook_not_configured`.
- Webhooks backend is selected with `CONSOLE_WEBHOOKS_BACKEND`:
  - `postgres`: durable webhook endpoint/delivery/attempt/dead-letter data via `CONSOLE_POSTGRES_URL` (fallback `POSTGRES_URL`)
  - `memory`: ephemeral in-memory webhook data for local dev

Example:

```bash
curl -s http://localhost:3001/console/billing/overview \
  -H "Authorization: Bearer dev-console-token"
```

### Coordinator Continuity Config (ECDSA Presign Sessions)

For multi-coordinator deployments behind a load balancer, configure each coordinator with:

1. a unique `THRESHOLD_COORDINATOR_INSTANCE_ID`
2. the same full `THRESHOLD_COORDINATOR_PEERS` map (all coordinators + URLs)

Example for 3 coordinators:

```bash
# coordinator-a env
THRESHOLD_COORDINATOR_INSTANCE_ID=coordinator-a
THRESHOLD_COORDINATOR_PEERS='[{"instanceId":"coordinator-a","relayerUrl":"https://relay-server.localhost"},{"instanceId":"coordinator-b","relayerUrl":"https://relay-server2.localhost"},{"instanceId":"coordinator-c","relayerUrl":"https://relay-server3.localhost"}]'
```

```bash
# coordinator-b env
THRESHOLD_COORDINATOR_INSTANCE_ID=coordinator-b
THRESHOLD_COORDINATOR_PEERS='[{"instanceId":"coordinator-a","relayerUrl":"https://relay-server.localhost"},{"instanceId":"coordinator-b","relayerUrl":"https://relay-server2.localhost"},{"instanceId":"coordinator-c","relayerUrl":"https://relay-server3.localhost"}]'
```

```bash
# coordinator-c env
THRESHOLD_COORDINATOR_INSTANCE_ID=coordinator-c
THRESHOLD_COORDINATOR_PEERS='[{"instanceId":"coordinator-a","relayerUrl":"https://relay-server.localhost"},{"instanceId":"coordinator-b","relayerUrl":"https://relay-server2.localhost"},{"instanceId":"coordinator-c","relayerUrl":"https://relay-server3.localhost"}]'
```

Without this config, cross-instance `/threshold-ecdsa/presign/step` requests cannot be forwarded to the owning coordinator and fall back to retriable `stale_session_state`.

Forwarding behavior for `/threshold-ecdsa/presign/step`:

1. Client hits any coordinator behind LB.
2. If that coordinator owns the session, it handles the step directly.
3. If not, it forwards the request to the owner coordinator and relays the response back to client.
4. Forwarding uses:
   - `x-threshold-ecdsa-presign-forward-hop` (hop depth / loop protection)
   - `x-threshold-ecdsa-presign-forwarded-by` (forwarding coordinator instance id)
5. Hop depth is trusted only when `forwarded-by` is a known configured peer; untrusted client-supplied hop values are ignored.
6. If owner is unavailable or continuity is lost, the route returns retriable `stale_session_state` and client should call `/threshold-ecdsa/presign/init` again.

### Run the Server

```bash
pnpm install
pnpm run dev    # Development server with auto-reload
pnpm run build  # Build for production
pnpm start      # Production server
```

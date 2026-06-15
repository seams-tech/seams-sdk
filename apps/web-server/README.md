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

- Request body (abridged): `{ new_account_id, device_number?, threshold_ed25519?, threshold_ecdsa?, rp_id, webauthn_registration, authenticator_options? }`
- Response: `{ success, transactionHash?, error?, message? }`
- When `RELAY_API_KEY_AUTH_ENABLED=1` (default in example), this route requires:
  - `Authorization: Bearer <secret_key>`
  - API key scope `accounts.create`
  - Optional environment bind header `X-Seams-Environment-Id: <environment-id>` (rejects mismatched key/environment)

This route is consumed internally by the SDK’s registration flows.

Current live secret-key machine scopes in this example are:

- `accounts.create` for `POST /registration/bootstrap`
- `wallets.read` for the machine wallet read routes below

### `GET /v1/wallets`, `GET /v1/wallets/search`, `GET /v1/wallets/:id`

Read wallet data through the machine API surface without reusing `/console/wallets*`.

- Required headers:
  - `Authorization: Bearer <secret_key>`
- Required scope:
  - `wallets.read`
- Behavior:
  - the authenticated key determines the effective org + environment scope
  - list, search, and detail requests cannot escape that environment scope
  - this surface is read-only; wallet signing is not exposed as a secret-key route

### `POST /sponsorships/evm/call`

Executes a generic sponsored single-call EVM transaction for the demo onboarding flow.

The route itself is generic, but the active runtime snapshot seeds a default `Tempo Testnet Onboarding` policy that only allows the Tempo faucet call `dripTo(address,address[])` on chain `42431`.

- Request body:
  ```json
  {
    "environmentId": "<environment-id>",
    "nearAccountId": "<near-account-id>",
    "walletAddress": "0x...",
    "chainId": 42431,
    "idempotencyKey": "<new-key-per-click>",
    "call": {
      "to": "0x...",
      "data": "0x...",
      "gasLimit": "300000",
      "value": "0"
    }
  }
  ```
- Required headers:
  - `Authorization: Bearer <publishable_key>`
  - `X-Seams-Environment-Id: <environment-id>`
- Behavior:
  - authenticates the publishable key against origin + environment
  - loads the latest runtime snapshot for the environment
  - matches the requested call against the resolved sponsored-call policy
  - requires an explicit `idempotencyKey` and replays terminal results only when that same key is reused
  - broadcasts a relay-owned EIP-1559 transaction when policy allows the call
  - records exact finalized gas spend in the console sponsored-call ledger
  - records a billing usage event for the associated org

Enable by setting `SPONSORED_EVM_EXECUTORS_JSON` in `.env.example`, for example:

```env
SPONSORED_EVM_EXECUTORS_JSON={"42431":{"rpcUrl":"https://rpc.moderato.tempo.xyz","sponsorPrivateKeyHex":"0x...","maxPriorityFeePerGasFloor":"2000000000","maxFeePerGasFloor":"40000000000"}}
```

If active sponsorship policies use spend caps, also configure a pricing adapter. The example relay supports either an optional real pricing source or an explicit static pricing config.

Real pricing currently supports:

- EVM native gas spend using live `eth_gasPrice` from the configured chain RPC plus CoinGecko USD pricing for the configured native asset
- NEAR gas-only spend using CoinGecko USD pricing for `near` plus an operator-configured reservation estimate in yoctoNEAR

```env
SPONSORED_EXECUTION_REAL_PRICING_JSON={"provider":"coingecko","cacheTtlMs":300000,"evm":{"42431":{"rpcUrl":"https://rpc.moderato.tempo.xyz","assetId":"near","nativeUnitDecimals":18,"pricingVersionPrefix":"coingecko-tempo-testnet"}},"near":{"TESTNET":{"assetId":"near","nativeUnitDecimals":24,"estimateFeeAmountYocto":"2000","pricingVersionPrefix":"coingecko-near-testnet"}}}
```

That adapter uses:

- `rpcUrl` to read live `eth_gasPrice` for EVM estimate reservations
- `assetId` to fetch the native asset USD price from CoinGecko
- `nativeUnitDecimals` to convert native fee units into whole-asset pricing
- `estimateFeeAmountYocto` for NEAR reservation estimates before execution settles actual `tokens_burnt`
- `pricingVersionPrefix` to stamp reservation/settlement records with the live pricing source version

If you do not want a live market source, you can still use the explicit static conversion config:

```env
SPONSORED_EXECUTION_STATIC_PRICING_JSON={"evm":{"42431":{"estimateFeePerGas":"22000000000","minorPerFeeUnitNumerator":"100","minorPerFeeUnitDenominator":"1000000000000000000","pricingVersion":"static-tempo-testnet-v1"}},"near":{"TESTNET":{"estimateFeeAmountYocto":"2000","minorPerFeeUnitNumerator":"1","minorPerFeeUnitDenominator":"1000","pricingVersion":"static-near-testnet-v1"}}}
```

That adapter uses:

- `estimateFeePerGas` to reserve capped budget before execution using `gasLimit * estimateFeePerGas`
- `estimateFeeAmountYocto` to reserve capped NEAR budget before execution
- `minorPerFeeUnitNumerator` / `minorPerFeeUnitDenominator` to convert native fee units into billable `spendMinor`
- `pricingVersion` to stamp the reservation/settlement records for observability

This is an operator-configured static conversion, not a live transaction-level pricing feed.

If both `SPONSORED_EXECUTION_REAL_PRICING_JSON` and `SPONSORED_EXECUTION_STATIC_PRICING_JSON` are configured, the relay prefers the real pricing source and falls back to static only when the real config is absent or invalid.

### Passkey Verification (`POST /auth/passkey/options` → `POST /auth/passkey/verify`)

Verifies a standard WebAuthn assertion (contract-free; relay-stored authenticators + counter persistence).

- Step 1 (options): `POST /auth/passkey/options` with `{ user_id, rp_id, ttl_ms? }` → `{ challengeId, challengeB64u }`
- Step 2 (verify): `POST /auth/passkey/verify` with:
  ```json
  {
    "challengeId": "<id>",
    "webauthn_authentication": {
      /* assertion */
    }
  }
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

### Signing-session seal routes (`POST /threshold/signing-session-seal/*`) (optional)

When enabled, this example mounts:

- `POST /threshold/signing-session-seal/apply-server-seal`
- `POST /threshold/signing-session-seal/remove-server-seal`
- `GET /.well-known/webauthn` response includes `capabilities.signingSessionSeal` so sealed-refresh clients can enforce startup parity (`mode`, `keyVersion`, `shamirPrimeB64u`)

Enable with `SIGNING_SESSION_SEAL_ENABLED=1` and provide:

- `SIGNING_SESSION_SEAL_KEY_VERSION`
- `SIGNING_SESSION_SHAMIR_P_B64U`
- `SIGNING_SESSION_SEAL_E_S_B64U`
- `SIGNING_SESSION_SEAL_D_S_B64U`

Generate matching server/client values:

```bash
# from repo root
pnpm signing-session-seal:keygen
```

The command prints:

- server env values: `SIGNING_SESSION_SHAMIR_P_B64U`, `SIGNING_SESSION_SEAL_E_S_B64U`, `SIGNING_SESSION_SEAL_D_S_B64U`, `SIGNING_SESSION_SEAL_KEY_VERSION`
- client env values: `VITE_SIGNING_SESSION_PERSISTENCE_MODE`, `VITE_SIGNING_SESSION_SEAL_KEY_VERSION`, `VITE_SIGNING_SESSION_SHAMIR_P_B64U`

Keep the printed client values aligned with relay `SIGNING_SESSION_*` values. Sealed-refresh clients fail closed on mismatch.

## Router A/B Normal Signing

Set `ROUTER_AB_NORMAL_SIGNING_WORKER_ID` on the relay/server when clients mint
Router A/B Ed25519 normal-signing sessions. The value must match the frontend
`VITE_ROUTER_AB_NORMAL_SIGNING_WORKER_ID`; local Router A/B workers use
`local-signing-worker`.

Optional limiter config:

- `SIGNING_SESSION_SEAL_RATE_LIMIT_KIND` (`in-memory` | `upstash-redis-rest` | `redis-tcp`)
- `SIGNING_SESSION_SEAL_RATE_LIMIT`
- `SIGNING_SESSION_SEAL_RATE_LIMIT_WINDOW_MS`
- `SIGNING_SESSION_SEAL_RATE_LIMIT_KEY_PREFIX`

Email OTP challenge, verify, and unseal-grant routes have independent abuse controls:

- `EMAIL_OTP_DELIVERY_MODE` (`memory` | `log` | `email_provider`)
- `EMAIL_OTP_RATE_LIMITER_KIND` (`in-memory` | `upstash-redis-rest` | `redis-tcp`)
- `EMAIL_OTP_RATE_LIMIT_KEY_PREFIX`
- `EMAIL_OTP_CHALLENGE_RATE_LIMIT_MAX`
- `EMAIL_OTP_CHALLENGE_RATE_LIMIT_WINDOW_MS`
- `EMAIL_OTP_VERIFY_RATE_LIMIT_MAX`
- `EMAIL_OTP_VERIFY_RATE_LIMIT_WINDOW_MS`
- `EMAIL_OTP_GRANT_RATE_LIMIT_MAX`
- `EMAIL_OTP_GRANT_RATE_LIMIT_WINDOW_MS`

Non-production defaults are local-friendly (`100` challenge, verify, and grant attempts per `60000` ms) and use an in-memory limiter unless an Email OTP-specific backend or explicit `EMAIL_OTP_RATE_LIMITER_KIND` is configured. Local delivery defaults to `memory`; the relay prints `[email-otp] development OTP code` with `devOtpCode` for non-production `memory` and `log` delivery modes. Production defaults are conservative when `NODE_ENV=production` (`5` challenges, `10` verifies, and `8` grant redemptions per `300000` ms). Production deploys should set `NODE_ENV=production` and explicit `EMAIL_OTP_*_RATE_LIMIT_*` values. The default limiter key prefix is `email-otp:v2:` so stale Redis buckets from older local defaults do not keep returning HTTP 429 after upgrading.

Optional idempotency replay config (for multi-instance apply/remove dedupe):

- `SIGNING_SESSION_SEAL_IDEMPOTENCY_KIND` (`in-memory` | `upstash-redis-rest` | `redis-tcp` | `postgres`)
- `SIGNING_SESSION_SEAL_IDEMPOTENCY_TTL_MS`
- `SIGNING_SESSION_SEAL_IDEMPOTENCY_KEY_PREFIX`
- `SIGNING_SESSION_SEAL_IDEMPOTENCY_UPSTASH_URL` / `SIGNING_SESSION_SEAL_IDEMPOTENCY_UPSTASH_TOKEN` (optional overrides)
- `SIGNING_SESSION_SEAL_IDEMPOTENCY_REDIS_URL` (optional override)
- `SIGNING_SESSION_SEAL_IDEMPOTENCY_POSTGRES_URL` / `SIGNING_SESSION_SEAL_IDEMPOTENCY_POSTGRES_NAMESPACE` (optional overrides)

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
# POSTGRES_URL=postgres://seams_signer:seams_signer@127.0.0.1:5432/seams_signer
# Optional signer migration URL (recommended separate migrator role)
# POSTGRES_MIGRATION_URL=postgres://seams_signer_migrator:seams_signer_migrator@127.0.0.1:5432/seams_signer

# Optional console persistence override (billing + webhooks + observability + console data)
# Keep this separate from POSTGRES_URL signer state.
# CONSOLE_POSTGRES_URL=postgres://seams_console:seams_console@127.0.0.1:5432/seams_console
# Optional console migration URL (recommended separate migrator role)
# CONSOLE_POSTGRES_MIGRATION_URL=postgres://seams_console_migrator:seams_console_migrator@127.0.0.1:5432/seams_console

# Google OIDC for /session/exchange (exchange.type=oidc_jwt)
# GOOGLE_OIDC_CLIENT_ID=
# GOOGLE_OIDC_CLIENT_IDS=
# Optional hosted-domain allowlist for /auth/google/verify
# GOOGLE_OIDC_HOSTED_DOMAINS=

# Relay runtime API key auth on POST /registration/bootstrap
RELAY_API_KEY_AUTH_ENABLED=1

# Console billing backend:
# - postgres (persists data to Postgres)
# - memory (ephemeral dev-only in-memory store)
# Defaults to postgres when CONSOLE_POSTGRES_URL is set, otherwise memory.
# CONSOLE_BILLING_BACKEND=postgres
# Set to 0/false to disable startup schema auto-creation (use explicit migration scripts).
# CONSOLE_BILLING_ENSURE_SCHEMA=1
# Optional namespace for Postgres billing tables
# CONSOLE_BILLING_NAMESPACE=relay-console
# Optional shared secret required by POST /console/billing/stripe/webhook
# CONSOLE_BILLING_STRIPE_WEBHOOK_SECRET=replace-with-strong-random-secret
# Optional live Stripe API credentials for /console/billing/stripe/* provider flows.
# When STRIPE_API_SK is unset, relay uses deterministic mock Stripe providers.
# STRIPE_API_SK=sk_test_...
# Optional (frontend usage; relay only logs presence)
# STRIPE_API_PK=pk_test_...
# Optional default Stripe checkout Price ID.
# If unset, relay checkout provider uses inline dynamic price_data for demo mode.
# STRIPE_CHECKOUT_PRICE_ID=price_...
# Optional Stripe API base URL override.
# STRIPE_API_BASE_URL=https://api.stripe.com
# Optional Stripe API request timeout in milliseconds (default 15000).
# STRIPE_API_TIMEOUT_MS=15000

# Console webhooks backend:
# - postgres (persists webhook endpoints/deliveries/attempts/dead-letters)
# - memory (ephemeral dev-only in-memory store)
# Defaults to postgres when CONSOLE_POSTGRES_URL is set, otherwise memory.
# CONSOLE_WEBHOOKS_BACKEND=postgres
# Set to 0/false to disable startup schema auto-creation (use explicit migration scripts).
# CONSOLE_WEBHOOKS_ENSURE_SCHEMA=1
# Optional namespace for Postgres webhook tables
# CONSOLE_WEBHOOKS_NAMESPACE=relay-console

# Console observability backend:
# - postgres (partitioned + retained observability events with query/backpressure guardrails)
# - memory (ephemeral dev-only status-only mode)
# Defaults to postgres when CONSOLE_POSTGRES_URL is set, otherwise memory.
# CONSOLE_OBSERVABILITY_BACKEND=postgres
# Set to 0/false to disable startup schema auto-creation (use explicit migration scripts).
# CONSOLE_OBSERVABILITY_ENSURE_SCHEMA=1
# Optional namespace for observability tables
# CONSOLE_OBSERVABILITY_NAMESPACE=relay-console
# Strict read-query max window (default 7 days)
# CONSOLE_OBSERVABILITY_QUERY_MAX_WINDOW_MS=604800000
# Ingest backpressure guardrails
# CONSOLE_OBSERVABILITY_INGEST_MAX_BATCH_SIZE=200
# CONSOLE_OBSERVABILITY_INGEST_MAX_EVENTS_PER_MINUTE=10000
# Retention TTL guardrails
# CONSOLE_OBSERVABILITY_RETENTION_TTL_MS=2592000000
# CONSOLE_OBSERVABILITY_RETENTION_PRUNE_INTERVAL_MS=300000
# CONSOLE_OBSERVABILITY_RETENTION_BATCH_SIZE=1000

# Threshold signing-root shares
# Local dev automatically wires fixture signing-root shares for localhost/.local origins
# unless NODE_ENV=production.
# Use real sealed signing-root share storage before using the signer for real funds.
# THRESHOLD_SIGNING_ROOT_LOCAL_DEV_RESOLVER=1
# The authenticated project/environment runtime scope supplies signingRootId per request.
# Active environment metadata supplies signingRootVersion=default for the local fixture.
# Do not configure a process-wide signing root on the relay for hosted multi-project flows.

# Optional signing-session seal/unseal routes for refresh rehydrate.
# SIGNING_SESSION_SEAL_ENABLED=1
# SIGNING_SESSION_SEAL_KEY_VERSION=kek-s-2026-02
# Generate values with: pnpm signing-session-seal:keygen
# SIGNING_SESSION_SHAMIR_P_B64U=...
# SIGNING_SESSION_SEAL_E_S_B64U=...
# SIGNING_SESSION_SEAL_D_S_B64U=...
# SIGNING_SESSION_SEAL_RATE_LIMIT_KIND=in-memory
# SIGNING_SESSION_SEAL_RATE_LIMIT=30
# SIGNING_SESSION_SEAL_RATE_LIMIT_WINDOW_MS=60000
# SIGNING_SESSION_SEAL_RATE_LIMIT_KEY_PREFIX=threshold:signing-session-seal:rate:
# EMAIL_OTP_DELIVERY_MODE=memory
# EMAIL_OTP_RATE_LIMITER_KIND=in-memory
# EMAIL_OTP_RATE_LIMIT_KEY_PREFIX=email-otp:v2:
# EMAIL_OTP_CHALLENGE_RATE_LIMIT_MAX=100
# EMAIL_OTP_CHALLENGE_RATE_LIMIT_WINDOW_MS=60000
# EMAIL_OTP_VERIFY_RATE_LIMIT_MAX=100
# EMAIL_OTP_VERIFY_RATE_LIMIT_WINDOW_MS=60000
# EMAIL_OTP_GRANT_RATE_LIMIT_MAX=100
# EMAIL_OTP_GRANT_RATE_LIMIT_WINDOW_MS=60000
# SIGNING_SESSION_SEAL_IDEMPOTENCY_KIND=in-memory
# SIGNING_SESSION_SEAL_IDEMPOTENCY_TTL_MS=90000
# SIGNING_SESSION_SEAL_IDEMPOTENCY_KEY_PREFIX=threshold:signing-session-seal:idempotency:
# SIGNING_SESSION_SEAL_IDEMPOTENCY_UPSTASH_URL=
# SIGNING_SESSION_SEAL_IDEMPOTENCY_UPSTASH_TOKEN=
# SIGNING_SESSION_SEAL_IDEMPOTENCY_REDIS_URL=
# SIGNING_SESSION_SEAL_IDEMPOTENCY_POSTGRES_URL=
# SIGNING_SESSION_SEAL_IDEMPOTENCY_POSTGRES_NAMESPACE=
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

# optional: bootstrap split DB users + databases + grants
pnpm run postgres:bootstrap:split

# full split-domain setup + verify (up -> bootstrap -> migrate -> verify)
pnpm run postgres:setup:split
```

Then in your relay `.env`:

```bash
# runtime/signer data (threshold session/auth/share stores)
POSTGRES_URL=postgres://seams_signer:seams_signer@127.0.0.1:5432/seams_signer

# optional: console domain data (billing/webhooks/observability/admin control-plane)
# keep separate from POSTGRES_URL
CONSOLE_POSTGRES_URL=postgres://seams_console:seams_console@127.0.0.1:5432/seams_console

# optional: migration-only URLs (recommended for least-privilege runtime users)
POSTGRES_MIGRATION_URL=postgres://seams_signer_migrator:seams_signer_migrator@127.0.0.1:5432/seams_signer
CONSOLE_POSTGRES_MIGRATION_URL=postgres://seams_console_migrator:seams_console_migrator@127.0.0.1:5432/seams_console
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

Run migrations explicitly per domain:

```bash
# signer/runtime schema (uses POSTGRES_MIGRATION_URL, fallback POSTGRES_URL)
pnpm run postgres:migrate:signer

# console billing/webhooks/observability schema (uses CONSOLE_POSTGRES_MIGRATION_URL, fallback CONSOLE_POSTGRES_URL)
pnpm run postgres:migrate:console

# both
pnpm run postgres:migrate:all

# verify least-privilege split roles (runtime cannot DDL, migrator can DDL)
pnpm run postgres:verify:split
```

Migrate an existing single-DB setup into split signer/console databases:

```bash
# source monolith DB (required)
MONOLITH_POSTGRES_URL=postgresql://seams:seams@127.0.0.1:5432/seams

# target signer DB (required; migration URL preferred)
POSTGRES_MIGRATION_URL=postgresql://seams:seams@127.0.0.1:5432/seams_signer

# target console DB (required; migration URL preferred)
CONSOLE_POSTGRES_MIGRATION_URL=postgresql://seams:seams@127.0.0.1:5432/seams_console

# optional:
# SPLIT_MIGRATION_CREATE_DATABASES=1   # default 1, auto-create target DBs if missing
# SPLIT_MIGRATION_BATCH_SIZE=500       # default 500

pnpm run postgres:migrate:split-from-monolith
```

After migration, set runtime URLs to the split DBs:

```bash
POSTGRES_URL=postgresql://seams:seams@127.0.0.1:5432/seams_signer
CONSOLE_POSTGRES_URL=postgresql://seams:seams@127.0.0.1:5432/seams_console
```

Bootstrap/verify scripts require explicit split-domain role and database envvars. The bootstrap script also requires passwords so generated URLs match the roles it creates:

- `POSTGRES_BOOTSTRAP_ADMIN_USER` (default: `seams`)
- `POSTGRES_BOOTSTRAP_HOST` (default: `127.0.0.1`)
- `POSTGRES_BOOTSTRAP_PORT` (default: `5432`)
- `SIGNER_DB_NAME`, `SIGNER_RUNTIME_USER`, `SIGNER_RUNTIME_PASSWORD`, `SIGNER_MIGRATOR_USER`, `SIGNER_MIGRATOR_PASSWORD`
- `CONSOLE_DB_NAME`, `CONSOLE_RUNTIME_USER`, `CONSOLE_RUNTIME_PASSWORD`, `CONSOLE_MIGRATOR_USER`, `CONSOLE_MIGRATOR_PASSWORD`

For local development, set the conventional split-domain names explicitly:

```bash
SIGNER_DB_NAME=seams_signer
SIGNER_RUNTIME_USER=seams_signer
SIGNER_RUNTIME_PASSWORD=seams_signer
SIGNER_MIGRATOR_USER=seams_signer_migrator
SIGNER_MIGRATOR_PASSWORD=seams_signer_migrator

CONSOLE_DB_NAME=seams_console
CONSOLE_RUNTIME_USER=seams_console
CONSOLE_RUNTIME_PASSWORD=seams_console
CONSOLE_MIGRATOR_USER=seams_console_migrator
CONSOLE_MIGRATOR_PASSWORD=seams_console_migrator
```

In stricter environments, disable startup schema creation and require migrations:

```bash
CONSOLE_BILLING_ENSURE_SCHEMA=0
CONSOLE_WEBHOOKS_ENSURE_SCHEMA=0
```

For production/serverless, prefer Upstash REST:

- `UPSTASH_REDIS_REST_URL`
- `UPSTASH_REDIS_REST_TOKEN`

### Console/Admin Billing + Webhooks APIs

This example server also mounts console/admin routes at `/console/*`.

- Auth: relay app session (`app_session_v1`) via HttpOnly cookie or bearer JWT from:
  - `POST /session/exchange` (`exchange.type=oidc_jwt`),
  - `POST /session/exchange` (`exchange.type=passkey_assertion`).
- Demo org/member seed:
  - Enabled by default with `CONSOLE_DEMO_SEED_ENABLED=1`.
  - Seeded identities include:
    - `console-owner` (`owner`)
    - `console-admin` (`admin`)
    - `console-operator` (`overview_read`, `wallet_operations_read`, `integrations_read`)
  - Seed controls:
    - `CONSOLE_DEMO_ORG_ID` (optional explicit org override; otherwise the relay resolves the only persisted org from storage)
    - `CONSOLE_DEMO_PROJECT_ID`
    - `CONSOLE_DEMO_ENVIRONMENT_ID`
    - `CONSOLE_SSO_DEFAULT_ROLES` (optional additional bootstrap roles)
    - `CONSOLE_DEMO_ROLES` (fallback additional bootstrap roles)
    - `CONSOLE_PLATFORM_ADMIN_EMAILS` (optional CSV allowlist for additive `platform_admin` claims)
  - First-login SSO provisioning behavior:
    - ensures org context exists,
    - bootstraps missing active membership with `owner` + `admin` + configured additional roles,
    - appends audit event `member.owner.bootstrap`.
- Billing backend is selected with `CONSOLE_BILLING_BACKEND`:
  - `postgres`: durable billing data via `CONSOLE_POSTGRES_URL`
  - `memory`: ephemeral in-memory billing data for local dev
- Stripe provider mode:
  - set `STRIPE_API_SK` to use live Stripe API for prepaid checkout-session creation.
  - leave `STRIPE_API_SK` unset to use deterministic mock provider outputs for local/offline testing.
  - optional `STRIPE_CHECKOUT_PRICE_ID` pins checkout sessions to a pre-created Stripe Price ID.
- Stripe webhook auth for billing is configured with `CONSOLE_BILLING_STRIPE_WEBHOOK_SECRET`:
  - when set, `/console/billing/stripe/webhook` requires header `x-console-stripe-webhook-secret` with an exact secret match.
  - when unset, webhook route returns `stripe_webhook_not_configured`.
- Webhooks backend is selected with `CONSOLE_WEBHOOKS_BACKEND`:
  - `postgres`: durable webhook endpoint/delivery/attempt/dead-letter data via `CONSOLE_POSTGRES_URL`
  - `memory`: ephemeral in-memory webhook data for local dev
- Observability backend is selected with `CONSOLE_OBSERVABILITY_BACKEND`:
  - `postgres`: durable observability data via `CONSOLE_POSTGRES_URL` with partitioning, retention TTL, strict query windows, and ingest backpressure.
  - `memory`: status-only fallback with no durable event storage.

Example (cookie session from `/session/exchange`):

```bash
curl -s http://localhost:3001/console/session \
  -H "Cookie: seams-jwt=<app_session_jwt>"
```

### Coordinator Continuity Config (ECDSA Presign Sessions)

For multi-coordinator deployments behind a load balancer, configure each coordinator with:

1. a unique `THRESHOLD_COORDINATOR_INSTANCE_ID`
2. the same full `THRESHOLD_COORDINATOR_PEERS` map (all coordinators + URLs)

Example for 3 coordinators:

```bash
# coordinator-a env
THRESHOLD_COORDINATOR_INSTANCE_ID=coordinator-a
THRESHOLD_COORDINATOR_PEERS='[{"instanceId":"coordinator-a","relayerUrl":"https://localhost:9444"},{"instanceId":"coordinator-b","relayerUrl":"https://localhost:8445"},{"instanceId":"coordinator-c","relayerUrl":"https://localhost:8446"}]'
```

```bash
# coordinator-b env
THRESHOLD_COORDINATOR_INSTANCE_ID=coordinator-b
THRESHOLD_COORDINATOR_PEERS='[{"instanceId":"coordinator-a","relayerUrl":"https://localhost:9444"},{"instanceId":"coordinator-b","relayerUrl":"https://localhost:8445"},{"instanceId":"coordinator-c","relayerUrl":"https://localhost:8446"}]'
```

```bash
# coordinator-c env
THRESHOLD_COORDINATOR_INSTANCE_ID=coordinator-c
THRESHOLD_COORDINATOR_PEERS='[{"instanceId":"coordinator-a","relayerUrl":"https://localhost:9444"},{"instanceId":"coordinator-b","relayerUrl":"https://localhost:8445"},{"instanceId":"coordinator-c","relayerUrl":"https://localhost:8446"}]'
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

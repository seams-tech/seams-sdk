# Router API Server

Router API server that creates NEAR accounts on behalf of users through the configured relayer account.

## Features

- **Direct Account Creation**: Create NEAR accounts using configured relayer account authority
- **Custom Funding**: Configurable initial balance for new accounts
- **Transaction Queuing**: Prevents nonce conflicts
- **Simple JSON API**: Easy integration
- **Console/Admin APIs**: Optional `/console/*` routes with billing and webhook endpoints

## API

### Health endpoints

- `GET /healthz` — basic server health + feature configuration hints (fast; no external dependency checks)
- `GET /readyz` — readiness check

### `POST /registration/bootstrap`

Atomically create a NEAR account and register a WebAuthn authenticator in Router API storage (contract-free).

- Request body (abridged): `{ new_account_id, device_number?, threshold_ed25519?, threshold_ecdsa?, rp_id, webauthn_registration, authenticator_options? }`
- Response: `{ success, transactionHash?, error?, message? }`
- When `ROUTER_API_KEY_AUTH_ENABLED=1` (default in example), this route requires:
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
  - broadcasts a Router API-owned EIP-1559 transaction when policy allows the call
  - records exact finalized gas spend in the console sponsored-call ledger
  - records a billing usage event for the associated org

Enable by setting `SPONSORED_EVM_EXECUTORS_JSON` in `.env.example`, for example:

```env
SPONSORED_EVM_EXECUTORS_JSON={"42431":{"rpcUrl":"https://rpc.moderato.tempo.xyz","sponsorPrivateKeyHex":"0x...","maxPriorityFeePerGasFloor":"2000000000","maxFeePerGasFloor":"40000000000"}}
```

If active sponsorship policies use spend caps, also configure a pricing adapter. The example Router API supports either an optional real pricing source or an explicit static pricing config.

Real pricing currently supports:

- EVM native gas spend using live `eth_gasPrice` plus the on-chain Outlayer NEAR/USD price
- NEAR gas-only spend using the on-chain Outlayer NEAR/USD price plus an operator-configured reservation estimate in yoctoNEAR

```env
SPONSORED_EXECUTION_REAL_PRICING_JSON={"provider":"outlayer","nearRpcUrl":"https://free.rpc.fastnear.com","oracleContractId":"price-oracle.near","nearUsdPriceId":"c415de8d2efa7db216527dff4b60e8f3a5311c740dadb233e13e12547e226750","maxAgeSeconds":120,"maxLatestToEmaDeviationBps":1000,"cacheTtlMs":60000,"near":{"TESTNET":{"nativeUnitDecimals":24,"estimateFeeAmountYocto":"2000","pricingVersionPrefix":"outlayer-near-testnet"}}}
```

That adapter uses:

- `rpcUrl` to read live `eth_gasPrice` for EVM estimate reservations
- `nearRpcUrl`, `oracleContractId`, and `nearUsdPriceId` to read latest and EMA NEAR/USD prices on-chain
- `maxAgeSeconds` to reject stale oracle publications
- `maxLatestToEmaDeviationBps` to reject a latest price that has moved too far from the EMA
- `cacheTtlMs` to bound reuse of a validated oracle quote
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

If both `SPONSORED_EXECUTION_REAL_PRICING_JSON` and `SPONSORED_EXECUTION_STATIC_PRICING_JSON` are configured, Router API uses the real pricing source. An invalid real-pricing configuration fails startup validation instead of selecting static pricing.

### Passkey Verification (`POST /auth/passkey/options` → `POST /auth/passkey/verify`)

Verifies a standard WebAuthn assertion (contract-free; Router API-stored authenticators + counter persistence).

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

- The sample server mounts this route via the SDK router (`createRouterApiRouter(authService)`).
- `POST /auth/passkey/verify` is verification-only and does not mint app sessions.
- For cookie sessions, CORS must allow credentials and specify explicit origins.
  The example config enables CORS with `origin: [EXPECTED_ORIGIN, EXPECTED_WALLET_ORIGIN]` and `credentials: true`.
  Your frontend must use `credentials: 'include'` with fetch.

### Signing-session seal routes (`POST /wallet-session/seal/*`) (optional)

When enabled, this example mounts:

- `POST /wallet-session/seal/apply`
- `POST /wallet-session/seal/remove`
- `GET /.well-known/webauthn` publishes the public protocol and current key version.

The backend derives its Shamir lock key from one random 32-byte secret:

- `SIGNING_SESSION_SEAL_ROOT_SECRET_B64U` (secret)
- `SIGNING_SESSION_SEAL_CURRENT_KEY_VERSION` (deployment config)
- `SIGNING_SESSION_SEAL_ACCEPTED_WARM_KEY_VERSIONS` (comma-separated deployment config)

The frontend only selects `VITE_SIGNING_SESSION_PERSISTENCE_MODE=sealed_refresh_v1`. It
learns the public protocol and active key version from the backend capability response.

## Router A/B Normal Signing

Set `ROUTER_AB_NORMAL_SIGNING_WORKER_ID` on the Router server when clients mint
Router A/B Ed25519 normal-signing sessions. The value must match the frontend
`VITE_ROUTER_AB_NORMAL_SIGNING_WORKER_ID`; local Router A/B workers use
`local-signing-worker`.

Router A/B active signing requires the Router server to reach the private SigningWorker:

- `ROUTER_AB_SIGNING_WORKER_URL` (local default: `http://127.0.0.1:9103`)
- `ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET` (dev-only local value: `dev-router-ab-internal-service-auth`)

Router A/B normal-signing admission is durable in the Cloudflare D1/DO router.
The Express example uses in-memory admission only for local development and
fails startup for production normal-signing admission.

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

Non-production defaults are local-friendly (`100` challenge, verify, and grant attempts per `60000` ms) and use an in-memory limiter unless an Email OTP-specific backend or explicit `EMAIL_OTP_RATE_LIMITER_KIND` is configured. Local delivery defaults to `memory`; Router API prints `[email-otp] development OTP code` with `devOtpCode` for non-production `memory` and `log` delivery modes. Production allows `30` challenges, `30` verifications, and `30` grant redemptions per `60000` ms. Five incorrect codes trigger a five-minute lockout. Production deploys should set `NODE_ENV=production` and explicit `EMAIL_OTP_*` policy values. The default limiter key prefix is `email-otp:v2:` so stale Redis buckets from older local defaults do not keep returning HTTP 429 after upgrading.

Optional idempotency replay config (for multi-instance apply/remove dedupe):

- `SIGNING_SESSION_SEAL_IDEMPOTENCY_KIND` (`in-memory` | `upstash-redis-rest` | `redis-tcp`)
- `SIGNING_SESSION_SEAL_IDEMPOTENCY_TTL_MS`
- `SIGNING_SESSION_SEAL_IDEMPOTENCY_KEY_PREFIX`
- `SIGNING_SESSION_SEAL_IDEMPOTENCY_UPSTASH_URL` / `SIGNING_SESSION_SEAL_IDEMPOTENCY_UPSTASH_TOKEN` (optional overrides)
- `SIGNING_SESSION_SEAL_IDEMPOTENCY_REDIS_URL` (optional override)

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

# Google OIDC for /session/exchange (exchange.type=oidc_jwt)
# GOOGLE_OIDC_CLIENT_ID=
# GOOGLE_OIDC_CLIENT_IDS=
# Optional hosted-domain allowlist for /auth/google/verify
# GOOGLE_OIDC_HOSTED_DOMAINS=

# GitHub OAuth App for /session/exchange (exchange.type=github_oauth_code)
# GITHUB_OAUTH_CLIENT_ID=
# GITHUB_OAUTH_CLIENT_SECRET=
# GITHUB_OAUTH_CALLBACK_URL=https://localhost/dashboard/login

# Router API runtime key auth on POST /registration/bootstrap
ROUTER_API_KEY_AUTH_ENABLED=1

# Console storage in this Node runner is memory-only. Use the Cloudflare D1 local
# worker for persistent Refactor 82 development.
# Stripe endpoint signing secret for raw Stripe-Signature verification.
# STRIPE_WEBHOOK_SECRET=whsec_...
# This memory-backed Node runner rejects STRIPE_API_SK. Use the durable D1 worker
# for live Stripe checkout and refund operations.

# Strict read-query max window (default 7 days)
# CONSOLE_OBSERVABILITY_QUERY_MAX_WINDOW_MS=604800000
# Ingest backpressure guardrails
# CONSOLE_OBSERVABILITY_INGEST_MAX_BATCH_SIZE=200
# CONSOLE_OBSERVABILITY_INGEST_MAX_EVENTS_PER_MINUTE=10000
# Retention TTL guardrails
# CONSOLE_OBSERVABILITY_RETENTION_TTL_MS=2592000000
# CONSOLE_OBSERVABILITY_RETENTION_PRUNE_INTERVAL_MS=300000
# CONSOLE_OBSERVABILITY_RETENTION_BATCH_SIZE=1000

# Threshold Router A/B role-local root-share fixtures
# Local dev automatically wires Deriver A/B fixtures for localhost/.local origins
# unless NODE_ENV=production. Use independent role-local custody before using the
# signer for real funds.
# The authenticated project/environment runtime scope supplies signingRootId per request.
# Active environment metadata supplies signingRootVersion=default for the local fixture.
# Do not configure a process-wide signing root on the Router API for hosted multi-project flows.

# Optional signing-session seal/unseal routes.
# SIGNING_SESSION_SEAL_ROOT_SECRET_B64U=<base64url-encoded random 32 bytes>
# SIGNING_SESSION_SEAL_CURRENT_KEY_VERSION=signing-session-seal-local-r2
# SIGNING_SESSION_SEAL_ACCEPTED_WARM_KEY_VERSIONS=signing-session-seal-local-r2
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
```

## Development

### Persistence

Staging-required local development uses the Cloudflare D1/DO Worker from the
installed `@seams/wallet-server` package:

```bash
pnpm -C packages/console-server-ts run d1:local:prepare
pnpm -C packages/console-server-ts run d1:local:dev
```

The Express Router API is a Node example. It stores WebAuthn authenticators
(credential public keys + counters) and credential bindings privately. By
default it uses **in-memory** stores, which means:

- credentials are lost on restart
- multi-instance deployments will intermittently fail (“Credential is not registered for user”)

For local Express durability, run Redis and set `REDIS_URL`:

```bash
# from apps/web-server
docker compose -f docker-compose.redis.yml up -d
```

Then in your Router API `.env`:

```bash
# Node-only TCP Redis
REDIS_URL=redis://127.0.0.1:6379
```

For production/serverless, prefer Upstash REST:

- `UPSTASH_REDIS_REST_URL`
- `UPSTASH_REDIS_REST_TOKEN`

### Console/Admin Billing + Webhooks APIs

This example server also mounts console/admin routes at `/console/*`.

- Auth: Router API app session (`app_session_v1`) via HttpOnly cookie or bearer JWT from:
  - `POST /session/exchange` (`exchange.type=oidc_jwt`),
  - `POST /session/exchange` (`exchange.type=passkey_assertion`).
- Demo org/member seed:
  - Enabled by default with `CONSOLE_DEMO_SEED_ENABLED=1`.
  - Seeded identities include:
    - `console-seed-owner` (`OWNER`)
    - `console-backup-owner` (`OWNER`)
    - `console-admin` (`ADMIN` with all four administrator permissions)
    - `console-operator` (`MEMBER` with editor access to the demo project)
  - Seed controls:
    - `CONSOLE_DEMO_ORG_ID` (optional explicit org override; otherwise Router API resolves the only persisted org from storage)
    - `CONSOLE_DEMO_PROJECT_ID`
    - `CONSOLE_DEMO_ENVIRONMENT_ID`
    - `CONSOLE_PLATFORM_SUPPORT_EMAILS` (optional CSV allowlist for internal support access)
  - First-login SSO provisioning behavior:
    - ensures org context exists,
    - creates the first organization membership as `OWNER`,
    - appends audit event `member.owner.bootstrap`.
- Console storage in this Node runner is in-memory. Durable Refactor 82 local
  development runs through the Cloudflare D1/DO worker.
- This Node runner uses deterministic mock Stripe provider outputs and rejects
  `STRIPE_API_SK`; live Stripe requires the durable D1 console worker.
- Stripe webhook verification is configured with `STRIPE_WEBHOOK_SECRET`:
  - `/console/billing/stripe/webhook` verifies Stripe's `Stripe-Signature` against the exact raw request body.
  - when unset, webhook route returns `stripe_webhook_not_configured`.
- Webhooks and observability use the same console backend family as billing.

Example (cookie session from `/session/exchange`):

```bash
curl -s http://localhost:3001/console/session \
  -H "Cookie: seams-jwt=<app_session_jwt>"
```

### Run the Server

```bash
pnpm install
pnpm run dev    # Development server with auto-reload
pnpm run build  # Build for production
pnpm start      # Production server
```

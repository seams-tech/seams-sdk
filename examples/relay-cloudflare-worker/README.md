# Cloudflare Relay Worker Notes

This Worker packages the relay server logic for Cloudflare's runtime. That
runtime differs from Node.js in a few important ways, so the Worker has some
extra requirements and limitations compared to the Express example.

## Runtime constraints

- **No filesystem access.** Workers cannot read from or write to a local fs.
  Any configuration that expects `fs.readFile` (e.g. `grace-keys.json`) must be
  provided via environment variables, KV/DO bindings, or omitted entirely. The
  Worker sets `graceShamirKeysFile` to an empty string for this reason.
- **No `process`, `__dirname`, or path resolution.** Relative URLs based on
  `import.meta.url` work in bundlers, but they resolve to `about:blank` inside a
  Worker bundle. AuthService now accepts a `signerWasm` override so the Worker
  can inject the WASM module directly.
- **Limited Web APIs only.** Use the WHATWG Fetch API and other browser-style
  globals. Node-only modules (net, tls, fs, path, etc.) are unavailable unless
  polyfilled by Wrangler's `nodejs_compat`, and even then many functions throw.

## WASM bundling

- The signer worker WASM is imported directly from the package sources
  (`import signerWasmModule from '@seams/sdk/server/wasm/signer'` and
  `import shamirWasmModule from '@seams/sdk/server/wasm/signer'`).
  Wrangler bundles the referenced files automatically; no `[wasm_modules]`
  section is required in `wrangler.toml`.
- Do **not** try to `fetch` the WASM from an arbitrary URL at runtime. Workers
  sit behind restricted networking rules and cannot access `file://` or other
  private origins.

## Configuration and secrets

- **Worker secrets** (sensitive) must be added via `wrangler secret put` (or the
  Cloudflare dashboard). They are not stored in `wrangler.toml`:
  - Required:
    - `RELAYER_PRIVATE_KEY`
    - `SIGNING_SESSION_SHAMIR_P_B64U`, `SIGNING_SESSION_SEAL_E_S_B64U`, `SIGNING_SESSION_SEAL_D_S_B64U`
  - Optional:
    - `SIGNING_ROOT_SECRET_SHARE_KEK_B64U` (enables signing-root threshold signing when sealed shares are present)
- **Worker vars** (non-secret) can be set in `wrangler.toml` `[vars]`, in the
  Cloudflare dashboard, or at deploy-time via `wrangler deploy --var ...`:
  - CORS allowlist (recommended to set explicitly if you use cookies):
    - `EXPECTED_ORIGIN` (e.g. docs/app origin)
    - `EXPECTED_WALLET_ORIGIN` (e.g. wallet iframe origin)
  - Runtime + ROR config (see `wrangler.toml` defaults):
    - `RELAYER_ACCOUNT_ID`, `NETWORK_ID`, `NEAR_RPC_URL`, etc.
    - `ROR_RP_ID` (optional; defaults to `hostname(EXPECTED_WALLET_ORIGIN)`)
    - `ROR_ALLOWED_ORIGINS` (optional comma-separated extra origins)
- Scheduled jobs are disabled by default. If you enable any cron-backed job,
  set at least one schedule in `[triggers].crons` in `wrangler.toml`.
- `wrangler.toml` now includes explicit per-environment cron job vars under
  `[env.production.vars]` and `[env.staging.vars]` with all console jobs set to
  disabled (`"0"`). Postgres URL defaults are explicit empty strings (`""`) and
  org id defaults are explicit empty CSV values (`""`), so missing required
  config is visible in deployment config and pre-flight warnings. To enable a
  job, set its `*_ENABLED="1"` and provide the required Postgres URL + org ids.
- When a cron job is enabled but required job config is missing, the worker
  logs a structured `[cron][worker-config]` warning before the cron runner
  evaluates job-specific skips.
- Optional Shamir rotation:
  - `ENABLE_ROTATION="1"`
- Generate matching Shamir values for server + client config:
  - `pnpm signing-session-seal:keygen`
- Optional billing monthly finalization (SaaS console):
  - `BILLING_FINALIZATION_ENABLED="1"`
  - `BILLING_POSTGRES_URL=<postgres url>`
  - `BILLING_NAMESPACE=<namespace>` (optional; defaults to `console-default`)
  - `BILLING_FINALIZATION_PERIOD_MONTH_UTC=YYYY-MM` (optional manual override)
  - `BILLING_FINALIZATION_ORG_IDS=<csv org ids>` (required in production)
  - `BILLING_FINALIZATION_CRONS=<csv cron expressions>` (optional tick allowlist; exact match against `event.cron`)
- Optional runtime snapshot outbox dispatch (SaaS console):
  - `RUNTIME_SNAPSHOT_OUTBOX_ENABLED="1"`
  - `RUNTIME_SNAPSHOT_OUTBOX_POSTGRES_URL=<postgres url>` (optional; defaults to `BILLING_POSTGRES_URL`)
  - `RUNTIME_SNAPSHOT_OUTBOX_NAMESPACE=<namespace>` (optional; defaults to `BILLING_NAMESPACE` or `console-default`)
  - `RUNTIME_SNAPSHOT_OUTBOX_ORG_IDS=<csv org ids>` (required in production)
  - `RUNTIME_SNAPSHOT_OUTBOX_LIMIT=<int>` (optional; default runner uses `100`)
  - `RUNTIME_SNAPSHOT_OUTBOX_CRONS=<csv cron expressions>` (optional tick allowlist; exact match against `event.cron`)
- Optional webhook retry dispatch (SaaS console):
  - `WEBHOOK_RETRY_ENABLED="1"`
  - `WEBHOOK_RETRY_POSTGRES_URL=<postgres url>` (optional; defaults to `BILLING_POSTGRES_URL`)
  - `WEBHOOK_RETRY_NAMESPACE=<namespace>` (optional; defaults to `BILLING_NAMESPACE` or `console-default`)
  - `WEBHOOK_RETRY_ORG_IDS=<csv org ids>` (required in production)
  - `WEBHOOK_RETRY_LIMIT=<int>` (optional; default runner uses `100`)
  - `WEBHOOK_RETRY_CRONS=<csv cron expressions>` (optional tick allowlist; exact match against `event.cron`)
  - `WEBHOOK_RETRY_MAX_ATTEMPTS=<int>` (optional; default `5`)
  - `WEBHOOK_RETRY_INITIAL_BACKOFF_MS=<int>` (optional; default `60000`)
  - `WEBHOOK_RETRY_MAX_BACKOFF_MS=<int>` (optional; default `3600000`)
  - Webhook retry observability incidents are written through the console observability ingestion schema using the same Postgres URL and namespace chain (`WEBHOOK_RETRY_*` first, then `BILLING_*`).

### Threshold signing (optional)

Threshold signing endpoints are enabled only when you provide:

- sealed signing-root shares in the threshold Durable Object
- `SIGNING_ROOT_SECRET_SHARE_KEK_B64U` (32 bytes, base64url) via `wrangler secret put`

You do **not** set the KEK via `--var` (it’s a secret).

Cloudflare-native persistence

- This example uses a **Durable Object** to persist threshold auth sessions + FROST signing sessions.
- Configure the base key prefix in `wrangler.toml` (or dashboard):
  - `THRESHOLD_PREFIX` (e.g. `seams:prod:w3a`)
  - Optional: `THRESHOLD_ED25519_SHARE_MODE=derived` (recommended for serverless)
  - Optional: `THRESHOLD_SIGNING_ROOT_OBJECT_NAME` (defaults to `threshold-signing-root-secrets`)
  - Optional: `SIGNING_ROOT_SECRET_SHARE_CACHE_TTL_MS` (defaults to `30000`)

### Session configuration (optional)

The Worker mints sessions only when you provide a SessionService. No JWT library
is bundled — you supply minimal sign/verify hooks. Cookies default to
`HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=24h` and can be customized via
cookie hooks.

Example hooks used in this example Worker entry:

```ts
const session = new SessionService({
  jwt: {
    signToken: ({ payload }) => {
      // If payload.exp is supplied (e.g., threshold session tokens), do not override it with `expiresIn`.
      const hasExp =
        typeof (payload as any).exp === 'number' && Number.isFinite((payload as any).exp);
      return jwt.sign(payload as any, env.JWT_SECRET || 'dev-token', {
        algorithm: 'HS256',
        issuer: 'relay-worker-demo',
        audience: 'seams-app-demo',
        ...(hasExp ? {} : { expiresIn: 86400 }),
      });
    },
    verifyToken: async (token) => {
      try {
        return { valid: true, payload: jwt.verify(token, env.JWT_SECRET || 'dev-token') };
      } catch {
        return { valid: false };
      }
    },
  },
  // Minimal cookie config (defaults are fine for Lax; customize with hooks below if needed)
  cookie: { name: 'seams-jwt' },
});
```

## Signing-session seal routes (`/threshold/signing-session-seal/*`)

This worker mounts:

- `POST /threshold/signing-session-seal/apply-server-seal`
- `POST /threshold/signing-session-seal/remove-server-seal`

Configure with vars:

- `SIGNING_SESSION_SEAL_ENABLED` (`"1"` or `"0"`, defaults to enabled)
- `SIGNING_SESSION_SEAL_KEY_VERSION` (defaults to `kek-s-2026-02`)

Custom cookie headers (optional):

```ts
const session = new SessionService({
  jwt: {
    /* sign/verify as above */
  },
  cookie: {
    name: 'seams-jwt',
    buildSetHeader: (token) =>
      [
        `seams-jwt=${token}`,
        'Path=/',
        'HttpOnly',
        'Secure',
        'SameSite=None',
        'Max-Age=86400',
      ].join('; '),
    buildClearHeader: () =>
      [
        'seams-jwt=',
        'Path=/',
        'HttpOnly',
        'Secure',
        'SameSite=None',
        'Max-Age=0',
        'Expires=Thu, 01 Jan 1970 00:00:00 GMT',
      ].join('; '),
  },
});
```

## Session verification (JWT or HttpOnly cookie)

Passkey verification is a 2-step WebAuthn flow:

- `POST /auth/passkey/options` with `{ user_id, rp_id, ttl_ms? }` → returns `{ challengeId, challengeB64u }`
- `POST /auth/passkey/verify` with `{ challengeId, webauthn_authentication }` → verifies challenge/assertion only

App-session issuance is exchange-first:

- `POST /session/exchange` with `{ sessionKind, exchange: { type: 'oidc_jwt', token } }` issues app session JWT/cookie.
- `/auth/passkey/verify` no longer mints app sessions.

Cookie mode and CORS

- Pass raw env origins to the router: it normalizes CSV/duplicates internally and only
  advertises `Access-Control-Allow-Credentials: true` when echoing a specific `Origin`.
- Set `EXPECTED_ORIGIN` (and/or `EXPECTED_WALLET_ORIGIN`) to explicit origins; avoid `*` when using cookies.
- Your frontend can use either exchange mode:
  1. OIDC/BYO token exchange:
  - `POST /session/exchange` with `{ sessionKind, exchange: { type: 'oidc_jwt', token } }`
  2. One-step passkey assertion exchange:
  - `POST /wallet/unlock/challenge` to get `challengeId` + `challengeB64u`
  - collect WebAuthn assertion in client
  - `POST /session/exchange` with
    `{ sessionKind, exchange: { type: 'passkey_assertion', challengeId, webauthn_authentication } }`

  `POST /auth/passkey/verify` remains verification-only:

  ```ts
  const options = await fetch(`${relay}/auth/passkey/options`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user_id, rp_id }),
  }).then((r) => r.json());

  await fetch(`${relay}/auth/passkey/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      challengeId: options.challengeId,
      webauthn_authentication,
    }),
  });
  ```

## Deployment checklist

1. From the repo root:
   - Install workspace deps: `pnpm install`
   - Build the SDK (required for the Worker bundle): `pnpm build:sdk-prod`
2. Authenticate: `npx wrangler login` or `npx wrangler config` with an API
   token.
3. Provision required secrets (repeat for each environment you deploy):

   ```bash
   # staging env (w3a-relay-staging)
   pnpm -C examples/relay-cloudflare-worker exec wrangler secret put RELAYER_PRIVATE_KEY --env staging
   pnpm -C examples/relay-cloudflare-worker exec wrangler secret put SIGNING_SESSION_SHAMIR_P_B64U --env staging
   pnpm -C examples/relay-cloudflare-worker exec wrangler secret put SIGNING_SESSION_SEAL_E_S_B64U --env staging
   pnpm -C examples/relay-cloudflare-worker exec wrangler secret put SIGNING_SESSION_SEAL_D_S_B64U --env staging

   # production env (w3a-relay-prod)
   pnpm -C examples/relay-cloudflare-worker exec wrangler secret put RELAYER_PRIVATE_KEY --env production
   pnpm -C examples/relay-cloudflare-worker exec wrangler secret put SIGNING_SESSION_SHAMIR_P_B64U --env production
   pnpm -C examples/relay-cloudflare-worker exec wrangler secret put SIGNING_SESSION_SEAL_E_S_B64U --env production
   pnpm -C examples/relay-cloudflare-worker exec wrangler secret put SIGNING_SESSION_SEAL_D_S_B64U --env production
   ```

4. Optional: provision threshold signing-root KEK (repeat per environment):
   ```bash
   pnpm -C examples/relay-cloudflare-worker exec wrangler secret put SIGNING_ROOT_SECRET_SHARE_KEK_B64U --env staging
   pnpm -C examples/relay-cloudflare-worker exec wrangler secret put SIGNING_ROOT_SECRET_SHARE_KEK_B64U --env production
   ```
5. Deploy:
   ```bash
   pnpm -C examples/relay-cloudflare-worker exec wrangler deploy --env staging
   pnpm -C examples/relay-cloudflare-worker exec wrangler deploy --env production
   ```
6. Tail logs during testing:
   ```bash
   pnpm -C examples/relay-cloudflare-worker exec wrangler tail --env staging
   pnpm -C examples/relay-cloudflare-worker exec wrangler tail --env production
   ```

### CORS allowlist (recommended)

If you want cookie-based sessions (`credentials: 'include'`), you must use an
explicit allowlist (not `Access-Control-Allow-Origin: *`).

Example mapping:

- staging: `EXPECTED_ORIGIN=https://staging.seams.xyz`, `EXPECTED_WALLET_ORIGIN=https://wallet-staging.web3authn.org`
- prod: `EXPECTED_ORIGIN=https://seams.xyz`, `EXPECTED_WALLET_ORIGIN=https://wallet.web3authn.org`

## Local testing tips

- Use `wrangler dev --remote` to run against a real edge runtime. The local
  Miniflare-based dev server cannot emulate the WASM bundling behaviour.
- The Worker logs detailed signer WASM initialization errors. If you see
  a WASM init/import error, re-run `pnpm build:sdk-prod` and verify
  `examples/relay-cloudflare-worker/wrangler.toml` includes the `CompiledWasm`
  `[[rules]]` entry for `**/*.wasm`.

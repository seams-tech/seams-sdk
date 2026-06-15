# Deployment Infra

This repo deploys these hosted surfaces:

- SDK runtime bundles in Cloudflare R2.
- App and wallet Pages projects from `examples/seams-site`.
- Relay Worker from `examples/relay-cloudflare-worker`.
- Router A/B Workers from `crates/router-ab-cloudflare`.

The relay also needs durable persistence. Use split Postgres databases for
signer/runtime state and console/control-plane state.

## GitHub Environments

Create these GitHub Environments:

- `staging`
- `production`

Use the same variable names in both environments. Values differ per
environment.

### Secrets

| Secret                                          | Used by                         | Notes                                                                                  |
| ----------------------------------------------- | ------------------------------- | -------------------------------------------------------------------------------------- |
| `CLOUDFLARE_API_TOKEN`                          | Pages, relay, Router A/B deploy | Needs Pages deploy, Worker deploy, Worker secrets, and Email Routing permissions.      |
| `CLOUDFLARE_ACCOUNT_ID`                         | Pages, relay, Router A/B deploy | Cloudflare account id.                                                                 |
| `CLOUDFLARE_ZONE_ID`                            | relay deploy                    | Required only when the workflow should manage Email Routing.                           |
| `CF_PAGES_PROJECT_VITE`                         | Pages deploy                    | Cloudflare Pages project for the app/site surface.                                     |
| `CF_PAGES_PROJECT_WALLET`                       | Pages deploy                    | Cloudflare Pages project for the wallet origin.                                        |
| `R2_ENDPOINT`                                   | SDK R2 publish                  | S3-compatible R2 endpoint URL.                                                         |
| `R2_BUCKET`                                     | SDK R2 publish                  | Bucket that stores `releases/*` and `releases-dev/*`.                                  |
| `R2_ACCESS_KEY_ID`                              | SDK R2 publish                  | R2 access key with write access to the SDK bucket.                                     |
| `R2_SECRET_ACCESS_KEY`                          | SDK R2 publish                  | R2 secret access key.                                                                  |
| `THRESHOLD_ED25519_MASTER_SECRET_B64U`          | relay deploy                    | Optional. When present, the relay workflow writes it as a Worker secret before deploy. |
| `SIGNER_A_ROOT_SHARE_WIRE_SECRET`               | Router A/B deploy               | Deriver A root-share wire secret. Written to the Deriver A Worker environment.         |
| `SIGNER_A_ENVELOPE_HPKE_PRIVATE_KEY`            | Router A/B deploy               | Deriver A signer-envelope HPKE private key.                                            |
| `SIGNER_A_PEER_SIGNING_KEY`                     | Router A/B deploy               | Deriver A private key for A/B peer messages.                                           |
| `SIGNER_B_ROOT_SHARE_WIRE_SECRET`               | Router A/B deploy               | Deriver B root-share wire secret. Written to the Deriver B Worker environment.         |
| `SIGNER_B_ENVELOPE_HPKE_PRIVATE_KEY`            | Router A/B deploy               | Deriver B signer-envelope HPKE private key.                                            |
| `SIGNER_B_PEER_SIGNING_KEY`                     | Router A/B deploy               | Deriver B private key for A/B peer messages.                                           |
| `SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY` | Router A/B deploy               | SigningWorker server-output HPKE private key.                                          |

### Variables

| Variable                                                 | Used by           | Notes                                                                        |
| -------------------------------------------------------- | ----------------- | ---------------------------------------------------------------------------- |
| `RECOVER_EMAIL_RECIPIENT`                                | relay deploy      | Email address routed to the relay Worker.                                    |
| `ROUTER_AB_JWT_ISSUER`                                   | Router A/B deploy | JWT issuer accepted by the Router admission boundary.                        |
| `ROUTER_AB_JWT_AUDIENCE`                                 | Router A/B deploy | JWT audience accepted by the Router; defaults operationally to `router-ab`.  |
| `ROUTER_AB_JWT_JWKS_URL`                                 | Router A/B deploy | JWKS URL used by Router JWT verification.                                    |
| `ROUTER_AB_SIGNER_A_ENVELOPE_HPKE_PUBLIC_KEY`            | Router A/B deploy | Public key matching `SIGNER_A_ENVELOPE_HPKE_PRIVATE_KEY`.                    |
| `ROUTER_AB_SIGNER_B_ENVELOPE_HPKE_PUBLIC_KEY`            | Router A/B deploy | Public key matching `SIGNER_B_ENVELOPE_HPKE_PRIVATE_KEY`.                    |
| `ROUTER_AB_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY` | Router A/B deploy | Public key matching `SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY`.         |
| `ROUTER_AB_SIGNER_A_PEER_VERIFYING_KEY_HEX`              | Router A/B deploy | Public verifying key matching `SIGNER_A_PEER_SIGNING_KEY`.                   |
| `ROUTER_AB_SIGNER_B_PEER_VERIFYING_KEY_HEX`              | Router A/B deploy | Public verifying key matching `SIGNER_B_PEER_SIGNING_KEY`.                   |
| `VITE_RELAYER_URL`                                       | Pages build       | Public relay API base URL.                                                   |
| `VITE_CONSOLE_BASE_URL`                                  | Pages build       | Optional console API base URL; defaults in app code when unset.              |
| `VITE_RELAYER_ACCOUNT_ID`                                | Pages build       | Parent NEAR account used for account creation.                               |
| `VITE_SEAMS_ENVIRONMENT_ID`                              | Pages build       | Hosted environment id for managed registration and sponsored actions.        |
| `VITE_SEAMS_PUBLISHABLE_KEY`                             | Pages build       | Publishable key for browser-managed relay calls.                             |
| `VITE_WALLET_ORIGIN`                                     | Pages build       | Wallet origin. Must match CORS and WebAuthn RP configuration.                |
| `VITE_WALLET_SERVICE_PATH`                               | Pages build       | Wallet service path; defaults to `/wallet-service` when unset.               |
| `VITE_SDK_BASE_PATH`                                     | Pages build       | SDK asset path; defaults to `/sdk` when unset.                               |
| `VITE_RP_ID_BASE`                                        | Pages build       | WebAuthn RP id base.                                                         |
| `VITE_DOCS_ORIGIN`                                       | Pages build       | Public docs origin used by site links and local header rules.                |
| `VITE_NEAR_NETWORK`                                      | Pages build       | `testnet` or `mainnet`.                                                      |
| `VITE_NEAR_RPC_URL`                                      | Pages build       | NEAR RPC URL.                                                                |
| `VITE_NEAR_EXPLORER`                                     | Pages build       | Explorer base URL.                                                           |
| `VITE_TEMPO_RPC_URL`                                     | Pages build       | Optional Tempo RPC URL.                                                      |
| `VITE_TEMPO_EXPLORER`                                    | Pages build       | Optional Tempo explorer URL.                                                 |
| `VITE_TEMPO_FEE_TOKEN`                                   | Pages build       | Optional Tempo fee token address.                                            |
| `VITE_ARC_RPC_URL`                                       | Pages build       | Optional Arc RPC URL.                                                        |
| `VITE_ARC_EXPLORER`                                      | Pages build       | Optional Arc explorer URL.                                                   |
| `VITE_SIGNING_SESSION_PERSISTENCE_MODE`                  | Pages build       | Set when enabling sealed-refresh client flows.                               |
| `VITE_SIGNING_SESSION_SEAL_KEY_VERSION`                  | Pages build       | Must match the active relay seal key version when sealed-refresh is enabled. |
| `VITE_SIGNING_SESSION_SHAMIR_P_B64U`                     | Pages build       | Public Shamir prime value for sealed-refresh clients.                        |
| `VITE_DASHBOARD_WALLETS_ROUTES_ENABLED`                  | Pages build       | Optional dashboard route gate.                                               |

## Cloudflare Pages

Create two Pages projects:

- app/site project: stored in `CF_PAGES_PROJECT_VITE`
- wallet-origin project: stored in `CF_PAGES_PROJECT_WALLET`

The `deploy-pages` workflow builds once and can deploy app, wallet, or both.
It deploys branch alias `dev` for staging and `main` for production.

The workflow copies SDK runtime assets into the Pages output:

- `sdk/dist/esm/sdk/*` -> `examples/seams-site/dist/sdk/*`
- `sdk/dist/workers/*` -> `examples/seams-site/dist/sdk/workers/*`

That means Pages serves the same runtime assets at `/sdk/*` that were built
for the commit being deployed.

## Cloudflare R2

Create one R2 bucket for SDK runtime bundles. The publish workflow writes:

- `releases-dev/<commit-sha>` for staging/dev commits
- `releases/<commit-sha>` for production/main commits
- `releases/<tag>` for `v*` tags pointing at the published commit

The workflow rewrites `.wasm` objects with `content-type: application/wasm`.
If the bucket is public or proxied, configure cache rules outside this repo.
Keep immutable SHA prefixes cacheable; keep mutable aliases such as tag prefixes
easy to invalidate.

## Relay Worker

Worker configuration lives in
`examples/relay-cloudflare-worker/wrangler.toml`.

Wrangler environments:

- `staging` deploys `w3a-relay-staging`
- `production` deploys `w3a-relay-prod`

Before the first deploy, set Worker secrets for each Wrangler environment:

```bash
pnpm -C examples/relay-cloudflare-worker exec wrangler secret put RELAYER_PRIVATE_KEY --env staging
pnpm -C examples/relay-cloudflare-worker exec wrangler secret put SIGNING_SESSION_SHAMIR_P_B64U --env staging
pnpm -C examples/relay-cloudflare-worker exec wrangler secret put SIGNING_SESSION_SEAL_E_S_B64U --env staging
pnpm -C examples/relay-cloudflare-worker exec wrangler secret put SIGNING_SESSION_SEAL_D_S_B64U --env staging
pnpm -C examples/relay-cloudflare-worker exec wrangler secret put SIGNING_ROOT_SECRET_SHARE_KEK_B64U --env staging

pnpm -C examples/relay-cloudflare-worker exec wrangler secret put RELAYER_PRIVATE_KEY --env production
pnpm -C examples/relay-cloudflare-worker exec wrangler secret put SIGNING_SESSION_SHAMIR_P_B64U --env production
pnpm -C examples/relay-cloudflare-worker exec wrangler secret put SIGNING_SESSION_SEAL_E_S_B64U --env production
pnpm -C examples/relay-cloudflare-worker exec wrangler secret put SIGNING_SESSION_SEAL_D_S_B64U --env production
pnpm -C examples/relay-cloudflare-worker exec wrangler secret put SIGNING_ROOT_SECRET_SHARE_KEK_B64U --env production
```

Generate seal keys with:

```bash
pnpm signing-session-seal:keygen
```

If cron-backed console jobs use Postgres from the Worker, store database URLs as
Worker secrets with the same names the Worker reads:

```bash
pnpm -C examples/relay-cloudflare-worker exec wrangler secret put BILLING_POSTGRES_URL --env staging
pnpm -C examples/relay-cloudflare-worker exec wrangler secret put RUNTIME_SNAPSHOT_OUTBOX_POSTGRES_URL --env staging
pnpm -C examples/relay-cloudflare-worker exec wrangler secret put WEBHOOK_RETRY_POSTGRES_URL --env staging
```

Repeat for production. Enable cron jobs by editing the relevant `*_ENABLED`,
`*_CRONS`, namespace, and org-id vars in `wrangler.toml` or by managing them in
Cloudflare.

## Router A/B Workers

Router A/B Worker configuration lives in:

- `crates/router-ab-cloudflare/wrangler.router.toml`
- `crates/router-ab-cloudflare/wrangler.signer-a.toml`
- `crates/router-ab-cloudflare/wrangler.signer-b.toml`
- `crates/router-ab-cloudflare/wrangler.signing-worker.toml`

Wrangler environments:

| Target       | Router                            | Deriver A                           | Deriver B                           | SigningWorker                             |
| ------------ | --------------------------------- | ----------------------------------- | ----------------------------------- | ----------------------------------------- |
| `staging`    | `router-ab-strict-router-staging` | `router-ab-strict-signer-a-staging` | `router-ab-strict-signer-b-staging` | `router-ab-strict-signing-worker-staging` |
| `production` | `router-ab-strict-router-prod`    | `router-ab-strict-signer-a-prod`    | `router-ab-strict-signer-b-prod`    | `router-ab-strict-signing-worker-prod`    |

The checked-in Wrangler vars contain placeholder public keys so dry-run builds
work without environment configuration. The `deploy-router-ab` workflow injects
the real public keys and Router JWT values from GitHub Environment variables
during `upload-version` and `deploy`, then writes the private values to the
corresponding Cloudflare Worker secrets before uploading or deploying Workers.

Use these templates to fill each GitHub Environment:

- [`router-ab-cloudflare-env.example.yml`](router-ab-cloudflare-env.example.yml):
  reviewable environment contract for Router, Deriver A, Deriver B, and
  SigningWorker.
- [`../../crates/router-ab-cloudflare/env/github-environment.example.env`](../../crates/router-ab-cloudflare/env/github-environment.example.env):
  copy/paste variable and secret names for GitHub Environment setup.

Role-specific configuration:

| Role          | Wrangler config                                            | GitHub Environment vars                                                                                                                 | GitHub Environment secrets                                                                           |
| ------------- | ---------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| Router        | `crates/router-ab-cloudflare/wrangler.router.toml`         | `ROUTER_AB_JWT_ISSUER`, `ROUTER_AB_JWT_AUDIENCE`, `ROUTER_AB_JWT_JWKS_URL`, all Router A/B public key vars                              | None beyond Cloudflare deploy credentials.                                                           |
| Deriver A     | `crates/router-ab-cloudflare/wrangler.signer-a.toml`       | `ROUTER_AB_SIGNER_A_ENVELOPE_HPKE_PUBLIC_KEY`, `ROUTER_AB_SIGNER_A_PEER_VERIFYING_KEY_HEX`, `ROUTER_AB_SIGNER_B_PEER_VERIFYING_KEY_HEX` | `SIGNER_A_ROOT_SHARE_WIRE_SECRET`, `SIGNER_A_ENVELOPE_HPKE_PRIVATE_KEY`, `SIGNER_A_PEER_SIGNING_KEY` |
| Deriver B     | `crates/router-ab-cloudflare/wrangler.signer-b.toml`       | `ROUTER_AB_SIGNER_B_ENVELOPE_HPKE_PUBLIC_KEY`, `ROUTER_AB_SIGNER_A_PEER_VERIFYING_KEY_HEX`, `ROUTER_AB_SIGNER_B_PEER_VERIFYING_KEY_HEX` | `SIGNER_B_ROOT_SHARE_WIRE_SECRET`, `SIGNER_B_ENVELOPE_HPKE_PRIVATE_KEY`, `SIGNER_B_PEER_SIGNING_KEY` |
| SigningWorker | `crates/router-ab-cloudflare/wrangler.signing-worker.toml` | `ROUTER_AB_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY`                                                                                | `SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY`                                                      |

`CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` are required for every
`upload-version` and `deploy` operation. Deriver root-share secrets use the
`mpc-prf-root-share-wire-v1:` prefix. Deriver envelope private keys use
`hpke-x25519-private-v1:`. The SigningWorker server-output private key uses
`hpke-x25519-server-output-private-v1:`.

Generate deployment identity keys with:

```bash
pnpm router:deploy:keygen -- --env staging
pnpm router:deploy:keygen -- --env staging --apply
```

The command generates Deriver A/B envelope HPKE keys, Deriver A/B peer-message
signing keys, and the SigningWorker server-output HPKE key. It does not
generate `SIGNER_A_ROOT_SHARE_WIRE_SECRET` or
`SIGNER_B_ROOT_SHARE_WIRE_SECRET`; those values come from the
derivation/provisioning ceremony. By default the command redacts private values
in stdout; use `--show-secrets` only for manual secret entry.

The Router serves public deployment keys at:

- `/.well-known/router-ab/keyset`
- `/v1/router-ab/keyset`

Self-hosted relay deployments may serve the same public keyset routes when
`routerAbPublicKeyset` is provided to the relay router. The browser SDK
prefetches `/v1/router-ab/keyset` during registration precompute whenever
Router A/B normal signing is enabled.

Manual validation and deployment:

```bash
gh workflow run deploy-router-ab.yml --ref dev -f target=staging -f operation=validate -f role=all
gh workflow run deploy-router-ab.yml --ref dev -f target=staging -f operation=upload-version -f role=all
gh workflow run deploy-router-ab.yml --ref dev -f target=staging -f operation=deploy -f role=all
```

For production, use `--ref main -f target=production`.

Local Cloudflare-shape checks:

```bash
pnpm router:deploy:dry-run
pnpm router:deploy:upload -- --env staging
```

Latest local dry-run evidence:

- `crates/router-ab-cloudflare/reports/startup-latencies/startup-latencies-2026-06-14T14-11-55-253Z.json`
- mode: `dry_run`
- gzip upload sizes: Router `573.83 KiB`, Deriver A `598.97 KiB`, Deriver B
  `599.92 KiB`, SigningWorker `567.14 KiB`

`operation=deploy` runs `pnpm router:deploy:check` before any Worker deployment.
Keep that gate green on the target commit, then deploy all four Workers in the
workflow order: SigningWorker, Deriver A, Deriver B, Router.

## Postgres

Use two database domains:

- signer/runtime: WebAuthn authenticators, threshold sessions, signer state
- console/control-plane: billing, webhooks, observability, org/project/env data

Use separate runtime and migrator roles per domain:

| Domain                | Runtime URL            | Migration URL                    |
| --------------------- | ---------------------- | -------------------------------- |
| signer/runtime        | `POSTGRES_URL`         | `POSTGRES_MIGRATION_URL`         |
| console/control-plane | `CONSOLE_POSTGRES_URL` | `CONSOLE_POSTGRES_MIGRATION_URL` |

Runtime roles need DML only. Migrator roles own DDL.

### Local Split Setup

```bash
pnpm -C examples/relay-server run postgres:setup:split
```

That command starts local Postgres, creates split databases and roles, runs
migrations, and verifies grants. It prints suggested `.env` values.

To run steps separately:

```bash
pnpm -C examples/relay-server run postgres:up
pnpm -C examples/relay-server run postgres:bootstrap:split
pnpm -C examples/relay-server run postgres:migrate:all
pnpm -C examples/relay-server run postgres:verify:split
```

To stop local Postgres:

```bash
pnpm -C examples/relay-server run postgres:down
```

### Production Migration

Provision production databases and roles with your DBA/IaC path, then run:

```bash
POSTGRES_MIGRATION_URL=postgresql://... \
CONSOLE_POSTGRES_MIGRATION_URL=postgresql://... \
pnpm -C examples/relay-server run postgres:migrate:all
```

Set runtime URLs on the relay host:

```bash
POSTGRES_URL=postgresql://runtime-user:...@.../signer_db
CONSOLE_POSTGRES_URL=postgresql://runtime-user:...@.../console_db
```

For stricter environments, disable startup schema creation and require explicit
migrations:

```bash
CONSOLE_BILLING_ENSURE_SCHEMA=0
CONSOLE_WEBHOOKS_ENSURE_SCHEMA=0
CONSOLE_OBSERVABILITY_ENSURE_SCHEMA=0
```

### Monolith To Split

For an existing single-database install:

```bash
MONOLITH_POSTGRES_URL=postgresql://.../seams \
POSTGRES_MIGRATION_URL=postgresql://.../seams_signer \
CONSOLE_POSTGRES_MIGRATION_URL=postgresql://.../seams_console \
pnpm -C examples/relay-server run postgres:migrate:split-from-monolith
```

After migration, update runtime URLs to point at the split databases.

## Redis And Upstash

Postgres is the preferred durable local and hosted path. Redis/Upstash can still
be used for rate limits or hot-path idempotency where configured:

- `REDIS_URL` for Node TCP Redis
- `UPSTASH_REDIS_REST_URL`
- `UPSTASH_REDIS_REST_TOKEN`

When both `POSTGRES_URL` and `REDIS_URL` are present, the example relay prefers
Postgres for threshold stores.

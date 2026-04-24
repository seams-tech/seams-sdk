# Deployment Infra

This repo deploys three hosted surfaces:

- SDK runtime bundles in Cloudflare R2.
- App and wallet Pages projects from `examples/tatchi-site`.
- Relay Worker from `examples/relay-cloudflare-worker`.

The relay also needs durable persistence. Use split Postgres databases for
signer/runtime state and console/control-plane state.

## GitHub Environments

Create these GitHub Environments:

- `staging`
- `production`

Use the same variable names in both environments. Values differ per
environment.

### Secrets

| Secret                                 | Used by             | Notes                                                                                  |
| -------------------------------------- | ------------------- | -------------------------------------------------------------------------------------- |
| `CLOUDFLARE_API_TOKEN`                 | Pages, relay deploy | Needs Pages deploy, Worker deploy, Worker secrets, and Email Routing permissions.      |
| `CLOUDFLARE_ACCOUNT_ID`                | Pages, relay deploy | Cloudflare account id.                                                                 |
| `CLOUDFLARE_ZONE_ID`                   | relay deploy        | Required only when the workflow should manage Email Routing.                           |
| `CF_PAGES_PROJECT_VITE`                | Pages deploy        | Cloudflare Pages project for the app/site surface.                                     |
| `CF_PAGES_PROJECT_WALLET`              | Pages deploy        | Cloudflare Pages project for the wallet origin.                                        |
| `R2_ENDPOINT`                          | SDK R2 publish      | S3-compatible R2 endpoint URL.                                                         |
| `R2_BUCKET`                            | SDK R2 publish      | Bucket that stores `releases/*` and `releases-dev/*`.                                  |
| `R2_ACCESS_KEY_ID`                     | SDK R2 publish      | R2 access key with write access to the SDK bucket.                                     |
| `R2_SECRET_ACCESS_KEY`                 | SDK R2 publish      | R2 secret access key.                                                                  |
| `THRESHOLD_ED25519_MASTER_SECRET_B64U` | relay deploy        | Optional. When present, the relay workflow writes it as a Worker secret before deploy. |

### Variables

| Variable                                | Used by      | Notes                                                                        |
| --------------------------------------- | ------------ | ---------------------------------------------------------------------------- |
| `RECOVER_EMAIL_RECIPIENT`               | relay deploy | Email address routed to the relay Worker.                                    |
| `VITE_RELAYER_URL`                      | Pages build  | Public relay API base URL.                                                   |
| `VITE_CONSOLE_BASE_URL`                 | Pages build  | Optional console API base URL; defaults in app code when unset.              |
| `VITE_RELAYER_ACCOUNT_ID`               | Pages build  | Parent NEAR account used for account creation.                               |
| `VITE_TATCHI_ENVIRONMENT_ID`            | Pages build  | Hosted environment id for managed registration and sponsored actions.        |
| `VITE_TATCHI_PUBLISHABLE_KEY`           | Pages build  | Publishable key for browser-managed relay calls.                             |
| `VITE_WALLET_ORIGIN`                    | Pages build  | Wallet origin. Must match CORS and WebAuthn RP configuration.                |
| `VITE_WALLET_SERVICE_PATH`              | Pages build  | Wallet service path; defaults to `/wallet-service` when unset.               |
| `VITE_SDK_BASE_PATH`                    | Pages build  | SDK asset path; defaults to `/sdk` when unset.                               |
| `VITE_RP_ID_BASE`                       | Pages build  | WebAuthn RP id base.                                                         |
| `VITE_DOCS_ORIGIN`                      | Pages build  | Public docs origin used by site links and local header rules.                |
| `VITE_NEAR_NETWORK`                     | Pages build  | `testnet` or `mainnet`.                                                      |
| `VITE_NEAR_RPC_URL`                     | Pages build  | NEAR RPC URL.                                                                |
| `VITE_NEAR_EXPLORER`                    | Pages build  | Explorer base URL.                                                           |
| `VITE_TEMPO_RPC_URL`                    | Pages build  | Optional Tempo RPC URL.                                                      |
| `VITE_TEMPO_EXPLORER`                   | Pages build  | Optional Tempo explorer URL.                                                 |
| `VITE_TEMPO_FEE_TOKEN`                  | Pages build  | Optional Tempo fee token address.                                            |
| `VITE_ARC_RPC_URL`                      | Pages build  | Optional Arc RPC URL.                                                        |
| `VITE_ARC_EXPLORER`                     | Pages build  | Optional Arc explorer URL.                                                   |
| `VITE_SIGNING_SESSION_PERSISTENCE_MODE` | Pages build  | Set when enabling sealed-refresh client flows.                               |
| `VITE_SIGNING_SESSION_SEAL_KEY_VERSION` | Pages build  | Must match the active relay seal key version when sealed-refresh is enabled. |
| `VITE_SIGNING_SESSION_SHAMIR_P_B64U`    | Pages build  | Public Shamir prime value for sealed-refresh clients.                        |
| `VITE_DASHBOARD_WALLETS_ROUTES_ENABLED` | Pages build  | Optional dashboard route gate.                                               |

## Cloudflare Pages

Create two Pages projects:

- app/site project: stored in `CF_PAGES_PROJECT_VITE`
- wallet-origin project: stored in `CF_PAGES_PROJECT_WALLET`

The `deploy-pages` workflow builds once and can deploy app, wallet, or both.
It deploys branch alias `dev` for staging and `main` for production.

The workflow copies SDK runtime assets into the Pages output:

- `sdk/dist/esm/sdk/*` -> `examples/tatchi-site/dist/sdk/*`
- `sdk/dist/workers/*` -> `examples/tatchi-site/dist/sdk/workers/*`

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

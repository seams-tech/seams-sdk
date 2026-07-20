# Deployment Infra

This repo deploys these hosted surfaces:

- SDK runtime bundles in Cloudflare R2.
- App and wallet Pages projects from `apps/seams-site`.
- Router A/B Workers from `crates/router-ab-cloudflare`.
- Gateway Workers from `packages/console-server-ts`.

The web server persists state in Cloudflare data services:

- `CONSOLE_DB` D1 for console/control-plane state.
- `SIGNER_DB` D1 for wallet, signer metadata, identity, WebAuthn, Email OTP,
  and recovery state.
- `THRESHOLD_STORE` Durable Object storage for threshold/session coordination
  and normal-signing admission state.
- R2 for SDK runtime bundles and scheduled D1 backup exports.

## GitHub Environments

Create these general GitHub Environments:

- `staging`
- `production`

Use the same variable names in both environments. Values differ per
environment.

Create `staging-gateway` and `production-gateway` for Gateway. Create
`staging-mpc-router`, `staging-deriver-a`,
`staging-deriver-b`, `staging-signing-worker`, plus matching `production-*`
role environments. Each role environment owns its Cloudflare credentials,
private material, variables, and protected approver set.

Automatic entrypoints are intentionally separate:

- `.github/workflows/deploy-staging.yml` accepts only successful `dev` CI.
- `.github/workflows/deploy-production.yml` accepts only successful `main` CI.

Both call `.github/workflows/deploy-router-ab.yml`, which is the shared release
implementation. Environment labels and branch restrictions remain in the
entrypoint YAML instead of a caller-selected runtime flag.

### Secrets

| Secret                                          | Used by                         | Notes                                                                                  |
| ----------------------------------------------- | ------------------------------- | -------------------------------------------------------------------------------------- |
| `CLOUDFLARE_API_TOKEN`                          | Pages, Router A/B deploy        | Needs Pages deploy, Worker deploy, and Worker secrets permissions.                    |
| `CLOUDFLARE_ACCOUNT_ID`                         | Pages, Router A/B deploy        | Cloudflare account id.                                                                 |
| `CF_PAGES_PROJECT_VITE`                         | Pages deploy                    | Cloudflare Pages project for the app/site surface.                                     |
| `CF_PAGES_PROJECT_WALLET`                       | Pages deploy                    | Cloudflare Pages project for the wallet origin.                                        |
| `R2_ENDPOINT`                                   | SDK R2 publish                  | S3-compatible R2 endpoint URL.                                                         |
| `R2_BUCKET`                                     | SDK R2 publish                  | Bucket that stores `releases/*` and `releases-dev/*`.                                  |
| `R2_ACCESS_KEY_ID`                              | SDK R2 publish                  | R2 access key with write access to the SDK bucket.                                     |
| `R2_SECRET_ACCESS_KEY`                          | SDK R2 publish                  | R2 secret access key.                                                                  |
| `DERIVER_A_ROOT_SHARE_WIRE_SECRET`               | Router A/B deploy               | Deriver A root-share wire secret. Written to the Deriver A Worker environment.         |
| `DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY`            | Router A/B deploy               | Deriver A signer-envelope HPKE private key.                                            |
| `DERIVER_A_PEER_SIGNING_KEY`                     | Router A/B deploy               | Deriver A private key for A/B peer messages.                                           |
| `DERIVER_B_ROOT_SHARE_WIRE_SECRET`               | Router A/B deploy               | Deriver B root-share wire secret. Written to the Deriver B Worker environment.         |
| `DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY`            | Router A/B deploy               | Deriver B signer-envelope HPKE private key.                                            |
| `DERIVER_B_PEER_SIGNING_KEY`                     | Router A/B deploy               | Deriver B private key for A/B peer messages.                                           |
| `SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY` | Router A/B deploy               | SigningWorker server-output HPKE private key.                                          |
| `RELAY_SESSION_HMAC_SECRET`                    | Gateway deploy                  | Environment-specific browser session signing secret.                                   |
| `ACCOUNT_ID_DERIVATION_SECRET`                 | Gateway deploy                  | Environment-specific account identifier derivation secret.                             |
| `ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET`       | Router A/B and Gateway          | Shared only by Workers inside one environment. Never share it across staging and production. |
| `ROUTER_AB_CEREMONY_JWT_PRIVATE_JWK`           | Gateway deploy                  | Private ceremony JWT signing key for this environment.                                  |
| `RELAYER_PRIVATE_KEY`                          | Gateway deploy                  | Relayer key matching `RELAYER_PUBLIC_KEY`.                                              |
| `SPONSORED_EVM_EXECUTORS_JSON`                 | Gateway deploy                  | Environment-specific sponsored EVM executor secrets.                                   |

### Variables

| Variable                                                 | Used by           | Notes                                                                        |
| -------------------------------------------------------- | ----------------- | ---------------------------------------------------------------------------- |
| `ROUTER_AB_JWT_ISSUER`                                   | Router A/B deploy | JWT issuer accepted by the Router admission boundary.                        |
| `ROUTER_AB_JWT_AUDIENCE`                                 | Router A/B deploy | JWT audience accepted by the Router; defaults operationally to `router-ab`.  |
| `ROUTER_AB_JWT_JWKS_URL`                                 | Router A/B deploy | JWKS URL used by Router JWT verification.                                    |
| `ROUTER_AB_DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY`            | Router A/B deploy | Public key matching `DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY`.                    |
| `ROUTER_AB_DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY`            | Router A/B deploy | Public key matching `DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY`.                    |
| `ROUTER_AB_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY` | Router A/B deploy | Public key matching `SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY`.         |
| `ROUTER_AB_DERIVER_A_PEER_VERIFYING_KEY_HEX`              | Router A/B deploy | Public verifying key matching `DERIVER_A_PEER_SIGNING_KEY`.                   |
| `ROUTER_AB_DERIVER_B_PEER_VERIFYING_KEY_HEX`              | Router A/B deploy | Public verifying key matching `DERIVER_B_PEER_SIGNING_KEY`.                   |
| `VITE_RELAYER_URL`                                       | Pages build       | Public Gateway base URL; historical env var name.                            |
| `VITE_CONSOLE_BASE_URL`                                  | Pages build       | Optional console API base URL; defaults in app code when unset.              |
| `VITE_RELAYER_ACCOUNT_ID`                                | Pages build       | Parent NEAR account used for account creation.                               |
| `VITE_SEAMS_PROJECT_ENVIRONMENT_ID`                      | Pages build       | Project-environment id for managed registration and sponsored actions.       |
| `VITE_SEAMS_PUBLISHABLE_KEY`                             | Pages build       | Publishable key for browser-managed Gateway calls.                           |
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
| `VITE_SIGNING_SESSION_SEAL_KEY_VERSION`                  | Pages build       | Must match the active Gateway seal key version when sealed-refresh is enabled. |
| `VITE_SIGNING_SESSION_SHAMIR_P_B64U`                     | Pages build       | Public Shamir prime value for sealed-refresh clients.                        |
| `VITE_ROUTER_AB_NORMAL_SIGNING_WORKER_ID`                | Pages build       | Exact SigningWorker id bound into Router A/B warm signing sessions.          |
| `VITE_DASHBOARD_WALLETS_ROUTES_ENABLED`                  | Pages build       | Optional dashboard route gate.                                               |

The Gateway environments additionally require:

- distinct `GATEWAY_WORKER_NAME`,
  `GATEWAY_CONSOLE_D1_DATABASE_NAME`,
  `GATEWAY_CONSOLE_D1_DATABASE_ID`,
  `GATEWAY_SIGNER_D1_DATABASE_NAME`, and
  `GATEWAY_SIGNER_D1_DATABASE_ID`;
- `GATEWAY_SECRETS_STORE_ID`, `SIGNING_ROOT_KEK_ID`,
  `SIGNING_ROOT_KEK_SECRET_NAME`, and `SIGNING_ROOT_KEK_ENCODING`;
- tenant identity (`SEAMS_TENANT_STORAGE_NAMESPACE`, `SEAMS_ORG_ID`,
  `SEAMS_PROJECT_ID`, `SEAMS_ENV_ID`);
- public Router A/B keyset, topology, HPKE keys, Gateway origin, relayer
  identity, NEAR configuration, session issuer/audience, allowed origins,
  cookie name, and Google OIDC client ID.

Use names such as `seams-console-staging` and `seams-signer-staging` for
staging. Production uses `seams-console` and `seams-signer` with different D1
IDs. The renderer rejects equal console/signer IDs within an environment.

## Cloudflare Pages

Create two Pages projects:

- app/site project: stored in `CF_PAGES_PROJECT_VITE`
- wallet-origin project: stored in `CF_PAGES_PROJECT_WALLET`

The `deploy-pages` workflow builds once and can deploy app, wallet, or both.
It deploys branch alias `dev` for staging and `main` for production.

The workflow copies SDK runtime assets into the Pages output:

- `packages/sdk-web/dist/esm/sdk/*` -> `apps/seams-site/dist/sdk/*`
- `packages/sdk-web/dist/workers/*` -> `apps/seams-site/dist/sdk/workers/*`

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

Create a separate R2 bucket or locked prefix for D1 backup exports. Store weekly
exports for both `CONSOLE_DB` and `SIGNER_DB`, retain the Cloudflare D1 Time
Travel window for short rollback, and run the local restore drill after changing
D1 schemas:

```bash
pnpm --dir packages/console-server-ts run d1:local:restore:drill
```

## Router A/B Workers

Router A/B Worker configuration lives in:

- `crates/router-ab-cloudflare/wrangler.router.toml`
- `crates/router-ab-cloudflare/wrangler.deriver-a.toml`
- `crates/router-ab-cloudflare/wrangler.deriver-b.toml`
- `crates/router-ab-cloudflare/wrangler.signing-worker.toml`

Wrangler environments:

| Target    | MPCRouter                  | Deriver A                    | Deriver B                    | SigningWorker                      |
| --------- | -------------------------- | ---------------------------- | ---------------------------- | ---------------------------------- |
| `staging` | `router-ab-mpc-router-staging` | `router-ab-deriver-a-staging` | `router-ab-deriver-b-staging` | `router-ab-signing-worker-staging` |
| `production` | `router-ab-mpc-router` | `router-ab-deriver-a` | `router-ab-deriver-b` | `router-ab-signing-worker` |

The checked-in Wrangler vars contain placeholder public keys so dry-run builds
work without environment configuration. The `deploy-router-ab` workflow injects
the real public keys and MPCRouter JWT values from GitHub Environment variables
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
| Deriver A     | `crates/router-ab-cloudflare/wrangler.deriver-a.toml`       | `ROUTER_AB_DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY`, `ROUTER_AB_DERIVER_A_PEER_VERIFYING_KEY_HEX`, `ROUTER_AB_DERIVER_B_PEER_VERIFYING_KEY_HEX` | `DERIVER_A_ROOT_SHARE_WIRE_SECRET`, `DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY`, `DERIVER_A_PEER_SIGNING_KEY` |
| Deriver B     | `crates/router-ab-cloudflare/wrangler.deriver-b.toml`       | `ROUTER_AB_DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY`, `ROUTER_AB_DERIVER_A_PEER_VERIFYING_KEY_HEX`, `ROUTER_AB_DERIVER_B_PEER_VERIFYING_KEY_HEX` | `DERIVER_B_ROOT_SHARE_WIRE_SECRET`, `DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY`, `DERIVER_B_PEER_SIGNING_KEY` |
| SigningWorker | `crates/router-ab-cloudflare/wrangler.signing-worker.toml` | `ROUTER_AB_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY`                                                                                | `SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY`                                                      |

`CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` are required for every
`upload-version` and `deploy` operation. Deriver root-share secrets use the
`mpc-prf-root-share-wire-v1:` prefix. Deriver envelope private keys use
`hpke-x25519-private-v1:`. The SigningWorker server-output private key uses
`hpke-x25519-server-output-private-v1:`.

### Router A/B backup, recovery, and incident procedure

Cloudflare Worker secrets are runtime copies. They are not backups. Keep each
Deriver's root-share wire secret, envelope private key, and peer-signing key in
its role-owned secret manager. A custodial principal for A must not be able to
read B's escrow, and the reverse must also hold. Store public-key fingerprints,
secret versions, and rotation epochs in the release record; never store private
values in repository evidence.

The A and B root-share Durable Objects persist startup metadata. The root-share
wire values remain in the matching Worker secret. After restoring a role's
secrets, startup revalidates or idempotently reconstructs its metadata. The Yao
session Durable Objects hold one-ceremony execution and redelivery state. Do
not restore an expired, failed, or interrupted Yao session from backup; let it
reach a terminal state and start a fresh admitted ceremony. This avoids
resurrecting replay or one-use state.

All Router A/B Durable Object namespaces use SQLite storage. Cloudflare retains
[30 days of point-in-time recovery history](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/#pitr-point-in-time-recovery-api)
for SQLite-backed Durable Objects. PITR is an emergency tool for durable
metadata corruption, not a routine Yao session retry mechanism. The production
Workers expose no administrative recovery endpoint. If PITR is required,
disable Router admission and deploy a reviewed, role-specific recovery build
that records the pre-restore bookmark, restores only the affected root-metadata
object, and aborts that object so recovery takes effect. Verify the role's
public key, epoch, and startup metadata, then redeploy the canonical role
artifact before admission is re-enabled. Never add PITR to a public route.

For a suspected role compromise:

1. Disable new Router admission and allow no new A/B ceremonies.
2. Revoke the affected role's deploy token and protected-environment access.
3. Rotate that role's root-share custody value, envelope key, peer key, and
   epochs. Update the opposite role's verifying key and Router public keyset in
   the same reviewed release.
4. Invalidate in-flight ceremonies. Do not copy state or secrets into the
   opposite role.
5. Deploy the affected role from a reviewed version, verify its binding and
   secret-name inventory, then run registration, recovery, export, and
   post-refresh signing before reopening admission.

For a code regression, roll back each role independently to the last reviewed
Worker version. Preserve key epochs and Durable Object state unless the
incident specifically requires rotation or recovery. Logs and alerts remain
role-specific and must contain deployment identities and opaque ceremony
identifiers without private inputs, labels, shares, ciphertext bodies, or
secret values.

Generate deployment identity keys with:

```bash
pnpm router:deploy:keygen -- --env staging
pnpm router:deploy:keygen -- --env staging --apply
```

The command generates Deriver A/B envelope HPKE keys, Deriver A/B peer-message
signing keys, and the SigningWorker server-output HPKE key. It does not
generate `DERIVER_A_ROOT_SHARE_WIRE_SECRET` or
`DERIVER_B_ROOT_SHARE_WIRE_SECRET`; those values come from the
derivation/provisioning ceremony. By default the command redacts private values
in stdout; use `--show-secrets` only for manual secret entry.

Generate matched Router A/B root-share wire secrets with:

```bash
pnpm router:deploy:root-share-keygen
pnpm router:deploy:root-share-keygen -- --json
```

The command prints the fixed 2-of-2 share pair using Deriver A share id `1` and
Deriver B share id `2`. Store the A value only in the Account-1 / Deriver-A
environment and the B value only in the Account-2 / Deriver-B environment.

The Router serves public deployment keys at:

- `/.well-known/router-ab/keyset`
- `/router-ab/keyset`

Self-hosted Gateway deployments may serve the same public keyset routes when
`routerAbPublicKeyset` is provided to the Gateway router. The browser SDK
prefetches `/router-ab/keyset` during registration precompute whenever
Router A/B normal signing is enabled.

Manual validation and deployment:

```bash
gh workflow run deploy-router-ab.yml --ref dev -f target=staging -f operation=validate -f role=all
gh workflow run deploy-router-ab.yml --ref dev -f target=staging -f operation=upload-version -f role=all
gh workflow run deploy-router-ab.yml --ref dev -f target=staging -f operation=deploy -f role=all
```

Production manual dispatch uses `--ref main -f target=production`. Normal
production releases start automatically after `ci` succeeds on `main`.

Local Cloudflare-shape checks:

```bash
pnpm router:deploy:dry-run
pnpm router:deploy:upload -- --env staging
```

Latest local dry-run evidence:

- ignored timestamped JSON under
  `crates/router-ab-cloudflare/reports/startup-latencies/`
- mode: `dry_run`
- gzip upload sizes: Router `573.83 KiB`, Deriver A `598.97 KiB`, Deriver B
  `599.92 KiB`, SigningWorker `567.14 KiB`

`operation=deploy` runs `pnpm router:deploy:check` before any Worker deployment.
Keep that gate green on the target commit, then deploy all four Workers in the
workflow order: SigningWorker, Deriver A, Deriver B, Router.

## Cloudflare Data

Staging and production use one backend family at a time. The current staging
target is D1/DO/R2, with no mixed Postgres runtime.

| Domain                       | Cloudflare binding | Source of schema/state                                      |
| ---------------------------- | ------------------ | ----------------------------------------------------------- |
| console/control-plane        | `CONSOLE_DB`       | `packages/console-server-ts/migrations/d1-console`              |
| signer/runtime metadata      | `SIGNER_DB`        | `packages/sdk-server-ts/migrations/d1-signer`               |
| threshold/session/admission  | `THRESHOLD_STORE`  | `ThresholdStoreDurableObject` SQLite Durable Object storage |
| dashboard and recovery files | R2                 | backup/export jobs and SDK publish workflows                |

Local development uses Wrangler/Miniflare with the same binding names:

```bash
pnpm --dir packages/console-server-ts run d1:local:prepare
pnpm --dir packages/console-server-ts run d1:local:dev
```

The local config is
`packages/console-server-ts/wrangler.d1-local.toml`. It binds `seams-console` to
`CONSOLE_DB`, `seams-signer` to `SIGNER_DB`, and
`ThresholdStoreDurableObject` to `THRESHOLD_STORE`.

Create D1 databases per environment and bind the returned database IDs in the
Worker config used for that environment:

```bash
wrangler d1 create seams-console-staging
wrangler d1 create seams-signer-staging
cp packages/console-server-ts/wrangler.d1-staging-console.toml.example \
  packages/console-server-ts/wrangler.d1-staging-console.toml
cp packages/console-server-ts/wrangler.d1-staging-gateway.toml.example \
  packages/console-server-ts/wrangler.d1-staging-gateway.toml
pnpm --dir packages/console-server-ts run d1:staging:check
wrangler d1 migrations apply seams-console-staging --remote
wrangler d1 migrations apply seams-signer-staging --remote
```

The staging templates already point at the deployable Worker entrypoints:
`src/router/cloudflare/d1ConsoleStagingWorker.ts` for the dashboard Worker and
`src/router/cloudflare/d1RouterApiStagingWorker.ts` for Gateway.
Fill `wrangler.d1-staging-console.toml` and `wrangler.d1-staging-gateway.toml`
with remote D1 database IDs, Cloudflare Secrets Store ID, relayer public key, and
the required Wrangler secret declarations before running the preflight. The
console Worker config binds only `CONSOLE_DB`. The Gateway config binds
`CONSOLE_DB`, `SIGNER_DB`, `THRESHOLD_STORE`, hosted signer KEKs, Gateway
session env secrets, and relayer secrets. The check fails if either config points at the wrong staging Worker,
contains Postgres env tokens, stores signer KEKs, session secrets, or
sponsored-EVM executor config in plaintext vars, omits required profile
bindings, or leaves D1/Secrets Store placeholders in place.

Production uses separate database names and IDs from staging. Apply D1
migrations before deploying Workers that depend on new columns or tables.
Durable Object class migrations are part of the Worker `wrangler` config; deploy
those class migrations with the same versioned Worker upload that introduces the
new Durable Object storage shape.

After the static staging check passes, generate the deployment log and command
runbook:

```bash
pnpm --dir packages/console-server-ts run d1:staging:runbook -- \
  --output ../../docs/deployment/refactor-82-staging-log.md \
  --r2-bucket <staging-r2-backup-bucket> \
  --console-origin <console-staging-origin> \
  --gateway-origin <gateway-staging-origin>
```

Use that generated log for the live Phase 6 evidence: migration versions, D1 Time
Travel bookmark JSON files, fixture import records, Worker deploy versions,
dashboard reconciliation results, sponsored-gas billing results, signer route
health, fixture-backed custody checks, R2 backup object keys, and restore-drill
integrity checks.

Capture the staging resource inventory before remote changes:

```bash
pnpm --dir packages/console-server-ts run d1:staging:resources -- --mode dry-run
pnpm --dir packages/console-server-ts run d1:staging:resources -- --mode remote
```

The inventory script records config-derived Worker names, D1 database IDs,
Durable Object bindings, Secrets Store metadata, required secret names, and remote
D1/Worker JSON metadata under
`packages/console-server-ts/.wrangler/d1-staging-resource-inventory`.

Apply staging D1 migrations through the checked migration script:

```bash
pnpm --dir packages/console-server-ts run d1:staging:migrate -- --mode dry-run
pnpm --dir packages/console-server-ts run d1:staging:migrate -- --mode remote
```

The migration script validates the console and Gateway staging configs, records
local migration file hashes, runs remote `wrangler d1 migrations list`, applies
remote migrations with `CI=true`, lists again after apply, and writes a manifest
under `packages/console-server-ts/.wrangler/d1-staging-migrations`.

Capture D1 Time Travel bookmarks through the checked script:

```bash
pnpm --dir packages/console-server-ts run d1:staging:bookmark -- \
  --mode remote \
  --purpose before_fixture_import
pnpm --dir packages/console-server-ts run d1:staging:bookmark -- \
  --mode remote \
  --purpose before_route_switch
```

The bookmark script validates the same console and Gateway staging configs as the
readiness gate, captures console and signer bookmark JSON via `wrangler d1
time-travel info`, and writes manifests under
`packages/console-server-ts/.wrangler/d1-staging-bookmarks`.

Check hosted signer KEK metadata through Wrangler Secrets Store before deploying
Gateway:

```bash
pnpm --dir packages/console-server-ts run d1:staging:kek-check -- --mode dry-run
pnpm --dir packages/console-server-ts run d1:staging:kek-check -- --mode remote
```

The check reads the Gateway staging Wrangler config, derives the expected
Cloudflare Secrets Store secret names and binding names, lists remote Secrets
Store metadata, and writes a manifest under
`packages/console-server-ts/.wrangler/d1-staging-kek-checks`. Do not use `wrangler
secrets-store secret get` for this check; the deployment log needs metadata
presence only.

Import fixture SQL through the checked script:

```bash
pnpm --dir packages/console-server-ts run d1:staging:import-fixtures -- \
  --mode dry-run \
  --console-fixture ./staging/fixtures/console.sql \
  --signer-fixture ./staging/fixtures/signer.sql
pnpm --dir packages/console-server-ts run d1:staging:import-fixtures -- \
  --mode remote \
  --console-fixture ./staging/fixtures/console.sql \
  --signer-fixture ./staging/fixtures/signer.sql
```

The import script uses the same console and Gateway readiness checks as the runbook,
rejects schema-changing SQL, rejects console fixtures touching signer tables and
signer fixtures touching console tables, and writes a manifest with fixture hashes
under `packages/console-server-ts/.wrangler/d1-staging-fixture-imports`.

After both Workers deploy, capture readiness evidence with:

```bash
pnpm --dir packages/console-server-ts run d1:staging:smoke -- \
  --mode remote \
  --console-origin <console-staging-origin> \
  --gateway-origin <gateway-staging-origin>
```

The smoke script checks `/console/readyz` on the console Worker, `/readyz` plus
`/healthz` on Gateway, and the configured signer custody health routes
`/router-ab/ed25519/healthz` and `/router-ab/ecdsa-derivation/healthz`. It records
response bodies, statuses, and timestamps under
`packages/console-server-ts/.wrangler/d1-staging-smoke`.

Run read-only D1 reconciliation after staging smoke passes:

```bash
pnpm --dir packages/console-server-ts run d1:staging:reconcile -- --mode dry-run
pnpm --dir packages/console-server-ts run d1:staging:reconcile -- --mode remote
```

The reconciliation script uses remote D1 `SELECT` checks only. It validates
dashboard billing balances, prepaid reservation summary totals,
sponsored-EVM billing links, sponsored settlement amounts, and signer sealed-share
KEK/lifecycle integrity, then writes evidence under
`packages/console-server-ts/.wrangler/d1-staging-reconciliation`.

Run the fixture-backed signer custody route drill after fixture import and
reconciliation:

```bash
export SEAMS_STAGING_ECDSA_WALLET_SESSION_JWT="<fixture-wallet-session-jwt>"
pnpm --dir packages/console-server-ts run d1:staging:signer-custody -- \
  --mode dry-run \
  --gateway-origin <gateway-staging-origin> \
  --export-share-fixture ./staging/fixtures/ecdsa-export-share.json
pnpm --dir packages/console-server-ts run d1:staging:signer-custody -- \
  --mode remote \
  --gateway-origin <gateway-staging-origin> \
  --export-share-fixture ./staging/fixtures/ecdsa-export-share.json
```

The signer custody script calls the configured threshold route health endpoints
and the production `/router-ab/ecdsa-derivation/export/share` route with the fixture
request. It writes redacted evidence under
`packages/console-server-ts/.wrangler/d1-staging-signer-custody` and never records
the wallet-session JWT or server export share. For the optional missing-KEK
variant, rerun with `--missing-kek-fixture`,
`--missing-kek-wallet-session-jwt-env`, `--missing-kek-expected-status`, and
`--missing-kek-expected-code`.

Run the D1-to-R2 restore drill through the checked script:

```bash
pnpm --dir packages/console-server-ts run d1:staging:r2-restore-drill -- \
  --mode dry-run \
  --r2-bucket <staging-r2-backup-bucket>
pnpm --dir packages/console-server-ts run d1:staging:r2-restore-drill -- \
  --mode remote \
  --r2-bucket <staging-r2-backup-bucket>
```

The drill exports both staging D1 databases, stores the SQL exports in R2 under a
timestamped `refactor-82/` prefix, downloads the objects into a restore workspace,
creates timestamped restore-drill D1 databases, imports the downloaded SQL, runs
`PRAGMA integrity_check`, and records command/artifact evidence under
`packages/console-server-ts/.wrangler/d1-staging-r2-restore-drills`.

After every remote Phase 6 command has produced a manifest, run the final
evidence verifier:

```bash
pnpm --dir packages/console-server-ts run d1:staging:evidence -- \
  --resources <resource-inventory-remote-manifest.json> \
  --kek-check <kek-check-remote-manifest.json> \
  --migrations <migrations-remote-manifest.json> \
  --bookmark-before-fixture-import <before-fixture-import-bookmark-manifest.json> \
  --fixture-import <fixture-import-remote-manifest.json> \
  --bookmark-before-route-switch <before-route-switch-bookmark-manifest.json> \
  --smoke <smoke-remote-manifest.json> \
  --reconciliation <reconciliation-remote-manifest.json> \
  --signer-custody <signer-custody-remote-manifest.json> \
  --r2-restore-drill <r2-restore-drill-remote-manifest.json>
```

The verifier rejects missing manifests, dry-run manifests, failed commands,
reconciliation mismatch rows, missing signer custody export-share evidence, and
incomplete restore artifacts. Store the verification JSON path in the live Phase
6 deployment log before production planning.

Keep the Postgres escape hatch out of staging until the full Postgres adapter
family exists and passes the same signer, console, billing, recovery, and
threshold contract tests. At that point the migration is all-or-nothing:
`CONSOLE_DB`, `SIGNER_DB`, and `THRESHOLD_STORE` state are migrated together to
Postgres-backed stores.

## Redis And Upstash

D1/DO is the preferred durable local and hosted path. Redis/Upstash can still be
used for rate limits or hot-path idempotency where configured:

- `REDIS_URL` for Node TCP Redis
- `UPSTASH_REDIS_REST_URL`
- `UPSTASH_REDIS_REST_TOKEN`

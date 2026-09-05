# Deployment Infra

This repo deploys these hosted surfaces:

- SDK runtime bundles served by Cloudflare Pages.
- App and wallet Pages projects from `apps/seams-site`.
- Router A/B Workers from `crates/router-ab-cloudflare`.
- Gateway Workers from `packages/console-server-ts`.

The web server persists state in Cloudflare data services:

- `CONSOLE_DB` D1 for console/control-plane state.
- `SIGNER_DB` D1 for wallet, signer metadata, identity, WebAuthn, Email OTP,
  and recovery state.
- `THRESHOLD_STORE` Durable Object storage for threshold/session coordination
  and normal-signing admission state.
- R2 for scheduled D1 backup exports.

## GitHub Environments

Use the existing release and lane GitHub Environments for frontend builds,
read-only smoke checks, and backend roles:

- `staging` and the five `staging-*` backend role environments.
- `production` and the five `production-*` backend role environments for the
  production-mainnet lane.
- five `production-testnet-*` backend role environments for the production-
  testnet lane.

The frontend environments own Pages credentials, public build variables, and
the public origins used by the read-only deployment smoke checks. Values differ
per environment.

Use `staging-gateway`, `production-testnet-gateway`, and
`production-gateway` for Gateway. Use the corresponding Router, Deriver A,
Deriver B, and SigningWorker role environments for each lane. Each role
environment owns its Cloudflare credentials, private material, and variables.
Production is manual and restricted to `main` by the existing `production`
environment branch policy and the workflow guards. Staging is the currently
provisioned backend lane; both production lane role sets remain pending until
fresh resources and identities are generated.

Gateway and the four Router A/B Workers use Cloudflare service bindings and
must be deployed in the same Cloudflare account. Give each role a scoped deploy
token while keeping `CLOUDFLARE_ACCOUNT_ID` identical across those five GitHub
Environments.

Prepare one complete release-level generation at a time:

```bash
pnpm wallet-core:deploy:env-prepare -- --lane staging-testnet --repo seams-tech/seams-sdk
pnpm wallet-core:deploy:env-prepare -- --lane production-mainnet --repo seams-tech/seams-sdk
```

The command validates all six GitHub Environments for the selected release. It
generates the Router A/B identities, matched root shares, shared internal
service credential, Gateway random secrets, ceremony JWT key, and
signing-session seal values. It writes separate protected `wallet-core` and
`product` manifests with matching generation metadata. Supply provisioned
Cloudflare, domain, funded-account, OAuth, and tenant values through the
protected values file documented in
[tooling.md](tooling.md#github-environment-bootstrap). The output
contains private material and must not be committed.

To create the six environments for a currently supported release, apply
wallet-core and product separately from the paired manifests printed by
preparation:

```bash
gh auth login
pnpm deploy:env-rotate -- staging-testnet
pnpm deploy:env-rotate -- production-mainnet
```

Prepare mode resolves external values from the protected file and current shell,
discovers existing Cloudflare account, D1, Pages, and R2 metadata when possible,
and refuses to write a partial required configuration. Component apply creates
missing environments and preserves existing environments and protection rules.
Product apply verifies the wallet-core generation first. Every preparation
generates fresh cryptographic identities, so use the guarded rotation wrapper
for an initialized release.

These environment commands are lane-aware. `staging-testnet` uses the staging
role set, while `production-testnet` and `production-mainnet` use their exact
role prefixes and resource names. Production-testnet and production-mainnet
remain behind their provisioning gates until fresh resources and identities are
recorded in `deployment/targets.json`; never reuse production-mainnet private
material for production-testnet.

Progress and per-environment upload counts are written to stderr. The guarded
wrapper stores a complete restricted backup plus separate component manifests
under `$HOME/.seams/backups`.

```bash
pnpm deploy:env-verify -- --lane staging-testnet --repo seams-tech/seams-sdk
```

The backup contains private keys and secrets. Move it to the approved secrets
vault, then remove the local copy.

The current checkout determines the GitHub repository. To target another
repository explicitly, pass its real name, for example
`--repo seams-tech/seams-sdk`. Do not copy placeholder text such as
`owner/repo`.

For a manual split apply, use the component commands:

```bash
pnpm wallet-core:deploy:env-apply -- \
  --lane staging-testnet --manifest-file <wallet-core-manifest> --rotate
pnpm product:deploy:env-apply -- \
  --site staging --manifest-file <product-manifest>
```

Deployment entrypoints are the five hand-written workflows documented in
[README.md](README.md): one staging backend workflow, separate production
testnet and mainnet backend workflows, and staging and production frontend
workflows. Their branch restrictions and
GitHub environment bindings are fixed in each entrypoint. They use the
workflow event's `${{ github.sha }}` and expose no historical-SHA or
cross-run artifact inputs.

### Secrets

| Secret                                          | Used by                  | Notes                                                                                                     |
| ----------------------------------------------- | ------------------------ | --------------------------------------------------------------------------------------------------------- |
| `CLOUDFLARE_API_TOKEN`                          | Pages, Router A/B deploy | Frontend environments use Pages-only tokens; backend role environments use Worker-scoped tokens.          |
| `CLOUDFLARE_ACCOUNT_ID`                         | Pages, Router A/B deploy | Cloudflare account id, scoped to the matching authority environment.                                      |
| `CF_PAGES_PROJECT_VITE`                         | Pages deploy             | Cloudflare Pages project for the app/site surface.                                                        |
| `CF_PAGES_PROJECT_DOCS`                         | Pages deploy             | Cloudflare Pages project for the VitePress documentation surface.                                         |
| `CF_PAGES_PROJECT_WALLET`                       | Pages deploy             | Staging wallet Pages project.                                                                             |
| `CF_PAGES_PROJECT_WALLET_TESTNET`               | Pages deploy             | Production testnet wallet Pages project; pending production-testnet provisioning.                         |
| `CF_PAGES_PROJECT_WALLET_MAINNET`               | Pages deploy             | Production mainnet wallet Pages project; pending production-mainnet provisioning.                         |
| `DERIVER_A_ROOT_SHARE_WIRE_SECRET`              | Router A/B deploy        | Deriver A root-share wire secret. Written to the Deriver A Worker environment.                            |
| `DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY`           | Router A/B deploy        | Deriver A signer-envelope HPKE private key.                                                               |
| `DERIVER_A_PEER_SIGNING_KEY`                    | Router A/B deploy        | Deriver A private key for A/B peer messages.                                                              |
| `DERIVER_B_ROOT_SHARE_WIRE_SECRET`              | Router A/B deploy        | Deriver B root-share wire secret. Written to the Deriver B Worker environment.                            |
| `DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY`           | Router A/B deploy        | Deriver B signer-envelope HPKE private key.                                                               |
| `DERIVER_B_PEER_SIGNING_KEY`                    | Router A/B deploy        | Deriver B private key for A/B peer messages.                                                              |
| `SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY` | Router A/B deploy        | SigningWorker server-output HPKE private key.                                                             |
| `RELAY_SESSION_HMAC_SECRET`                     | Gateway deploy           | Environment-specific browser session signing secret.                                                      |
| `ACCOUNT_ID_DERIVATION_SECRET`                  | Gateway deploy           | Environment-specific account identifier derivation secret.                                                |
| `ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET`        | Router A/B and Gateway   | Shared only by Workers inside one environment. Never share it across staging and production.              |
| `LINKED_DEVICE_TARGET_DESCRIPTOR_HMAC_SECRET`   | Gateway deploy           | Dedicated private HMAC secret for authenticated linked-device target descriptors; minimum 32 UTF-8 bytes. |
| `ROUTER_AB_CEREMONY_JWT_PRIVATE_JWK`            | Gateway deploy           | Private ceremony JWT signing key for this environment.                                                    |
| `RELAYER_PRIVATE_KEY`                           | Gateway deploy           | Optional funded NEAR relayer key; its public key is derived during startup.                               |
| `SPONSORED_EVM_EXECUTORS_JSON`                  | Gateway deploy           | Optional environment-specific sponsored EVM executor secrets.                                             |
| `STRIPE_API_SK`                                 | Gateway deploy           | Required Stripe secret or restricted key for hosted Checkout sessions.                                    |
| `STRIPE_WEBHOOK_SECRET`                         | Gateway deploy           | Required Stripe endpoint signing secret for webhook verification.                                         |
| `RESEND_API_KEY`                                | Gateway deploy           | Required Resend API key for console transactional email.                                                  |
| `CONSOLE_EMAIL_INVITATION_SECRET_KEY_B64U`      | Console deploy           | Generated 32-byte base64url key for invitation-secret encryption.                                         |
| `CONSOLE_WEBHOOK_SECRET_KEY_B64U`               | Console deploy           | Generated 32-byte base64url key sealing webhook signing secrets at rest. Without it every `/console/webhooks` route answers 501. |

### Variables

| Variable                                                 | Used by             | Notes                                                                                   |
| -------------------------------------------------------- | ------------------- | --------------------------------------------------------------------------------------- |
| `ROUTER_AB_JWT_ISSUER`                                   | Router A/B deploy   | JWT issuer accepted by the Router admission boundary.                                   |
| `ROUTER_AB_JWT_AUDIENCE`                                 | Router A/B deploy   | JWT audience accepted by the Router; defaults operationally to `router-ab`.             |
| `ROUTER_AB_JWT_JWKS_JSON`                                | Router A/B deploy   | Public JWKS injected into Router JWT verification.                                      |
| `SPONSORED_EXECUTION_REAL_PRICING_JSON`                  | Gateway deploy      | On-chain Outlayer NEAR/USD pricing rules for sponsored execution.                       |
| `CONSOLE_BASE_URL`                                       | Console, Gateway    | Public console URL used in transactional email links.                                   |
| `CONSOLE_EMAIL_FROM`                                     | Gateway deploy      | Resend sender using a verified domain.                                                  |
| `ROUTER_AB_DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY`           | Router A/B deploy   | Public key matching `DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY`.                              |
| `ROUTER_AB_DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY`           | Router A/B deploy   | Public key matching `DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY`.                              |
| `ROUTER_AB_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY` | Router A/B deploy   | Public key matching `SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY`.                    |
| `ROUTER_AB_DERIVER_A_PEER_VERIFYING_KEY_HEX`             | Router A/B deploy   | Public verifying key matching `DERIVER_A_PEER_SIGNING_KEY`.                             |
| `ROUTER_AB_DERIVER_B_PEER_VERIFYING_KEY_HEX`             | Router A/B deploy   | Public verifying key matching `DERIVER_B_PEER_SIGNING_KEY`.                             |
| `VITE_RELAYER_URL`                                       | Pages build         | Public Gateway base URL; historical env var name.                                       |
| `VITE_CONSOLE_BASE_URL`                                  | Pages build         | Optional console API base URL; defaults in app code when unset.                         |
| `VITE_RELAYER_ACCOUNT_ID`                                | Staging Pages build | Parent NEAR account used for testnet account creation.                                  |
| `VITE_SEAMS_PROJECT_ENVIRONMENT_ID`                      | Pages build         | Administrator-created project-environment id for managed registration.                  |
| `VITE_SEAMS_PUBLISHABLE_KEY`                             | Pages build         | Administrator-created browser-safe publishable key.                                     |
| `VITE_WALLET_ORIGIN`                                     | Pages build         | Wallet origin. Must match CORS and WebAuthn RP configuration.                           |
| `VITE_WALLET_SERVICE_PATH`                               | Pages build         | Wallet service path; defaults to `/wallet-service` when unset.                          |
| `VITE_SDK_BASE_PATH`                                     | Pages build         | SDK asset path; defaults to `/sdk` when unset.                                          |
| `VITE_RP_ID_BASE`                                        | Pages build         | WebAuthn RP id base.                                                                    |
| `VITE_NEAR_NETWORK`                                      | Staging Pages build | `testnet`; production uses `VITE_TESTNET_NEAR_NETWORK` and `VITE_MAINNET_NEAR_NETWORK`. |
| `VITE_NEAR_RPC_URL`                                      | Staging Pages build | Testnet NEAR RPC URL; production uses exact lane prefixes.                              |
| `VITE_NEAR_EXPLORER`                                     | Staging Pages build | Testnet explorer base URL; production uses exact lane prefixes.                         |
| `VITE_TEMPO_RPC_URL`                                     | Pages build         | Optional Tempo RPC URL.                                                                 |
| `VITE_TEMPO_EXPLORER`                                    | Pages build         | Optional Tempo explorer URL.                                                            |
| `VITE_TEMPO_FEE_TOKEN`                                   | Pages build         | Optional Tempo fee token address.                                                       |
| `VITE_ARC_RPC_URL`                                       | Pages build         | Optional Arc RPC URL.                                                                   |
| `VITE_ARC_EXPLORER`                                      | Pages build         | Optional Arc explorer URL.                                                              |
| `VITE_SIGNING_SESSION_PERSISTENCE_MODE`                  | Pages build         | Set when enabling sealed-refresh client flows.                                          |
| `VITE_ROUTER_AB_NORMAL_SIGNING_WORKER_ID`                | Pages build         | Exact SigningWorker id bound into Router A/B warm signing sessions.                     |
| `VITE_DASHBOARD_WALLETS_ROUTES_ENABLED`                  | Pages build         | Optional dashboard route gate.                                                          |

Production Pages variables use exact network namespaces. Each lane requires
`VITE_TESTNET_SEAMS_PROJECT_ENVIRONMENT_ID`,
`VITE_TESTNET_SEAMS_PUBLISHABLE_KEY`, `VITE_TESTNET_NEAR_NETWORK`,
`VITE_TESTNET_NEAR_RPC_URL`, `VITE_TESTNET_NEAR_EXPLORER`,
`VITE_TESTNET_SIGNING_SESSION_PERSISTENCE_MODE`, and
`VITE_TESTNET_ROUTER_AB_NORMAL_SIGNING_WORKER_ID` for testnet; the mainnet
lane uses the same suffixes under `VITE_MAINNET_`. Optional lane-specific
values keep the same prefix, including `TEMPO_*`, `ARC_*`,
`WALLET_SERVICE_PATH`, and `SDK_BASE_PATH`. Staging keeps the unprefixed
`VITE_*` names listed above.

`deployment/targets.json` owns the non-secret Gateway configuration: D1
resource IDs, runtime tenant identity, origins, Router A/B public
identity, session settings, and optional integration configuration. The
deployment target parser validates this document once and the renderer emits
the individual Worker bindings expected by the runtime. Tenant identifiers are
configuration only; deployment creates no tenant rows.

The browser discovers the public signing-session seal protocol from the
Gateway capability response. Shamir key rotation does not require Pages build
variables or a frontend rebuild.

Refactor 93 uses partitioned D1 and the MPC Router immediately. Gateway
configuration has no Yao family cutoff or drain variables. Remove any retired
`ROUTER_AB_YAO_GATEWAY_*_ADMISSION_CUTOFF_MS` or
`ROUTER_AB_YAO_GATEWAY_*_DRAIN_UNTIL_MS` values from the staging and production
GitHub Environments; the deployment does not read them.

Gateway private cryptographic values and external credentials remain GitHub
secrets. Public keys and deployment metadata are reviewed with normal code
changes in `deployment/targets.json`.

Staging uses `seams-console-staging-nrt` and `seams-signer-staging-nrt`.
Production testnet uses `seams-console-testnet` and `seams-signer-testnet`;
production mainnet uses `seams-console` and `seams-signer`. Each lane has
different D1 IDs, and the renderer rejects equal console/signer IDs within an
environment.

## Cloudflare Pages

Apply mode creates the Pages projects for the selected release when they are
absent:

- app/site project: stored in `CF_PAGES_PROJECT_VITE`
- VitePress docs project: stored in `CF_PAGES_PROJECT_DOCS`
- staging wallet-origin project: stored in `CF_PAGES_PROJECT_WALLET`
- production testnet wallet-origin project: stored in
  `CF_PAGES_PROJECT_WALLET_TESTNET`
- production mainnet wallet-origin project: stored in
  `CF_PAGES_PROJECT_WALLET_MAINNET`

The matching frontend workflow builds the app and VitePress docs, then deploys
the app, docs, and every declared wallet Pages project. The docs deploy binds
`staging.docs.seams.sh` for staging and `docs.seams.sh` for production. It
deploys branch alias `dev` for staging and `main` for production. Production frontend deployment remains gated while
either backend lane is pending. The stack workflow has no Pages mutation jobs or
Pages credentials.

The workflow copies SDK runtime assets into the Pages output:

- `packages/wallet/dist/esm/sdk/*` -> `apps/seams-site/dist/sdk/*`
- `packages/wallet/dist/workers/*` -> `apps/seams-site/dist/sdk/workers/*`

That means Pages serves the same runtime assets at `/sdk/*` that were built
for the commit being deployed.

## Cloudflare R2 Backups

R2 is reserved for D1 backup and export storage. Create a separate R2 bucket or
locked prefix for D1 backup exports. Store weekly
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

| Target               | MPCRouter                      | Deriver A                     | Deriver B                     | SigningWorker                      |
| -------------------- | ------------------------------ | ----------------------------- | ----------------------------- | ---------------------------------- |
| `staging-testnet`    | `router-ab-mpc-router-staging` | `router-ab-deriver-a-staging` | `router-ab-deriver-b-staging` | `router-ab-signing-worker-staging` |
| `production-testnet` | `router-ab-mpc-router-testnet` | `router-ab-deriver-a-testnet` | `router-ab-deriver-b-testnet` | `router-ab-signing-worker-testnet` |
| `production-mainnet` | `router-ab-mpc-router`         | `router-ab-deriver-a`         | `router-ab-deriver-b`         | `router-ab-signing-worker`         |

The checked-in Wrangler vars contain placeholder public keys so dry-run builds
work without environment configuration. The environment-specific Router A/B
jobs inside the matching backend workflow inject the real public keys and
MPCRouter JWT values from GitHub Environment variables during deployment, then
write the private values to the corresponding Cloudflare Worker secrets before
uploading or deploying Workers.

Use these templates to fill each GitHub Environment:

- [`router-ab-cloudflare-env.example.yml`](router-ab-cloudflare-env.example.yml):
  reviewable environment contract for Router, Deriver A, Deriver B, and
  SigningWorker.
- [`../../crates/router-ab-cloudflare/env/github-environment.example.env`](../../crates/router-ab-cloudflare/env/github-environment.example.env):
  copy/paste variable and secret names for GitHub Environment setup.

Role-specific configuration:

| Role          | Wrangler config                                            | GitHub Environment vars                                                                                                                                | GitHub Environment secrets                                                                              |
| ------------- | ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------- |
| Router        | `crates/router-ab-cloudflare/wrangler.router.toml`         | `ROUTER_AB_JWT_ISSUER`, `ROUTER_AB_JWT_AUDIENCE`, `ROUTER_AB_JWT_JWKS_JSON`, `ROUTER_AB_PROJECT_POLICY_BOOTSTRAP_JSON`, all Router A/B public key vars | `ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET`                                                                |
| Deriver A     | `crates/router-ab-cloudflare/wrangler.deriver-a.toml`      | `ROUTER_AB_DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY`, `ROUTER_AB_DERIVER_A_PEER_VERIFYING_KEY_HEX`, `ROUTER_AB_DERIVER_B_PEER_VERIFYING_KEY_HEX`             | `DERIVER_A_ROOT_SHARE_WIRE_SECRET`, `DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY`, `DERIVER_A_PEER_SIGNING_KEY` |
| Deriver B     | `crates/router-ab-cloudflare/wrangler.deriver-b.toml`      | `ROUTER_AB_DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY`, `ROUTER_AB_DERIVER_A_PEER_VERIFYING_KEY_HEX`, `ROUTER_AB_DERIVER_B_PEER_VERIFYING_KEY_HEX`             | `DERIVER_B_ROOT_SHARE_WIRE_SECRET`, `DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY`, `DERIVER_B_PEER_SIGNING_KEY` |
| SigningWorker | `crates/router-ab-cloudflare/wrangler.signing-worker.toml` | `ROUTER_AB_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY`                                                                                               | `SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY`                                                         |

`CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` are required for every
`wrangler deploy`, secret operation, and diagnostic `wrangler versions upload`.
The production deployment workflows use immediate `wrangler deploy`; the
diagnostic upload path does not serve traffic. Deriver root-share secrets use the
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

For a code regression, revert the bad change or land a corrective commit on the
target branch, then deploy that branch tip and verify its binding and
readiness. This restores the Worker code without reverting secrets, D1
migrations, Durable Object state, or other environment state. Preserve key
epochs and Durable Object state unless the incident specifically requires
rotation or recovery. Logs and alerts
remain role-specific and must contain deployment identities and opaque
ceremony identifiers without private inputs, labels, shares, ciphertext bodies,
or secret values.

Generate deployment identity keys with:

```bash
pnpm router:deploy:keygen -- --lane staging-testnet
```

The command generates deployment envelope, peer-signing, private-D1, online
wrapping, tenant-root creation, and control-plane issuer keys. Tenant secrets
are created by the server-owned R120 ceremony. Both Derivers and the Router
receive both envelope public keys; private keys remain role-local.

Use `wallet-core:deploy:env-prepare` and `wallet-core:deploy:env-apply` to generate
and apply per-Worker manifests. The low-level key generator never uploads keys.
Every prepare generates fresh identities; preserve existing manifests when
repairing missing environment values.

Production manifests require separate A/B Google KMS key-version references
(`ROUTER_AB_DERIVER_{A,B}_TENANT_ROOT_MANAGED_BACKUP_KEY_VERSION`) and service-account
credentials (`DERIVER_{A,B}_TENANT_ROOT_MANAGED_BACKUP_GOOGLE_CREDENTIALS_JSON`)
through the protected values file. KMS wrapping keys are provisioned externally.
Staging retains the operational HPKE backup provider. Private output is redacted
unless `--show-secrets` is supplied.

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

Manual deployment uses the matching workflow file and branch only:

```bash
gh workflow run deploy-staging-backend.yml --ref dev
gh workflow run deploy-production-testnet-backend.yml --ref main
gh workflow run deploy-production-mainnet-backend.yml --ref main
```

The frontend workflows use the same branch rules and accept `--site` identities
through their fixed workflow environment. They accept no source SHA,
artifact-run, or release-set inputs. Production backend dispatches remain
gated by pending provisioning guards.

Local non-serving Router shape checks:

```bash
pnpm router:deploy:dry-run
pnpm router:deploy:upload -- --env staging
```

The upload command is a diagnostic Cloudflare versions upload and does not
serve traffic or deploy a backend lane. The three backend deployment workflows
own serving Worker deployment and secret operations.

Latest local dry-run evidence:

- ignored timestamped JSON under
  `crates/router-ab-cloudflare/reports/startup-latencies/`
- mode: `dry_run`
- gzip upload sizes: Router `573.83 KiB`, Deriver A `598.97 KiB`, Deriver B
  `599.92 KiB`, SigningWorker `567.14 KiB`

The backend workflow performs a five-environment component preflight from
`deployment/targets.json`, then applies D1 migrations before the ordered Worker
deployments: SigningWorker, Deriver A, Deriver B, MPCRouter, and Gateway.
Backend smoke runs at the end of the Gateway job. The frontend workflow builds,
deploys, and smokes its Pages output in one independent job; neither lane waits
for a coordination receipt from the other.

## Cloudflare Data

Staging and production use one backend family at a time. The current staging
target is D1/DO/R2, with no mixed Postgres runtime.

| Domain                       | Cloudflare binding | Source of schema/state                                      |
| ---------------------------- | ------------------ | ----------------------------------------------------------- |
| console/control-plane        | `CONSOLE_DB`       | `packages/console-server-ts/migrations/d1-console`          |
| signer/runtime metadata      | `SIGNER_DB`        | `packages/wallet-server/migrations/d1-signer`               |
| threshold/session/admission  | `THRESHOLD_STORE`  | `ThresholdStoreDurableObject` SQLite Durable Object storage |
| dashboard and recovery files | R2                 | backup/export jobs                                          |

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
wrangler d1 create seams-console-staging-nrt
wrangler d1 create seams-signer-staging-nrt
cp packages/console-server-ts/wrangler.d1-staging-console.toml.example \
  packages/console-server-ts/wrangler.d1-staging-console.toml
cp packages/console-server-ts/wrangler.d1-staging-gateway.toml.example \
  packages/console-server-ts/wrangler.d1-staging-gateway.toml
pnpm --dir packages/console-server-ts run d1:staging:check
wrangler d1 migrations apply seams-console-staging-nrt --remote
wrangler d1 migrations apply seams-signer-staging-nrt --remote
```

The staging templates already point at the deployable Worker entrypoints:
`src/router/cloudflare/d1ConsoleStagingWorker.ts` for the dashboard Worker and
`src/router/cloudflare/d1RouterApiStagingWorker.ts` for Gateway.
Fill `wrangler.d1-staging-console.toml` and `wrangler.d1-staging-gateway.toml`
with remote D1 database IDs, relayer public key, and
the required Wrangler secret declarations before running the preflight. The
console Worker config binds only `CONSOLE_DB`. The Gateway config binds
`CONSOLE_DB`, `SIGNER_DB`, `THRESHOLD_STORE`, Gateway session env secrets, and
relayer secrets. The check fails if either config points at the wrong staging Worker,
contains Postgres env tokens, stores signer KEKs, session secrets, or
sponsored-EVM executor config in plaintext vars, omits required profile
bindings, or leaves D1 placeholders in place.

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
Durable Object bindings, required secret names, and remote D1/Worker JSON
metadata under
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

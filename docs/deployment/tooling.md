# Deployment Tooling

This guide covers the repository scripts used to generate deployment identity
material, populate GitHub Environments, validate Router A/B releases, and run
manual deployment evidence checks.

It covers deployment tooling under `crates/router-ab-cloudflare/scripts` and
the related root-level `pnpm` commands. It does not document every `.mjs` file
in the repository; benchmark, test, and local-development scripts have their
own package documentation.

## Prerequisites

Run these commands from the repository root:

```bash
pnpm install --frozen-lockfile
gh auth login
```

For Worker build and deployment checks, also install:

- Rust and the `wasm32-unknown-unknown` target.
- Wrangler authentication with a token that can deploy the target account.
- `wasm-pack` when running SDK production builds or the Pages job locally.

GitHub apply mode requires repository administration permission to create or
update deployment environments, Actions variables, and Actions secrets.

## GitHub Environment Bootstrap

Prepare one audited backend-lane generation before the first deployment or an
intentional identity rotation. Product Pages use the paired frontend site:

```bash
pnpm wallet-core:deploy:env-prepare -- --lane staging-testnet --repo seams-tech/seams-sdk
pnpm wallet-core:deploy:env-prepare -- --lane production-mainnet --repo seams-tech/seams-sdk
```

Each invocation validates the complete target and writes two owner-only
manifests under `~/.seams/backups`:

- `wallet-core`: Gateway, MPCRouter, Deriver A, Deriver B, and SigningWorker.
- `product`: the target's existing `staging` or `production` environment.
  These environments hold Pages variables, credentials, and public origins for
  read-only smoke checks.

Both files carry the same generation ID, timestamp, and complete-manifest
SHA-256. The product manifest contains the public wallet-core handoff values it
needs. It does not contain Deriver, SigningWorker, or Gateway private material.

The generator creates fresh Router A/B identities, matched root shares,
ceremony JWT signing material, internal service authentication, Gateway
secrets, and signing-session seal material. Prepare mode also provisions the
target's D1 databases and Pages projects when they do not exist.
Supply the administrator-created organization, project, environment, and
project-environment IDs plus the publishable key in the protected deployment
values file after completing onboarding.

The output contains private material. Do not commit it or paste it into chat or
issue trackers.

### Create environments and upload generated values

Create a protected values file for credentials and infrastructure that already
exist:

```bash
mkdir -p "$HOME/.seams"
install -m 600 \
  crates/router-ab-cloudflare/env/deployment-values.example.env \
  "$HOME/.seams/staging-deployment.env"
```

Set `CLOUDFLARE_API_TOKEN`. Add a funded NEAR account and private key only when
NEAR gas sponsorship is required. EVM sponsorship, Google OIDC, custom domains,
and R2 backup configuration are also optional. The generator resolves supplied values in
this order:

1. GitHub Environment-specific names such as
   `STAGING_GATEWAY__CLOUDFLARE_API_TOKEN`.
2. Target-specific names such as `STAGING__CLOUDFLARE_API_TOKEN`.
3. Shared names such as `CLOUDFLARE_API_TOKEN`.

The provisioned `staging` profile targets NEAR testnet and uses
`demo_code_response`, which returns the six-digit code to the exact configured
demo origin. Production testnet and mainnet are represented by pending lane
provisioning until fresh resources and identities are generated. The server
supports `provider_and_demo_code` when an embedding supplies a real email-
provider adapter. Use `GATEWAY_RUNTIME_PROFILE=mainnet_service` for a future
mainnet generation; that profile rejects demo-code delivery and requires
`email_provider` delivery.

The generated manifest contains the lane's public handoff and Gateway
deployment configuration. Review it against the matching lane's
`provisioning` branch in `deployment/targets.json` before deploying. Later
profile, origin, public key, or delivery-mode changes are ordinary reviewed
target-file changes and never rotate Router A/B identities.

Prepare the manifests, then upload each ownership group explicitly:

```bash
pnpm wallet-core:deploy:env-prepare -- \
  --lane staging-testnet \
  --repo seams-tech/seams-sdk

pnpm wallet-core:deploy:env-apply -- \
  --lane staging-testnet \
  --manifest-file "$HOME/.seams/backups/<wallet-core-manifest>.json" \
  --repo seams-tech/seams-sdk

pnpm product:deploy:env-apply -- \
  --site staging \
  --manifest-file "$HOME/.seams/backups/<product-manifest>.json" \
  --repo seams-tech/seams-sdk
```

The generator automatically loads
`$HOME/.seams/<target>-deployment.env`. Use `--values-file` only to
select a different protected file.

Prepare mode provisions or discovers shared Cloudflare resources and validates
the complete six-environment topology for one release: one frontend environment
plus the five wallet-core role environments. Component apply mode:

- Creates missing GitHub Environments.
- Preserves existing environments and their protection rules.
- Creates missing release-scoped D1 databases and Pages projects.
- Generates and uploads all repository-owned cryptographic secrets.
- Uploads externally owned values loaded from the protected file or shell.
- Discovers the Cloudflare account ID and existing Cloudflare resources through
  Wrangler.
- Emits the non-secret Gateway deployment document for review and placement in
  `deployment/targets.json`. The deployment renderer validates that checked-in
  document once and expands it into Worker bindings.
- Removes the obsolete scalar Gateway variables after the replacement config is
  uploaded. Unrelated variables and all secrets are preserved.
- Refuses a partial apply while required values remain unresolved.
- Writes a step progress bar and per-environment upload counts to stderr.
- Verifies the component manifest's own SHA-256 before uploading it.
- Requires wallet-core to be uploaded before product.
- Refuses product upload when the wallet-core generation metadata differs.
- Prints the exact uploaded variables and secrets to stdout for backup.

The generator accepts one backend `--lane` (`staging-testnet`,
`production-testnet`, or `production-mainnet`) for wallet-core work and one
frontend `--site` (`staging` or `production`) for product work. Pending
production lanes are rejected before credentials or GitHub are accessed.

`--allow-incomplete` permits an intentional partial setup. Avoid it for a
deployment checkpoint because rerunning the generator rotates repository-owned
identity material.

CLI options can override the most common public identity values:

```bash
pnpm wallet-core:deploy:env-prepare -- \
  --lane staging-testnet \
  --gateway-origin https://gateway.staging.example.com \
  --org-id org-id \
  --project-id project-id \
  --environment-id staging \
  --project-environment-id project-environment-id \
  --tenant-namespace staging
```

funded NEAR relayer keys, funded EVM executor keys,
and OAuth credentials are externally owned and cannot be generated safely by
this repository. Keep them in the same protected target file as the Cloudflare
deployment credentials.

### Apply external values without rotating identities

After the initial setup, preview operator-owned configuration changes:

```bash
pnpm wallet-core:deploy:env-update -- \
  --lane staging-testnet \
  --repo seams-tech/seams-sdk
```

Apply the displayed plan:

```bash
pnpm wallet-core:deploy:env-update -- \
  --lane staging-testnet \
  --repo seams-tech/seams-sdk \
  --apply
```

Limit an update to named values when changing one integration:

```bash
pnpm wallet-core:deploy:env-update -- \
  --lane staging-testnet \
  --repo seams-tech/seams-sdk \
  --only RELAYER_PRIVATE_KEY,SPONSORED_EVM_EXECUTORS_JSON \
  --apply
```

Use `--variables-only` to leave every GitHub secret untouched, or
`--secrets-only` to leave every GitHub variable untouched. `--only` can be
combined with either option and fails when a requested name is absent, which
prevents misspelled names from producing a partial update.

Signer-domain changes do not require identity rotation. Set
`VITE_WALLET_ORIGIN` and `VITE_RP_ID_BASE` in the protected deployment values
file, then apply both components. The wallet-core update replaces the signer
origin in the Gateway CORS and publishable-key allowlists; the product update
updates the browser build variables.

Update product-owned Pages and browser network values independently:

```bash
pnpm product:deploy:env-update -- \
  --site staging \
  --repo seams-tech/seams-sdk \
  --apply
```

When changing the Gateway runtime profile or NEAR relayer public configuration,
edit `deployment/targets.json` first. Apply the wallet-core secret update, then
run the product update. The product update reads the checked-in Gateway profile
and synchronizes `VITE_NEAR_NETWORK`, `VITE_NEAR_RPC_URL`, and
`VITE_NEAR_EXPLORER` so the browser and Gateway target the same NEAR network.

The command reads the protected values file for the selected lane/site
(`staging-deployment.env`, `production-testnet-deployment.env`, or
`production-deployment.env`) and updates only whitelisted
external values:

- Cloudflare deployment token and account ID for every target service.
- NEAR relayer identity and private key.
- Optional Google OIDC configuration.
- Tempo and Arc browser endpoint overrides.
- Sponsored EVM executor configuration.

It validates supplied public values against `deployment/targets.json` before
updating secrets or frontend variables. Router A/B keys, root shares,
signing-session material, and Gateway signing keys remain unchanged. Dry run is
the default. Update `VITE_SEAMS_PROJECT_ENVIRONMENT_ID` and
`VITE_SEAMS_PUBLISHABLE_KEY` through this path after an administrator creates
or rotates them, then redeploy the frontend.

The wallet-core updater can reach only Gateway and MPC service environments.
The product updater can reach only the target's shared frontend environment.
Run both component commands when rotating a Cloudflare token shared by both
ownership groups.

Frontend variable changes take effect on the next Pages deployment. Gateway
integration changes take effect on the next Gateway deployment.

The current checkout determines the GitHub repository. When targeting another
repository, pass its actual name, for example
`--repo seams-tech/seams-sdk`. The script rejects documentation placeholders
such as `owner/repo` before generating identities.

Every prepare invocation generates new cryptographic identities. Prepare and
wallet-core apply refuse an initialized target unless `--rotate` is present. Use that flag only
for a coordinated identity rotation that intentionally invalidates the prior
wallet custody configuration. Staging and production must be generated
independently.

For a complete staging rotation, use the guarded wrapper. It prepares one
generation, saves the complete backup, applies wallet-core, then applies the
paired product manifest:

```bash
pnpm deploy:env-rotate -- staging-testnet
```

Production rotations keep custody manifests lane-scoped. Run the testnet
rotation first; it updates only the five `production-testnet-*` environments
and leaves the shared `production` Pages environment untouched. After both
production lanes are prepared, run the mainnet rotation. Its product manifest
uses the `production` site identity and carries both production lane handoffs,
so the shared product environment is applied once:

```bash
pnpm deploy:env-rotate -- production-testnet
pnpm deploy:env-rotate -- production-mainnet
```

The operation writes these non-secret audit variables to all six GitHub
Environments after every normal variable and secret has uploaded:

- `SEAMS_DEPLOYMENT_GENERATION_ID`
- `SEAMS_DEPLOYMENT_GENERATED_AT`
- `SEAMS_DEPLOYMENT_MANIFEST_SHA256`

The SHA-256 identifies the complete manifest, including its secret values,
without disclosing them. GitHub does not permit reading secret values back, so
the generation metadata records which complete manifest the uploader committed.
The generation ID is written last. An interrupted metadata commit produces a
cross-environment mismatch instead of marking the rotation complete.

If wallet-core upload succeeds and product upload fails, reuse the saved
product manifest. Do not prepare another generation:

```bash
pnpm product:deploy:env-apply -- \
  --site staging \
  --manifest-file "$HOME/.seams/backups/<same-generation-product-manifest>.json" \
  --repo seams-tech/seams-sdk
```

Verify that every staging environment references one generation before
deploying:

```bash
pnpm deploy:env-verify -- \
  --lane staging-testnet \
  --repo seams-tech/seams-sdk
```

Compare its generation ID, timestamp, and manifest SHA-256 with the protected
backup. The command fails when any environment is missing metadata or contains
a different generation.

Preparation automatically writes mode-`600` component manifests. To retain an
additional complete machine-readable backup while preparing, capture stdout
from that same invocation:

```bash
umask 077
pnpm --silent wallet-core:deploy:env-prepare -- --lane staging-testnet --json \
  --values-file "$HOME/.seams/staging-deployment.env" \
  --repo seams-tech/seams-sdk \
  > staging-complete-generation.json
```

Progress remains visible in the terminal because it is written to stderr. The
complete backup contains both ownership groups. The two prepared component
files under `$HOME/.seams/backups` are the files used for upload. Move backups
to the approved secrets vault when local retention is not permitted.

## Individual Generators

The complete environment generator should be preferred for a new target. The
lower-level generators are useful for controlled rotation or inspection:

| Command                                               | Purpose                                                                                                                             |
| ----------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `pnpm router:deploy:keygen -- --lane staging-testnet` | Generates Router A/B public/private deployment identities only. It does not generate root shares or Gateway secrets.                |
| `pnpm router:deploy:root-share-keygen`                | Generates the matched Deriver A and Deriver B MPC PRF root-share wire secrets. Keep each share in its assigned Deriver environment. |

The low-level key generator supports `--show-secrets`, `--json`, `--apply`, and
`--repo`. Use `--silent` with pnpm when piping JSON. The root-share generator
supports `--json`. The complete lane generator owns signing-session seal
material so it remains matched with the Gateway manifest.

Do not combine independently generated low-level outputs with an already
applied complete manifest unless you are deliberately rotating the complete
related identity set. Public and private values, root shares, topology JSON,
and Gateway configuration must remain matched.

## Router A/B Build Diagnostics

Validate the four Worker bundles without creating Cloudflare Worker versions:

```bash
pnpm router:deploy:dry-run -- --env staging
pnpm router:deploy:dry-run -- --env staging --role router
```

The supported roles are `router`, `deriver-a`, `deriver-b`, and
`signing-worker`. Reports are written under
`crates/router-ab-cloudflare/reports/startup-latencies/`.

Capture Cloudflare startup measurements and upload Worker versions without
deploying traffic:

```bash
pnpm router:deploy:upload -- --env staging
pnpm router:deploy:upload -- --env staging --role router
```

The upload command requires the target Worker variables and Cloudflare
credentials. The same checks are used by `Validate / cloudflare-mpc-router-ab` and
the Router A/B jobs in the environment-specific backend workflow.
This diagnostic upload creates a non-serving Worker version; it is not the
production deployment or rollback path.

## Deployment

The normal deployment path is explicit workflow dispatch:

Before either staging dispatch, complete and push the full local `dev` branch
to `origin/dev`, fetch it again, and verify that `git rev-parse dev` equals
`git rev-parse origin/dev`. The worktree must be clean. Stop when those
conditions are unmet. Staging does not use partial cherry-picks, selected
commits, isolated deployment branches, or an unpushed local `dev`. See the
[staging branch parity invariant](README.md#staging-branch-parity-invariant).

Before any production dispatch, merge the complete staging-tested promotion
into protected `main`, fetch `origin/main`, fast-forward local `main`, and
verify that `git rev-parse main` equals `git rev-parse origin/main`. The
worktree must be clean. Stop when those conditions are unmet. Production uses
one verified `main` SHA across its frontend and backend workflows. Partial
promotions, selected commits, isolated release branches, and mixed-SHA
deployments are outside the release path. See the
[production branch parity invariant](README.md#production-branch-parity-invariant).

```bash
gh workflow run deploy-staging-backend.yml --ref dev
gh workflow run deploy-staging-frontend.yml --ref dev
gh workflow run deploy-production-testnet-backend.yml --ref main
gh workflow run deploy-production-mainnet-backend.yml --ref main
gh workflow run deploy-production-frontend.yml --ref main
```

Use the matching branch only. Production workflows are manual and require
`main`; the existing `production` environment also enforces its branch policy.
The two production backend workflows currently remain gated by pending lane
provisioning. The complete order and rollback procedure are documented in
[README.md](README.md#system-and-branch-rules).

Each backend lane workflow builds all components once, validates its five
custody environments before mutation, applies D1 migrations, then deploys
SigningWorker, Deriver A, Deriver B, Router, and Gateway. Backend smoke runs at
the end of the Gateway job. The matching frontend workflow uses one job to
build, deploy the site and wallet Pages projects, and run smoke checks.

Do not deploy a Gateway that references a different Router A/B identity set.
Generate and apply the target manifest before starting the matching environment
backend workflow.

## D1 and Staging Operations

Gateway D1 and staging operational scripts are documented in
[infra.md](infra.md#cloudflare-data). Common checks are:

```bash
pnpm --dir packages/console-server-ts run d1:staging:check
pnpm --dir packages/console-server-ts run d1:staging:resources -- --mode dry-run
pnpm --dir packages/console-server-ts run d1:staging:migrate -- --mode dry-run
pnpm --dir packages/console-server-ts run d1:staging:smoke -- --mode dry-run
```

Use `--mode remote` only when the operation is intentionally targeting the
remote staging resources. Prefer the generated staging runbook for multi-step
data operations:

```bash
pnpm --dir packages/console-server-ts run d1:staging:runbook -- \
  --operator <name> \
  --console-origin https://console.staging.example.com \
  --gateway-origin https://gateway.staging.example.com \
  --r2-bucket <bucket-name>
```

Do not record secret values in runbooks or deployment evidence. Record secret
names, resource IDs, versions, bookmarks, and pass/fail summaries only.

## Troubleshooting

If JSON parsing fails when piping a pnpm command, use `pnpm --silent`.

If apply mode fails before uploading values, verify `gh auth status`, the
`--repo` value, and repository administration permission. If it fails midway,
do not immediately rerun with a new generation: inspect which values were
applied, then intentionally decide whether to complete or rotate the entire
target identity set.

If environment preparation reports a missing variable or secret, compare the
generated manifest with the target's six GitHub Environments. The environment
generator checks its inventory against the hand-written deployment workflows and
fails when a workflow reference is missing from the manifest.

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
- `wasm-pack` when running SDK production builds or the full Pages workflow.

GitHub apply mode requires repository administration permission to create or
update deployment environments, Actions variables, and Actions secrets.

## GitHub Environment Bootstrap

The recommended first-deployment command is the complete environment
generator:

```bash
pnpm router:deploy:env-keygen -- --env staging
pnpm router:deploy:env-keygen -- --env production
```

Each invocation generates a complete manifest for one target containing six
GitHub Environments:

- The general Pages and SDK environment: `staging` or `production`.
- The Gateway environment: `<target>-gateway`.
- The MPCRouter environment: `<target>-mpc-router`.
- Deriver A, Deriver B, and SigningWorker environments.

The generator creates fresh Router A/B identities, matched root shares,
ceremony JWT signing material, internal service authentication, Gateway
secrets, signing-session seal material, tenant identifiers, and a publishable
key. Apply mode also provisions the target's D1 databases, Pages projects, and
Secrets Store when they do not exist.

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
and R2 publication are also optional. The generator resolves supplied values in
this order:

1. GitHub Environment-specific names such as
   `STAGING_GATEWAY__CLOUDFLARE_API_TOKEN`.
2. Target-specific names such as `STAGING__CLOUDFLARE_API_TOKEN`.
3. Shared names such as `CLOUDFLARE_API_TOKEN`.

Production Email OTP requires an email delivery provider. The current Gateway
runtime does not implement that provider, so production targets should omit
Google OIDC until delivery is configured.

Use `--apply` to create missing environments and upload every resolved value:

```bash
pnpm router:deploy:env-keygen -- \
  --env staging \
  --apply
```

The generator automatically loads
`$HOME/.seams/<target>-deployment.env`. Use `--values-file` only to
select a different protected file.

Apply mode:

- Creates missing GitHub Environments.
- Preserves existing environments and their protection rules.
- Creates missing target-scoped D1 databases and Pages projects. It reuses the
  account Secrets Store or creates one when the account has none.
- Generates and uploads all repository-owned cryptographic secrets.
- Uploads externally owned values loaded from the protected file or shell.
- Discovers the Cloudflare account ID and existing Cloudflare resources through
  Wrangler.
- Stores Gateway deployment metadata in one versioned
  `GATEWAY_DEPLOYMENT_CONFIG_JSON` variable. The deployment renderer validates
  this document once and expands it into Worker bindings.
- Removes the obsolete scalar Gateway variables after the replacement config is
  uploaded. Unrelated variables and all secrets are preserved.
- Refuses a partial apply while required values remain unresolved.
- Writes a step progress bar and per-environment upload counts to stderr.
- Prints the exact uploaded variables and secrets to stdout for backup.

`--allow-incomplete` permits an intentional partial bootstrap. Avoid it for a
deployment checkpoint because rerunning the generator rotates repository-owned
identity material.

CLI options can override the most common public identity values:

```bash
pnpm router:deploy:env-keygen -- \
  --env staging \
  --gateway-origin https://gateway.staging.example.com \
  --org-id org-id \
  --project-id project-id \
  --environment-id staging \
  --project-environment-id project-environment-id \
  --tenant-namespace staging \
  --apply
```

Cloudflare R2 access keys, funded NEAR relayer keys, funded EVM executor keys,
and OAuth credentials are externally owned and cannot be generated safely by
this repository. Keep them in the same protected target file as the Cloudflare
deployment credentials.

### Apply external values without rotating identities

After the initial bootstrap, preview operator-owned configuration changes:

```bash
pnpm router:deploy:env-apply -- \
  --env staging \
  --repo seams-tech/seams-sdk
```

Apply the displayed plan:

```bash
pnpm router:deploy:env-apply -- \
  --env staging \
  --repo seams-tech/seams-sdk \
  --apply
```

The command reads
`$HOME/.seams/<target>-deployment.env` and updates only whitelisted
external values:

- Cloudflare deployment token and account ID for every target service.
- NEAR relayer identity and private key.
- Optional Google OIDC configuration.
- Tempo and Arc browser endpoint overrides.
- R2 publication credentials.
- Sponsored EVM executor configuration.

It validates the deployed `GATEWAY_DEPLOYMENT_CONFIG_JSON` before patching
optional Gateway integrations. Router A/B keys, root shares, signing-session
material, Gateway signing keys, tenant identifiers, and publishable keys remain
unchanged. Dry run is the default.

Cloudflare credentials are copied to the target's Pages, Gateway, MPCRouter,
Deriver A, Deriver B, and SigningWorker GitHub Environments. Token rotation
therefore does not rotate any generated deployment identity.

Frontend variable changes take effect on the next Pages deployment. Gateway
integration changes take effect on the next Gateway deployment. R2 credentials
are consumed by the next SDK publication workflow.

The current checkout determines the GitHub repository. When targeting another
repository, pass its actual name, for example
`--repo seams-tech/seams-sdk`. The script rejects documentation placeholders
such as `owner/repo` before generating identities.

Every invocation generates new cryptographic identities. Apply mode refuses to
replace an initialized target unless `--rotate` is present. Use that flag only
for a coordinated identity rotation that intentionally invalidates the prior
wallet custody configuration. Staging and production must be generated
independently.

For a complete staging rotation, capture the exact manifest produced by the
same operation that replaces the GitHub values:

```bash
umask 077
pnpm --silent router:deploy:env-keygen -- \
  --env staging \
  --apply \
  --rotate \
  --repo seams-tech/seams-sdk \
  > staging-github-environment-backup.txt
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

Verify that every staging environment references one generation before
deploying:

```bash
pnpm router:deploy:env-verify -- \
  --env staging \
  --repo seams-tech/seams-sdk
```

Compare its generation ID, timestamp, and manifest SHA-256 with the protected
backup. The command fails when any environment is missing metadata or contains
a different generation.

To consolidate an already initialized Gateway without rotating any secret or
wallet identity, run the config-only migration:

```bash
pnpm router:deploy:env-keygen -- \
  --env staging \
  --migrate-gateway-config \
  --apply \
  --repo seams-tech/seams-sdk
```

This reads the existing scalar Gateway variables and the general environment's
publishable key, validates the replacement document, uploads
`GATEWAY_DEPLOYMENT_CONFIG_JSON`, and removes only the replaced Gateway
variables.

Capture the output from the same apply operation rather than running the
generator a second time:

```bash
umask 077
pnpm --silent router:deploy:env-keygen -- --env staging --apply \
  --values-file "$HOME/.seams/staging-deployment.env" \
  > staging-github-environment-backup.txt
```

Progress remains visible in the terminal because it is written to stderr. The
backup file contains the exact generated secrets from that invocation. Move it
to the approved secrets vault, then remove the local copy.

Before the first GitHub write, apply mode also saves a mode-`600` recovery copy
under `$HOME/.seams/backups`. This preserves generated values if a later
GitHub upload fails partway through.

For machine-readable output, suppress pnpm's banner:

```bash
pnpm --silent router:deploy:env-keygen -- --env staging --json > staging-manifest.json
```

Treat that file as secret material and delete it after securely transferring
the values.

## Individual Generators

The complete environment generator should be preferred for a new target. The
lower-level generators are useful for controlled rotation or inspection:

| Command                                      | Purpose                                                                                                                             |
| -------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `pnpm router:deploy:keygen -- --env staging` | Generates Router A/B public/private deployment identities only. It does not generate root shares or Gateway secrets.                |
| `pnpm router:deploy:root-share-keygen`       | Generates the matched Deriver A and Deriver B MPC PRF root-share wire secrets. Keep each share in its assigned Deriver environment. |
| `pnpm signing-session-seal:keygen`           | Generates Shamir 3-pass signing-session seal material for the Gateway and browser build.                                            |

The low-level key generator supports `--show-secrets`, `--json`, `--apply`, and
`--repo`. Use `--silent` with pnpm when piping JSON. The root-share generator
supports `--json`; the signing-session generator supports `--json`,
`--key-version`, and `--prime-bits`.

Do not combine independently generated low-level outputs with an already
applied complete manifest unless you are deliberately rotating the complete
related identity set. Public and private values, root shares, topology JSON,
and Gateway configuration must remain matched.

## Release Validation

Run the release blocker check before a deployment:

```bash
pnpm router:deploy:check
```

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
credentials. It is used by the release workflow for startup evidence.

## Deployment

The normal deployment path is branch-driven:

```bash
git push origin dev   # staging
git push origin main  # production
```

The successful CI workflow invokes the matching deployment workflow. For a
manual deployment, use the workflow dispatch commands documented in
[README.md](README.md#normal-promotion).

The deployment order is:

1. Validate and upload or deploy SigningWorker, Deriver A, Deriver B, and
   MPCRouter.
2. Apply Gateway D1 migrations and deploy the Gateway Worker.
3. Deploy the Pages app and wallet surfaces.
4. Publish the SDK runtime bundle to R2.

Do not deploy a Gateway that references a different Router A/B identity set.
Generate and apply the target manifest before starting the release workflow.

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

If release validation reports a missing variable or secret, compare the
generated manifest with the target's six GitHub Environments. The environment
generator checks its inventory against the deployment workflows and will fail
when a workflow reference is missing from the manifest.

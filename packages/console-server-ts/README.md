# Console Server TypeScript Package

This package owns console services, console routers, hosted D1/DO composition
workers, console D1 migrations, and D1 local/staging operations.

Deployable server applications live under `apps/`.

## Local D1/DO Development

The D1 migration work uses Wrangler and Miniflare as the local source of truth.
From this package:

```sh
pnpm run d1:local:prepare
pnpm run d1:local:paths
pnpm run d1:local:restore:drill
pnpm run d1:local:dev
```

`d1:local:dev` applies the local console and signer migrations before starting
the Worker. `d1:local:prepare` performs that preparation independently, creates
friendly live links at `sqlite/seams_console.sqlite` and
`sqlite/seams_signer.sqlite`, then checks that the expected tables exist.
Run `d1:local:paths` independently to refresh those links after changing the
local Wrangler persistence root. The command honors
`SEAMS_D1_LOCAL_PERSIST_TO` and `SEAMS_D1_LOCAL_SQLITE_DIR` when custom paths
are needed.
To wipe the local console and signer D1 databases plus Durable Object state,
stop the local Worker and run:

```sh
pnpm run d1:local:reset -- --yes
pnpm run d1:local:prepare
```

The reset removes the entire configured local Wrangler persistence root and
preserves the friendly SQLite symlinks. Run `d1:local:prepare` afterward to
repoint them. It does not seed application data.
`d1:local:restore:drill` backs up the local
console and signer SQLite databases, restores them into fresh SQLite files,
checks `PRAGMA integrity_check`, verifies expected table counts, and writes a
manifest under `.wrangler/d1-local-restore-drills`. `d1:local:dev` starts the
minimal local Worker from `wrangler.d1-local.toml` with persistent state under
`.wrangler/state/seams-d1`. It loads local configuration from the repository
root `.env.local`. Use `dev.vars` in this package as a reference for the
console-specific entries in that file.
To enable GitHub dashboard sign-in, register a GitHub OAuth App with
`https://localhost/dashboard/login` as its callback URL, then set
`GITHUB_OAUTH_CLIENT_ID`, `GITHUB_OAUTH_CLIENT_SECRET`, and
`GITHUB_OAUTH_CALLBACK_URL` in the root `.env.local`.
Set `STRIPE_API_SK` in the root `.env.local` to make Billing
create real Stripe Checkout Sessions. Without that server-side key, the local
billing provider remains an in-process test double and must not be used to
exercise the hosted Stripe Checkout page. Set `STRIPE_WEBHOOK_SECRET` to the
signing secret for the Stripe endpoint forwarded to the local Worker.
Use `GET /readyz` on the local Worker to verify the D1 table set and the
Durable Object normal-signing admission path:

```sh
curl http://127.0.0.1:9090/readyz
```

Open `sqlite/seams_console.sqlite` or `sqlite/seams_signer.sqlite` in TablePlus
with the SQLite driver when manual inspection is useful. The files are stable
symlinks to Wrangler's live hashed D1 files, so the D1 runtime and manual
inspection use the same database. Treat local inspection as read-only. Remote D1
inspection should use Wrangler, Cloudflare dashboard tools, exports, or a
purpose-built admin route.

Local EVM signing is client-funded. Sponsored EVM execution is optional and
uses Console D1 pricing rows, never request-time backfill or Worker env pricing.
For local sponsorship-route tests only, seed static Tempo pricing explicitly
with `seedD1ConsoleStaticEvmSponsorshipPricingRule`.

## Staging D1/DO Preflight

Before applying remote D1 migrations, copy
`wrangler.d1-staging-console.toml.example` to
`wrangler.d1-staging-console.toml` and `wrangler.d1-staging-gateway.toml.example`
to `wrangler.d1-staging-gateway.toml`. These concrete staging config files are
gitignored; keep the `.example` templates as the tracked source of structure. The
examples already point at the staging entrypoints:

- `src/router/cloudflare/d1ConsoleStagingWorker.ts`
- `src/router/cloudflare/d1RouterApiStagingWorker.ts`

Fill in the remote D1 database IDs, relayer public key, and Wrangler secret
declarations, then run:

```sh
pnpm run d1:staging:check
```

The check is static and credential-free. It rejects local-only Worker config,
wrong staging entrypoints, Postgres env tokens, placeholder D1 IDs, missing
profile bindings, signer/DO bindings on the console Worker, plaintext session
secrets, plaintext sponsored-EVM executor config. Gateway configuration must
declare the registration, recovery, and export admission-cutoff/drain pairs;
each pair may remain empty before cutover, and populated pairs must contain
ordered non-negative millisecond timestamps.

After the check passes, generate the credential-free staging deployment log:

```sh
pnpm run d1:staging:runbook -- \
  --output ../../docs/deployment/refactor-82-staging-log.md \
  --r2-bucket <staging-r2-backup-bucket> \
  --console-origin <console-staging-origin> \
  --gateway-origin <gateway-staging-origin>
```

The generated log contains the exact Wrangler 4.111.0 command sequence for
remote migrations, Time Travel bookmark capture, fixture import, Worker deploy,
staging smoke, and R2 export/restore drills. Record command output summaries,
bookmarks, object keys, and pass/fail evidence there; never paste secret values.

Capture resource inventory before remote changes:

```sh
pnpm run d1:staging:resources -- --mode dry-run
pnpm run d1:staging:resources -- --mode remote
```

The inventory script records config-derived Worker names, D1 database IDs,
Durable Object bindings, required secret names, and remote D1/Worker JSON
metadata under `.wrangler/d1-staging-resource-inventory`.

Apply remote D1 migrations through the manifest-producing staging script:

```sh
pnpm run d1:staging:migrate -- --mode dry-run
pnpm run d1:staging:migrate -- --mode remote
```

The migration script checks the console and Gateway staging Wrangler profiles,
hashes the local console/signer migration files, lists unapplied remote
migrations, applies them with `CI=true` for noninteractive Wrangler execution,
lists again after apply, and writes command evidence under
`.wrangler/d1-staging-migrations`.

Capture D1 Time Travel bookmarks before fixture import and before route changes:

```sh
pnpm run d1:staging:bookmark -- \
  --mode dry-run \
  --purpose before_fixture_import
pnpm run d1:staging:bookmark -- \
  --mode remote \
  --purpose before_fixture_import
pnpm run d1:staging:bookmark -- \
  --mode dry-run \
  --purpose before_route_switch
pnpm run d1:staging:bookmark -- \
  --mode remote \
  --purpose before_route_switch
```

The bookmark script checks the staging Wrangler profiles, captures console and
signer D1 bookmark JSON with `wrangler d1 time-travel info`, and writes a
manifest under `.wrangler/d1-staging-bookmarks`.

Fixture import is a named script so staging does not run ad hoc SQL:

```sh
pnpm run d1:staging:import-fixtures -- \
  --mode dry-run \
  --console-fixture ./staging/fixtures/console.sql \
  --signer-fixture ./staging/fixtures/signer.sql
pnpm run d1:staging:import-fixtures -- \
  --mode remote \
  --console-fixture ./staging/fixtures/console.sql \
  --signer-fixture ./staging/fixtures/signer.sql
```

The script requires readiness-clean staging configs, accepts data-only SQL
fixtures, rejects schema DDL and cross-domain table writes, writes a hash
manifest, and runs the remote import only with `--mode remote`.

Run staging smoke after deploy:

```sh
pnpm run d1:staging:smoke -- \
  --mode dry-run \
  --console-origin <console-staging-origin> \
  --gateway-origin <gateway-staging-origin>
pnpm run d1:staging:smoke -- \
  --mode remote \
  --console-origin <console-staging-origin> \
  --gateway-origin <gateway-staging-origin>
```

The smoke script checks the actual staging readiness endpoints:
`/console/readyz` on the console Worker, `/readyz` and `/healthz` on Gateway,
Worker, and the configured signer custody health routes
`/router-ab/ed25519/healthz` and `/router-ab/ecdsa-derivation/healthz`. It writes a
JSON evidence manifest under `.wrangler/d1-staging-smoke`.

Run read-only D1 reconciliation after staging smoke passes:

```sh
pnpm run d1:staging:reconcile -- --mode dry-run
pnpm run d1:staging:reconcile -- --mode remote
```

The reconciliation script checks dashboard billing balances, prepaid reservation
summary totals, sponsored-EVM billing links, sponsored settlement amounts, and
signer custody health. It writes evidence under `.wrangler/d1-staging-reconciliation`
and fails when any mismatch query returns rows.

Run the fixture-backed signer custody route drill after fixture import and
reconciliation:

```sh
export SEAMS_STAGING_ECDSA_WALLET_SESSION_JWT="<fixture-wallet-session-jwt>"
pnpm run d1:staging:signer-custody -- \
  --mode dry-run \
  --gateway-origin <gateway-staging-origin> \
  --origin <console-staging-origin> \
  --export-share-fixture ./staging/fixtures/ecdsa-export-share.json \
  --wallet-session-jwt-env SEAMS_STAGING_ECDSA_WALLET_SESSION_JWT
pnpm run d1:staging:signer-custody -- \
  --mode remote \
  --gateway-origin <gateway-staging-origin> \
  --origin <console-staging-origin> \
  --export-share-fixture ./staging/fixtures/ecdsa-export-share.json \
  --wallet-session-jwt-env SEAMS_STAGING_ECDSA_WALLET_SESSION_JWT
```

The signer custody script calls the configured threshold route health endpoints
and the production `/router-ab/ecdsa-derivation/export/share` route with the
success fixture. It writes redacted evidence under
`.wrangler/d1-staging-signer-custody` and never stores the wallet-session JWT or
server export share in the manifest.

Run the remote R2 export/restore drill after staging smoke passes:

```sh
pnpm run d1:staging:r2-restore-drill -- \
  --mode dry-run \
  --r2-bucket <staging-r2-backup-bucket>
pnpm run d1:staging:r2-restore-drill -- \
  --mode remote \
  --r2-bucket <staging-r2-backup-bucket>
```

The drill exports the console and signer D1 databases, uploads both SQL exports
to R2, downloads them into a restore workspace, creates timestamped restore-drill
D1 databases, imports the downloaded SQL, runs `PRAGMA integrity_check`, and
writes an evidence manifest under `.wrangler/d1-staging-r2-restore-drills`.

After every remote Phase 6 command has produced a manifest, verify the evidence
set before production planning:

```sh
pnpm run d1:staging:evidence -- \
  --resources <resource-inventory-remote-manifest.json> \
  --migrations <migrations-remote-manifest.json> \
  --bookmark-before-fixture-import <before-fixture-import-bookmark-manifest.json> \
  --fixture-import <fixture-import-remote-manifest.json> \
  --bookmark-before-route-switch <before-route-switch-bookmark-manifest.json> \
  --smoke <smoke-remote-manifest.json> \
  --reconciliation <reconciliation-remote-manifest.json> \
  --signer-custody <signer-custody-remote-manifest.json> \
  --r2-restore-drill <r2-restore-drill-remote-manifest.json> \
  --output .wrangler/d1-staging-evidence/verification.json
```

The evidence verifier rejects missing manifests, dry-run manifests, failed
commands, reconciliation mismatch rows, missing signer custody export-share
evidence, wrong custody endpoint paths/statuses, mixed staging environments, and
incomplete restore artifacts.

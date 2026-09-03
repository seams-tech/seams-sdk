# Seams SDK

Monorepo for `@seams/wallet`: an embedded passkey wallet SDK and
self-hostable signing infrastructure.

## Product direction

Seams is for applications that need a persistent wallet for each user or
shopping agent. The three primary use cases are platform wallets, shopping
wallet applications, and shopping agents purchasing from unrelated ecommerce
stores. Ordinary one-off merchant checkout is outside the primary customer
profile.

Read [the wallet vision](docs/vision.md) for customer fit, product boundaries,
and priorities.

## Getting Started

```bash
pnpm install
```

Run the local site, wallet origin, docs, Gateway, and Router A/B workers
from the repo root:

```bash
pnpm run site
pnpm router
```

- Run the commands above in separate terminals.
- `pnpm run site` is the canonical local UI entrypoint. It stops an existing
  Caddy listener on the Seams development ports, then starts Caddy + site + docs
  in the foreground. Ctrl+C releases the ports for another local project.
- If SDK wallet assets or Router A/B Worker artifacts are missing or stale,
  refresh them explicitly with `pnpm build:sdk`. After browser WASM changes,
  run `pnpm build:sdk-full`.
- `pnpm router` starts Gateway, MPCRouter, Deriver A, Deriver B, and SigningWorker. It starts Gateway through `pnpm gateway:server` when `127.0.0.1:4100` is not already ready.
- Primary local endpoints: app `http://localhost:4001`, wallet `https://localhost:4002`, Gateway base `https://localhost:4101`.
- Docs default origin: `https://docs.localhost:4003`.
- Internal dev ports: site Vite on `http://localhost:4004`, Console Vite on `http://localhost:4005`, docs VitePress on `http://localhost:4006`, Gateway on `http://127.0.0.1:4100`, and MPCRouter on `http://127.0.0.1:4102`.
- Browser-managed registration in the local site uses
  `VITE_SEAMS_PROJECT_ENVIRONMENT_ID` and `VITE_SEAMS_PUBLISHABLE_KEY`.
- Keep all human-edited local configuration in the ignored root `.env.local`.
  `pnpm router` generates its role-specific env files; do not edit those files.

## Repo Layout

- `apps/seams-site`: local app, wallet origin, and Caddy config.
- `apps/web-server`: Gateway runtime.
- `apps/docs`: documentation site.
- `packages/wallet`: browser SDK package.
- `packages/wallet-server`: server-side Router helpers.
- `packages/wallet/src/core/runtime`: shared runtime composition code.
- `packages/shared-ts`: shared TypeScript utilities.
- `crates`: Rust protocol, signer, HSS, and Router A/B crates.
- `wasm`: signer WASM packages.
- `tests`: Playwright and TypeScript integration/unit tests.

## Repo development

### Useful commands

- Build browser WASM packages: `pnpm build:wasm`
- Build SDK from existing browser WASM outputs plus Router A/B Workers: `pnpm build:sdk`
- Build browser WASM packages, SDK, and Router A/B Workers: `pnpm build:sdk-full`
- Build SDK (prod/release-style): `pnpm build:sdk-prod`
- SDK type check: `pnpm type-check:sdk`
- Tests: `pnpm test`
- Signer runtime regression gate: `pnpm test:signers:gates`
- Source guards: `pnpm test:source-guards`
- Full local check: `pnpm check`

### TypeScript type modules

Search existing `*.types.ts`, `types.ts`, and `*.typecheck.ts` surfaces before
adding domain types. Dedicated type-only source modules use `*.types.ts`;
compile-time invalid-state fixtures use `*.typecheck.ts`. Keep raw input
parsers near request, persistence, worker, and UI boundaries, then normalize into
the existing domain type.

### Router A/B Local Development

- Interleaved local service logs: `pnpm router`
- 2x2 terminal dashboard: `pnpm router:multiplex`
- Verify a running local topology: `pnpm router:check`
- Public HTTPS route probe: `pnpm router:public-route-smoke`

These commands launch Router A/B protocol harnesses. Browser account creation at
`http://localhost:4001` still needs the local site; `pnpm router` and
`pnpm router:multiplex` start Gateway at `127.0.0.1:4100` when it is
not already running. Run `pnpm build:sdk` after SDK or Router A/B Rust changes.
Run `pnpm build:sdk-full` after browser WASM changes. `pnpm router` validates
the existing strict Worker artifacts and starts services without rebuilding.

See `docs/router-ab/local-development.md` for the full local-development flow.

### Router A/B Deployment Prep

- Complete environment preparation: `pnpm wallet-core:deploy:env-prepare -- --env staging --repo <owner/repo>`
- Cloudflare startup dry-run: `pnpm router:deploy:dry-run`
- Cloudflare version upload evidence: `pnpm router:deploy:upload -- --env staging`
- Public keyset discovery: `/v1/router-ab/keyset`

`wallet-core:deploy:env-prepare` generates the deployment identities, internal
service authentication, ceremony signing material, Gateway secrets, and
signing-session seal material. Tenant root shares are created and rotated by the
role-separated tenant-root protocol; they are never generated as deployment
secrets. The Router or self-host relay serves the public keyset for SDK prefetch.
The deployment workflow performs its component-scoped preflight before any
remote mutation.

## Architecture

- Current architecture notes: `docs/architecture-current.md`
- Router A/B signer plan: `docs/router-A-B-signer.md`
- Router A/B spec: `docs/router-A-B-signer-SPEC.md`
- Deployment choices memo: `docs/router-a-b-deployment-choices.md`
- Signing session architecture: `docs/signing-session-architecture/`

## Deployment

See `docs/deployment/README.md` and `docs/deployment/infra.md`.

## License

MIT (see `LICENSE`).

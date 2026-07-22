# Seams SDK

Monorepo for `@seams/sdk`: an embedded passkey wallet SDK and
self-hostable signing infrastructure.

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
- `pnpm run site` is the canonical local UI entrypoint. It starts Caddy + site + docs for local HTTPS (`brew install caddy`; first run may prompt for trust via `caddy trust`).
- If SDK wallet assets or Router A/B Worker artifacts are missing or stale,
  refresh them explicitly with `pnpm build:sdk`. After browser WASM changes,
  run `pnpm build:sdk-full`.
- `pnpm router` starts Gateway, MPCRouter, Deriver A, Deriver B, and SigningWorker. It starts Gateway through `pnpm gateway:server` when `127.0.0.1:9090` is not already ready.
- Primary local endpoints: app `https://localhost`, wallet `https://localhost:8443`, Gateway base `https://localhost:9444`.
- Docs default origin: `https://docs.localhost`.
- Internal dev ports: Vite on `http://localhost:3600`, Gateway on `http://127.0.0.1:9090`, and MPCRouter on `http://127.0.0.1:9100`.
- Browser-managed registration in the local site uses
  `VITE_SEAMS_PROJECT_ENVIRONMENT_ID` and `VITE_SEAMS_PUBLISHABLE_KEY`.

## Repo Layout

- `apps/seams-site`: local app, wallet origin, and Caddy config.
- `apps/web-server`: Gateway runtime.
- `apps/docs`: documentation site.
- `packages/sdk-web`: browser SDK package.
- `packages/sdk-server-ts`: server-side Router helpers.
- `packages/sdk-web/src/core/runtime`: shared runtime composition code.
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
`https://localhost` still needs the local site; `pnpm router` and
`pnpm router:multiplex` start Gateway at `127.0.0.1:9090` when it is
not already running. Run `pnpm build:sdk` after SDK or Router A/B Rust changes.
Run `pnpm build:sdk-full` after browser WASM changes. `pnpm router` validates
the existing strict Worker artifacts and starts services without rebuilding.

See `docs/router-ab/local-development.md` for the full local-development flow.

### Router A/B Deployment Prep

- Deployment key generation: `pnpm router:deploy:keygen -- --env staging`
- Release blocker check: `pnpm router:deploy:check`
- Cloudflare startup dry-run: `pnpm router:deploy:dry-run`
- Cloudflare version upload evidence: `pnpm router:deploy:upload -- --env staging`
- Public keyset discovery: `/v1/router-ab/keyset`

`router:deploy:keygen` generates stable per-environment deployment identity keys
for Deriver A, Deriver B, and SigningWorker. Root-share wire secrets still come
from the derivation/provisioning ceremony. The Router or self-host relay serves
the public keyset for SDK prefetch. `router:deploy:check` must pass on the
target commit before running the deploy operation.

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

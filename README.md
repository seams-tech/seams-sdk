# Seams SDK

Monorepo for `@seams/sdk`: an embedded passkey wallet SDK and
self-hostable signing infrastructure.

## Getting Started

```bash
pnpm install
pnpm build:sdk-full
```

Run the local site, wallet origin, docs, and Router API server from the repo root:

```bash
pnpm run site
pnpm run server
```

- Run the commands above in separate terminals.
- `pnpm run site` is the canonical local UI entrypoint. It starts Caddy + site + docs for local HTTPS (`brew install caddy`; first run may prompt for trust via `caddy trust`).
- `pnpm run server` starts the Router API server.
- Primary local endpoints: app `https://localhost`, wallet `https://localhost:8443`, Router API base `https://localhost:9444`.
- Docs default origin: `https://docs.localhost`.
- Internal dev ports: Vite on `http://localhost:3600`, Router API server on `http://127.0.0.1:9090`.
- Browser-managed registration in the local site uses
  `VITE_SEAMS_ENVIRONMENT_ID` and `VITE_SEAMS_PUBLISHABLE_KEY`.

## Repo Layout

- `apps/seams-site`: local app, wallet origin, and Caddy config.
- `apps/web-server`: relay/server runtime.
- `apps/docs`: documentation site.
- `packages/sdk-web`: browser SDK package.
- `packages/sdk-server-ts`: server-side router and relay helpers.
- `packages/sdk-web/src/core/runtime`: shared runtime composition code.
- `packages/shared-ts`: shared TypeScript utilities.
- `crates`: Rust protocol, signer, HSS, and Router A/B crates.
- `wasm`: signer WASM packages.
- `tests`: Playwright and TypeScript integration/unit tests.

## Repo development

### Useful commands

- Build WASM workers: `pnpm build:wasm`
- Build SDK from existing WASM outputs: `pnpm build:sdk`
- Build WASM workers + SDK: `pnpm build:sdk-full`
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
`pnpm router:multiplex` start the Router server at `127.0.0.1:9090` when it is
not already running. After SDK or WASM changes, run `pnpm build:sdk-full`
explicitly before restarting local services.

See `docs/router-a-b-local-dev.md` for the full local-development flow.

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

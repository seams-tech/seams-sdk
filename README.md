# Web3Authn SDK

Monorepo for `@seams/sdk`: an embedded passkey wallet SDK for NEAR.

## Installation

```bash
pnpm install
pnpm build:sdk-full
```

Run examples from the repo root:

```bash
pnpm run site
pnpm run server
```

- Run the commands above in separate terminals.
- `pnpm run site` is the canonical local UI entrypoint. It starts Caddy + site + docs for local HTTPS (`brew install caddy`; first run may prompt for trust via `caddy trust`).
- `pnpm run server` starts the relay server.
- Primary local endpoints: app `https://localhost`, wallet `https://localhost:8443`, relay API base `https://localhost:9444`.
- Docs default origin: `https://docs.localhost`.
- Internal dev ports: Vite on `http://localhost:3600`, relay on `http://127.0.0.1:8444`.
- Browser-managed registration in the example site uses `VITE_SEAMS_ENVIRONMENT_ID` + `VITE_SEAMS_PUBLISHABLE_KEY` from `examples/seams-site/.env`.

## Repo development

### Useful commands

- Build WASM workers: `pnpm build:wasm`
- Build SDK from existing WASM outputs: `pnpm build:sdk`
- Build WASM workers + SDK: `pnpm build:sdk-full`
- Build SDK (prod/release-style): `pnpm -C sdk build:prod`
- SDK watch mode: `pnpm -C sdk dev`
- Tests: `pnpm -C sdk test`
- Signer runtime regression gate: `pnpm test:signers:gates`
- Type check: `pnpm -C sdk run type-check`
- Signer runtime specs: `docs/signer-runtime-contracts.md`

## Architecture

- Wallet iframe / origin isolation: `examples/seams-docs/src/concepts/architecture.md`
- Security model: `examples/seams-docs/src/concepts/security-model.md`
- SecureConfirm + WebAuthn: `examples/seams-docs/src/concepts/secureconfirm-webauthn.md`
- Relay deployment: `examples/relay-server/README.md`

## Deployment

See `docs/deployment/README.md`.

## License

MIT (see `LICENSE`).

# Seams Site Dev Server

This app runs a dedicated wallet/service origin for local development. The app Vite server owns only the demo application, while Caddy serves the hosted wallet asset tree from `packages/sdk-web/dist/public`.

- Dev server: `http://localhost:3600`
- Docs origin (via Caddy): `https://docs.localhost`
- Wallet origin (via Caddy): `https://localhost:8443`
- Router API origin (via Caddy): `https://localhost:9444`
- Service path: `/wallet-service`
- SDK assets base: `/sdk/*` (served from `packages/sdk-web/dist/public/sdk`)

## Usage

- Start this dev server:

```
pnpm -C apps/seams-site dev
```

- Ensure Caddy is running so localhost TLS endpoints are available. If you are running the main example app (`pnpm run site`), it starts Caddy for you; run `pnpm router` separately so the Router API origin `https://localhost:9444` is available. If wallet assets are missing or stale, refresh them explicitly with `pnpm build:sdk`; after Rust/WASM changes, run `pnpm build:sdk-full`.

Open:

- `https://localhost:8443/wallet-service` – the iframe service page
- `https://localhost:9444` – Router API origin
- `https://docs.localhost` – docs site

## Production deployment

Production app and wallet Pages artifacts are built from the accepted `main`
revision by the `Deploy / production / cloudflare-stack` workflow. Revisions
under `apps/seams-site/` select both Pages deployments so their SDK and wallet
assets stay on the same release.

## Notes

- The route `/wallet-service` is served by Caddy from `packages/sdk-web/dist/public/wallet-service/index.html` and loads `/sdk/wallet-iframe-host-runtime.js` from the same wallet origin.
- App-origin requests for `/sdk/*`, `/wallet-service`, and `/export-viewer` return 404 through Caddy to catch accidental app-hosted wallet asset dependencies.
- The wallet origin does not use app COOP, COEP, CORP, or Permissions-Policy defaults for SDK assets. Document routes keep the local `frame-ancestors` policy emitted in the static header manifest.
- Keep the SDK build current by re-running `pnpm build:sdk` after wallet runtime changes.
- Docs are served from the VitePress dev server at `https://docs.localhost`.

### Dashboard inline modal scrolling

- Keep exactly one scroll host active while an inline modal is open.
- For dashboard modals, the backdrop should own scrolling and the underlying `.dashboard-main` container should be scroll-locked.
- If both the backdrop and `.dashboard-main` scroll at the same time, trackpad and wheel scrolling can stop halfway through the modal and require a second gesture.
- Elastic overscroll can also expose the backdrop boundary near the topbar, so the backdrop should extend beyond the visible content frame instead of ending exactly at the viewport edge.

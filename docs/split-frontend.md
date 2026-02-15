# Split Frontend Status: `tatchi-site` + `tatchi-docs`

## Current Layout
- App site: `examples/tatchi-site` (Vite + React)
- Docs site: `examples/tatchi-docs` (VitePress)
- Hosts:
  - `https://example.localhost` -> app site
  - `https://docs.example.localhost` -> docs site
  - `https://wallet.example.localhost` -> wallet-service (from app dev server)

## What Is Completed
- Docs and app runtimes are split into separate packages.
- Site runtime no longer depends on VitePress app-shell hooks.
- Cross-origin docs links are generated from `VITE_DOCS_ORIGIN`.
- Caddy host split is in place for app/docs/wallet.
- Type-check/build validation passed for both packages.

## Routing Policy
- No temporary `/docs/*` compatibility redirect on `example.localhost`.
- All docs navigation should use `https://docs.example.localhost/...` directly.

## Checklist (Updated)
### Workspace And Scripts
- [x] Docs package path is `examples/tatchi-docs`.
- [x] Root scripts target `examples/tatchi-docs` (`docs:*`, `type-check:docs`, `examples:vite*`, `examples:docs`).
- [x] Workspace includes `examples/tatchi-docs`.

### Runtime Split
- [x] Site routes (`/`, `/products`, `/solutions`, `/pricing`, `/company`, `/contact`, `/dashboard`) render via site runtime.
- [x] Docs host serves VitePress docs independently.
- [x] Wallet service remains on wallet origin.

### Validation
- [x] `pnpm -C examples/tatchi-site exec tsc --noEmit`
- [x] `pnpm -C examples/tatchi-site build`
- [x] `pnpm -C examples/tatchi-docs build`

## Remaining Cleanup
- Update any historical old-path mentions in other user-facing docs if we surface this migration plan externally.

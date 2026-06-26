# Server TypeScript Package

This package owns reusable server-side TypeScript source: route adapters,
WebAuthn verification policy, threshold service code, storage adapters, console
helpers, and server wasm bindings.

Deployable server applications live under `apps/`.

## Local D1/DO Development

The D1 migration work uses Wrangler and Miniflare as the local source of truth.
From this package:

```sh
pnpm run d1:local:prepare
pnpm run d1:local:dev
```

`d1:local:prepare` applies the local console and signer migrations, then checks
that the expected tables exist. `d1:local:dev` starts the minimal local Worker
from `wrangler.d1-local.toml` with persistent state under `.wrangler/state/seams-d1`.

Open the SQLite files under `.wrangler/state/seams-d1` in TablePlus with the
SQLite driver when manual inspection is useful. Treat local inspection as
read-only. Remote D1 inspection should use Wrangler, Cloudflare dashboard tools,
exports, or a purpose-built admin route.

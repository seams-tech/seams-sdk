# router-ab-dev

Local development adapters for the Router/A/B architecture.

This crate owns developer-only helpers that are intentionally outside the
transport-neutral `router-ab-core` crate:

- local SQLite seed and startup checks,
- local Ed25519 Yao lifecycle and performance harnesses,
- local Router/Deriver/SigningWorker config parsing,
- private-worker local harness support.

Run the complete local Ed25519 Yao lifecycle in both fixed development
profiles:

```sh
pnpm router:yao-smoke
```

Run the complete local validation gate:

```sh
pnpm validate:yaos-ab-local
```

The profile-specific commands are `pnpm router:yao-smoke:one-account` and
`pnpm router:yao-smoke:two-administrator`. Use
`pnpm router:yao-measure-local` for optimized local latency and byte evidence.
These commands do not deploy Cloudflare Workers.

Initialize generated local env files and state directories:

```sh
cargo run --manifest-path crates/router-ab-dev/Cargo.toml --bin router_ab_local_init -- --force
```

Run the local process harness through the repo-level wrappers:

```sh
pnpm router:init -- --force
pnpm router:up
pnpm router:check
pnpm router:down
```

For a single terminal with Docker-style interleaved logs, launch all four
workers with:

```sh
pnpm router
```

For a single-terminal dashboard:

```sh
pnpm router:multiplex
```

`pnpm router` and `pnpm router:multiplex` launch the production-equivalent
MPCRouter, Deriver A, Deriver B, and SigningWorker Cloudflare Workers on
`127.0.0.1:9100-9103`. They start Gateway at
`127.0.0.1:9090` when it is not already running. They also verify
`https://localhost:9444/.well-known/webauthn` and start the local Caddy proxy
when that HTTPS endpoint is absent. Browser account creation still needs the
local app from `pnpm site`.

Build the SDK and strict Worker artifacts explicitly before launching:

```sh
pnpm build:sdk
pnpm router
```

Local `pnpm build:sdk` uses the fast Rust development profile for the strict
Workers (`--dev --no-opt`). Use
`ROUTER_AB_WORKER_BUILD_PROFILE=release pnpm build:sdk` when optimized Worker
artifacts are required, and use the same variable with `pnpm router` to launch
those artifacts. `pnpm router` checks that all four artifacts exist and match
the current build profile. It does not compile Rust/WASM during startup. Use
`pnpm router:build` when only the strict Workers need rebuilding. Stop a
running Router topology before either build command; the build refuses to
replace artifacts while ports `9100-3` are active.

Starting `pnpm router` replaces any processes listening on ports `9100-9103`.
It stops the existing listeners, waits for the ports to clear, and then claims
them for the new topology. A port-conflict error means a listener survived both
graceful and forced shutdown.

Pass `--fresh` to regenerate local role secrets before launch:

```sh
pnpm router -- --fresh
pnpm router:multiplex -- --fresh
```

`pnpm gateway:server` is the lower-level Gateway command under
`apps/web-server`; `pnpm router` starts it automatically for the normal local
backend stack. Gateway calls the same Cloudflare Worker route surfaces
used by production for Yao and ECDSA work.

Capture a timestamped local timing evidence artifact:

```sh
pnpm router:measure
```

The local deployment parity plan lives at
[`../../docs/router-ab/local-development.md`](../../docs/router-ab/local-development.md).

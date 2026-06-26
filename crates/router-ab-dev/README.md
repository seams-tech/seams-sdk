# router-ab-dev

Local development adapters for the Router/A/B architecture.

This crate owns developer-only helpers that are intentionally outside the
transport-neutral `router-ab-core` crate:

- local SQLite seed and startup checks,
- committed Ed25519-HSS parity fixtures,
- local Router/Deriver/SigningWorker config parsing,
- private-worker local harness support.

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

For a single-terminal 2x2 dashboard:

```sh
pnpm router:multiplex
```

`pnpm router` and `pnpm router:multiplex` launch the Router A/B private-worker
harness and start the SDK Router server at `127.0.0.1:9090` when it is not
already running. They also verify
`https://localhost:9444/.well-known/webauthn` and start the local Caddy proxy
when that HTTPS endpoint is absent. Browser account creation still needs the
local app from `pnpm site`.

Pass `--fresh` to regenerate env files with the default `9090-9093` localhost
ports before launch:

```sh
pnpm router -- --fresh
pnpm router:multiplex -- --fresh
```

`pnpm router:server` is the lower-level main Router server command under
`apps/web-server`; `pnpm router` starts it automatically for the normal local
backend stack. The Rust local worker binary now exposes only Deriver A, Deriver
B, and SigningWorker private roles; the SDK Router route table owns the
browser-facing local API.

If the default ports `9090-9093` are already in use, generate the same local
environment with free localhost ports:

```sh
pnpm router -- --fresh --ephemeral-ports
```

Capture a timestamped local timing evidence artifact:

```sh
pnpm router:measure
```

The local deployment parity plan lives at
[`../../docs/router-a-b-local-dev.md`](../../docs/router-a-b-local-dev.md).

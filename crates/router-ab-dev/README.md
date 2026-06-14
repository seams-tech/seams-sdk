# router-ab-dev

Local development adapters for the Router/A/B architecture.

This crate owns developer-only helpers that are intentionally outside the
transport-neutral `router-ab-core` crate:

- local SQLite seed and startup checks,
- committed Ed25519-HSS parity fixtures,
- local Router/Deriver/SigningWorker config parsing,
- four-process local worker harness support.

Initialize generated local env files and state directories:

```sh
cargo run --manifest-path crates/router-ab-dev/Cargo.toml --bin router_ab_local_init -- --force
```

Run the local process harness through the repo-level wrappers:

```sh
pnpm router-ab:local:init -- --force
pnpm router-ab:local:up
pnpm router-ab:local:smoke
pnpm router-ab:local:smoke:bundled
pnpm router-ab:local:down
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

For a single bundled server that exposes Router, Deriver A, Deriver B, and
SigningWorker routes from one process:

```sh
pnpm router:bundled
```

Verify a running bundled server from a second terminal:

```sh
pnpm router-ab:local:smoke -- --topology bundled
```

Pass `--fresh` to regenerate env files with free localhost ports before launch:

```sh
pnpm router -- --fresh
pnpm router:multiplex -- --fresh
```

`pnpm server` remains the main SDK relay server under `apps/web-server`. It is
not the Router A/B single-server profile.

If the default ports `8787-8790` are already in use, generate the same local
environment with free localhost ports:

```sh
pnpm router-ab:local:init -- --force --ephemeral-ports
pnpm router-ab:local:up
pnpm router-ab:local:smoke
pnpm router-ab:local:down
```

For CI-safe local parity smoke with temp state and ephemeral ports:

```sh
pnpm router-ab:local:smoke:ci
pnpm router-ab:local:smoke:bundled
```

Capture a timestamped local timing evidence artifact:

```sh
pnpm router-ab:local:measure
```

The local deployment parity plan lives at
[`../../docs/router-a-b-local-dev.md`](../../docs/router-a-b-local-dev.md).

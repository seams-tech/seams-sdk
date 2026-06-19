# Refactor 68B: Router Worker Cleanup

Status: in progress; local topology switch applied

## Goal

Make the Router the single browser-facing server/worker for local development and
deployment. The historical "relay" naming is stale: the relay API and Router API
are the same public surface. Caddy exists only to provide local HTTPS and should
forward the whole origin to one Router process.

## Target Topology

Local browser-facing origin:

- `https://localhost:9444` is Caddy TLS.
- Caddy forwards every request to one local Router server.
- The Router server owns wallet/session APIs, Wallet Session issuance and seal
  routes, registration, ECDSA-HSS lifecycle/export routes, Ed25519 lifecycle
  routes, and Router A/B normal-signing routes.
- Deriver A, Deriver B, and SigningWorker remain private service workers.
- Caddy must not path-split `/v2/router-ab/*` or `/v1/hss/ecdsa/sign*` to a
  second public upstream.

Target local ports after cleanup:

| Role                 |   Port | Public            |
| -------------------- | -----: | ----------------- |
| Caddy HTTPS          | `9444` | yes               |
| Router server/worker | `9090` | behind Caddy only |
| Deriver A            | `9091` | private           |
| Deriver B            | `9092` | private           |
| SigningWorker        | `9093` | private           |

The single Router server binds `127.0.0.1:9090`. Caddy forwards the whole
`https://localhost:9444` origin to that one Router server.

## Current Problem

The codebase previously had two local concepts using Router-like language:

- `apps/web-server` / `packages/sdk-server-ts` owns the public wallet/session API
  surface.
- `crates/router-ab-dev` also started a Rust `router` worker on
  `127.0.0.1:9090` for strict Router A/B protocol work.

That split led to a bad local fix where Caddy routed Router A/B signing paths to
`9090` while all other routes went to `8444`. That made signing paths work
locally, but it encoded the wrong architecture: two browser-facing public
upstreams behind one HTTPS origin.

## Invariants

- One browser-facing Router route table owns every public route.
- Caddy has one upstream per origin.
- No public route is implemented by Caddy path selection.
- No duplicate public signing route families.
- No `/threshold-*` public signing routes return.
- Router A/B signing-capable state requires Wallet Session bearer JWT auth and
  curve-specific Router A/B state before it can be advertised as sign-ready.
- Deriver and SigningWorker routes are private service routes with internal
  service auth.
- Compatibility code remains only at request/persistence boundaries with an
  explicit deletion condition.

## Phase 1: Stop Encoding Split Public Routing

- [x] Remove the local Caddy path split for Router A/B signing paths.
- [x] Add a source guard that fails if `apps/web-client/Caddyfile` contains
      `@router_ab_public_signing`, more than one `reverse_proxy` inside the
      `localhost:9444` site block, or any path-specific Router A/B signing
      proxy rule.
- [x] Add a local route smoke probe that proves
      `https://localhost:9444/v2/router-ab/ed25519/sign/prepare` reaches the
      same Router server as `https://localhost:9444/v2/router-ab/wallet-session/ed25519`.
      Added as `pnpm router:public-route-smoke`; run it after `pnpm site` and
      `pnpm router` are ready.
- [x] Update failure docs so an Express-style `Cannot POST /v2/router-ab/...`
      means the main Router route table is missing that route.

## Phase 2: Rename Local Dev Concepts

- [x] Rename `frontendRelay*` locals in
      `crates/router-ab-dev/scripts/dev-local-workers.mjs` to `routerServer*`.
- [x] Rename log labels from `frontend relay` to `router server`.
- [x] Update `package.json` script comments/docs so `pnpm server` and
      `pnpm router` do not imply two public API servers.
- [x] Update `docs/router-a-b-local-dev.md` diagrams to show Caddy forwarding
      the whole origin to the Router server.
- [x] Keep "relay" only where it names a NEAR relayer account, historical
      persisted field, or explicit compatibility boundary.
      Scoped grep now leaves test-relay harness/provisioning references,
      historical chat text, relayer account config, and this plan's own cleanup
      terminology.

## Phase 3: Choose The Single Router Runtime

Decision: the main Router runtime is the SDK server route layer
(`packages/sdk-server-ts` plus `apps/web-server`) because it already owns wallet
auth, sessions, registration, WebAuthn, Wallet Session seal, budget, and console
surfaces. Router A/B strict protocol code must move behind this route layer.

- [ ] Treat the Rust `router` worker in `crates/router-ab-dev` as a temporary
      strict-protocol implementation detail.
- [x] Move public Router A/B Ed25519 normal-signing handlers into the main Router
      route table.
- [x] Move public Router A/B ECDSA-HSS normal-signing handlers into the main
      Router route table.
- [x] Keep Deriver A/B and SigningWorker private HTTP workers for local dev and
      Cloudflare service bindings.
- [ ] Delete the separate public Rust Router role once the main Router route
      table owns equivalent admission, replay, quota, abuse, and forwarding
      behavior.

## Phase 4: Port Strict Router A/B Admission Into Main Router

- [ ] Extract the strict Router A/B public-route admission logic from
      `crates/router-ab-cloudflare` into reusable protocol tests/vectors where
      practical.
- [x] Add main Router Wallet Session, scope, SigningWorker id, and expiry
      checks before active Ed25519 and ECDSA-HSS signing requests are forwarded.
- [x] Forward main Router active Ed25519 and ECDSA-HSS signing requests only to
      private SigningWorker routes with `x-router-ab-internal-service-auth`.
- [x] Implement Ed25519 prepare, presign-pool prepare, and finalize admission in
      the main Router route layer.
- [x] Implement ECDSA-HSS prepare and finalize admission in the main Router route
      layer.
- [ ] Preserve raw-body digest semantics where the spec requires exact request
      binding.
- [ ] Preserve replay, expiry, quota, abuse, and abandoned-prepare cleanup
      semantics.
- [ ] Add negative tests for missing bearer, old threshold JWT kinds, scope drift,
      expired requests, replayed request ids, duplicate handles, and
      cross-session attempts.

## Phase 5: Collapse Local Port Model

- [x] Move the main Router server from `127.0.0.1:8444` to `127.0.0.1:9090`.
- [x] Update `apps/web-client/Caddyfile` so `localhost:9444` reverse-proxies the
      whole origin to `127.0.0.1:9090`.
- [x] Update `package.json` server scripts and `pnpm router` orchestration to use
      the target ports.
- [x] Remove the Rust `router` role from `crates/router-ab-dev/scripts/dev-local-workers.mjs`.
- [x] Keep `9091`, `9092`, and `9093` for Deriver A, Deriver B, and SigningWorker.
- [x] Add preflight checks that fail when another process owns a target port.

## Phase 6: Delete Split-Worker Bloat

- [x] Delete any helper whose only purpose is proxying public Router A/B signing
      routes from one public upstream to another.
- [x] Delete docs that describe a public `frontend relay` separate from Router.
- [x] Delete or confirm absent route tests that expect a Caddy path split.
- [x] Delete or confirm absent source guards that preserve split public routing.
- [x] Add source guards that reject Caddy Router A/B signing path matchers,
      public route registration in both the main Router and a second public Rust
      Router worker, and local dev scripts starting two public API servers for
      the same origin.

## Phase 7: Verification

- [x] `caddy validate --config apps/web-client/Caddyfile --adapter caddyfile`.
- [x] Router route-surface unit tests prove the main Router owns
      `POST /v2/router-ab/ed25519/sign/prepare`,
      `POST /v2/router-ab/ed25519/sign/presign-pool/prepare`,
      `POST /v2/router-ab/ed25519/sign`,
      `POST /v1/hss/ecdsa/sign/prepare`, `POST /v1/hss/ecdsa/sign`, Wallet
      Session issuance, and seal routes.
- [ ] Local browser unlock-to-sign test passes for Ed25519.
- [ ] Local browser unlock-to-sign test passes for ECDSA-HSS Tempo and EVM.
- [ ] `pnpm router` starts Caddy plus exactly one public Router server.
- [x] `pnpm router:public-route-smoke` passes with the local site and Router
      workers running.
- [x] `pnpm router:check` validates Ed25519 and ECDSA-HSS through
      `https://localhost:9444`.
      Evidence on 2026-06-18: `rtk pnpm router:check` passed against the live
      local four-worker topology. The summary reported Ed25519
      `normal_signing_status=ed25519_v1`, ECDSA-HSS
      `ecdsa_hss_prepare_status=http_200_bound`,
      `ecdsa_hss_finalize_status=http_200_signature`, and
      `ecdsa_hss_replay_rejection_status=http_400_one_use_replay_rejected`.
- [x] Source guards pass for no public split routing.

## Completion Criteria

- Caddy forwards `https://localhost:9444` to one upstream.
- The main Router route table owns every public route used by the SDK.
- No public signing request depends on Caddy path selection.
- Local dev has one public Router server and three private Router A/B service
  workers.
- Manual Ed25519 and ECDSA-HSS signing tests pass locally before Cloudflare
  deployment work resumes.

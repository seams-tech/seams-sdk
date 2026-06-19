# Refactor 68B: Router Worker Cleanup

Status: complete and closed on 2026-06-19; local topology switch and spec audit complete

Closure note: 68B has no remaining tasks. Future Router A/B topology drift
should be handled in a new plan or the active Router cleanup plan, not by
reopening this document.

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

- [x] Treat the Rust `router` worker in `crates/router-ab-dev` as a temporary
      strict-protocol implementation detail.
      Evidence on 2026-06-19: the SDK Router route table owns the
      browser-facing local API. The existing source guard
      `pnpm router launches one public Router server and three private workers`
      asserts repo-level `pnpm router` does not spawn the Rust router role.
- [x] Move public Router A/B Ed25519 normal-signing handlers into the main Router
      route table.
- [x] Move public Router A/B ECDSA-HSS normal-signing handlers into the main
      Router route table.
- [x] Keep Deriver A/B and SigningWorker private HTTP workers for local dev and
      Cloudflare service bindings.
- [x] Delete the separate public Rust Router role once the main Router route
      table owns equivalent admission, replay, quota, abuse, and forwarding
      behavior.
      Evidence on 2026-06-19: the local worker binary rejects the removed public
      Router role, the single-process local profile binary and scripts are
      deleted, obsolete Rust public Router forwarding handlers are deleted, and
      `rtk cargo check --manifest-path crates/router-ab-dev/Cargo.toml` passes.

## Phase 4: Port Strict Router A/B Admission Into Main Router

- [x] Extract the strict Router A/B public-route admission logic from
      `crates/router-ab-cloudflare` into reusable protocol tests/vectors where
      practical.
      Current extraction coverage:
      - [x] Ed25519 normal-signing SDK builders are checked against Rust
            admission digest vectors:
            `tests/unit/routerAbNormalSigningVectors.unit.test.ts`.
      - [x] ECDSA-HSS normal-signing request/response digest binding is covered
            by focused TypeScript boundary tests:
            `tests/unit/routerAbEcdsaHssNormalSigning.unit.test.ts`.
      - [x] ECDSA-HSS route admission scope comparison is guarded to use
            canonical protocol bytes:
            `tests/unit/routerAbServerWalletSessionClaimBoundary.guard.unit.test.ts`.
      - [x] Quota and abuse admission-store behavior is ported to focused
            TypeScript store tests:
            `tests/unit/routerAbNormalSigningAdmissionStore.unit.test.ts`.
- [x] Add main Router Wallet Session, scope, SigningWorker id, and expiry
      checks before active Ed25519 and ECDSA-HSS signing requests are forwarded.
- [x] Forward main Router active Ed25519 and ECDSA-HSS signing requests only to
      private SigningWorker routes with `x-router-ab-internal-service-auth`.
- [x] Implement Ed25519 prepare, presign-pool prepare, and finalize admission in
      the main Router route layer.
- [x] Implement ECDSA-HSS prepare and finalize admission in the main Router route
      layer.
- [x] Preserve exact request-binding digest semantics required by the current
      normal-signing specs. Current Ed25519 and ECDSA-HSS normal-signing specs
      bind canonical typed protocol bytes:
      - [x] Ed25519 admission material matches Rust vectors:
            `tests/unit/routerAbNormalSigningVectors.unit.test.ts`.
      - [x] ECDSA-HSS prepare/finalize request digest mismatches are rejected:
            `tests/unit/routerAbEcdsaHssNormalSigning.unit.test.ts`.
      - [x] ECDSA-HSS scope comparison uses canonical protocol bytes in shared
            code and server admission:
            `tests/unit/routerAbServerWalletSessionClaimBoundary.guard.unit.test.ts`.
- [x] Preserve replay, expiry, quota, abuse, and abandoned-prepare cleanup
      semantics.
      Current semantics coverage:
      - [x] Replay rejection for Ed25519 and ECDSA-HSS prepare request ids:
            `tests/relayer/router-ab-normal-signing-auth-boundary.test.ts`.
      - [x] Current-time expiry rejection before private SigningWorker
            forwarding:
            `tests/unit/thresholdSessionClaims.unit.test.ts` and
            `tests/relayer/router-ab-normal-signing-auth-boundary.test.ts`.
      - [x] Abandoned-prepare cleanup semantics in strict Cloudflare and
            local-dev stores:
            `crates/router-ab-cloudflare/tests/bindings.rs` and
            `crates/router-ab-dev/src/lib.rs`.
      - [x] Main Router route layer has a typed normal-signing admission
            boundary for project-policy, quota, and abuse decisions:
            `packages/sdk-server-ts/src/router/routerAbPrivateSigningWorker.ts`.
      - [x] Ed25519 and ECDSA-HSS prepare/finalize route handlers evaluate that
            boundary before private SigningWorker configuration, material, or
            forwarding is read:
            `packages/sdk-server-ts/src/router/express/routes/thresholdEd25519.ts`,
            `packages/sdk-server-ts/src/router/express/routes/thresholdEcdsa.ts`,
            `packages/sdk-server-ts/src/router/cloudflare/routes/thresholdEd25519.ts`,
            and `packages/sdk-server-ts/src/router/cloudflare/routes/thresholdEcdsa.ts`.
      - [x] Focused route tests cover quota saturation and abuse rejection
            before private SigningWorker forwarding:
            `tests/relayer/router-ab-normal-signing-auth-boundary.test.ts`.
      - [x] Durable quota and abuse admission-store parity is implemented in the
            main Router route layer:
            `packages/sdk-server-ts/src/router/routerAbNormalSigningAdmissionStore.ts`
            defines strict project-policy, quota, and abuse decision unions,
            in-memory local state, and Postgres-backed admission tables.
      - [x] The app server wires the concrete admission adapter whenever Router
            A/B normal signing is enabled:
            `apps/web-server/src/index.ts`.
      - [x] Focused store tests cover accepted, reuse-existing, short-window
            saturation, project-policy rejection, abuse rate limiting/rejection,
            expiry, and Ed25519/ECDSA-HSS quota separation:
            `tests/unit/routerAbNormalSigningAdmissionStore.unit.test.ts`.
- [x] Add negative tests for missing bearer, old threshold JWT kinds, scope drift,
      expired requests, replayed request ids, duplicate handles, and
      cross-session attempts.
      Current negative-test coverage:
      - [x] Missing bearer rejection at the validator boundary:
            `tests/unit/thresholdSessionClaims.unit.test.ts`.
      - [x] Missing bearer rejection at the public route boundary before private
            SigningWorker configuration is read:
            `tests/relayer/router-ab-normal-signing-auth-boundary.test.ts`.
      - [x] Legacy threshold JWT kind rejection at the validator boundary:
            `tests/unit/thresholdSessionClaims.unit.test.ts`.
      - [x] Legacy threshold JWT kind rejection at the public route boundary
            before private SigningWorker configuration is read:
            `tests/relayer/router-ab-normal-signing-auth-boundary.test.ts`.
      - [x] Ed25519 scope, session, worker, Wallet Session expiry drift, and
            current-time expired request rejection at the private validator
            boundary:
            `tests/unit/thresholdSessionClaims.unit.test.ts`.
      - [x] Ed25519 scope drift rejection at the public route boundary before
            private SigningWorker configuration is read:
            `tests/relayer/router-ab-normal-signing-auth-boundary.test.ts`.
      - [x] Ed25519 cross-session scope drift rejection at the public route
            boundary before private SigningWorker configuration is read:
            `tests/relayer/router-ab-normal-signing-auth-boundary.test.ts`.
      - [x] ECDSA-HSS canonical scope, Wallet Session expiry drift, and
            current-time expired request rejection at the private validator
            boundary:
            `tests/unit/thresholdSessionClaims.unit.test.ts`.
      - [x] ECDSA-HSS canonical scope drift rejection at the public route
            boundary:
            `tests/relayer/router-ab-normal-signing-auth-boundary.test.ts`.
      - [x] ECDSA-HSS cross-session canonical scope drift rejection at the
            public route boundary before private SigningWorker configuration is
            read:
            `tests/relayer/router-ab-normal-signing-auth-boundary.test.ts`.
      - [x] Current-time expired request rejection at the public route boundary
            before private SigningWorker configuration is read:
            `tests/relayer/router-ab-normal-signing-auth-boundary.test.ts`.
      - [x] Replayed prepare request id rejection before a second private
            SigningWorker forward for Ed25519 and ECDSA-HSS:
            `tests/relayer/router-ab-normal-signing-auth-boundary.test.ts`.
      - [x] Duplicate presignature handle rejection:
            `tests/unit/routerAbEcdsaHssPresignBridge.unit.test.ts`.
      - [x] Rejected ECDSA-HSS presign-step cleanup and replay/missing-session
            rejection after cleanup:
            `tests/unit/thresholdEcdsa.presignDistributed.unit.test.ts`.
      - [x] Abandoned-prepare cleanup semantics:
            strict SigningWorker round-1 Durable Object cleanup is covered by
            `crates/router-ab-cloudflare/tests/bindings.rs`, and local-dev
            in-memory round-1 cleanup is covered by
            `crates/router-ab-dev/src/lib.rs`.

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
- [x] Local browser unlock-to-sign test passes for Ed25519.
      Evidence on 2026-06-18: `rtk pnpm -C tests exec playwright test
      ./e2e/emailOtp.thresholdEcdsa.tempoSigning.test.ts -g
      "session-mode Email OTP reload signs NEAR and Tempo without another OTP"
      --reporter=line` passed. This covers the reload path that restores the
      Email OTP Ed25519 companion material and signs without a second OTP.
- [x] Local browser unlock-to-sign test passes for ECDSA-HSS Tempo and EVM.
      Evidence on 2026-06-18: `rtk pnpm -C tests exec playwright test
      ./e2e/emailOtp.thresholdEcdsa.tempoSigning.test.ts -g
      "session-mode Email OTP login (bootstraps warm ECDSA capability and signs
      twice|also signs normal EVM eip1559 transactions)" --reporter=line`
      passed for the Tempo-twice and EVM EIP-1559 cases.
- [x] `pnpm router` manages the local Caddy proxy, exactly one public Router
      server, and the three private Router A/B service workers.
      Evidence on 2026-06-18: the focused source guard
      `pnpm router launches one public Router server and three private workers`
      passed, and `rtk pnpm router -- --help` reports Router server
      `127.0.0.1:9090`, Caddy `https://localhost:9444`, Deriver A, Deriver B,
      and SigningWorker as the managed local topology.
- [x] `pnpm router:public-route-smoke` passes with the local site and Router
      workers running.
- [x] `pnpm router:check` validates Ed25519 and ECDSA-HSS through
      `https://localhost:9444`.
      Evidence on 2026-06-18: `rtk pnpm router:check` passed against the live
      local SDK Router plus private-worker topology. The summary reported Ed25519
      `normal_signing_status=ed25519_v1`, ECDSA-HSS
      `ecdsa_hss_prepare_status=http_200_bound`,
      `ecdsa_hss_finalize_status=http_200_signature`, and
      `ecdsa_hss_replay_rejection_status=http_400_one_use_replay_rejected`.
- [x] Source guards pass for no public split routing.

## Phase 8: Final Spec-To-Code Compliance Audit

Run this phase only after all Phase 3 and Phase 4 items are complete, including
deletion of the temporary public Rust Router role.

- [x] Use `/Users/pta/.codex/skills/spec-to-code-compliance/SKILL.md` to audit
      the completed implementation against the Router A/B spec corpus.
- [x] Discover and normalize the relevant spec corpus before comparing code.
      At minimum include this plan plus the Router A/B topology, local-dev,
      single-session, deployment-choice, signing, and cleanup docs that define
      public Router ownership, Wallet Session auth, replay, quota/abuse,
      request binding, private worker boundaries, and Caddy topology.
- [x] Produce a durable audit artifact under `docs/audits/` with:
      - Spec-IR for every extracted intended behavior, invariant, actor,
        trust boundary, timing/order constraint, error condition, and security
        requirement.
      - Code-IR for the public Router route layer, private worker forwarding,
        Wallet Session validation, replay, quota/abuse admission, request
        binding, Caddy topology guards, and local worker orchestration.
      - Alignment-IR mapping every Spec-IR item to code evidence with one of
        `full_match`, `partial_match`, `mismatch`, `missing_in_code`,
        `code_stronger_than_spec`, or `code_weaker_than_spec`.
      - Divergence findings for every mismatch, missing implementation, weaker
        code path, undocumented code path, or ambiguity.
      - The 16-section final report required by the skill.
- [x] Cite exact documentation excerpts and exact code line numbers for every
      audit claim. Low-confidence items must be classified as ambiguous instead
      of inferred.
- [x] If the audit finds any divergence, add a new remediation phase below this
      phase with one checklist item per finding, including severity, evidence,
      remediation, and validation command.
- [x] Mark this phase complete only after the audit has no open Critical, High,
      or Medium divergence findings, or after the newly added remediation phase
      has been implemented and validated.
      Evidence on 2026-06-19:
      `docs/audits/refactor-68b-spec-to-code-compliance-2026-06-19.md`
      found no open Critical, High, or Medium divergences.

## Completion Criteria

- Caddy forwards `https://localhost:9444` to one upstream.
- The main Router route table owns every public route used by the SDK.
- No public signing request depends on Caddy path selection.
- Local dev has one public Router server and three private Router A/B service
  workers.
- Manual Ed25519 and ECDSA-HSS signing tests pass locally before Cloudflare
  deployment work resumes.
- Phase 8 spec-to-code compliance audit has passed, or all audit findings have
  been captured in a follow-up remediation phase and closed.

# Refactor 69C: Router A/B Flow Audit And Slimming Plan

Date created: June 18, 2026

Status: complete for the current Router A/B flow-audit and slimming scope.
The concrete 69B cleanup slices through Phase 8 are complete. Package folding,
server tsconfig isolation, package-export guard validation, hard
server-dependency removal from the browser package, and the public
`@seams/sdk-server` split are implemented. Remaining adjacent work is tracked in
the follow-up plans called out below, not in Refactor 69C.

Follow-up ownership:

- Server-authoritative signing-session budget and step-up behavior:
  [refactor-70-server-budget.md](./refactor-70-server-budget.md).
- Signing grant / naming baseline cleanup:
  [refactor-71-inventory.md](./refactor-71-inventory.md) and
  [refactor-71-rename-id.md](./refactor-71-rename-id.md).
- Login without HSS during unlock and worker-owned material restore:
  [signing-session-architecture](./signing-session-architecture/README.md).
- Ed25519 worker-material simplification:
  [refactor-75-simplify-ed25519.md](./refactor-75-simplify-ed25519.md).
- Broad Router A/B cleanup, strict signable state, and deployment evidence:
  [router-a-b-SPEC.md](./router-a-b-SPEC.md).

Primary source of truth:

- [refactor-68-wallet-session-v2.md](./refactor-68-wallet-session-v2.md)
- [refactor-70-server-budget.md](./refactor-70-server-budget.md)
- [router-a-b-SPEC.md](./router-a-b-SPEC.md)
- [router-a-b-SPEC.md](./router-a-b-SPEC.md)
- [router-a-b-local-dev.md](./router-a-b-local-dev.md)

## Goal

Comprehensively audit every Router A/B flow across SDK web, SDK server, Rust
Router crates, browser/WASM workers, tests, and active docs.

The audit should produce a concrete cleanup backlog for:

- slimming code and deleting bloat
- tightening domain typings and compile-time guards
- reorganizing files so the folder hierarchy shows ownership and legal call
  direction

This plan is intentionally audit-first. Each implementation slice should be
small, independently validated, and scoped to current Router A/B behavior.

## Non-Goals

- Preserve no long-lived compatibility aliases in core logic.
- Keep compatibility handling at persistence and request boundaries only.
- Keep durable `thresholdSessionId` naming where it identifies the concrete
  threshold/MPC protocol session.
- Keep the stable route-auth protocol discriminant `threshold_session` where it
  is part of an intentional wire shape.
- Avoid changing cryptographic protocol semantics, replay gates, quota policy,
  budget accounting, signer-set validation, or canonical digest definitions
  during the audit pass.
- Avoid large file moves before the flow inventory and call-direction map are
  complete.

## Flow Families To Audit

### Ed25519 Router A/B

- Wallet Session minting, reconnect, and persisted-state recovery.
- NEAR transaction signing.
- NEP-413 message signing.
- NEP-461 delegate-action signing.
- Ed25519 presign pool refill, reserve, burn, and finalize.
- Ed25519 HSS bootstrap, reconstruction, missing-relayer-key repair, and
  explicit export.
- Signing budget reads and signing-session seal refresh.
- Local Router A/B smoke and self-hosted browser evidence paths.

### ECDSA-HSS Router A/B

- Wallet registration bootstrap.
- Add-signer bootstrap.
- Passkey Wallet Session reconnect.
- Email OTP Wallet Session bootstrap.
- Role-local bootstrap and export.
- EVM digest normal signing.
- ECDSA-HSS presignature pool fill, owner forwarding, bridge storage, and
  client-side reservation.
- Activation refresh and SigningWorker material binding.
- Key identity, runtime policy scope, signing-root derivation, and key-handle
  validation.

### Worker And Browser Transport

- Email OTP worker wallet unlock.
- Email OTP Ed25519 export.
- Email OTP ECDSA bootstrap, export, warm-session seal, and rehydrate.
- Passkey confirm worker seal and remove-seal paths.
- Wallet iframe request and response payloads.
- SeamsWeb public API inputs.
- Browser public signing surface assembly.

### Server And Rust Router

- Express route adapters.
- Cloudflare route adapters.
- Shared route/service handlers.
- Wallet Session claim signing and validation.
- Strict worker roles: Router, SigningWorker, Deriver A, and Deriver B. Some
  Cloudflare wire/deploy names still use Signer A/B as a historical persisted
  or service-binding name; treat those as compatibility/naming cleanup targets,
  not new role concepts.
- `router-ab-core` public request parsing, canonical digests, protocol
  envelopes, admission, gate logic, and vector generation.
- `router-ab-dev` local worker and bundled local profiles.

## Audit Inventory Template

Create one row per flow. Use a table or one subsection per flow when the row
gets too dense.

```text
Flow:
User-visible entry points:
Internal entry points:
SDK domain builders:
SDK route clients:
Server route adapters:
Shared service handlers:
Rust Router modules:
Worker/WASM modules:
Credential accepted:
Boundary parser:
Internal domain type:
Storage touched:
Replay/quota/budget hooks:
SigningWorker/private route:
Tests:
Source/type guards:
Allowed compatibility exceptions:
Deletion candidates:
Refactor notes:
```

Every row must answer these questions:

- Can a caller reach the flow with an invalid lifecycle state?
- Can a signing-capable path use cookie auth, an app-session token, or a legacy
  threshold-session JWT after the request boundary?
- Is raw JSON, a decoded JWT, a DB record, or a worker payload normalized more
  than once?
- Are identity, auth, session, signing, budget, and restore fields required in
  the internal type?
- Does any branch rely on diagnostics objects for control flow?
- Could a discriminated union replace boolean flags or optional bags?
- Does the folder location make legal callers and ownership obvious?

## Call-Direction Map

For each audited flow, write the shortest accurate call graph.

Example shape:

```text
Public SDK/API
  -> public input parser
  -> domain builder
  -> Router A/B route client
  -> server route adapter
  -> shared route handler
  -> Wallet Session claim parser
  -> service/domain handler
  -> store/admission/policy
  -> private worker or WASM boundary
  -> response parser
  -> persisted capability/readiness state
```

The call graph should make violations easy to spot:

- SDK public APIs should not call low-level route clients directly.
- Worker dispatch should not own domain assembly.
- Route adapters should not own policy or lifecycle logic.
- Store modules should not parse raw request bodies.
- Protocol modules should not depend on UI, browser, iframe, or worker message
  shapes.

## Boundary Audit Rules

For every Router A/B boundary, verify:

- Raw inputs are parsed once into precise internal types.
- Wallet Session JWT auth is the only signing-capable Router A/B SDK
  credential.
- Bearer Router A/B SDK requests use `credentials: 'omit'`.
- Cookie auth appears only in explicitly allowed request or persistence
  compatibility boundaries.
- Public SDK and iframe payloads do not expose `signingRootId` or
  `signingRootVersion`.
- Signing-root identity is derived only at server, protocol, persistence, or
  HSS client-material boundaries.
- SigningWorker private routes receive only Router-admitted material.
- Normal signing public routes never receive or mint per-request signing grants.
- ECDSA-HSS public EVM digest signing and presignature pool fill validate
  Router A/B ECDSA-HSS Wallet Session claims.
- Ed25519 normal signing and presign pool refill validate Router A/B Ed25519
  Wallet Session claims.
- Durable `thresholdSessionId` fields stay separate from the signing allowance
  identifier.

## Slimming And Bloat Removal Opportunities

Prioritize these during the audit.

### Split Oversized Modules

Likely targets:

- `packages/sdk-server-ts/src/core/ThresholdService/ThresholdSigningService.ts`
- `packages/sdk-web/src/core/signingEngine/workerManager/workers/email-otp.worker.ts`
- shared session/warm-capability modules that mix persistence, planning,
  readiness, and route transport
- route files that duplicate Express and Cloudflare logic

Target shape:

- one module for one flow family
- one parser per raw boundary
- one builder per internal domain object
- one route adapter per transport
- one shared handler per route behavior

### Collapse Route Duplication

Express and Cloudflare routes should call shared handlers.

Adapter responsibility:

- read method, path, headers, and body
- call shared handler
- serialize status and body
- attach transport-specific CORS or platform details

Shared handler responsibility:

- parse request
- verify Wallet Session claims
- call service/domain logic
- map domain result to route result

### Server Route Duplicate And Redundancy Audit

Current audit snapshot, June 18 2026:

- Relay route surface: 80 route definitions, 85 concrete `(method, path)` keys
  including aliases, zero exact duplicate keys.
- Relay Express stack with health, ready, signing-session seal, sponsored EVM,
  signed delegate, and custom session-state paths enabled: 85 concrete routes,
  zero exact duplicate `(method, path)` registrations.
- Console route surface: 100 route definitions, zero exact duplicate keys.
- Console Express stack with health and ready enabled: 103 concrete routes, zero
  exact duplicate `(method, path)` registrations.
- Console live-only routes outside the route surface are
  `GET /console/healthz`, `GET /console/readyz`, and
  `POST /console/billing/stripe/webhook`.

Intentional aliases:

- Router A/B public keyset is exposed at `/router-ab/keyset`,
  `/.well-known/router-ab/keyset`, and trailing-slash variants.
- Related Origin Requests is exposed at `/.well-known/webauthn` and
  `/.well-known/webauthn/`.
- Custom session-state routes intentionally keep `/session/state` as an alias
  when the configured primary path differs.

Semantic overlaps found:

- `GET /v1/wallets/search` overlaps `GET /v1/wallets/:id`, with the static
  search route registered first.
- `GET /console/wallets/search` overlaps `GET /console/wallets/:id`, with the
  static search route registered first.

These overlaps are currently safe. Add a guard that rejects parameterized routes
registered before overlapping static routes so future edits cannot invert the
order.

Redundancy candidates to audit before deleting anything:

- Route behavior is duplicated across Express and Cloudflare adapters. Extract
  shared handlers first, then leave adapters as transport shims.
- Some route files mount literal paths while others mount paths from
  `RouteDefinition`. Move toward route-definition-owned mounting so path,
  policy, aliases, and tests share one source of truth.
- `login/verify` and `login/verify-and-unseal` may be a convenience split.
  Keep only if the inventory shows real client lifecycle value.
- `email-otp/unseal` and `email-otp/signing-session/unseal` should be reviewed
  after the Email OTP operation model is captured as discriminated state.
- Global relay health, curve-specific Router A/B health, and console health
  routes should be documented by deploy unit. Delete any probe that is not tied
  to a distinct runtime or monitor.
- Console health/readiness and Stripe webhook routes sit outside the console
  route surface. Either keep them as an explicit public/webhook surface or add a
  typed route-surface branch with non-console auth semantics.

Validation used for this snapshot:

```sh
rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/router.relayRouteSurface.unit.test.ts --reporter=line
```

The numeric route-count snapshot is informational until the route-count audit is
checked in as a reproducible script or test. Do not use an ad hoc `tsx -e`
snippet as release evidence.

### Centralize Auth And Transport

Create one SDK-side Router A/B credential module per curve:

- Ed25519 Wallet Session credential builder.
- ECDSA-HSS Wallet Session credential builder.
- Shared bearer header builder.
- Shared `credentials: 'omit'` enforcement.

Create one server-side Wallet Session claim boundary:

- Ed25519 Wallet Session parser.
- ECDSA-HSS Wallet Session parser.
- route error mapping.
- typed verified claims.

### Delete Legacy-Only Tests And Fixtures

Review tests, fixtures, mocks, and source guards for obsolete behavior:

- old per-request normal-signing grants
- legacy threshold-session JWT kinds in active signing
- cookie-backed signing-capable sessions
- public signing-root fields
- old presign pool routes
- non-Router threshold signing stacks

Keep compatibility tests only at request and persistence boundaries where the
current product still intentionally supports migration reads.

## Confirmed Bloat Cuts From Refactor 69B

This section absorbs the concrete implementation backlog from
`refactor-69B-reduce-bloat.md`. These cuts were already pre-audited and are more
specific than the general flow-audit checklist above. Keep them as reviewable
implementation slices while this document acts as the main Router A/B slimming
plan.

### 69B Goal

Reduce bloat in the Router A/B Rust crates without changing the active
production signing model.

Scope:

- `crates/router-ab-core`
- `crates/router-ab-cloudflare`
- `crates/router-ab-dev`

The cleanup should delete stale compiled paths, move evidence-only APIs out of
runtime exports, and collapse duplicated local/Cloudflare adapter boilerplate.
The resulting code should read as if `mpc_threshold_prf_v1`, Wallet Session
Router A/B signing, and pool-backed ECDSA-HSS signing had always been the only
active behavior.

### 69B Security-Critical Boundaries

Do not weaken these invariants:

- Router A/B-only signing for Ed25519 and ECDSA-HSS.
- Wallet Session claim validation on signing-capable public Router routes.
- Internal service-auth headers on private worker/service-binding routes.
- One-use replay, nonce, round-1, and presignature storage.
- Pool-backed ECDSA-HSS prepare/finalize binding.
- Router-admitted material only on SigningWorker private routes.
- A/B role separation and root-share secrecy.
- Durable protocol wire names, route versions, and persisted record versions
  that are still active contracts.

Compatibility is allowed only at request or persistence boundaries. Core runtime
types should model the current selected behavior directly.

### 69B Phase 1: Prune Generated Startup-Latency Reports

Status: complete on June 20, 2026.

Completion note: no generated startup-latency JSON files are tracked, and
`.gitignore` excludes `crates/router-ab-cloudflare/reports/startup-latencies/*.json`.
The remaining startup-time evidence item in
`docs/router-a-b-deployment.md` is deployment evidence, not generated-report
cleanup.

Delete committed generated startup-latency JSON files from
`crates/router-ab-cloudflare/reports/startup-latencies`.

Keep:

- `crates/router-ab-cloudflare/scripts/measure-startup-latencies.mjs`
- current package scripts that run the measurement
- one canonical docs summary or audit entry for release evidence

Update docs that link to deleted report files:

- `docs/router-a-b-SPEC.md`
- `docs/router-a-b-SPEC.md`
- `docs/router-a-b-SPEC.md`
- `docs/router-a-b-local-dev.md`
- `docs/router-a-b-SPEC.md`
- deployment docs and audits that reference exact report paths

Add or confirm an ignore rule so new report output is generated outside the
tracked tree or under an ignored reports directory.

Validation:

- `rtk git status --short`
- `rtk rg "startup-latencies-[0-9]{4}" docs crates/router-ab-cloudflare`

### 69B Phase 2: Retire Stale Core Dev Signer Smoke

Status: complete on June 18, 2026.

Remove the stale core dev smoke path after confirming current local evidence
uses `router:smoke` and `router:smoke:bundled`.

Cut:

- `crates/router-ab-core/src/bin/dev_router_ab_signer.rs`
- `router:dev:signer` command in the root `package.json`
- `dev-signer` branch in `crates/router-ab-dev/scripts/local-command.mjs`
- docs that list `dev_router_ab_signer.rs` as an active evidence path

Keep:

- vector emit binaries while they are still used for committed vector fixtures
- `router_ab_local_smoke`
- `router_ab_local_bundled`
- `router_ab_local_release_evidence`

Validation:

- `rtk rg "dev_router_ab_signer|router:dev:signer|dev-signer" package.json crates docs/router-a-b-SPEC.md docs/audits --glob '!**/target/**'`
- `rtk cargo check --manifest-path crates/router-ab-core/Cargo.toml`
- `rtk cargo check --manifest-path crates/router-ab-dev/Cargo.toml`

### 69B Phase 3: Delete Generic Direct ECDSA-HSS Prepare Handler

Status: complete on June 18, 2026. Runtime package folding,
`sdk-server-ts` tsconfig isolation, shared type moves, public runtime value
exports, package-export guard updates, hard server-dependency removal from
browser installs, and the later `@seams/sdk-server` package split are
implemented.

Delete only the stale direct generic prepare path. The active strict
SigningWorker prepare route must continue to use the pool-backed path:

`handle_cloudflare_signing_worker_ecdsa_hss_evm_digest_prepare_private_fetch_from_pool_v1`

Cut:

- `CloudflareSigningWorkerEcdsaHssEvmDigestPrepareHandlerV1`
- `handle_cloudflare_signing_worker_ecdsa_hss_evm_digest_prepare_private_request_v1`
- `handle_cloudflare_signing_worker_ecdsa_hss_evm_digest_prepare_private_fetch_v1`
- tests and source guards that assert the old direct prepare helper path
- test-only `TestEcdsaHssEvmDigestPrepareHandler`

Keep:

- `prepare_cloudflare_role_separated_ecdsa_hss_evm_digest_from_pool_record_v1`
- pool take lookup and validation
- `signing_worker_ecdsa_presignature_pool_take_call`
- `require_signing_worker_ecdsa_presignature_pool_take_response_v1`
- `signing_worker_ecdsa_presignature_put_call`
- finalize handler and finalize private fetch path
- source guards that enforce pool-backed strict dispatch
- Router service call paths and response validation

Validation:

- `rtk rg "CloudflareSigningWorkerEcdsaHssEvmDigestPrepareHandlerV1|handle_cloudflare_signing_worker_ecdsa_hss_evm_digest_prepare_private_fetch_v1|handle_cloudflare_signing_worker_ecdsa_hss_evm_digest_prepare_private_request_v1" crates/router-ab-cloudflare`
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml ecdsa_hss --test bindings`
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test source_guards`

### 69B Phase 4: Remove Split-Root From Compiled Runtime API

Status: complete on June 18, 2026.

`SplitRootDerivationV1` is no longer an active compiled candidate. Runtime
types should expose only the selected production candidate.

Cut from compiled API:

- `CandidateId::SplitRootDerivationV1`
- boundary parser acceptance for `"split_root_derivation_v1"`
- contract vectors that require split-root contexts
- compiled tests that exercise split-root comparison behavior
- benchmark report entries that treat split-root as current runtime state

Keep rejection coverage:

- external/request parsing should reject `"split_root_derivation_v1"` with
  `UnsupportedCandidate`
- source guard should continue to assert `candidate_split_root.rs` and split-root
  public APIs are absent
- docs may retain historical comparison material outside compiled tests

Implementation notes:

- Update `CandidateId::as_str` to return only `mpc_threshold_prf_v1`.
- Update `parse_candidate_id_v1` and any signer/plaintext parser so split-root
  strings reject at the boundary.
- Move historical split-root vector/comparison content to docs or audit
  artifacts if it remains useful.
- Update tests that currently build sample contexts with split-root to use
  `MpcThresholdPrfV1`, unless the test is specifically rejection coverage.

Validation:

- `rtk rg "SplitRootDerivationV1|CandidateId::SplitRootDerivationV1" crates/router-ab-core/src crates/router-ab-core/tests crates/router-ab-core/benches`
- `rtk cargo test --manifest-path crates/router-ab-core/Cargo.toml`
- `rtk cargo check --manifest-path crates/router-ab-core/Cargo.toml --benches`
- `rtk cargo test --manifest-path crates/threshold-prf/Cargo.toml --test vectors`
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test source_guards`

### 69B Phase 5: Move Measurement-Gate Runtime Exports To Docs/Benches

Status: complete on June 18, 2026.

`crates/router-ab-core/src/derivation/bench.rs` is evidence/reporting logic. It
does not need to be public runtime API.

Cut:

- public re-exports of `candidate_measurement_gate_report_v1`
- public report structs used only by the measurement-gate runtime API
- tests that assert the runtime measurement-gate API shape
- docs that instruct consumers to call the runtime report function

Keep:

- Criterion benchmark targets
- benchmark commands in docs
- a static docs summary of current evidence
- generated or measured benchmark output as ignored artifacts

Possible target shape:

- `crates/router-ab-core/benches/derivation_candidates.rs` remains executable
  evidence.
- `docs/router-a-b-SPEC.md` or an audit doc summarizes the selected
  candidate evidence.
- Compiled library API exposes protocol behavior, not release evidence reports.

Validation:

- `rtk rg "candidate_measurement_gate_report_v1|candidate_round_trip_profiles_v1|selected_candidate_protocol_wire_profiles_v1|CANDIDATE_MEASUREMENT_GATES_VERSION_V1" crates/router-ab-core/src crates/router-ab-core/tests docs/audits docs/router-a-b-SPEC.md`
- `rtk cargo test --manifest-path crates/router-ab-core/Cargo.toml`
- Run Criterion only if the bench code itself changes.

### 69B Phase 6: Add A Typed Cloudflare Service POST Helper

Status: complete on June 18, 2026.

Implemented private `post_service_json` and converted the Cloudflare
service-binding POST call sites in `crates/router-ab-cloudflare/src/lib.rs`:

- Deriver recipient proof-bundle service calls.
- ECDSA-HSS Deriver registration/export/recovery/activation-refresh service
  calls.
- SigningWorker proof-bundle activation, direct delivery, and
  ECDSA-HSS activation/activation-refresh service calls.
- Normal-signing prepare/finalize/presign-pool service calls.
- ECDSA-HSS prepare/finalize service calls.
- Direct A/B peer service calls.

Collapse repeated Service Binding POST boilerplate in
`crates/router-ab-cloudflare/src/lib.rs`.

Add one private helper that owns the common mechanics:

```rust
async fn post_service_json<TReq, TResp>(
    env: &worker::Env,
    binding_name: &str,
    url: &str,
    label: &str,
    request: &TReq,
) -> RouterAbProtocolResult<TResp>
where
    TReq: Serialize,
    TResp: DeserializeOwned,
{
    // build JSON body
    // set content-type
    // set internal service-auth header
    // fetch service binding
    // require 2xx
    // parse typed JSON response
}
```

The helper must not choose routes, build domain requests, or validate protocol
bindings. Endpoint-specific functions still own:

- peer role checks
- request construction
- endpoint URL selection
- response branch validation
- request/response binding checks
- normal-signing and ECDSA-HSS-specific digest checks

Likely targets:

- `execute_cloudflare_signer_recipient_proof_bundle_service_call_v1`
- ECDSA-HSS deriver registration/export/recovery/refresh service calls
- SigningWorker activation and direct delivery service calls
- normal-signing prepare/finalize/presign-pool service calls
- ECDSA-HSS prepare/finalize service calls
- direct A/B peer service calls

Validation:

- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings`
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test source_guards`
- `rtk pnpm -C crates/router-ab-cloudflare test:wasm-vectors` only if wasm-facing helpers move

### 69B Phase 7: Collapse Local Worker And Bundled HTTP Duplication

Status: complete on June 18, 2026.

Implemented shared local HTTP plumbing in `crates/router-ab-dev/src/lib.rs`:

- `LocalDevHttpRequestPartsV1` request parsing.
- Shared JSON response writing and route error body construction.
- Shared Wallet Session bearer authorization and internal service-auth checks.
- `LocalDevHttpTopologyV1` with `FourWorker` and `Bundled` branches.
- One dispatcher for Router public signing routes, Deriver peer routes,
  SigningWorker activation, and private SigningWorker signing routes.
- Ed25519 normal-signing Router wrappers now build admitted private
  SigningWorker requests and include internal service auth before forwarding.

`router_ab_local_worker.rs` and `router_ab_local_bundled.rs` now keep process
startup, env loading, socket accept loops, and topology selection only.

`router_ab_local_worker.rs` and `router_ab_local_bundled.rs` duplicate HTTP
request parsing, response writing, auth helpers, and route branching.

Target shape:

- one local HTTP parser/response helper shared by both binaries
- one route dispatcher that takes a topology/runtime enum
- topology-specific branches only where behavior differs

Preserve:

- four-worker routing and owned-path rejection
- bundled single-server routing
- Wallet Session authorization on public signing-capable routes
- internal service-auth on private SigningWorker ECDSA-HSS pool/prepare/finalize
  routes
- health/readiness response behavior
- existing smoke-test URLs and CLI flags

Suggested internal state:

```rust
enum LocalHttpTopology<'a> {
    FourWorker(&'a LocalWorkerRoleConfigV1),
    Bundled {
        signing_worker: LocalSigningWorkerConfigV1,
    },
}
```

Keep the implementation boring. Avoid introducing an HTTP framework for this
dev-only binary.

Validation:

- `rtk cargo test --manifest-path crates/router-ab-dev/Cargo.toml --test local_worker_env`
- `rtk cargo test --manifest-path crates/router-ab-dev/Cargo.toml --test local_worker_http`
- `rtk pnpm router:smoke`
- `rtk pnpm router:smoke:bundled`

### 69B Phase 8: Reduce TypeScript SDK Package Boundary Bloat

Status: complete for the current branch package/runtime scope on June 19, 2026.

Implementation notes:

- `packages/sdk-runtime-ts` has been folded into `packages/sdk-web`.
- Neutral NEAR action/delegate and WebAuthn option shapes now live in
  `packages/shared-ts`.
- `packages/sdk-server-ts` owns server-local NEAR and EVM RPC helpers instead
  of importing browser SDK clients.
- `packages/sdk-server-ts/tsconfig.json` no longer extends
  `packages/sdk-web/tsconfig.json` and no longer has an `@/*` web alias.
- Current packaging decision: `@seams/sdk` is browser/runtime/react only, and
  `packages/sdk-server-ts` publishes as `@seams/sdk-server` for root server APIs,
  router adapters, Postgres stores, and server WebAuthn helpers. The old
  `@seams/sdk/server` subpaths have been deleted.
- The server package owns server dependencies such as `pg`, Express, and
  `@simplewebauthn/server`. Browser installs of `@seams/sdk` no longer carry
  server dependencies or optional server peers.
- Package export guard validation now asserts the canonical
  `dist/types/sdk-web/...` declaration paths and the public
  `@seams/sdk/runtime` value exports. It also asserts `pg` and
  `@simplewebauthn/server` stay out of hard browser dependencies.
- Package install smoke validation now covers browser/runtime imports without
  server dependencies, verifies the old `@seams/sdk/server` subpath is gone, and
  verifies `@seams/sdk-server` imports root server APIs, router adapters, and
  Postgres storage helpers.
- The `core/runtime` import inventory is recorded in
  `docs/refactor-69D-cleanup-2.md`; current imports are sdk-web composition
  ports, runtime services, signing-flow ports, state ports, or sdk-web internal
  types. The source guard now also blocks server-only package imports from
  `core/runtime`.

The TypeScript workspace currently has two public packages and one private
shared source package:

- `packages/sdk-web`: public `@seams/sdk` package and browser SDK source
- `packages/sdk-server-ts`: public `@seams/sdk-server` package and server SDK
  source
- `packages/shared-ts`: private shared utility/protocol package

The useful boundaries are `sdk-web`, `sdk-server-ts`, and `shared-ts`.
`sdk-runtime-ts` was too small and too coupled to `sdk-web` to justify a
separate package, so it has been folded back into `sdk-web`.

Todo:

- [x] Move `packages/sdk-runtime-ts/src/runtime` to
      `packages/sdk-web/src/core/runtime`.
- [x] Keep the public `@seams/sdk/runtime` export working from
      `packages/sdk-web/src/runtime.ts`.
- [x] Delete `packages/sdk-runtime-ts/package.json`,
      `packages/sdk-runtime-ts/tsconfig.json`, and its `pnpm-workspace.yaml` entry.
- [x] Remove runtime aliases for `@seams-internal/runtime` and
      `@/core/runtime` that point outside `packages/sdk-web`.
- [x] Update `packages/sdk-web/rolldown.config.ts`, `tsconfig*.json`, and
      `tests/tsconfig.playwright.json` after the runtime move.
- [x] Keep or strengthen the runtime-entry guard so `@seams/sdk/runtime` still
      avoids React, DOM, iframe, IndexedDB, and browser adapter imports.
- [x] Keep `packages/shared-ts` as a separate internal package. It is the real
      shared protocol/utility boundary used by web, server, tests, and the app.
- [x] Keep `packages/sdk-server-ts` as a separate source package, then isolate
      it from the web package by giving it a server-oriented tsconfig instead of
      extending `packages/sdk-web/tsconfig.json`.
- [x] Remove server imports from `packages/sdk-web/src/core` by moving the small
      shared NEAR action/client types into `packages/shared-ts` or server-local
      modules.
- [x] Remove the `@/*` web alias from `packages/sdk-server-ts/tsconfig.json`
      once the server no longer imports web-core files.
- [x] Move server exports to the separate public `@seams/sdk-server` package.
- [x] Move server-only runtime dependencies out of hard browser installs.
      Browser consumers should not hard-install `pg` or
      `@simplewebauthn/server`.
- [x] Fix `tests/unit/refactor51bPackageExports.unit.test.ts` so it asserts the
      canonical `dist/types/sdk-web/...` declaration paths and keeps
      `@seams/sdk/runtime` value exports covered.
- [x] Update package docs that describe the four-package layout.

Keep:

- public browser exports from `@seams/sdk`
- public React exports from `@seams/sdk/react`
- public runtime export from `@seams/sdk/runtime`
- public server exports from `@seams/sdk-server`
- shared domain parsers, constants, and wire helpers in `shared-ts`

Validation:

- `rtk rg "@seams-internal/runtime|\\.\\./sdk-runtime-ts|RUNTIME_SRC_ROOT_ABS" packages tests`
- `rtk pnpm -C packages/sdk-web type-check`
- `rtk pnpm -C packages/shared-ts type-check`
- `rtk pnpm -C packages/sdk-server-ts type-check`
- `rtk pnpm -C tests test:source-guards`
- `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/refactor51bPackageExports.unit.test.ts --reporter=line`
- `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/refactor51bPackageInstallSmoke.unit.test.ts --reporter=line`
- `rtk pnpm -C packages/sdk-web build:prepare`

Current validation note: the targeted Phase 8 package/runtime checks pass. The
full `rtk pnpm -C tests test:source-guards` suite still fails on broader guard
debt outside this package-boundary slice. Those failures are scoped to the
Router A/B signing-state, architecture, fixture, and local harness cleanup
tracked under the completed Router A/B cleanup, not to
this package-boundary phase.

### 69B Execution Order

1. Delete committed generated reports and update docs.
2. Retire `router:dev:signer`.
3. Remove the generic direct ECDSA-HSS prepare handler path.
4. Remove split-root from compiled runtime API and tests.
5. Move measurement-gate runtime exports to docs/benches.
6. Add the Cloudflare `post_service_json` helper.
7. Collapse local worker/bundled HTTP dispatch.
8. Fold `sdk-runtime-ts` into `sdk-web` and tighten TypeScript package
   boundaries.

The first seven phases shrink the Rust Router A/B surface and local-dev
plumbing before the TypeScript package-boundary cleanup. Keep each phase
independently reviewable. Phase 8 is adjacent TypeScript package-boundary
cleanup and can land separately from the Rust Router A/B cuts.

### 69B Completion Criteria

- `SplitRootDerivationV1` is gone from compiled public runtime types.
- External `"split_root_derivation_v1"` input is rejected at the boundary.
- Strict ECDSA-HSS prepare dispatch remains pool-backed.
- Direct generic ECDSA-HSS prepare handler code is gone.
- `router:dev:signer` and its core binary are gone or aliased to current smoke
  evidence.
- Startup-latency report JSON is no longer committed as generated output.
- `router-ab-core` runtime API no longer exports measurement-gate report
  builders.
- Cloudflare service-binding boilerplate is centralized without bypassing
  endpoint-specific validation.
- Local worker and bundled dispatch share HTTP plumbing while preserving auth
  and topology behavior.
- `packages/sdk-runtime-ts` is gone or replaced by a real independent runtime
  package with no web/server alias leakage.
- Browser installs no longer hard-require `pg` or `@simplewebauthn/server`.
- Server APIs are published from `@seams/sdk-server`; old
  `@seams/sdk/server` subpaths are gone.

## Typing And Compile-Time Guard Opportunities

### Branded Wallet Session JWTs

Introduce branded curve-specific JWT types after server claim validation and
SDK boundary parsing:

```ts
type RouterAbEd25519WalletSessionJwt = string & {
  readonly __kind: 'router_ab_ed25519_wallet_session_jwt';
};

type RouterAbEcdsaHssWalletSessionJwt = string & {
  readonly __kind: 'router_ab_ecdsa_hss_wallet_session_jwt';
};
```

Then require branch-specific credentials:

```ts
type Ed25519RouterAbCredential = {
  curve: 'ed25519';
  walletSessionJwt: RouterAbEd25519WalletSessionJwt;
};

type EcdsaHssRouterAbCredential = {
  curve: 'ecdsa_hss';
  walletSessionJwt: RouterAbEcdsaHssWalletSessionJwt;
};
```

### Signing-Capable State Builders

Replace ad hoc object literals with branch-specific builders only where a
builder removes invalid states or repeated boundary validation:

- `buildEd25519RouterAbReadyState`
- `buildEcdsaHssRouterAbReadyState`
- `buildEd25519PresignPoolScope`
- `buildEcdsaHssPresignaturePoolScope`
- `buildWalletSigningBudgetStatusAuth`
- `buildEmailOtpEcdsaWorkerBootstrapPayload`

Builders should return exact discriminated union branches and reject:

- missing Wallet Session JWT
- `sessionKind: 'cookie'`
- missing `thresholdSessionId`
- missing signing allowance id
- missing participant ids
- mismatched curve or chain target
- public signing-root fields in non-boundary payloads

### Type Fixtures

Add or extend `*.typecheck.ts` fixtures for:

- old `thresholdSessionAuthToken`
- old public normal-signing grant fields
- broad object-spread lifecycle construction
- raw JWT strings where branded Wallet Session JWTs are required
- Ed25519 credential passed to ECDSA-HSS route clients
- ECDSA-HSS credential passed to Ed25519 route clients
- `sessionKind: 'cookie'` in signing-capable states
- `signingRootId` / `signingRootVersion` in public SDK and worker payloads
- optional identity/auth/session/signing/budget fields in core functions

### Source Guards

Add exact-allowlist source guards for:

- `thresholdSessionAuthToken`
- `routerAbNormalSigningGrant`
- legacy Wallet Session JWT kinds
- `sessionKind: 'cookie'`
- `credentials: 'include'`
- public `signingRootId` / `signingRootVersion`
- `parseThresholdEd25519SessionClaims`
- `parseThresholdEcdsaSessionClaims`
- old v1 normal-signing public route helpers

Allowlist only:

- docs that intentionally describe deleted behavior
- negative type fixtures
- persistence/request compatibility parsers
- stable wire discriminants such as `threshold_session`
- durable identifiers such as `thresholdSessionId`

## Proposed Folder Reorganization

The folder hierarchy should communicate ownership and legal imports. Treat this
as a menu of extraction targets, not a folder scaffold. Move files only when the
call graph proves a real ownership boundary, a duplicated route handler can be
deleted, or an invalid import direction can be guarded.

Proposed target shape:

```text
packages/sdk-web/src/core/signingEngine/routerAb/
  shared/
    credential.ts
    routeAuth.ts
    routeResult.ts
    ids.ts
    policyScope.ts
  ed25519/
    readyState.ts
    requestBuilders.ts
    routeClient.ts
    hssLifecycle.ts
    presignPool.ts
    budgetStatus.ts
  ecdsaHss/
    readyState.ts
    requestBuilders.ts
    routeClient.ts
    roleLocalBootstrap.ts
    roleLocalExport.ts
    presignaturePool.ts
    poolFillClient.ts
    keyIdentity.ts
    signingRootBoundary.ts
  workers/
    emailOtp/
      messageParser.ts
      walletUnlock.ts
      ed25519Export.ts
      ecdsaBootstrap.ts
      ecdsaRehydrate.ts
      sealTransport.ts
    passkeyConfirm/
      sealTransport.ts
```

```text
packages/sdk-server-ts/src/routerAb/
  http/
    express/
      adapters.ts
    cloudflare/
      adapters.ts
    handlers/
      ed25519.ts
      ecdsaHss.ts
      sessions.ts
  walletSession/
    claims.ts
    signing.ts
    budgetStatus.ts
  ed25519/
    hss.ts
    normalSigning.ts
    presignPool.ts
    repair.ts
  ecdsaHss/
    bootstrap.ts
    export.ts
    normalSigning.ts
    activation.ts
    presignaturePool.ts
    poolFill.ts
  stores/
  policies/
```

```text
crates/router-ab-core/src/
  public_request/
    ed25519.rs
    ecdsa_hss.rs
  admission/
  protocol/
    ed25519/
    ecdsa_hss/
  derivation/
  vectors/
```

Import direction should be one-way:

```text
public API / iframe / worker message
  -> boundary parser
  -> domain builder
  -> flow service
  -> route client or store
  -> protocol/WASM boundary
```

Lower layers should not import from public API, iframe, UI, or worker message
modules.

## Audit Phases

### Phase 1: Inventory And Call Graphs

Status: complete on June 18, 2026.

Audit artifact:

- [refactor-69c-router-ab-flow-inventory-2026-06-18.md](./audits/refactor-69c-router-ab-flow-inventory-2026-06-18.md)

Task list:

- [x] Build the flow inventory table.
- [x] Write call graphs for every flow family.
- [x] Identify all public/request/persistence boundaries.
- [x] Mark every intentional compatibility exception.
- [x] Record current tests and guards per flow.
- [x] Write the Phase 1 audit artifact under `docs/audits/`.

Validation:

```sh
rtk rg -n "routerAb|RouterAb|router-ab|Wallet Session|walletSessionJwt" packages crates tests docs
```

### Phase 2: Auth And Boundary Invariants

Status: complete on June 18, 2026.

Audit notes:

- Active Router A/B SDK signing clients use Wallet Session bearer material and
  `credentials: 'omit'`.
- Cookie-backed `credentials: 'include'` hits are outside active Router A/B
  signing, mainly UI/email-OTP request boundaries that still need separate
  product-flow review before deletion.
- Active server signing, seal, and budget paths use Router A/B Wallet Session
  claim parsers. Legacy threshold-session parsers remain only in validation and
  compatibility/test boundaries with explicit deletion comments.
- Source guards caught one local runtime fixture marker in
  `crates/router-ab-dev/src/lib.rs`; the local normal-signing material selector
  now derives the committed fixture choice from the request scope instead of
  pinning one fixture in runtime code.

- [x] Verify every active signing-capable SDK flow requires Wallet Session JWT
      material.
- [x] Verify bearer calls use `credentials: 'omit'`.
- [x] Verify cookie auth is isolated to allowed request or persistence
      boundaries.
- [x] Verify legacy threshold-session JWT parsers are absent from active
      signing.
- [x] Verify worker payload parsers reject old fields and invalid session kinds.
- [x] Remove committed smoke fixture markers from local runtime source.
- [x] Tighten source guards so committed fixture names and fixture account ids
      cannot re-enter local runtime files.

Validation:

```sh
rtk rg -n "thresholdSessionAuthToken|routerAbNormalSigningGrant|prepareRouterAbNormalSigningV1|finalizeRouterAbNormalSigningV1" packages tests crates
rtk rg -n "sessionKind: 'cookie'|credentials: 'include'|parseThresholdEd25519SessionClaims|parseThresholdEcdsaSessionClaims" packages tests
rtk pnpm -C tests exec playwright test -c playwright.source.config.ts unit/routerAbNormalSigningSdk.guard.unit.test.ts unit/routerAbServerWalletSessionClaimBoundary.guard.unit.test.ts --reporter=line
rtk cargo check --manifest-path crates/router-ab-dev/Cargo.toml --lib
```

### Phase 3: Type Model Audit

Status: complete on June 19, 2026.

Resolved findings:

- Sealed restore metadata still models signable Ed25519/ECDSA state with
  optional Wallet Session JWT fields and raw material fields. Treat it as a
  request/persistence boundary until Phase 15.10 deletes raw-material
  compatibility.
- Persisted Ed25519 and ECDSA session records still allow optional Router A/B
  normal-signing state because old records can be read, but active signing now
  crosses through strict signable in-memory record parsers before use.
- Final NEAR/EVM signing ready-state types no longer expose optional
  `xClientBaseB64u`, `clientVerifyingShareB64u`, or optional Router A/B material
  fields at active signing boundaries.
- ECDSA final signing now routes through `ReadyEcdsaSignerSession`, Router A/B
  normal-signing state, and handle-only ready-session client-share branches.

- [x] Scan Router A/B signing state for optional identity, auth, session, and
      raw-material fields.
- [x] Record the Phase 3 type-model targets in the audit artifact.
- [x] Split persisted compatibility records from signable in-memory records.
      Current progress: - [x] Added
      `packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts`
      as the Router A/B persisted-record classifier and strict
      signable Wallet Session boundary for Ed25519 and ECDSA-HSS. - [x] Added
      `packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.typecheck.ts`
      to reject missing auth/session/signing-root/material fields and
      raw material on signable Wallet Session records. - [x] Added
      `tests/unit/signingCapabilityStrictRecords.unit.test.ts` to prove
      selected signing capability reads expose only complete Router A/B
      signable records.
- [x] Require worker-owned Ed25519 material handles at final NEAR signing
      ready-state boundaries.
- [x] Add HSS worker store/open-by-handle operations for ECDSA-HSS role-local
      signing material.
- [x] Route final EVM role-local signing-share opening through the ECDSA-HSS
      worker material handle.
- [x] Convert EVM final signing to a handle-only signable ECDSA session union
      after loading role-local material into the HSS worker.
- [x] Replace the ECDSA-HSS `role_local_ready_state_blob` ready-session branch
      with a handle-only signable branch.
      Current progress: - [x] `ReadyEcdsaSignerSession.clientShare` is now handle-only:
      persisted `role_local_ready_state_blob` backend bindings are
      converted to deterministic `role_local_worker_share` handles at the
      signer-session boundary. - [x] The secp256k1 final signing material carries an explicit
      role-local restore record only at the final worker-restore boundary,
      preserving reload repair without reintroducing raw blobs into the
      ready signer-session union. - [x] Type fixtures reject raw role-local blob client-share branches on
      signable ready sessions.
- [x] Keep raw Ed25519 `xClientBaseB64u` / `clientVerifyingShareB64u` fields
      behind reconstruction or persistence boundary parsers.
      Current progress: - [x] `RouterAbEd25519SigningWalletSession`,
      `NearResolvedEd25519SigningSessionState`, and
      `RouterAbEd25519NormalSigningReadyState` now carry a required
      `signingMaterial` ref instead of top-level Ed25519 material fields. - [x] `xClientBaseB64u` remains confined to persistence/repair and worker
      material reconstruction paths; final NEAR signing receives only a
      worker material handle, binding digest, and verifier through the
      parsed material ref. - [x] Type fixtures reject obsolete top-level raw verifier fields and
      missing material refs at the strict Wallet Session and ready-state
      boundaries.
- [x] Keep raw ECDSA client share/verifying-share fields behind worker,
      registration, or persistence boundary parsers.
      Current progress: - [x] Added a strict Router A/B ECDSA-HSS Wallet Session signing material
      ref so selected signable Wallet Session records expose the public
      verifier through parsed `signingMaterial`, not top-level persisted
      verifier field names. - [x] The ECDSA signable Wallet Session parser now rejects missing
      persisted client verifier material and verifier drift between the
      persisted record and Router A/B normal-signing scope. - [x] Finish the ready signer transport cleanup so active EVM signing code
      consumes the same parsed material ref instead of direct
      `clientVerifyingShareB64u` transport fields.
- [x] Review domain lifecycle unions.
      Current progress: - [x] Tightened warm-session capability lifecycle branches so `ready` and
      `material_pending` ECDSA states require ready Wallet Session auth
      and a warm PRF claim, ECDSA no longer exposes an impossible
      `invalid` branch, and Ed25519 non-`auth_missing` states require
      bearer Wallet Session auth.
- [x] Review session, budget, signing, restore, auth, and protocol state types.
      Current progress: - [x] Confirmed remaining optional fields in this Phase 3 audit are
      builder inputs, dependency/config ports, UI/display surfaces,
      availability diagnostics, or request/persistence compatibility
      boundaries. The full server budget reservation lifecycle remains
      tracked in `docs/refactor-70-server-budget.md`.
- [x] Add missing `never` exclusions.
      Current progress: - [x] Existing strict Router A/B signable Wallet Session, ready-state,
      ECDSA identity, and sealed recovery boundary fixtures now cover the
      raw-material and legacy auth-field exclusions found in the Phase 3
      scan.
- [x] Replace optional core identity fields with required fields where the flow can
      require them.
      Current progress: - [x] `NearResolvedEd25519SigningSessionState` now requires signing root,
      runtime policy scope, Router A/B normal-signing state, and bearer
      Wallet Session auth at the active NEAR signing boundary.
- [x] Add type fixtures for known escape hatches.
      Current progress: - [x] Added
      `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signers/ecdsaHssClientSigningMaterialSource.typecheck.ts`
      to prove the final ECDSA-HSS signing material boundary rejects raw
      `role_local_ready_state_blob` client-share material after worker
      handle loading. - [x] Added resolved Ed25519 Wallet Session state fixtures rejecting
      cookie auth and missing signing root, runtime policy scope, or
      Router A/B state. - [x] Added warm-session lifecycle fixtures rejecting Ed25519 `ready`
      without bearer auth, ECDSA `ready` without a warm PRF claim, and
      the impossible ECDSA `invalid` lifecycle branch.

Validation:

```sh
rtk pnpm -C packages/sdk-web run type-check
rtk pnpm -C packages/sdk-server-ts run type-check
```

Latest focused validation for the Ed25519 raw-material boundary slice:

```sh
pnpm -C packages/sdk-web type-check
pnpm -C packages/sdk-web build:prepare
pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/routerAbEd25519.walletSessionState.unit.test.ts unit/signingCapabilityStrictRecords.unit.test.ts unit/thresholdEd25519.hssMaterialHandle.unit.test.ts --reporter=line
git diff --check -- packages/sdk-web/src/core/signingEngine/threshold/ed25519/hssMaterialBinding.ts packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.typecheck.ts packages/sdk-web/src/core/signingEngine/interfaces/near.ts packages/sdk-web/src/core/signingEngine/flows/signNear/shared/routerAbEd25519WalletSessionState.ts packages/sdk-web/src/core/signingEngine/flows/signNear/shared/routerAbWalletSessionCredential.ts packages/sdk-web/src/core/signingEngine/flows/signNear/shared/routerAbWalletSessionCredential.typecheck.ts packages/sdk-web/src/core/signingEngine/flows/signNear/signTransactions.ts packages/sdk-web/src/core/signingEngine/flows/signNear/signDelegate.ts packages/sdk-web/src/core/signingEngine/flows/signNear/signNep413.ts packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519PresignFinalize.ts tests/unit/routerAbEd25519.walletSessionState.unit.test.ts
```

Phase 3 validation completed so far:

```sh
rtk pnpm -C packages/sdk-web type-check
rtk pnpm -C packages/sdk-web build:prepare
rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/signingCapabilityStrictRecords.unit.test.ts --reporter=line
rtk pnpm -C tests exec playwright test -c playwright.source.config.ts unit/routerAbNormalSigningSdk.guard.unit.test.ts --reporter=line
pnpm -C packages/sdk-web type-check
pnpm -C packages/sdk-web build:prepare
pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/evmFamilyEcdsaIdentity.unit.test.ts unit/ecdsaMaterialState.unit.test.ts unit/signingFlow.readySigner.unit.test.ts --reporter=line
pnpm -C tests exec playwright test -c playwright.source.config.ts unit/routerAbNormalSigningSdk.guard.unit.test.ts --reporter=line
```

Phase 3 type-fixture validation completed so far:

```sh
rtk pnpm -C packages/sdk-web type-check
pnpm -C packages/sdk-web type-check
pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/routerAbEd25519.walletSessionState.unit.test.ts unit/warmSessionStore.invariants.unit.test.ts unit/warmSessionTransitions.unit.test.ts --reporter=line
```

### Phase 4: Bloat And File Ownership Audit

Status: complete on June 19, 2026.

Task list:

- [x] List large modules and route files.
- [x] Mark mixed responsibilities.
- [x] Propose extraction targets with dependency direction.
- [x] Identify duplicate Express/Cloudflare logic.
- [x] Identify duplicated SDK route-client and auth-header helpers.

Large-module inventory from
`rtk rg --files packages/sdk-web/src packages/sdk-server-ts/src | xargs wc -l | sort -nr | head -80`:

| File                                                                            | Lines | Ownership note                                                                                                                        |
| ------------------------------------------------------------------------------- | ----: | ------------------------------------------------------------------------------------------------------------------------------------- |
| `packages/sdk-server-ts/src/core/AuthService.ts`                                | 16464 | Broad server auth/account service. Leave out of Router A/B cleanup unless a route/auth boundary task needs a narrow parser or issuer. |
| `packages/sdk-server-ts/src/router/express/createConsoleRouter.ts`              |  4667 | Console route assembly; separate from Router A/B signing cleanup.                                                                     |
| `packages/sdk-server-ts/src/core/ThresholdService/ThresholdSigningService.ts`   |  4599 | Mixed threshold-era service surface. Extract only when active Router A/B handlers need narrower service ports.                        |
| `packages/sdk-server-ts/src/router/cloudflare/createCloudflareConsoleRouter.ts` |  4522 | Console route assembly; keep out of signing cleanup.                                                                                  |
| `packages/sdk-web/src/core/signingEngine/session/persistence/records.ts`        |  3074 | Persistence boundary for legacy/current records. Phase 15.11 owns strict signable-state split.                                        |
| `packages/sdk-server-ts/src/router/routeDefinitions.ts`                         |  2182 | Route metadata mixes public, console, API, and threshold-era signing labels. Phase 15.17 owns auth metadata cleanup.                  |
| `packages/sdk-server-ts/src/router/express/routes/sessions.ts`                  |  1900 | Duplicated with Cloudflare sessions route; server auth/session boundary cleanup owns extraction.                                      |
| `packages/sdk-server-ts/src/router/cloudflare/routes/sessions.ts`               |  1895 | Duplicated with Express sessions route; extract shared validation only after auth semantics are pinned.                               |
| `packages/sdk-server-ts/src/router/express/routes/thresholdEcdsa.ts`            |  1111 | Active Router A/B ECDSA-HSS routes live in a threshold-named adapter file.                                                            |
| `packages/sdk-server-ts/src/router/cloudflare/routes/thresholdEcdsa.ts`         |   816 | Cloudflare duplicate of active Router A/B ECDSA-HSS route behavior.                                                                   |
| `packages/sdk-server-ts/src/router/express/routes/thresholdEd25519.ts`          |   837 | Active Router A/B Ed25519 normal-signing routes live in a threshold-named adapter file.                                               |
| `packages/sdk-server-ts/src/router/cloudflare/routes/thresholdEd25519.ts`       |   745 | Cloudflare duplicate of active Router A/B Ed25519 route behavior.                                                                     |
| `packages/sdk-web/src/core/rpcClients/relayer/walletRegistration.ts`            |  1514 | SDK route client mixes registration calls, local POST helper, auth headers, and Router A/B bootstrap response parsing.                |
| `packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigning.ts`         |  1087 | SDK Router A/B signing client owns canonical request/digest construction plus local POST helper.                                      |
| `packages/sdk-web/src/core/rpcClients/relayer/thresholdEcdsa.ts`                |   702 | ECDSA-HSS bootstrap client still carries threshold-era naming and separate bearer/fetch helpers.                                      |

Mixed-responsibility findings and extraction targets:

- Express and Cloudflare Router A/B signing routes previously duplicated
  validation, Wallet Session claim parsing, admission-store lookup, private
  SigningWorker calls, logging, and status mapping in threshold-named files.
  Current state: the Ed25519 and ECDSA-HSS normal-signing core is split into
  `routerAbPrivateSigningWorker.ts`; threshold-named adapters may remain while
  they still own mixed request-boundary routes and framework response
  serialization. Dependency direction: adapter wrappers import server-local
  Router A/B handlers; handlers may import `shared-ts` protocol parsers and
  server service ports; `sdk-web` must not import server route code.
- `routeDefinitions.ts` still uses `thresholdSessionRoute` metadata for active
  Router A/B signing routes. Extraction target: route metadata groups for
  Router A/B Wallet Session JWT routes, threshold bootstrap/repair routes,
  console routes, and API-credential routes. Dependency direction: route
  registration imports route definitions; business handlers must not branch on
  display/metadata labels.
- Express and Cloudflare session/auth routes repeat bearer/cookie signal
  detection and malformed-session diagnostics. Extraction target:
  adapter-neutral request-boundary parsers after Phase 15.17 finalizes
  bearer-only signing-capable auth. Dependency direction: adapters parse raw
  headers/cookies once, then pass typed auth/session inputs into server-local
  handlers.
- SDK relayer clients duplicate URL trimming, JSON POST, bearer header building,
  and `credentials: 'omit'` fetch options across `walletRegistration.ts`,
  `routerAbNormalSigning.ts`, `thresholdEcdsa.ts`, and
  `routerAbPublicKeyset.ts`. Extraction target: a small sdk-web-local
  `postRelayerJson` helper plus branch-specific auth-header builders. Dependency
  direction: route clients import the helper; the helper accepts already-parsed
  route paths, typed headers, and boundary-normalized request bodies. Protocol
  digest construction stays in the protocol-specific clients.
- Large console, billing, and general account/auth modules are real bloat but
  outside Router A/B signing cleanup. Keep them out of the current cleanup
  unless a later server package split needs export-boundary work.

Implementation sequencing:

1. Keep Phase 15.11 and 15.17 signing/session state cleanup ahead of route
   extraction when the extraction would otherwise preserve invalid state shapes.
2. Keep Router A/B route-core logic split out of threshold-named server files;
   leave mixed adapters threshold-named only while they still own
   request-boundary routes and framework response serialization.
3. Consolidate SDK route-client POST/auth helpers only after the helper accepts
   narrow typed inputs and does not hide request-boundary parsing.
4. Treat console/auth-service bloat as a separate server-package cleanup lane.

Validation:

```sh
rtk rg --files packages/sdk-web/src packages/sdk-server-ts/src | xargs wc -l | sort -nr | head -80
wc -l packages/sdk-server-ts/src/router/express/routes/thresholdEd25519.ts packages/sdk-server-ts/src/router/cloudflare/routes/thresholdEd25519.ts packages/sdk-server-ts/src/router/express/routes/thresholdEcdsa.ts packages/sdk-server-ts/src/router/cloudflare/routes/thresholdEcdsa.ts packages/sdk-server-ts/src/router/express/routes/sessions.ts packages/sdk-server-ts/src/router/cloudflare/routes/sessions.ts packages/sdk-server-ts/src/router/emailOtpRouteHandlers.ts packages/sdk-server-ts/src/router/routeDefinitions.ts packages/sdk-web/src/core/rpcClients/relayer/walletRegistration.ts packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigning.ts packages/sdk-web/src/core/rpcClients/relayer/thresholdEcdsa.ts
rtk rg -n 'function .*post|async function .*post|const .*post|Authorization:|credentials:|stripTrailingSlashes|resolveBearerToken|fetch\(' packages/sdk-web/src/core/rpcClients/relayer
rtk rg -n "register.*Route|findRouteDefinitionById|thresholdSessionRoute|RouteAuthPolicy|handleRouterAb|routerAb.*status|parse.*WalletSession|hadBearerSessionSignal|hasBearerSessionSignal" packages/sdk-server-ts/src/router/express/routes packages/sdk-server-ts/src/router/cloudflare/routes packages/sdk-server-ts/src/router/routeDefinitions.ts packages/sdk-server-ts/src/router/routeAuthPolicy.ts
```

### Phase 5: Test And Fixture Audit

Status: complete on June 19, 2026.

Task list:

- [x] Delete tests that encode obsolete behavior.
- [x] Move compatibility tests to boundary-specific suites.
- [x] Ensure every active flow has positive and negative coverage.
- [x] Ensure source guards cover deleted names and invalid public shapes.

Deleted-test replacement map, reconciled against the current branch:

| Deleted obsolete test                                                                                                                                                                                                                                                                                              | Preserved invariant                                                                                     | Current coverage                                                                                                                                                                                                                                                                                             |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `tests/e2e/thresholdEd25519.authorizeUnauthorizedNoBroadcast.test.ts`                                                                                                                                                                                                                                              | Unauthorized signing requests must not broadcast.                                                       | `tests/unit/routerAbServerWalletSessionClaimBoundary.guard.unit.test.ts`, `tests/relayer/router-ab-normal-signing-auth-boundary.test.ts`, and `tests/unit/routerAbNormalSigningSdk.guard.unit.test.ts` cover bearer-only Wallet Session auth and reject cookie/legacy signing-capable paths.                 |
| `tests/e2e/thresholdEd25519.batchSigning.test.ts`                                                                                                                                                                                                                                                                  | Active Ed25519 signing uses the Router A/B path rather than old threshold batch routes.                 | `tests/e2e/thresholdEd25519.nep413Signing.test.ts`, `tests/e2e/thresholdEd25519.delegateSigning.test.ts`, `tests/unit/routerAbNormalSigningVectors.unit.test.ts`, and `tests/unit/routerAbWireVectors.unit.test.ts`.                                                                                         |
| `tests/e2e/thresholdEd25519.digestBinding.test.ts`                                                                                                                                                                                                                                                                 | Request digest/scope binding is enforced.                                                               | `tests/unit/routerAbNormalSigningValidation.unit.test.ts`, `tests/unit/routerAbWireVectors.unit.test.ts`, `tests/unit/routerAbNormalSigningSdk.guard.unit.test.ts`, and Rust Router A/B vector tests.                                                                                                        |
| `tests/e2e/thresholdEd25519.frostTamper.test.ts`                                                                                                                                                                                                                                                                   | Tampered signing/share material is rejected.                                                            | `tests/unit/thresholdEd25519.hssMaterialHandle.unit.test.ts`, `tests/unit/thresholdEd25519.nearSigningQueue.guard.unit.test.ts`, `tests/unit/routerAbNormalSigningSdk.guard.unit.test.ts`, and current Rust Router A/B protocol tests.                                                                       |
| `tests/e2e/thresholdEd25519.onchainScope.test.ts`                                                                                                                                                                                                                                                                  | Scope and account binding stay enforced.                                                                | `tests/unit/thresholdEd25519.sessionPolicyDigest.unit.test.ts`, `tests/unit/routerAbNormalSigningValidation.unit.test.ts`, and Router A/B Wallet Session claim guards.                                                                                                                                       |
| `tests/e2e/thresholdEd25519.relayerFailure.test.ts`                                                                                                                                                                                                                                                                | Relayer/SigningWorker failures do not fall back to old signing paths.                                   | `tests/unit/routerAbNormalSigningSdk.guard.unit.test.ts`, `tests/unit/thresholdEd25519.nearSigningQueue.guard.unit.test.ts`, and active relayer auth-boundary tests.                                                                                                                                         |
| `tests/e2e/thresholdEd25519.sessionExhaustion.test.ts`                                                                                                                                                                                                                                                             | Session use limits and exhausted-session behavior stay enforced.                                        | `tests/unit/sessionTokens.unit.test.ts`, `tests/unit/walletSessionReadiness.gate.unit.test.ts`, `tests/unit/signingSessionBudgetFinalizer.unit.test.ts`, and server signing-budget tests.                                                                                                                    |
| `tests/relayer/threshold-ed25519.scope.test.ts`                                                                                                                                                                                                                                                                    | Old public threshold scope routes are gone.                                                             | `tests/unit/router.routeDefinitions.unit.test.ts` and `tests/unit/routerAbNormalSigningSdk.guard.unit.test.ts` reject old public threshold signing route literals.                                                                                                                                           |
| `tests/unit/thresholdEd25519.finalizeAndDispatch.unit.test.ts`                                                                                                                                                                                                                                                     | Final Ed25519 signing dispatch uses current Router A/B finalization.                                    | `tests/unit/routerAbNormalSigningVectors.unit.test.ts`, `tests/unit/routerAbEd25519.walletSessionState.unit.test.ts`, and `tests/unit/thresholdEd25519.hssMaterialHandle.unit.test.ts`.                                                                                                                      |
| `tests/unit/thresholdEd25519.immediateSignFallback.unit.test.ts`                                                                                                                                                                                                                                                   | Immediate fallback signing remains deleted.                                                             | `tests/unit/routerAbNormalSigningSdk.guard.unit.test.ts` rejects fallback route/helper names and requires Wallet Session v2 request builders.                                                                                                                                                                |
| `tests/unit/thresholdEd25519.presignContracts.unit.test.ts`, `tests/unit/thresholdEd25519.presignFinalizeClient.unit.test.ts`, `tests/unit/thresholdEd25519.presignRefill.unit.test.ts`, `tests/unit/thresholdEd25519.relayerClient.unit.test.ts`, and `tests/unit/thresholdEd25519.relayerCosigners.stub.test.ts` | Old presign/refill client contract does not remain as active public behavior.                           | `tests/unit/thresholdEd25519.presignPool.unit.test.ts`, `tests/unit/thresholdEd25519.presignStore.unit.test.ts`, `tests/unit/thresholdEd25519.hssMaterialHandle.unit.test.ts`, and Router A/B normal-signing source guards.                                                                                  |
| `tests/unit/thresholdEd25519.singleKeyHssActivePath.script.unit.test.ts` and `tests/unit/thresholdEd25519AuthSession.rehydrate.unit.test.ts`                                                                                                                                                                       | Old single-key/auth-session rehydrate paths are not active signing paths.                               | `tests/unit/thresholdEd25519WalletSession.rehydrate.unit.test.ts`, `tests/unit/routerAbEd25519.walletSessionState.unit.test.ts`, and `tests/unit/sessionTokens.unit.test.ts`.                                                                                                                                |
| `tests/unit/thresholdEcdsa.authorizePolicyHint.unit.test.ts`, `tests/unit/thresholdEcdsa.requestTimeout.unit.test.ts`, and `tests/unit/thresholdEcdsa.tempoHighLevel.integration.test.ts`                                                                                                                          | Old ECDSA authorize/direct-timeout/high-level paths do not define current Router A/B ECDSA-HSS signing. | `tests/unit/routerAbEcdsaHssNormalSigning.unit.test.ts`, `tests/unit/routerAbEcdsaHssPresignBridge.unit.test.ts`, `tests/unit/thresholdEcdsa.authorizationBootstrapVerifier.unit.test.ts`, `tests/unit/thresholdEcdsa.hssBootstrapPolicy.unit.test.ts`, and `tests/e2e/thresholdEcdsa.tempoSigning.test.ts`. |

Compatibility coverage is boundary-specific:

- JWT kind compatibility and legacy threshold-session rejection live in
  `tests/unit/sessionTokens.unit.test.ts`.
- Sealed restore and persistence compatibility live in
  `tests/unit/sealedSessionStore.unit.test.ts`,
  `tests/unit/signingSessionRestoreCoordinator.unit.test.ts`,
  `tests/unit/thresholdEd25519WalletSession.rehydrate.unit.test.ts`, and
  `tests/unit/thresholdPostgresMalformedCleanup.unit.test.ts`.
- Server request/auth compatibility checks live in
  `tests/unit/routerAbServerWalletSessionClaimBoundary.guard.unit.test.ts`,
  `tests/relayer/router-ab-normal-signing-auth-boundary.test.ts`, and
  route-surface tests. These suites are the allowed request-boundary home for
  legacy input classification.
- Raw-material compatibility remains open under Phase 3 and Router cleanup
  Phases 15.10 through 15.12. Do not move those tests into active signing
  suites while raw record classification is still required at persistence
  boundaries.

Active-flow coverage:

- Ed25519 Router A/B normal signing has positive coverage through
  `tests/e2e/thresholdEd25519.nep413Signing.test.ts`,
  `tests/e2e/thresholdEd25519.delegateSigning.test.ts`,
  `tests/unit/routerAbNormalSigningVectors.unit.test.ts`, and
  `tests/unit/routerAbWireVectors.unit.test.ts`; negative coverage lives in
  `tests/unit/routerAbNormalSigningValidation.unit.test.ts`,
  `tests/unit/routerAbServerWalletSessionClaimBoundary.guard.unit.test.ts`, and
  `tests/unit/routerAbNormalSigningSdk.guard.unit.test.ts`.
- ECDSA-HSS Router A/B normal signing and pool fill have positive coverage in
  `tests/unit/routerAbEcdsaHssNormalSigning.unit.test.ts`,
  `tests/unit/routerAbEcdsaHssPresignBridge.unit.test.ts`,
  `tests/unit/thresholdEcdsa.presignDistributed.unit.test.ts`, and
  `tests/unit/thresholdEcdsa.presignPoolRefill.unit.test.ts`; negative coverage
  lives in the HSS bootstrap, authorization verifier, pool-policy, and
  source-guard suites.
- Wallet Session auth, claim parsing, signing budget status, and seal-session
  policy boundaries have coverage in `tests/unit/sessionTokens.unit.test.ts`,
  `tests/unit/signingSessionSeal.sessionPolicy.unit.test.ts`,
  `tests/unit/signingBudgetStatus.parser.unit.test.ts`,
  `tests/unit/signingSessionBudgetFinalizer.unit.test.ts`, and relayer
  auth-boundary suites.
- Source guards cover deleted route literals, deleted helper names, invalid
  public package shapes, Router A/B v1 route confinement, raw-material leakage,
  old `thresholdSessionAuthToken` usage, and package-boundary regressions in
  `tests/unit/routerAbNormalSigningSdk.guard.unit.test.ts`,
  `tests/unit/routerAbServerWalletSessionClaimBoundary.guard.unit.test.ts`,
  `tests/unit/signingEngineArchitecture.*.guard.unit.test.ts`,
  `tests/unit/crossPlatformBoundaries.guard.unit.test.ts`, and the refactor
  package-boundary guard suites.

Closure note:

- Raw-material and strict signable-state work moved to
  `docs/refactor-75-simplify-ed25519.md`, and `docs/router-a-b-SPEC.md`.
- Route/auth extraction and SDK route-client helper consolidation landed in
  Phase 6. Remaining route metadata cleanup belongs to
  `docs/router-a-b-SPEC.md`.
- Deleted threshold-era tests must stay deleted. Replacement coverage should
  target Router A/B routes, Wallet Session JWT boundaries, worker-owned
  material handles, or explicit persistence/request compatibility parsers.

Validation:

```sh
rtk pnpm -C tests exec playwright test -c playwright.source.config.ts unit/routerAbNormalSigningSdk.guard.unit.test.ts unit/routerAbServerWalletSessionClaimBoundary.guard.unit.test.ts --reporter=line
rtk git status --short tests | rtk rg "^ D|^D |^ R|^R |thresholdEd25519|thresholdEcdsa|routerAb|signing-session|source|guard"
rtk rg --files tests | rtk rg "(thresholdEd25519|thresholdEcdsa|routerAb|RouterAb|signing-session|walletSession|source|guard)"
```

### Phase 6: Implementation Slices

Implement after the audit report is reviewed.

Suggested order:

Status: complete on June 20, 2026.

Task list:

- [x] Shared route handler extraction.
      Current progress: - [x] Extracted the Router A/B Ed25519 normal-signing route core into
      `packages/sdk-server-ts/src/router/routerAbPrivateSigningWorker.ts`
      so Express and Cloudflare share Wallet Session validation,
      request-scope admission, quota/admission evaluation, replay
      reservation, private SigningWorker path resolution, and forwarding.
      Framework adapters still own logging and response serialization. - [x] Review follow-up: Cloudflare normal-signing dispatch now reaches
      the shared Router A/B core before old Ed25519 threshold scheme
      resolution, presign-pool prepare uses phase-scoped replay
      reservation, and success-path tests assert the exact private
      SigningWorker URL for prepare, presign-pool prepare, normal
      finalize, and presign-pool finalize. - [x] Extracted the remaining duplicated Router A/B ECDSA-HSS route core
      into `packages/sdk-server-ts/src/router/routerAbPrivateSigningWorker.ts`.
      Express and Cloudflare now share Wallet Session validation,
      request-scope admission, quota/admission evaluation, prepare replay,
      final-signing budget consumption, private body construction, and
      private SigningWorker forwarding. Legacy threshold route helpers
      stay in the threshold-named adapters because they still own
      request-boundary semantics.
- [x] SDK Router A/B credential and route-client consolidation.
      Current progress: - [x] Browser relayer clients share
      `packages/sdk-web/src/core/rpcClients/relayer/relayerHttp.ts` for
      base URL normalization, JSON request init, `credentials: 'omit'`,
      and bearer `Authorization` header construction. Protocol-specific
      request bodies, digest construction, response parsers, and error
      messages remain in `routerAbNormalSigning.ts`,
      `routerAbPublicKeyset.ts`, `walletRegistration.ts`, and
      `thresholdEcdsa.ts`. - [x] Fix the stale ECDSA bootstrap fixture used by the route-client
      consolidation tests. - [x] Fix Ed25519 presign-pool request/response binding so the SDK
      request builder and response parser prove that accepted pool entries
      bind to the original request scope, generation, and client offers.
- [x] Worker operation split.
      Closure evidence: - `workerTypes.ts` now exposes domain operation aliases for Email OTP
      challenge/enrollment/restore/warm-session/export operations, ETH
      transaction/local-secp256k1/ECDSA-presign operations, Tempo
      transaction operations, NEAR Ed25519 material/presign/digest/finalize
      operations, and HSS Ed25519 / ECDSA role-local material and presign
      operations. - Runtime dispatch ownership remains unchanged:
      `email-otp.worker.ts` owns Email OTP restore/export/warm-session
      execution, `hss-client.worker.ts` owns HSS Ed25519 and ECDSA
      role-local material execution, `eth-signer.worker.ts` owns ETH
      transaction and ECDSA presignature execution, `tempo-signer.worker.ts`
      owns Tempo transaction execution, and `near-signer.worker.ts` owns
      NEAR Ed25519 material, digest, and finalize execution. - `workerTypes.typecheck.ts` now proves old mixed-domain requests cannot
      be constructed across ETH transaction vs ECDSA presign, NEAR
      material vs digest, HSS Ed25519 vs ECDSA role-local, and Email OTP
      export vs warm-session domains. - HSS wrapper calls in `threshold/crypto/hssClientSignerWasm.ts` now
      dispatch through narrow Ed25519 protocol, ECDSA role-local material,
      and ECDSA role-local presign request helpers instead of accepting
      the broad HSS worker request type at each call site. - No worker cryptographic protocol semantics, replay protection, or
      material lifetime rules changed.
- [x] ECDSA identity and signing-root boundary consolidation.
      Closure evidence: - Active signable ECDSA state now derives Router A/B threshold-key,
      signing-root, signing-root-version, signing-worker, and verifier
      identity from `RouterAbEcdsaHssSigningMaterialRef`. - `ReadyThresholdEcdsaSignerTransport` no longer duplicates
      `ecdsaThresholdKeyId`; the role-local material-handle binding derives
      it from parsed signing material. - `evmFamilyEcdsaIdentity.typecheck.ts` rejects loose threshold-key,
      signing-root, key-handle, raw verifier, cookie auth, broad key-ref,
      raw Router A/B state, and raw role-local blob branches on active
      ready signer sessions. - ECDSA-HSS protocol derivation, key-handle derivation, and signing-root
      share resolver semantics were not changed.
- [x] Folder moves with import-direction guards.
      Closure evidence: - Target ownership map:
      `routerAb/ecdsaHss/signingMaterialRef.ts` and `poolFillRoutes.ts`
      are pure Router A/B protocol/request-boundary modules;
      `session/identity/*` owns parsed identity and active signer
      boundaries; `workerManager/*` owns worker request/transport
      boundaries; route adapters and operation flows depend inward on
      those modules. - `routerAbNormalSigningSdk.guard.unit.test.ts` now rejects import
      direction drift: pure Router A/B modules cannot import flows,
      persistence, warm-session, worker, or UI layers; identity modules
      cannot import operation flows, worker manager, or warm-session
      lifecycle logic; worker boundary modules cannot import signing flows
      or UI layers. - No file move was needed because the guarded ownership map has no current
      violation requiring a path change.
- [x] Legacy fixture/test deletion.
      Closure evidence: - Phase 5 lists the exact obsolete threshold-era tests deleted in this
      cleanup and the replacement coverage that preserves current Router
      A/B behavior. - The zero-tolerance source guard continues to reject deleted public
      threshold signing route literals, helper names, and legacy public
      signing surfaces. - No additional low-risk obsolete tests were identified in this pass.
      Future deletions should name the exact stale fixture/test and point
      to replacement coverage before removal.

Each slice should include its own type fixtures or source guards.

Validation completed for the worker operation, ECDSA identity, and import-guard
slice:

```sh
pnpm -C packages/sdk-web type-check
pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/evmFamilyEcdsaIdentity.unit.test.ts --reporter=line
pnpm -C tests exec playwright test -c playwright.source.config.ts unit/routerAbNormalSigningSdk.guard.unit.test.ts --reporter=line
```

Validation completed for the SDK route-client helper slice:

```sh
rtk pnpm -C packages/sdk-web type-check
rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/routerAbPublicKeyset.unit.test.ts unit/routerAbNormalSigningValidation.unit.test.ts unit/walletRegistrationEcdsaRouterAbBootstrap.unit.test.ts unit/routerAbNormalSigningVectors.unit.test.ts --reporter=line
rtk pnpm -C tests exec playwright test -c playwright.source.config.ts unit/routerAbNormalSigningSdk.guard.unit.test.ts unit/routerAbServerWalletSessionClaimBoundary.guard.unit.test.ts --reporter=line
rtk git diff --check
```

Validation completed for the shared Ed25519 route-core extraction:

```sh
rtk pnpm -C packages/sdk-server-ts type-check
rtk pnpm -C tests exec playwright test -c playwright.relayer.config.ts relayer/router-ab-normal-signing-auth-boundary.test.ts --reporter=line
rtk pnpm -C tests exec playwright test -c playwright.source.config.ts unit/routerAbNormalSigningSdk.guard.unit.test.ts unit/routerAbServerWalletSessionClaimBoundary.guard.unit.test.ts --reporter=line
```

Validation completed for the shared ECDSA-HSS route-core extraction:

```sh
pnpm -C packages/sdk-server-ts type-check
pnpm -C tests exec playwright test -c playwright.relayer.config.ts relayer/router-ab-normal-signing-auth-boundary.test.ts --reporter=line
```

Validation completed for the SDK route-client follow-up fixes:

```sh
rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/routerAbNormalSigningValidation.unit.test.ts unit/routerAbEcdsaHssNormalSigning.unit.test.ts --reporter=line
rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/routerAbPublicKeyset.unit.test.ts unit/routerAbNormalSigningValidation.unit.test.ts unit/walletRegistrationEcdsaRouterAbBootstrap.unit.test.ts unit/routerAbNormalSigningVectors.unit.test.ts unit/routerAbEcdsaHssNormalSigning.unit.test.ts --reporter=line
rtk pnpm -C packages/sdk-web type-check
rtk pnpm -C tests exec playwright test -c playwright.source.config.ts unit/routerAbNormalSigningSdk.guard.unit.test.ts unit/routerAbServerWalletSessionClaimBoundary.guard.unit.test.ts --reporter=line
rtk git diff --check
```

### Phase 7: Router A/B Naming, Guard, And Budget Hardening

This phase handles cleanup that remains after active transaction signing has
been moved to Router A/B. These tasks are naming, guard, and policy-boundary
work. They are not evidence that legacy public threshold signing remains active.

Task list:

- [x] Resolve threshold-era active Router A/B route-core ownership.
      Closure evidence: - Active Ed25519 and ECDSA-HSS normal-signing core code now lives in
      `packages/sdk-server-ts/src/router/routerAbPrivateSigningWorker.ts`. - Express and Cloudflare `thresholdEd25519.ts` / `thresholdEcdsa.ts`
      files stay threshold-named because they still own threshold-era
      request-boundary routes and framework response serialization. - `tests/unit/routerAbNormalSigningSdk.guard.unit.test.ts` now proves
      normal-signing admission, request validation, private body
      construction, budget consumption, and private worker forwarding stay
      outside threshold-named adapters.
- [x] Keep the legacy public signing guard as a zero-tolerance check for old
      active signing routes and helpers. The current guard lives in
      `tests/unit/routerAbNormalSigningSdk.guard.unit.test.ts` and should
      continue rejecting old `/threshold-ed25519/*`, `/threshold-ecdsa/*`, and
      deleted helper names.
- [x] Fix the focused Router A/B source-guard failure caused by raw ECDSA
      marker strings in strict type `never` exclusions. The guard failure is
      about cleanup around `clientSigningShare32` markers, not old public
      threshold signing routes. Prefer a named boundary marker or a narrower
      guard allowlist over weakening the old-route guard.
- [x] Enforce server-side Wallet Session remaining-use budget consumption on
      Router A/B final signing. The Router should validate the Wallet Session
      JWT and scope, admit signing only when server budget has remaining uses,
      and consume one server budget use at the correct one-use finalization
      boundary. SDK budget projection remains a local UX/concurrency mirror.
      This is the 69C interim direct-consume guard. The complete server budget
      reservation lifecycle remains tracked in
      `docs/refactor-70-server-budget.md`: prepare-time reservation,
      finalize-time commit, release on abandoned prepare or private
      SigningWorker failure, and concurrent overspend prevention.
- [x] Add focused tests for Router A/B server budget exhaustion across Ed25519,
      ECDSA EVM, and Tempo signing. Cover successful use consumption,
      exhausted-session rejection, idempotent retry behavior, and no-consume on
      rejected admission before final signing.
- [x] Record the distinction between removed legacy signing flows and remaining
      cleanup debt in this plan after the guard and budget fixes land.

Distinction note: old public threshold signing routes and helper names remain
treated as deleted legacy flow and are covered by the zero-tolerance source
guard. Mixed threshold-named adapters remain only where they still own
request-boundary routing and response serialization; the Router A/B
normal-signing core is guarded outside those adapters.

Threshold-era naming cleanup closure criteria:

- Add an explicit rename map before changing paths or exported symbols.
- Preserve names that describe real cryptographic threshold concepts, historical
  deleted-route audits, persisted compatibility parsers, or request-boundary
  adapters.
- Rename active Router A/B files/adapters only when the current name obscures
  ownership after shared core extraction.
- Guard active Router A/B route-core ownership outside threshold-era adapters.

Completed rename map:

| Old path                                                                   | New path                                                                                      | Reason                                                                                                                                                                                                |
| -------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `packages/sdk-server-ts/src/core/ThresholdService/schemes/types.ts`        | `packages/sdk-server-ts/src/core/ThresholdService/schemes/thresholdServiceSchemes.types.ts`   | Mechanical Refactor 73 type-module rename for the server threshold scheme registry. Exported scheme IDs and real cryptographic threshold names remain unchanged.                                      |
| `packages/sdk-server-ts/src/router/cloudflare/types.ts`                    | `packages/sdk-server-ts/src/router/cloudflare/cloudflare.types.ts`                            | Mechanical Refactor 73 type-module rename for Cloudflare adapter boundary types after Refactor 70 core budget work stabilized. Runtime bindings and route handling remain unchanged.                  |
| `packages/sdk-server-ts/src/threshold/session/signingSessionSeal/types.ts` | `packages/sdk-server-ts/src/threshold/session/signingSessionSeal/signingSessionSeal.types.ts` | Mechanical Refactor 73 type-module rename for signing-session seal boundary types after Refactor 70 core budget work stabilized. Seal policy, auth, budget, and transport semantics remain unchanged. |

Validation completed for the Phase 7 route-core ownership guard:

```sh
pnpm -C tests exec playwright test -c playwright.source.config.ts unit/routerAbNormalSigningSdk.guard.unit.test.ts --reporter=line
```

Suggested validation:

```sh
pnpm -C tests exec playwright test -c playwright.source.config.ts unit/routerAbNormalSigningSdk.guard.unit.test.ts --reporter=line
pnpm -C tests exec playwright test -c playwright.relayer.config.ts relayer/router-ab-normal-signing-auth-boundary.test.ts --reporter=line
pnpm -C packages/sdk-web type-check
pnpm -C packages/sdk-server-ts type-check
git diff --check
```

Validation completed for the Phase 7 source-guard slice:

```sh
pnpm -C tests exec playwright test -c playwright.source.config.ts unit/routerAbNormalSigningSdk.guard.unit.test.ts --reporter=line
git diff --check -- tests/unit/routerAbNormalSigningSdk.guard.unit.test.ts docs/refactor-69C-cleanup-reduce-bloat.md
```

Validation completed for the Phase 7 server budget slice:

```sh
pnpm -C tests exec playwright test -c playwright.relayer.config.ts relayer/router-ab-normal-signing-auth-boundary.test.ts --reporter=line
pnpm -C packages/sdk-server-ts type-check
pnpm -C tests exec playwright test -c playwright.source.config.ts unit/routerAbNormalSigningSdk.guard.unit.test.ts --reporter=line
pnpm -C packages/sdk-web type-check
git diff --check
```

## Validation Matrix

Run the cheapest check that covers the changed slice.

### SDK Web

```sh
rtk pnpm -C packages/sdk-web run type-check
rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/routerAbNormalSigningSdk.guard.unit.test.ts ./unit/routerAbEcdsaHssNormalSigning.unit.test.ts ./unit/thresholdEd25519.presignPool.unit.test.ts --reporter=line
```

### SDK Server

```sh
rtk pnpm -C packages/sdk-server-ts run type-check
rtk pnpm -C tests exec playwright test -c playwright.relayer.config.ts ./relayer/router-ab-keyset-routes.test.ts ./relayer/signing-session-seal-router.test.ts --reporter=line
```

### Rust Router

```sh
rtk cargo test --manifest-path crates/router-ab-core/Cargo.toml --test normal_signing_v2 --test ecdsa_hss_protocol --test source_guards
rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings --test source_guards
```

### End-To-End Smoke

```sh
rtk pnpm router:deploy:check
rtk pnpm router:deploy:browser-evidence
```

## Deliverable

Delivered audit document:

- [refactor-69c-router-ab-flow-inventory-2026-06-18.md](./audits/refactor-69c-router-ab-flow-inventory-2026-06-18.md)

The audit covers:

- complete flow inventory
- call graphs per flow
- boundary exception list
- type tightening backlog
- bloat deletion backlog
- proposed file moves
- guard/test additions
- validation evidence

The audit separates findings into:

- release-blocking correctness issues
- high-value cleanup
- naming and folder organization
- optional ergonomics

Implementation work began after the inventory identified the modules that own
each Router A/B behavior and the callers allowed to reach them.

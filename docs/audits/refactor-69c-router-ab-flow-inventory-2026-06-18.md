# Refactor 69C Router A/B Flow Inventory

Date: June 18, 2026

Status: Phase 1 inventory complete. Phase 2 auth and boundary invariant audit
has been completed in the main plan; this document remains the working flow map
for later type, bloat, and file-ownership audit slices.

## Scope

This inventory covers active Router A/B behavior across:

- `packages/sdk-web`
- `packages/sdk-server-ts`
- `packages/shared-ts`
- `crates/router-ab-core`
- `crates/router-ab-cloudflare`
- `crates/router-ab-dev`
- `tests`

Compatibility is allowed only at request and persistence boundaries. Core SDK,
server service, and Rust protocol code should model the current Router A/B-only
behavior directly.

## Flow Inventory

| Flow                                              | Public Entry Points                                                                             | SDK Owners                                                                       | Server Owners                                                                         | Rust/Worker Owners                                                                               | Boundaries                                                                                         | Tests/Guards                                                                                            | Notes                                                                                                                |
| ------------------------------------------------- | ----------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| Public keyset                                     | `GET /v2/router-ab/keyset`, well-known keyset path                                              | `routerAbPublicKeyset` route client                                              | Express/Cloudflare router adapters, route definitions                                 | `crates/router-ab-cloudflare/src/strict_worker.rs`                                               | Public unauthenticated read; CORS and cache boundary                                               | `routerAbPublicKeyset.unit.test.ts`, keyset env boundary tests, relayer keyset route tests              | Keep public. Rotation shape includes `current`; future previous/next epochs should stay explicit.                    |
| Ed25519 Wallet Session issuance                   | `POST /v2/router-ab/wallet-session/ed25519`                                                     | warm-session bootstrap, wallet session readiness, persisted signing lanes        | Ed25519 route adapters, Wallet Session claim helpers, signing session seal service    | HSS WASM for session material, server ThresholdService                                           | Request auth boundary, Wallet Session JWT minting boundary, sealed persistence boundary            | wallet session readiness tests, Ed25519 wallet-session state tests, signing-session seal tests          | Must reject cookie signing sessions and legacy threshold JWTs in signing-capable routes.                             |
| Ed25519 HSS lifecycle                             | `/v2/router-ab/ed25519/hss/prepare`, `/respond`, `/finalize`                                    | HSS bootstrap/recovery orchestration, worker-owned material handles target state | Ed25519 route adapters, ThresholdService HSS handlers                                 | Ed25519 HSS WASM, signer worker boundary                                                         | Request body parse, HSS ceremony state persistence, sealed restore persistence                     | Ed25519 bootstrap integrity, registration warm-session, HSS-related unit suites                         | Current cleanup direction is worker-owned client material; TS should persist handles/bindings only.                  |
| Ed25519 normal signing, pool miss                 | `/v2/router-ab/ed25519/sign/prepare`, `/v2/router-ab/ed25519/sign`                              | NEAR tx/message/delegate signing flows, Router A/B route client                  | Router A/B normal signing routes, private SigningWorker forwarding                    | `router-ab-core` normal signing parsers, Cloudflare strict worker, local dev dispatcher          | Wallet Session bearer, canonical request digest, SigningWorker service auth, one-use round-1 state | normal-signing validation/vectors/SDK guards                                                            | Public route is Router-owned. SigningWorker private route must remain service-auth-only.                             |
| Ed25519 presign-pool refill and pool-hit finalize | `/v2/router-ab/ed25519/sign/presign-pool/prepare`, `/v2/router-ab/ed25519/sign` pool-hit branch | Ed25519 presign pool reservation/refill, signing flows                           | Router A/B presign routes and private SigningWorker forwarding                        | Durable Object unbound pool storage, local dev presign pool store, `router-ab-core` pool binding | Wallet Session bearer, unbound pool put/take, binding digest, one-use handle                       | `thresholdEd25519.presignPool.unit.test.ts`, normal-signing guard tests, Cloudflare/local source guards | Preserve pool-hit latency. Reject stale material and binding drift.                                                  |
| NEAR transaction signing                          | SDK public NEAR sign APIs                                                                       | signNear flows, signing queues, lane selection                                   | Uses Ed25519 Router A/B normal signing and budget/seal services                       | HSS client worker, Router/SigningWorker                                                          | Wallet Session readiness, UI confirmation boundary, signing material boundary                      | e2e NEAR, Ed25519 queue/commit tests, readiness gate tests                                              | User-visible signing should not trigger step-up when a fresh signing session is already valid.                       |
| NEP-413 message signing                           | SDK message signing API                                                                         | signNear shared message flow                                                     | Same Ed25519 Router A/B server routes                                                 | Same Ed25519 normal signing protocol                                                             | Same as NEAR signing plus message intent digest                                                    | NEP-413 e2e tests                                                                                       | Shares the Ed25519 normal-signing credential path.                                                                   |
| NEP-461 delegate signing                          | SDK delegate action signing and relay route                                                     | delegate flow, shared NEAR action/delegate types                                 | `delegateAction`, relay signed delegate route, sponsorship near policy                | Ed25519 normal signing for delegate signature; server NEAR RPC helper for relay tx               | Signed delegate body parser, relayer policy, server NEAR RPC boundary                              | delegate signing e2e, sponsorship route tests                                                           | Shared NEAR action/delegate types now live in `shared-ts`.                                                           |
| ECDSA-HSS key identities and bootstrap            | `/v1/hss/ecdsa/key-identities`, `/v1/hss/ecdsa/bootstrap`, registration bootstrap APIs          | wallet registration, add signer, ECDSA identity persistence                      | ECDSA route adapters, key identity and bootstrap handlers, Wallet Session JWT helpers | `router-ab-core` ECDSA-HSS public identity and scope parsers                                     | Request auth, public identity/context binding, Wallet Session JWT minting                          | ECDSA bootstrap/persistence/key identity tests                                                          | `signingRootId` and `signingRootVersion` must stay server/protocol/persistence boundary facts, not public SDK state. |
| ECDSA-HSS export/recovery/activation refresh      | `/v1/hss/ecdsa/export/share`, strict export/recover/refresh routes                              | export/recovery UI and session recovery flows                                    | ECDSA export/recovery/activation handlers, sealed restore service                     | Deriver A/B and SigningWorker strict routes, `router-ab-core` ECDSA-HSS request parsers          | Explicit export auth, activation identity, service auth                                            | export policy tests, hss role-local parser tests, sealed refresh tests                                  | Export-distinct telemetry and strict recovery binding stay release-sensitive.                                        |
| ECDSA-HSS presignature pool fill                  | `/v1/hss/ecdsa/presignature-pool/fill/init`, `/step`                                            | `routerAb/ecdsaHss/presignaturePool.ts`, pool fill route client                  | `routerAb/ecdsaHssPoolFillHandlers.ts`, presign bridge                                | SigningWorker ECDSA pool put, Durable Object/local store                                         | Wallet Session bearer, active-state scope, presign session CAS, private service auth               | ECDSA presign pool refill/policy/distributed tests                                                      | Current route names are still `v1/hss/ecdsa`; keep only if treated as Router-owned current routes.                   |
| ECDSA-HSS EVM digest signing                      | `/v1/hss/ecdsa/sign/prepare`, `/v1/hss/ecdsa/sign`                                              | EVM-family signer, ECDSA-HSS normal signing state, pool reservation              | Router A/B ECDSA signing routes, private SigningWorker forwarding                     | `router-ab-core` ECDSA-HSS request/finalize parsers, Cloudflare strict worker, local dev         | Wallet Session bearer, active-state scope, pool-take, request digest, service auth                 | `routerAbEcdsaHssNormalSigning.unit.test.ts`, Tempo/EVM e2e tests                                       | Browser pool key must include active-state scope. TS should not own raw presign material.                            |
| Signing budget status                             | Budget readers and sign-ready checks                                                            | signing budget route client and readiness gates                                  | `signingBudgetStatus.ts`, Wallet Session claim validation                             | Server policy only                                                                               | Wallet Session JWT auth and budget persistence boundary                                            | budget/status tests, Wallet Session claim boundary guard                                                | Should accept Router A/B Wallet Session claim kinds only for signing-capable budget reads.                           |
| Signing session seal apply/remove                 | `/v2/wallet-session/seal/apply-server-seal`, `/remove-server-seal`                              | sealed refresh store and rehydrate flow                                          | `threshold/session/signingSessionSeal/*`                                              | Server seal cipher and persistence                                                               | Wallet Session JWT parser, sealed payload parser, persistence compatibility                        | signing-session seal route/shared/postgres tests                                                        | Must hydrate signing-capable state only after Router A/B material/state validation succeeds.                         |
| Local Router A/B dev runtime                      | `pnpm router`, Caddy -> Router server, private local workers                                    | SDK route clients against `https://localhost:9444`                               | main Router server route table                                                        | `crates/router-ab-dev` local worker/bundled dispatcher                                           | Caddy single-upstream boundary, local service auth, local durable stores                           | local worker env/http tests, router smoke tests                                                         | Split public routing has been removed; local dev should have one public Router server.                               |
| Cloudflare strict runtime                         | deployed Router, Deriver A/B, SigningWorker, Durable Objects                                    | Browser SDK against deployed origin                                              | route adapters and deploy checks                                                      | `router-ab-cloudflare` strict worker and DOs                                                     | CORS, bearer auth, service bindings, DO storage, deployed runtime evidence                         | deploy checks, deployed browser evidence tests                                                          | Deployment evidence remains separate from local cleanup.                                                             |

## Call Graphs

### Ed25519 Wallet Session Issuance

```text
SDK unlock/registration
  -> warm-session/session policy builder
  -> /v2/router-ab/wallet-session/ed25519 route client
  -> server route adapter
  -> Wallet Session claim builder
  -> ThresholdService Ed25519 session/HSS state
  -> signing-session seal apply/remove when persisted
  -> persisted signing lane/readiness state
```

### Ed25519 Normal Signing

```text
SDK signNear / signMessage / signDelegate
  -> lane/readiness selector
  -> Router A/B Ed25519 credential builder
  -> prepare or presign-pool route client
  -> Router route adapter
  -> Wallet Session claim parser
  -> router-ab-core request parser and canonical digest validation
  -> Router admission, replay/quota/budget checks
  -> private SigningWorker route with internal service auth
  -> one-use round-1 or presign-pool state
  -> finalize route client
  -> response parser
  -> signed NEAR payload
```

### Ed25519 HSS Restore/Reconstruction

```text
SDK restore/unlock
  -> sealed session remove/apply
  -> HSS prepare/respond/finalize route client when material is missing
  -> server HSS route adapter
  -> ThresholdService HSS WASM boundary
  -> server share repair/persistence boundary
  -> SDK worker material validation
  -> persisted signing-capable readiness state
```

### ECDSA-HSS Bootstrap And Activation

```text
Registration / add-signer / unlock
  -> ECDSA-HSS bootstrap route client
  -> server route adapter
  -> authorization and public identity validation
  -> Wallet Session claim builder
  -> server/protocol signing-root and key-handle normalization
  -> Deriver A/B or local role bootstrap where needed
  -> activation/public identity state
  -> persisted ECDSA key ref with Router A/B normal-signing state
```

### ECDSA-HSS Presignature Pool Fill

```text
SDK ECDSA pool refill
  -> pool-fill init route client
  -> server presign session handler
  -> pool-fill step route client loop
  -> server CAS/session state
  -> SigningWorker private presignature-pool put with service auth
  -> durable/local pool storage keyed by active state
  -> SDK pool records keyed by active-state scope
```

### ECDSA-HSS EVM Digest Signing

```text
SDK EVM/Tempo signing
  -> ECDSA ready lane and key handle
  -> pool reservation or refill
  -> /v1/hss/ecdsa/sign/prepare route client
  -> Wallet Session claim parser and active-state scope validation
  -> router-ab-core ECDSA-HSS request digest parser
  -> Router admission and private SigningWorker prepare
  -> /v1/hss/ecdsa/sign finalize route client
  -> pool record take and response binding checks
  -> EVM signature returned to SDK
```

### Signing Session Seal

```text
SDK sealed refresh store
  -> apply/remove seal route client
  -> server seal route adapter
  -> Router A/B Wallet Session claim parser
  -> sealed payload parser
  -> seal cipher/persistence backend
  -> SDK rehydrate
  -> lane advertised only after Router A/B state and worker material are valid
```

## Boundary Exceptions

Allowed compatibility exceptions:

- Durable `thresholdSessionId` names where they identify concrete threshold/MPC
  protocol sessions.
- Stable route-auth wire discriminants such as `threshold_session` when they are
  part of an intentional persisted/request shape.
- Persistence parsers for previously stored signing-session seal records.
- Request-boundary parsers that reject old JWT kinds or old public route shapes.
- Historical docs and negative source/type fixtures.

Disallowed outside boundary modules:

- `sessionKind: 'cookie'` in signing-capable state.
- Legacy `threshold_ed25519_session_v1` or `threshold_ecdsa_session_v2` JWTs on
  Router A/B signing-capable routes.
- `signingRootId` and `signingRootVersion` on public SDK payloads or domain
  objects.
- Raw Ed25519 `xClientBaseB64u`, signing shares, nonce material, or ECDSA
  presign material in TypeScript core logic.
- Caddy path-split routing between multiple public Router servers.

## Type Tightening Backlog

Release-sensitive:

- Split Ed25519 auth-ready state from signing-material-ready state.
- Persist and restore worker-owned Ed25519 HSS material handles, not raw TS
  material.
- Require validated ECDSA-HSS normal-signing active state in every signable ECDSA
  lane.
- Make signing-capable Wallet Session credential types curve-specific and
  branded at the boundary.

High-value cleanup:

- Replace optional Router A/B state fields in ECDSA key refs with discriminated
  signable vs non-signable branches.
- Add type fixtures rejecting cookie sessions, raw JWT strings, legacy grants,
  and public signing-root fields.
- Collapse repeated route-auth header construction in SDK route clients.

## Bloat Deletion Backlog

- Delete remaining route tests or fixtures that preserve deleted public
  `/threshold-*/sign/*` and `/threshold-*/presign/*` behavior.
- Keep server-local NEAR/EVM RPC helpers out of `sdk-web`; add guard coverage so
  `sdk-server-ts` does not import `@/*`.
- Split oversized server modules by flow after the call graph is reviewed:
  `ThresholdSigningService.ts`, route adapters, and ECDSA pool-fill handlers are
  likely first candidates.
- Move local-dev evidence fixtures out of runtime paths when they are test-only.
- Consolidate Express/Cloudflare route adapters around shared handlers where the
  behavior is already identical.

## Proposed File Moves

Short-term:

- `packages/sdk-web/src/core/signingEngine/routerAb/ed25519/*` for Ed25519
  credential, route client, presign pool, and HSS lifecycle code.
- `packages/sdk-web/src/core/signingEngine/routerAb/ecdsaHss/*` for ECDSA-HSS
  credential, route client, presignature pool, and signing scope builders.
- `packages/sdk-server-ts/src/routerAb/walletSession/*` for Router A/B Wallet
  Session claim signing/validation and budget auth.
- `packages/sdk-server-ts/src/routerAb/ed25519/*` and
  `packages/sdk-server-ts/src/routerAb/ecdsaHss/*` for shared route handlers.

Longer-term:

- Split `crates/router-ab-cloudflare/src/lib.rs` by public Router routes,
  private SigningWorker routes, Deriver routes, and service-binding clients.
- Split `crates/router-ab-dev/src/lib.rs` into local HTTP dispatch, local
  storage, Ed25519 fixtures, and ECDSA-HSS fixtures.

## Guard And Test Additions

- Source guard: `packages/sdk-server-ts/src` must not import `@/*`.
- Source guard: active signing-capable route/service files must not call legacy
  threshold JWT parsers.
- Type fixture: persisted ECDSA record without Router A/B normal-signing state is
  non-signable.
- Type fixture: Ed25519 final signing input requires validated worker material
  handle.
- Unit test: sealed restore publishes a signable lane only after material
  rehydrate succeeds.
- Unit test: ECDSA browser pool key changes across activation epoch and
  SigningWorker identity.

## Findings

### Release-Blocking Correctness Issues

- No new release-blocking issue was proven by Phase 1 inventory alone.
- Deployed Cloudflare evidence remains outside this local cleanup phase and
  should stay in the deployment-evidence phase.

### High-Value Cleanup

- `sdk-server-ts` package isolation is complete, but source guard coverage should
  be added so the boundary does not regress.
- Worker-owned Ed25519/ECDSA material handles remain the highest-value cleanup
  because they remove raw crypto-adjacent material from TypeScript state.
- Signing Session seal is a key restore boundary and should be audited before
  additional route-file moves.

### Naming And Folder Organization

- Route names under `v1/hss/ecdsa` are still current Router-owned public ECDSA
  routes. Treat them as current wire names until a deliberate schema/route bump.
- `thresholdSessionId` remains acceptable as a protocol session identifier.
- `threshold-*` public signing/presign route names should remain deleted.

### Optional Ergonomics

- The public server export now lives on `@seams/sdk-server`. Browser installs of
  `@seams/sdk` should stay free of server-only dependencies.

## Validation Evidence

Commands run for this inventory/pass:

```sh
rtk rg -n "routerAb|RouterAb|router-ab|Wallet Session|walletSessionJwt" packages crates tests docs
rtk rg -n "ROUTER_AB_|/v2/router-ab|/v1/hss/ecdsa|wallet-session|presignature-pool|presign-pool" packages/sdk-web/src packages/sdk-server-ts/src packages/shared-ts/src crates/router-ab-core/src/protocol crates/router-ab-cloudflare/src crates/router-ab-dev/src/lib.rs
rtk rg --files tests | rtk rg 'routerAb|router-ab|thresholdEcdsa|thresholdEd25519|signingSessionSeal|walletSession'
rtk pnpm -C packages/sdk-server-ts type-check
rtk pnpm -C packages/shared-ts type-check
rtk pnpm -C packages/sdk-web type-check
```

The TypeScript type-check commands passed after the Phase 8 package-boundary
cleanup.

## Phase 2 Auth And Boundary Scan

Status: complete on June 18, 2026.

Scan summary:

- Active Router A/B SDK signing route clients use Wallet Session bearer auth
  and `credentials: 'omit'`.
- `credentials: 'include'` hits remain in non-signing request boundaries such as
  account UI and Email OTP flows. They are not active Router A/B normal-signing
  transport.
- Active server signing, budget, and signing-session seal paths use Router A/B
  Wallet Session claim parsers. Legacy threshold claim parsers remain in
  boundary validation and tests with explicit deletion comments.
- Source guards caught `derived-gamma` in `crates/router-ab-dev/src/lib.rs`.
  Runtime local normal signing now derives the committed fixture selection from
  `account_id`, `session_id`, and `signing_worker_id` instead of pinning a
  single committed fixture name in source. The guard now rejects the committed
  fixture-name family and committed fixture account ids from local runtime
  files.

Validation:

```sh
rtk rg -n "thresholdSessionAuthToken|routerAbNormalSigningGrant|prepareRouterAbNormalSigningV1|finalizeRouterAbNormalSigningV1" packages tests crates
rtk rg -n "sessionKind: 'cookie'|credentials: 'include'|parseThresholdEd25519SessionClaims|parseThresholdEcdsaSessionClaims" packages tests
rtk rg -n "threshold_ed25519_session_v1|threshold_ecdsa_session_v2|ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND|ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND|parseRouterAbEd25519WalletSessionClaims|parseRouterAbEcdsaHssWalletSessionClaims" packages/sdk-server-ts/src tests/unit tests/relayer
rtk pnpm -C tests exec playwright test -c playwright.source.config.ts unit/routerAbNormalSigningSdk.guard.unit.test.ts unit/routerAbServerWalletSessionClaimBoundary.guard.unit.test.ts --reporter=line
rtk cargo check --manifest-path crates/router-ab-dev/Cargo.toml --lib
```

## Phase 3 Type Model Scan

Status: in progress on June 18, 2026.

Initial target list:

- Sealed restore metadata still carries optional Wallet Session JWT fields and
  raw Ed25519/ECDSA material fields. Keep it as a boundary shape until the raw
  material compatibility cleanup is implemented.
- Persisted Ed25519 and ECDSA session records still allow optional Router A/B
  normal-signing state for old record reads. Split those persistence records
  from signable in-memory records so final signing cannot receive an incomplete
  lifecycle state.
- NEAR/EVM final signing ready-state types still allow optional
  `xClientBaseB64u`, `clientVerifyingShareB64u`, and Router A/B material fields.
  Replace those final inputs with worker-owned material handles and public
  binding facts.
- Ed25519 final normal-signing ready state now carries
  `ed25519HssMaterialHandle` and `ed25519HssMaterialBindingDigest`, with a
  type fixture rejecting ready states that omit either field.
- ECDSA final signing already flows through `ReadyEcdsaSignerSession` and
  `ReadyRouterAbEcdsaHssNormalSigning`, but the signable client-share union still
  includes `role_local_ready_state_blob`. Final role-local share opening now
  converts the session to a handle-only local signable union after storing that
  material in the HSS worker, then reopens it by material handle before computing
  the signing share. Replace the ready-session raw-material branch with a
  handle-only branch before marking the full ECDSA type-model cleanup complete.
- UI and Email OTP request shapes still carry `sessionKind: 'jwt' | 'cookie'`.
  Keep them as prompt/request-boundary shapes, then normalize into JWT-only
  signing state before a lane can be advertised as signable.

Validation:

```sh
rtk rg -n "routerAbNormalSigning\\?:|routerAbEcdsaHssNormalSigning\\?:|walletSessionJwt\\?:|sessionKind\\?:|thresholdSessionId\\?:|signingWorkerId\\?:|xClientBaseB64u\\?:|clientVerifyingShareB64u\\?:" packages/sdk-web/src packages/shared-ts/src packages/sdk-server-ts/src
rtk rg -n "xClientBaseB64u\\?: string|clientVerifyingShareB64u\\?: string|routerAbNormalSigning\\?: RouterAbEd25519NormalSigningState|routerAbEcdsaHssNormalSigning\\?: RouterAbEcdsaHssNormalSigningStateV1|walletSessionJwt\\?: string|sessionKind: 'jwt' \\| 'cookie'" packages/sdk-web/src/core/signingEngine packages/sdk-web/src/SeamsWeb packages/shared-ts/src/utils/signingSessionSeal.ts packages/sdk-server-ts/src/core/types.ts
rtk pnpm -C packages/sdk-web type-check
```

Additional Phase 3 validation after the ECDSA worker-handle cut:

```sh
rtk pnpm -C packages/sdk-web type-check
```

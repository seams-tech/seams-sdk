# Router A/B Cleanup Plan

Date created: June 16, 2026

Status: active route cleanup is locally implemented, with one local architecture
phase still open. The public threshold-era lifecycle endpoint migration is
implemented locally, and Ed25519/ECDSA signatures are signed only through Router
A/B in the active SDK/server signing paths. Local Rust ECDSA-HSS route parity is
implemented in Phase 15.8 with live `pnpm router` smoke/evidence capture. Phase
15.9 tracks the crypto-secret boundary cleanup that moves Ed25519/ECDSA client
signing material behind `crates/signer-core` and WASM worker handles. Phase
15.10 prepares the raw-material deletion gates and stale-record invalidation
paths. Phase 15.11 makes signable persisted state strict. Phase 15.12 deletes
raw-material fields and helpers after those prerequisites are closed for each
curve/surface. Phases 15.13 through 15.16 split the broader rot audit into SDK
route/auth boundaries, canonical digests, Rust/local topology cleanup, and
test/docs/artifact hygiene. Phase 15.17 tracks the remaining server seal/budget
boundary cleanup. Phase 15.18 is the spec-to-code compliance audit gate after
local cleanup is complete, and Phase 15.19 is reserved for issues found by that
audit. Cloudflare deployment-config hardening and deployed-runtime checks are
tracked separately in Phase 16 as the post-deployment release tail.

Primary plans:

- [router-a-b-single-session.md](./router-a-b-single-session.md)
- [router-a-b-ecdsa.md](./router-a-b-ecdsa.md)
- [refactor-68-wallet-session-v2.md](./refactor-68-wallet-session-v2.md)
- [router-A-B-signer.md](./router-A-B-signer.md)

## Goal

Make Router A/B the only SDK/server signing architecture for Ed25519 and ECDSA
signatures.

The old non-Router threshold-session signing surfaces must be deleted after
Router A/B replacements cover the same product signing cases:

- Ed25519 NEAR transaction signing.
- Ed25519 NEP-413 message signing.
- Ed25519 NEP-461 delegate-action signing.
- Ed25519 presign-pool hit and pool-miss signing.
- ECDSA-HSS EVM digest signing.
- ECDSA-HSS presign-pool hit and pool-miss signing.

This is broader than the Wallet Session V2 cutover. That cutover removed the
old Router A/B public grant flow. This cleanup removes the separate non-Router
threshold-session signing architecture.

## Current Finding

Router A/B legacy normal-signing grant/v1 code is gone and guarded. Active SDK
Ed25519 and ECDSA-HSS signing paths use Router A/B Wallet Session credentials,
and old public `/threshold-ed25519/*` and `/threshold-ecdsa/*` signing route
literals are now confined to the cleanup plan and source-guard deny-lists.
ECDSA live presign refill requires Router A/B `poolFill`; the retained
`local_threshold_ecdsa_presignature_pool` shape is limited to persisted-record
cleanup surfaces. Server Wallet Session record storage is now named through
`WalletSessionStore` types, factories, parser names, and tests.

Remaining cleanup work:

- Local Rust `pnpm router` ECDSA-HSS live smoke/evidence capture is complete in
  Phase 15.8.
- Crypto-secret material must be moved out of TypeScript orchestration and into
  `crates/signer-core` plus WASM worker-owned handles in Phase 15.9.
- Raw-material deletion must be prepared in Phase 15.10, blocked on strict
  persisted state in Phase 15.11, and executed per eligible curve/surface in
  Phase 15.12.
- The broader refactor rot found in the June 18, 2026 diff audit must be
  closed in Phases 15.13 through 15.16: SDK route/auth boundaries, canonical
  scope binding, module splitting, and test replacement mapping.
- Remaining server Ed25519 seal and budget boundary cleanup is tracked in Phase
  15.17.
- After Phases 15.9 through 15.17 are closed, Phase 15.18 runs the
  `spec-to-code-compliance` audit against the Router A/B specification corpus and
  active implementation. Any issues found by that audit must be copied into
  Phase 15.19 as traceable remediation tasks.
- Post-deployment Cloudflare deployment-config hardening and browser/runtime
  evidence are tracked in Phase 16.

Current Router A/B private worker routes such as
`/router-ab/v1/signing-worker/sign`, `/router-ab/v1/signing-worker/sign/prepare`,
and `/router-ab/v1/signing-worker/ecdsa-hss/sign` are active internal
cross-worker protocol routes. Keep them until the Router A/B protocol itself
gets a new durable wire version.

Current deletion blockers:

- Phase 15.9 must remove raw Ed25519/ECDSA client signing material from active
  TypeScript signing orchestration before the local cleanup plan is complete.
- Phase 15.10 must prepare stale raw-material record invalidation without
  deleting parsers or fields that Phase 15.11 still needs to classify old
  development state.
- Phase 15.11 must make current signable persisted state strict enough that raw
  fields cannot be selected as ready.
- Phase 15.12 must delete the obsolete raw-material persistence/request
  compatibility surface only after the relevant Phase 15.10 and 15.11 gates are
  complete for that curve/surface.
- Phases 15.13 through 15.16 must close the broad Router A/B rot audit without
  deleting core Router A/B features or reintroducing old threshold-session
  compatibility.
- Phase 15.17 must close the remaining server seal/budget boundary cleanup.
- Phase 15.18 must run the final spec-to-code compliance audit after the local
  cleanup plan is complete. Phase 15.19 must resolve or explicitly defer every
  audit finding before Cloudflare release evidence work resumes.
- Cloudflare deployment-config hardening and browser/runtime evidence remain the
  production release-tail blockers in Phase 16.

## Deletion Rules

- No legacy flags.
- No compatibility fallback from Router A/B to `/threshold-ed25519/*` or
  `/threshold-ecdsa/*` signing.
- Destructive route/helper deletion is blocked until active SDK signing callers
  prove they use Router A/B only for the same product flow.
- Delete obsolete public routes, SDK helpers, tests, fixtures, mocks, docs, and
  route definitions once their Router A/B replacement is wired.
- Keep compatibility only at persistence/request boundaries for shapes that are
  still read in development. Each remaining boundary parser must have a deletion
  condition and tests.
- Keep `V1` or `V2` suffixes where they are current durable protocol labels,
  wire schemas, metrics, persisted record versions, or cross-language contracts.
- Remove suffixes and old threshold-session names from internal code after the
  old signing stack is deleted.

## Phase 0: Freeze Router A/B-Only Requirement

- [x] Declare Router A/B-only Ed25519/ECDSA signing as a release requirement in
      `router-a-b-single-session.md`, `router-a-b-ecdsa.md`, and
      `router-A-B-signer.md`.
      Completed: `router-a-b-single-session.md` and `router-A-B-signer.md` state
      that Cloudflare Router A/B deployment is blocked until Ed25519 and ECDSA
      signing use Router A/B only, and `router-a-b-ecdsa.md` classifies
      ECDSA-HSS as a pre-deploy release blocker.
- [x] Update release readiness wording so Cloudflare deployment is blocked until
      the old non-Router signing routes are deleted or explicitly moved out of
      release scope.
      Completed in this cleanup plan and the Router A/B release docs: old
      non-Router `/threshold-ed25519/*` and `/threshold-ecdsa/*` public signing
      routes are release-scope blockers until deleted, while deployed runtime
      evidence remains tracked as the separate Cloudflare release tail.
Source-guard setup and tightened guard evidence now live in Phase 8 so release
requirements and static rejection coverage are not duplicated.

## Phase 1: Confirm Router A/B Replacement Coverage

Current product-flow matrix:

| Product flow | SDK entrypoint | Public Router route | Private worker route | Old route status | Focused coverage |
| --- | --- | --- | --- | --- | --- |
| Ed25519 NEAR transaction | `signTransactions` | Pool hit: `/v2/router-ab/ed25519/sign`; pool miss: `/v2/router-ab/ed25519/sign/prepare` then `/v2/router-ab/ed25519/sign`; refill: `/v2/router-ab/ed25519/sign/presign-pool/prepare` | `/router-ab/v1/signing-worker/sign*` | `/threshold-ed25519/*` public signing routes deleted and guarded | `thresholdEd25519.presignPool.unit.test.ts`, `routerAbNormalSigningVectors.unit.test.ts`, `routerAbNormalSigningSdk.guard.unit.test.ts` |
| Ed25519 NEP-413 message | `signNep413` | Pool hit: `/v2/router-ab/ed25519/sign`; pool miss: `/v2/router-ab/ed25519/sign/prepare` then `/v2/router-ab/ed25519/sign`; refill: `/v2/router-ab/ed25519/sign/presign-pool/prepare` | `/router-ab/v1/signing-worker/sign*` | `/threshold-ed25519/*` public signing routes deleted and guarded | `thresholdEd25519.presignPool.unit.test.ts`, `routerAbNormalSigningVectors.unit.test.ts`, `routerAbNormalSigningSdk.guard.unit.test.ts` |
| Ed25519 NEP-461 delegate action | `signDelegate` | Pool hit: `/v2/router-ab/ed25519/sign`; pool miss: `/v2/router-ab/ed25519/sign/prepare` then `/v2/router-ab/ed25519/sign`; refill: `/v2/router-ab/ed25519/sign/presign-pool/prepare` | `/router-ab/v1/signing-worker/sign*` | `/threshold-ed25519/*` public signing routes deleted and guarded | `thresholdEd25519.presignPool.unit.test.ts`, `routerAbNormalSigningVectors.unit.test.ts`, `routerAbNormalSigningSdk.guard.unit.test.ts` |
| ECDSA-HSS EVM digest | `signEvmFamily` | Sign: `/v1/hss/ecdsa/sign/prepare` then `/v1/hss/ecdsa/sign`; pool fill: `/v1/hss/ecdsa/presignature-pool/fill/init` and `/v1/hss/ecdsa/presignature-pool/fill/step` | `/router-ab/v1/signing-worker/ecdsa-hss/sign*` and `/router-ab/v1/signing-worker/ecdsa-hss/presignature-pool/put` | `/threshold-ecdsa/*` public signing and presign routes deleted and guarded | `routerAbEcdsaHssNormalSigning.unit.test.ts`, `thresholdEcdsa.presignPoolRefill.unit.test.ts`, `routerAbNormalSigningSdk.guard.unit.test.ts` |

The matrix above describes the intended SDK/server, strict Cloudflare route
surface, and local Rust `pnpm router` route parity. The ECDSA-HSS private
SigningWorker paths are covered in Phase 15.8.

Remaining coverage gap:

- [x] Existing app, wallet iframe, VoiceID, docs examples, and test harnesses
      have a Router A/B signing path for every currently supported signing use
      case.
      Completed for the current app/docs/test surface. Updated active ECDSA,
      TEE/serverless, and stealth-address docs to reference Router A/B ECDSA-HSS
      and Router A/B Ed25519 behavior instead of deleted public threshold signing
      routes. Focused scans now find no deleted public signing route literals or
      old SDK signing helper names across `apps`, `voiceId`, active docs,
      `packages/sdk-web/src/SeamsWeb`, active SDK signing code, SDK relayer
      clients, e2e helpers, or e2e tests outside the dedicated guard and cleanup
      plan.

## Phase 2: Switch SDK Ed25519 Signing To Router A/B Only

- [x] Update `signNear`, `signTransactions`, `signDelegate`, and `signNep413` so
      the active threshold Ed25519 path requires Router A/B normal-signing
      configuration and Wallet Session credentials.
      Completed by requiring `RouterAbEd25519NormalSigningReadyState` in the
      active transaction, NEP-413, and delegate signing executors, with
      `walletSessionJwt` sourced from the ready-state builder.
- [x] Replace calls to `finalizeThresholdEd25519Presign` with Router A/B
      pool-hit finalize requests.
- [x] Replace old pool-refill calls that post to `/threshold-ed25519/*` with the
      Router A/B presign-pool refill route.
- [x] Remove threshold-session auth branches from Ed25519 signing inputs.
      Completed for active product signing inputs; `thresholdSessionAuthToken`
      remains only in named persistence, recovery, export, budget, and
      request-boundary cleanup surfaces.
- [x] Make invalid Ed25519 signing states unrepresentable: a signing-ready state
      carries Router A/B URL, Wallet Session JWT, account id, session id,
      SigningWorker identity, signer public key, scope, and pool state.
      Completed with `RouterAbEd25519NormalSigningReadyState`,
      `requireRouterAbEd25519NormalSigningReadyState`, and
      `routerAbWalletSessionCredential.typecheck.ts`, which rejects missing
      Router A/B normal-signing state, cookie auth, missing Wallet Session JWT,
      and legacy auth-token object spreads.
- [x] Delete Ed25519 SDK fallback code that can still call
      `/threshold-ed25519/sign/init`,
      `/threshold-ed25519/sign/finalize`, or
      `/threshold-ed25519/sign/finalize-and-dispatch`.
      Completed by deleting the old `thresholdEd25519Presign` route client and
      the shared fallback helpers that called it.
- [x] Delete old presign fallback calls from `signTransactions.ts`,
      `signNep413.ts`, and `signDelegate.ts` after Router A/B pool hit/miss
      behavior is mandatory for those flows.
- [x] Delete imports and call sites for
      `tryFinalizeThresholdEd25519NearTransactionPresign` and
      `tryFinalizeThresholdEd25519SignatureOnlyPresign` from active signing
      flows.
- [x] Update Ed25519 SDK tests to assert Router A/B request construction,
      bearer auth, `credentials: 'omit'`, pool-hit one-request signing, pool-miss
      prepare/finalize signing, and no old route calls.
      Completed by deleting `thresholdEd25519.immediateSignFallback`,
      `thresholdEd25519.presignFinalizeClient`, and
      `thresholdEd25519.relayerClient`; adding Router A/B guard coverage for
      bearer auth and `credentials: 'omit'`; using Router A/B Rust vector
      coverage for request construction and admission digests; and keeping
      `thresholdEd25519.presignPool.unit.test.ts` as the pool-hit reservation,
      burn, and pool-miss refill coverage.

## Phase 3: Switch SDK ECDSA Signing To Router A/B Only

- [x] Add or finish public SDK ECDSA-HSS Router A/B prepare/finalize request
      builders.
- [x] Replace `authorizeEcdsaWithSession` with Router A/B Wallet Session
      admission.
- [x] Replace `signThresholdEcdsaDigestWithPool` with Router A/B ECDSA-HSS
      prepare/finalize or pool-hit finalize.
- [x] Route `signEvmFamily` secp256k1 signing through Router A/B ECDSA-HSS
      SigningWorker state.
      Completed for the active pool-hit path: `signReadySecp256k1Digest` now
      consumes ready Router A/B ECDSA-HSS state and Wallet Session bearer
      credentials, calls `/v1/hss/ecdsa/sign/prepare`, computes the client HSS
      signature share locally, and calls `/v1/hss/ecdsa/sign`.
- [x] Preserve the latency model while replacing `signEvmFamily`: pool hits use
      the Router A/B ECDSA-HSS pool path, and pool misses use Router A/B
      prepare/finalize without calling `/threshold-ecdsa/*`.
      Completed for the active SDK EVM path: pool hits consume Router A/B
      SigningWorker presignatures, while cold pool misses refill through the
      Router A/B ECDSA-HSS pool-fill route and then sign through Router A/B
      prepare/finalize.
- [x] Add interim ECDSA-HSS cold-pool behavior for active EVM signing: when the
      client pool is empty, refill one client/server presignature into the
      Router A/B SigningWorker pool, then sign through Router A/B
      prepare/finalize.
      This keeps ECDSA-HSS functional for cold local testing.
- [x] Add Router A/B-named ECDSA-HSS presignature pool-fill init/step routes
      and switch SDK pool-fill handshakes to them.
      Completed by adding shared route constants, Express/Cloudflare relay route
      registration, route definitions, SDK route selection for Router A/B
      pool-fill, and focused assertions that active pool-fill traffic uses
      `/v1/hss/ecdsa/presignature-pool/fill/init` and
      `/v1/hss/ecdsa/presignature-pool/fill/step`.
- [x] Delete imports and call sites for `authorizeEcdsaWithSession` and
      `signThresholdEcdsaDigestWithPool` from active EVM signing flows.
      Validation: `rtk pnpm -C packages/sdk-web type-check`, `rtk pnpm -C
tests exec playwright test -c playwright.unit.config.ts
./unit/evmFamilyEcdsaIdentity.unit.test.ts
./unit/signingFlow.readySigner.unit.test.ts --reporter=line`, and `rtk pnpm
-C tests exec playwright test -c playwright.config.ts
./unit/routerAbNormalSigningSdk.guard.unit.test.ts --reporter=line`.
- [x] Delete obsolete SDK ECDSA authorize and foreground threshold-signing
      helpers after active EVM signing moved to Router A/B.
      Completed by deleting `authorizeEcdsaWithSession`,
      `signThresholdEcdsaDigestWithPool`, `ecdsaSignInit`, and
      `ecdsaSignFinalize` from SDK source. Remaining same-name server handler
      methods are old public route deletion blockers for Phase 4 and Phase 5.
- [x] Delete legacy ECDSA signing helpers from the public SDK
      `packages/sdk-web/src/threshold.ts` entrypoint.
      Completed by removing `authorizeEcdsaWithSession`, `ecdsaPresignInit`,
      `ecdsaPresignStep`, `ecdsaSignInit`, and `ecdsaSignFinalize` exports and
      tightening the source guard.
- [x] Remove obsolete active EVM signing presign-refill callback plumbing that
      existed only for the old threshold-session presign pool.
      Completed by deleting the `Secp256k1Engine`
      `routerAbEcdsaHssPresignaturePoolPolicy` and
      `onThresholdEcdsaPresignRefillScheduled` inputs, the runtime
      `STEP_08_PRESIGN_REFILL_SCHEDULED` emission, and active-engine tests that
      protected that old callback behavior.
- [x] Remove threshold-session auth branches from ECDSA signing inputs.
      Completed for the active ECDSA ready-signing path: ready ECDSA signing
      inputs now use the Router A/B Wallet Session credential instead of
      `signerSession.transport.auth`, and any `thresholdSessionAuthToken`
      mapping is confined to current budget/persistence boundary shapes.
- [x] Make invalid ECDSA signing states unrepresentable: a signing-ready state
      carries Router A/B URL, Wallet Session JWT, wallet id, ECDSA threshold key
      id, signing root id/version, activation epoch, SigningWorker identity,
      public identity, and pool state.
      Completed by requiring `routerAbEcdsaHssNormalSigning` on ready ECDSA
      signer sessions, removing duplicated ready-transport auth, and adding
      type fixtures that reject cookie auth, top-level threshold-session auth,
      missing Router A/B state, and broad-spread construction. Validation:
      `rtk pnpm -C packages/sdk-web type-check`, `rtk pnpm -C tests exec
      playwright test -c playwright.unit.config.ts
      ./unit/evmFamilyEcdsaIdentity.unit.test.ts --reporter=line`, and `rtk
      pnpm -C tests exec playwright test -c playwright.unit.config.ts
      ./unit/signingFlow.readySigner.unit.test.ts --reporter=line`.
- [x] Delete ECDSA SDK fallback code that can still call
      `/threshold-ecdsa/authorize`, `/threshold-ecdsa/presign/init`,
      `/threshold-ecdsa/presign/step`, `/threshold-ecdsa/sign/init`, or
      `/threshold-ecdsa/sign/finalize`. This includes deleting the internal SDK
      `ecdsaPresignInit` / `ecdsaPresignStep` helpers and the
      no-`routerAbEcdsaHssPoolFill` branch in `runPresignHandshake` after the
      Router A/B pool-fill helper is the only ECDSA presign producer.
- [x] Update ECDSA SDK tests to assert Router A/B request construction, bearer
      auth, active-state binding, pool-hit signing, pool-miss signing, and no old
      route calls.
      Completed with the Router A/B ECDSA-HSS normal-signing tests, presign pool
      refill tests, and the Router A/B SDK source guard. Follow-up cleanup
      later renamed persisted, sealed, helper, and test-harness auth material to
      `walletSessionJwt`.
- [x] Add focused SDK tests proving the interim Router A/B ECDSA-HSS pool-fill
      bridge behavior: refill sends a `poolFill` destination to the presign
      producer, and a cold pool miss refills once before Router A/B
      prepare/finalize signing.
      Updated to assert Router A/B pool-fill init/step route usage.

## Phase 4: Delete Old Public Server Signing Routes

- [x] Delete Ed25519 public signing routes from Express and Cloudflare routers:
      `/threshold-ed25519/sign/init`,
      `/threshold-ed25519/sign/finalize`, and
      `/threshold-ed25519/sign/finalize-and-dispatch`.
      Completed by removing these route registrations from Express,
      Cloudflare, and `routeDefinitions.ts`. The low-level sign init/finalize
      handler internals remain as Phase 5 blockers until no Router A/B private
      primitive needs them.
- [x] Delete old Ed25519 presign refill route once Router A/B refill replaced
      it. Completed by removing `/threshold-ed25519/presign/refill` from
      Express, Cloudflare, `routeDefinitions.ts`, and the scanned source
      allowlist.
- [x] Delete old Ed25519 authorize route once Router A/B admission fully
      replaces it.
      Completed by removing `/threshold-ed25519/authorize` from Express,
      Cloudflare, route-level tests, stale E2E fixtures, and scanned active
      source. The literal now remains only in zero-tolerance source-guard tokens
      and this plan.
- [x] Delete ECDSA public signing routes from Express and Cloudflare routers:
      `/threshold-ecdsa/sign/init` and `/threshold-ecdsa/sign/finalize`.
- [x] Delete old ECDSA authorize route once Router A/B admission replaced it.
      Completed by removing `/threshold-ecdsa/authorize` from Express,
      Cloudflare, route definitions, and the scanned route allowlist. Follow-up
      handler/type cleanup completed in Phase 5.
- [x] Delete old ECDSA presign route registrations once Router A/B pool-fill
      fully replaces them: remove public Express and Cloudflare
      `/threshold-ecdsa/presign/init` and `/threshold-ecdsa/presign/step`
      registrations plus matching `routeDefinitions.ts` entries. Keep only the
      Router A/B public pool-fill routes and any private/server-local presign
      primitive code they still call.
      Completed by removing the public route registrations while retaining the
      Router A/B `/v1/hss/ecdsa/presignature-pool/fill/*` routes.
- [x] Remove the deleted ECDSA authorize/sign routes from `routeDefinitions.ts`
      and source-guard allowlists.
- [x] Remove the deleted Ed25519 sign/presign routes from
      `routeDefinitions.ts` and source-guard allowlists.
- [x] Remove deleted-route fallout from generated route docs, CORS tests, and
      self-hosted route inventories.
      Completed for the tested route inventories and stale route-level
      assertions: the relayer route tests no longer expect the deleted Ed25519 or
      ECDSA public signing routes, and the deleted ECDSA/Ed25519 route suites are
      removed from package scripts and Playwright includes.
- [x] Keep only Router A/B public Router routes and Router A/B private
      SigningWorker routes for signing.
      Completed for the old public authorize/sign/presign-refill surfaces. The
      remaining threshold ECDSA/Ed25519 routes are non-signing session/bootstrap,
      HSS ceremony, internal cosign, or Router A/B pool-fill surfaces.

## Phase 5: Delete Old Threshold Signing Handlers

- [x] Delete Ed25519 handler methods that exist only for
      `/threshold-ed25519/sign/init`,
      `/threshold-ed25519/sign/finalize`, or
      `/threshold-ed25519/sign/finalize-and-dispatch`.
      Completed by removing the public sign init/finalize coordinator methods
      from `signingHandlers.ts`, removing the Ed25519 presign refill and
      finalize-and-dispatch service methods, and narrowing the Ed25519 scheme
      module to the remaining private cosign continuation protocol.
- [x] Delete ECDSA handler methods that exist only for
      `/threshold-ecdsa/authorize`, `/threshold-ecdsa/presign/init`,
      `/threshold-ecdsa/presign/step`, `/threshold-ecdsa/sign/init`, or
      `/threshold-ecdsa/sign/finalize`.
      Completed by removing the authorize/sign init/finalize service methods,
      request parsers, scheme authorize entry, signing-session store dependency,
      public route tests, and stale bootstrap-policy authorize assertion. The
      remaining ECDSA presign handlers are Router A/B pool-fill init/step.
- [x] Keep cryptographic primitive helpers only when Router A/B SigningWorker
      handlers call them directly.
      Completed for the current normal-signing cleanup scope. The retained
      ECDSA-HSS presignature-pool primitive is now owned by
      `ThresholdService/routerAb/ecdsaHssPoolFillHandlers.ts`, and the private
      SigningWorker pool-put bridge is owned by
      `ThresholdService/routerAb/ecdsaHssPresignBridge.ts`. Current
      `/threshold-ecdsa/hss/bootstrap` and `/threshold-ecdsa/hss/export/share`
      remain ECDSA HSS lifecycle/export routes, not old public signing
      primitives.
- [x] Delete request/response types, parsers, metrics, logs, and budget
      idempotency records that only serve old public signing routes.
      Ed25519 public route request/response types, validation parsers, metrics,
      operation fingerprint export, and direct legacy tests were removed. This
      also now covers ECDSA authorize/sign request/response types, old
      signing-session parsers/stores, route-era presign hint config, and stale
      Postgres signing-session DDL. The active Ed25519 one-use presign store
      is now named as Router A/B at the parser/type boundary and uses
      `router_ab_ed25519_presign_record_v2` plus
      `router_ab_ed25519_presign_refill_rate_limit_v2` persisted labels. This
      now also covers the server Wallet Session record store rename away from
      `AuthSessionStore`; live ECDSA-HSS pool-fill route tests now send the
      required Router A/B `poolFill` binding instead of the old key-only
      presign-init body. Follow-up cleanup renamed the retained ECDSA-HSS
      pool-fill owner-forward headers and diagnostics away from old
      threshold-presign route wording, then renamed the live server
      init/step request and response types to
      `RouterAbEcdsaHssPoolFill*`. The retained ECDSA-HSS pool-fill session
      store and server presignature pool types/classes are also now named as
      Router A/B ECDSA-HSS pool-fill state, and internal Durable Object
      operation discriminants use Router A/B ECDSA-HSS pool-fill/presignature
      names. Server-side module ownership is now complete for the retained
      ECDSA-HSS pool-fill state machine and strict SigningWorker pool-put
      bridge. A final old-route source audit found no active old public
      sign/presign helpers or deleted signing route paths outside
      zero-tolerance guard tests.
      Validation: `rtk pnpm -C packages/sdk-web run type-check`, `rtk pnpm -C
      packages/sdk-server-ts run type-check`, `rtk pnpm -C packages/sdk-web run
      build`, and `rtk pnpm -C tests exec playwright test -c
      playwright.unit.config.ts unit/thresholdEd25519.presignPool.unit.test.ts
      unit/thresholdEd25519.presignStore.unit.test.ts --reporter=line`. Latest
      ECDSA-HSS pool-fill diagnostics validation: `rtk pnpm -C
      packages/sdk-server-ts run type-check`, `rtk pnpm -C tests exec
      playwright test -c playwright.unit.config.ts
      unit/thresholdEcdsa.presignDistributed.unit.test.ts --reporter=line`, and
      `rtk git diff --check`. Latest live type rename validation:
      `rtk pnpm -C packages/sdk-server-ts run type-check`, `rtk pnpm -C
      packages/sdk-web run type-check`, `rtk pnpm -C tests exec playwright test
      -c playwright.unit.config.ts unit/thresholdEcdsa.presignDistributed.unit.test.ts
      unit/thresholdEcdsa.presignPoolRefill.unit.test.ts --reporter=line`, and
      `rtk git diff --check`. Latest retained store/type rename validation:
      `rtk pnpm -C packages/sdk-server-ts run type-check`, `rtk pnpm -C tests
      exec playwright test -c playwright.unit.config.ts
      unit/thresholdEcdsa.presignDistributed.unit.test.ts
      unit/thresholdEcdsa.postgresRecords.unit.test.ts --reporter=line`, `rtk
      pnpm -C tests exec playwright test -c playwright.relayer.config.ts
      relayer/threshold-ecdsa.signature-harness.test.ts --reporter=line`, and
      `rtk git diff --check`. Latest Durable Object op-name validation: `rtk
      pnpm -C packages/sdk-server-ts run type-check`, `rtk pnpm -C tests exec
      playwright test -c playwright.unit.config.ts
      unit/thresholdEcdsa.presignDistributed.unit.test.ts
      unit/thresholdPostgresMalformedCleanup.unit.test.ts --reporter=line`,
      `rtk pnpm -C tests exec playwright test -c playwright.relayer.config.ts
      relayer/threshold-ecdsa.durable-stores.test.ts
      relayer/threshold-ecdsa.signature-harness.test.ts --reporter=line`, and
      `rtk git diff --check`. Latest server module-ownership validation: `rtk
      pnpm -C packages/sdk-server-ts run type-check`, `rtk pnpm -C tests exec
      playwright test -c playwright.unit.config.ts
      unit/thresholdEcdsa.presignDistributed.unit.test.ts
      unit/routerAbEcdsaHssPresignBridge.unit.test.ts
      unit/thresholdEcdsa.behavior.guard.unit.test.ts --reporter=line`, `rtk
      pnpm -C tests exec playwright test -c playwright.relayer.config.ts
      relayer/threshold-ecdsa.signature-harness.test.ts
      relayer/threshold-ecdsa.durable-stores.test.ts --reporter=line`, and an
      active-source scan for deleted public ECDSA/Ed25519 signing route helpers.
- [x] Move any still-current low-level signing primitive into a Router A/B
      SigningWorker module with narrow private inputs.
      Completed for the retained Router A/B ECDSA-HSS presignature-pool
      primitive. SDK-side modules moved to `routerAb/ecdsaHss/*`; server-side
      modules moved to `ThresholdService/routerAb/ecdsaHssPoolFillHandlers.ts`
      and `ThresholdService/routerAb/ecdsaHssPresignBridge.ts`. The service
      field is now `routerAbEcdsaHssPoolFillHandlers`, and the secp256k1 scheme
      module reaches the retained primitive only through its Router A/B
      `poolFill` driver. ECDSA HSS bootstrap/export stay outside this Phase 5
      normal-signing cleanup as lifecycle/export flows.
      Validation: `rtk pnpm -C packages/sdk-server-ts run
      type-check`, `rtk pnpm -C tests exec playwright test -c
      playwright.unit.config.ts unit/thresholdEcdsa.presignDistributed.unit.test.ts
      unit/routerAbEcdsaHssPresignBridge.unit.test.ts --reporter=line`, and
      `rtk git diff --check`. Latest retained store/type rename validation:
      `rtk pnpm -C packages/sdk-server-ts run type-check`, `rtk pnpm -C tests
      exec playwright test -c playwright.unit.config.ts
      unit/thresholdEcdsa.presignDistributed.unit.test.ts
      unit/thresholdEcdsa.postgresRecords.unit.test.ts --reporter=line`, `rtk
      pnpm -C tests exec playwright test -c playwright.relayer.config.ts
      relayer/threshold-ecdsa.signature-harness.test.ts --reporter=line`, and
      `rtk git diff --check`. Latest Durable Object op-name validation: `rtk
      pnpm -C packages/sdk-server-ts run type-check`, `rtk pnpm -C tests exec
      playwright test -c playwright.unit.config.ts
      unit/thresholdEcdsa.presignDistributed.unit.test.ts
      unit/thresholdPostgresMalformedCleanup.unit.test.ts --reporter=line`,
      `rtk pnpm -C tests exec playwright test -c playwright.relayer.config.ts
      relayer/threshold-ecdsa.durable-stores.test.ts
      relayer/threshold-ecdsa.signature-harness.test.ts --reporter=line`, and
      `rtk git diff --check`. Latest SDK module-ownership validation:
      `rtk pnpm -C packages/sdk-web run type-check` and `rtk pnpm -C tests exec
      playwright test -c playwright.unit.config.ts
      unit/thresholdEcdsa.presignPoolPolicy.unit.test.ts
      unit/thresholdEcdsa.presignPoolRefill.unit.test.ts
      unit/routerAbNormalSigningSdk.guard.unit.test.ts
      unit/signingEngineArchitecture.state.guard.unit.test.ts --reporter=line`.

## Phase 6: Clean Persistence And Session Models

- [x] Delete active signing reads of `thresholdSessionAuthToken`,
      `thresholdSessionKind`, and old threshold-session token-field route auth.
      ECDSA active signing no longer reads this auth shape directly; current
      SDK source uses `walletSessionJwt` and Wallet Session auth unions. The
      retained `threshold_session` route-auth discriminant is a stable protocol
      value for Wallet Session JWT bearer auth.
  - [x] Rename current ECDSA key-ref auth from `thresholdSessionAuthToken` to
        `walletSessionJwt`.
        `ThresholdEcdsaSecp256k1KeyRef` now carries `walletSessionJwt` and
        rejects `thresholdSessionAuthToken`; bootstrap adapters map server
        `jwt` values into that field, and persisted-record adapters write the
        old storage key only at the record boundary. Public SeamsWeb bootstrap
        key refs also omit `walletSessionJwt`. Validation: `packages/sdk-web`
        type-check and focused key-ref/source-guard tests passed for this
        slice.
  - [x] Rename current ECDSA bootstrap route output auth from
        `thresholdSessionAuthToken` to `walletSessionJwt`.
        `BootstrapEcdsaSessionRouteOutput` and the ECDSA relayer client now
        expose the bearer credential as `walletSessionJwt`; the old key remains
        only when building the current persisted record shape.
  - [x] Rename remaining current warm-session transport call sites to
        `walletSessionJwt`.
        Login ECDSA bootstrap fallback, Ed25519 warm-session reconstruction,
        and passkey ECDSA bootstrap now pass worker-facing auth as
        `walletSessionJwt`; old auth keys remain only in persisted/sealed
        restore shapes and type-level rejection fixtures.
  - [x] Move remaining Email OTP recovery/reconnect direct token reads onto
        Wallet Session boundary helpers.
        Email OTP ECDSA sealed recovery now resolves ECDSA record auth through
        `resolveRouterAbEcdsaWalletSessionAuthFromRecord`, companion Ed25519
        sealed-session updates use `walletSessionJwtFromPersistedEd25519Record`,
        and ECDSA reconnect planning uses
        `walletSessionJwtFromPersistedWarmSessionRecord`.
  - [x] Stop NEAR Ed25519 pre-confirm readiness from treating old
        threshold-session cookie/JWT route auth as spendable signing auth.
        `signNear.ts` now requires Router A/B normal-signing state plus bearer
        JWT through `hasRouterAbEd25519SigningAuth`; the focused
        `thresholdEd25519.nearSigningQueue.guard.unit.test.ts`, Router A/B SDK
        guard, and `packages/sdk-web` type-check passed for this slice.
  - [x] Move remaining active NEAR Ed25519 auth extraction out of `signNear.ts`.
        The Router A/B signing-auth predicate now lives in
        `routerAbWalletSessionCredential.ts`, Email OTP auth-lane extraction
        lives in `routerAbEd25519WalletSessionState.ts`, and the Router A/B SDK guard scans
        `signNear.ts` for old threshold-session field reads.
  - [x] Normalize Ed25519 resolved signing-session auth state to Wallet Session
        auth.
        `interfaces/near.ts` now exposes `walletSessionAuth` on
        `NearResolvedEd25519SigningSessionState` and rejects old
        `sessionKind` / `thresholdSessionAuthToken` construction. The
        persisted-record conversion now lives in the session-level
        `walletSessionAuthBoundary.ts`, while `routerAbEd25519WalletSessionState.ts` and
        `routerAbWalletSessionCredential.ts` consume the normalized Wallet
        Session state for active Router A/B signing. Validation:
        `packages/sdk-web` type-check, focused Router A/B source guards, and
        NEAR session-selection tests passed.
  - [x] Move Ed25519 trusted budget-status auth lookup onto the Wallet Session
        persisted-record boundary.
        `budgetStatusReader.ts` now resolves Ed25519 budget auth through
        `walletSessionAuthBoundary.ts` instead of reading
        `thresholdSessionAuthToken` / `thresholdSessionKind` directly.
        Validation: `packages/sdk-web` type-check plus focused trusted budget
        status and NEAR session-selection tests passed.
  - [x] Move Email OTP ECDSA recovery's companion Ed25519 auth normalization
        onto the Wallet Session persisted-record boundary.
        `ecdsaRecovery.ts` now uses `walletSessionAuthBoundary.ts` when an
        existing Ed25519 companion record is restored, leaving old persisted
        field writes only at the sealed-session restore write boundary.
        Validation: `packages/sdk-web` type-check plus focused sealed-recovery
        and Email OTP ECDSA signing-session auth tests passed.
  - [x] Stop EVM ready-material reconstruction from reading persisted
        threshold-session auth fields in the active signing flow.
        `readySecp256k1Material.ts` now consumes a discriminated
        `RouterAbEcdsaWalletSessionAuthResolution` from the warm-capability
        boundary, passes only `walletSessionJwt` into the ready signer session,
        and the ECDSA active-signing source guard now covers this file plus
        `signingFlowRuntime.ts`. Runtime reconnect tracing now reports
        `hasRouterAbWalletSessionAuth` instead of a threshold-session token flag.
  - [x] Move EVM-family ECDSA lane diagnostics and Email OTP auth-lane
        extraction onto Router A/B Wallet Session auth resolution.
        `ecdsaLanes.ts` now reports `routerAbWalletSessionAuth`, uses
        `walletSessionJwt` from the boundary resolver, and is included in the
        active ECDSA source guard.
  - [x] Normalize EVM-family ECDSA active lane and signer transport auth to
        Wallet Session state.
        `evmFamilyEcdsaIdentity.ts` now models active lane auth and signer
        transport auth as an explicit Wallet Session union, carries bearer
        material as `walletSessionJwt`, and confines
        `thresholdSessionAuthToken` / `thresholdSessionKind` handling to
        persisted record and key-ref conversion boundaries. The type fixture
        now rejects loose active `walletSessionJwt` on ready signer sessions
        and rejects invalid Wallet Session transport branches. Validation:
        `packages/sdk-web` type-check and focused EVM identity, request-boundary,
        ready-signer, and warm capability tests passed.
  - [x] Stop the EVM Email OTP signing-session bridge from reading persisted
        threshold-session auth fields directly.
        `emailOtpSigningSession.ts` now obtains the signing auth lane through
        `emailOtpEcdsaAuthLaneFromRecord`, requires Router A/B Wallet Session
        auth for refresh, and passes a JWT session kind after that boundary
        resolution.
  - [x] Stop EVM-family passkey ECDSA provision planning from inheriting
        persisted threshold-session session kind.
        `provisionPlan.ts` now builds passkey ECDSA provision plans as
        Wallet Session JWT-only, and `ecdsaProvisionPlan.ts` makes the
        passkey provision branch reject cookie auth at the type boundary.
  - [x] Stop the ECDSA Email OTP login signing bridge from inheriting
        persisted threshold-session session kind.
        `ecdsaLogin.ts` now passes the already-resolved route plan with a
        Wallet Session JWT session kind instead of mirroring
        `record.thresholdSessionKind` into the active login bridge.
  - [x] Move active key-export callers onto Wallet Session JWT naming.
        `nearEd25519ExportFlow.ts` now resolves the Ed25519 Router A/B-ready
        state and passes `walletSessionJwt` into the Email OTP and passkey HSS
        export callers. `ecdsaExportFlow.ts` now derives the Email OTP export
        auth lane from the ready Router A/B ECDSA-HSS signer session instead of
        reading `currentRecord.thresholdSessionAuthToken` directly, and the
        explicit ECDSA-HSS export helper is now
        `exportEcdsaHssKeyWithWalletSession`. Follow-up export worker payload
        and helper mappings are now also Wallet Session JWT-only.
  - [x] Rename active Email OTP export worker payload auth to Wallet Session
        JWT.
        `exportEmailOtpEd25519SeedWithAuthorization` and
        `exportThresholdEcdsaHssKeyWithEmailOtpAuthorization` worker messages
        now carry `walletSessionJwt` at the SDK-to-worker boundary. The worker
        maps that JWT into the retained HSS helper parameter internally until
        the lower-level helper contracts are renamed.
  - [x] Move ECDSA export-material route auth through the Wallet Session
        boundary resolver.
        `ecdsaExportMaterial.ts` now uses
        `resolveRouterAbEcdsaWalletSessionAuthFromRecord` for ready export
        material and fresh Email OTP route-auth material instead of reading
        `thresholdSessionAuthToken` or accepting cookie route auth directly.
        Validation: focused ECDSA export-material unit tests and
        `packages/sdk-web` type-check passed.
  - [x] Require Wallet Session route auth for the active Email OTP ECDSA
        export worker request.
        `exportRecovery.ts` now resolves the ECDSA export record through
        `resolveRouterAbEcdsaWalletSessionAuthFromRecord`, sends
        `walletSessionJwt`, and fixes the worker request to JWT route auth
        instead of inheriting persisted cookie route auth. Validation: focused
        Email OTP coordinator plus ECDSA export-material unit tests and
        `packages/sdk-web` type-check passed.
  - [x] Rename Ed25519 HSS helper bearer inputs to Wallet Session JWT.
        `hssLifecycle.ts`, `hssClientBase.ts`, the NEAR Ed25519 export helper,
        Email OTP provisioning, warm-session bootstrap, and the Email OTP
        worker's Ed25519 seed-export helper now pass `walletSessionJwt` into
        the HSS ceremony boundary. Validation: focused Email OTP coordinator
        plus ECDSA export-material unit tests and `packages/sdk-web`
        type-check passed.
  - [x] Make the lower-level ECDSA export worker helper Wallet Session
        JWT-only.
        `exportThresholdEcdsaHssKeyWithEmailOtpAuthorization` now requires
        `walletSessionJwt` at the worker payload parser, and
        `runThresholdEcdsaRoleLocalExportFromReadyRecord` no longer accepts
        `thresholdSessionAuthToken`, `sessionKind`, or cookie fallback auth.
        Validation: focused Email OTP coordinator plus ECDSA export-material
        unit tests and `packages/sdk-web` type-check passed.
- [x] Replace signing capability records with Router A/B signing capability
      records at the boundary where session state is restored.
  - [x] Rename warm capability auth material away from threshold-session auth
        fields.
        Warm capability envelopes now expose `walletSessionJwt` and
        `walletSessionJwtSource`; persisted records and ECDSA seal transport
        still serialize `thresholdSessionAuthToken` only at storage/request
        boundaries. The SDK dist was rebuilt so `/sdk/esm` browser tests see
        the new read model.
  - [x] Route ECDSA login presign-pool prefill through the Router A/B Wallet
        Session auth resolver.
        `ecdsaLoginPrefill.ts` no longer reads `thresholdSessionAuthToken` or
        `thresholdSessionKind` directly and now reports
        `missing_wallet_session_jwt` when no Router A/B Wallet Session bearer
        credential is available.
  - [x] Move warm Email OTP signing auth-lane resolution onto warm Wallet
        Session auth material.
        `capabilityReaderCore.ts` now resolves Email OTP Ed25519/ECDSA
        signing-session auth lanes from `walletSessionJwt` on
        `WarmSession*AuthMaterial` instead of reading persisted
        `thresholdSessionAuthToken` directly.
  - [x] Move Ed25519 client-base prewarm onto warm Wallet Session auth
        material.
        `thresholdWarmSessionBootstrap.ts` now resolves the prewarm bearer JWT
        through `resolveEd25519AuthByThresholdSessionId`, verifies the matched
        warm record identity, and passes a JWT session shape without reading
        persisted threshold-session auth fields in the prewarm branch.
  - [x] Move Ed25519 Email OTP warmup companion auth onto Router A/B Wallet
        Session auth resolution.
        `ed25519Warmup.ts` now obtains companion ECDSA bearer auth through
        `resolveRouterAbEcdsaWalletSessionAuthFromRecord` and passes the
        ECDSA login bridge a JWT session kind instead of reading persisted
        threshold-session fields directly.
  - [x] Stop passkey Ed25519 signing reconnect from inheriting persisted
        threshold-session session kind.
        `ed25519Recovery.ts` now provisions the active passkey reconnect with
        a Wallet Session JWT session kind while sealed-record restore remains
        isolated to the persistence boundary.
  - [x] Normalize accepted sealed-recovery records to Router A/B Wallet Session
        auth.
        `sealedRecovery/recoveryRecord.ts` now parses raw persisted
        `thresholdSessionAuthToken` / `sessionKind` metadata into a
        `walletSessionAuth` union on accepted recovery records. Email OTP,
        passkey, and UI confirm restore adapters convert that union back to the
        current persisted/worker transport fields only at their write
        boundaries. Added `recoveryRecord.typecheck.ts` to reject old
        `thresholdSessionAuthToken` / `sessionKind` object-literal construction
        on normalized recovery records. Validation: `packages/sdk-web`
        type-check and focused sealed-recovery coordinator/adapter tests
        passed.
  - [x] Normalize Email OTP and passkey sealed-recovery restore adapters to
        Wallet Session naming at the restore boundary.
        Email OTP and passkey ECDSA/Ed25519 recovery adapters now derive
        `walletSessionJwt` from normalized sealed-recovery auth once, then
        write `thresholdSessionAuthToken` only when constructing the current
        persisted record shape. Validation: `packages/sdk-web` type-check plus
        focused Email OTP coordinator, sealed-recovery adapter, and signing
        restore coordinator tests passed.
  - [x] Normalize UI confirm restore/seal transport inference around Wallet
        Session JWT.
        `UiConfirmManager.ts` now confines old persisted auth field access to
        local persisted-shape conversion helpers, resolves seal transports as
        `walletSessionJwt`, and writes old restore metadata only when building
        the current sealed-record persistence shape. Validation:
        `packages/sdk-web` type-check plus focused signing restore,
        sealed-recovery adapter, warm-session runtime, lifecycle, and PRF-claim
        tests passed.
  - [x] Move durable ECDSA available-lane JWT binding onto normalized
        sealed-recovery auth.
        `availableSigningLanes.ts` now validates durable ECDSA JWT claims from
        the already-normalized sealed-recovery `walletSessionAuth` union
        instead of reading raw `ecdsaRestore.thresholdSessionAuthToken`.
        Validation: `packages/sdk-web` type-check and focused
        available-signing-lane plus warm-session read-model tests passed.
  - [x] Move sealed Email OTP ECDSA auth-lane recovery onto normalized sealed
        recovery auth.
        `sealedSigningSessionAuth.ts` now derives the signing-session auth lane
        from `normalizeSealedRecoveryRecord(..., { allowExhausted: true })` and
        `walletSessionAuth`, preserving the exhausted-budget reauth behavior
        without raw `sessionKind` / `thresholdSessionAuthToken` reads. ECDSA
        sealed records still avoid top-level `signingRootId` /
        `signingRootVersion`; normalized recovery derives signing-root identity
        from the runtime-policy scope already bound into the stored auth
        material. Public SeamsWeb ECDSA capability args and wallet-iframe
        payloads also no longer accept `runtimePolicyScope`, `signingRootId`,
        or `signingRootVersion`; SeamsWeb derives scope from the app-session
        JWT at the boundary.
        Validation: `packages/sdk-web` type-check plus focused Email OTP ECDSA
        auth-lane, sealed-recovery adapter, session-policy, and public-surface
        guard tests passed.
  - [x] Isolate warm-capability persisted auth reads behind Wallet Session
        boundary helpers.
        `warmCapabilities/readModel.ts`, `statusReader.ts`, and `types.ts` now
        derive `walletSessionJwt` and Wallet Session auth-required state through
        `walletSessionAuthBoundary.ts`, leaving old stored field names only in
        that persisted-record boundary helper and seal-transport serialization.
        Validation: `packages/sdk-web` type-check and focused warm-session
        read-model/status/invariant/reconnect tests passed.
- [x] Delete sealed-session and warm-session branches whose only purpose is to
      reconnect old public threshold signing.
  - [x] Delete the active ECDSA cookie reconnect branch and rename the surviving
        ECDSA reconnect state to Router A/B Wallet Session auth.
        `ecdsaProvisionPlan.ts`, `provisionEcdsaSession.ts`,
        `ecdsaSessionProvision.ts`, `ecdsaBootstrap.ts`, and
        `ecdsaWarmCapabilityBootstrap.ts` now use
        `wallet_session_ecdsa_reconnect` /
        `wallet_session_reconnect_ecdsa_bootstrap`; the old
        `cookie_ecdsa_reconnect` and
        `passkey_cookie_reconnect_ecdsa_bootstrap` branches are deleted from
        active SDK state. Validation: focused ECDSA warm-session/reconnect
        tests, Router A/B source guards, `packages/sdk-web` type-check, and
        `packages/sdk-web` rolldown build passed for this slice.
  - [x] Narrow active ECDSA Wallet Session reconnect bootstrap auth to
        JWT-bearing route auth.
        `WalletSessionReconnectEcdsaBootstrapRequest` now accepts only
        `app_session` or `threshold_session` bearer route auth, the login
        warm-up reconnect branch uses an explicit type guard, and the type
        fixture rejects cookie auth for Wallet Session reconnect. Cookie auth
        remains confined to fresh passkey bootstrap flows that intentionally
        use browser session credentials. Validation: `packages/sdk-web`
        type-check and `seamsWeb.loginThresholdWarm.unit.test.ts` passed.
  - [x] Delete cookie passkey Ed25519 record-backed readiness.
        Warm-session read model, invariants, and status reader no longer treat
        a cookie Ed25519 record with stored `xClientBaseB64u` as ready or active
        signing auth. Those records now surface `auth_missing` until a Wallet
        Session JWT is available. Email OTP session-retained Ed25519
        record-backed status remains at the persistence boundary. Validation:
        focused warm-session read-model/lifecycle/status/invariant tests,
        Router A/B source guards, `packages/sdk-web` type-check, and
        `packages/sdk-web` rolldown build passed.
- [x] Delete old budget-status checks that call threshold-session status routes
      for signing.
      Completed for the trusted signing budget-status reader:
      `budgetStatusReader.ts` now has only threshold-scoped bearer auth with a
      required `walletSessionJwt`, sends `credentials: 'omit'`, drops persisted
      records without a JWT, and has focused coverage that cookie-only ECDSA
      records do not trigger a remote signing budget fetch. Follow-up cleanup
      moved ECDSA budget-status auth through
      `resolveRouterAbEcdsaWalletSessionAuthFromRecord`, leaving old persisted
      auth field reads only in the Ed25519 record-boundary helper. The ECDSA
      resolver now requires an exact chain-target match before reusing warm
      capability auth, so shared threshold session ids cannot borrow a JWT
      from another ECDSA target.
- [x] Keep persisted-shape parsers only for records that still exist in the
      development database or test fixtures, and add an explicit deletion
      condition for each parser.
      Completed for the current cleanup state. Remaining threshold-session
      record kinds and `local_threshold_ecdsa_presignature_pool` are current
      request/persistence boundary values with explicit deletion conditions or
      source-guard confinement; stale active-auth field parsers were renamed or
      deleted in the SDK state, seal transport, worker transport, and shared
      session-token layers.
  - [x] Inventory retained persisted/request-boundary parser surfaces and add
        deletion conditions.
        Remaining old auth field names are retained only at these boundaries:
        `session/persistence/records.ts` for current Ed25519/ECDSA stored
        session records, `session/persistence/sealedSessionStore.ts` and
        `session/sealedRecovery/recoveryRecord.ts` for sealed restore/recovery
        payloads, warm-capability readers that normalize stored
        `thresholdSessionAuthToken` into `walletSessionJwt`, and any remaining
        worker restore adapters that map normalized Wallet Session auth back to
        persisted transport fields. Delete each after a storage schema bump
        writes `walletSessionJwt`-named fields, no current fixture or
        development record contains the old keys, and the matching parser
        rejection tests cover malformed old payloads.
  - [x] Rename internal seal-transport auth source metadata away from
        threshold-session naming.
        `ThresholdSessionSealTransportAuthMaterial` still carries
        `thresholdSessionAuthToken` at the seal transport boundary, but its
        internal source discriminator is now `walletSessionJwtSource`; focused
        warm-session read-model/runtime tests assert the new field name.
  - [x] Rename warm-session worker transport auth payloads to Wallet Session
        JWT.
        Worker-facing Email OTP and passkey confirm seal/rehydrate payloads now
        use `walletSessionJwt`. Persisted records still read and write
        `thresholdSessionAuthToken` only at storage and sealed-record
        boundaries. Added worker transport type fixtures that reject the old
        transport token field, and the worker operation schema/parser for
        Email OTP seal/rehydrate now accepts `transport.walletSessionJwt`.
        Validation: focused Email OTP coordinator, warm-session runtime,
        warm-session lifecycle, warm-session PRF-claim, and ECDSA
        export-material unit tests plus `packages/sdk-web` type-check passed.
  - [x] Bump persisted and sealed signing-session auth fields to
        `walletSessionJwt`.
        Current Ed25519/ECDSA stored records, sealed restore metadata,
        warm-capability read models, UI-confirm restore helpers, shared
        `signingSessionSeal` types, and matching typed fixtures now use
        `walletSessionJwt`. The old stored field parser was deleted from the
        SDK persistence/sealed-record path; remaining
        `thresholdSessionAuthToken` references are deliberate negative
        type/source-guard fixtures.
  - [x] Remove the old auth field from current SDK state types and redaction
        lists.
        ECDSA key refs and NEAR resolved signing-session state no longer carry
        a `thresholdSessionAuthToken?: never` compatibility field; excess
        property fixtures still reject that key. Email OTP escrow redaction
        deny-lists now reject `walletSessionJwt`.
  - [x] Rename shared SDK/server session-token helpers to Wallet Session JWT
        terminology.
        `sessionTokens.ts` now exposes `WalletSessionJwtKind`,
        `WalletSessionJwtAuth`, `AppOrWalletSessionAuth`,
        `isWalletSessionJwt`, `requireWalletSessionJwt`,
        `walletSessionJwtAuth`, and `appOrWalletSessionJwtAuth`. The server
        boundary signer is now `signWalletSessionJwt`. The JWT payload `kind`
        strings and route-auth discriminant remain stable protocol values.
        Validation: `packages/sdk-web` type-check, `packages/sdk-server-ts`
        type-check, and focused session-token/claim unit tests passed.
  - [x] Rename remaining test-harness auth fixtures to `walletSessionJwt`.
        E2E debug snapshots, Ed25519 test bootstrap helpers, Email OTP tempo
        helpers, and relayer integration fixtures no longer construct or assert
        `thresholdSessionAuthToken`. Remaining matches are negative type
        fixtures and source-guard token lists. Validation: focused relayer
        Email OTP bootstrap integration tests passed.
- [x] Remove tests that protect old persisted signing auth behavior.
  - [x] Update warm-session lifecycle/read-model/invariant tests so capability
        auth assertions use the Router A/B Wallet Session auth shape while seal
        transport tests keep the boundary serialization checks.
  - [x] Rewrite cookie passkey Ed25519 persisted-auth tests to assert
        `auth_missing` instead of preserving old record-backed active status.
  - [x] Rewrite Ed25519 threshold-session state assertions to prove the Router
        A/B-ready state shape.
        `thresholdEd25519.walletSessionState.unit.test.ts` now keeps old
        auth field names only in persisted-record fixture setup and asserts
        `credential.walletSessionJwt` on the Router A/B-ready state. Validation:
        the focused Ed25519 threshold-session state unit file passes.
  - [x] Rewrite stale warm-session capability tests that expected cookie-backed
        Ed25519 readiness.
        `warmSessionStore.capabilityResolution.unit.test.ts` now asserts
        `auth_missing` for cookie-only Ed25519 records with warm PRF state,
        matching the Router A/B Wallet Session auth requirement. Validation:
        focused available-signing-lane and warm-session read-model tests passed.

## Phase 7: Rewrite Or Delete Tests And Fixtures

- [x] Delete tests whose only assertion is that old public threshold signing
      routes work.
      Completed for the old Ed25519 authorize/presign/finalize route suites,
      old ECDSA authorize/sign route assertions, obsolete ECDSA signing-session
      durable-store tests, and stale package/config references.
- [x] Delete the obsolete Ed25519 immediate/worker fallback suite after active
      NEAR signing stopped falling back to non-Router Ed25519 signing.
      Completed by removing `thresholdEd25519.immediateSignFallback.unit.test.ts`.
- [x] Delete obsolete Ed25519 presign route-client suites after the SDK
      `/threshold-ed25519/*` presign/finalize client was removed.
      Completed by removing `thresholdEd25519.presignFinalizeClient.unit.test.ts`
      and `thresholdEd25519.relayerClient.unit.test.ts`.
- [x] Delete obsolete active `Secp256k1Engine` tests that only protected old
      threshold-session presign-refill scheduling around EVM signing.
      Retained `thresholdEcdsa.presignPoolRefill.unit.test.ts` coverage is now
      limited to the old internal presign-pool helpers that remain deletion
      blockers for Router A/B pool-miss/refill replacement.
- [x] Delete SDK tests that only protected old ECDSA authorize behavior.
      Completed by removing `thresholdEcdsa.authorizePolicyHint.unit.test.ts`
      and pruning the authorize timeout case from
      `thresholdEcdsa.requestTimeout.unit.test.ts`.
- [x] Rewrite user-facing signing tests to assert the Router A/B path:
      Wallet Session auth, Router admission, SigningWorker private signing,
      Deriver A/B non-invocation on normal signing, and response binding.
      Completed with existing ECDSA-HSS normal-signing boundary tests plus the
      Ed25519 user-facing source guard. ECDSA-HSS tests assert bearer Wallet
      Session auth, Router prepare/finalize route use, and strict
      request-digest binding. Ed25519 NEAR transaction, NEP-413, and delegate
      flows now fail the guard if they stop building Router A/B-ready state,
      stop passing `credential.walletSessionJwt`, call old public Ed25519
      routes, route normal signing through Deriver code, or drop the
      prepare/finalize response-binding checks. Validation: focused ECDSA-HSS
      boundary tests and the Ed25519 source-guard file pass.
- [x] Replace old threshold-session route mocks in e2e and unit tests with
      Router A/B Router and SigningWorker mocks.
      Completed for deleted public signing routes. A strict scan for old
      Ed25519/ECDSA authorize, presign, and sign route mocks now finds only the
      source-guard deny-list. The remaining threshold route mock is retained
      ECDSA HSS bootstrap lifecycle coverage. Stale server comments that still
      described `/threshold-ed25519/sign/*` coordinator behavior were updated
      to the current registration/session and Router A/B bridge surface.
- [x] Delete fixture rows containing old signing route auth unless they test an
      explicitly retained persistence boundary.
      Completed for deleted public signing-route fixtures. Remaining
      `threshold_session` bearer fixtures are retained request-boundary coverage
      for Email OTP signing-session routes, warm-session restore, session-token
      parsers, or persisted-record normalization. The strict deleted-route scan
      has no old authorize/presign/sign fixture rows outside the source-guard
      deny-list.
- [x] Rename test files after old route names are deleted.
      Completed by deleting the route-client suites named for old public
      authorize, presign, finalize, finalize-and-dispatch, relayer-client, and
      immediate-fallback paths. The remaining `thresholdEd25519` and
      `thresholdEcdsa` filenames cover current crypto/lifecycle domains or
      Router A/B presign-pool internals, not deleted public signing routes.
- [x] Keep negative tests for missing or stale old records only when a current
      boundary must reject those records.
      Completed for this cleanup slice. Remaining stale/legacy negative tests
      are persistence, request-parser, source-guard, or schema-boundary tests:
      sealed-session store rejection/pruning, Router A/B legacy-field
      rejection, session-token parser rejection, and explicit source guards.
      Deleted public signing-route behavior has no retained negative route
      tests.

## Phase 8: Source Guards And Static Rejection

This is the single cleanup source-guard slice for old public signing routes,
old SDK signing helpers, active Wallet Session auth naming, and current Router
A/B route-version allowlists.

- [x] Add a guard that fails on old public signing route literals outside this
      doc and a small deny-list test.
      Completed in `routerAbNormalSigningSdk.guard.unit.test.ts` for old public
      ECDSA and Ed25519 signing route literals plus old SDK helper names.
- [x] Add a guard that fails on `thresholdSessionAuthToken` in active signing
      flows.
      Completed in `routerAbNormalSigningSdk.guard.unit.test.ts`; active ECDSA
      and Ed25519 signing modules now fail the guard if legacy
      threshold-session auth fields reappear.
- [x] Add a guard that fails on `thresholdSessionAuthToken`,
      `signerSession.transport.auth`, cookie auth, and `sessionKind` in active
      ECDSA signing flows.
      Completed in `routerAbNormalSigningSdk.guard.unit.test.ts` with validation:
      `rtk pnpm -C tests exec playwright test -c playwright.config.ts
      ./unit/routerAbNormalSigningSdk.guard.unit.test.ts --reporter=line`.
- [x] Add a guard that fails on `ThresholdEd25519PresignPoolRouteAuth` in active
      SDK signing flows.
      Completed by deleting the type from `signer-worker.ts`, tightening
      `routerAbNormalSigningSdk.guard.unit.test.ts`, and keeping the remaining
      Ed25519 presign-pool type fixture Router A/B-only.
- [x] Add a guard that fails on `authorizeEcdsaWithSession` and
      `signThresholdEcdsaDigestWithPool` in active SDK signing flows.
      Completed by removing `signEvmFamily` from the allowed-files list in
      `routerAbNormalSigningSdk.guard.unit.test.ts`; later tightened so these
      names are not allowed in SDK source at all.
- [x] Add a guard that fails on old public ECDSA helper exports at the SDK
      public boundary.
      Completed by guarding `ecdsaPresignInit`, `ecdsaPresignStep`,
      `ecdsaSignInit`, and `ecdsaSignFinalize` along with
      `authorizeEcdsaWithSession`.
- [x] Tighten the old ECDSA sign-route guard after SDK helper deletion.
      Completed by removing SDK source files from the allowlist for
      `/threshold-ecdsa/authorize`, `/threshold-ecdsa/sign/init`,
      `/threshold-ecdsa/sign/finalize`, `authorizeEcdsaWithSession`,
      `ecdsaSignInit`, `ecdsaSignFinalize`, and
      `signThresholdEcdsaDigestWithPool`.
- [x] Add a guard that fails when Express or Cloudflare route definitions expose
      old public threshold signing endpoints.
      Completed by scanning `packages/sdk-server-ts/src/router` with zero
      tolerance for the deleted public signing route literals.
- [x] Add a guard that allows current Router A/B private `v1` route constants
      and durable wire-schema suffixes.
      Completed with the Router A/B v1 route-literal allowlist in
      `routerAbNormalSigningSdk.guard.unit.test.ts`; current private/internal
      `/router-ab/v1` and public ECDSA-HSS `/v1/hss/ecdsa/*` contracts are now
      explicit, while old normal-signing `/v1/hss/sign*` remains denied by the
      SDK helper-surface guard.

## Phase 9: Validation Gates

Run focused checks after each deletion slice:

- [x] `rtk pnpm -C packages/sdk-web type-check`
      Passed after the Router A/B ECDSA-HSS pool-fill route switch.
- [x] `rtk pnpm -C packages/sdk-server-ts type-check`
      Passed after the Router A/B ECDSA-HSS pool-fill route switch.
- [x] `rtk cargo test --manifest-path crates/router-ab-core/Cargo.toml --test normal_signing_v2 --test ecdsa_hss_protocol --test source_guards`
      Passed: 91 tests across 3 suites.
- [x] `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings --test source_guards`
      Passed: 311 tests across 2 suites.
- [x] Focused Ed25519 Router A/B SDK tests for NEAR transaction, NEP-413,
      delegate action, pool hit, and pool miss.
      Passed with Router A/B normal-signing vectors for NEAR transaction,
      NEP-413, and delegate action builders, SigningWorker response-binding
      validation, Ed25519 presign-pool hit/miss lifecycle tests, and the
      user-facing Ed25519 source guard for NEAR transaction, NEP-413, and
      delegate flow selection.
- [x] Focused ECDSA-HSS Router A/B SDK tests for EVM digest signing, pool hit,
      and pool miss.
      Current focused evidence: Router A/B source guard passes; old internal
      `thresholdEcdsa.presignPoolRefill.unit.test.ts` still passes for retained
      deletion-blocker helpers. Router A/B cold-pool coverage passes and now
      asserts the Router A/B pool-fill route names for init/step.
      Latest validation also covers strict ECDSA-HSS response `request_digest`
      binding with `routerAbEcdsaHssNormalSigning.unit.test.ts`, and
      pool-hit/pool-miss behavior with
      `thresholdEcdsa.presignPoolRefill.unit.test.ts`.
- [x] `rtk pnpm router:smoke`
      Passed on the local four-worker topology. Evidence: setup, Deriver A/B
      peer exchange, SigningWorker activation, and Ed25519 normal signing all
      completed; Deriver A/B normal-signing request counts were zero.
- [x] `rtk pnpm router:smoke:bundled`
      Passed on the bundled one-process topology. Evidence: setup, Deriver A/B
      peer exchange, SigningWorker activation, and Ed25519 normal signing all
      completed; Deriver A/B normal-signing request counts were zero.
- [x] `rtk pnpm router:deploy:check`
      Passed: Router A/B release blockers clear.
- [x] `rtk pnpm router:deploy:dry-run -- --env staging`
      Passed for Router, Deriver A, Deriver B, and SigningWorker dry-run
      packages. Wrote an ignored startup report under
      `crates/router-ab-cloudflare/reports/startup-latencies/`.

Run full local verification before Cloudflare deployment:

- [x] Package-wide SDK type-check.
      Passed after the Express ECDSA presign route-label fix and ECDSA-HSS
      response request-digest binding update.
- [x] Focused Rust Router A/B test matrix.
      Passed with the focused `router-ab-core` normal signing/ECDSA-HSS/source
      guard suite and the focused `router-ab-cloudflare` bindings/source-guard
      suite.
- [x] Focused TypeScript Router A/B SDK test matrix.
      Passed with SDK/server package type-checks, Router A/B source guards,
      ECDSA-HSS normal-signing boundary tests, Ed25519 normal-signing vectors,
      Ed25519 response-binding validation, Ed25519 presign-pool lifecycle tests,
      and focused sealed/warm-session tests from the cleanup slices.
- [x] Local split-worker smoke.
      Passed via `rtk pnpm router:smoke` with Router, Deriver A, Deriver B, and
      SigningWorker running as separate local processes.
- [x] Local bundled smoke.
      Passed via `rtk pnpm router:smoke:bundled`.
- [x] ECDSA-HSS normal-signing benchmark.
      Completed with the local Router A/B release-evidence harness:
      `rtk pnpm router:evidence -- --out
      crates/router-ab-dev/reports/local-release-evidence/local-release-evidence-2026-06-17-command.json`.
      The harness exercises the current public and private ECDSA-HSS route
      shape, strict prepare/finalize request parsers, prepare response
      `request_digest` binding, finalize-to-prepare digest binding, and
      response binding for 250 iterations. This is protocol-shape evidence, not
      live `pnpm router` HTTP dispatch evidence for ECDSA-HSS. Evidence report:
      `crates/router-ab-dev/reports/local-release-evidence/local-release-evidence-2026-06-17-command.json`
      recorded average local protocol prepare/finalize binding time at 934 us.
      This is local protocol timing evidence; deployed runtime/browser evidence
      remains Phase 16.
- [x] Ed25519 pool-hit and pool-miss timing evidence.
      Completed with the same local Router A/B release-evidence harness:
      `rtk pnpm router:evidence -- --out
      crates/router-ab-dev/reports/local-release-evidence/local-release-evidence-2026-06-17-command.json`.
      The harness exercises `/v2/router-ab/ed25519/sign/presign-pool/prepare`, pool-hit
      `/v2/router-ab/ed25519/sign` lowering to the v2 finalize shape, and pool-miss
      `/v2/router-ab/ed25519/sign/prepare` plus `/v2/router-ab/ed25519/sign` protocol parsing for 250
      iterations. Evidence report averages: refill 87 us, pool-hit finalize
      741 us, and pool-miss prepare/finalize 349 us. The report also records
      one accepted pool entry, one rejected entry, and
      `pool_hit_lowers_to_finalize: true`. Deployed runtime/browser evidence
      remains Phase 16.
- [x] ECDSA-HSS browser presignature pool keys are active-state-bound.
      Completed after auditor review: the browser client pool key now includes
      the parsed Router A/B ECDSA-HSS normal-signing scope, including stable key
      context, public identity, SigningWorker identity, and activation epoch,
      plus the normalized participants. Pool depth and lane clearing require the
      active scope. Focused tests cover the same `ecdsaThresholdKeyId` with a
      different `activation_epoch` and prove stale presignatures stay isolated.
- [x] Retire stale pre-Router-A/B Ed25519 refactor docs.
      Completed by replacing `refactor-55b-signing-latency.md` and
      `refactor-52-ed25519-presign-pool-plan.md` with retired-plan tombstones
      that point to the Router A/B cleanup and Wallet Session V2 plans.

## Phase 10: Local Cleanup Review Handoff

- [x] Separate local cleanup completion from deployed-runtime release evidence.
      The cleanup implementation, local evidence harness, local smoke, type
      checks, focused tests, source guards, deploy check, and staging dry-run
      are complete enough for local cleanup review. The deployed Cloudflare
      browser/runtime checklist has moved to Phase 16 so production evidence is
      tracked as a post-deployment release gate.

## Phase 11: Final Naming Cleanup

Start this only after the old public threshold signing architecture is deleted.
This phase is the canonical home for the ECDSA plan's former "Phase 9: Final
Legacy And Naming Cleanup" checklist. Keep ECDSA-specific cleanup status here so
Router A/B legacy deletion, suffix normalization, source guards, and validation
are audited from one plan.

- [x] Rename internal types that still use threshold-session naming for active
      Router A/B signing state.
      June 17, 2026 audit: active Router A/B signing modules no longer read
      `thresholdSessionAuthToken`, `thresholdSessionAuth`, or
      `ThresholdEd25519PresignPoolRouteAuth`. Remaining `thresholdSessionId`
      names are the current opaque client-visible session handle or
      persistence/budget/readiness boundary fields, so they are not part of
      this old-auth naming cleanup.
  - [x] Rename the active NEAR Ed25519 Router A/B Wallet Session state helper.
        `thresholdSessionAuth.ts` is now
        `routerAbEd25519WalletSessionState.ts`, and its exported state
        resolver/require helpers now use `ResolvedRouterAbEd25519WalletSessionState`
        naming. The focused browser unit test was renamed to
        `routerAbEd25519.walletSessionState.unit.test.ts`.
  - [x] Rename ECDSA active route-auth plumbing away from
        `thresholdSessionAuth`.
        ECDSA activation/bootstrap request branches now carry
        `walletSessionRouteAuth`, and the lifecycle guard enforces the field is
        branch-specific. `ecdsaReadiness.ts` now compares ECDSA session
        identities through `buildEcdsaSessionIdentity` instead of paired local
        raw string parsing.
  - [x] Rename active ECDSA-HSS pool-fill SDK/server diagnostics away from old
        threshold-session and public presign-route wording.
        `commonRouterUtils.ts` now returns Wallet Session wording for the active
        ECDSA session-token boundary, `routerAbEcdsaHssPoolFillHandlers.ts` reports Router
        A/B ECDSA-HSS pool-fill errors, and the SDK pool-fill helper types and
        fallback messages use Router A/B ECDSA-HSS pool-fill terminology.
        Focused validation passed with `rtk pnpm -C packages/sdk-server-ts run
        type-check`, `rtk pnpm -C packages/sdk-web run type-check`, `rtk pnpm
        -C tests exec playwright test -c playwright.unit.config.ts
        unit/thresholdEcdsa.presignDistributed.unit.test.ts
        unit/routerAbEcdsaHssPresignBridge.unit.test.ts --reporter=line`,
        `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts
        unit/thresholdEcdsa.presignPoolRefill.unit.test.ts
        unit/routerAbEcdsaHssNormalSigning.unit.test.ts --reporter=line`, and
        `rtk pnpm -C tests exec playwright test -c playwright.relayer.config.ts
        relayer/threshold-ecdsa.signature-harness.test.ts --reporter=line`.
  - [x] Rename live ECDSA-HSS pool-fill request/scheme types away from old
        threshold presign-init/step terminology.
        Server route boundary types are now
        `RouterAbEcdsaHssPoolFillInitRequest`,
        `RouterAbEcdsaHssPoolFillInitResponse`,
        `RouterAbEcdsaHssPoolFillStepRequest`, and
        `RouterAbEcdsaHssPoolFillStepResponse`; the secp256k1 scheme driver now
        exposes `poolFill` instead of a generic `presign` branch, and the SDK
        pool-fill key selector uses Router A/B ECDSA-HSS naming. Validation:
        `rtk pnpm -C packages/sdk-server-ts run type-check`, `rtk pnpm -C
        packages/sdk-web run type-check`, `rtk pnpm -C tests exec playwright
        test -c playwright.unit.config.ts unit/thresholdEcdsa.presignDistributed.unit.test.ts
        unit/thresholdEcdsa.presignPoolRefill.unit.test.ts --reporter=line`, and
        `rtk git diff --check`.
  - [x] Rename retained ECDSA-HSS pool-fill session and server presignature
        pool store types away from threshold/relayer terminology.
        The live distributed pool-fill state is now typed as
        `RouterAbEcdsaHssPoolFillSession*`, the presignature share records and
        stores are `RouterAbEcdsaHssServerPresignatureShareRecord` and
        `RouterAbEcdsaHssPresignaturePool`, and service dependencies use
        `poolFillSessionStore` instead of old presign-session wording. Durable
        storage keys/tables remain boundary labels until a storage schema bump.
        Validation: `rtk pnpm -C packages/sdk-server-ts run type-check`, `rtk
        pnpm -C tests exec playwright test -c playwright.unit.config.ts
        unit/thresholdEcdsa.presignDistributed.unit.test.ts
        unit/thresholdEcdsa.postgresRecords.unit.test.ts --reporter=line`, `rtk
        pnpm -C tests exec playwright test -c playwright.relayer.config.ts
        relayer/threshold-ecdsa.signature-harness.test.ts --reporter=line`, and
        `rtk git diff --check`.
  - [x] Rename internal Durable Object ECDSA-HSS pool-fill operation names away
        from old presign-route terminology.
        The private Durable Object protocol now uses
        `routerAbEcdsaHssPresignaturePut`,
        `routerAbEcdsaHssPresignatureReserve`,
        `routerAbEcdsaHssPresignatureReserveById`,
        `routerAbEcdsaHssPoolFillSessionCreate`, and
        `routerAbEcdsaHssPoolFillSessionAdvanceCas`; local DO parser names and
        malformed-record messages use Router A/B ECDSA-HSS pool-fill wording.
        The public route `presignSessionId` field remains the active wire field.
        Validation: `rtk pnpm -C packages/sdk-server-ts run type-check`, `rtk
        pnpm -C tests exec playwright test -c playwright.unit.config.ts
        unit/thresholdEcdsa.presignDistributed.unit.test.ts
        unit/thresholdPostgresMalformedCleanup.unit.test.ts --reporter=line`,
        `rtk pnpm -C tests exec playwright test -c playwright.relayer.config.ts
        relayer/threshold-ecdsa.durable-stores.test.ts
        relayer/threshold-ecdsa.signature-harness.test.ts --reporter=line`, and
        `rtk git diff --check`.
  - [x] Rename live ECDSA-HSS handler-local aliases that still described
        Router A/B pool-fill as a threshold presign-session route.
        `RouterAbEcdsaHssSigningWorkerPoolFillDestination`,
        `parseRouterAbEcdsaHssPoolFillRequest`,
        `RouterAbEcdsaHssPresignatureMaterial`, and
        `RouterAbEcdsaHssPoolFillTarget` now describe the active handler state.
        WASM presign-session terms and the public `presignSessionId` field
        remain protocol terms. Validation: `rtk pnpm -C packages/sdk-server-ts
        run type-check` and `rtk pnpm -C tests exec playwright test -c
        playwright.unit.config.ts unit/thresholdEcdsa.presignDistributed.unit.test.ts
        --reporter=line`.
  - [x] Rename the SDK-facing ECDSA presign-pool config/API seam to Router A/B
        ECDSA-HSS presignature-pool terminology.
        Public config input now uses
        `routerAbEcdsaHssPresignaturePool`; the public auth method and iframe
        PM route are `prefillRouterAbEcdsaHssPresignaturePool` and
        `PM_PREFILL_ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL`; policy types,
        defaults, and resolver names now use
        `RouterAbEcdsaHssPresignaturePool*` naming. Validation: `rtk pnpm -C
        packages/sdk-web run type-check`, `rtk pnpm -C packages/sdk-web run
        build`, `rtk pnpm -C tests exec playwright test -c
        playwright.unit.config.ts unit/thresholdEcdsa.presignPoolPolicy.unit.test.ts
        unit/walletIframe.signerModeConfigPropagation.unit.test.ts
        unit/signingEngineEcdsaIdentity.publicSurfaces.guard.unit.test.ts
        unit/refactor54Simplify.guard.unit.test.ts --reporter=line`, and `rtk
        git diff --check`.
  - [x] Move the normalized SDK ECDSA-HSS presignature-pool config out of
        `signing.thresholdEcdsa`.
        Resolved configs now expose
        `signing.routerAbEcdsaHss.presignaturePool` for Router A/B ECDSA-HSS
        pool policy, while `signing.thresholdEcdsa` retains only ECDSA
        provisioning defaults. Iframe routing, warm-capability dependencies,
        default configs, config-builder validation, and focused tests now read
        the Router A/B ECDSA-HSS branch. Validation: `rtk pnpm -C
        packages/sdk-web run type-check`, `rtk pnpm -C packages/sdk-web run
        build`, `rtk pnpm -C tests exec playwright test -c
        playwright.unit.config.ts unit/thresholdEcdsa.presignPoolPolicy.unit.test.ts
        unit/walletIframe.signerModeConfigPropagation.unit.test.ts
        unit/signingEngineEcdsaIdentity.publicSurfaces.guard.unit.test.ts
        unit/refactor54Simplify.guard.unit.test.ts --reporter=line`, and `rtk
        git diff --check`.
  - [x] Move the SDK Router A/B ECDSA-HSS presignature-pool modules out of
        `threshold/ecdsa`.
        `presignPool.ts`, `sign.ts`, and `httpRequest.ts` now live as
        `routerAb/ecdsaHss/presignaturePool.ts`,
        `routerAb/ecdsaHss/poolFillRoutes.ts`, and
        `routerAb/ecdsaHss/httpRequest.ts`. Active EVM signing, warm-session
        prefill, and focused tests import the Router A/B module directly.
        Validation: `rtk pnpm -C packages/sdk-web run type-check` and `rtk
        pnpm -C tests exec playwright test -c playwright.unit.config.ts
        unit/thresholdEcdsa.presignPoolPolicy.unit.test.ts
        unit/thresholdEcdsa.presignPoolRefill.unit.test.ts
        unit/routerAbNormalSigningSdk.guard.unit.test.ts
        unit/signingEngineArchitecture.state.guard.unit.test.ts --reporter=line`.
  - [x] Rename the SDK Router A/B ECDSA-HSS client presignature-pool exports
        away from threshold-route naming.
        The active client pool helpers now use
        `RouterAbEcdsaHssClientPresignature*` types and
        `clear/get/schedule/refillRouterAbEcdsaHssClientPresignature*`
        functions. The cross-runtime refill Web Locks key also moved from
        `threshold-ecdsa:presign-refill` to
        `router-ab-ecdsa-hss:presignature-refill`. Validation: `rtk pnpm -C
        packages/sdk-web run type-check` and `rtk pnpm -C tests exec playwright
        test -c playwright.unit.config.ts
        unit/thresholdEcdsa.presignPoolPolicy.unit.test.ts
        unit/thresholdEcdsa.presignPoolRefill.unit.test.ts
        unit/routerAbNormalSigningSdk.guard.unit.test.ts
        unit/signingEngineArchitecture.state.guard.unit.test.ts --reporter=line`.
  - [x] Rename the Router A/B ECDSA-HSS pool-fill route utility helpers away
        from old threshold ECDSA route wording.
        The new module now uses `RouterAbEcdsaHssPoolFillProgress`,
        `fetchRouterAbEcdsaHssJson`, Router A/B ECDSA-HSS timeout constants,
        and `[router-ab-ecdsa-hss]` diagnostics. Current protocol field names
        such as `presignSessionId` and `ecdsaThresholdKeyId` remain because the
        live request and identity shapes still carry them. Validation: `rtk
        pnpm -C packages/sdk-web run type-check` and `rtk pnpm -C tests exec
        playwright test -c playwright.unit.config.ts
        unit/thresholdEcdsa.presignPoolPolicy.unit.test.ts
        unit/thresholdEcdsa.presignPoolRefill.unit.test.ts
        unit/routerAbNormalSigningSdk.guard.unit.test.ts
        unit/signingEngineArchitecture.state.guard.unit.test.ts --reporter=line`.
  - [x] Rename the internal login prefill scheduler for the Router A/B ECDSA-HSS
        presignature pool.
        The public auth method was already
        `prefillRouterAbEcdsaHssPresignaturePool`; the signing-surface and
        warm-capability internals now use
        `scheduleRouterAbEcdsaHssLoginPresignaturePrefill` and
        `RouterAbEcdsaHssLoginPresignaturePrefillResult`. Validation: `rtk
        pnpm -C packages/sdk-web run type-check` and `rtk pnpm -C tests exec
        playwright test -c playwright.unit.config.ts
        unit/seamsWeb.loginThresholdWarm.unit.test.ts
        unit/thresholdEcdsa.presignPoolPolicy.unit.test.ts
        unit/thresholdEcdsa.presignPoolRefill.unit.test.ts --reporter=line`.
  - [x] Rename Wallet Session activation dependency plumbing away from
        threshold-session naming.
        `ThresholdSessionActivationDeps`,
        `createThresholdSessionActivationDeps`, and
        `thresholdSessionActivationDeps` are now
        `WalletSessionActivationDeps`,
        `createWalletSessionActivationDeps`, and
        `walletSessionActivationDeps`. Focused validation passed with `rtk pnpm
        -C packages/sdk-web run type-check` and `rtk pnpm -C tests exec
        playwright test -c playwright.unit.config.ts
        ./unit/addWalletSigner.orchestration.unit.test.ts
        ./unit/seamsWeb.loginThresholdWarm.unit.test.ts
        ./unit/warmSessionEcdsaProvisioning.unit.test.ts
        ./unit/warmSessionStore.reconnect.unit.test.ts --reporter=line`.
  - [x] Rename the Email OTP active coordinator wrapper to Wallet Session
        terminology.
        `EmailOtpThresholdSessionCoordinator`,
        `EmailOtpThresholdSessionCoordinatorDeps`, and
        `EmailOtpThresholdSessionRuntime` are now
        `EmailOtpWalletSessionCoordinator`,
        `EmailOtpWalletSessionCoordinatorDeps`, and
        `EmailOtpWalletSessionRuntime`. Focused validation passed with `rtk pnpm
        -C packages/sdk-web run type-check` and `rtk pnpm -C tests exec
        playwright test -c playwright.unit.config.ts
        ./unit/emailOtpWalletSessionCoordinator.unit.test.ts
        ./unit/emailOtpOperationSplit.guard.unit.test.ts
        ./unit/signingEngineArchitecture.flows.guard.unit.test.ts
        ./unit/thresholdEd25519.nearSigningQueue.guard.unit.test.ts
        --reporter=line`.
  - [x] Rename active NEAR Ed25519 Router A/B Wallet Session state locals away
        from `thresholdSessionState`.
        The transaction, NEP-413, delegate, Router A/B presign/finalize, NEAR
        Ed25519 export, and passkey sealed-refresh helpers now use
        `walletSessionState` /
        `currentWalletSessionState` /
        `refreshedWalletSessionState` for
        `ResolvedRouterAbEd25519WalletSessionState`. Focused validation passed
        with `rtk pnpm -C packages/sdk-web run type-check` and `rtk pnpm -C
        tests exec playwright test -c playwright.unit.config.ts
        ./unit/routerAbNormalSigningSdk.guard.unit.test.ts
        ./unit/routerAbEd25519.walletSessionState.unit.test.ts
        ./unit/thresholdEd25519.presignPool.unit.test.ts
        ./unit/nearSigning.sessionSelection.unit.test.ts --reporter=line`;
        export-surface coverage passed with `rtk pnpm -C tests exec
        playwright test -c playwright.unit.config.ts
        ./unit/exportKeysUseCase.unit.test.ts
        ./unit/exportLaneSelection.unit.test.ts
        ./unit/crossPlatformBoundaries.guard.unit.test.ts --reporter=line`.
  - [x] Rename sealed recovery and UI-confirm Wallet Session JWT boundary locals
        away from threshold-session auth-token naming.
        `rawThresholdSessionAuthToken`,
        `companionThresholdSessionAuthToken`,
        `PersistedThresholdSessionAuthRecord`, and
        `walletSessionJwtFromPersistedThresholdRecord` are now named around
        Wallet Session JWT/session-auth records. Durable stored fields such as
        `thresholdSessionKind` remain persistence schema names. Validation:
        `rtk pnpm -C packages/sdk-web run type-check` and `rtk pnpm -C tests
        exec playwright test -c playwright.unit.config.ts
        ./unit/sealedRecovery.methodAdapters.unit.test.ts
        ./unit/signingSessionRestoreCoordinator.unit.test.ts
        ./unit/sealedSessionStore.unit.test.ts
        ./unit/touchConfirm.workerRouter.integration.test.ts --reporter=line`.
  - [x] Rename active signing-session auth-unavailable helpers away from
        threshold-session auth-token wording.
        `THRESHOLD_SESSION_AUTH_UNAVAILABLE_ERROR` and
        `isThresholdSessionAuthUnavailableError` are now
        `SIGNING_SESSION_AUTH_UNAVAILABLE_ERROR` and
        `isSigningSessionAuthUnavailableError`. The ECDSA ready-material error
        now says Wallet Session auth is unavailable, and iframe error mapping
        recognizes the new canonical message. Validation: `rtk pnpm -C
        packages/sdk-web run type-check` and `rtk pnpm -C tests exec
        playwright test -c playwright.unit.config.ts
        ./unit/thresholdSigningSessionReadiness.unit.test.ts
        ./unit/warmSessionStore.errorNormalization.unit.test.ts
        ./unit/walletIframeHost.signTempoCancel.unit.test.ts
        ./unit/signingFlow.readySigner.unit.test.ts --reporter=line`.
  - [x] Rename warm-session test fixture auth inputs from `sessionAuthToken` to
        `walletSessionJwt`.
        `createThresholdEcdsaBootstrapFixture` and the warm-session unit tests
        now use Wallet Session JWT fixture names; negative type fixtures still
        mention `thresholdSessionAuthToken` only to reject it. Validation: `rtk
        pnpm -C packages/sdk-web run type-check` and `rtk pnpm -C tests exec
        playwright test -c playwright.unit.config.ts
        ./unit/warmSessionStore.prfClaim.unit.test.ts
        ./unit/warmSessionStore.reconnect.unit.test.ts
        ./unit/warmSessionStore.transitions.unit.test.ts
        ./unit/warmSessionStore.invariants.unit.test.ts
        ./unit/warmSessionStore.concurrency.unit.test.ts
        ./unit/warmSessionStore.errorNormalization.unit.test.ts
        ./unit/warmSessionStore.capabilityResolution.unit.test.ts
        ./unit/warmSessionStore.bootstrapResolution.unit.test.ts
        ./unit/warmSessionRuntime.unit.test.ts
        ./unit/warmSessionEcdsaProvisioning.unit.test.ts
        ./unit/evmSigning.thresholdReconnectEvents.unit.test.ts
        ./unit/evmFamily.requestBoundary.unit.test.ts
        ./unit/evmFamilyStepUpProvisionPlan.unit.test.ts
        ./unit/emailOtpWalletSessionCoordinator.unit.test.ts --reporter=line`.
  - [x] Rename live threshold warm-session bootstrap auth locals from
        `sessionAuthToken` to `walletSessionJwt`.
        Ed25519 registration and passkey warm-session bootstrap still persist
        the current session schema, but the SDK-side local names now describe
        Wallet Session JWT material. Validation: `rtk pnpm -C packages/sdk-web
        run type-check` and `rtk pnpm -C tests exec playwright test -c
        playwright.unit.config.ts
        ./unit/thresholdEd25519.registrationWarmSession.unit.test.ts
        ./unit/seamsWeb.loginThresholdWarm.unit.test.ts
        ./unit/warmSessionStore.bootstrapResolution.unit.test.ts
        --reporter=line`.
  - [x] Rename the active NEAR signing-session auth planner away from
        `thresholdAuthMode` naming.
        `thresholdAuthMode.ts`, `NearThresholdSigningAuthPlan`,
        `NearThresholdSigningAuthContext`,
        `resolveNearThresholdSigningAuthContext`, and
        `buildNearThresholdSigningAuthPlan` are now
        `signingSessionAuthMode.ts`, `NearSigningSessionAuthPlan`,
        `NearSigningSessionAuthContext`,
        `resolveNearSigningSessionAuthContext`, and
        `buildNearSigningSessionAuthPlan`. Local plan/context variables were
        renamed to `signingSessionAuthPlan` /
        `signingSessionAuthContext`. Validation: `rtk pnpm -C
        packages/sdk-web run type-check` and `rtk pnpm -C tests exec
        playwright test -c playwright.unit.config.ts
        ./unit/nearSigning.sessionSelection.unit.test.ts
        ./unit/warmSessionStore.errorNormalization.unit.test.ts
        ./unit/routerAbNormalSigningSdk.guard.unit.test.ts
        ./unit/routerAbEd25519.walletSessionState.unit.test.ts
        ./unit/thresholdEd25519.presignPool.unit.test.ts --reporter=line`.
  - [x] Rename Ed25519 Wallet Session mint helper names away from
        threshold-session auth wording.
        `ThresholdEd25519SessionMintAuthorization`,
        `localPrfFirstForThresholdEd25519SessionMintAuthorization`,
        `mintEd25519AuthSession`, and the login mint builder are now named as
        Ed25519 Wallet Session mint helpers. The SDK helper module is now
        `walletSession.ts` with a matching `walletSession.typecheck.ts` fixture.
        Durable route discriminants such as `threshold_session_policy_webauthn`
        remain current boundary values.
        Validation: `rtk pnpm -C packages/sdk-web run type-check`, `rtk pnpm
        -C tests exec playwright test -c playwright.unit.config.ts
        unit/passkeyEd25519Recovery.unit.test.ts
        unit/signingEngineArchitecture.threshold.guard.unit.test.ts
        --reporter=line`, and `rtk
        pnpm -C tests exec playwright test -c playwright.config.ts
        unit/routerAbNormalSigningSdk.guard.unit.test.ts --reporter=line`.
  - [x] Rename server Wallet Session store names away from `AuthSession`.
        `AuthSessionStore.ts` is now `WalletSessionStore.ts`; exported
        factories, records, parser names, service fields, Durable Object store
        bindings, signing-session seal policy helpers, and focused tests now
        use Wallet Session names.
        Validation: `rtk pnpm -C packages/sdk-server-ts run type-check`, `rtk
        pnpm -C tests exec playwright test -c playwright.unit.config.ts
        unit/signingSessionSeal.sessionPolicy.unit.test.ts
        unit/thresholdSigningService.walletBudgetConsume.unit.test.ts
        unit/thresholdEd25519.sessionPolicyDigest.unit.test.ts
        unit/thresholdPostgresMalformedCleanup.unit.test.ts
        unit/thresholdEd25519WalletSession.rehydrate.unit.test.ts
        unit/warmSessionReadModel.unit.test.ts
        unit/warmSessionStore.capabilityResolution.unit.test.ts
        --reporter=line`, `rtk pnpm -C tests exec playwright test -c
        playwright.relayer.config.ts relayer/threshold-ecdsa.durable-stores.test.ts
        --reporter=line`, `rtk pnpm -C tests exec playwright test -c
        playwright.config.ts unit/routerAbNormalSigningSdk.guard.unit.test.ts
        --reporter=line`, and `rtk git diff --check`.
  - [x] Apply the Wallet Session store schema/config prefix bump.
        `THRESHOLD_ED25519_AUTH_PREFIX`,
        `THRESHOLD_ECDSA_AUTH_PREFIX`,
        `toThresholdEd25519AuthPrefix`,
        `toThresholdEcdsaAuthPrefix`, the `auth:` derived keyspace, the
        Postgres `kind = 'auth'` store row, and
        `threshold_ed25519_auth_consumptions` are now Wallet Session-named
        as `THRESHOLD_ED25519_WALLET_SESSION_PREFIX`,
        `THRESHOLD_ECDSA_WALLET_SESSION_PREFIX`,
        `toThresholdEd25519WalletSessionPrefix`,
        `toThresholdEcdsaWalletSessionPrefix`, `wallet-session:`,
        `kind = 'wallet_session'`, and
        `threshold_wallet_session_consumptions`.
        Validation: `rtk pnpm -C packages/sdk-server-ts run type-check`, `rtk
        pnpm -C tests exec playwright test -c playwright.unit.config.ts
        unit/thresholdPostgresMalformedCleanup.unit.test.ts
        unit/thresholdSigningService.walletBudgetConsume.unit.test.ts
        unit/signingSessionSeal.sessionPolicy.unit.test.ts --reporter=line`,
        and `rtk pnpm -C tests exec playwright test -c
        playwright.relayer.config.ts relayer/threshold-ecdsa.durable-stores.test.ts
        --reporter=line`.
  - [x] Rename the SDK public-auth domain helper away from `AuthSession`
        vocabulary.
        `authSessions.ts`, `AuthSessionDomainDeps`,
        `AuthSessionSigningSurface`, `AuthSessionWebContext`, and
        `getAuthSessionDeps` are now `walletAuth.ts`,
        `WalletAuthDomainDeps`, `WalletAuthSigningSurface`,
        `WalletAuthWebContext`, and `getWalletAuthDeps`. This keeps the public
        `auth.*` capability shape unchanged while removing stale internal
        auth-session naming from the active SDK source.
        Validation: `rtk pnpm -C packages/sdk-web run type-check`, `rtk pnpm
        -C tests exec playwright test -c playwright.unit.config.ts
        unit/refactor54Simplify.guard.unit.test.ts
        unit/seamsWeb.loginThresholdWarm.unit.test.ts
        unit/walletIframeHost.signTempoCancel.unit.test.ts --reporter=line`.
- [x] Isolate `signingRootId` / `signingRootVersion` to server, protocol, and
      persistence-normalization boundaries.
      These are not Wallet Session V2 client fields. Keep them only where the
      SDK is parsing current persisted/sealed records, validating protocol
      transcripts, or feeding low-level HSS/WASM/protocol helpers that still
      require signing-root binding. Remove them from client-side SDK domain
      objects, registration/link-device client payloads, active ECDSA key refs,
      warm-capability records, Email OTP worker request shapes, and legacy
      route helpers once `EvmFamilyEcdsaKeyHandle` / Router A/B key-handle
      state carries the binding.
  - [x] Audit current SDK-side occurrences in `packages/sdk-web/src/SeamsWeb`,
        `packages/sdk-web/src/core/signingEngine`,
        `packages/sdk-web/src/core/rpcClients`, and client IndexedDB helpers.
        Classify each occurrence as allowed boundary, protocol helper, or
        removal target.
        Audit result from June 17, 2026:
        - Allowed persistence/request boundaries:
          `core/indexedDB/schemaNames.ts`,
          `core/indexedDB/seamsWalletDB/emailOtpDeviceEnrollmentEscrows.ts`,
          `session/persistence/records.ts`,
          `session/persistence/sealedSessionStore.ts`, and
          `session/sealedRecovery/recoveryRecord.ts`.
        - Allowed protocol/HSS helpers:
          `core/rpcClients/relayer/thresholdEcdsa.ts`,
          `core/rpcClients/relayer/ecdsaUseCaseClient.ts`,
          `core/rpcClients/relayer/walletRegistration.ts`,
          `threshold/crypto/hssClientSignerWasm.ts`,
          `threshold/ecdsa/bootstrapSession.ts`,
          `threshold/ed25519/hssClientBase.ts`,
          `threshold/ed25519/hssLifecycle.ts`,
          `session/persistence/ecdsaRoleLocalRecords.ts`, and
          registration HSS bootstrap helpers.
        - Current internal identity contexts that still intentionally carry
          signing-root binding for HSS signing/export:
          `session/identity/evmFamilyEcdsaIdentity.ts`,
          `flows/signEvmFamily/*`, `flows/signNear/*`, and recovery/export
          helpers. These should stay typed as protocol/identity contexts, not
          public client inputs.
        - Remaining removal targets:
          registration/link-device/recovery client payload paths in
          `SeamsWeb/operations/*`, Email OTP worker payload shapes in
          `workerManager/workerTypes.ts`, and any typecheck fixtures that
          still model signing-root identity on non-boundary SDK domain
          objects.
  - [x] Delete `signingRootId` / `signingRootVersion` from active
        `ThresholdEcdsaSecp256k1KeyRef`, activation/bootstrap result objects,
        warm-capability/provision plans, registration/link-device/recovery
        client payloads, and Email OTP worker payloads that can instead carry
        `keyHandle`, `runtimePolicyScope`, or Router A/B key-handle state.
    - [x] Removed `signingRootId` / `signingRootVersion` from active
          `ThresholdEcdsaSecp256k1KeyRef` construction and key-ref adapters.
          Activation, wallet-registration, warm-session fixtures, ready-signer
          tests, and Email OTP worker bootstrap returns now keep key refs on
          `keyHandle` plus public facts. Persistence and signer activation
          derive signing-root binding from `runtimePolicyScope` or
          role-local public facts at the boundary. Validation: `rtk pnpm -C
          packages/sdk-web run type-check` and `rtk pnpm -C tests exec
          playwright test -c playwright.unit.config.ts
          ./unit/thresholdEcdsa.bootstrapPersistence.unit.test.ts
          ./unit/warmSessionStore.concurrency.unit.test.ts
          ./unit/evmFamilyEcdsaIdentity.unit.test.ts
          ./unit/signingFlow.readySigner.unit.test.ts --reporter=line`.
    - [x] Removed direct signing-root reads from link-device and email-recovery
          ECDSA prepare client payload parsers. Both parsers now require
          `runtimePolicyScope`, derive signing-root binding with
          `signingRootScopeFromRuntimePolicyScope`, and return the normalized
          scope through `WalletRegistrationEcdsaPrepareContext`. Wallet-key
          inventory responses still carry signing-root identity as protocol
          key facts. Validation: `rtk pnpm -C tests exec playwright test -c
          playwright.unit.config.ts
          ./unit/deviceRecoveryDomain.emailRecovery.unit.test.ts
          ./unit/linkDevice.flowEvents.unit.test.ts --reporter=line`.
    - [x] Removed `signingRootId` / `signingRootVersion` from the Email OTP
          ECDSA explicit-export worker request payload. The request now sends
          `keyHandle`, `readyRecord`, route auth, and session identity; the
          worker derives signing-root binding from parsed
          `readyRecord.publicFacts` before building the HSS export digest.
          Guard coverage now rejects root fields on the worker operation
          payload and checks the coordinator does not send them.
          Validation: `rtk pnpm -C packages/sdk-web run type-check` and
          `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts
          ./unit/emailOtpWalletSessionCoordinator.unit.test.ts
          --reporter=line`.
    - [x] Removed `signingRootId` from the Email OTP Ed25519 seed-export worker
          request payload. The export API now uses the stored session record's
          required `runtimePolicyScope`; the worker derives the HSS
          signing-root id with `signingRootScopeFromRuntimePolicyScope` before
          invoking the low-level Ed25519 export helper. Type fixtures reject
          `signingRootId` on this worker operation, and the coordinator unit
          test checks the request payload stays root-free.
          Validation: `rtk pnpm -C packages/sdk-web run type-check` and
          `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts
          ./unit/emailOtpWalletSessionCoordinator.unit.test.ts
          --reporter=line`.
    - [x] Removed `signingRootId` / `signingRootVersion` from the ECDSA
          provisioning use-case input and relayer bootstrap route input/output
          types. `ProvisionEcdsaInput` and `BootstrapEcdsaSessionRouteInput`
          now require `runtimePolicyScope`; the SDK derives signing-root
          binding with `signingRootScopeFromRuntimePolicyScope` at the
          protocol/persistence boundary before calling HSS helpers or validating
          relayer responses. Type fixtures reject direct signing-root fields on
          provisioning input, and the focused unit test checks the relayer input
          stays root-free. Validation: `rtk pnpm -C packages/sdk-web run
          type-check` and `rtk pnpm -C tests exec playwright test -c
          playwright.unit.config.ts ./unit/provisionEcdsaUseCase.unit.test.ts
          --reporter=line`.
    - [x] Removed the stored signing-root field from wallet-registration
          precompute readiness. The precompute handle now carries
          `thresholdRuntimePolicyScope`; registration derives `signingRootId`
          only at the Ed25519 HSS client-material boundary. The registration
          orchestration fixture was updated to carry current Router A/B
          normal-signing config rather than relying on a stale missing-config
          shape. Validation: `rtk pnpm -C packages/sdk-web run type-check` and
          `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts
          ./unit/addWalletSigner.orchestration.unit.test.ts --reporter=line`.
    - [x] Removed signing-root identity from the ECDSA warm-session provision
          plan's `EcdsaSigningKeyContext`. The plan context now carries only
          threshold key id and participant ids; activation derives signing-root
          binding from authoritative key identity or the persisted session
          record, and EVM reconnect digest/metadata paths derive from the
          selected record at the protocol boundary. Type fixtures reject root
          fields on `EcdsaSigningKeyContext`. Validation: `rtk pnpm -C
          packages/sdk-web run type-check`, `rtk pnpm -C tests exec
          playwright test -c playwright.unit.config.ts
          ./unit/warmSessionEcdsaProvisioning.unit.test.ts
          ./unit/warmSessionStore.reconnect.unit.test.ts
          ./unit/evmSigning.thresholdReconnectEvents.unit.test.ts
          ./unit/addWalletSigner.orchestration.unit.test.ts --reporter=line`,
          and `rtk pnpm -C tests exec playwright test -c playwright.config.ts
          ./unit/signingEngineEcdsaIdentity.publicSurfaces.guard.unit.test.ts
          --reporter=line`.
    - [x] Collapsed the login ECDSA bootstrap identity helper so it returns
          `keyHandle` plus a normalized `EvmFamilyEcdsaKeyIdentity` instead of
          an intermediate object with `signingRootId` / `signingRootVersion`.
          The helper still derives root from session runtime scope at the
          key-identity boundary. Validation: `rtk pnpm -C packages/sdk-web run
          type-check` and `rtk pnpm -C tests exec playwright test -c
          playwright.unit.config.ts ./unit/seamsWeb.loginThresholdWarm.unit.test.ts
          --reporter=line`.
    - [x] Removed `signingRootId` from the resolved NEAR Router A/B Ed25519
          Wallet Session state. `NearResolvedEd25519SigningSessionState` and
          `ResolvedRouterAbEd25519WalletSessionState` no longer carry a
          signing-root field; NEAR transaction, delegate, and NEP-413 signing
          derive `signingRootId` from `runtimePolicyScope` only when invoking
          the low-level Ed25519 HSS reconstruction helper. Type fixtures reject
          adding `signingRootId` back to the resolved Wallet Session state.
          Validation: `rtk pnpm -C packages/sdk-web run type-check` and `rtk
          pnpm -C tests exec playwright test -c playwright.unit.config.ts
          unit/routerAbEd25519.walletSessionState.unit.test.ts
          --reporter=line`, plus `rtk pnpm -C tests exec playwright test -c
          playwright.config.ts
          ./unit/signingEngineEcdsaIdentity.publicSurfaces.guard.unit.test.ts
          --reporter=line`.
    - [x] Removed signing-root identity from active EVM signing diagnostic
          summaries. `summarizeEvmFamilyEcdsaSessionRecord` now reports the
          opaque `keyHandle` and no longer emits `ecdsaThresholdKeyId`,
          `signingRootId`, or `signingRootVersion` into warning/debug payloads
          used by EVM signing lane selection and refresh paths. Validation:
          `rtk pnpm -C packages/sdk-web run type-check` and `rtk pnpm -C
          tests exec playwright test -c playwright.config.ts
          ./unit/signingEngineEcdsaIdentity.publicSurfaces.guard.unit.test.ts
          ./unit/evmFamilyEcdsaIdentity.unit.test.ts --reporter=line`.
    - [x] Removed signing-root identity from warm signing auth plans.
          `SigningAuthPlan` and `WalletAuthPlan` warm-session branches no
          longer carry `signingRootId`; EVM and NEAR auth planning now pass
          only curve, session id, expiry, and remaining-use data. A dedicated
          type fixture rejects reintroducing `signingRootId` on
          `SigningAuthPlan`. Validation: `rtk pnpm -C packages/sdk-web run
          type-check` and `rtk pnpm -C tests exec playwright test -c
          playwright.unit.config.ts unit/requireEvmFamilyStepUpAuth.unit.test.ts
          unit/signingFlow.readySigner.unit.test.ts --reporter=line`.
    - [x] Removed signing-root identity from prepared EVM signing operation
          metadata. `preparedSigning.ts` now carries material binding by
          operation id, optional operation fingerprint, exact lane identity
          key, and selected material; signing-root binding stays inside the
          material record and is derived only at protocol/HSS boundaries.
          Validation: `rtk pnpm -C packages/sdk-web run type-check` and `rtk
          pnpm -C tests exec playwright test -c playwright.unit.config.ts
          unit/ecdsaMaterialState.unit.test.ts
          unit/signingFlow.readySigner.unit.test.ts --reporter=line`.
    - [x] Removed signing-root identity from host-facing Email OTP recovery
          code rotation material. The Email OTP worker can still use
          signing-root identity inside its private encrypted enrollment escrow
          flow, but `EmailOtpRecoveryCodeRotationMaterial` no longer exposes
          `signingRootId` / `signingRootVersion` to host/public SDK code.
          Type fixtures reject reintroducing `signingRootId` on the rotation
          material. Validation: `rtk pnpm -C packages/sdk-web run type-check`.
    - [x] Removed companion Ed25519 signing-root identity from the Email OTP
          ECDSA warm-session rehydrate worker request. Host code now sends the
          companion session `runtimePolicyScope`; the Email OTP worker derives
          its exact internal `signingRootId` / `signingRootVersion` at the
          worker boundary before deriving the Ed25519 restore seed. Coordinator
          tests guard that `restore.ed25519` carries `runtimePolicyScope` and
          no root fields. Validation: `rtk pnpm -C packages/sdk-web run
          type-check` and `rtk pnpm -C tests exec playwright test -c
          playwright.unit.config.ts unit/emailOtpWalletSessionCoordinator.unit.test.ts
          --reporter=line`.
    - [x] Removed loose signing-root identity from the SeamsWeb Ed25519
          registration HSS preparation helpers. Registration and add-signer
          flows now pass `thresholdRuntimePolicyScope`; the helper derives
          `signingRootId` only at the low-level HSS client-material boundary.
          Validation: `rtk pnpm -C packages/sdk-web run type-check` and `rtk
          pnpm -C tests exec playwright test -c playwright.unit.config.ts
          unit/addWalletSigner.orchestration.unit.test.ts
          unit/thresholdEd25519.registrationWarmSession.unit.test.ts
          --reporter=line`. `unit/registrationWalletPersistence.unit.test.ts`
          still fails on unrelated account-store fixture drift
          (`deps.accountStore` is undefined in several tests).
    - [x] Removed stale signing-root fields from the type-only ECDSA
          provisioning lifecycle branch. `EcdsaProvisioningState` now models
          the `needs_secret_source` branch with `keyHandle` and
          `runtimePolicyScope`, while `signingRootId` / `signingRootVersion`
          remain confined to protocol command inputs and role-local storage
          key facts. Type fixtures reject reintroducing `signingRootId` on
          this lifecycle branch. Validation: `rtk pnpm -C packages/sdk-web
          run type-check`.
    - [x] Removed a non-boundary signing-root argument from the NEAR Ed25519
          explicit-export orchestration wrapper. `runNearEd25519HssExportAndViewer`
          now receives `runtimePolicyScope` and derives `signingRootId` only
          immediately before invoking the low-level HSS export ceremony helper.
          The focused export test fixtures were also updated from stale
          `indexedDB` dependencies to the current `keyMaterialStore` shape.
          Validation: `rtk pnpm -C packages/sdk-web run type-check` and `rtk
          pnpm -C tests exec playwright test -c playwright.unit.config.ts
          unit/privateKeyExportRecovery.binding.unit.test.ts
          unit/privateKeyExportRecovery.hardening.unit.test.ts --reporter=line`.
    - [x] Made the Email OTP wallet-unlock worker boundary require
          `runtimePolicyScope`. The higher-level login flow already resolves
          this scope before calling `unlockEmailOtpWallet`; the local payload
          builder now always sends it instead of preserving an optional core
          identity field. Validation: `rtk pnpm -C packages/sdk-web run
          type-check`.
    - [x] Tightened the `loginWithEmailOtpWallet` worker operation contract to
          require `runtimePolicyScope` at the shared worker-operation boundary.
          The raw worker parser now rejects missing scope, and the worker
          execution path no longer falls back to parsing runtime scope from the
          route JWT. Type fixtures reject omitting the scope from the payload.
          Validation: `rtk pnpm -C packages/sdk-web run type-check` and `rtk
          pnpm -C tests exec playwright test -c playwright.unit.config.ts
          unit/emailOtpWalletSessionCoordinator.unit.test.ts --reporter=line`.
    - [x] Removed signing-root identity from host-visible Email OTP
          enrollment-restore and recovery-code rotation worker results. The
          worker still keeps signing-root binding inside encrypted escrow and
          recovery-key AAD handling, while `restoreEmailOtpDeviceEnrollmentEscrow`
          and `rotateEmailOtpRecoveryCodes` now return root-free results to
          host SDK code. Type fixtures reject adding `signingRootId` /
          `signingRootVersion` back to those result shapes. Validation: `rtk
          pnpm -C packages/sdk-web run type-check` and `rtk pnpm -C tests exec
          playwright test -c playwright.unit.config.ts
          unit/seamsWeb.emailOtp.unit.test.ts
          unit/emailOtpWalletSessionCoordinator.unit.test.ts --reporter=line`.
    - [x] Removed the host-supplied Email OTP ECDSA role-local key identity
          handoff. `bootstrapEmailOtpEcdsaSessionsFromWorkerHandle` no longer
          accepts `roleLocalKeyIdentity`; host code sends `keyHandle` and
          `runtimePolicyScope`, and the worker derives the role-local
          threshold key id, signing-root binding, and relayer key id at the HSS
          bootstrap boundary. Existing-key bootstrap now checks the supplied
          key handle against the derived identity, type fixtures reject the old
          payload field, and the obsolete resolver/test were deleted.
          Validation: `rtk pnpm -C packages/sdk-web run type-check` and `rtk
          pnpm -C tests exec playwright test -c playwright.unit.config.ts
          unit/seamsWeb.emailOtp.unit.test.ts
          unit/emailOtpWalletSessionCoordinator.unit.test.ts --reporter=line`.
    - [x] Reclassified `core/rpcClients/relayer/ecdsaUseCaseClient.ts` after
          audit. It is still an active ECDSA role-local bootstrap route
          boundary: public/use-case inputs are root-free, and the helper
          derives signing-root binding from `runtimePolicyScope` only when
          building the low-level HSS route request or role-local storage facts.
          It is no longer tracked as a deletion target.
    - [x] Removed redundant signing-root fields from ready EVM signing
          material's non-boundary signing-key context. `ReadyEvmFamilyEcdsaMaterial`
          now carries only `ecdsaThresholdKeyId` and participant ids in
          `signingKeyContext`; signing-root binding remains on the selected
          protocol key identity and persisted record boundaries. Type fixtures
          reject adding `signingRootId` back to the ready-material context.
          Validation: `rtk pnpm -C packages/sdk-web run type-check` and `rtk
          pnpm -C tests exec playwright test -c playwright.unit.config.ts
          unit/evmFamilyEcdsaIdentity.unit.test.ts
          unit/ecdsaMaterialState.unit.test.ts
          unit/signingFlow.readySigner.unit.test.ts --reporter=line`.
    - [x] Removed signing-root identity from ECDSA availability diagnostics.
          `summarizeEcdsaLaneForDiagnostics` now reports key handle, key
          fingerprint, threshold key id, public facts, and session ids, while
          `summarizeSealedEcdsaRecordForDiagnostics` reports restore target
          identity without exposing `signingRootId` / `signingRootVersion` in
          host-visible debug payloads. Conflict grouping and protocol identity
          checks still use root binding internally. Validation: `rtk pnpm -C
          packages/sdk-web run type-check` and `rtk pnpm -C tests exec
          playwright test -c playwright.unit.config.ts
          unit/availableSigningLanes.ed25519Duplicates.unit.test.ts
          unit/availableSigningLanes.ecdsaDuplicates.unit.test.ts
          unit/warmSessionReadModel.unit.test.ts --reporter=line`.
    - [x] Removed duplicated full ECDSA key identity from wallet signing
          budget spend plans. `EcdsaWalletSigningSpendPlan` now derives ECDSA
          key identity from its selected lane and rejects an `ecdsaKey` field;
          the internal budget status check builder still uses `spend.lane.key`
          where exact ECDSA status reads need protocol identity. EVM budget
          finalization no longer accepts a separate key argument, and the
          spend-plan builder no longer accepts a duplicate identity bag.
          Validation:
          `rtk pnpm -C packages/sdk-web run type-check` and `rtk pnpm -C tests
          exec playwright test -c playwright.unit.config.ts
          unit/evmFamilyBudgetSpending.unit.test.ts
          unit/signingSessionBudgetFinalizer.unit.test.ts
          unit/evmFamily.requestBoundary.unit.test.ts --reporter=line`.
    - [x] Closed the remaining active SDK isolation audit. The remaining
          `signingRootId` / `signingRootVersion` uses are classified as
          protocol identity, persistence normalization, or low-level HSS/WASM
          helper inputs. Public SDK key refs, public facts, host-facing worker
          payloads, registration/link-device/recovery client payloads, and
          active diagnostics are root-free. `EvmFamilyEcdsaKeyIdentity`,
          `EvmFamilyEcdsaWalletKeyFacts`, resolved EVM signing lanes, and
          budget/conflict checks still carry full signing-root identity because
          those are internal protocol/read-model objects used to bind exact
          ECDSA-HSS material, reject cross-root drift, and build protocol
          transcripts. Those fields are not Wallet Session V2 client inputs.
          Source guards cover the public surfaces and keep root fields rejected
          on public SDK args, iframe payloads, key refs, and host-facing worker
          payloads.
  - [x] Add or extend source guards so public SDK/domain objects reject
        `signingRootId` / `signingRootVersion`, while explicit allowlists cover
        only protocol helpers, persistence normalization, and server-side code.
        Completed for the active SDK key-ref and public ECDSA call/payload
        surfaces: public-surface guards now reject root fields on public SDK
        args and iframe payloads, and require `KeyRef` to keep root fields as
        `never` tripwires. Validation: `rtk pnpm -C tests exec playwright test
        -c playwright.config.ts
        ./unit/signingEngineEcdsaIdentity.publicSurfaces.guard.unit.test.ts
        --reporter=line`.
- [x] Delete obsolete `V1`/`V2` suffixes from internal helpers whose version is
      no longer part of a durable protocol boundary.
      Completed for the current cleanup pass. The audit kept active wire,
      schema, route, persistence, metric, cryptographic transcript, and worker
      API names versioned, including Router A/B request builders/parsers,
      public keyset v2, ECDSA-HSS v1 protocol records, signing-root wire
      records, registration intents, current JWT claim kinds, and
      `awaitUserConfirmationV2`. Removed stale suffixes from the internal
      `routerAbEcdsaHssActiveStateSessionId` helper and from the local
      `awaitUserConfirmation` test alias. Validation: `rtk pnpm -C
      packages/sdk-web run type-check`, focused await-confirmation and
      Router A/B ECDSA-HSS normal-signing unit tests, and source scans for the
      deleted helper/test alias passed.
- [x] Keep durable protocol names such as Router A/B private worker route
      versions, serialized wire schemas, persistence records, and cryptographic
      transcript versions.
      Completed by classifying the remaining suffixes as current durable
      boundaries. Public Router A/B v2 normal-signing, Router A/B keyset v2,
      ECDSA-HSS v1, signing-root wire/migration artifacts, registration intent
      schemas, stored Wallet Session claim kinds, and current worker APIs remain
      explicitly versioned.
- [x] Remove old docs that describe non-Router threshold-session signing as an
      active path.
      Completed for active/public docs and app docs. Deleted obsolete standalone
      guides for old Ed25519 session auth, ECDSA presign-pool lifecycle,
      Cloudflare self-host route shape, and old Ed25519 benchmark reference;
      rewrote the route-auth, load-testing, ECDSA signing, and docs-app
      threshold-signing pages around Router A/B and Wallet Session auth.
      Validation: active docs/apps/packages stale-reference scans found no
      deleted standalone docs, deleted benchmark harness paths, or exact deleted
      public signing route literals outside cleanup/audit/refactor/future notes;
      `rtk pnpm -C tests exec playwright test -c playwright.config.ts
      ./unit/authSecretTerminology.guard.unit.test.ts --reporter=line` passed.
- [x] Update examples and public docs so Router A/B is the only documented
      Ed25519/ECDSA signing architecture.
      Completed for `apps/docs/src/concepts/threshold-signing.md`,
      `apps/web-server/README.md`, `docs/auth-gating-routes.md`,
      `docs/load-testing.md`, and `docs/threshold-ecdsa/ecdsa-threshold-signing.md`.
      The active public docs now point at Router A/B normal signing,
      Wallet Session V2 auth, Router A/B ECDSA-HSS, and deployed Cloudflare
      evidence gates. Validation: active docs/apps/packages stale-reference
      scans passed and the auth-secret terminology guard passed under
      `playwright.config.ts`.

## Phase 12: Plan Slimming And Architecture Cleanup

Start this after the active signing-route deletion slices are underway, or
sooner when stale planning text blocks implementation decisions.

Safety constraints for this phase:

- Plan slimming must preserve all current product signing flows: Ed25519 NEAR,
  NEP-413, delegate actions, Ed25519 pool hit/miss, ECDSA digest signing,
  and ECDSA pool hit/miss.
- Plan slimming must preserve all current ECDSA-HSS lifecycle flows:
  registration, activation, normal signing, pool-fill, export, recovery,
  refresh, keyset publication, and deployed evidence.
- Keep release-blocking security fixes in the active plan: private worker
  public-route closure, private worker service-auth, ECDSA export audit or
  telemetry, strict CORS evidence, deployed runtime evidence, source guards,
  and one-use nonce or presignature storage.
- Removing v1 N-of-N or t-of-N planning text only moves generalized future
  quorum work out of the release plan. It must not remove the current
  Deriver A plus Deriver B role split, current two-role HSS security model,
  current ECDSA-HSS support, or current recovery and refresh flows.
- Guard consolidation must preserve the same deny-list coverage or strengthen
  it. Each deleted guard task needs a mapped replacement guard and a focused
  test.
- Compact flow matrices must include lifecycle-sensitive support flows or link
  to a separate lifecycle matrix. Do not let signing-only tables hide
  export, recovery, refresh, keyset, activation, or pool-fill work.
- Compatibility parser cleanup must stay at request and persistence boundaries.
  Each deleted parser needs proof that no current stored, fixture, deployed,
  or request shape still needs it.
- Naming cleanup is internal unless a protocol version bump is explicitly in
  scope. Preserve durable wire labels, transcript labels, route versions,
  persistence record versions, and cross-language schema names.

- [x] Replace stale absolute links in `router-A-B-signer.md` with local relative
      links. Delete references to missing follow-up docs such as the old
      `refactor-67-router-ab-threshold-prf-adapter.md` link if there is no
      current local source of truth.
      Completed for the current file state. A focused scan found no
      `/Users/...`, `simple-threshold-signer`, or missing
      `refactor-67-router-ab-threshold-prf-adapter.md` references in
      `router-A-B-signer.md`.
- [x] Trim `router-A-B-signer.md` to current release-useful content: security
      target, role split, durable wire labels, active release blockers, and open
      evidence gates.
      Completed by replacing the long implementation checklist with a compact
      implementation-status section. The active signer plan now points to the
      current release state and remaining deployed evidence gates.
- [x] Move completed checklist history, old benchmark snapshots, and long status
      logs out of `router-A-B-signer.md` into an evidence/archive note so the
      active plan stays readable.
      Completed in
      `docs/audits/router-a-b-signer-implementation-history-2026-06-17.md`.
- [x] Remove v1 N-of-N and t-of-N implementation guidance from the active
      release plan. Track future quorum work in a separate protocol-version
      note with fresh vectors, leakage review, and acceptance criteria.
      Completed: `router-A-B-signer.md` now states that v1 release work is
      strict 2-of-2 Deriver A plus Deriver B, and generalized quorum work lives
      in `router-a-b-future-quorum.md`.
- [x] Freeze the current versioned length-prefixed `WireMessageV1` canonical
      encoding as the active implementation path. Remove open-ended codec option
      lists from the release checklist.
      Completed in `router-A-B-signer.md`: the active wire protocol section now
      names `WireMessageV1` as the release encoding with fixed field order,
      the `router-ab-protocol/wire-message/v1` domain label, 32-bit big-endian
      length prefixes, message-kind bytes, transcript digest bytes, and payload
      bytes. Alternate codecs require a later protocol-version bump and fresh
      vectors.
- [x] Move multi-cloud TEE deployment staging out of the active cleanup plan and
      into future deployment notes. Keep the current release path focused on
      Cloudflare split-worker deployment plus deployed evidence.
      Completed in `router-A-B-signer.md`: the old Stage 3 roadmap section is
      now Future Provider-Diverse Hardening and links to
      `router-a-b-deployment-choices.md`.
- [x] Reframe the bundled one-process profile as local smoke and packaging
      coverage only. Remove wording that presents it as a customer custody
      profile for the strict Router A/B security boundary.
      Completed in `router-A-B-signer.md`: the bundled profile is described as
      local smoke and packaging coverage for route shape, bindings, bundle
      construction, and parity checks. The strict release security boundary is
      explicitly the four-role Cloudflare deployment.
- [x] Replace duplicate bundle/startup evidence text with one current evidence
      row: dry-run size recorded, real `startup_time_ms` pending upload or
      deployment.
      Completed in `router-A-B-signer.md`. The older June 13 size table was
      replaced with the current June 16 dry-run role-size row and an explicit
      note that `startup_time_ms` requires Cloudflare upload or deploy.
- [x] Collapse Phase 0 guard tasks and Phase 8 guard tasks into one source-guard
      slice for old public signing routes and old SDK signing helpers.
      Completed by keeping release-scope decisions in Phase 0 and making Phase 8
      the single source-guard slice for old route literals, old SDK helpers,
      Wallet Session auth naming, and current Router A/B route-version
      allowlists.
- [x] Replace the broad replacement-coverage checklist with a compact flow
      matrix: SDK entrypoint, Router public route, private SigningWorker route,
      old route removed, focused test.
      Completed in Phase 1. The remaining app/wallet iframe/VoiceID/docs/test
      harness coverage question stays as a single explicit gap under the matrix.
- [x] Reorder implementation slices vertically by product flow: Ed25519 NEAR,
      Ed25519 NEP-413/delegate actions, ECDSA digest signing, ECDSA pool
      hit/miss, server route deletion, persistence-boundary cleanup, and final
      naming cleanup.
      Completed without renumbering historical phase anchors. Phase 1 now
      carries the product-flow matrix, Phase 2 owns Ed25519 product signing,
      Phase 3 owns ECDSA-HSS signing and pool-fill behavior, Phases 4 and 5 own
      server route/handler deletion, Phase 6 owns persistence-boundary cleanup,
      Phase 11 owns final naming cleanup, and Phases 13 through 15 track the
      remaining slimming follow-ups. Validation: phase-heading review with
      `rtk rg -n "^## Phase" docs/router-a-b-cleanup.md`.
- [x] Keep request and persistence compatibility parsers only where current
      stored or deployed shapes still require them. Each retained parser needs a
      deletion condition and a focused rejection test.
      Completed through the Phase 6 parser inventory and the Phase 14.5 ECDSA
      pool-fill request-boundary blocker. Retained old auth-field names are
      confined to current persisted/sealed record normalization or negative
      type/source-guard fixtures, and
      `local_threshold_ecdsa_presignature_pool` is confined to ECDSA presign
      session persistence parsing with an explicit schema-bump deletion
      condition. Focused rejection coverage includes old route-profile keysets,
      missing live ECDSA `poolFill`, old transport auth fields, and active
      signing source guards. Validation is recorded beside those Phase 6 and
      Phase 14.5 slices.
- [x] Rename runtime/internal `SignerA` and `SignerB` labels to `DeriverA` and
      `DeriverB` in one breaking pass after old public routes are gone. Preserve
      durable protocol labels until a protocol version bump changes wire
      compatibility.
      Completed for the Cloudflare strict runtime layer: the per-role runtime
      structs, strict fetch entrypoints, shared runtime enum variants, source
      guards, and binding tests now use Deriver A/B naming. Durable protocol and
      deployment labels remain intentionally unchanged:
      `Role::SignerA`/`Role::SignerB`,
      `CloudflareWorkerRoleV1::SignerA`/`CloudflareWorkerRoleV1::SignerB`,
      `CLOUDFLARE_SIGNER_*`, service-binding names, and private route constants
      stay wire/deployment labels until a schema/deployment version bump.
      Validation: `rtk cargo test --manifest-path
      crates/router-ab-cloudflare/Cargo.toml --test bindings --test
      source_guards` and `rtk git diff --check`.
- [x] Keep the security-preserving pieces while slimming: strict boundary
      parsers, unknown-field rejection, Router ciphertext opacity, one-use
      presignature semantics, active-state binding, secret/log source guards,
      and local evidence. Deployed runtime evidence is tracked in Phase 16.

## Phase 13: Codebase Slimming Refactor

Start this after Router A/B replacements exist for the touched product flow.
Each slice should delete one obsolete path end-to-end instead of keeping the old
and new signing stacks alive side by side.

Current execution status:

- Safe to start now: plan slimming, stale-link cleanup, flow-matrix cleanup,
  source-guard additions, compatibility-parser inventory, combined Worker
  entrypoint removal after per-role deploy scripts are confirmed, and
  one-variant route-profile cleanup after release gates are updated.
- Old public Ed25519/ECDSA signing routes, old SDK signing helpers, old public
  route handlers, and route-level tests are deleted. Remaining cleanup is the
  live ECDSA pool-fill request boundary, persistence/recovery boundary naming,
  and any curve-local primitives still required by Router A/B.

Safety constraints for this phase:

- Do not remove strict boundary parsers, one-use presignature state,
  active-state binding, Router ciphertext opacity, service-auth checks,
  secret/log source guards, or deployed-evidence gates.
- Keep request and persistence compatibility only where current stored records,
  fixtures, deployed routes, or request shapes still need it.
- Delete tests that protect old public threshold signing behavior. Replace only
  tests that assert current Router A/B behavior.
- Run the cheapest focused check for each deletion slice. Run smoke, dry-run,
  and deployed evidence only when route surfaces, Worker packaging, or
  release gates change.

- [x] Delete the old public Ed25519 threshold signing surface once Router A/B
      Ed25519 covers NEAR transactions, NEP-413 messages, delegate actions, pool
      hits, and pool misses:
      `packages/sdk-server-ts/src/router/express/routes/thresholdEd25519.ts`,
      `packages/sdk-server-ts/src/router/cloudflare/routes/thresholdEd25519.ts`,
      old route definitions, `ThresholdService/signingHandlers.ts` methods,
      and tests whose only purpose is
      `/threshold-ed25519/authorize`, `/presign/refill`, `/sign/init`,
      `/sign/finalize`, or `/sign/finalize-and-dispatch`.
      Completed by removing the public Ed25519 route registrations, route
      definitions, authorize/sign service handlers, stale route-level tests, and
      SDK `thresholdEd25519Presign.ts` route client. Deeper curve-local
      presign-pool slimming remains tracked in Phase 15.
- [x] Delete the old public ECDSA threshold signing surface once Router A/B
      ECDSA-HSS covers digest signing, pool hits, and pool misses:
      `packages/sdk-server-ts/src/router/express/routes/thresholdEcdsa.ts`,
      `packages/sdk-server-ts/src/router/cloudflare/routes/thresholdEcdsa.ts`,
      old route definitions, `ThresholdService/routerAb/ecdsaHssPoolFillHandlers.ts`
      methods, `threshold/ecdsa/authorize.ts`, `threshold/ecdsa/sign.ts`,
      old signing branches in `threshold/ecdsa/presignPool.ts`, and tests whose
      only purpose is `/threshold-ecdsa/authorize`, `/presign/init`,
      `/presign/step`, `/sign/init`, or `/sign/finalize`.
      Completed by deleting the SDK authorize/sign helpers, old public route
      registrations, route definitions, route-level tests, authorize/sign
      service methods, obsolete request/response types, ECDSA signing-session
      stores/parsers, route-era presign hint config, and stale Postgres DDL. The
      retained ECDSA presign session/pool primitives now serve Router A/B
      pool-fill only.
- [x] Replace SDK active signing call sites before deleting their helpers:
      route `signEvmFamily` secp256k1 signing through Router A/B ECDSA-HSS and
      remove direct calls to `authorizeEcdsaWithSession` and
      `signThresholdEcdsaDigestWithPool`; route Ed25519 presign finalization
      through Router A/B and remove direct calls to
      `finalizeThresholdEd25519Presign`.
      Completed for active EVM and NEAR signing; source guards now treat the old
      helpers and old public route literals as zero-tolerance in active source.
- [x] Add the public SDK/shared TypeScript boundary for Router A/B ECDSA-HSS
      normal signing before cutting over active EVM signing:
      strict prepare/finalize request builders, response parsers bound to the
      originating request, Wallet Session bearer-only POST helpers for
      `/v1/hss/ecdsa/sign/prepare` and `/v1/hss/ecdsa/sign`, and focused tests
      that reject legacy threshold-session fields.
      Completed with `routerAbEcdsaHss` shared builders/parsers and
      `prepareRouterAbEcdsaHssEvmDigestSigningV1` /
      `finalizeRouterAbEcdsaHssEvmDigestSigningV1`.
      Auditor follow-up completed by adding shared canonical request-digest
      builders for prepare/finalize requests and comparing response
      `request_digest` to the originating request in both strict response
      parsers.
      Validation: `rtk pnpm -C tests exec playwright test -c
playwright.unit.config.ts ./unit/routerAbEcdsaHssNormalSigning.unit.test.ts
--reporter=line`, `rtk pnpm -C tests exec playwright test -c
playwright.unit.config.ts ./unit/thresholdEcdsa.presignPoolRefill.unit.test.ts
--reporter=line`, `rtk pnpm -C packages/sdk-web type-check`, and
      `rtk pnpm -C packages/sdk-server-ts type-check`.
- [x] Extend ready ECDSA signer material with Router A/B ECDSA-HSS
      normal-signing scope and Wallet Session bearer credentials. This must be
      present before `signEvmFamily` can safely replace
      `authorizeEcdsaWithSession` and `signThresholdEcdsaDigestWithPool`.
      Completed with parsed `routerAbEcdsaHssNormalSigning` state on persisted
      ECDSA key/session records, required Router A/B ECDSA-HSS ready state on
      `ReadyEcdsaSignerSession`, and bearer-only Wallet Session credentials for
      ready signing.
      Validation: `rtk pnpm -C packages/sdk-web type-check`, `rtk pnpm -C
tests exec playwright test -c playwright.unit.config.ts
./unit/evmFamilyEcdsaIdentity.unit.test.ts
./unit/signingFlow.readySigner.unit.test.ts --reporter=line`, and `rtk pnpm
-C tests exec playwright test -c playwright.unit.config.ts
./unit/routerAbEcdsaHssNormalSigning.unit.test.ts --reporter=line`.
- [x] Delete or restrict public exports from `packages/sdk-web/src/threshold.ts`
      that expose old threshold-session signing helpers. Keep only current
      durable public APIs or move remaining low-level helpers behind internal
      test/build-only imports.
      Completed by removing `authorizeEcdsaWithSession`, `ecdsaPresignInit`,
      `ecdsaPresignStep`, `ecdsaSignInit`, and `ecdsaSignFinalize` from the
      public threshold entrypoint, then tightening the source guard so those
      helpers cannot be re-exported there. Follow-up completed by removing the
      low-level `connectEd25519Session` and `connectEcdsaSession` bootstrap
      exports from `@seams/sdk/threshold`; the helpers remain internal
      provisioning implementation details behind SeamsWeb/session surfaces.
      Validation: `rtk pnpm -C packages/sdk-web run type-check`, `rtk pnpm -C
      tests exec playwright test -c playwright.config.ts
      unit/routerAbNormalSigningSdk.guard.unit.test.ts --reporter=line`, and
      `rtk git diff --check`.
- [x] Remove the combined strict Worker entrypoint from
      `crates/router-ab-cloudflare`: delete `strict-worker-entrypoint`,
      `build:combined`, combined role measurement, `ROUTER_AB_WORKER_ROLE`
      parsing, and env-selected dispatch once all deploy and dry-run configs use
      per-role Worker entrypoints.
      Completed after per-role Wrangler configs became the only deploy path.
      The role enum remains for internal storage ownership and service-binding
      target validation.
- [x] Delete one-variant route-profile plumbing if no second strict route profile
      exists: remove `ROUTER_AB_ROUTE_PROFILE`, `strict_proof_bundle` parsing,
      route-profile validation, and matching wrangler variables. Keep explicit
      per-role Worker configs and route constants.
      Completed with a breaking public keyset schema bump:
      `router_ab_keyset_v2` at `/v2/router-ab/keyset` removes `route_profile`,
      rejects the old route-profile-bearing shape, and keeps the well-known
      discovery alias serving the v2 body.
      App server Router A/B keyset env resolution now constructs v2 keysets
      directly and has a focused boundary guard rejecting `route_profile`,
      `ROUTER_AB_KEYSET_ROUTE_PROFILE`, and v1 parser/version symbols:
      `rtk pnpm -C tests exec playwright test tests/unit/routerAbPublicKeyset.unit.test.ts tests/unit/routerAbPublicKeysetEnvBoundary.unit.test.ts --config=playwright.unit.config.ts`.
- [x] Collapse duplicated Deriver A and Deriver B strict fetch handlers into one
      role-parameterized helper in `crates/router-ab-cloudflare/src/strict_worker.rs`.
      The helper must keep role-specific paths, runtime bindings, envelope
      decrypt keys, peer signing keys, root-share metadata lookup, and
      `validate_for_worker_role` checks.
      Completed with `StrictDeriverRuntimeV1` and
      `handle_strict_deriver_fetch_v1`; the public Deriver A/B entrypoints now
      only enforce service auth, parse their role-specific runtime, and delegate.
- [x] Collapse repeated Deriver request handling inside the strict fetch helper:
      parse request, validate worker role, build preload plan, load verifying
      keys, preload the role host, load root-share metadata, dispatch to the
      operation-specific decrypt/handle function, and serialize the response.
      Completed with one shared Deriver fetch helper plus
      `preload_strict_deriver_host_v1`; operation-specific request parsing and
      decrypt dispatch remain explicit.
- [x] Revisit `DeriverAEngine` and `DeriverBEngine` in `router-ab-core`. If the
      host field remains unused for evaluation, replace the thin wrappers with
      role-specific free functions or zero-sized engines that still reject wrong
      role input.
      Completed by making both engines zero-sized role guards. Production and
      local evaluation now construct `DeriverAEngine::new()` or
      `DeriverBEngine::new()` without cloning or storing a host, while existing
      role-mismatch rejection tests remain active.
- [x] Revisit `SignerHost` and host trait exports. Keep individual traits used by
      Cloudflare code, but delete unused composite traits, reexports, or test-only
      wrappers that do not enforce a live invariant.
      Completed by deleting the unused composite `SignerHost` blanket trait and
      public reexport. The live granular host traits remain in use by
      Cloudflare preload/runtime code and focused tests.
- [x] After old public signing routes are gone, narrow source guards to the
      current invariant surface: old public route literals and old SDK signing
      helpers must fail in active code; persistence/request-boundary parsers must
      remain allowlisted only with deletion criteria.
      Completed by moving deleted public route literals, old SDK helper names,
      old ECDSA sign helpers, `ThresholdEd25519PresignPoolRouteAuth`,
      `buildNearWorkerSigningEnvelope`, and the live ECDSA no-poolFill fallback
      marker into zero-tolerance guard checks. Remaining allowlists are confined
      to documented persistence/request-boundary cleanup surfaces.
- [x] After each code-slimming slice, remove obsolete fixtures, mocks, route
      inventories, generated route docs, CORS tests, and package scripts that
      existed only for the deleted path.
      Current cleanup removed the stale executable threshold signing benchmark
      package scripts, `benchmarks/threshold-load`,
      `benchmarks/threshold-ecdsa-presign`, and their generated reports under
      `docs/benchmarks`. Remaining historical prose references are tracked in
      Phase 12 plan slimming.
- [x] Record focused validation beside each completed slice. Minimum expected
      checks are affected package type-checks or Rust tests, the relevant
      source-guard test, and `rtk git diff --check`; add Router smoke/dry-run
      only when Worker routes, packaging, or release gates changed.
      Current cleanup slices recorded focused validation with per-role
      Cloudflare wasm `cargo check`, `source_guards`, `bindings`,
      `cloudflare_parity`, `router:deploy:check`, `cargo fmt --check`, and
      `git diff --check`.

## Phase 14: ECDSA-HSS SDK Slimming Follow-Up

Start this after active EVM signing is stable on Router A/B ECDSA-HSS. The goal
is to remove the old threshold ECDSA SDK shape that now only supports tests,
fallback normalization, or duplicated argument plumbing.

Safety constraints for this phase:

- Keep strict shared request/response builders and parsers.
- Keep Router A/B scope binding, active SigningWorker binding, one-use
  presignature semantics, bearer-only request auth, zeroization, and focused
  source guards.
- Keep request or persistence compatibility only at the boundary that parses
  current stored records or deployed request shapes.

- [x] Delete `signThresholdEcdsaDigestWithPool` from
      `packages/sdk-web/src/core/signingEngine/routerAb/ecdsaHss/presignaturePool.ts`
      after moving any still-current zeroization, in-flight refill, and stale
      share assertions onto `signRouterAbEcdsaHssDigestWithPool`.
- [x] Delete old ECDSA sign/init and sign/finalize SDK helpers from
      `packages/sdk-web/src/core/signingEngine/routerAb/ecdsaHss/poolFillRoutes.ts` once no
      retained test or route path needs `/threshold-ecdsa/sign/init` or
      `/threshold-ecdsa/sign/finalize`.
- [x] Split Router A/B ECDSA-HSS pool-fill helpers away from legacy threshold
      presign route selection: replace `ThresholdEcdsaPresignRouteProfile` with
      fixed Router A/B pool-fill init/step helpers, then remove the legacy route
      profile branch.
      Completed the helper split first: the SDK stopped selecting between
      Router A/B and legacy presign routes through
      `ThresholdEcdsaPresignRouteProfile`.
      Follow-up completed by deleting the old fixed
      `ecdsaPresignInit`/`ecdsaPresignStep`
      `/threshold-ecdsa/presign/*` callers.
      The current Router A/B-only helpers are
      `routerAbEcdsaHssPresignaturePoolFillInit` /
      `routerAbEcdsaHssPresignaturePoolFillStep` helpers for
      `/v1/hss/ecdsa/presignature-pool/fill/*`.
      Validation: `rtk pnpm -C packages/sdk-web type-check`, `rtk pnpm -C
tests exec playwright test -c playwright.unit.config.ts
./unit/thresholdEcdsa.presignPoolRefill.unit.test.ts --reporter=line`, `rtk
pnpm -C tests exec playwright test -c playwright.unit.config.ts
./unit/routerAbEcdsaHssNormalSigning.unit.test.ts --reporter=line`, and `rtk
pnpm -C tests exec playwright test -c playwright.config.ts
./unit/routerAbNormalSigningSdk.guard.unit.test.ts --reporter=line`.
- [x] Delete the internal SDK `ecdsaPresignInit` and `ecdsaPresignStep`
      helpers from
      `packages/sdk-web/src/core/signingEngine/routerAb/ecdsaHss/poolFillRoutes.ts` once
      Router A/B pool-fill is the only ECDSA presign producer. No retained SDK
      helper should post to `/threshold-ecdsa/presign/init` or
      `/threshold-ecdsa/presign/step`.
      Completed by retaining only
      `routerAbEcdsaHssPresignaturePoolFillInit` /
      `routerAbEcdsaHssPresignaturePoolFillStep`.
- [x] Remove the no-`routerAbEcdsaHssPoolFill` branch in
      `runPresignHandshake`. Make `routerAbEcdsaHssPoolFill` required for every
      remaining ECDSA presign refill call, then simplify refill input types so
      the legacy no-pool-fill union branch disappears.
      Completed by making `routerAbEcdsaHssPoolFill` required on
      `RouterAbEcdsaHssClientPresignatureRefillInput`,
      `scheduleRouterAbEcdsaHssClientPresignaturePoolRefill`, and
      `refillRouterAbEcdsaHssClientPresignaturePool`; login prefill now skips
      records that lack Router A/B ECDSA-HSS normal-signing state.
- [x] Delete the public `/threshold-ecdsa/presign/init` and
      `/threshold-ecdsa/presign/step` route registrations and handler methods in
      the Phase 4/5 server-route cleanup slice. Keep only Router A/B public
      pool-fill routes and private/server-local primitive code they still call.
      Completed in Express, Cloudflare, and `routeDefinitions.ts`; server
      internals were renamed to
      `routerAbEcdsaHssPresignaturePoolFillInit` /
      `routerAbEcdsaHssPresignaturePoolFillStep`.
- [x] Remove `/threshold-ecdsa/presign/init`,
      `/threshold-ecdsa/presign/step`, `ecdsaPresignInit`, and
      `ecdsaPresignStep` from
      `tests/unit/routerAbNormalSigningSdk.guard.unit.test.ts` allowlists when
      Router A/B-only ECDSA presign refill lands.
      Completed by turning those tokens into zero-tolerance guard entries with
      no allowed source files.
- [x] Delete or rewrite tests whose only purpose is preserving old public ECDSA
      presign routes, especially old-route cases in
      `tests/unit/thresholdEcdsa.presignPoolRefill.unit.test.ts` and
      `tests/unit/thresholdEcdsa.presignDistributed.unit.test.ts`.
      Completed by making refill and distributed tests use Router A/B pool-fill
      routes only, deleting the obsolete SDK presign timeout test, and retiring
      the old Tempo high-level threshold-session ECDSA signing integration.
- [x] Preserve one-use presignature pop semantics, in-flight refill deduping,
      stale-share rejection, response binding, and zeroization on the Router A/B
      pool-fill path while deleting the old public presign route surface.
      Validation: `rtk pnpm -C packages/sdk-web type-check`, `rtk pnpm -C
      packages/sdk-server-ts type-check`, `rtk pnpm -C tests exec playwright
      test -c playwright.config.ts ./unit/routerAbNormalSigningSdk.guard.unit.test.ts
      --reporter=line`, `rtk pnpm -C tests exec playwright test -c
      playwright.unit.config.ts ./unit/thresholdEcdsa.presignPoolRefill.unit.test.ts
      --reporter=line`, `rtk pnpm -C tests exec playwright test -c
      playwright.unit.config.ts ./unit/thresholdEcdsa.presignPoolPolicy.unit.test.ts
      --reporter=line`, and `rtk pnpm -C tests exec playwright test -c
      playwright.unit.config.ts ./unit/thresholdEcdsa.presignDistributed.unit.test.ts
      --reporter=line`.
- [x] Narrow `signRouterAbEcdsaHssDigestWithPool` and
      `signRouterAbEcdsaHssDigestWithPoolHit` inputs so duplicated public-key
      and key-id fields come from `RouterAbEcdsaHssNormalSigningScopeV1`.
      The active signing call should not separately pass
      `ecdsaThresholdKeyId`, `clientVerifyingShareB64u`,
      `thresholdEcdsaPublicKeyB64u`, or `relayerVerifyingShareB64u` when those
      values are already bound inside the Router A/B scope.
      Completed by deriving ECDSA threshold key id, client public key, and
      threshold public key from the parsed Router A/B ECDSA-HSS normal-signing
      scope inside the signing helper. Active `signEvmFamily` and focused tests
      now pass only the scope, Wallet Session credential, digest, signing
      share, participant ids, and transport.
- [x] Remove unused presign-handshake parameters from
      `runPresignHandshake`: `relayerKeyId` and `clientVerifyingShareB64u`.
      Keep only the fields that the local presign handshake actually consumes.
      Completed by deleting both parameters from `runPresignHandshake` and
      removing `relayerKeyId` from the client presign refill/scheduler inputs.
      `clientVerifyingShareB64u` remains on the low-level refill input until
      the retained legacy presign refill path is deleted, because that helper
      still uses it to derive or validate the group public key.
      Validation: `rtk pnpm -C packages/sdk-web type-check`, `rtk pnpm -C
tests exec playwright test -c playwright.unit.config.ts
./unit/thresholdEcdsa.presignPoolRefill.unit.test.ts --reporter=line`, `rtk
pnpm -C tests exec playwright test -c playwright.unit.config.ts
./unit/thresholdEcdsa.presignPoolPolicy.unit.test.ts --reporter=line`, `rtk
pnpm -C tests exec playwright test -c playwright.unit.config.ts
./unit/signingFlow.readySigner.unit.test.ts --reporter=line`, and `rtk pnpm -C
tests exec playwright test -c playwright.config.ts
./unit/routerAbNormalSigningSdk.guard.unit.test.ts --reporter=line`.
- [x] Move keyRef/record fallback normalization out of
      `secp256k1.ts` and into the persistence or signing-runtime boundary that
      owns record hydration. Active signing should receive
      `ReadyEcdsaSignerSession` material directly.
- [x] After fallback normalization moves, delete
      `buildReadySecp256k1SigningMaterialFromKeyRef` and retain only the
      record-boundary builder still required by current runtime hydration.
- [x] Add focused type fixtures for the Router A/B ECDSA-HSS ready branch:
      reject missing `routerAbEcdsaHssNormalSigning`, reject cookie auth for
      Router A/B ECDSA-HSS normal signing, reject top-level
      `thresholdSessionAuthToken`, and reject broad object-spread construction
      that bypasses the ready-state builder.
      Completed by moving record hydration to `readySecp256k1Material.ts`,
      deleting the key-ref fallback export from `secp256k1.ts`, narrowing ready
      ECDSA signer sessions to bearer Wallet Session auth, and adding
      `evmFamilyEcdsaIdentity.typecheck.ts` fixtures. Validation: `rtk pnpm -C
packages/sdk-web type-check`, `rtk pnpm -C tests exec playwright test -c
playwright.unit.config.ts ./unit/signingFlow.readySigner.unit.test.ts
--reporter=line`, and `rtk pnpm -C tests exec playwright test -c
playwright.unit.config.ts ./unit/evmFamilyEcdsaIdentity.unit.test.ts
--reporter=line`.
- [x] Replace the long legacy allowlist in
      `tests/unit/routerAbNormalSigningSdk.guard.unit.test.ts` with a smaller
      zero-tolerance guard after old ECDSA route helpers are deleted. Old route
      literals and old helper names should be allowed only in deletion-plan docs
      or boundary tests with explicit removal criteria. `/threshold-ecdsa/presign/init`,
      `/threshold-ecdsa/presign/step`, `ecdsaPresignInit`, and `ecdsaPresignStep`
      must leave the allowlist when Router A/B-only ECDSA presign refill lands.
      Completed by moving removed ECDSA route/helper markers into a
      zero-tolerance token list. Follow-up cleanup also removed the final
      `ecdsaSignInit` / `ecdsaSignFinalize` deletion-blocker allowlist and
      confined the old local ECDSA pool-fill label to named persisted-record
      cleanup surfaces. Validation: `rtk pnpm -C tests exec playwright test -c
   playwright.config.ts ./unit/routerAbNormalSigningSdk.guard.unit.test.ts
   --reporter=line`.
- [x] Simplify `routerAbEcdsaHssActiveStateSessionId`: trust its typed
      `RouterAbEcdsaHssNormalSigningStateV1` input, or rename it as a boundary
      parser that accepts `unknown`. Avoid reparsing already-typed core state.
      Completed by trusting `RouterAbEcdsaHssNormalSigningStateV1` and leaving
      parsing in `parseRouterAbEcdsaHssNormalSigningStateV1` /
      `requireRouterAbEcdsaHssNormalSigningStateV1`. Validation: `rtk pnpm -C
packages/sdk-web type-check` and `rtk pnpm -C tests exec playwright test -c
playwright.unit.config.ts ./unit/routerAbEcdsaHssNormalSigning.unit.test.ts
--reporter=line`.
- [x] Retire or rewrite old threshold ECDSA tests whose only live purpose is
      preserving `/threshold-ecdsa/*` behavior:
      `thresholdEcdsa.authorizePolicyHint.unit.test.ts`,
      `thresholdEcdsa.requestTimeout.unit.test.ts`, and the old
      `signThresholdEcdsaDigestWithPool` cases in
      `thresholdEcdsa.presignPoolRefill.unit.test.ts`.
- [x] Validate each slice with the cheapest relevant checks:
      `rtk pnpm -C packages/sdk-web type-check`, focused Playwright unit tests
      for `routerAbEcdsaHssNormalSigning`, `evmFamilyEcdsaIdentity`,
      `signingFlow.readySigner`, `thresholdEcdsa.presignPoolRefill`, and
      `routerAbNormalSigningSdk.guard`, plus `rtk git diff --check`.

## Phase 14.5: ECDSA Pool-Fill Request Boundary Blocker

Finish this before calling ECDSA Router A/B-only complete or starting broad
Ed25519 SDK slimming. The current server request boundary still accepts omitted
`poolFill` and silently maps it to `local_threshold_ecdsa_presignature_pool`.
That is a live compatibility path, even if active SDK signing now sends Router
A/B pool-fill.

- [x] Make live ECDSA presign refill Router A/B pool-fill-only. In
      `packages/sdk-server-ts/src/core/ThresholdService/routerAb/ecdsaHssPoolFillHandlers.ts`,
      change `parseRouterAbEcdsaHssPresignPoolFillRequest` so `undefined` is an
      invalid request and every live request must include
      `poolFill.kind === 'router_ab_ecdsa_hss_signing_worker_pool'`, `scope`,
      and `expiresAtMs`.
      Completed by rejecting omitted `poolFill` at the live parser and narrowing
      the parsed live branch to Router A/B pool-fill only.
- [x] Split any retained local-pool shape away from the live request type. In
      `packages/sdk-server-ts/src/core/types.ts`, remove the
      `poolFill?: never` union branch from `ThresholdEcdsaPresignInitRequest`.
      If `local_threshold_ecdsa_presignature_pool` is still needed for current
      persisted records, give it a separate persisted-record parser/type under
      the persistence owner and keep it out of live route request parsing.
      Completed by making `ThresholdEcdsaPresignInitRequest.poolFill` a required
      Router A/B branch. The old local-pool label remains only in ECDSA presign
      session persistence parsing/tests and the persisted-record completion
      cleanup sink.
- [x] Preserve Router A/B ECDSA-HSS request binding while deleting the fallback:
      the parser must keep exact-key rejection, scope parsing, expiry parsing,
      account/session/signing-worker binding, and any current public-key or
      runtime-policy binding checks before a pool-fill request can reach the
      handler.
      Completed by keeping exact `poolFill` keys, strict Router A/B scope
      parsing, expiry bounds, account/rp/key/signing-root identity checks, and
      public-identity checks in the live validator.
- [x] Add a focused rejection test for missing `poolFill` on live ECDSA
      presign refill. The test should fail if a request without `poolFill` is
      accepted or classified as `local_threshold_ecdsa_presignature_pool`.
      Update the existing `thresholdEcdsa.presignPoolRefill` or nearest server
      parser/route unit test instead of adding a broad integration fixture.
      Completed in `thresholdEcdsa.presignDistributed.unit.test.ts`.
- [x] Update source guards after the fallback is deleted. Any remaining
      `local_threshold_ecdsa_presignature_pool` or `poolFill?: never` references
      must be allowlisted only in persisted-record parsing or deletion-plan docs
      with an explicit removal condition.
      Completed by adding `poolFill?: never` as a zero-tolerance source token and
      allowlisting the local-pool label only in ECDSA presign session persistence
      parsing and cleanup files.
- [x] Validate this blocker with `rtk pnpm -C packages/sdk-server-ts type-check`,
      the focused ECDSA presign-refill test, the Router A/B SDK guard, and
      `rtk git diff --check`.
      Validation so far: `rtk pnpm -C packages/sdk-server-ts run type-check`,
      `rtk pnpm -C packages/sdk-web run type-check`, `rtk pnpm -C tests exec
      playwright test -c playwright.unit.config.ts
      ./unit/thresholdEcdsa.presignDistributed.unit.test.ts --reporter=line`,
      `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts
      ./unit/thresholdEcdsa.presignPoolRefill.unit.test.ts --reporter=line`,
      `rtk pnpm -C tests exec playwright test -c playwright.config.ts
      ./unit/routerAbNormalSigningSdk.guard.unit.test.ts --reporter=line`, and
      the ECDSA Postgres/durable store focused checks. `rtk pnpm -C tests run
      test:threshold-core` and `rtk git diff --check` also passed after this
      blocker.

## Phase 15: Ed25519 SDK Slimming Follow-Up

Start this after the old `thresholdEd25519Presign.ts` route client,
`tryFinalizeThresholdEd25519*Presign` helpers, and active Ed25519 fallback calls
are gone. The goal is to make active NEAR/Ed25519 SDK signing read as if Router
A/B normal signing had always been the only signing path.

Preconditions:

- Active `signTransactions.ts`, `signNep413.ts`, and `signDelegate.ts` throw
  when Router A/B normal signing is unavailable.
- `tests/unit/routerAbNormalSigningSdk.guard.unit.test.ts` has zero-tolerance
  entries for the deleted Ed25519 route-client helpers and old presign/finalize
  route literals.
- Delete or rewrite stale Ed25519 public-route tests that are already included
  by `tests/playwright.unit.config.ts` and now fail because the routes return
  404. Do this before deeper slimming:
  `tests/unit/thresholdEd25519.presignRefill.unit.test.ts` old
  `/threshold-ed25519/presign/refill` route assertions, and
  `tests/unit/thresholdEd25519.finalizeAndDispatch.unit.test.ts` old public
  finalize-and-dispatch route assertions. Move still-current fingerprint,
  intent-binding, digest-binding, and budget-consume assertions into Router A/B
  normal-signing validation/vector tests.
- If any precondition fails in the target branch, finish the relevant blocker
  before deeper Phase 15 slimming.

Safety constraints for this phase:

- Keep Router A/B V2 request builders, response parsers, scope binding,
  operation fingerprints, intent/digest binding, one-use presignature pop
  semantics, bearer-only request auth, and `credentials: 'omit'`.
- Keep local WASM helpers that compute Ed25519 digests, reconstruct the client
  base, finalize returned signatures into NEAR transaction/delegate outputs, or
  burn stale client nonces.
- Keep `thresholdSessionAuthToken` only in negative type fixtures and
  zero-tolerance source guards. Current persistence, recovery, export, budget,
  and request-boundary code should use `walletSessionJwt`.
- Do not add a Router A/B feature flag, legacy fallback flag, compatibility
  branch, or diagnostics-driven route switch.

- [x] Prove active NEAR/Ed25519 call sites are Router A/B-only before deleting
      more code. Check
      `packages/sdk-web/src/core/signingEngine/flows/signNear/signTransactions.ts`,
      `signNep413.ts`, and `signDelegate.ts` for imports or calls to
      `tryFinalizeThresholdEd25519NearTransactionPresign`,
      `tryFinalizeThresholdEd25519SignatureOnlyPresign`,
      `finalizeThresholdEd25519Presign`,
      `refillThresholdEd25519PresignPool`,
      `/threshold-ed25519/presign/refill`,
      `/threshold-ed25519/sign/finalize-and-dispatch`,
      `/threshold-ed25519/sign/init`, or
      `/threshold-ed25519/sign/finalize`. The only acceptable matches should be
      deletion-plan docs or zero-tolerance guard token lists.
      Completed with `routerAbNormalSigningSdk.guard.unit.test.ts` zero-tolerance
      coverage for the old public Ed25519 signing routes and old SDK helper
      names.
- [x] Delete old worker-request envelope carryover from active Router A/B
      Ed25519 signing. In `signTransactions.ts`, `signNep413.ts`, and
      `signDelegate.ts`, remove active signing dependence on
      `buildNearWorkerSigningEnvelope`, `ThresholdSignerConfig`,
      `thresholdSessionKind`, and `thresholdSessionAuthToken`. Replace the old
      `requestPayload` shape with the narrow Router A/B signing inputs that the
      flow actually consumes: session id, Router A/B normal-signing state,
      Wallet Session bearer JWT, client base, operation id/fingerprint, product
      intent, and local WASM digest/finalization data.
      Completed by deleting `buildNearWorkerSigningEnvelope` and
      `chains/near/workerRequest.ts`, replacing the active transaction,
      delegate, and NEP-413 signing payloads with narrow Router A/B payloads,
      and moving active auth reads behind the Router A/B Ed25519 ready-state
      builder. The active signing modules now carry `walletSessionJwt`, never
      `thresholdSessionAuthToken`, and the source guard enforces that invariant.
- [x] Narrow the budget/signing wrappers instead of preserving the old worker
      payload type. If `signPreparedTransactionOperation` or shared NEAR command
      helpers still require a `WasmSign*Request` payload only to satisfy a
      generic signature, introduce a branch-specific Router A/B payload type or
      narrower generic parameter. Do not keep `credential`,
      `thresholdSessionKind`, or relayer-authorize fields in active signing
      payloads as adapter filler.
      Completed by replacing the active transaction, delegate, and NEP-413
      signing `requestPayload` shapes with branch-specific Router A/B payloads
      that carry only a required client base.
- [x] Move Wallet Session credential extraction to a single boundary builder.
      Replace core calls that pass full
      `ResolvedRouterAbEd25519WalletSessionState` only to read
      `thresholdSessionAuthToken` with a parsed Router A/B-ready Ed25519 state
      that carries `routerAbNormalSigning` plus `walletSessionJwt`. Rename
      `routerAbWalletSessionCredentialFromResolvedWalletSessionState` or
      replace it with a builder whose name reflects the Router A/B Ed25519 ready
      branch. The builder must validate Router A/B ready-state identity before
      exposing `walletSessionJwt`: account id, threshold session id,
      SigningWorker id, runtime-policy scope, and signer public key or threshold
      key material must match the active Ed25519 signing state. The Router A/B
      request/admission builder must validate operation scope against the
      request being prepared. Cookie auth must remain rejected for active Router
      A/B normal signing.
      Completed with
      `requireRouterAbEd25519NormalSigningReadyState`, which validates the
      threshold session id, wallet signing-session id, account id, threshold key
      material account, Router A/B normal-signing state, SigningWorker id,
      runtime-policy scope, relayer URL, signer public key, and bearer Wallet
      Session JWT before exposing a Router A/B credential.
- [x] Collapse active `thresholdSessionAuthToken` reads in NEAR signing. Remove
      direct reads from `signTransactions.ts`, `signNep413.ts`, and
      `signDelegate.ts` once the ready-state builder exposes
      `walletSessionJwt`. Keep reads only in `routerAbEd25519WalletSessionState.ts`,
      persisted-record hydration, recovery/export, and budget-status boundaries
      until those owners are migrated. Add type fixtures that reject a ready
      Ed25519 Router A/B signing state with missing `routerAbNormalSigning`,
      cookie auth, missing Wallet Session JWT, or broad object-spread
      construction.
      Completed by wiring transactions, delegate, and NEP-413 signing through
      `RouterAbEd25519NormalSigningReadyState`, renaming active client-base
      reconstruction and repair inputs to `walletSessionJwt`, adding
      `routerAbWalletSessionCredential.typecheck.ts`, and extending
      `routerAbNormalSigningSdk.guard.unit.test.ts` to reject old auth fields in
      active Ed25519 signing modules.
- [x] Recheck missing-key repair ownership after the auth collapse.
      Missing-key repair now force-refreshes current worker-owned Ed25519 HSS
      signing material through `ensureThresholdEd25519HssSigningMaterial`, feeds
      it `walletSessionJwt` from the Router A/B Ed25519 ready state, rebuilds the
      Router A/B request payload, and retries the same Router A/B signing
      executor. The old raw-cache repair helper,
      `repairThresholdEd25519MissingRelayerKey`, was deleted after active
      transactions, delegate, and NEP-413 signing stopped importing it.
- [x] Rename or delete stale internal threshold-presign labels that now describe
      Router A/B behavior. Review
      `packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519PresignFinalize.ts`
      and `packages/sdk-web/src/core/signingEngine/threshold/ed25519/presignPool.ts`
      for internal-only names such as `ThresholdEd25519PresignRefillRunResult`
      and `threshold_ed25519_presign_refill_run_result_v1`. Rename them to
      Router A/B Ed25519 names when they are local types or metrics. Keep a
      durable label only if it is a persisted record, deployed wire contract, or
      cross-language protocol value.
      Completed by renaming the local refill-run result type/kind and the local
      presign operation identity discriminant to Router A/B Ed25519 names. The
      status/clear worker message payloads, result kinds, policy types, scope
      key builder, clear helpers, and status helper are now also named as
      Router A/B Ed25519 presign-pool internals. The retained
      `ThresholdEd25519*` names in this area describe curve/WASM primitives,
      not old public route contracts.
      Validation: `rtk pnpm -C packages/sdk-web run type-check` and `rtk pnpm
      -C tests exec playwright test -c playwright.unit.config.ts
      unit/thresholdEd25519.presignPool.unit.test.ts --reporter=line`.
- [x] Thin `ed25519PresignFinalize.ts` after the envelope and auth cleanup.
      Remove unused worker imports, old route-auth types, old helper result
      aliases, and duplicate request-preparation branches. Keep the Router A/B
      pool-hit path, pool-miss prepare/finalize path, background refill
      scheduling, stale-share rejection, response binding, and zeroization.
      Split the file only if the deleted code leaves an obvious product-flow
      boundary; avoid a cosmetic file split.
      Completed by deleting the old route-client imports and helper result
      aliases during the Router A/B rewrite, then renaming the remaining
      active orchestration helpers to Router A/B names:
      `RouterAbEd25519SignatureOnlyPurpose`,
      `createRouterAbEd25519PresignOffer`,
      `createRouterAbEd25519PresignOffers`, and
      `burnRouterAbEd25519PresignOffers`. The retained
      `ThresholdEd25519*` names in this file now refer to curve/WASM primitives,
      operation fingerprints, or the curve-local client presign pool.
- [x] After the immediate stale-route tests are deleted or rewritten, update E2E
      names and fixtures that say `thresholdEd25519` only because they exercised
      the old public route shape. Keep names that still describe the Ed25519-HSS
      key material or product signing curve.
      Completed for the current e2e surface. Remaining `thresholdEd25519` e2e
      names describe Ed25519-HSS curve/key material and product signing behavior.
      Focused scans over `tests/e2e` and `tests/helpers` find no deleted public
      Ed25519/ECDSA signing route literals or old SDK signing helper names.
- [x] Shrink the Router A/B SDK source guard again after this phase. Move
      `/threshold-ed25519/authorize`, `/threshold-ed25519/sign/init`,
      `/threshold-ed25519/sign/finalize`,
      `ThresholdEd25519PresignPoolRouteAuth`,
      `buildNearWorkerSigningEnvelope`, and active-flow
      `thresholdSessionAuthToken` reads from allowlisted blockers to
      zero-tolerance entries once the corresponding deletion lands. Leave
      `thresholdSessionAuthToken` only in named negative type fixtures and
      source-guard token lists.
      Completed by moving the old Ed25519 public signing routes,
      `ThresholdEd25519PresignPoolRouteAuth`, old route-client helpers, and
      `buildNearWorkerSigningEnvelope` into zero-tolerance guard checks. Active
      Ed25519 signing modules are separately guarded against
      `thresholdSessionAuthToken`, `thresholdSessionKind`,
      `ThresholdSignerConfig`, and the deleted worker envelope.
- [x] Delete public Ed25519 server routes after SDK zero-tolerance passes:
      `POST /threshold-ed25519/authorize`,
      `POST /threshold-ed25519/sign/init`, and
      `POST /threshold-ed25519/sign/finalize` from Express, Cloudflare,
      `routeDefinitions.ts`, CORS route inventories, and
      `ThresholdService` handlers. Preserve private Router A/B worker routes and
      server-local primitives that the Router A/B protocol still calls.
      Completed by deleting the remaining authorize route, request/response
      types, service methods, route tests, and stale E2E public-route fixtures;
      the old Ed25519 public route literals now remain only as zero-tolerance
      source-guard tokens.
- [x] Clean stale test commands and configs after route-test deletion. Update
      `tests/package.json`, Playwright configs, route inventories, and helper
      scripts that still reference deleted tests such as
      `thresholdEcdsa.tempoHighLevel.integration.test.ts` or old Ed25519 public
      route suites. A deleted test file must not remain in any package script or
      config include list.
      Completed for the deleted ECDSA integration command/config path in
      `tests/package.json`, `tests/playwright.integration.config.ts`, and
      `tests/README.md`; `test:threshold-core` now runs the Router A/B ECDSA-HSS
      and Ed25519 presign-pool core unit tests instead of the obsolete
      `/threshold-ecdsa/*` relayer harness. The old Ed25519 public route files
      are deleted and no longer appear in Playwright includes. Also slimmed
      `nearSigning.sessionSelection.unit.test.ts` so it keeps current
      auth-planning and warm-material restore coverage while removing stale
      sign-through assertions that depended on the old threshold-session worker
      payload.
- [x] Validate the phase with the smallest checks that cover the changed
      surface:
      `rtk pnpm -C packages/sdk-web type-check`;
      `rtk pnpm -C packages/sdk-server-ts type-check` when server routes change;
      `rtk pnpm -C tests exec playwright test -c playwright.config.ts ./unit/routerAbNormalSigningSdk.guard.unit.test.ts --reporter=line`;
      `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/routerAbNormalSigningValidation.unit.test.ts ./unit/routerAbNormalSigningVectors.unit.test.ts ./unit/thresholdEd25519.presignPool.unit.test.ts ./unit/nearSigning.sessionSelection.unit.test.ts --reporter=line`;
      run the broader unit suite when this phase changes shared unit-test
      surfaces beyond Router A/B signing, pool lifecycle, or session selection;
      `rtk pnpm -C tests test:threshold-core`;
      add `thresholdEd25519.presignPool.unit.test.ts` or
      `routerAbNormalSigningVectors.unit.test.ts` when presign-pool scheduling
      or fingerprint contracts change; finish with `rtk git diff --check`.
      Completed for the Phase 15 slimming slice with
      `rtk pnpm -C packages/sdk-web run type-check`, the Router A/B SDK source
      guard, the Router A/B validation/vector/session-selection bundle,
      `rtk pnpm -C tests run test:threshold-core`, and
      `rtk git diff --check`.

## Phase 15.5: Remaining Threshold Lifecycle Endpoint Migration

The earlier cleanup phases deleted the old public signing and presign routes.
This phase owns the remaining `/threshold-ed25519/*`, `/threshold-ecdsa/*`, and
`/threshold/signing-session-seal/*` lifecycle endpoints. These routes are not
the old product signing finalizers, but several of them still mint sessions,
bootstrap HSS state, resolve key identity, seal or unseal signing-session
state, export server-side material, or continue protocol state. That means they
can still create Router A/B-incomplete signing state, as seen in the
wallet-unlock regressions.

Start this before treating local cleanup as complete for deployment. The goal is
to make the public API read as Router A/B and Wallet Session architecture from
the first request that creates signing-capable state.

Safety constraints for this phase:

- Do not delete a lifecycle endpoint until every active SDK/server caller has a
  Router A/B-compatible replacement route, typed request builder, parser, and
  focused test.
- A signing-capable lane is sign-ready only when the normalized runtime record
  has Router A/B normal-signing state, Wallet Session auth material, SigningWorker
  identity, runtime scope, threshold session id, wallet signing-session id, and
  curve-specific public identity. Lane selection must reject stale runtime or
  sealed records before final signing code is reached.
- Signing-capable Ed25519 session responses must include
  `routerAbNormalSigning`, runtime-policy scope, SigningWorker identity, and a
  bearer Wallet Session JWT. A route that cannot provide those fields must fail
  before the SDK stores a signable record.
- Signing-capable ECDSA-HSS records must include
  `routerAbEcdsaHssNormalSigning` with stable key context, public identity,
  SigningWorker identity, activation epoch, normalized participants, and Wallet
  Session JWT auth material. A bootstrap, restore, activation, or sealed-refresh
  path that cannot provide those fields must produce a non-signable
  compatibility record or fail before persistence.
- Signing-session seal routes must not be able to write or hydrate a signable
  Ed25519/ECDSA record unless the sealed payload already carries the
  curve-specific Router A/B state and Wallet Session auth material required
  above. Seal apply/remove remains a persistence boundary only until it is
  renamed to Wallet Session terminology.
- Public routes that remain must be Router A/B or Wallet Session routes with
  strict WebAuthn or bearer Wallet Session proof. Cookie auth and diagnostics
  must not select signing behavior.
- Internal continuation routes must become service-bound/private Router A/B
  worker routes or module-local helpers. A public route named `internal` is a
  security smell unless a route-auth audit proves it is only a non-secret
  compatibility boundary with a deletion date.
- Keep durable transcript labels, persisted record versions, and cross-language
  protocol labels only when changing them would break current storage or worker
  protocol evidence. Rename local TypeScript route helpers and public route
  names once the boundary replacement is wired.
- Add source guards after each deletion or route rename so the old public
  lifecycle route names cannot re-enter active SDK/server routing.

Endpoint review and intended refactor:

| Existing endpoint | Current role | Router A/B refactor decision |
| --- | --- | --- |
| `GET /threshold-ed25519/healthz` | Public health probe for the threshold Ed25519 service. | Rename or consolidate behind a Router A/B health route, for example `GET /v2/router-ab/healthz` with role/scheme status in the body. Delete the threshold-named route after route inventories, smoke scripts, and CORS tests use the Router A/B route. Health output must not reveal secret config, key material, or Deriver/SigningWorker binding internals. |
| `POST /threshold-ed25519/session` | Public WebAuthn-gated Ed25519 session issuance. This is the highest-priority route because it can produce a wallet-unlock session that later fails Router A/B signing if `routerAbNormalSigning` is absent. | Replace with a Router A/B Wallet Session issuance route, preferably a unified route such as `POST /v2/router-ab/wallet-session` with an Ed25519 capability request. The server must reject signing-capable issuance when Router A/B normal signing is not configured. The response parser must require Router A/B normal-signing state, runtime-policy scope, SigningWorker id, Wallet Session JWT, account id, threshold session id, wallet signing-session id, and signer public key before persistence. |
| `POST /threshold-ed25519/hss/prepare` | Ed25519 HSS ceremony/client-base setup step. | Review active callers and move the route to a Router A/B Ed25519 HSS lifecycle namespace, for example `POST /v2/router-ab/ed25519/hss/prepare`, or make it private if it is only a server-local primitive. The replacement must bind the request to Wallet Session identity, account id, runtime policy, and Router A/B normal-signing config. It must not create a signable persisted record unless the final response includes Router A/B normal-signing state. |
| `POST /threshold-ed25519/hss/respond` | Ed25519 HSS ceremony response step. | Keep only as part of the Router A/B Ed25519 HSS lifecycle replacement. Bind it to the prepared ceremony id, Wallet Session identity, account id, and exact protocol transcript. Reject stale or cross-account responses. Rename SDK/server helpers away from threshold route terminology after the Router A/B route lands. |
| `POST /threshold-ed25519/hss/finalize` | Ed25519 HSS ceremony finalization step. | Replace with the Router A/B Ed25519 HSS lifecycle finalizer. The finalizer must either persist a Router A/B-ready Ed25519 record or fail. Add a regression test for wallet unlock followed by NEAR transaction signing where the persisted record contains `routerAbNormalSigning` before any sign flow runs. |
| `POST /threshold-ed25519/internal/cosign/init` | Public route labelled internal, currently gated by threshold protocol state. | Audit callers. If still required, move to a private service-bound Router A/B worker route or module-local helper. If obsolete, delete route definitions, Express/Cloudflare handlers, CORS entries, route docs, and tests. Add a source guard that rejects public `/threshold-ed25519/internal/cosign/*` route registration. |
| `POST /threshold-ed25519/internal/cosign/finalize` | Public route labelled internal, currently gated by threshold protocol state. | Same as cosign init. The replacement must prove no client-origin public route can drive cosign continuation without Router A/B service auth and transcript binding. |
| `POST /threshold/signing-session-seal/apply-server-seal` | Public sealed-refresh route that applies server-held seal material to signing-session state. It can hydrate state used by later signing readiness. | Rename or wrap behind a Wallet Session sealed-refresh namespace, for example `POST /v2/wallet-session/seal/apply`, or fold into Wallet Session issuance/recovery. The request parser must bind wallet id, curve, threshold session id, wallet signing-session id, retention policy, and Wallet Session auth. The service must reject attempts to seal signable records missing Ed25519 `routerAbNormalSigning` or ECDSA `routerAbEcdsaHssNormalSigning` plus Wallet Session JWT auth material. Keep the threshold-named route only as a request/persistence compatibility boundary with a deletion condition. |
| `POST /threshold/signing-session-seal/remove-server-seal` | Public sealed-refresh route that removes server-held seal material for signing-session state. | Rename or wrap with the same Wallet Session sealed-refresh namespace as apply. It must prove exact wallet/session ownership, reject cross-user or stale removal, and avoid changing signing readiness based on diagnostics or optional auth. Delete the threshold-named route once workers, tests, route docs, and CORS inventories use the Wallet Session route. |
| `GET /threshold-ecdsa/healthz` | Public health probe for the threshold ECDSA service. | Rename or consolidate behind the Router A/B health route. Delete the threshold-named route once scripts and tests use the Router A/B health endpoint. |
| `POST /threshold-ecdsa/key-identities` | Resolves ECDSA key identities for an active Ed25519 session. | Replace with a Router A/B ECDSA-HSS identity route or fold the identity lookup into registration/bootstrap and activation refresh responses. The public response should use public identity, stable key context, activation epoch, SigningWorker identity, and keyset version terms. Avoid exposing legacy `relayerKeyId` or local server-share identifiers outside a parser boundary. |
| `POST /threshold-ecdsa/hss/bootstrap` | ECDSA-HSS role-local bootstrap route. | Replace active SDK usage with the strict Router A/B ECDSA-HSS registration/bootstrap route described in `router-a-b-ecdsa.md`. The new route must route Deriver A/B through Router A/B, activate the SigningWorker, and persist `routerAbEcdsaHssNormalSigning` plus Wallet Session JWT auth material. The SDK bootstrap parser must reject any signing-capable ECDSA record that lacks Router A/B ECDSA-HSS normal-signing state, Wallet Session auth, or active SigningWorker identity. |
| `POST /threshold-ecdsa/hss/export/share` | Releases an authorized ECDSA-HSS server-side export share. | Replace with the Router A/B ECDSA-HSS export route. Scope it by Wallet Session JWT, export request id, recipient class, public identity, activation epoch, and explicit user intent. Keep any legacy field conversion only inside the export request parser, then delete the threshold-named public route after SDK export callers move. |
| `POST /threshold-ecdsa/internal/cosign/init` | Public route labelled internal, currently gated by threshold protocol state. | Audit callers and either delete it or move it behind private Router A/B service auth. The route must not remain public if it can influence ECDSA signing, presignature generation, or server-share state. |
| `POST /threshold-ecdsa/internal/cosign/finalize` | Public route labelled internal, currently gated by threshold protocol state. | Same as ECDSA cosign init. Add tests that the public router no longer registers `/threshold-ecdsa/internal/cosign/*` once the replacement is wired. |

Implementation checklist:

- [x] Harden the immediate unlock-to-sign readiness invariant before endpoint
      migration. Completed in commit `1b3088136`: Ed25519 warm-session policy
      creation now requires Router A/B normal-signing state, server startup fails
      without `ROUTER_AB_NORMAL_SIGNING_WORKER_ID`, session issuance rejects
      missing `sessionPolicy.routerAbNormalSigning`, runtime Ed25519/ECDSA lane
      selection refuses stale records without Router A/B normal-signing state,
      and focused stale-lane regressions cover both curves.
- [x] Build a caller inventory for every endpoint above. Include SDK clients,
      iframe wallet calls, local dev harnesses, Express routes, Cloudflare
      routes, route definitions, CORS inventories, tests, scripts, and docs.
      Completed by tracing the active SDK/server callers, route definitions,
      Express/Cloudflare handlers, worker seal callers, relayer tests, source
      guards, and docs for every endpoint in the table.
- [x] Split the inventory into product lifecycle groups: Wallet Session
      issuance, Ed25519 HSS lifecycle, ECDSA-HSS identity/bootstrap,
      ECDSA-HSS export, sealed signing-session hydration, internal cosign
      continuation, and health probes.
      Completed by grouping the route moves into Ed25519 Wallet Session,
      Ed25519 HSS lifecycle, ECDSA-HSS lifecycle/export, Wallet Session seal,
      public health, and deleted public cosign surfaces.
- [x] Define the Router A/B public route names and request/response schemas for
      each group. Prefer a small number of cohesive Wallet Session or Router
      A/B lifecycle routes over one-for-one legacy route renames when a unified
      route makes invalid state harder to represent.
      Completed with shared route constants for `/v2/router-ab/*`,
      `/v1/hss/ecdsa/*`, and `/v2/wallet-session/seal/*`, and with route
      definitions/tests asserting the old threshold paths are absent.
- [x] Implement the Ed25519 Wallet Session replacement first. Make
      `routerAb.normalSigning.mode="enabled"` the only SDK/server signing
      configuration for product signing, and reject local startup or session
      issuance when `signingWorkerId` or `ROUTER_AB_NORMAL_SIGNING_WORKER_ID`
      is missing.
      Completed via `POST /v2/router-ab/wallet-session/ed25519`; SDK warm-up,
      Email OTP provisioning, Express, Cloudflare, and route inventories now use
      the Router A/B Wallet Session route.
- [x] Move Ed25519 HSS prepare/respond/finalize callers to Router A/B-named
      routes or private helpers. Add unlock-to-sign regression tests proving
      Ed25519 records are Router A/B-ready before `signTransactions`,
      `signNep413`, or `signDelegate` runs.
      Completed via `/v2/router-ab/ed25519/hss/{prepare,respond,finalize}` and
      the Ed25519 Wallet Session readiness tests listed below.
- [x] Move ECDSA identity/bootstrap callers to Router A/B ECDSA-HSS routes.
      Add unlock-to-EVM-sign regression tests proving ECDSA records carry
      `routerAbEcdsaHssNormalSigning` before `signEvmFamily` builds a ready
      signer session.
      Completed via `/v1/hss/ecdsa/key-identities` and
      `/v1/hss/ecdsa/bootstrap`; SDK callers, route definitions, Express,
      Cloudflare, and focused unit/relayer tests use the new constants.
- [x] Move ECDSA export callers to Router A/B ECDSA-HSS export routes and keep
      legacy field normalization only at the export request parser boundary.
      Completed via `/v1/hss/ecdsa/export/share`; SDK export callers and server
      routes use the shared Router A/B ECDSA-HSS export constant.
- [x] Move signing-session seal apply/remove callers to Wallet Session-named
      sealed-refresh routes. Add parser tests proving signable sealed records
      require Router A/B state and Wallet Session auth, and route tests proving
      the threshold-named seal routes are compatibility-only until deletion.
      Completed for the public route move via `/v2/wallet-session/seal/*`;
      worker callers, route definitions, Express/Cloudflare transports, and
      relayer tests now use the Wallet Session route. Deeper sealed-record
      parser hardening remains covered by the sealed-session store tests.
- [x] Delete or privatize both Ed25519 and ECDSA `internal/cosign` routes. Add
      route-definition and source-guard checks that fail if public
      `/threshold-*/internal/cosign/*` routes return.
      Completed by removing the public cosign route definitions and
      Express/Cloudflare registrations, and by adding route-level 404 coverage
      plus source-guard denial for `/threshold-*/internal/cosign/*`.
- [x] Rename or consolidate health routes after functional lifecycle routes are
      migrated.
      Completed via `/v2/router-ab/ed25519/healthz` and
      `/v1/hss/ecdsa/healthz`.
- [x] Delete the old threshold lifecycle route definitions, Express handlers,
      Cloudflare handlers, SDK route clients, CORS entries, route docs, stale
      tests, and guard allowlists after each replacement route is proven.
      Completed for the public lifecycle route names: active SDK/server callers
      use shared Router A/B or Wallet Session route constants, and the old route
      literals remain only in this plan, negative route assertions, and source
      guard deny-lists.
- [x] Update completion criteria so local cleanup cannot be complete while any
      signing-capable public lifecycle route remains under
      `/threshold-ed25519/*`, `/threshold-ecdsa/*`, or
      `/threshold/signing-session-seal/*`.
      Completed by adding the Phase 15.5 completion criterion below and then
      satisfying it with route-definition/source-guard checks and relayer 404
      tests.

## Phase 15.6: Strict Internal Signing Wallet Session Types

Phase 15.5 removed or renamed the public threshold-era lifecycle routes, but the
SDK still has lower-level provisioning and persistence types that can describe
cookie-backed signing-capable state. This phase makes that invalid state
unrepresentable inside the SDK. Public app-session cookies can still authorize
lifecycle routes, but every internal signing-capable Wallet Session record must
carry bearer Wallet Session JWT auth plus curve-specific Router A/B state before
it can be persisted, advertised as ready, or passed to a signer.

Implementation checklist:

- [x] Add strict internal curve-specific Wallet Session types:
      `RouterAbEd25519SigningWalletSession` and
      `RouterAbEcdsaHssSigningWalletSession`. Each type must require
      `walletSessionJwt`, `walletSigningSessionId`, `thresholdSessionId`,
      expiry/quota fields, runtime-policy scope, and the curve-specific Router
      A/B normal-signing state. These are SDK-internal types only; public app
      APIs, iframe messages, diagnostics, and callbacks must not expose the JWT.
- [x] Add boundary builders that convert route responses, runtime records,
      sealed recovery records, and warm-capability records into the strict
      internal types. A builder must return a typed failure instead of producing a
      signable object when Wallet Session JWT auth, Router A/B state,
      SigningWorker identity, or required scope is missing.
- [x] Change Router A/B Ed25519 and ECDSA signing/readiness inputs to require the
      strict internal types. Final signing helpers, ready-signer builders,
      availability lane builders, budget readers, and warm-session reconnect code
      must not accept raw records, optional JWTs, optional Router A/B state, or
      broad `sessionKind` unions.
- [x] Delete cookie-backed signing-capability branches from SDK internals:
      `cookie_passkey`, `sessionKind: 'cookie'` on signing-capable warm
      capabilities, passkey Ed25519/ECDSA provisioning, Email OTP ECDSA
      bootstrap/enrollment/login, worker payloads, and ECDSA use-case activation
      plans. Keep cookie auth only as lifecycle route authorization that mints or
      refreshes a bearer Wallet Session JWT-backed internal record.
- [x] Add `@ts-expect-error` fixtures proving the strict types reject missing
      `walletSessionJwt`, missing Ed25519 `routerAbNormalSigning`, missing ECDSA
      `routerAbEcdsaHssNormalSigning`, cookie auth as signing auth, legacy
      `threshold_ecdsa_session_v2` / `threshold_ed25519_session_v1` as current
      Wallet Session auth, and public SDK shapes that expose Wallet Session JWTs.
- [x] Add source guards for the strict phase. Active signing-capable SDK modules
      must reject `cookie_passkey`, signing-capable `sessionKind: 'cookie'`,
      `thresholdSessionAuthToken`, and old threshold-session JWT kinds outside
      parser/test compatibility boundaries.
- [ ] Add unlock-to-sign regression coverage that uses real persisted state:
      passkey unlock to Ed25519 sign, passkey unlock to ECDSA sign, Email OTP
      unlock to Ed25519 sign, and Email OTP unlock to ECDSA sign. The tests must
      fail before final signing if the persisted lane cannot build the strict
      internal Wallet Session type.
- [x] Update `docs/refactor-68-wallet-session-v2.md` when this phase lands so the
      Wallet Session V2 historical plan records the internal/public boundary:
      public APIs do not expose Wallet Session JWTs; internal signing sessions
      require bearer JWT plus Router A/B state; cookies are lifecycle route auth
      only.

Validation checklist:

- [x] `rtk pnpm -C packages/sdk-web type-check`.
- [x] `rtk pnpm -C packages/sdk-server-ts type-check`.
- [x] `rtk pnpm -C tests exec playwright test -c playwright.source.config.ts
      unit/routerAbNormalSigningSdk.guard.unit.test.ts --reporter=line`.
- [x] Focused SDK readiness tests proving wallet unlock produces Ed25519
      Router A/B-ready persisted records before transaction, NEP-413, or
      delegate signing can build ready state.
      Covered by
      `unit/seamsWeb.loginThresholdWarm.unit.test.ts`,
      `unit/routerAbEd25519.walletSessionState.unit.test.ts`, and
      `unit/thresholdEd25519WalletSession.rehydrate.unit.test.ts`.
- [x] Focused SDK readiness tests proving wallet unlock or activation produces
      ECDSA Router A/B-ready persisted records before EVM signing can build a
      ready signer session.
      Covered by
      `unit/seamsWeb.loginThresholdWarm.unit.test.ts` and
      `unit/signingEngineEcdsaIdentity.lifecycle.guard.unit.test.ts`.
- [x] Focused sealed-refresh/store-boundary tests proving apply/remove stays an
      ownership-bound seal operation and restored sealed records do not become
      spendable signing auth unless the SDK readiness layer can recover the exact
      Wallet Session and Router A/B state.
      Covered by
      `relayer/signing-session-seal-router.test.ts`,
      `unit/sealedSessionStore.unit.test.ts`,
      `unit/signingSessionRestoreCoordinator.unit.test.ts`, and
      `unit/thresholdEd25519.nearSigningQueue.guard.unit.test.ts`.
- [x] Route-level tests proving old public lifecycle endpoints return 404 after
      their replacements land.
      Covered by
      `relayer/threshold-ed25519.scheme-dispatch.test.ts`.
- [x] Source guards proving old public signing routes, old public lifecycle
      routes, old SDK helpers, and old threshold-session auth names cannot
      re-enter active SDK/server routing.
      Covered by
      `unit/routerAbNormalSigningSdk.guard.unit.test.ts` and
      `unit/router.routeDefinitions.unit.test.ts`.
- [x] Router A/B signing-capable lifecycle routes reject cookie-mode session
      issuance/bootstrap before writing server signing state.
      Covered by
      `relayer/threshold-ed25519.scheme-dispatch.test.ts` and
      `relayer/threshold-ecdsa-role-local-passkey-bootstrap.test.ts`; both
      assert `400`, no `Set-Cookie`, and no downstream session/bootstrap call.
- [x] Router A/B signing-capable route validators require Router A/B Wallet
      Session JWT claim kinds instead of legacy `threshold_*_session_*` kinds.
      Covered by `unit/thresholdSessionClaims.unit.test.ts` and route-level
      rejection coverage in `relayer/threshold-ed25519.scheme-dispatch.test.ts`.
- [x] Executable harness/docs no longer advertise the old public threshold
      lifecycle route names.
      Updated `tests/scripts/test-relay-server.mjs`,
      `apps/web-server/README.md`,
      `docs/signing-session-architecture/sealed-refresh.md`,
      `docs/threshold-ecdsa/ecdsa-hss-v2-integration.md`, and
      `crates/ed25519-hss/README.md`.
- [x] `rtk pnpm -C tests run test:threshold-core`.
- [x] `rtk git diff --check`.

## Phase 15.7: Strict Server Wallet Session Claim Boundaries

Phase 15.6 makes SDK signing-capable state strict, but the server must enforce
the same rule at every signing-capable claim boundary. Active Router A/B Wallet
Session issuance, sealed-refresh, budget-status, HSS lifecycle, ECDSA-HSS
bootstrap/export, and internal service entrypoints must use Router A/B Wallet
Session JWT claim kinds only. Legacy `threshold_ed25519_session_v1` and
`threshold_ecdsa_session_v2` claims may remain only in explicitly named legacy
parser tests or non-signing compatibility readers with a deletion condition.

Implementation checklist:

- [x] Add narrow server JWT signing wrappers:
      `signRouterAbEd25519WalletSessionJwt` and
      `signRouterAbEcdsaHssWalletSessionJwt`. These wrappers must hard-code the
      Router A/B claim kind, require `sessionKind: 'jwt'`, reject cookie-mode
      signing auth, and require the curve-specific binding inputs needed by
      signing-capable records. Ed25519 inputs must include
      `routerAbNormalSigning`, SigningWorker id, runtime-policy scope, threshold
      session id, wallet signing grant/session id, participant set, and expiry.
      ECDSA-HSS inputs must include the Router A/B ECDSA-HSS normal-signing
      state or its issuer-side binding components: stable key context, public
      identity, SigningWorker id, activation epoch, participant set, key handle,
      threshold session id, wallet signing grant/session id, and expiry.
      Completed in `commonRouterUtils.ts`; the Ed25519 wrapper validates
      Router A/B normal-signing state and runtime-policy scope, and the
      ECDSA-HSS wrapper validates the issuer-side key/identity/activation
      binding or a full Router A/B ECDSA-HSS normal-signing state before
      minting. The validated Router A/B binding is signed into the JWT:
      Ed25519 JWTs carry `routerAbNormalSigning`, and ECDSA-HSS JWTs carry
      either `routerAbEcdsaHssNormalSigning` or
      `routerAbEcdsaHssIssuerBinding`. ECDSA-HSS JWT parsing requires exactly
      one of those two binding branches so normal-signing state and issuer-side
      binding cannot disagree inside the same token.
- [x] Convert active signable issuers to the narrow wrappers:
      `packages/sdk-server-ts/src/router/relayWalletRegistration.ts`,
      `packages/sdk-server-ts/src/router/express/routes/linkDevice.ts`,
      `packages/sdk-server-ts/src/router/cloudflare/routes/linkDevice.ts`,
      `packages/sdk-server-ts/src/router/express/routes/syncAccount.ts`,
      `packages/sdk-server-ts/src/router/cloudflare/routes/syncAccount.ts`,
      `packages/sdk-server-ts/src/router/express/routes/emailRecovery.ts`,
      `packages/sdk-server-ts/src/router/cloudflare/routes/emailRecovery.ts`,
      Ed25519 Wallet Session issuance, and ECDSA-HSS bootstrap. Keep any generic
      `signWalletSessionJwt` helper only as a lower-level implementation detail
      or rename it as legacy/non-signing if a compatibility boundary still needs
      it.
      Completed for the listed issuer inventory; direct Ed25519 JWT construction
      now also routes through the strict wrapper. The generic
      `signWalletSessionJwt` implementation is private and accepts Router A/B
      Wallet Session kinds only.
- [x] Make `/v2/wallet-session/seal/*` Router A/B Wallet Session-only at the
      auth boundary. The seal route and service must parse
      `parseRouterAbEd25519WalletSessionClaims` /
      `parseRouterAbEcdsaHssWalletSessionClaims`, reject legacy threshold-session
      claim kinds, and refuse to hydrate a signable sealed record unless the
      restored payload can recover the exact Router A/B state required by
      Phase 15.6.
      Already satisfied by the Wallet Session seal route/service boundary; this
      pass kept the legacy rejection coverage in
      `relayer/signing-session-seal-router.test.ts`.
- [x] Make signing budget-status auth Router A/B Wallet Session-only. Remove
      `parseThresholdEd25519SessionClaims` and
      `parseThresholdEcdsaSessionClaims` fallbacks from active budget-status
      parsing, and add negative tests proving old threshold-session JWTs cannot
      read current signing budgets.
      Completed in `signingBudgetStatus.ts` with a dedicated legacy-token
      rejection test.
- [x] Remove legacy claim-parser fallbacks from signing-capable service
      entrypoints, including Ed25519 HSS `prepareWithSession`,
      `respondWithSession`, `finalizeWithSession`, and ECDSA-HSS bootstrap/auth
      service paths. Route wrappers already validate Router A/B claims, but the
      service boundary must not silently accept old threshold-session claims.
      Completed in `ThresholdSigningService.ts`; Ed25519 HSS session methods and
      ECDSA-HSS session authorization now parse Router A/B Wallet Session claims
      only.
- [x] Add source guards for active server route/service code. Guards must fail if
      active signing-capable files contain `kind: 'threshold_ed25519_session_v1'`,
      `kind: 'threshold_ecdsa_session_v2'`,
      `parseThresholdEd25519SessionClaims`, or
      `parseThresholdEcdsaSessionClaims`. Allow exceptions only through an exact
      file allowlist, and each allowlisted file must contain a comment explaining
      why the legacy parser remains plus its deletion condition. Active
      route/service files have zero tolerance.
      Completed with
      `unit/routerAbServerWalletSessionClaimBoundary.guard.unit.test.ts`; the
      only active-code allowlist is the legacy parser definition file, which now
      carries deletion-condition comments. The guard also rejects exported
      generic JWT signers, legacy session-token constants, and active SDK
      `browser_cookie` signing auth.
- [x] Update tests for the new server claim boundary:
      seal route legacy rejection, budget-status legacy rejection, Ed25519 HSS
      route/service legacy rejection, ECDSA-HSS bootstrap/export legacy
      rejection, and positive Router A/B Wallet Session claim coverage.
      Completed with wrapper tests, budget-status legacy rejection, source
      guard coverage, and the existing seal/route rejection suites.
- [x] Remove SDK signing-capable cookie auth escape hatches.
      Ed25519 persisted Wallet Session auth, sealed-recovery auth, Email OTP
      ECDSA publication, EVM-family ECDSA transport auth, and durable ECDSA lane
      parsing now require bearer Router A/B Wallet Session JWT material for
      signable state.
- [x] Update `docs/refactor-68-wallet-session-v2.md` to record the final server
      claim-boundary rule: Router A/B signable state is issued, sealed,
      refreshed, budget-checked, and consumed with Router A/B Wallet Session JWT
      kinds only.

Validation checklist:

- [x] `rtk pnpm -C packages/sdk-server-ts type-check`.
- [x] Focused claim parser and route tests:
      `unit/thresholdSessionClaims.unit.test.ts`,
      `relayer/signing-session-seal-router.test.ts`, and
      `unit/signingBudgetStatus.parser.unit.test.ts`.
      Also covered by
      `unit/routerAbServerWalletSessionClaimBoundary.guard.unit.test.ts`.
- [x] Focused Ed25519/ECDSA Router A/B route tests covering legacy-claim
      rejection and Router A/B claim success.
- [x] `rtk git diff --check`.

## Phase 15.8: Local Rust ECDSA-HSS Dev Worker Route Parity

The strict Cloudflare SigningWorker exposes the ECDSA-HSS private routes, and the
TypeScript relay-side pool-fill bridge now posts to
`/router-ab/v1/signing-worker/ecdsa-hss/presignature-pool/put`. The local Rust
`pnpm router` four-worker and bundled topologies need the same ECDSA-HSS route
surface before they can be used as local ECDSA-HSS end-to-end evidence.

Implementation checklist:

- [x] Add local Rust route constants in `crates/router-ab-dev/src/lib.rs` for the
      public ECDSA-HSS signing routes and strict private SigningWorker routes:
      `/v1/hss/ecdsa/sign/prepare`, `/v1/hss/ecdsa/sign`,
      `/router-ab/v1/signing-worker/ecdsa-hss/presignature-pool/put`,
      `/router-ab/v1/signing-worker/ecdsa-hss/sign/prepare`, and
      `/router-ab/v1/signing-worker/ecdsa-hss/sign`.
- [x] Extend `local_worker_owned_paths_v1` so the Router owns the public
      ECDSA-HSS prepare/finalize routes and the SigningWorker owns the private
      pool-put, prepare, and finalize routes.
- [x] Extend `router_ab_local_worker` four-worker dispatch for ECDSA-HSS:
      Router public prepare/finalize should validate local Wallet Session auth,
      forward only admitted ECDSA-HSS requests to the SigningWorker, and validate
      the SigningWorker response binding before returning it.
- [x] Extend `router_ab_local_worker` SigningWorker dispatch for ECDSA-HSS:
      pool-put must parse the strict private pool-fill request, bind it to the
      active ECDSA-HSS SigningWorker scope, and persist a one-use local
      presignature pool record; prepare must consume exactly one pool entry and
      persist a request-bound server presignature record; finalize must consume
      exactly that request-bound record and return a response bound to the
      prepare request.
      - [x] Pool-put strict private request parsing, active scope binding, one-use
            pool insert, duplicate detection, and Cloudflare-compatible receipt.
            Local pool storage is keyed by active SigningWorker state plus
            presignature id, and same-id different-scope/material replays fail.
      - [x] Prepare requires local internal service auth, parses a
            Router-admitted service envelope, consumes exactly one pool entry,
            and persists a request-bound server presignature record.
      - [x] Finalize requires local internal service auth, parses a
            Router-admitted service envelope, consumes exactly that
            request-bound record, and returns a response bound to the prepare
            request.
- [x] Extend `router_ab_local_bundled` with the same ECDSA-HSS public and private
      route handling so `pnpm router:smoke:bundled` exercises the same route
      surface as the split-worker topology.
      - [x] Bundled private pool-put dispatch matches split-worker dispatch.
      - [x] Bundled public prepare/finalize and private prepare/finalize dispatch.
- [x] Mirror strict Cloudflare service-auth semantics for local private
      ECDSA-HSS pool-fill, prepare, and finalize routes. Use
      `ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET` when configured, otherwise use the
      local development secret, and keep the auth check at the private request
      boundary.
- [x] Add live local Rust HTTP smoke coverage for ECDSA-HSS pool-fill plus
      prepare/finalize. The smoke must prove a relay-side pool-fill request to
      the SigningWorker private
      `/router-ab/v1/signing-worker/ecdsa-hss/presignature-pool/put` route
      succeeds, an ECDSA public prepare consumes that pool entry, finalize
      consumes the request-bound presignature, and a second consume fails.
- [x] Update `rtk pnpm router:smoke`, `rtk pnpm router:smoke:bundled`, and
      `rtk pnpm router:evidence` output so local ECDSA-HSS evidence clearly
      distinguishes live HTTP route dispatch from protocol-shape/parser-only
      evidence.
      `router:smoke` and `router:smoke:bundled` now report
      `ecdsa_hss_evidence_kind: live_http_route_dispatch` plus pool-fill,
      prepare, finalize, and replay-rejection statuses. `router:evidence` now
      reports `evidence_kind: protocol_shape_parser_binding_timing`, includes
      the private pool-fill route, and explicitly points to the smoke commands
      for live HTTP evidence.
- [x] Add a source guard or release-check assertion that fails if the cleanup plan
      or release evidence marks local ECDSA-HSS `pnpm router` support complete
      while the local Rust route table lacks the private ECDSA-HSS SigningWorker
      routes.

Validation checklist:

- [x] `rtk cargo test --manifest-path crates/router-ab-dev/Cargo.toml`.
- [x] `rtk pnpm router:smoke`.
      Passed on June 18, 2026 with four-worker live HTTP
      ECDSA-HSS pool-fill, prepare, finalize, and one-use replay rejection.
- [x] `rtk pnpm router:smoke:bundled`.
      Passed on June 18, 2026 with bundled live HTTP ECDSA-HSS pool-fill,
      prepare, finalize, and one-use replay rejection.
- [x] `rtk pnpm router:evidence -- --out <new evidence report>`.
      Passed on June 18, 2026 and wrote
      `crates/router-ab-dev/reports/local-release-evidence/local-release-evidence-2026-06-18-phase-15-8.json`.
- [x] Focused source/release guard covering local ECDSA-HSS route parity.

## Phase 15.9: Move Client Crypto Material Behind Signer-Core And WASM Handles

The Router A/B signing cleanup removed legacy public signing routes, but active
SDK code still exposes crypto-secret client material in TypeScript. Ed25519 HSS
client-base material is persisted as `xClientBaseB64u`, TypeScript readiness code
can decide whether that material is usable, and normal-signing flows pass raw
client material through orchestration code before reaching WASM. ECDSA-HSS has
similar risks around client verifying shares, presignature material, and
registration/bootstrap public fact construction.

Target boundary:

- `crates/signer-core` owns cryptographic protocol logic, key/share derivation,
      material validation, signing-share generation, binding checks, and
      crypto-adjacent serialization formats.
- WASM workers are the browser execution boundary for `signer-core` operations.
      They own secret material, PRF-derived state, nonce/client-base state,
      presign/client-share state, and crypto validation.
- The TypeScript SDK orchestrates only: route selection, public/session metadata,
      typed lifecycle state, worker calls, non-secret handles, public binding
      facts, Wallet Session JWTs, and server requests.
- The Router/server owns admission, policy, JWT/session issuance, route auth,
      persistence, SigningWorker forwarding, and observability.
- Cloudflare SigningWorker owns server-side signing material, one-use
      nonce/presign state, prepare/finalize execution, and private route
      enforcement.

Implementation checklist:

- [x] Added the first Ed25519 worker material-handle slice:
      `Ed25519HssMaterialHandle`, `RouterAbEd25519SigningMaterialReady`,
      an HSS client-worker material store, and a handle-based normal-signing
      client-share command.
- [x] Replaced active Ed25519 Router A/B normal-signing finalizers in
      `signTransactions`, `signDelegate`, `signNep413`, and
      `ed25519PresignFinalize` so the final signing boundary consumes
      `RouterAbEd25519SigningMaterialReady` instead of raw `xClientBaseB64u`.
- [x] Replaced the Ed25519 Router A/B presign-pool refill and pool-hit signing
      path so client presign creation and presign signing consume the worker
      material handle plus public verifying-share binding. The shared
      `ed25519PresignFinalize` orchestration file no longer references
      `xClientBaseB64u`.
- [x] Removed raw Ed25519 client-base material from
      `RouterAbEd25519NormalSigningReadyState`. The ready state now carries
      Router A/B auth/session/worker identity, expiry, policy scope, and public
      client verifying-share binding; the temporary raw client-base field is
      confined to the HSS material reconstruction adapter and persistence
      cleanup tail.
- [x] Replaced raw Ed25519 client-base arguments in active signing executors
      with a narrow `Ed25519HssMaterialCache` boundary object. `signTransactions`,
      `signDelegate`, and `signNep413` now pass `existingMaterialCache` /
      `repairedMaterialCache` into the HSS material adapter instead of threading
      `existingXClientBaseB64u`, `existingClientVerifyingShareB64u`, or
      `repairedXClientBaseB64u` through orchestration code.
- [x] Added a focused SDK source guard proving active Ed25519 Router A/B final
      signing and Ed25519 presign-pool orchestration do not pass raw
      client-base material into finalizer payloads.
- [x] Define a browser worker material-handle model for Ed25519 HSS signing:
      `Ed25519HssMaterialHandle`, `Ed25519HssMaterialBinding`, and a
      `RouterAbEd25519SigningMaterialReady` state. The binding must cover at
      least wallet id/account id, threshold session id, wallet signing session
      id, signing root id/version, relayer key id, participant ids,
      SigningWorker id, Wallet Session JWT subject/session binding, client
      verifying share public fact, and expiry.
      Completed for Ed25519 active signing with `RouterAbEd25519SigningMaterialReady`;
      the material binding now includes account id, threshold session id, wallet
      signing session id, signing root id/version, expiry, relayer key id,
      participant ids, SigningWorker id, and client verifying-share public fact.
- [x] Move active Ed25519 HSS client-base use behind a WASM worker material
      handle. Active Ed25519 signing executors no longer receive or pass raw
      client-base strings, and the SDK now persists/restores worker-owned
      material handles plus binding digests for sign-ready Ed25519 records.
- [ ] Delete the temporary Ed25519 raw-material reconstruction surface after the
      handle-only request/persistence boundary is complete. The remaining
      `Ed25519HssMaterialCache` reconstruction adapter and raw persistence
      fields are prepared for deletion in Phase 15.10 and removed in Phase 15.12
      only after stale raw development records are rejected, pruned, or
      invalidated at the boundary.
- [x] Replace Ed25519 normal-signing flow inputs in `signTransactions`,
      `signDelegate`, `signNep413`, and `ed25519PresignFinalize` so they accept
      only `RouterAbEd25519SigningMaterialReady`. The final client-share worker
      command should take the handle and request binding, validate both inside
      the worker, and return only the public protocol response needed by Router
      A/B.
- [x] Persist and restore Ed25519 worker-owned material handles for active
      Wallet Session records. Warm-session bootstrap, Email OTP provisioning,
      and active Ed25519 signing flows now write/read `{ materialHandle,
      bindingDigest, publicFacts, sessionIds, walletSessionJwt,
      signingWorkerScope }` for sign-ready state before final signing.
      The Ed25519 material loader now validates already-loaded HSS-client and
      NEAR-signer worker handles before attempting raw-cache or PRF
      reconstruction, so a freshly provisioned signable record can sign from the
      worker-owned handle without another passkey prompt.
      Current progress, June 19, 2026: active NEAR transaction, delegate, and
      NEP-413 final signing now call
      `requireThresholdEd25519HssSigningMaterialHandle` for ordinary signing.
      The reconstruction-capable `ensureThresholdEd25519HssSigningMaterial`
      helper remains only in explicit repair/bootstrap paths until Phase 15.12
      deletes the raw-material compatibility surface.
- [x] Move Ed25519 warm-session reconstruction persistence to worker-owned
      material handles. The warm-session reconstruction path still uses the
      temporary reconstruction adapter, but it now stores only
      `{ ed25519HssMaterialHandle, ed25519HssMaterialBindingDigest,
      clientVerifyingShareB64u }` in the active session record and clears stale
      `xClientBaseB64u` when the handle is persisted.
- [ ] Update passkey registration, login, sealed restore, Email OTP restore, and
      warm-session bootstrap so they persist only `{ materialHandle,
      bindingDigest, publicFacts, sessionIds, walletSessionJwt,
      signingWorkerScope }` for Ed25519 signable state. Remove persisted
      `xClientBaseB64u` from current active records after a request/persistence
      boundary parser can delete or invalidate old development records.
      Current progress, June 18, 2026: the warm-session Ed25519 persistence
      writer no longer accepts or writes `xClientBaseB64u`. Email OTP Ed25519
      reconstruction still uses raw HSS output only inside the provisioning
      worker boundary, stores the worker material handle plus public verifying
      share, and no longer exposes `xClientBaseB64u` in its result type. The
      active NEAR Ed25519 signing state no longer exposes `xClientBaseB64u` or
      a `persistClientBase` callback, and transactions/delegate/NEP-413 repair
      paths now force-refresh `ensureThresholdEd25519HssSigningMaterial` and
      persist the refreshed worker-owned material handle before retrying Router
      A/B signing. The focused Router A/B normal-signing SDK source guard now
      rejects `persistClientBase`, `ed25519HssMaterialCacheFromWalletSessionState`,
      and `repairThresholdEd25519MissingRelayerKey` in active Ed25519 signing
      executors. The raw-cache repair helper file was deleted. The remaining
      work is passkey registration/login, sealed restore, and the remaining
      Email OTP restore compatibility surfaces.
      Current progress, June 19, 2026: Email OTP ECDSA sealed restore now rejects
      signing-root drift before worker rehydrate using the flattened sealed
      ECDSA signing-root metadata, and it no longer hydrates companion Ed25519
      recovery from raw `xClientBaseB64u` / `clientVerifyingShareB64u` material.
      The ECDSA companion seal writer is a no-op until the sealed companion
      schema can carry worker-owned Ed25519 material handles.
      Current progress, June 19, 2026: Email OTP Ed25519 provisioning no longer
      opens `completed.clientOutput.xClientBaseB64u` in TypeScript. It now runs
      the HSS ceremony to a worker-owned material handle through
      `runThresholdEd25519HssCeremonyWithMaterialHandle`; the HSS client worker
      opens the finalized client output, derives the public client verifying
      share, computes the canonical Router A/B material binding digest, stores
      the raw client base internally, and returns only
      `{ materialHandle, bindingDigest, clientVerifyingShareB64u }`. Email OTP
      Ed25519 seal transport also stopped carrying `emailOtpRestore` raw
      material.
      Current progress, June 19, 2026: warm-session Ed25519 reconstruction now
      uses `runThresholdEd25519HssCeremonyWithMaterialHandle` as well. The
      warm-session bootstrap path no longer opens `completed.clientOutput` in
      TypeScript, no longer derives `clientVerifyingShareB64u` from
      `xClientBaseB64u` in orchestration code, and no longer calls the temporary
      raw-cache store helper. It persists only the worker material handle,
      binding digest, and public client verifying share returned by the HSS
      worker.
      Current progress, June 19, 2026: the active NEAR final-signing paths no
      longer use `ensureThresholdEd25519HssSigningMaterial` for ordinary signing.
      They require a preloaded worker-owned handle and only enter the
      reconstruction helper inside the existing repair branch.
- [x] Add a pending/non-signing restore state for any restored Ed25519 material.
      A record becomes sign-ready only after the WASM worker validates the handle
      and binding against the current Router A/B Wallet Session state.
- [x] Define the equivalent ECDSA-HSS worker handle model for registration,
      activation, presign-pool refill, and normal signing. TS may carry public
      identity, activation epoch, key handle, scope digest, and public binding
      facts; client signing material and presignature material stay inside the
      worker.
      Current progress: ECDSA-HSS presign-pool refill now receives a
      worker-owned one-use presignature handle plus public `bigR`; normal
      signing consumes the handle inside the worker; the public presign/signing
      APIs now take a one-shot `RouterAbEcdsaHssClientSigningMaterialSource`
      instead of a raw `clientSigningShare32`. Registration and activation now
      publish signable key refs with `role_local_worker_handle`.
      Remaining raw-material debt is the bootstrap compatibility boundary that
      still carries a ready-state blob long enough to store it in the worker.
- [ ] Move ECDSA-HSS registration/bootstrap finalization and presignature refill
      client-share generation behind signer-core/WASM commands that return
      handles plus public facts. TS bootstrap code must stop assembling
      crypto-adjacent ready state from raw field bags.
      Current progress: presignature refill/signing no longer exposes `kShare32`,
      `sigmaShare32`, or raw presignature bytes to TypeScript pool orchestration.
      Refill opens the ECDSA client signing share only through a one-shot source
      inside the Router A/B ECDSA-HSS pool boundary and zeroizes it after the
      handshake. Registration/bootstrap finalization remains open.
      Current progress, June 18, 2026: active EVM/Tempo secp256k1 signing no
      longer opens `clientSigningShare32` or role-local state blobs in
      `signers/secp256k1.ts`. It now asks a narrow Router A/B ECDSA-HSS material
      source helper for a one-shot signing source, while the active signer
      orchestrates only public facts, Router A/B scope, Wallet Session auth, and
      the digest request. Registration/bootstrap finalization remains open.
      Current progress, June 19, 2026: the generic Router A/B ECDSA-HSS
      presignature pool no longer opens `clientSigningShare32`, maps additive
      shares, initializes EVM presign sessions, steps local presign sessions, or
      aborts local presign sessions directly. It delegates the local presign
      session lifecycle to the typed material-source boundary and orchestrates
      only route calls, public `bigR`, one-use presignature handles, pool keys,
      and signing scope. The remaining ECDSA-HSS raw-share exposure is confined
      to `clientSigningMaterialBoundary.ts`,
      `ecdsaHssClientSigningMaterialSource.ts`, Email OTP worker boundaries, and
      `ecdsaLoginPrefillSigningMaterialSource.ts`. Closing this task fully still
      requires the Email OTP ECDSA path and bootstrap finalization to return
      worker-owned handles plus public facts without exposing raw shares to
      TypeScript.
      Current progress, June 19, 2026: role-local ECDSA-HSS presign refill,
      pool-hit signing, and pool-miss signing now use HSS-client worker commands
      that consume `role_local_worker_session` material handles, run local
      presign init/step/abort inside that worker, store HSS-owned presignature
      handles, and compute signature shares from those HSS-owned handles. The
      generic pool asks the material source to spend the presignature handle, so
      a handle is spent by the same worker family that created it.
      - [x] Move the generic Router A/B ECDSA-HSS presignature pool away from
            raw `clientSigningShare32` opening, additive-share mapping, and local
            EVM presign-session initialization.
      - [x] Move local ECDSA-HSS presign-session `step` and `abort` ownership out
            of the generic pool and into the typed material-source boundary.
      - [x] Replace the warm-login ECDSA-HSS prefill
            `resolveClientSigningShare32` dependency with a typed
            `resolveClientSigningMaterialSource` boundary. The prefill
            orchestrator now receives the same material-source shape as active
            signing and no longer asks broad warm-signing assembly code for a raw
            32-byte share.
      - [x] Move role-local ECDSA-HSS presign init/step/abort and signature-share
            computation behind HSS-client worker commands that consume
            `role_local_worker_session` material handles.
      - [ ] Replace the remaining typed material-source boundary with a
            worker-owned ECDSA-HSS presign refill command for Email OTP ECDSA
            worker sessions, then delete the temporary additive-share bridge.
- [x] Store ECDSA-HSS registration role-local signing material behind the WASM
      worker boundary before publishing signable registration key refs. The
      registration finalizer now returns finalized public facts and a ready-state
      compatibility blob, then the per-chain session bootstrap stores that
      material through `SignerCryptoPort.storeEcdsaRoleLocalSigningMaterial` and
      emits active key refs with `role_local_worker_handle`. The raw
      ready-state blob remains only inside the persisted role-local ready record
      until Phase 15.12 deletes the raw-material compatibility surface.
- [ ] Update sealed-session persistence and recovery records for both curves to
      store worker handles and public bindings only. Any old raw-material
      compatibility parser must live in a named request/persistence boundary
      with an explicit deletion condition, and active signing paths must reject
      records that still require raw material in TS.
      Current progress, June 19, 2026: normalized Email OTP Ed25519 sealed
      recovery records no longer carry `xClientBaseB64u` or
      `clientVerifyingShareB64u`, and type fixtures reject adding those fields
      to the normalized recovery shape. The sealed-store classifier now marks
      Ed25519 sealed records with raw HSS material as `delete_required`, and it
      strips stale raw Ed25519 companion metadata from normalized ECDSA sealed
      records so ECDSA restore cannot rehydrate an Ed25519 companion through
      raw client-base material.
- [x] Add source guards that fail if active SDK orchestration files reference
      raw crypto-secret fields or operations:
      `xClientBaseB64u`, additive shares, signing shares, nonce secrets,
      presignature secrets, PRF-derived material, or signer-core crypto commands
      outside the WASM worker boundary and named persistence/request parsers.
      Completed for active signing orchestration on June 18, 2026:
      `routerAbNormalSigningSdk.guard.unit.test.ts` proves active Ed25519
      signing executors consume worker material handles instead of raw
      client-base material, active ECDSA-HSS signing uses the narrow one-shot
      material source, and ECDSA auth planning no longer branches on raw
      `role_local_ready_state_blob` material. Remaining raw-material references
      are confined to the ECDSA material-state boundary, the temporary
      ECDSA-HSS material-source helper, WASM worker bridges, and named
      persistence/request parsers scheduled for Phase 15.12 deletion.
      Current progress, June 19, 2026: ECDSA-HSS activation now stores the
      role-local ready-state blob in the HSS client worker before publishing a
      signable key ref, and active activation key refs now use
      `role_local_worker_handle` instead of `role_local_ready_state_blob`.
      The bootstrap response still carries a ready-state blob through the
      compatibility boundary long enough to store it in the worker; Phase 15.12
      must delete that raw boundary once signer-core can return only a handle
      plus public facts.
      Current progress, June 19, 2026: the source guard now inspects the active
      final-signing slice in `signTransactions`, `signDelegate`, and `signNep413`.
      It requires `requireThresholdEd25519HssSigningMaterialHandle` and rejects
      ordinary final-signing use of `ensureThresholdEd25519HssSigningMaterial`.
      Current progress, June 19, 2026: the same source-guard suite now confines
      ECDSA-HSS `clientSigningShare32`, additive-share mapping, and
      presign-session init references to exact worker wrappers, the named
      ECDSA-HSS client signing-material boundary, Email OTP worker boundaries,
      warm-login prefill, and type fixtures. Active EVM/Tempo signing files and
      the generic Router A/B ECDSA-HSS presignature pool remain zero-tolerance for
      those raw-share markers.
- [x] Add type fixtures that reject direct construction of sign-ready Ed25519 or
      ECDSA states without a worker material handle, binding digest, public
      facts, Wallet Session JWT, SigningWorker scope, threshold session id, and
      wallet signing session id.
      Completed on June 18, 2026: `routerAbSigningWalletSession.typecheck.ts`
      rejects signable Ed25519 Wallet Session state without a worker material
      handle, binding digest, wallet signing session id, or bearer JWT auth, and
      rejects raw `xClientBaseB64u` on signable state. It also rejects signable
      ECDSA-HSS Wallet Session state without Router A/B normal-signing state,
      runtime-policy scope, bearer JWT auth, or with raw `clientSigningShare32`.
- [ ] Add regression tests:
      fresh registration produces Ed25519 and ECDSA sign-ready handles without
      raw material in TS records; sealed restore publishes sign-ready state only
      after worker validation; stale handle binding fails before signing; warm
      Ed25519 signing does not prompt for passkey or transaction confirmation
      when a valid handle exists; ECDSA pool refill/signing keeps client
      presignature material inside the worker.
      Current progress: `unit/thresholdEd25519.hssMaterialHandle.unit.test.ts`
      proves the Ed25519 signing-material loader uses a loaded worker handle
      before PRF reconstruction.
      Current progress: `unit/addWalletSigner.orchestration.unit.test.ts` now
      uses Router A/B keyset prefetch, Router A/B Ed25519/ECDSA Wallet Session
      JWT fixtures, and ECDSA `role_local_worker_handle` registration material
      storage in the registration/add-signer orchestration coverage.
      Current progress, June 18, 2026: warm-session persistence type fixtures
      reject raw Ed25519 `xClientBaseB64u`, and focused warm-session tests prove
      strict pending/ready behavior still passes after the writer stopped
      accepting raw client-base material.
- [x] Update `docs/refactor-68-wallet-session-v2.md`, `docs/router-a-b-ecdsa.md`,
      and `docs/router-A-B-signer-SPEC.md` so the public architecture states
      that TypeScript holds handles and public facts, while signer-core/WASM owns
      crypto-secret client material.
      Completed on June 18, 2026: all three docs now state that SDK TypeScript
      carries only orchestration state, Wallet Session auth, worker handles,
      binding digests, public facts, and scope metadata, while `signer-core` and
      WASM workers own Ed25519/ECDSA client secret material and binding checks.

Validation checklist:

- [x] `rtk pnpm -C packages/sdk-web type-check`.
      Passed on June 18, 2026 after the first Ed25519 material-handle slice.
      Passed again on June 18, 2026 after the Ed25519 presign-pool handle slice.
      Passed again on June 18, 2026 after adding expiry to the Ed25519 material
      binding.
      Passed again on June 18, 2026 after removing raw client-base material from
      `RouterAbEd25519NormalSigningReadyState`.
      Passed again on June 18, 2026 after replacing active executor raw
      client-base arguments with `Ed25519HssMaterialCache`.
      Passed again on June 18, 2026 after Ed25519 handle persistence,
      `material_pending` readiness, and ECDSA presign-pool handle conversion.
      Passed again on June 18, 2026 after replacing ECDSA presign/signing public
      inputs with `RouterAbEcdsaHssClientSigningMaterialSource`.
      Passed again on June 18, 2026 after adding Ed25519 worker material-handle
      validation before PRF reconstruction.
      Passed again on June 18, 2026 after Ed25519 warm-session reconstruction
      persistence stopped writing raw client-base material.
      Passed again on June 18, 2026 after active ECDSA-HSS secp256k1 signing
      moved raw share opening behind the Router A/B material-source helper.
      Passed again on June 18, 2026 after adding strict Router A/B signable
      Wallet Session type fixtures for Ed25519 and ECDSA-HSS.
      Passed again on June 18, 2026 after moving Email OTP ECDSA readiness
      source classification behind the ECDSA material-state boundary.
      Passed again on June 18, 2026 after ECDSA-HSS registration session
      bootstrap started storing finalized role-local signing material in the HSS
      worker and publishing signable key refs with `role_local_worker_handle`.
      Passed again on June 18, 2026 after repairing registration/add-signer
      Router A/B Wallet Session fixtures and documenting the signer-core/WASM
      material boundary.
      Passed again on June 18, 2026 after the warm-session Ed25519 persistence
      writer stopped accepting raw `xClientBaseB64u`.
      Passed again on June 19, 2026 after warm-session Ed25519 reconstruction
      moved from the raw `runThresholdEd25519HssCeremonyWithSession` output to
      `runThresholdEd25519HssCeremonyWithMaterialHandle`.
      Passed again on June 19, 2026 after active NEAR Ed25519 final signing moved
      to the handle-only loader and ECDSA activation type-check issues were
      verified fixed.
      Passed again on June 19, 2026 after ECDSA-HSS presign refill moved local
      presign-session initialization out of the generic pool and into the named
      client signing-material boundary.
      Passed again on June 19, 2026 after ECDSA-HSS presign refill moved local
      presign-session step/abort ownership out of the generic pool and into the
      named client signing-material boundary.
      Passed again on June 19, 2026 after warm-login ECDSA-HSS prefill stopped
      depending on a raw `resolveClientSigningShare32` callback and now receives
      a typed Router A/B client signing-material source:
      `rtk pnpm -C packages/sdk-web type-check`.
      Passed again on June 19, 2026 after role-local ECDSA-HSS presign refill
      and signature-share computation moved to HSS-client worker commands keyed
      by `role_local_worker_session` material handles:
      `rtk pnpm -C packages/sdk-web type-check`.
- [x] `rtk pnpm -C tests exec tsc --noEmit -p tsconfig.playwright.json`.
      Passed on June 18, 2026 after the first Ed25519 material-handle slice.
      Passed again on June 18, 2026 after the Ed25519 presign-pool handle slice.
      Passed again on June 18, 2026 after adding expiry to the Ed25519 material
      binding.
      Passed again on June 18, 2026 after removing raw client-base material from
      `RouterAbEd25519NormalSigningReadyState`.
      Passed again on June 18, 2026 after replacing active executor raw
      client-base arguments with `Ed25519HssMaterialCache`.
      Passed again on June 18, 2026 after Ed25519 handle persistence,
      `material_pending` readiness, and ECDSA presign-pool handle conversion.
      Passed again on June 18, 2026 after replacing ECDSA presign/signing public
      inputs with `RouterAbEcdsaHssClientSigningMaterialSource`.
      Passed again on June 18, 2026 after adding Ed25519 worker material-handle
      validation before PRF reconstruction.
      Passed again on June 18, 2026 after Ed25519 warm-session reconstruction
      persistence stopped writing raw client-base material.
      Passed again on June 18, 2026 after active ECDSA-HSS secp256k1 signing
      moved raw share opening behind the Router A/B material-source helper.
      Passed again on June 18, 2026 after adding strict Router A/B signable
      Wallet Session type fixtures for Ed25519 and ECDSA-HSS.
      Passed again on June 18, 2026 after moving Email OTP ECDSA readiness
      source classification behind the ECDSA material-state boundary.
      Passed again on June 18, 2026 after ECDSA-HSS registration session
      bootstrap started storing finalized role-local signing material in the HSS
      worker and publishing signable key refs with `role_local_worker_handle`.
      Passed again on June 18, 2026 after repairing registration/add-signer
      Router A/B Wallet Session fixtures and documenting the signer-core/WASM
      material boundary.
      Passed again on June 18, 2026 after the warm-session Ed25519 persistence
      writer stopped accepting raw `xClientBaseB64u`.
      Passed again on June 19, 2026 after warm-session Ed25519 reconstruction
      moved to the worker-owned material-handle HSS ceremony.
      Passed again on June 19, 2026 after active NEAR Ed25519 final signing moved
      to the handle-only loader and the relayer auth-boundary fixture typing was
      narrowed to the actual session adapter parser.
      Passed again on June 19, 2026 after ECDSA-HSS presign refill moved local
      presign-session initialization out of the generic pool and into the named
      client signing-material boundary.
      Passed again on June 19, 2026 after ECDSA-HSS presign refill moved local
      presign-session step/abort ownership out of the generic pool and into the
      named client signing-material boundary.
      Passed again on June 19, 2026 after warm-login ECDSA-HSS prefill stopped
      depending on a raw `resolveClientSigningShare32` callback and now receives
      a typed Router A/B client signing-material source:
      `rtk pnpm -C tests exec tsc --noEmit -p tsconfig.playwright.json`.
      Passed again on June 19, 2026 after role-local ECDSA-HSS presign refill
      and signature-share computation moved to HSS-client worker commands keyed
      by `role_local_worker_session` material handles:
      `rtk pnpm -C tests exec tsc --noEmit -p tsconfig.playwright.json`.
- [x] Focused unit/type tests for Ed25519 and ECDSA worker material-handle state.
      `unit/warmSessionReadModel.unit.test.ts` now covers Ed25519
      `material_pending`, `unit/routerAbEd25519.walletSessionState.unit.test.ts`
      covers strict Ed25519 Wallet Session state, and
      `unit/thresholdEcdsa.presignPoolRefill.unit.test.ts` covers ECDSA
      presign-pool refill/signing with worker-owned handles.
      Passed on June 18, 2026:
      `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/warmSessionReadModel.unit.test.ts unit/routerAbEd25519.walletSessionState.unit.test.ts --reporter=line`.
      Passed again on June 18, 2026 after Ed25519 warm-session reconstruction
      persistence stopped writing raw client-base material:
      `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/routerAbEd25519.walletSessionState.unit.test.ts unit/seamsWeb.loginThresholdWarm.unit.test.ts unit/warmSessionReadModel.unit.test.ts unit/warmSessionStore.transitions.unit.test.ts --reporter=line`.
      Passed on June 18, 2026:
      `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/thresholdEcdsa.presignPoolRefill.unit.test.ts --reporter=line`.
      Passed again on June 18, 2026:
      `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/thresholdEcdsa.presignPoolRefill.unit.test.ts unit/thresholdEcdsa.presignPoolPolicy.unit.test.ts --reporter=line`.
      Passed again on June 18, 2026 after the active secp256k1 signer delegated
      ECDSA-HSS material opening to the Router A/B material-source helper:
      `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/thresholdEcdsa.presignPoolRefill.unit.test.ts --reporter=line`.
      Passed again on June 18, 2026 after ECDSA-HSS registration session
      bootstrap began emitting `role_local_worker_handle` key refs:
      `W3A_TEST_FRONTEND_URL=http://127.0.0.1:5199 rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/walletRegistrationEcdsaRouterAbBootstrap.unit.test.ts --reporter=line`.
      The default unit-test run on port 3600 was blocked by an unrelated
      existing dev server, so this focused run used an alternate local frontend
      port.
      Passed again on June 18, 2026 after the Ed25519 warm-session persistence
      writer stopped accepting raw client-base material:
      `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/seamsWeb.loginThresholdWarm.unit.test.ts unit/warmSessionReadModel.unit.test.ts unit/warmSessionStore.transitions.unit.test.ts --reporter=line`.
      Passed again on June 19, 2026 after warm-session reconstruction stopped
      opening raw HSS client output in TypeScript:
      `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/seamsWeb.loginThresholdWarm.unit.test.ts unit/warmSessionReadModel.unit.test.ts unit/warmSessionStore.transitions.unit.test.ts unit/thresholdEd25519.hssMaterialHandle.unit.test.ts --reporter=line`.
      Passed again on June 19, 2026 after active NEAR Ed25519 final signing moved
      to the handle-only loader:
      `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/thresholdEd25519.hssMaterialHandle.unit.test.ts unit/routerAbEd25519.walletSessionState.unit.test.ts unit/signingCapabilityStrictRecords.unit.test.ts --reporter=line`.
      Passed again on June 19, 2026 after the generic ECDSA-HSS presign pool
      stopped opening client signing shares:
      `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/thresholdEcdsa.presignPoolRefill.unit.test.ts unit/thresholdEcdsa.presignPoolPolicy.unit.test.ts --reporter=line`.
      Passed again on June 19, 2026 after the generic ECDSA-HSS presign pool
      delegated local presign-session step/abort to the typed material-source
      boundary:
      `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/thresholdEcdsa.presignPoolRefill.unit.test.ts unit/thresholdEcdsa.presignPoolPolicy.unit.test.ts --reporter=line`.
      Passed again on June 19, 2026 after warm-login ECDSA-HSS prefill started
      constructing the same typed client signing-material source used by active
      Router A/B signing:
      `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/thresholdEcdsa.presignPoolRefill.unit.test.ts unit/thresholdEcdsa.presignPoolPolicy.unit.test.ts --reporter=line`.
      Passed again on June 19, 2026 after role-local ECDSA-HSS presignature
      handles became worker-family-owned and signature-share computation moved
      through the material-source boundary:
      `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/thresholdEcdsa.presignPoolRefill.unit.test.ts unit/thresholdEcdsa.presignPoolPolicy.unit.test.ts --reporter=line`.
- [x] Focused source guards proving active TS signing orchestration has no raw
      crypto-secret material references.
      `unit/routerAbNormalSigningSdk.guard.unit.test.ts` now checks that active
      Ed25519 Router A/B final signing and presign-pool orchestration consume
      worker material handles instead of `xClientBaseB64u`.
      `unit/thresholdEd25519.presignPool.unit.test.ts` passed after the
      presign-pool handle slice.
      The guard now also rejects `existingXClientBaseB64u`,
      `existingClientVerifyingShareB64u`, and `repairedXClientBaseB64u` in
      active Ed25519 signing executors.
      The guard now also checks that ECDSA-HSS Router A/B public presign/signing
      APIs accept the one-shot material source and consume worker-owned
      presignature handles. Passed on June 18, 2026:
      `rtk pnpm -C tests exec playwright test -c playwright.source.config.ts unit/routerAbNormalSigningSdk.guard.unit.test.ts --reporter=line`.
      Passed again on June 18, 2026 after moving raw ECDSA share opening out of
      `signers/secp256k1.ts` and into the narrow Router A/B ECDSA-HSS material
      source helper:
      `rtk pnpm -C tests exec playwright test -c playwright.source.config.ts unit/routerAbNormalSigningSdk.guard.unit.test.ts --reporter=line`.
      Passed again on June 18, 2026 after adding strict Router A/B signable
      Wallet Session type fixtures:
      `rtk pnpm -C tests exec playwright test -c playwright.source.config.ts unit/routerAbNormalSigningSdk.guard.unit.test.ts --reporter=line`.
      Passed again on June 18, 2026 after guarding ECDSA auth planning against
      raw role-local material branches:
      `rtk pnpm -C tests exec playwright test -c playwright.source.config.ts unit/routerAbNormalSigningSdk.guard.unit.test.ts --reporter=line`.
      Passed again on June 18, 2026 after ECDSA-HSS registration session
      bootstrap began emitting worker-handle-backed signable key refs:
      `rtk pnpm -C tests exec playwright test -c playwright.source.config.ts unit/routerAbNormalSigningSdk.guard.unit.test.ts --reporter=line`.
      Passed again on June 18, 2026 after removing the duplicate `site:router`
      local mode and narrowing Ed25519 warm-session persistence away from raw
      client-base material:
      `rtk pnpm -C tests exec playwright test -c playwright.source.config.ts unit/routerAbNormalSigningSdk.guard.unit.test.ts --reporter=line`.
      Passed again on June 19, 2026 after warm-session reconstruction switched
      to the worker-owned material-handle HSS ceremony:
      `rtk pnpm -C tests exec playwright test -c playwright.source.config.ts unit/routerAbNormalSigningSdk.guard.unit.test.ts --reporter=line`.
      Passed again on June 19, 2026 after Email OTP Ed25519 sealed recovery
      records stopped normalizing raw HSS material:
      `rtk pnpm -C tests exec playwright test -c playwright.source.config.ts unit/routerAbNormalSigningSdk.guard.unit.test.ts --reporter=line`.
      Passed again on June 19, 2026 after the guard started rejecting ordinary
      final-signing use of `ensureThresholdEd25519HssSigningMaterial` in active
      NEAR Ed25519 signing files:
      `rtk pnpm -C tests exec playwright test -c playwright.source.config.ts unit/routerAbNormalSigningSdk.guard.unit.test.ts --reporter=line`.
      Passed again on June 19, 2026 after the guard began confining ECDSA-HSS
      raw client signing-share markers to exact temporary/worker boundary files
      and rejected those markers in the generic ECDSA-HSS presign pool:
      `rtk pnpm -C tests exec playwright test -c playwright.source.config.ts unit/routerAbNormalSigningSdk.guard.unit.test.ts --reporter=line`.
      Passed again on June 19, 2026 after the guard also rejected local ECDSA-HSS
      presign-session step/abort WASM calls in the generic ECDSA-HSS presign pool:
      `rtk pnpm -C tests exec playwright test -c playwright.source.config.ts unit/routerAbNormalSigningSdk.guard.unit.test.ts --reporter=line`.
      Passed again on June 19, 2026 after the guard started rejecting
      `resolveClientSigningShare32` in warm-login ECDSA-HSS prefill and broad
      warm-signing assembly code:
      `rtk pnpm -C tests exec playwright test -c playwright.source.config.ts unit/routerAbNormalSigningSdk.guard.unit.test.ts --reporter=line`.
      Passed again on June 19, 2026 after the guard started requiring role-local
      ECDSA-HSS presign/sign-share paths to use HSS-client worker material-handle
      commands:
      `rtk pnpm -C tests exec playwright test -c playwright.source.config.ts unit/routerAbNormalSigningSdk.guard.unit.test.ts --reporter=line`.
- [x] Focused Ed25519 handle-first regression test.
      `unit/thresholdEd25519.hssMaterialHandle.unit.test.ts` proves the loader
      validates loaded HSS-client and NEAR-signer worker handles before falling
      back to PRF reconstruction. Passed on June 18, 2026:
      `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/thresholdEd25519.hssMaterialHandle.unit.test.ts --reporter=line`.
      Passed again on June 19, 2026 after the stale NEAR-signer duplicate
      validation expectation was removed and the active HSS-client material
      handle boundary stayed covered.
      Passed again on June 19, 2026 as part of the focused warm-session
      material-handle regression run.
- [ ] Local browser registration-to-sign test passes for Ed25519 without a
      second transaction-confirmation prompt or Touch ID prompt.
- [ ] Local browser registration-to-sign test passes for ECDSA-HSS Tempo and EVM
      without raw client presignature material crossing TypeScript orchestration.
- [ ] `rtk pnpm router:smoke` and `rtk pnpm router:smoke:bundled` still pass.

## Phase 15.10: Prepare Raw-Material Deletion Gates

Start this phase only after Phase 15.9 has landed for the specific curve/surface
being prepared. Do not delete raw-material fields, parsers, or helpers in this
phase. The purpose is to make the later destructive deletion safe by proving old
raw-material records are terminal at the boundary and cannot become signable.

Boundary code may recognize old raw-material development records only to reject,
prune, or invalidate them. It must not hydrate old raw fields into current
signable state.

Surface eligibility checklist:

- [ ] The current writer stores only worker handles, binding digests, public
      facts, session ids, Wallet Session JWTs, and SigningWorker scope.
      Current progress, June 18, 2026: the Ed25519 warm-session capability
      writer no longer accepts or persists raw `xClientBaseB64u`; it stores the
      worker material handle, material binding digest, public client verifying
      share, session ids, Wallet Session JWT, and Router A/B SigningWorker
      scope. Other Ed25519/ECDSA writers remain to be audited before this
      surface-wide gate is complete.
      Current progress, June 19, 2026: Email OTP Ed25519 reconstruction
      provisioning stores the same handle/digest/public-facts shape after the
      worker consumes HSS ceremony output internally, and UI-confirm seal
      transport now rejects `emailOtpRestore` raw material for Email OTP
      Ed25519.
      Current progress, June 19, 2026: warm-session Ed25519 reconstruction now
      stores the same worker-owned material handle shape directly from the
      worker-owned ceremony result; the bootstrap path no longer handles raw
      `xClientBaseB64u`.
      Current progress, June 19, 2026: ECDSA-HSS activation writers now store
      role-local signing material in the HSS client worker and publish
      `role_local_worker_handle` key refs for signable activation records. The
      ECDSA bootstrap compatibility boundary still carries the ready-state blob
      before worker storage, so the surface-wide gate remains open.
- [ ] The Phase 15.11 strict reader/parser exists for this surface and parses
      records into `signable`, `pending_restore`, `pending_material`, `invalid`,
      or `non_signing` states. Phase 15.10 only verifies the gate for the
      surface being prepared; it must not implement a second parser.
- [ ] Restore/bootstrap paths cannot select a raw-material record as ready.
- [ ] Stale raw-material records are rejected, pruned, or invalidated at the
      request/persistence boundary with a focused regression test.
      Current progress, June 18, 2026: selected Ed25519 signing-capability
      reads now reject stale raw-material-only records before final signing.
      `classifyRouterAbEd25519PersistedSigningRecord` returns `invalid` with
      `raw_material_without_handle` when a record still carries
      `xClientBaseB64u` but lacks a worker-owned `ed25519HssMaterialHandle`.
      Current progress, June 18, 2026: passkey Ed25519 sealed-store and
      sealed-recovery boundaries now reject records that carry raw
      `xClientBaseB64u` / `clientVerifyingShareB64u` material instead of
      hydrating them into signable or restorable passkey state. Ed25519
      warm-session reconstruction now persists a worker-owned material handle
      and clears stale raw client-base material. Remaining work: apply the same
      terminal boundary behavior to bootstrap and ECDSA-HSS surfaces before
      deleting fields.
      Current progress, June 19, 2026: Email OTP ECDSA sealed restore rejects
      raw companion Ed25519 recovery before worker rehydrate, and best-effort
      ECDSA companion seal updates no longer write raw Ed25519 restore material
      into ECDSA sealed records.
      Current progress, June 19, 2026: Email OTP Ed25519 provisioning no longer
      sends raw `xClientBaseB64u` through TypeScript or seal transport; the HSS
      client worker stores the material behind the canonical Router A/B handle.
      Current progress, June 19, 2026: Email OTP Ed25519 sealed recovery records
      with raw `xClientBaseB64u` / `clientVerifyingShareB64u` are rejected at
      the recovery normalizer and classified as `delete_required` by the sealed
      store. ECDSA sealed records keep their ECDSA restore path, but stale raw
      Ed25519 companion metadata is dropped from the normalized record.
- [x] Add and run the current Ed25519 local dev-store cleanup path that deletes
      stale raw-material signable records for development accounts. This path is
      a current-schema cleanup: ordinary account, threshold-session, lane, and
      list reads prune Ed25519 records that still carry `xClientBaseB64u` without
      a worker-owned `ed25519HssMaterialHandle`, and never hydrate the raw
      material into active signing state.
- [ ] Add and run equivalent cleanup paths for remaining raw-material
      persistence surfaces, including ECDSA-HSS and any durable IndexedDB records
      that Phase 15.11 still classifies before Phase 15.12 deletion.
- [x] Active signing code has a source guard proving it does not depend on raw
      material helper or field names for the prepared surface.
      Current progress, June 18, 2026: the Router A/B normal-signing SDK guard
      rejects `persistClientBase`, `ed25519HssMaterialCacheFromWalletSessionState`,
      and `repairThresholdEd25519MissingRelayerKey` in active Ed25519 signing
      executors, and requires missing-key repair retries to force-refresh and
      persist worker-owned signing material before rebuilding the Router A/B
      request payload.
      Current progress, June 19, 2026: the guard now rejects ordinary final
      signing use of `ensureThresholdEd25519HssSigningMaterial` in
      `signTransactions`, `signDelegate`, and `signNep413`; that reconstruction
      helper remains allowed only in repair/bootstrap paths.

Validation checklist:

- [ ] Focused tests prove stale raw-material records are rejected, pruned, or
      invalidated before final signing for each prepared surface.
      Current progress, June 18, 2026:
      `unit/signingCapabilityStrictRecords.unit.test.ts` covers the selected
      Ed25519 final-signing boundary rejection for stale raw-material-only
      records.
      `unit/routerAbEd25519.walletSessionState.unit.test.ts` now proves
      persisting an Ed25519 material handle clears stale `xClientBaseB64u`.
      The same focused file also proves stale Ed25519 raw-material records are
      pruned from active account, threshold-session, lane, and list reads.
      `unit/sealedRecovery.methodAdapters.unit.test.ts` now proves Email OTP
      Ed25519 sealed recovery records with raw client-base metadata are
      rejected at the normalized recovery boundary. `unit/sealedSessionStore.unit.test.ts`
      passed with the sealed-store classifier deleting Ed25519 raw-material
      sealed records and dropping stale raw Ed25519 companion metadata from
      normalized ECDSA records.
- [x] `rtk pnpm -C packages/sdk-web type-check`.
      Passed on June 18, 2026 after selected Ed25519/ECDSA signing-capability
      reads were gated by the strict Router A/B Wallet Session record parsers.
      Passed again on June 18, 2026 after Ed25519 warm-session reconstruction
      persistence stopped writing raw client-base material.
      Passed again on June 18, 2026 after the Ed25519 active dev-store pruning
      path rejected stale raw-material records at account/session/lane reads.
      Passed again on June 18, 2026 after the Ed25519 warm-session persistence
      writer stopped accepting raw `xClientBaseB64u`.
      Passed again on June 18, 2026 after active Ed25519 signing state stopped
      exposing `xClientBaseB64u` / `persistClientBase` and repair retries moved
      through force-refreshed worker-owned material handles.
      Passed again on June 19, 2026 after Email OTP Ed25519 provisioning moved
      finalized HSS client-output opening and material storage into the HSS
      client worker.
      Passed again on June 19, 2026 after normalized Email OTP Ed25519 sealed
      recovery stopped carrying raw HSS material.
      Passed again on June 19, 2026 after ECDSA-HSS activation started
      publishing `role_local_worker_handle` key refs.
- [x] `rtk pnpm -C tests exec tsc --noEmit -p tsconfig.playwright.json`.
      Passed on June 18, 2026 after the Ed25519 worker material-handle
      validation slice.
      Passed again on June 18, 2026 after Ed25519 warm-session reconstruction
      persistence stopped writing raw client-base material.
      Passed again on June 18, 2026 after the Ed25519 active dev-store pruning
      path rejected stale raw-material records at account/session/lane reads.
      Passed again on June 18, 2026 after active Ed25519 signing state stopped
      exposing `xClientBaseB64u` / `persistClientBase` and repair retries moved
      through force-refreshed worker-owned material handles.
      Passed again on June 19, 2026 after Email OTP Ed25519 provisioning moved
      finalized HSS client-output opening and material storage into the HSS
      client worker.
      Passed again on June 19, 2026 after normalized Email OTP Ed25519 sealed
      recovery records rejected raw HSS material fields.
- [ ] Fresh registration-to-sign and wallet-unlock-to-sign browser tests pass
      for Ed25519, ECDSA-HSS Tempo, and EVM with worker handles only.
- [ ] `rtk pnpm router:smoke` and `rtk pnpm router:smoke:bundled` pass.

## Phase 15.11: Strict Signable State And Lane Diagnostics

The June 18, 2026 diff audit found that the Router A/B refactor has the right
target architecture, but several implementation seams became too broad while
legacy paths were being deleted. This first rot-hardening phase fixes the
persisted-state and lane-readiness problems that produced "almost ready"
sessions. It must preserve Router A/B-only signing, Wallet Session JWT-only
signing auth, one-use SigningWorker nonce/presignature state, canonical
request/scope binding, and signer-core/WASM ownership of crypto-secret client
material.

General implementation guidance:

- Work from the boundary inward. Start by adding boundary parsers/builders for
      route responses, decoded JWTs, IndexedDB records, sealed-session payloads,
      and worker responses. Convert raw shapes into precise internal states once,
      then make core signing and readiness functions accept only those states.
- Make invalid signable state unrepresentable before deleting more code. Add the
      strict discriminated unions and type fixtures first, then update callers,
      then delete old optional-field helpers. This keeps regressions visible at
      compile time instead of surfacing during wallet unlock or final signing.
- Keep crypto-secret material movement separate from state-shape cleanup. Phase
      15.9 moves active Ed25519/ECDSA material behind worker handles, Phase
      15.10 prepares stale-record invalidation, and Phase 15.12 deletes raw
      material surfaces after strict state exists. Phase 15.11 should focus on
      strict persisted state, ready-state construction, and lane diagnostics.
      Later rot-hardening work is split into Phases 15.13 through 15.16.
- Preserve every old security invariant before deleting its old test. Build the
      deleted-test replacement map early, land Router A/B coverage for each
      invariant, and delete old tests only after the replacement is named in this
      plan.
- Refactor by vertical slices. For example: first Ed25519 persisted-state and
      lane diagnostics, then ECDSA-HSS persisted-state and lane diagnostics, then
      canonical scope digests, then server helper narrowing, then Rust module
      splitting. Each slice should have focused type-check/source-guard/test
      evidence.
- Keep compatibility isolated and terminal. A parser may reject or invalidate an
      old development record at a persistence/request boundary. It must not
      hydrate that record into current signable state or fallback to old
      threshold-session routes.
- Prefer shared canonical builders over duplicated validation. If a value is
      security-significant across SDK, server, local Router, and Cloudflare, put
      its parser or digest builder in `shared-ts`, `router-ab-core`, or
      `signer-core` as appropriate and use the same helper everywhere.
- Treat diagnostics as observability, not control flow. Availability and unlock
      paths should expose stable invalid-lane reasons, but signing decisions must
      depend on strict internal state, not on warning strings or best-effort
      diagnostics.
- Split monoliths only after the behavior is pinned by tests. Move code into
      modules with route constants, parsers, and security checks preserved
      exactly; keep any behavior change in a separate commit from file movement.
- Keep commits small and reviewable. Separate SDK state hardening, server JWT
      boundary hardening, private service HTTP consolidation, Rust module
      splitting, generated-artifact cleanup, and unrelated demo/package/docs
      cleanup.

Implementation checklist:

- [ ] Replace persisted signing-session records that can describe "almost ready"
      state with strict internal discriminated unions. Signable Ed25519 and
      ECDSA-HSS records must require Wallet Session JWT auth, threshold session
      id, wallet signing session id, runtime-policy scope, SigningWorker scope,
      expiry/quota, and the curve-specific Router A/B normal-signing state or
      worker material handle. Raw IndexedDB, sealed-session, route-response, and
      request/persistence compatibility shapes must be parsed once at the
      boundary into `signable`, `pending_restore`, `invalid`, or `non_signing`
      states.
      Current progress: Ed25519 final NEAR signing ready state now requires
      `ed25519HssMaterialHandle` and `ed25519HssMaterialBindingDigest`.
      ECDSA-HSS final EVM signing now converts role-local material into a local
      handle-only signable union after loading it into the HSS worker. The
      selected signing-capability reader now rejects Ed25519/ECDSA records that
      fail the strict Router A/B Wallet Session parser before final signing.
      Current progress, June 18, 2026: `routerAbSigningWalletSession.ts` now
      classifies persisted Ed25519 and ECDSA-HSS records into explicit
      `signable`, `pending_material`, `invalid`, and `non_signing` states, and
      selected signing capability reads consume those classifier branches. The
      warm-session read model and envelope invariant checker now derive
      `ready` only from the `signable` classifier branch. The remaining work is
      to replace the broad persisted record shapes at raw IndexedDB/sealed
      parsing boundaries with explicit `signable`, `pending_restore`,
      `pending_material`, `invalid`, and `non_signing` parser outputs.
      Current progress, June 18, 2026: `routerAbSigningWalletSession.typecheck.ts`
      now pins the strict signable Wallet Session state shape for both curves at
      compile time. It rejects Ed25519 states missing worker material handle,
      material binding digest, wallet signing session id, or bearer JWT auth,
      and rejects ECDSA-HSS states missing Router A/B normal-signing state,
      runtime-policy scope, or bearer JWT auth.
- [ ] Make malformed persisted lanes explicit. Availability readers must stop
      silently skipping runtime Ed25519/ECDSA records that are missing Router A/B
      state, Wallet Session JWT auth, runtime-policy scope, SigningWorker scope,
      or budget identity. Return an invalid-lane diagnostic with a stable reason,
      and make unlock-to-sign tests fail before final signing when a lane cannot
      build the strict internal state.
      Current progress: available-lane reads now return
      `diagnostics.invalidLanes` with stable runtime-record reasons for missing
      Router A/B state, missing threshold session ids, missing wallet signing
      session ids, unsupported ECDSA chain targets, and invalid ECDSA public
      facts. Ed25519 and ECDSA warm-session read-model tests now prove records
      missing Router A/B state remain non-ready before final signing. Remaining
      work is to extend the same explicit diagnostics to raw IndexedDB/sealed
      record parser branches and the full unlock-to-sign path.
- [x] Make ECDSA warm capability readiness JWT-only. `deriveEcdsaCapabilityState`
      and `persistedWarmSessionRecordRequiresWalletSessionJwt` must require
      bearer Wallet Session JWT auth for every ECDSA signing-capable record,
      regardless of `thresholdSessionKind`. Cookie-backed ECDSA records should
      normalize to `invalid` or `auth_missing`, never `ready`. Add focused tests
      proving a cookie ECDSA record with warm PRF material cannot become a ready
      Router A/B signing capability.
      Fix guidance: replace the capability-specific conditional in
      `persistedWarmSessionRecordRequiresWalletSessionJwt` with an unconditional
      JWT requirement for both Ed25519 and ECDSA signable records. Then make
      `resolveEcdsaAuthMaterial` return a discriminated failure for
      `cookie_session` / `missing_wallet_session_jwt`, and teach
      `deriveEcdsaCapabilityState` plus `assertWarmSessionEnvelopeInvariant` to
      map that failure to `auth_missing` or `invalid`. Avoid reading
      `thresholdSessionKind` in core readiness logic except to reject old
      records at the persistence boundary.
      Completed on June 18, 2026: warm-session records now require Wallet
      Session JWT auth unconditionally, ECDSA auth resolution returns explicit
      `cookie_session` and `missing_wallet_session_jwt` failure branches, and
      ECDSA readiness/invariant derivation maps both branches to `auth_missing`
      before a warm PRF claim can advertise the lane as ready.
- [x] Make Router A/B ECDSA-HSS normal-signing config mandatory at signable
      activation boundaries. `activateEcdsaSession` must fail closed when it is
      asked to create or refresh a signing-capable ECDSA session and
      `routerAbNormalSigning.mode` is not `enabled`. It must not persist a live
      ECDSA record without `routerAbEcdsaHssNormalSigning`, SigningWorker scope,
      Wallet Session JWT auth, and runtime-policy scope. Keep any disabled-mode
      behavior only for explicitly non-signing local/test boundaries with source
      guards.
      Fix guidance: split ECDSA activation into explicit signable and
      non-signing/bootstrap-only branches. The signable branch should accept
      `RouterAbNormalSigningConfig & { mode: "enabled" }` or a prevalidated
      `RouterAbEcdsaHssNormalSigningStateV1`; the disabled branch should not be
      able to call the persisted signable-record builder. Move the existing
      `case "disabled": return undefined` behavior behind a named
      non-signing/test helper, and add a source guard so active EVM/Tempo
      activation cannot import it.
      Completed on June 18, 2026: `activateEcdsaSession` now rejects disabled
      Router A/B normal-signing config before bootstrap, session-id allocation,
      worker use, or persistence; the Router A/B ECDSA-HSS normal-signing state
      builder returns a required state; and the persisted ECDSA key ref stores
      that state unconditionally for signable activation.
      Current progress, June 19, 2026: signable activation now stores
      role-local signing material in the HSS client worker and publishes
      `role_local_worker_handle` key refs. The focused activation test covers
      the worker-store call and key-ref material kind.
- [x] Tighten Ed25519 passkey provisioning so it cannot persist a signable JWT
      session without Router A/B signing material. `provisionThresholdEd25519Session`
      must either produce a strict Router A/B signable record with
      `routerAbNormalSigning`, runtime-policy scope, signing root, material
      handle, binding digest, client verifying share, Wallet Session JWT, and
      wallet signing-session id, or persist a non-signing/pending-material state
      that transaction, NEP-413, and delegate signing cannot select as ready.
      Fix guidance: introduce a boundary builder such as
      `buildRouterAbEd25519SignableRecord` that takes the mint response, HSS
      material-handle result, runtime policy, and Wallet Session JWT and returns
      only a strict signable record. If passkey provisioning has only PRF material
      and no material handle yet, persist a `pending_material` record through a
      different builder and keep it out of `thresholdEd25519LaneCandidateFromSessionRecord`
      / available-lane ready selection. Final signing should consume only the
      strict builder output.
      Completed on June 18, 2026: Ed25519 passkey provisioning records that
      carry Wallet Session JWT auth and Router A/B state but do not yet carry a
      worker-owned HSS material handle now remain `material_pending` in the
      warm-session read model, and selected final signing rejects them with the
      strict Router A/B signable-record parser before any signing attempt.
- [ ] Tighten persisted-record parsers for current signable records. ECDSA
      normalization must reject or classify as non-signing any current record
      missing `routerAbEcdsaHssNormalSigning`. Ed25519 normalization must reject
      or classify as pending/non-signing records missing signing root, HSS
      material handle, material binding digest, client verifying share,
      runtime-policy scope, Wallet Session JWT, wallet signing-session id, or
      `routerAbNormalSigning`. Keep old-record handling only as a boundary
      rejection/pruning path.
      Fix guidance: stop returning one broad `ThresholdEd25519SessionRecord` /
      `ThresholdEcdsaSessionRecord` shape from raw persistence parsing. Parse raw
      records into a union with at least `signable`, `pending_restore`,
      `pending_material`, `invalid`, and `non_signing` branches. Provide narrow
      accessors like `requireSignableRouterAbEd25519Record` and
      `requireSignableRouterAbEcdsaHssRecord`; selection, budget, pool-fill, and
      signing code should accept those narrow types. Old records should be
      pruned or reported as invalid lanes during read, not upgraded by optional
      field checks in core logic.
      Current progress, June 18, 2026: selected signing capability, warm-session
      read-state derivation, and warm-session envelope invariants now use the
      Router A/B persisted-record classifier. This blocks "almost ready" records
      from becoming sign-ready, but the lower raw persistence parsers still need
      the full union rewrite before this task is complete.
      Current progress, June 18, 2026: the Ed25519 classifier now distinguishes
      stale raw-material-only development records from ordinary
      `pending_material` records. Records with `xClientBaseB64u` but no
      worker-owned HSS material handle classify as `invalid` with
      `raw_material_without_handle`, and selected final-signing capability reads
      fail before any signing attempt.
      Current progress, June 18, 2026: Ed25519 warm-session reconstruction now
      persists strict handle-backed material state and clears stale
      `xClientBaseB64u`, so a reconstructed record cannot re-enter final signing
      through the raw client-base field.
- [x] Make stale Ed25519 raw-material active-store records terminal at the
      persistence boundary. Account, threshold-session, lane, and list read paths
      now prune records that still carry `xClientBaseB64u` without an
      `ed25519HssMaterialHandle`, so old development state cannot survive lane
      selection by moving between store indexes.
- [x] Make stale Ed25519 raw-material records terminal in warm-session readiness
      and auth planning. A record with raw `xClientBaseB64u` but no worker-owned
      HSS material handle now derives `invalid` instead of `material_pending`,
      and NEAR signing auth planning fails before restore, status probing, or
      step-up selection. Deleted stale NEAR session-selection tests that treated
      raw cached client-base material or status-only sealed restore as a valid
      warm signing session.
- [x] Repair stale registration/add-signer orchestration fixtures. The
      `addWalletSigner.orchestration.unit.test.ts` fixture now enables Router
      A/B normal signing, serves the Router A/B public keyset prefetch route,
      mints Router A/B Ed25519/ECDSA Wallet Session JWTs, and stores
      registration ECDSA role-local material through a worker-owned handle
      fixture. This keeps the test aligned with the Router A/B-only product
      state instead of the old disabled-normal-signing fixture path.
	- [x] Fix stale available-lane durable fixture coverage in
	      `tests/unit/availableSigningLanes.ed25519Duplicates.unit.test.ts`. The
	      suite still contains sealed-record fixture assumptions from before the
	      current Router A/B sealed restore contract, which causes broad runs to fail
      with `missing_restore_metadata` even though the focused runtime diagnostic
      test passes. Keep only current availability-normalization assertions:
      update the remaining Ed25519 durable fixture to the current sealed restore
      contract, and delete durable ECDSA/readback assertions that belong in
      sealed-store/parser tests or only preserve obsolete raw-material and
      pre-Router A/B restore behavior. The full file must pass before Phase 15.11
      is marked complete.
      Completed on June 18, 2026: stale durable ECDSA sealed-readback assertions
      and the obsolete passkey Ed25519 no-client-base durable assertion were
	      deleted from this availability-normalization suite; the remaining tests
	      cover current Ed25519 durable duplicate normalization plus runtime Router
	      A/B Ed25519/ECDSA availability and diagnostics.
	- [x] Make passkey Ed25519 sealed restore records terminal when they contain raw
	      client-base material. `sealedSessionStore.ts` now classifies passkey
	      Ed25519 sealed records with `xClientBaseB64u` as `delete_required`, and
	      `recoveryRecord.ts` rejects passkey Ed25519 sealed recovery records with
	      either `xClientBaseB64u` or `clientVerifyingShareB64u`. Email OTP Ed25519
	      recovery keeps its explicit encrypted-restorable raw-material fixture
	      until the Email OTP worker-handle replacement lands. The passkey
	      Ed25519 sealed-restore publisher no longer writes unreachable
	      `xClientBaseB64u` / `clientVerifyingShareB64u` fields after worker
	      rehydrate succeeds.

Validation checklist:

	- [x] `rtk pnpm -C packages/sdk-web type-check`.
	      Passed on June 18, 2026 after the Ed25519 final ready-state material
	      handle slice and ECDSA-HSS final signing handle-only local union slice.
      Passed again on June 18, 2026 after ECDSA warm-capability JWT-only
      readiness hardening.
      Passed again on June 18, 2026 after ECDSA activation fail-closed
      hardening.
	      Passed again on June 18, 2026 after selected Ed25519/ECDSA
	      signing-capability reads were gated by the strict Router A/B Wallet
	      Session record parsers.
	      Passed again on June 18, 2026 after passkey Ed25519 sealed-store and
	      sealed-recovery boundaries rejected raw client-base material.
	      Passed again on June 18, 2026 after Ed25519 warm-session reconstruction
	      persistence moved to material handles.
      Passed again on June 18, 2026 after Ed25519 active-store reads pruned stale
      raw-material records before lane selection.
      Passed again on June 18, 2026 after the Ed25519 warm-session persistence
      writer stopped accepting raw `xClientBaseB64u`.
      Passed again on June 19, 2026 after ECDSA-HSS activation started storing
      role-local material through worker handles.
	- [x] `rtk pnpm -C tests exec tsc --noEmit -p tsconfig.playwright.json`.
	      Passed on June 18, 2026 after the Ed25519 worker material-handle
	      validation slice.
      Passed again on June 18, 2026 after selected Ed25519/ECDSA
      signing-capability reads were gated by the strict Router A/B Wallet
      Session record parsers.
      Passed again on June 18, 2026 after the focused strict selected-capability
      fixture covered Ed25519 and ECDSA invalid persisted signable records.
      Passed again on June 18, 2026 after the availability diagnostics suite
      added the symmetric ECDSA missing Router A/B state assertion.
      Passed again on June 18, 2026 after the Ed25519 passkey provisioning
      pending-material regression test.
	      Passed again on June 18, 2026 after the Router A/B persisted-record
	      classifier was wired into selected capability reads and warm-session
	      readiness.
	      Passed again on June 18, 2026 after passkey Ed25519 sealed-store and
	      sealed-recovery boundaries rejected raw client-base material.
	      Passed again on June 18, 2026 after Ed25519 warm-session reconstruction
	      persistence moved to material handles.
      Passed again on June 18, 2026 after Ed25519 active-store reads pruned stale
      raw-material records before lane selection.
      Passed again on June 19, 2026 after ECDSA-HSS activation started storing
      role-local material through worker handles.
- [ ] Focused unlock-to-sign regression tests for fresh and restored Ed25519,
      ECDSA-HSS Tempo, and EVM sessions.
- [x] Focused warm-capability tests proving ECDSA cookie records and records
      missing Wallet Session JWT auth cannot produce `state: "ready"`.
      Passed on June 18, 2026:
      `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/warmSessionReadModel.unit.test.ts --reporter=line`.
      Related invariant/provisioning/transition tests passed:
      `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/warmSessionStore.invariants.unit.test.ts unit/warmSessionTransitions.unit.test.ts unit/warmSessionEcdsaProvisioning.unit.test.ts --reporter=line`.
- [x] Focused warm read-model and invariant tests proving Ed25519/ECDSA records
      missing Router A/B state cannot become `ready`.
      Passed on June 18, 2026:
      `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/warmSessionReadModel.unit.test.ts --reporter=line`.
      Related transition coverage passed:
      `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/warmSessionStore.transitions.unit.test.ts --reporter=line`.
- [x] Focused ECDSA activation tests proving disabled Router A/B normal-signing
      config cannot create a signing-capable ECDSA session record.
      Passed on June 18, 2026:
      `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/thresholdEcdsa.authorizationBootstrapVerifier.unit.test.ts --reporter=line`.
      Passed again on June 19, 2026 after adding the signable activation
      regression proving activation stores role-local material in the HSS client
      worker and publishes a `role_local_worker_handle` key ref.
- [x] Focused Ed25519 passkey provisioning tests proving a successful passkey
      provision either creates strict Router A/B signable material or a
      non-signing pending state that cannot be selected for final signing.
      Passed on June 18, 2026:
      `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/warmSessionStore.transitions.unit.test.ts --reporter=line`.
      The focused regression covers a successful Ed25519 provision that persists
      Wallet Session JWT auth and Router A/B state without a worker-owned
      material handle; the warm-session state remains `material_pending`, and
      selected final signing rejects the record as `missing_material_handle`.
      Passed again on June 18, 2026 after stale raw-material-only Ed25519
      records became terminal `invalid` warm-session state:
      `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/warmSessionReadModel.unit.test.ts unit/signingCapabilityStrictRecords.unit.test.ts unit/warmSessionStore.transitions.unit.test.ts --reporter=line`.
- [x] Focused persisted-record parser tests proving current Ed25519/ECDSA
      signable records without Router A/B state/material are rejected or
      surfaced as invalid/pending records before final signing.
      Passed on June 18, 2026:
      `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/signingCapabilityStrictRecords.unit.test.ts --reporter=line`.
      The focused fixture proves selected Ed25519 signing capability rejects
      records missing worker-owned material handles and selected ECDSA signing
      capability rejects records missing Router A/B ECDSA-HSS normal-signing
      state before final signing.
      Passed again on June 18, 2026 after adding
      `raw_material_without_handle` as a distinct invalid Ed25519 parser reason.
      `unit/nearSigning.sessionSelection.unit.test.ts` also passed after stale
      raw-cache and status-only sealed-restore assertions were deleted:
      `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/nearSigning.sessionSelection.unit.test.ts --reporter=line`.
      Passed again on June 18, 2026 after active-store account, threshold-session,
      lane, and list reads pruned stale Ed25519 raw-material records:
      `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/routerAbEd25519.walletSessionState.unit.test.ts unit/warmSessionReadModel.unit.test.ts unit/warmSessionStore.transitions.unit.test.ts --reporter=line`.
	- [x] Focused lane-diagnostics tests proving malformed persisted records are
	      surfaced as invalid lanes instead of being hidden.
	      Passed on June 18, 2026. The focused Ed25519 runtime record case passed
      with:
      `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/availableSigningLanes.ed25519Duplicates.unit.test.ts -g "does not advertise a warm Ed25519 runtime lane without Router A/B normal-signing state" --reporter=line`.
	      The full `availableSigningLanes.ed25519Duplicates.unit.test.ts` file
	      now covers Ed25519 and ECDSA runtime rows missing Router A/B state and
	      passes after obsolete durable-readback assertions were deleted:
	      `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/availableSigningLanes.ed25519Duplicates.unit.test.ts --reporter=line`.
	- [x] Focused sealed-session boundary tests proving passkey Ed25519 sealed
	      restore no longer accepts raw client-base material. Passed on June 18,
	      2026:
	      `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/sealedSessionStore.unit.test.ts unit/sealedRecovery.methodAdapters.unit.test.ts --reporter=line`.
	      Passed again after deleting the dead passkey Ed25519 sealed-restore raw
	      material write path, with the related passkey recovery and NEAR
	      session-selection coverage:
	      `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/sealedSessionStore.unit.test.ts unit/sealedRecovery.methodAdapters.unit.test.ts unit/passkeyEd25519Recovery.unit.test.ts unit/nearSigning.sessionSelection.unit.test.ts --reporter=line`.
	- [x] Focused warm-session reconstruction tests proving Ed25519 handle
	      persistence clears stale raw client-base material and still satisfies
	      strict Router A/B ready-state fixtures. Passed on June 18, 2026:
	      `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/routerAbEd25519.walletSessionState.unit.test.ts unit/seamsWeb.loginThresholdWarm.unit.test.ts unit/warmSessionReadModel.unit.test.ts unit/warmSessionStore.transitions.unit.test.ts --reporter=line`.
- [x] Focused registration/add-signer orchestration test proving the current
      fixtures use Router A/B keyset prefetch, Router A/B Wallet Session JWTs,
      and worker-handle-backed ECDSA registration material. Passed on June 18,
      2026:
      `W3A_TEST_FRONTEND_URL=http://127.0.0.1:5208 rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/addWalletSigner.orchestration.unit.test.ts --reporter=line`.

## Phase 15.12: Delete Raw-Material Compatibility Surface

Start this phase only after the relevant Phase 15.10 surface gates and Phase
15.11 strict signable-state gates have landed for the curve/surface being
cleaned. Do not run this as one broad deletion pass. A surface is eligible only
when its writer, reader, restore parser, sign-ready builder, stale-record
invalidation path, and tests all use worker-owned material handles.

This phase removes the temporary compatibility surface so raw crypto-secret
material cannot drift back into TypeScript orchestration.

Deletion checklist:

- [ ] Delete active TypeScript record fields that store Ed25519 client-base
      material or ECDSA client signing material. Current durable signable records
      should carry only worker handles, binding digests, public facts, session
      ids, Wallet Session JWTs, and SigningWorker scope.
- [ ] Delete raw-material write paths:
      `persistStoredThresholdEd25519SessionClientBase`, direct
      `xClientBaseB64u` record writes, direct `clientVerifyingShareB64u` record
      writes for signable Ed25519 state, and any ECDSA presign/client-share
      writes outside worker-owned storage.
- [ ] Delete raw-material read paths from active signing and restore code. If an
      old development record is encountered, invalidate it and require a fresh
      Wallet Session/bootstrap flow instead of reconstructing active signing
      state from raw fields.
- [ ] Delete request/persistence compatibility parsers that accepted raw Ed25519
      HSS client-base material or raw ECDSA client signing material after the
      stale-record cleanup path is covered by tests. Any parser retained after
      this phase must be non-signing, named as a historical import/export
      boundary, and guarded by a deletion issue/date.
- [ ] Delete or rewrite tests, fixtures, mocks, and snapshots that construct
      sign-ready Ed25519/ECDSA state with raw material fields. Keep only tests
      that prove old raw-material records are rejected or invalidated at the
      boundary.
      Current progress: `unit/thresholdEcdsa.presignPoolRefill.unit.test.ts`
      now constructs ECDSA presign-pool state with worker handles and public
      `bigR`, and the raw `thresholdEcdsaComputeSignatureShare` worker
      operation/wrapper was deleted. Active ECDSA presign/signing API call sites
      now pass `RouterAbEcdsaHssClientSigningMaterialSource` instead of
      `clientSigningShare32`.
- [ ] Delete docs that instruct SDK, app, or test authors to handle
      `xClientBaseB64u`, client shares, signing shares, nonce secrets,
      presignature secrets, or PRF-derived material in TypeScript.
- [ ] Rename any remaining `clientBase`/`clientShare` TypeScript domain objects
      that now represent worker handles or public facts so the names cannot be
      mistaken for secret material.
- [ ] Narrow source-guard allowlists to exact files. Active SDK orchestration,
      route clients, registration/login flows, restore flows, sealed-session
      persistence, and test fixture builders must be zero-tolerance for raw
      material names unless the file is a WASM worker boundary or signer-core
      binding shim.
- [ ] Remove any temporary diagnostic logs that print raw material presence,
      cache hit/miss state for secret material, or crypto-secret field names in
      active user flows.

Validation checklist:

- [ ] `rtk rg "xClientBaseB64u|clientVerifyingShareB64u|signingShare|additiveShare|prfFirstB64u" packages/sdk-web/src` returns only WASM worker boundaries,
      signer-core binding shims, negative guards, and historical docs explicitly
      marked as non-active.
- [ ] `rtk pnpm -C packages/sdk-web type-check`.
- [x] `rtk pnpm -C tests exec tsc --noEmit -p tsconfig.playwright.json`.
      Passed on June 18, 2026 after the selected-capability, availability
      diagnostics, and Ed25519 pending-material provisioning slices.
- [ ] Focused source guards reject raw-material references in active SDK
      orchestration, persistence, restore, registration, and route-client code.
- [ ] Fresh registration-to-sign and wallet-unlock-to-sign browser tests pass
      for Ed25519, ECDSA-HSS Tempo, and EVM with worker handles only.
- [ ] `rtk pnpm router:smoke` and `rtk pnpm router:smoke:bundled` pass.

## Phase 15.13: SDK And Server Route/Auth Boundary Cleanup

This phase narrows active SDK route clients, browser registration/bootstrap
parsing, and server Wallet Session issuance boundaries. It should not change
crypto protocol semantics or persisted record shapes; it should make route/auth
inputs exact before later route-module cleanup.

Implementation checklist:

- [x] Narrow the SDK ECDSA-HSS route client auth surface. Remove `cookie`,
      `threshold_session`, and `sessionKind?: "cookie"` branches from active
      Router A/B ECDSA-HSS bootstrap/export/signing route-client types. Active
      callers should pass exact Wallet Session/app/bootstrap bearer auth unions,
      and request builders should always use `credentials: "omit"` for
      signing-capable Router A/B routes. Keep legacy route-auth parsing only in
      explicitly named boundary tests or deleted-route compatibility parsers.
      Fix guidance: split `ThresholdEcdsaHssRouteAuth` into branch-specific
      route auth types: first-bootstrap app/bootstrap bearer auth, signable
      Wallet Session bearer auth, and export bearer auth. Delete `CookieSessionAuth`
      and `{ kind: "threshold_session" }` from active route-client imports.
      Replace `buildRelayRequestInit` with a bearer-only request builder for
      signing-capable Router A/B routes, and leave any cookie-capable request
      builder in a lifecycle-only module with source guards.
      Completed on June 18, 2026: `WalletSessionJwtAuth` now uses the
      `wallet_session` discriminator, the active ECDSA-HSS route client no
      longer imports `CookieSessionAuth` or accepts `sessionKind?: "jwt" |
      "cookie"`, the ECDSA bootstrap platform input is JWT-only, and the
      ECDSA-HSS request builder always sends bearer requests with
      `credentials: "omit"`. The login warm-up path now fails fast when only
      cookie route auth is available.
- [x] Clean up passkey ECDSA sealed-restore storage writes. Replace the ad hoc
      `upsertStoredThresholdEcdsaSessionRecord({ recordsByLane: new Map() },
      ...)` call with an explicit restore-store dependency or a dedicated global
      restore helper that documents which indices and artifacts are updated.
      The restore path must preserve ECDSA role-local ready state, Router A/B
      normal-signing state, Wallet Session auth, chain target, and export/seal
      metadata without relying on a disposable map side effect.
      Fix guidance: add a restore-specific storage port to
      `restorePasskeyEcdsaSealedRecordForWallet` or create a helper such as
      `upsertRestoredThresholdEcdsaSessionRecord`. That helper should call the
      same canonical signable-record parser as normal activation, update the
      global lane/session indices intentionally, preserve any export artifact
      map if the caller owns one, and return the exact record that
      `getStoredThresholdEcdsaSessionRecordByThresholdSessionIdForTarget` will
      later resolve. Add a regression test that restore, status read, and final
      ECDSA material selection all see the same record.
      Completed on June 18, 2026: passkey ECDSA sealed restore now calls the
      dedicated `upsertRestoredThresholdEcdsaSessionRecord` helper instead of
      passing a disposable empty map to the generic upsert path. The helper
      writes intentionally into the active ECDSA session index used by
      threshold-session lookups.
- [x] Remove route-client JWT claim parsing from active browser registration
      clients. `walletRegistration.ts` must stop manually decoding Wallet
      Session JWT payloads to reconstruct Router A/B ECDSA-HSS normal-signing
      state. Either the server response must return the typed Router A/B state
      directly, or the claim parser/binding validator must live in `shared-ts`
      and be reused by server, SDK, and tests.
      Completed on June 18, 2026: `walletRegistration.ts` uses the shared
      `parseRouterAbEcdsaHssNormalSigningFromWalletRegistrationJwtV1` boundary
      parser from `shared-ts`; the focused source guard rejects inline claim
      parsing markers such as `decodeJwtPayloadRecord` and direct
      `payload.routerAbEcdsaHssNormalSigning` reads in the browser registration
      client.
- [x] Narrow server Wallet Session signing helpers further. Active signable
      issuers should call curve-specific builders that accept exact Router A/B
      inputs and return exact claim objects. Keep any generic JWT signer private
      and unable to accept broad `extraClaims`, optional session identity, or
      issuer-binding-only ECDSA state for signing-capable tokens.
      Completed on June 18, 2026: `commonRouterUtils.ts` now builds exact
      `RouterAbEd25519WalletSessionClaims` and
      `RouterAbEcdsaHssWalletSessionClaims` objects before signing. The private
      signer validates those exact claims and no longer accepts `kind`,
      `allowedSessionKinds`, or `extraClaims`. The ECDSA-HSS wrapper also
      verifies the Router A/B normal-signing state against the bootstrap wallet,
      RP, key context, public identity, activation epoch, and SigningWorker id
      before minting a signable JWT.

Validation checklist:

- [x] `rtk pnpm -C packages/sdk-server-ts type-check`.
      Passed on June 18, 2026 after the SDK route-auth discriminator cleanup
      and Wallet Session seal status discriminator normalization.
      Passed again on June 18, 2026 after narrowing the server Wallet Session
      JWT helper to exact curve-specific Router A/B claim builders.
- [x] Focused SDK route-client/source-guard tests proving active ECDSA-HSS
      Router A/B route clients no longer expose cookie auth,
      `threshold_session`, or `sessionKind: "cookie"` branches.
      Current progress: `unit/routerAbNormalSigningSdk.guard.unit.test.ts`
      covers the browser registration client shared-claim boundary.
      Passed on June 18, 2026 after adding a source guard for current
      Wallet Session route-auth discriminators and bearer-only ECDSA-HSS route
      client boundaries:
      `rtk pnpm -C tests exec playwright test -c playwright.source.config.ts unit/routerAbNormalSigningSdk.guard.unit.test.ts --reporter=line`.
      Focused token/status/bootstrap regression tests also passed:
      `W3A_TEST_FRONTEND_URL=http://127.0.0.1:5211 rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/sessionTokens.unit.test.ts unit/signingBudgetStatus.parser.unit.test.ts unit/walletRegistrationEcdsaRouterAbBootstrap.unit.test.ts --reporter=line`.
      The Wallet Session seal route regression suite passed:
      `rtk pnpm -C tests exec playwright test -c playwright.relayer.config.ts relayer/signing-session-seal-router.test.ts --reporter=line`.
      Passkey ECDSA restored-record indexing is covered by
      `unit/ecdsaRoleLocalRecords.unit.test.ts`. Passed on June 18, 2026:
      `W3A_TEST_FRONTEND_URL=http://127.0.0.1:5212 rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/ecdsaRoleLocalRecords.unit.test.ts --reporter=line`.
- [x] Focused server-route tests proving signable Wallet Session JWT issuance
      cannot produce issuer-binding-only ECDSA tokens.
      Completed on June 18, 2026: `unit/thresholdSessionClaims.unit.test.ts`
      now proves Router A/B ECDSA-HSS JWT issuance succeeds only with
      normal-signing state bound to the bootstrap facts and rejects
      issuer-binding-only ECDSA input without calling the session signer.
      Passed:
      `W3A_TEST_FRONTEND_URL=http://127.0.0.1:5213 rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/thresholdSessionClaims.unit.test.ts --reporter=line`.
      The broader Playwright TypeScript gate also passed after the stale ECDSA
      fixture literal was replaced with the shared normal-signing state kind:
      `rtk pnpm -C tests exec tsc --noEmit -p tsconfig.playwright.json`.
- [x] Source guards proving no broad `extraClaims` signable JWT issuer and no
      cookie-capable request builder in active signing-capable Router A/B route
      clients.
      Completed on June 18, 2026: `unit/routerAbServerWalletSessionClaimBoundary.guard.unit.test.ts`
      rejects `extraClaims`, `allowedSessionKinds`, legacy generic Wallet
      Session signer names, and legacy JWT-kind helpers in the active server
      Router A/B issuer. `unit/routerAbNormalSigningSdk.guard.unit.test.ts`
      continues to prove the active SDK route clients use current bearer-only
      Wallet Session discriminators. Passed:
      `rtk pnpm -C tests exec playwright test -c playwright.source.config.ts unit/routerAbServerWalletSessionClaimBoundary.guard.unit.test.ts --reporter=line`.
      `rtk pnpm -C tests exec playwright test -c playwright.source.config.ts unit/routerAbNormalSigningSdk.guard.unit.test.ts --reporter=line`.

## Phase 15.14: Canonical Scope Digests And Private Service HTTP

This phase replaces ad hoc equality and repeated private HTTP plumbing with
canonical builders and shared service-call helpers. Keep endpoint-specific
validators and service auth intact while deduplicating.

Implementation checklist:

- [x] Replace structural `JSON.stringify` scope equality with canonical
      request/scope digests. ECDSA-HSS prepare/finalize validators, private
      SigningWorker forwarding, pool-fill scope checks, and SDK pool keys should
      compare canonical bytes or shared digest builders from
      `shared-ts/routerAbEcdsaHss`, not object stringification.
      Completed on June 18, 2026: `shared-ts/routerAbEcdsaHss` now exports
      canonical normal-signing scope bytes and a canonical scope equality
      helper. Shared prepare/finalize response validation, server private
      SigningWorker request validation, and SDK ECDSA-HSS browser presignature
      pool keys now use the shared canonical scope boundary instead of
      structural JSON stringification.
- [x] Consolidate private service-binding HTTP/auth boilerplate. The ECDSA-HSS
      pool-fill bridge, private SigningWorker forwarder, and Cloudflare
      service-binding callers should use one typed `postServiceJson`-style
      helper plus endpoint-specific request/response validators. Do not weaken
      service auth, route ownership checks, or error normalization while
      deduplicating.
      Completed on June 18, 2026: `internalServiceHttp.ts` now owns the shared
      Router A/B internal-service auth header, token normalization, JSON POST,
      response text capture, and JSON parsing for the TS Router layer. The
      ECDSA-HSS pool-fill bridge and private SigningWorker forwarder call that
      helper and keep their endpoint-specific request validators and error
      normalization. Cloudflare service-binding callers already route through
      `post_service_json`; local Rust private SigningWorker forwarding now uses
      `local_http_post_signing_worker_private_json_v1` with endpoint-specific
      validation preserved.

Validation checklist:

- [x] Focused private SigningWorker validator tests proving canonical
      request/scope digest mismatch is rejected for prepare, finalize, pool-fill,
      and replay cases.
      Completed on June 18, 2026: `unit/thresholdSessionClaims.unit.test.ts`
      now proves ECDSA-HSS private prepare and finalize validators accept the
      exact canonical Wallet Session scope and reject activation/scope drift
      before the request is forwarded to the SigningWorker. Focused ECDSA-HSS
      normal-signing, pool-fill bridge, and presignature-pool tests passed after
      canonical scope comparison and shared private service HTTP consolidation.
      Replay protection remains in the Router/core replay boundary rather than
      the stateless private validator: `crates/router-ab-core` covers replay
      nonce digest binding and local replay-cache rejection, while the active
      ECDSA-HSS pool-fill test covers replayed/missing presign-session handling.
      Passed:
      `W3A_TEST_FRONTEND_URL=http://127.0.0.1:5216 rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/thresholdSessionClaims.unit.test.ts --reporter=line`.
- [x] Source guards proving no `JSON.stringify` scope comparison in active
      Router A/B signing, pool-fill, or private SigningWorker validators.
      Completed on June 18, 2026:
      `unit/routerAbServerWalletSessionClaimBoundary.guard.unit.test.ts` now
      rejects structural JSON scope comparison helpers in the shared ECDSA-HSS
      protocol module, server private SigningWorker validator, and SDK
      ECDSA-HSS presignature pool key. It also proves the ECDSA-HSS pool-fill
      bridge and private SigningWorker forwarder use the shared
      `postRouterAbInternalServiceJson` helper instead of hand-rolled
      internal-auth JSON POSTs. Passed:
      `rtk pnpm -C tests exec playwright test -c playwright.source.config.ts unit/routerAbServerWalletSessionClaimBoundary.guard.unit.test.ts --reporter=line`.
      Focused canonical boundary and pool-key tests passed:
      `W3A_TEST_FRONTEND_URL=http://127.0.0.1:5214 rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/routerAbEcdsaHssNormalSigning.unit.test.ts unit/thresholdSessionClaims.unit.test.ts unit/thresholdEcdsa.presignPoolRefill.unit.test.ts --reporter=line`.
      Focused private-service HTTP bridge tests passed:
      `W3A_TEST_FRONTEND_URL=http://127.0.0.1:5215 rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/routerAbEcdsaHssPresignBridge.unit.test.ts unit/routerAbEcdsaHssNormalSigning.unit.test.ts unit/thresholdSessionClaims.unit.test.ts --reporter=line`.
      TypeScript validation passed:
      `rtk pnpm -C packages/sdk-server-ts type-check`;
      `rtk pnpm -C packages/sdk-web type-check`;
      `rtk pnpm -C tests exec tsc --noEmit -p tsconfig.playwright.json`.
- [x] `rtk cargo test --manifest-path crates/router-ab-core/Cargo.toml`.
      Passed on June 18, 2026 after canonical scope and private service HTTP
      consolidation.
- [x] `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings --test source_guards`.
      Passed on June 18, 2026 after confirming Cloudflare service-binding calls
      continue to use shared `post_service_json` routing.
      Local Rust Router A/B validation also passed:
      `rtk cargo check --manifest-path crates/router-ab-dev/Cargo.toml`;
      `rtk cargo test --manifest-path crates/router-ab-dev/Cargo.toml --test local_worker_http local_router_private_forwarding_uses_shared_internal_service_http_helper -- --nocapture`;
      `rtk cargo test --manifest-path crates/router-ab-dev/Cargo.toml --test local_worker_http ecdsa_hss -- --nocapture`.

## Phase 15.15: Rust And Local Router Topology Cleanup

This phase is file/module cleanup for Rust Router A/B and local development
topology. It must preserve route constants, parser boundaries, service auth,
Router-admitted envelope forwarding, and existing local smoke behavior.

Implementation checklist:

- [ ] Split Router A/B monolith files by protocol surface without changing
      behavior. Break `crates/router-ab-cloudflare/src/lib.rs`,
      `durable_object.rs`, `strict_worker.rs`, `tests/bindings.rs`, and
      `crates/router-ab-dev/src/lib.rs` into modules for Ed25519 normal signing,
      ECDSA-HSS normal signing, ECDSA-HSS pool fill, ceremony persistence,
      keyset/config, local dev dispatch, and service-binding HTTP. Keep route
      constants and parser boundaries centralized.
      Current progress, June 18, 2026: local private service HTTP forwarding
      was split out of `crates/router-ab-dev/src/lib.rs` into
      `crates/router-ab-dev/src/local_service_http.rs`. The same module now
      owns the generic local service-binding endpoint/client helpers and the
      direct JSON POST helper used for private SigningWorker forwarding. Local
      HTTP request parsing/response/error helpers were split into
      `crates/router-ab-dev/src/local_dev_http.rs`. Local worker source guards
      now prove those helpers stay out of the `router-ab-dev` monolith, while
      route handlers continue to call the shared dispatcher and service helper.
      Local worker topology helpers were also split into
      `crates/router-ab-dev/src/local_worker_topology.rs`, with a focused source
      guard proving health response and route-ownership helpers stay out of
      `lib.rs`. Local dev dispatch was moved into
      `crates/router-ab-dev/src/local_dev_http.rs`; bin entrypoints now call the
      shared dispatcher while protocol handlers remain in `lib.rs` until their
      protocol-surface module split. The local Ed25519 normal-signing smoke flow
      now builds client
      finalization material from the same scope-bound HSS fixture used by the
      SigningWorker, fixing the stale fixture mismatch that produced `Ed25519
      verifying shares do not sum to group public key`.
      Completed local split slices:
      - [x] Local service-binding HTTP client and private SigningWorker POST
            helper live in `crates/router-ab-dev/src/local_service_http.rs`.
      - [x] Local HTTP request parsing, response writing, JSON errors, and
            auth checks live in `crates/router-ab-dev/src/local_dev_http.rs`.
      - [x] Local worker health/topology and route-ownership helpers live in
            `crates/router-ab-dev/src/local_worker_topology.rs`.
      - [x] Local ECDSA-HSS presignature pool ids stay burned after prepare:
            the local SigningWorker store now models `Available` versus
            `Consumed`, exact duplicates are idempotent only before prepare, and
            reuse after prepare/finalize is rejected by route tests.
      - [x] Local ECDSA-HSS presignature pool lifecycle storage lives in
            `crates/router-ab-dev/src/local_ecdsa_hss_pool_store.rs`, with a
            source guard keeping the one-use lifecycle state out of `lib.rs`.
      - [x] Local dev dispatch lives in
            `crates/router-ab-dev/src/local_dev_http.rs`, with a source guard
            proving `LocalDevHttpTopologyV1`, `local_dev_http_handle_request_v1`,
            and the topology route helpers stay out of `lib.rs`.
      - [ ] Ed25519 normal-signing, ECDSA-HSS normal-signing, ECDSA-HSS pool-fill,
            ceremony persistence, keyset/config, and Cloudflare worker modules
            still need protocol-surface splits.
- [x] Unify local-dev route dispatch. The split-worker and bundled local Rust
      servers should share request parsing, internal service-auth checks, JSON
      error bodies, Router-admitted envelope forwarding, and ECDSA-HSS/Ed25519
      route ownership logic, with only topology-specific wiring left in the bin
      entrypoints.
      Completed on June 18, 2026: both `router_ab_local_worker` and
      `router_ab_local_bundled` delegate requests to
      `local_dev_http_handle_request_v1`. The focused source guard
      `local_worker_bins_delegate_to_shared_route_dispatcher` now rejects route
      tables in either bin entrypoint, and the shared dispatcher is covered by
      split-worker and bundled route-surface tests.

Validation checklist:

- [x] `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings --test source_guards`.
      Passed on June 18, 2026 after the local service HTTP module split and
      local Ed25519 fixture consistency fix.
- [x] `rtk cargo test --manifest-path crates/router-ab-dev/Cargo.toml`.
      Passed on June 18, 2026 after extracting local service HTTP and fixing
      local Ed25519 normal-signing fixture consistency. Focused checks also
      passed:
      `rtk cargo check --manifest-path crates/router-ab-dev/Cargo.toml`;
      `rtk cargo test --manifest-path crates/router-ab-dev/Cargo.toml --test local_worker_http local_dev_http_request_boundary_lives_outside_monolith -- --nocapture`;
      `rtk cargo test --manifest-path crates/router-ab-dev/Cargo.toml --test local_worker_http local_dev_http_dispatch_lives_outside_monolith -- --nocapture`;
      `rtk cargo test --manifest-path crates/router-ab-dev/Cargo.toml --test local_worker_http local_signing_worker_private_http_helper_lives_outside_monolith -- --nocapture`;
      `rtk cargo test --manifest-path crates/router-ab-dev/Cargo.toml --test local_worker_http local_worker_topology_helpers_live_outside_monolith -- --nocapture`;
      `rtk cargo test --manifest-path crates/router-ab-dev/Cargo.toml --test local_worker_http local_ecdsa_hss_pool_lifecycle_store_lives_outside_monolith -- --nocapture`;
      `rtk cargo test --manifest-path crates/router-ab-dev/Cargo.toml --test local_worker_http local_worker_bins_delegate_to_shared_route_dispatcher -- --nocapture`;
      `rtk cargo test --manifest-path crates/router-ab-dev/Cargo.toml --test local_worker_http local_router_private_forwarding_uses_shared_internal_service_http_helper -- --nocapture`;
      `rtk cargo test --manifest-path crates/router-ab-dev/Cargo.toml --test local_worker_http local_router_ecdsa_hss_pool_fill_prepare_finalize_uses_one_prepared_record -- --nocapture`;
      `rtk cargo test --manifest-path crates/router-ab-dev/Cargo.toml --test local_worker_http ecdsa_hss -- --nocapture`.
- [x] `rtk pnpm router:smoke` and `rtk pnpm router:smoke:bundled`.
      Passed on June 18, 2026 after the smoke binary switched Ed25519
      finalization to the scope-bound HSS fixture. Both four-worker and bundled
      smoke summaries reported `normal_signing_status: "ed25519_v1"`,
      `ecdsa_hss_prepare_status: "http_200_bound"`,
      `ecdsa_hss_finalize_status: "http_200_signature"`, and
      `ecdsa_hss_replay_rejection_status: "http_400_one_use_replay_rejected"`.
- [x] Route-surface tests proving split-worker and bundled local dispatch expose
      the same public/private Router A/B behavior.
      Completed on June 18, 2026: `local_worker_http` covers split-worker
      Ed25519 normal signing, split-worker ECDSA-HSS pool-fill/prepare/finalize,
      private service-auth rejection, and bundled Ed25519 normal signing through
      one listener. The bundled listener test now also exercises ECDSA-HSS
      pool-fill/prepare/finalize through the same public/private route surface.
      `rtk cargo test --manifest-path crates/router-ab-dev/Cargo.toml` passed
      with 53 tests across 16 suites.

## Phase 15.16: Test, Route-Surface, Package, And Artifact Hygiene

This phase removes review friction after behavior is pinned. It should not
change signing semantics. Use it to preserve invariant coverage, move generated
artifacts out of source paths, align local docs/scripts, and keep package
cleanup separate from protocol changes.

Implementation checklist:

- [ ] Create a deleted-test replacement map before removing more old threshold
      tests. For each deleted Ed25519/ECDSA threshold test, record the preserved
      invariant and the current Router A/B test that covers it: digest/request
      binding, FROST/share tamper rejection, session exhaustion, scope rejection,
      replay rejection, relayer/SigningWorker failure, CORS/route rejection, and
      budget expiry.
- [ ] Move generated evidence artifacts out of committed source paths or keep
      only summarized docs. Startup-latency and release-evidence JSON files
      should be written under ignored `target/` or report artifact directories
      unless a specific summary is intentionally checked into docs.
- [ ] Separate unrelated churn from Router A/B cleanup commits. VoiceID/demo
      changes, package-wrapper slimming, benchmark deletion, stale-doc tombstones,
      Rust module splitting, SDK state hardening, and server route cleanup should
      be committed as separate reviewable slices.
- [x] Fix the package/runtime export guard after folding `sdk-runtime-ts` into
      `sdk-web`. The canonical declaration layout is
      `dist/types/sdk-web/...`; `@seams/sdk/runtime` exports
      `createSigningRuntime` and `createSigningRuntimeStatePorts`; and focused
      package/export tests cover the public runtime value exports.
- [x] Resolve the `pnpm site` / `pnpm site:router` local-mode ambiguity.
      `pnpm site` is now the single Router A/B local site entrypoint and the
      duplicate `site:router` script has been deleted from `package.json`.
      The focused source guard now rejects reintroducing `site:router` and
      requires `pnpm site` to carry the local Router A/B SigningWorker id.
      Passed on June 18, 2026:
      `rtk pnpm -C tests exec playwright test -c playwright.source.config.ts unit/routerAbNormalSigningSdk.guard.unit.test.ts --reporter=line`.
- [x] Update local port docs and smoke assumptions after moving the Router server
      upstream to `127.0.0.1:9090`. `package.json` and
      `apps/web-client/Caddyfile` now point Caddy at `9090`; README,
      `docs/router-a-b-local-dev.md`, `apps/web-client/README.md`, the focused
      source guard, and `pnpm router:public-route-smoke` agree on the same
      topology.
- [x] Finish the local package-boundary cleanup left after deleting
      `sdk-runtime-ts`. `packages/sdk-server-ts` is isolated from the web
      tsconfig and `@/*` alias, shared server-consumed types are in
      `shared-ts` or server-local modules, and `pg` plus
      `@simplewebauthn/server` are no longer hard browser dependencies.
- [x] Repair stale source-guard harness assumptions after the package/folder
      cleanup. The source-script tests now use
      `tests/tsconfig.playwright.json`, the Postgres split-domain script tests
      provide the required signer/console env fixture before checking invalid
      SQL identifiers, and the headless-auth guard points at the current
      `apps/web-client` demo path.
- [x] Repair stale Email OTP coordinator fixtures after the Router A/B Wallet
      Session and handle-owned material cleanup. The focused coordinator suite
      now uses Router A/B ECDSA-HSS Wallet Session JWT fixtures, enabled local
      Router A/B normal-signing config, valid ECDSA public facts, and the
      current no-raw-Ed25519-companion behavior. ECDSA sealed restore now
      rejects signing-root/runtime-policy drift before invoking worker
      rehydrate.
      Passed on June 18, 2026:
      `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/emailOtpWalletSessionCoordinator.unit.test.ts --reporter=line`.
      Passed again on June 19, 2026 after ECDSA sealed restore stopped hydrating
      raw Ed25519 companion material and the fixture helper stopped auto-injecting
      `xClientBaseB64u`: 31 tests passed.
      Passed again on June 19, 2026 after Email OTP Ed25519 provisioning moved
      finalized HSS client-output opening and material storage into the HSS
      client worker, and Email OTP Ed25519 seal transport stopped carrying raw
      restore metadata: 31 tests passed.
- [x] Decide the larger public server package/export split sequencing.
      `@seams/sdk-server` is real packaging cleanup, but it is not a Router A/B
      correctness blocker. Keep it behind Router topology, signer-material
      handles, raw-material deletion gates, and server auth/session boundary
      cleanup.
- [ ] Implement the `@seams/sdk-server` split after signing/session cleanup is
      stable. Publish `packages/sdk-server-ts` as `@seams/sdk-server`; move
      `./server`, `./server/router/express`, `./server/router/cloudflare`,
      `./server/router/ror`, and `./server/wasm/signer` exports out of
      `packages/sdk-web/package.json`; keep `@seams/sdk` browser/runtime/react
      only; move server deps from optional peers in `@seams/sdk` to normal
      dependencies or peers in `@seams/sdk-server`; update imports from
      `@seams/sdk/server` to `@seams/sdk-server`; add clean-room browser and
      server package install smokes; and delete the old `@seams/sdk/server`
      subpaths.
- [ ] Split Router A/B route handlers out of threshold-named server modules.
      Active Router A/B public routes now live in
      `express/routes/thresholdEd25519.ts`,
      `express/routes/thresholdEcdsa.ts`, and their Cloudflare equivalents, with
      threshold log prefixes and `thresholdSessionRoute` metadata still carrying
      Router A/B routes. Move them to `routerAbEd25519Routes` and
      `routerAbEcdsaHssRoutes`, rename log prefixes/status helpers, and make
      route-definition auth metadata describe Wallet Session JWT auth rather than
      threshold-era route categories.
- [ ] Split ECDSA-HSS bootstrap authorization branches into exact route/service
      types. The current bootstrap handler accepts either existing Router A/B
      ECDSA Wallet Session auth or first-bootstrap auth, then mints a signable
      Wallet Session JWT. Model these as separate branch results so
      issuer-binding/bootstrap and signable Wallet Session refresh paths cannot
      produce different Router A/B claim shapes or accidentally mint
      issuer-binding-only signing tokens.
- [ ] Normalize Ed25519 Router A/B normal-signing status mapping across Express
      and Cloudflare. The new Ed25519 normal-signing handler manually maps
      validation failures while ECDSA uses the shared threshold status helper.
      Use one Router A/B status mapper so malformed bodies, missing sessions,
      invalid Wallet Session claims, not-configured service state, and scope
      errors return the same status/body shape in every adapter.
- [ ] Add source guards and type fixtures for the rot fixes: no raw crypto-secret
      fields in active SDK orchestration, no optional critical signable-state
      fields, no broad `extraClaims` signable JWT issuer, no `JSON.stringify`
      scope comparison, no silent lane skip for missing Router A/B state, and no
      old public threshold signing route literals outside deny-list tests/docs.
      Current progress: `routerAbWalletSessionCredential.typecheck.ts` rejects
      Ed25519 Router A/B ready states that omit the worker-owned material handle
      or binding digest. Add the remaining guards/type fixtures as each Phase
      15.11 through 15.16 slice lands.

Validation note, June 18, 2026: stale source-guard harness fixes reduced
`rtk pnpm -C tests test:source-guards` from 23 failures to 18 failures. The
three source-backed `tsx` tests, the Postgres split-domain script guard, and
the headless-auth source guard now pass in focused runs. The full source-guard
gate remains red on raw-material, signing-state, duplicate iframe, signer-worker
PRF, architecture, signing-root, and local cargo/fixture-vector failures.

Shared validation checklist for Phases 15.11 through 15.16:

- [x] `rtk pnpm -C packages/sdk-web type-check`.
      Passed on June 18, 2026 after the Ed25519 final ready-state material
      handle slice and ECDSA-HSS final signing handle-only local union slice.
      Passed again on June 18, 2026 after ECDSA warm-capability JWT-only
      readiness hardening.
      Passed again on June 18, 2026 after ECDSA activation fail-closed
      hardening.
      Passed again on June 18, 2026 after the Router A/B persisted-record
      classifier was wired into selected capability reads and warm-session
      readiness.
      Passed again on June 18, 2026 after repairing the Email OTP coordinator
      fixtures and adding sealed ECDSA signing-root drift rejection before
      worker rehydrate.
      Passed again on June 19, 2026 after Email OTP ECDSA companion restore was
      made fail-closed for raw Ed25519 companion material.
- [x] `rtk pnpm -C packages/sdk-server-ts type-check`.
      Passed on June 18, 2026 after the `pnpm site` / `site:router`
      local-mode cleanup.
- [x] `rtk pnpm -C tests exec tsc --noEmit -p tsconfig.playwright.json`.
      Passed on June 18, 2026 after the selected-capability, availability
      diagnostics, Ed25519 pending-material provisioning, and warm-session
      strict-readiness slices.
      Passed again on June 18, 2026 after repairing the Email OTP coordinator
      fixtures and adding sealed ECDSA signing-root drift rejection before
      worker rehydrate.
      Passed again on June 19, 2026 after Email OTP ECDSA companion restore was
      made fail-closed for raw Ed25519 companion material.
- [ ] Focused unlock-to-sign regression tests for fresh and restored Ed25519,
      ECDSA-HSS Tempo, and EVM sessions.
- [x] Focused warm-capability tests proving ECDSA cookie records and records
      missing Wallet Session JWT auth cannot produce `state: "ready"`.
      Passed on June 18, 2026:
      `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/warmSessionReadModel.unit.test.ts --reporter=line`.
      Related invariant/provisioning/transition tests passed:
      `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/warmSessionStore.invariants.unit.test.ts unit/warmSessionTransitions.unit.test.ts unit/warmSessionEcdsaProvisioning.unit.test.ts --reporter=line`.
- [x] Focused warm read-model and invariant tests proving Ed25519/ECDSA records
      missing Router A/B state cannot become `ready`.
      Passed on June 18, 2026:
      `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/warmSessionReadModel.unit.test.ts --reporter=line`.
      Related transition coverage passed:
      `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/warmSessionStore.transitions.unit.test.ts --reporter=line`.
- [x] Focused ECDSA activation tests proving disabled Router A/B normal-signing
      config cannot create a signing-capable ECDSA session record.
      Passed on June 18, 2026:
      `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/thresholdEcdsa.authorizationBootstrapVerifier.unit.test.ts --reporter=line`.
- [x] Focused Ed25519 passkey provisioning tests proving a successful passkey
      provision either creates strict Router A/B signable material or a
      non-signing pending state that cannot be selected for final signing.
      Passed on June 18, 2026:
      `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/warmSessionStore.transitions.unit.test.ts --reporter=line`.
- [x] Focused persisted-record parser tests proving current Ed25519/ECDSA
      signable records without Router A/B state/material are rejected or
      surfaced as invalid/pending records before final signing.
      Passed on June 18, 2026:
      `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/signingCapabilityStrictRecords.unit.test.ts --reporter=line`.
- [x] Focused SDK route-client/source-guard tests proving active ECDSA-HSS
      Router A/B route clients no longer expose cookie auth,
      `threshold_session`, or `sessionKind: "cookie"` branches.
      Passed on June 18, 2026:
      `rtk pnpm -C tests exec playwright test -c playwright.source.config.ts unit/routerAbNormalSigningSdk.guard.unit.test.ts --reporter=line`.
- [x] Focused lane-diagnostics tests proving malformed persisted records are
      surfaced as invalid lanes instead of being hidden.
      Passed on June 18, 2026:
      `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/availableSigningLanes.ed25519Duplicates.unit.test.ts --reporter=line`.
- [ ] Focused server-route tests proving signable Wallet Session JWT issuance
      cannot produce issuer-binding-only ECDSA tokens.
- [ ] Focused private SigningWorker validator tests proving canonical
      request/scope digest mismatch is rejected for prepare, finalize, pool-fill,
      and replay cases.
- [x] `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts
      unit/refactor51bPackageExports.unit.test.ts --reporter=line`.
      Passed on June 18, 2026 after the package/runtime export cleanup.
- [ ] Focused route-surface tests proving Router A/B routes are registered by
      Router A/B-named modules, old threshold route modules do not own active
      Router A/B signing routes, and Express/Cloudflare return identical statuses
      for Ed25519 and ECDSA-HSS validation failures.
- [ ] Focused package-boundary guards proving `sdk-server-ts` no longer extends
      `sdk-web/tsconfig.json`, server source does not import `@/core/*` from
      web-owned modules except through explicitly retained boundary files, and
      the local site/server scripts have one documented Router A/B topology.
- [ ] Source guards for raw material, optional signable-state fields,
      `JSON.stringify` scope comparison, broad signable JWT helpers, and deleted
      public threshold route literals.
- [ ] `rtk cargo test --manifest-path crates/router-ab-core/Cargo.toml`.
- [ ] `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings --test source_guards`.
- [ ] `rtk cargo test --manifest-path crates/router-ab-dev/Cargo.toml`.
- [ ] `rtk pnpm router:smoke` and `rtk pnpm router:smoke:bundled`.
- [x] `rtk git diff --check`.
      Passed on June 18, 2026 after the `pnpm site` / `site:router`
      local-mode cleanup and focused topology guard update.

## Phase 15.17: Server Route/Auth, Seal, And Budget Boundary Cleanup

This phase addresses the remaining server-side Router A/B route/auth, Ed25519
seal, signing budget, and signing-session seal findings from the diff audit. The
goal is to make the server route/auth model match the Router A/B-only product
model: signing-capable routes require bearer Router A/B Wallet Session JWTs,
route metadata says Wallet Session rather than threshold-era session auth,
sealed restore records cannot model cookie-backed signable state, and shared
wallet-signing budget storage is explicit.

Implementation checklist:

- [ ] **P1: Make signing-capable server auth bearer-only.**
      `validateRouterAbEd25519WalletSessionTokenInputs`,
      `validateRouterAbEcdsaHssWalletSessionInputs`,
      `parseWalletSigningBudgetStatusRequest`, and
      signing-session seal authorization currently call generic
      `session.parse(headers)`, which accepts cookies when no bearer token is
      present. Add a narrow bearer-only Wallet Session parser for Router A/B
      signing-capable routes. It should extract only `Authorization: Bearer`,
      verify the JWT with the existing session service, parse the curve-specific
      Router A/B Wallet Session claim kind, and reject cookie-only requests
      before service logic runs.
- [ ] Apply the bearer-only parser to Ed25519 HSS
      prepare/respond/finalize, Ed25519 normal signing prepare/finalize/presign
      pool prepare, ECDSA-HSS signing/bootstrap/export/pool-fill routes where
      they consume signable Wallet Session auth, signing budget status, and
      `/v2/wallet-session/seal/*`. Lifecycle routes that intentionally allow
      app-session cookies must stay outside this parser and use separately named
      app-session auth helpers.
- [ ] Add focused Express and Cloudflare tests proving cookie-only requests to
      every signing-capable Router A/B server route return `401` and do not
      mint, read, refresh, seal, unseal, forward to SigningWorker, or consume
      budget state. Add positive tests for bearer Router A/B Wallet Session JWTs
      on the same routes.
- [ ] **P2: Replace threshold-era route auth metadata for Router A/B routes.**
      `routeDefinitions.ts` still registers Router A/B Ed25519 HSS/signing
      routes with `thresholdSessionRoute(...)`, and
      `/session/signing-budget/status` is marked Ed25519-only even though the
      parser accepts Ed25519 and ECDSA-HSS Router A/B Wallet Session JWTs. Add a
      `walletSessionRoute(...)` or `routerAbWalletSessionRoute(...)` helper with
      curve-specific variants such as `ed25519`, `ecdsa_hss`, and `any_router_ab`.
      Use it for Router A/B signing-capable routes and budget/seal routes.
- [ ] Update `RouteAuthPolicy` and route-policy/source-guard tests so active
      Router A/B signing-capable routes cannot be registered with generic
      `threshold_session` auth. Keep the stable wire string
      `threshold_session` only where it is an intentional persisted or SDK
      compatibility discriminant, not as route-registry auth for current Router
      A/B signing routes.
- [ ] **P2: Split legacy sealed-restore shapes from active signable restore
      state.** `SealedSigningSessionEcdsaRestoreMetadata` and
      `SealedSigningSessionEd25519RestoreMetadata` still permit
      `sessionKind: "cookie"` and optional Wallet Session / Router A/B material.
      Introduce boundary-only legacy record parsers for old persisted blobs, then
      convert successful parses into exact active restore branches:
      Ed25519 active restore must require a bearer Wallet Session JWT,
      Router A/B normal-signing state, threshold session id, wallet signing
      session id, participant ids, and required signer-worker/public material
      handles. ECDSA-HSS active restore must require bearer Wallet Session JWT,
      Router A/B ECDSA-HSS normal-signing scope, key handle, activation epoch,
      chain target, participant ids, and presignature-pool scope material.
- [ ] Add type fixtures and parser tests proving active restore/signable state
      cannot be constructed with `sessionKind: "cookie"`, missing
      `walletSessionJwt`, missing Router A/B normal-signing state, missing
      threshold session id, or optional identity/auth/signing fields. Keep old
      cookie-shaped records only in named persistence-compatibility fixtures
      that parse to non-signable pending/invalid states or fail with a clear
      migration error.
- [ ] **P3: Rename and isolate shared wallet signing-budget storage.**
      Budget records are intentionally shared across Ed25519 and ECDSA-HSS but
      are wired through the Ed25519 wallet-session store name. Introduce a
      `WalletSigningBudgetStore` adapter or clearly named wrapper over the
      existing backing store. Route code and seal policy should depend on
      `walletSigningBudgetStore`, while curve session stores remain
      `ed25519WalletSessionStore` and `ecdsaWalletSessionStore`.
- [ ] Add budget-store tests proving Ed25519 and ECDSA-HSS budget status,
      consume, and refresh use the same signer-bound budget id format while
      still rejecting mismatched curve, threshold session id, user id, rp id, and
      participant set. The tests should make cross-curve budget intent explicit
      so future maintainers do not “fix” it into two incompatible stores.

Validation checklist:

- [x] `rtk pnpm -C packages/sdk-server-ts type-check`.
      Passed on June 18, 2026 after the `pnpm site` / `site:router`
      local-mode cleanup.
- [ ] `rtk pnpm -C tests exec playwright test -c playwright.relayer.config.ts
      relayer/threshold-ed25519.scheme-dispatch.test.ts
      relayer/signing-session-seal-router.test.ts
      relayer/router-ab-keyset-routes.test.ts --reporter=line`.
- [ ] `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts
      unit/thresholdSessionClaims.unit.test.ts
      unit/signingBudgetStatus.parser.unit.test.ts
      unit/router.routeDefinitions.unit.test.ts
      unit/routerAbServerWalletSessionClaimBoundary.guard.unit.test.ts
      --reporter=line`.
- [ ] Source guards proving active Router A/B route definitions do not use
      generic `thresholdSessionRoute(...)`, active signing-capable auth parsers
      do not call cookie-capable `session.parse(headers)`, and active
      signable-state types do not expose `sessionKind: "cookie"`.
- [x] `rtk git diff --check`.
      Passed on June 18, 2026 after the `pnpm site` / `site:router`
      local-mode cleanup and focused topology guard update.

## Phase 15.18: Spec-To-Code Compliance Audit Gate

Start this phase only after Phases 15.9 through 15.17 have no open
implementation or local-validation tasks. This is the final local review gate
before Phase 16 deployed Cloudflare evidence work.

Use `/Users/pta/.codex/skills/spec-to-code-compliance/SKILL.md` for the audit.
The audit must separate extraction, alignment, classification, and reporting;
each claim must cite exact documentation text and code line evidence, include a
confidence score, and classify ambiguity instead of inferring unspecified
behavior.

Specification corpus:

- [ ] Normalize and include `docs/router-a-b-single-session.md`.
- [ ] Normalize and include `docs/router-a-b-ecdsa.md`.
- [ ] Normalize and include `docs/router-A-B-signer-SPEC.md`.
- [ ] Normalize and include `docs/router-A-B-signer.md`.
- [ ] Normalize and include `docs/refactor-68-wallet-session-v2.md`.
- [ ] Normalize and include `docs/refactor-68B-router-cleanup.md`.
- [ ] Normalize and include `docs/router-a-b-local-dev.md`.
- [ ] Normalize and include this cleanup plan.
- [ ] Add any referenced Router A/B, Wallet Session, ECDSA-HSS, Ed25519 HSS,
      sealed-session, deployment, or route-topology docs discovered during
      documentation discovery.

Spec-IR requirements:

- [ ] Extract actors, roles, trust boundaries, and public/private route
      ownership for Router, Deriver A, Deriver B, SigningWorker, browser SDK,
      WASM workers, Wallet Session, seal service, and budget service.
- [ ] Extract Ed25519 requirements for HSS setup, normal signing,
      presign-pool hit and miss behavior, one-use handles, replay rejection,
      route auth, scope binding, Wallet Session JWT use, and worker-owned client
      material.
- [ ] Extract ECDSA-HSS requirements for key identity, bootstrap, activation,
      stable key context, active-state binding, presignature pool refill,
      prepare/finalize signing, one-use nonce/presignature semantics, export,
      route auth, and worker-owned client material.
- [ ] Extract Router A/B local topology requirements: one public Router server
      behind Caddy, private Deriver/SigningWorker service routes, internal
      service-auth, and no Caddy path split for signing routes.
- [ ] Extract cleanup invariants: no old public `/threshold-*` signing routes,
      no legacy threshold-session signing auth in active signing paths, no
      cookie-backed signable state, no raw crypto-secret client material in
      TypeScript orchestration, and no stale test/docs surfaces that advertise
      deleted behavior.

Code-IR requirements:

- [ ] Analyze active SDK signing code under `packages/sdk-web/src/core/signingEngine/`
      and registration/session orchestration under `packages/sdk-web/src/SeamsWeb/operations/`.
- [ ] Analyze active server route, Wallet Session, seal, budget, and Router A/B
      service code under `packages/sdk-server-ts/src/`.
- [ ] Analyze shared Router A/B protocol utilities under `packages/shared-ts/src/`.
- [ ] Analyze Rust Router A/B protocol, local-dev, and Cloudflare worker code
      under `crates/router-ab-core/`, `crates/router-ab-dev/`, and
      `crates/router-ab-cloudflare/`.
- [ ] Analyze WASM worker and signer-core boundaries under `wasm/eth_signer/`
      and any signer-core crates used by Ed25519/ECDSA client material handles.
- [ ] Analyze source guards, route-surface tests, type fixtures, and local smoke
      harnesses that enforce Router A/B-only behavior.

Alignment and reporting:

- [ ] Produce Spec-IR, Code-IR, Alignment-IR, and divergence findings with exact
      source evidence and confidence scores.
- [ ] Write the audit report to
      `docs/audits/router-a-b-spec-to-code-compliance-YYYY-MM-DD.md`.
- [ ] Include an alignment matrix for Ed25519 signing, ECDSA-HSS signing,
      Wallet Session JWT claims, sealed restore, budget status/consume, route
      topology, private service auth, worker-owned material handles, one-use
      nonce/presignature lifecycle, and cleanup/source-guard invariants.
- [ ] Classify every divergence as Critical, High, Medium, or Low using the
      skill severity model. Mark undocumented active code behavior as
      `UNDOCUMENTED CODE PATH`.
- [ ] Copy every unresolved divergence into Phase 15.19 with the same severity,
      spec excerpt, code evidence, confidence score, and remediation target.
- [ ] Do not mark local cleanup complete while any Critical, High, or
      security-relevant Medium finding remains open, unless it is explicitly a
      deployment-only item moved to Phase 16 with evidence.

Validation checklist:

- [ ] The audit report exists and cites exact line references for every finding.
- [ ] Phase 15.19 is populated from the audit report or explicitly marked empty
      with report evidence.
- [ ] `rtk git diff --check`.

## Phase 15.19: Spec-To-Code Compliance Findings Remediation

This phase is intentionally empty until Phase 15.18 produces the final
spec-to-code compliance report. Populate it directly from that report.

Historical audit status:

- [x] Reconciled
      `docs/audits/router-a-b-spec-to-code-compliance-2026-06-16.md` after
      checking the follow-up implementation. The historical P1 private-worker
      boundary issue, P1 ECDSA explicit export audit issue, P2 Ed25519
      finalize group-key hardening issue, P3 stale-checklist drift, and P3
      Router A/B ECDSA bridge naming issue are marked fixed locally in the audit
      report. The only remaining item from that historical audit is deployed
      strict Cloudflare browser/runtime evidence, which is tracked in Phase 16.

Rules for adding findings:

- [ ] Add each finding as a checklist item with severity, affected spec section,
      affected code path, confidence score, and remediation target.
- [ ] Keep Critical and High findings as local cleanup blockers.
- [ ] Keep security-relevant Medium findings as local cleanup blockers unless
      their evidence proves they are Cloudflare-deployment-only and they are
      moved to Phase 16.
- [ ] Resolve Low documentation drift by updating or tombstoning stale docs,
      tests, and harnesses that can reintroduce old threshold-session behavior.
- [ ] After remediation, rerun the focused validation listed in the finding and
      update the corresponding checklist item with the command and result.

## Completion Criteria

- [x] No active SDK signing flow can call `/threshold-ed25519/*` routes for
      signing authorization, presign refill, or signing finalization.
- [x] No active NEAR/Ed25519 SDK signing flow imports
      `buildNearWorkerSigningEnvelope`, accepts `ThresholdSignerConfig`, or
      carries `thresholdSessionKind`/`thresholdSessionAuthToken` through a
      Router A/B signing payload.
      Active transaction, delegate, and NEP-413 signing now consume
      `walletSessionJwt` from `RouterAbEd25519NormalSigningReadyState`, and the
      guard rejects `thresholdSessionAuthToken`, `thresholdSessionKind`,
      `ThresholdSignerConfig`, and `buildNearWorkerSigningEnvelope` in those
      files.
- [x] No active SDK signing flow can call `/threshold-ecdsa/*` routes for
      signing authorization, presign sessions, or signing finalization.
- [x] Live ECDSA pool-fill requests reject missing `poolFill`; any retained
      `local_threshold_ecdsa_presignature_pool` parsing is isolated to
      persisted-record compatibility with deletion criteria.
- [x] No active SDK signing flow imports or calls
      `authorizeEcdsaWithSession`, `signThresholdEcdsaDigestWithPool`,
      `tryFinalizeThresholdEd25519NearTransactionPresign`,
      `tryFinalizeThresholdEd25519SignatureOnlyPresign`,
      `finalizeThresholdEd25519Presign`, or
      `refillThresholdEd25519PresignPool`.
- [x] No Express or Cloudflare server exposes old public threshold signing
      routes.
- [x] No active signing state requires `thresholdSessionAuthToken`.
      ECDSA ready signing now uses `walletSessionJwt` from
      `routerAbEcdsaHssNormalSigning`; Ed25519 and ECDSA active export callers
      now pass Wallet Session JWTs at their public flow boundary, and ECDSA
      export material resolves route auth through the Wallet Session boundary
      resolver. The active Email OTP ECDSA export worker request now sends JWT
      material through Wallet Session route auth only, and the Ed25519 HSS
      helper boundary takes `walletSessionJwt`. The lower-level ECDSA export
      worker helper is also Wallet Session JWT-only. Current ECDSA key refs now
      carry `walletSessionJwt` and reject `thresholdSessionAuthToken`.
      Persisted and sealed signing-session records now also write
      `walletSessionJwt`;
      remaining old auth names are confined to negative type/source-guard
      fixtures.
- [x] Server Wallet Session stores no longer use `AuthSession` type, factory,
      parser, file, helper, or test names.
- [x] Ed25519 product signing flows pass through Router A/B only.
- [x] ECDSA product signing flows pass through Router A/B only.
- [x] Source guards fail if old public signing routes or old threshold-session
      signing auth are reintroduced.
      `routerAbNormalSigningSdk.guard.unit.test.ts` now treats the deleted
      public signing routes and SDK helper names as zero-tolerance tokens, and
      separately rejects old threshold-session auth fields in active Router A/B
      ECDSA and Ed25519 signing modules.
- [x] Local smoke, focused tests, type-checks, release guards, and staging
      dry-run all pass.
- [x] Local Rust `pnpm router` ECDSA-HSS route parity is proven over live HTTP:
      pool-fill put, public prepare, public finalize, one-use pool entry
      consumption, and one-use request-bound presignature consumption all pass in
      split-worker and bundled local topologies.
- [ ] Active TypeScript SDK signing orchestration holds no raw crypto-secret
      Ed25519 or ECDSA client material. It may persist and route worker material
      handles, binding digests, public facts, session ids, Wallet Session JWTs,
      and SigningWorker scopes only.
- [ ] Raw-material compatibility code has been deleted after the worker-handle
      model is active. Old development records with raw signable material are
      invalidated at a boundary instead of being hydrated into active signing
      state.
- [x] No signing-capable public lifecycle endpoint remains under
      `/threshold-ed25519/*`, `/threshold-ecdsa/*`, or
      `/threshold/signing-session-seal/*`. Any retained threshold-named route is
      either a non-signing compatibility boundary with a deletion date, or has
      been moved to a private service-bound/module-local surface.
      Old public lifecycle route literals are now confined to this cleanup plan,
      negative route assertions, and source-guard deny-lists. Active SDK/server
      callers use Router A/B or Wallet Session route constants.
- [x] Deployed Cloudflare evidence is excluded from local cleanup completion and
      tracked as a separate post-deployment release gate in Phase 16.
- [ ] Phase 15.18 spec-to-code compliance audit is complete, the report is
      committed under `docs/audits/`, and Phase 15.19 contains every unresolved
      finding from the report.
- [ ] Phase 15.19 has no open Critical, High, or security-relevant Medium
      finding before Phase 16 Cloudflare evidence work resumes.

## Phase 16: Post-Deployment Cloudflare Evidence

Start this phase after the local cleanup plan is reviewed, Phase 15.8 local
ECDSA-HSS route parity is closed if local ECDSA end-to-end evidence is required,
and the Cloudflare deployment configuration has been hardened. This phase is the
deployed-runtime release-tail gate for production deployment.

- [x] Run the local release blocker check before any upload attempt.
      `rtk pnpm router:deploy:check` passed on June 17, 2026 with
      "Router A/B release blockers clear."
- [x] Run the non-mutating staging startup dry-run for all four strict Workers.
      `rtk pnpm router:deploy:dry-run -- --env staging` passed on
      June 17, 2026 and wrote an ignored timestamped report under
      `crates/router-ab-cloudflare/reports/startup-latencies/`.
      Dry-run gzip sizes: Router `932.46 KiB`, Deriver A `792.16 KiB`,
      Deriver B `792.72 KiB`, SigningWorker `974.57 KiB`.
- [x] Create a local commit for the current cleanup implementation before using
      the GitHub deployment workflow. Completed in local commit `615fcf24b`
      (`Complete Router A/B lifecycle route migration`).
- [ ] Add Cloudflare internal service-auth secret provisioning before any
      upload/deploy. All four strict Workers now read the binding named by
      `ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET_BINDING` and use
      `ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET` for private cross-worker service
      calls, but the deployment workflow currently only provisions the older
      role secrets. Add one high-entropy shared internal service-auth secret to
      keygen output, GitHub environment docs, workflow secret checks, and
      `wrangler secret put` for Router, Deriver A, Deriver B, and
      SigningWorker. Add a release check proving the binding name and secret
      provisioning contract are present for every role.
- [ ] Make release validation reject placeholder Cloudflare runtime values.
      `router:deploy:check` must fail for production/staging deploy paths when
      Wrangler or injected workflow values contain `issuer.example`,
      `REPLACE_WITH`, `<...>` placeholders, repeated dummy X25519 public keys
      such as `x25519:111...`, or malformed JWT issuer/JWKS/public-key values.
      Keep checked-in placeholder Wrangler values only as dry-run templates, and
      make the deploy workflow prove real GitHub Environment values override
      them.
- [ ] Promote key epochs into the deploy contract. Current Wrangler files fix
      signer-envelope HPKE, peer-signing, and SigningWorker server-output epochs
      to `epoch-1` while the workflow injects only key material. Add explicit
      deploy variables for the current epochs, or derive epochs from public-key
      fingerprints. Add a release check that a changed deployed public key cannot
      reuse the previous epoch, and include the optional previous-key overlap
      variables in the rotation procedure.
- [ ] Decide and guard production Router `workers_dev` exposure. Deriver A,
      Deriver B, and SigningWorker are guarded against `workers_dev = true`, but
      production Router still enables workers.dev. Either set the production
      Router to `workers_dev = false` with a route/custom-domain deployment, or
      document workers.dev as intentional public exposure and add an explicit
      release-check assertion for that decision.
- [ ] Remove or isolate local-machine compiler fallbacks from release scripts.
      Homebrew-specific `CC_wasm32_unknown_unknown` fallback behavior is useful
      for local smoke commands, but release validation should use an explicit
      CI/toolchain setup and fail clearly when the wasm compiler is missing.
      Keep any fallback in local-only commands, or emit an obvious diagnostic
      when it is used.
- [ ] Push the local cleanup implementation commits to `dev` before using the
      GitHub deployment workflow. The workflow runs the remote ref, so an upload
      from unpushed local commits would deploy stale code.
- [ ] Configure upload/deploy credentials for staging. Local Wrangler is not
      logged in, and the current GitHub environment has public Router A/B key
      variables plus private role keys, while `CLOUDFLARE_API_TOKEN`,
      `CLOUDFLARE_ACCOUNT_ID`, `SIGNER_A_ROOT_SHARE_WIRE_SECRET`, and
      `SIGNER_B_ROOT_SHARE_WIRE_SECRET` are still missing from the workflow
      secret surface. This must also include
      `ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET` after the service-auth deploy
      contract is added.
- [ ] Re-run `rtk pnpm router:deploy:check` and
      `rtk pnpm router:deploy:dry-run -- --env staging` after the deployment
      hardening tasks above. The June 17, 2026 passing evidence predates the
      Cloudflare deployment-config audit and is no longer sufficient by itself.
- [ ] Deploy or upload the cleaned Router A/B workers to staging.
- [ ] Capture deployed browser evidence for Ed25519 `/v2/router-ab/ed25519/sign/prepare`,
      `/v2/router-ab/ed25519/sign/presign-pool/prepare`, and `/v2/router-ab/ed25519/sign`.
- [ ] Capture deployed browser evidence for ECDSA-HSS Router A/B registration,
      activation, prepare, finalize, and pool-fill dependent signing.
- [ ] Confirm configured-origin success, rejected-origin behavior, preflight
      behavior, and timing with preflight included.
- [ ] Confirm Cloudflare logs and metrics show no Deriver A/B invocation on
      normal Ed25519 or ECDSA signing.
- [ ] Confirm no deployed public route serves old `/threshold-ed25519/*` or
      `/threshold-ecdsa/*` signing endpoints.
- [ ] Record final deployed Cloudflare evidence that confirms Router A/B-only
      Ed25519 and ECDSA signing behavior.

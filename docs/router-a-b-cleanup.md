# Router A/B Cleanup Plan

Date created: June 16, 2026

Status: local signing cleanup review-ready, with one remaining local API
architecture cleanup phase now open for the threshold-era lifecycle endpoints.
Ed25519 and ECDSA signatures are signed only through Router A/B in the active
SDK/server signing paths. Remaining Cloudflare deployed-runtime checks are
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

Remaining local cleanup work:

- Phase 15.5 owns the remaining `/threshold-ed25519/*` and
  `/threshold-ecdsa/*` lifecycle endpoints that are not old product signing
  finalizers, but still expose threshold-era public API names and can mint or
  hydrate signing-capable state.
- Post-deployment Cloudflare browser/runtime evidence is tracked in Phase 16.

Current Router A/B private worker routes such as
`/router-ab/v1/signing-worker/sign`, `/router-ab/v1/signing-worker/sign/prepare`,
and `/router-ab/v1/signing-worker/ecdsa-hss/sign` are active internal
cross-worker protocol routes. Keep them until the Router A/B protocol itself
gets a new durable wire version.

Current deletion blockers:

- Phase 15.5 must classify each remaining threshold lifecycle endpoint as
  deleted, Router A/B public, private service-bound, or persistence/request
  boundary only. No endpoint should keep a threshold-era public route name if it
  can mint, hydrate, export, or continue signing-capable state.
- Post-deployment Cloudflare browser/runtime evidence remains the production
  release-tail blocker in Phase 16.

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
| Ed25519 NEAR transaction | `signTransactions` | Pool hit: `/v2/hss/sign`; pool miss: `/v2/hss/sign/prepare` then `/v2/hss/sign`; refill: `/v2/hss/sign/presign-pool/prepare` | `/router-ab/v1/signing-worker/sign*` | `/threshold-ed25519/*` public signing routes deleted and guarded | `thresholdEd25519.presignPool.unit.test.ts`, `routerAbNormalSigningVectors.unit.test.ts`, `routerAbNormalSigningSdk.guard.unit.test.ts` |
| Ed25519 NEP-413 message | `signNep413` | Pool hit: `/v2/hss/sign`; pool miss: `/v2/hss/sign/prepare` then `/v2/hss/sign`; refill: `/v2/hss/sign/presign-pool/prepare` | `/router-ab/v1/signing-worker/sign*` | `/threshold-ed25519/*` public signing routes deleted and guarded | `thresholdEd25519.presignPool.unit.test.ts`, `routerAbNormalSigningVectors.unit.test.ts`, `routerAbNormalSigningSdk.guard.unit.test.ts` |
| Ed25519 NEP-461 delegate action | `signDelegate` | Pool hit: `/v2/hss/sign`; pool miss: `/v2/hss/sign/prepare` then `/v2/hss/sign`; refill: `/v2/hss/sign/presign-pool/prepare` | `/router-ab/v1/signing-worker/sign*` | `/threshold-ed25519/*` public signing routes deleted and guarded | `thresholdEd25519.presignPool.unit.test.ts`, `routerAbNormalSigningVectors.unit.test.ts`, `routerAbNormalSigningSdk.guard.unit.test.ts` |
| ECDSA-HSS EVM digest | `signEvmFamily` | Sign: `/v1/hss/ecdsa/sign/prepare` then `/v1/hss/ecdsa/sign`; pool fill: `/v1/hss/ecdsa/presignature-pool/fill/init` and `/v1/hss/ecdsa/presignature-pool/fill/step` | `/router-ab/v1/signing-worker/ecdsa-hss/sign*` and `/router-ab/v1/signing-worker/ecdsa-hss/presignature-pool/put` | `/threshold-ecdsa/*` public signing and presign routes deleted and guarded | `routerAbEcdsaHssNormalSigning.unit.test.ts`, `thresholdEcdsa.presignPoolRefill.unit.test.ts`, `routerAbNormalSigningSdk.guard.unit.test.ts` |

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
      packages. Wrote startup report:
      `crates/router-ab-cloudflare/reports/startup-latencies/startup-latencies-2026-06-16T18-58-46-840Z.json`.

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
      response binding for 250 iterations. Evidence report:
      `crates/router-ab-dev/reports/local-release-evidence/local-release-evidence-2026-06-17-command.json`
      recorded average local protocol prepare/finalize binding time at 934 us.
      This is local protocol timing evidence; deployed runtime/browser evidence
      remains Phase 16.
- [x] Ed25519 pool-hit and pool-miss timing evidence.
      Completed with the same local Router A/B release-evidence harness:
      `rtk pnpm router:evidence -- --out
      crates/router-ab-dev/reports/local-release-evidence/local-release-evidence-2026-06-17-command.json`.
      The harness exercises `/v2/hss/sign/presign-pool/prepare`, pool-hit
      `/v2/hss/sign` lowering to the v2 finalize shape, and pool-miss
      `/v2/hss/sign/prepare` plus `/v2/hss/sign` protocol parsing for 250
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
      `ensureThresholdEd25519HssClientBase` and
      `repairThresholdEd25519MissingRelayerKey` are still valid only if they
      repair current HSS client-base material and retry Router A/B signing. If a
      branch exists only to recover the old relayer authorize/sign route path,
      delete it. If the repair path remains current, test that the retry still
      signs through Router A/B prepare/finalize and never calls
      `/threshold-ed25519/*`.
      Completed by retaining the repair path as HSS client-base reconstruction,
      feeding it `walletSessionJwt` from the Router A/B Ed25519 ready state, and
      adding a source guard that requires transaction, delegate, and NEP-413
      repair branches to rebuild the Router A/B payload and retry their Router
      A/B signing executor without old `/threshold-ed25519/*` route references
      or legacy auth reads.
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
This phase owns the remaining `/threshold-ed25519/*` and `/threshold-ecdsa/*`
lifecycle endpoints. These routes are not the old product signing finalizers,
but several of them still mint sessions, bootstrap HSS state, resolve key
identity, export server-side material, or continue protocol state. That means
they can still create Router A/B-incomplete signing state, as seen in the
current wallet-unlock regressions.

Start this before treating local cleanup as complete for deployment. The goal is
to make the public API read as Router A/B and Wallet Session architecture from
the first request that creates signing-capable state.

Safety constraints for this phase:

- Do not delete a lifecycle endpoint until every active SDK/server caller has a
  Router A/B-compatible replacement route, typed request builder, parser, and
  focused test.
- Signing-capable Ed25519 session responses must include
  `routerAbNormalSigning`, runtime-policy scope, SigningWorker identity, and a
  bearer Wallet Session JWT. A route that cannot provide those fields must fail
  before the SDK stores a signable record.
- Signing-capable ECDSA-HSS records must include
  `routerAbEcdsaHssNormalSigning` with stable key context, public identity,
  SigningWorker identity, activation epoch, and normalized participants.
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
| `GET /threshold-ecdsa/healthz` | Public health probe for the threshold ECDSA service. | Rename or consolidate behind the Router A/B health route. Delete the threshold-named route once scripts and tests use the Router A/B health endpoint. |
| `POST /threshold-ecdsa/key-identities` | Resolves ECDSA key identities for an active Ed25519 session. | Replace with a Router A/B ECDSA-HSS identity route or fold the identity lookup into registration/bootstrap and activation refresh responses. The public response should use public identity, stable key context, activation epoch, SigningWorker identity, and keyset version terms. Avoid exposing legacy `relayerKeyId` or local server-share identifiers outside a parser boundary. |
| `POST /threshold-ecdsa/hss/bootstrap` | ECDSA-HSS role-local bootstrap route. | Replace active SDK usage with the strict Router A/B ECDSA-HSS registration/bootstrap route described in `router-a-b-ecdsa.md`. The new route must route Deriver A/B through Router A/B, activate the SigningWorker, and persist `routerAbEcdsaHssNormalSigning`. The SDK bootstrap parser must reject any signing-capable ECDSA record that lacks Router A/B ECDSA-HSS normal-signing state. |
| `POST /threshold-ecdsa/hss/export/share` | Releases an authorized ECDSA-HSS server-side export share. | Replace with the Router A/B ECDSA-HSS export route. Scope it by Wallet Session JWT, export request id, recipient class, public identity, activation epoch, and explicit user intent. Keep any legacy field conversion only inside the export request parser, then delete the threshold-named public route after SDK export callers move. |
| `POST /threshold-ecdsa/internal/cosign/init` | Public route labelled internal, currently gated by threshold protocol state. | Audit callers and either delete it or move it behind private Router A/B service auth. The route must not remain public if it can influence ECDSA signing, presignature generation, or server-share state. |
| `POST /threshold-ecdsa/internal/cosign/finalize` | Public route labelled internal, currently gated by threshold protocol state. | Same as ECDSA cosign init. Add tests that the public router no longer registers `/threshold-ecdsa/internal/cosign/*` once the replacement is wired. |

Implementation checklist:

- [ ] Build a caller inventory for every endpoint above. Include SDK clients,
      iframe wallet calls, local dev harnesses, Express routes, Cloudflare
      routes, route definitions, CORS inventories, tests, scripts, and docs.
- [ ] Split the inventory into product lifecycle groups: Wallet Session
      issuance, Ed25519 HSS lifecycle, ECDSA-HSS identity/bootstrap,
      ECDSA-HSS export, internal cosign continuation, and health probes.
- [ ] Define the Router A/B public route names and request/response schemas for
      each group. Prefer a small number of cohesive Wallet Session or Router
      A/B lifecycle routes over one-for-one legacy route renames when a unified
      route makes invalid state harder to represent.
- [ ] Implement the Ed25519 Wallet Session replacement first. Make
      `routerAb.normalSigning.mode="enabled"` the only SDK/server signing
      configuration for product signing, and reject local startup or session
      issuance when `signingWorkerId` or `ROUTER_AB_NORMAL_SIGNING_WORKER_ID`
      is missing.
- [ ] Move Ed25519 HSS prepare/respond/finalize callers to Router A/B-named
      routes or private helpers. Add unlock-to-sign regression tests proving
      Ed25519 records are Router A/B-ready before `signTransactions`,
      `signNep413`, or `signDelegate` runs.
- [ ] Move ECDSA identity/bootstrap callers to Router A/B ECDSA-HSS routes.
      Add unlock-to-EVM-sign regression tests proving ECDSA records carry
      `routerAbEcdsaHssNormalSigning` before `signEvmFamily` builds a ready
      signer session.
- [ ] Move ECDSA export callers to Router A/B ECDSA-HSS export routes and keep
      legacy field normalization only at the export request parser boundary.
- [ ] Delete or privatize both Ed25519 and ECDSA `internal/cosign` routes. Add
      route-definition and source-guard checks that fail if public
      `/threshold-*/internal/cosign/*` routes return.
- [ ] Rename or consolidate health routes after functional lifecycle routes are
      migrated.
- [ ] Delete the old threshold lifecycle route definitions, Express handlers,
      Cloudflare handlers, SDK route clients, CORS entries, route docs, stale
      tests, and guard allowlists after each replacement route is proven.
- [ ] Update completion criteria so local cleanup cannot be complete while any
      signing-capable public lifecycle route remains under
      `/threshold-ed25519/*` or `/threshold-ecdsa/*`.

Validation checklist:

- [ ] `rtk pnpm -C packages/sdk-web type-check`.
- [ ] `rtk pnpm -C packages/sdk-server-ts type-check`.
- [ ] Focused SDK tests for wallet unlock followed by Ed25519 transaction,
      NEP-413, and delegate signing with Router A/B-ready persisted records.
- [ ] Focused SDK tests for wallet unlock or activation followed by ECDSA EVM
      signing with Router A/B-ready persisted records.
- [ ] Route-level tests proving old public lifecycle endpoints return 404 after
      their replacements land.
- [ ] Source guards proving old public signing routes, old public lifecycle
      routes, old SDK helpers, and old threshold-session auth names cannot
      re-enter active SDK/server routing.
- [ ] `rtk pnpm -C tests run test:threshold-core`.
- [ ] `rtk git diff --check`.

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
- [ ] No signing-capable public lifecycle endpoint remains under
      `/threshold-ed25519/*` or `/threshold-ecdsa/*`. Any retained
      threshold-named route is either a non-signing compatibility boundary with
      a deletion date, or has been moved to a private service-bound/module-local
      surface.
- [x] Deployed Cloudflare evidence is excluded from local cleanup completion and
      tracked as a separate post-deployment release gate in Phase 16.

## Phase 16: Post-Deployment Cloudflare Evidence

Start this phase after the local cleanup plan is reviewed and the cleaned Router
A/B workers are deployed or uploaded to staging. This phase is the release-tail
gate for production deployment, not a blocker for reviewing the local cleanup
implementation.

- [ ] Deploy or upload the cleaned Router A/B workers to staging.
- [ ] Capture deployed browser evidence for Ed25519 `/v2/hss/sign/prepare`,
      `/v2/hss/sign/presign-pool/prepare`, and `/v2/hss/sign`.
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

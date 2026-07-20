# Router A/B Diff Review Inventory

Status: active audit tracker
Last updated: 2026-06-18

This file tracks which files have been reviewed during the Router A/B cleanup audit so follow-up passes can cover new slices instead of revisiting the same area.

## Diff Size Snapshot

Observed source-control UI count: approximately `+546k / -59k`.

Git tracked diff snapshot:

- Tracked modified/deleted files: `+48,670 / -68,676`
- Normal untracked files: approximately `+23,123`
- The much larger UI addition count appears to include ignored/generated outputs, especially Rust `target` directories, Node/Vite build output, and dependency caches.

Initial conclusion: the source diff is still broad and needs slimming, but the `+546k` number is not an accurate source-code bloat measure.

## Reviewed Slices

### Server Router A/B ECDSA-HSS Route And Service Boundaries

Reviewed files:

- `packages/sdk-server-ts/src/core/ThresholdService/validation.ts`
- `packages/sdk-server-ts/src/core/ThresholdService/stores/EcdsaSigningStore.ts`
- `packages/sdk-server-ts/src/core/ThresholdService/stores/CloudflareDurableObjectStore.ts`
- `packages/sdk-server-ts/src/core/ThresholdService/routerAb/ecdsaHssPoolFillHandlers.ts`
- `packages/sdk-server-ts/src/router/commonRouterUtils.ts`
- `packages/sdk-server-ts/src/router/routerAbPrivateSigningWorker.ts`
- `packages/sdk-server-ts/src/router/express/routes/thresholdEcdsa.ts`
- `packages/sdk-server-ts/src/router/cloudflare/routes/thresholdEcdsa.ts`
- `packages/shared-ts/src/utils/routerAbEcdsaHss.ts`

Flagged issues:

- ECDSA-HSS Wallet Session claim parser does not fully bind embedded Router A/B normal-signing scope back to top-level JWT claims.
- Signing-capable ECDSA routes still use generic `session.parse(headers)`, which may accept cookie-backed credentials.
- Cloudflare ECDSA pool-fill route does not pass the same forwarding/auth transport metadata as Express.
- Private ECDSA scope comparison uses `JSON.stringify`.
- Non-Postgres ECDSA presignature stores can enqueue duplicate presignature ids.

### SDK Router A/B Signing State And Client Boundary

Reviewed files:

- `packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519PresignFinalize.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signNear/signTransactions.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signNear/signDelegate.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signNear/signNep413.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signNear/shared/routerAbWalletSessionCredential.ts`
- `packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/routerAbEcdsaWalletSessionAuth.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/walletSessionAuthBoundary.ts`
- `packages/sdk-web/src/core/signingEngine/session/walletSessionAuthBoundary.ts`
- `packages/sdk-web/src/core/signingEngine/threshold/ed25519/hssClientBase.ts`
- `packages/sdk-web/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.ts`
- `packages/sdk-web/src/core/signingEngine/workerManager/workers/hss-client.worker.ts`
- `packages/sdk-web/src/core/types/signer-worker.ts`
- `wasm/hss_client_signer/src/threshold_hss.rs`

Flagged issue classes:

- Too much cryptographic material assembly is happening in TypeScript instead of wasm/signer-core boundaries.
- Final signing paths became Router A/B-only before all upstream issuance, restore, and bootstrap paths produced a fully bound Router A/B-ready state.
- Some helpers accept broad session/auth shapes where narrow Wallet Session Router A/B signing state should be required.

### Rust Router A/B Cloudflare And Local Dev Runtime

Reviewed files:

- `crates/router-ab-cloudflare/src/lib.rs`
- `crates/router-ab-cloudflare/src/strict_worker.rs`
- `crates/router-ab-cloudflare/src/durable_object.rs`
- `crates/router-ab-cloudflare/Cargo.toml`
- `crates/router-ab-cloudflare/package.json`
- `crates/router-ab-cloudflare/scripts/assert-release-ready.mjs`
- `crates/router-ab-cloudflare/scripts/measure-startup-latencies.mjs`
- `crates/router-ab-cloudflare/scripts/measure-strict-workers.mjs`
- `crates/router-ab-cloudflare/wrangler.router.toml`
- `crates/router-ab-cloudflare/wrangler.signer-a.toml`
- `crates/router-ab-cloudflare/wrangler.signer-b.toml`
- `crates/router-ab-cloudflare/wrangler.signing-worker.toml`
- `crates/router-ab-dev/src/lib.rs`
- `crates/router-ab-dev/src/bin/router_ab_local_worker.rs`
- `crates/router-ab-dev/src/bin/router_ab_local_bundled.rs`
- `crates/router-ab-dev/src/bin/router_ab_local_smoke.rs`
- `crates/router-ab-dev/tests/local_worker_http.rs`

Flagged issue classes:

- Strict-worker combined entrypoint and role-env parsing are stale if per-role deployment is the intended architecture.
- Local Rust ECDSA-HSS route parity needed private service auth and admitted-envelope forwarding.
- Some release checks used stale function names after Deriver naming cleanup.
- Generated startup reports should not accumulate as committed source artifacts.

### Router A/B Core Protocol And Bloat Candidates

Reviewed files:

- `crates/router-ab-core/src/derivation/context.rs`
- `crates/router-ab-core/src/derivation/mod.rs`
- `crates/router-ab-core/src/derivation/bench.rs`
- `crates/router-ab-core/src/protocol/normal_signing.rs`
- `crates/router-ab-core/src/protocol/ecdsa_hss.rs`
- `crates/router-ab-core/src/protocol/engine/deriver_a.rs`
- `crates/router-ab-core/src/protocol/engine/deriver_b.rs`
- `crates/router-ab-core/src/protocol/engine/host.rs`
- `crates/router-ab-core/tests/ecdsa_hss_protocol.rs`
- `crates/router-ab-core/tests/normal_signing_v2.rs`

Flagged issue classes:

- Old split-root derivation candidate types look stale after API removal.
- Runtime library API appears to expose benchmark/evidence helpers that could live in benches/docs.
- Thin engine/host wrappers may no longer justify their abstraction cost.

### SDK Passkey, Email OTP, Warm Capability, And Sealed Restore Boundaries

Reviewed files:

- `packages/sdk-web/src/core/signingEngine/session/passkey/ed25519SessionProvision.ts`
- `packages/sdk-web/src/core/signingEngine/session/passkey/ecdsaSessionProvision.ts`
- `packages/sdk-web/src/core/signingEngine/session/passkey/ecdsaBootstrap.ts`
- `packages/sdk-web/src/core/signingEngine/session/passkey/ecdsaRecovery.ts`
- `packages/sdk-web/src/core/signingEngine/session/passkey/ed25519Recovery.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/provisioning.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/ed25519Recovery.ts`
- `packages/sdk-web/src/core/signingEngine/session/persistence/records.ts`
- `packages/sdk-web/src/core/signingEngine/session/sealedRecovery/recoveryRecord.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/walletSessionAuthBoundary.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/routerAbEcdsaWalletSessionAuth.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/readModel.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/capabilityReaderCore.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/types.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ecdsaProvisionPlan.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaSelection.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaMaterialState.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/readySecp256k1Material.ts`
- `packages/sdk-web/src/core/rpcClients/relayer/thresholdEcdsa.ts`
- `packages/sdk-web/src/core/signingEngine/threshold/ecdsa/activation.ts`

Flagged issue classes:

- Warm capability readiness can still mark ECDSA cookie records as ready because JWT auth is required only when `thresholdSessionKind === "jwt"`.
- Ed25519/ECDSA persisted records can be normalized as live by budget without requiring Router A/B signing state and signing material.
- Router A/B normal signing remains optional at some provisioning boundaries when config mode is disabled, creating non-signable records.
- ECDSA route-client types still expose `cookie`, `threshold_session`, and `sessionKind?: "cookie"` compatibility branches.
- Passkey ECDSA sealed restore uses an ad hoc fresh-map upsert; it reaches the global in-memory store, but bypasses dependency-scoped indices/artifacts and should be made explicit or removed.

### Server Router A/B Ed25519, Seal, And Budget Boundaries

Reviewed files:

- `packages/sdk-server-ts/src/router/express/routes/thresholdEd25519.ts`
- `packages/sdk-server-ts/src/router/cloudflare/routes/thresholdEd25519.ts`
- `packages/sdk-server-ts/src/router/commonRouterUtils.ts`
- `packages/sdk-server-ts/src/router/routeDefinitions.ts`
- `packages/sdk-server-ts/src/router/routeAuthPolicy.ts`
- `packages/sdk-server-ts/src/router/signingBudgetStatus.ts`
- `packages/sdk-server-ts/src/core/SessionService.ts`
- `packages/sdk-server-ts/src/core/ThresholdService/ThresholdSigningService.ts`
- `packages/sdk-server-ts/src/core/ThresholdService/routerAbNormalSigningPolicy.ts`
- `packages/sdk-server-ts/src/threshold/session/signingSessionSeal/index.ts`
- `packages/sdk-server-ts/src/threshold/session/signingSessionSeal/options.ts`
- `packages/sdk-server-ts/src/threshold/session/signingSessionSeal/policy/sessionPolicy.ts`
- `packages/sdk-server-ts/src/threshold/session/signingSessionSeal/routesOptions.ts`
- `packages/sdk-server-ts/src/threshold/session/signingSessionSeal/service.ts`
- `packages/sdk-server-ts/src/threshold/session/signingSessionSeal/transport/cloudflare.ts`
- `packages/sdk-server-ts/src/threshold/session/signingSessionSeal/transport/express.ts`
- `packages/sdk-server-ts/src/threshold/session/signingSessionSeal/transport/shared.ts`
- `packages/sdk-server-ts/src/threshold/session/signingSessionSeal/types.ts`
- `packages/shared-ts/src/utils/signingSessionSeal.ts`

Flagged issue classes:

- Router A/B signing-capable validators, budget status, and seal authorization still call generic `session.parse(headers)`, which accepts cookies when no bearer token is present.
- The central route registry still models Router A/B Wallet Session routes as generic `threshold_session` routes, and the budget status route is mislabeled as Ed25519-only even though the parser accepts ECDSA and Ed25519.
- Shared sealed signing-session restore metadata still permits `sessionKind: "cookie"` and optional Wallet Session/Router A/B material, keeping invalid active restore states representable outside a narrow compatibility parser.
- The wallet signing-budget store is intentionally shared across curves but is named and wired through the Ed25519 wallet-session store, which makes the ECDSA budget path hard to reason about and easy to misconfigure.

### SDK Runtime Package Fold And Public Export Slice

Reviewed files:

- `package.json`
- `packages/sdk-runtime-ts/package.json`
- `packages/sdk-runtime-ts/src/index.ts`
- `packages/sdk-runtime-ts/src/runtime/createSigningRuntime.ts`
- `packages/sdk-runtime-ts/src/runtime/index.ts`
- `packages/sdk-runtime-ts/src/runtime/runtimeConfig.typecheck.ts`
- `packages/sdk-runtime-ts/src/runtime/types.ts`
- `packages/sdk-runtime-ts/tsconfig.json`
- `packages/sdk-web/package.json`
- `packages/sdk-web/rolldown.config.ts`
- `packages/sdk-web/build-paths.ts`
- `packages/sdk-web/src/runtime.ts`
- `packages/sdk-web/src/core/runtime/createSigningRuntime.ts`
- `packages/sdk-web/src/core/runtime/index.ts`
- `packages/sdk-web/src/core/runtime/types.ts`
- `packages/sdk-web/src/SeamsWeb/assembly/createBrowserSigningRuntime.ts`
- `tests/unit/refactor67ReorgFolders.guard.unit.test.ts`
- `tests/unit/refactor51bPlatformBoundaries.guard.unit.test.ts`
- `tests/unit/refactor54Simplify.guard.unit.test.ts`
- `tests/unit/signingRuntime.construction.unit.test.ts`

Flagged issue classes:

- Resolved locally on June 18, 2026: the deleted runtime package exported
  `createSigningRuntime`, and the folded public `@seams/sdk/runtime` entry now
  exports `createSigningRuntime` and `createSigningRuntimeStatePorts` with
  focused package/export guard coverage.
- Partially resolved locally on June 18, 2026: `packages/sdk-web` still
  publishes server subpaths, but `pg` and `@simplewebauthn/server` are no longer
  hard browser dependencies. They are optional peers/dev dependencies. The
  remaining packaging bloat is the larger decision to keep those server subpaths
  or create a separate public server package.
- `core/runtime` is still tightly coupled to web SDK internals through `@/...` imports, `WorkerOperationContext`, signing-engine persistence records, and browser assembly ports. The fold is acceptable as bloat reduction, but it confirms this is not a reusable platform-neutral runtime boundary yet.
- Resolved locally on June 18, 2026: focused package/export tests now prove
  `@seams/sdk/runtime` keeps the intended value exports after the package fold
  and keeps server-only packages out of hard browser dependencies.

### Cleanup And Architecture Planning Docs

Reviewed files:

- `docs/router-a-b-SPEC.md`
- `docs/router-a-b-SPEC.md`
- `docs/router-a-b-SPEC.md`
- `docs/router-a-b-SPEC.md`
- `docs/router-a-b-SPEC.md`
- `docs/refactor-68-wallet-session-v2.md`
- `docs/refactor-69-rename-id.md`
- `docs/refactor-69B-reduce-bloat.md`
- `docs/refactor-70-passkey-account-refactor.md`
- `docs/refactor-71-delegate-wallets.md`
- `docs/refactor-72-share-rotation.md`

Flagged issue classes:

- Older signer/spec docs implied Ed25519-only deployment readiness after ECDSA-HSS became required.
- Cleanup plan needed explicit endpoint migration, strict claim boundaries, and local Rust ECDSA-HSS route parity tasks.
- Refactor ordering needed stale-plan triage before larger passkey/delegation/share-rotation work.

## Still Needing Review

- `packages/sdk-web/src/core/signingEngine/session/passkey/*` files not listed in the passkey/email-OTP slice above
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/*` files not listed in the passkey/email-OTP slice above
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/*` files not listed in the passkey/email-OTP slice above
- `tests/unit/*` and `tests/e2e/*` for obsolete behavior that still encodes legacy threshold-session semantics
- `voiceId/*` changes, which the audit intentionally deferred for a later VoiceID-specific review

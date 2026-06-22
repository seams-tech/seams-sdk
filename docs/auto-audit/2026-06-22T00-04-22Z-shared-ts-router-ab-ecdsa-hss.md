# Auto Audit Report

- Timestamp: `2026-06-22T00:04:22Z`
- Target file: `packages/shared-ts/src/utils/routerAbEcdsaHss.ts`
- Flow: `Wallet SDK Router A/B ECDSA-HSS wire parser, JWT rehydration, request digest binding, and active-session identity`

## Scope / Call Graph Summary

This audit focused on [`/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts`](/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts), with the wallet SDK and Rust protocol paths that consume its typed state, request digests, and active-session identifiers.

- Direct local imports inside the target file:
  - `./encoders::{base64UrlDecode, base64UrlEncode}`
  - `./sessionTokens::{decodeJwtPayloadRecord, ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND}`

- Direct internal responsibilities inside the target file:
  - Scope parsing and canonicalization for `RouterAbEcdsaHssNormalSigningScopeV1`
  - Wallet-session JWT rehydration through `parseRouterAbEcdsaHssNormalSigningFromWalletRegistrationJwtV1`
  - Prepare/finalize request digest computation and response/request matching
  - Active-state session id derivation through `routerAbEcdsaHssActiveStateSessionId`
  - Cloudflare ECDSA presignature-pool put request/receipt parsing

- Direct local callers / consumers:
  - [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/rpcClients/relayer/walletRegistration.ts`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/rpcClients/relayer/walletRegistration.ts) and [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/rpcClients/relayer/thresholdEcdsa.ts`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/rpcClients/relayer/thresholdEcdsa.ts) call `parseRouterAbEcdsaHssNormalSigningFromWalletRegistrationJwtV1` when bootstrap responses arrive from the relayer.
  - [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigning.ts`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigning.ts) calls the prepare/finalize request digest helpers and the response-for-request parsers before accepting signing results.
  - [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/routerAb/ecdsaHss/presignaturePool.ts`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/routerAb/ecdsaHss/presignaturePool.ts) builds finalize requests from prepare responses and depends on the digest binding to keep the flow coherent.
  - [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts), [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/routerAb/ecdsaHss/signingMaterialRef.ts`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/routerAb/ecdsaHss/signingMaterialRef.ts), [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/registration/services/ecdsaRegistrationBootstrap.ts`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/registration/services/ecdsaRegistrationBootstrap.ts), [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/threshold/ecdsa/activation.ts`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/threshold/ecdsa/activation.ts), and [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ecdsaLoginPrefillSigningMaterialSource.ts`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ecdsaLoginPrefillSigningMaterialSource.ts) all derive storage/runtime identities from `routerAbEcdsaHssActiveStateSessionId`.
  - [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/persistence/records.ts`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/persistence/records.ts) imports the normal-signing parser/type for persisted ECDSA session records.

- Relevant transitive local imports:
  - [`/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/sessionTokens.ts`](/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/sessionTokens.ts) only decodes JWT payload records and separately exposes `exp`-based helpers.
  - [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ecdsaProvisionPlan.ts`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ecdsaProvisionPlan.ts) reconstructs wallet-session expiry from JWT `exp`, which makes expiry parity with this parser relevant.
  - [`/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/ecdsa_hss.rs`](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/ecdsa_hss.rs) mirrors the finalize-request canonical bytes and active-state session id algorithm used here, so drift or omissions propagate cross-stack.

## Security Findings

### 1. High: finalize request digests omit `budget_reservation_id` and `budget_operation_id`

- Evidence:
  - The finalize request type carries both fields: [`/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:146`](/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:146)
  - The finalize parser enforces both fields on input: [`/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:1031`](/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:1031)
  - The canonical finalize bytes skip both fields and hash only scope, request id, expiry, signing digest, server presignature id, and signature share: [`/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:633`](/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:633)
  - The finalize request digest and response-for-request parser both rely on that incomplete digest as the request binding: [`/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:648`](/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:648), [`/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:1260`](/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:1260)
  - The main caller populates those budget ids from the prepare response and assumes the finalize request digest covers the whole finalize payload: [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/routerAb/ecdsaHss/presignaturePool.ts:952`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/routerAb/ecdsaHss/presignaturePool.ts:952)
  - The Rust protocol mirror omits the same fields from canonical finalize bytes, which confirms the bug spans the shared boundary and server parity layer: [`/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/ecdsa_hss.rs:1803`](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/ecdsa_hss.rs:1803)

- Impact:
  - The client-side finalize request digest does not authenticate the budget reservation or budget operation identity that authorizes the spend.
  - Request/response matching can still succeed after those budget ids drift, which weakens the only local transcript binding on the finalize leg and hides authorization mismatches until deeper server-side failure paths.

- Recommendation:
  - Include `budget_reservation_id` and `budget_operation_id` in canonical finalize bytes on both the TS and Rust sides.
  - Add fixed fixtures that prove the finalize digest changes when either budget id changes.

### 2. High: active-state session ids are collision-prone because they join unconstrained fields with `:`

- Evidence:
  - The boundary accepts any printable ASCII after trimming. It does not reject `:` in identity components: [`/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:206`](/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:206)
  - `routerAbEcdsaHssActiveStateSessionId` concatenates `ecdsa_threshold_key_id`, `signing_root_id`, `signing_root_version`, and `activation_epoch` with `:`: [`/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:945`](/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:945)
  - That derived string feeds role-local material handles and runtime-validation keys: [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/routerAb/ecdsaHss/signingMaterialRef.ts:29`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/routerAb/ecdsaHss/signingMaterialRef.ts:29), [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts:461`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts:461)
  - Registration/bootstrap and activation paths persist worker material under that same composite id: [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/registration/services/ecdsaRegistrationBootstrap.ts:232`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/registration/services/ecdsaRegistrationBootstrap.ts:232), [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/threshold/ecdsa/activation.ts:768`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/threshold/ecdsa/activation.ts:768)
  - The handle builder compounds the ambiguity by embedding the already-delimited session id into another `:`-joined material handle: [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/identity/ecdsaHssSigningMaterialHandle.ts:28`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/identity/ecdsaHssSigningMaterialHandle.ts:28)
  - The Rust protocol and Cloudflare durable-object lookup mirror the same delimiter-joined identity, so collisions are cross-stack: [`/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/ecdsa_hss.rs:740`](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/ecdsa_hss.rs:740), [`/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/durable_object.rs:2703`](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/durable_object.rs:2703)

- Impact:
  - Distinct ECDSA-HSS state tuples can collapse to the same active-session id whenever any component contains `:`.
  - That alias can misaddress stored worker material, runtime-validation cache entries, and active-signing-worker lookups.

- Recommendation:
  - Replace the delimiter-joined string with one canonical length-prefixed encoding plus digest.
  - If the string format must survive temporarily, reject `:` at the parser boundary for every session-id component and add fixed rejection tests.

### 3. Medium: bootstrap parsing never proves JWT `exp` matches `thresholdExpiresAtMs`, so local expiry becomes path-dependent

- Evidence:
  - The bootstrap JWT parser validates `payload.thresholdExpiresAtMs` and never checks the standard `exp` claim: [`/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:819`](/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:819)
  - The wallet-registration bootstrap path persists `expiresAtMs` from the outer response material, not from JWT `exp`: [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/rpcClients/relayer/walletRegistration.ts:787`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/rpcClients/relayer/walletRegistration.ts:787)
  - A reconnect/warm-capability path reconstructs expiry from JWT `exp`: [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ecdsaProvisionPlan.ts:353`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ecdsaProvisionPlan.ts:353)
  - The shared JWT helper already treats `exp` as the authoritative unexpired check elsewhere: [`/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/sessionTokens.ts:58`](/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/sessionTokens.ts:58)

- Impact:
  - If the relayer ever emits drift between `thresholdExpiresAtMs` and `exp`, bootstrap/persistence and reconnect/restore code paths disagree about whether the same wallet session is still usable.
  - That creates avoidable local session drift: stale material can remain optimistically available, or valid material can be stranded during reconnect.

- Recommendation:
  - Require `exp` to exist and match `thresholdExpiresAtMs / 1000` at this parser boundary.
  - Reduce the model to one expiry source internally after parsing and delete the duplicate trust path.

## Refactor / Slimming Findings

### 1. The Cloudflare ECDSA presignature-pool put helpers are dead export surface today

- `buildCloudflareSigningWorkerEcdsaHssPresignaturePoolPutRequestV1`, `parseCloudflareSigningWorkerEcdsaHssPresignaturePoolPutReceiptV1`, and `parseCloudflareSigningWorkerEcdsaHssPresignaturePoolPutReceiptForRequestV1` are only referenced inside their own definitions: [`/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:1339`](/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:1339), [`/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:1394`](/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:1394), [`/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:1419`](/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:1419)
- Keeping unused wire helpers in a shared boundary increases drift pressure and makes it easier for Cloudflare-only shapes to stay half-validated in the wallet SDK surface.
- Recommendation:
  - Delete these exports until an actual caller exists, or move them behind the Cloudflare RPC layer that owns the flow.

### 2. The module repeats raw 33-byte/base64url checks where narrower boundary parsers should exist

- Public identity keys, server `bigR`, presignature shares, and receipt fields all repeat `requireBase64UrlFixed(..., 33)` or adjacent ad-hoc checks instead of sharing one narrow parser: [`/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:340`](/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:340), [`/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:1097`](/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:1097), [`/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:1074`](/Users/pta/Dev/rust/seams-sdk/packages/shared-ts/src/utils/routerAbEcdsaHss.ts:1074)
- The current duplication is how the file ended up with a finalize digest omission and a delimiter-collision session id while still looking heavily validated.
- Recommendation:
  - Introduce a small set of narrow boundary parsers/builders for compressed secp256k1 points, ECDSA budget-bound finalize digests, and active-session identity construction.
  - Delete the repeated ad-hoc helpers once the narrow builders exist.

## Recommended Next Audit Candidates

1. `packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigning.ts`
   - Follow the ECDSA-HSS finalize RPC end-to-end and confirm the client/server request-binding assumptions after the digest omission above.

2. `packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts`
   - Audit persisted wallet-session rehydration, runtime material validation keys, and how the active-session id collision propagates into restore logic.

3. `crates/router-ab-cloudflare/src/lib.rs`
   - Audit the ECDSA-HSS prepare/finalize handlers because the Rust mirror shares the same finalize digest omission and active-state session-id scheme.

## Finding Counts

- Security findings: `3`
- Refactor/slimming findings: `2`
- Total findings: `5`

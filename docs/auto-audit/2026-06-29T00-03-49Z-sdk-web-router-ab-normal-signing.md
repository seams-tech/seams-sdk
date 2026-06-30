# Auto Audit Report

- Timestamp: `2026-06-29T00:03:49Z`
- Target file: `packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigning.ts`
- Flow: `Wallet SDK Router A/B Ed25519 normal-signing prepare/finalize RPC, presign-pool refill, and budget-bound response binding`

## Scope / Call Graph Summary

This audit focused on [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigning.ts`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigning.ts), with the wallet SDK signing flow and the Rust Router/SigningWorker path that consume its request builders and response parsers.

- Direct local imports inside the target file:
  - `@shared/utils/routerAbEcdsaHss` for the ECDSA-HSS mirror helpers and budgeted finalize digest bindings
  - `./relayerHttp` for authenticated JSON POST setup
  - `@/core/signingEngine/session/budget/budget` for mapped budget error prefixes

- Direct internal responsibilities inside the target file:
  - Ed25519 normal-signing prepare/finalize wire types and request builders
  - Presign-pool refill request/response builders and parsers
  - Canonical intent and signing-payload digests through `deriveRouterAbNormalSigningAdmissionMaterialV2`
  - RPC posting for `/router-ab/ed25519/sign/prepare`, `/router-ab/ed25519/sign/presign-pool/prepare`, and `/router-ab/ed25519/sign`
  - Shared request parsing helpers for scope, commitments, digests, and error payloads

- Direct local callers / consumers:
  - [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519PresignFinalize.ts`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519PresignFinalize.ts:62) is the only runtime caller. It imports the prepare/finalize builders, the presign-pool refill path, and the action fingerprint helper.
  - [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/signTransactions.ts`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/signTransactions.ts:862), [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/signDelegate.ts`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/signDelegate.ts:414), and [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/signNep413.ts`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/signNep413.ts:296) enter the audited flow through `ed25519PresignFinalize.ts`.
  - [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts:1) and [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/shared/routerAbWalletSessionCredential.ts`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/shared/routerAbWalletSessionCredential.ts:1) consume `RouterAbWalletSessionCredential` and feed the JWT-bearing wallet session into this RPC client.

- Relevant transitive local imports:
  - [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigningValidation.ts`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigningValidation.ts:25) already has request-bound prepare/finalize matchers, but only the finalize matcher is used in the main signing flow.
  - [`/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/normal_signing.rs`](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-core/src/protocol/normal_signing.rs:1707) mirrors the request-bound prepare/finalize matching rules on the Rust side.
  - [`/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/lib.rs`](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/lib.rs:7279) handles the public Router prepare/finalize endpoints for this flow.
  - [`/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/signing_worker/mod.rs`](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/signing_worker/mod.rs:1209) materializes the admitted finalize request and consumes the protocol fields during signature assembly.

## Security Findings

### 1. Medium: Ed25519 prepare responses are not request-bound before the SDK uses `server_verifying_share_b64u`, `server_commitments`, and budget metadata

- Evidence:
  - The request-bound prepare matcher already exists: [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigningValidation.ts:25`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigningValidation.ts:25)
  - The Ed25519 prepare RPC path skips that matcher and only runs `parsePrepareResponse`: [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigning.ts:1029`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigning.ts:1029)
  - The ECDSA-HSS sibling path in the same file already performs request-bound parsing at the RPC boundary: [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigning.ts:1043`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigning.ts:1043)
  - The signing flow immediately feeds the unvalidated prepare response into local share generation and finalize request construction: [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519PresignFinalize.ts:752`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519PresignFinalize.ts:752), [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519PresignFinalize.ts:777`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519PresignFinalize.ts:777)
  - The SDK only validates the response after the finalize round-trip completes: [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519PresignFinalize.ts:787`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519PresignFinalize.ts:787)
  - The Router-to-SigningWorker prepare call already validates the prepare response against the admitted request before returning it to the public caller: [`/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/lib.rs:12131`](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-cloudflare/src/lib.rs:12131)
  - The server-side finalize crypto routine verifies the supplied server verifying share against the active server secret, which reduces this from a demonstrated signing bypass to an SDK trust-boundary bug: [`/Users/pta/Dev/rust/seams-sdk/crates/ed25519-hss/src/role_signing.rs:250`](/Users/pta/Dev/rust/seams-sdk/crates/ed25519-hss/src/role_signing.rs:250)

- Impact:
  - A tampered or buggy prepare response can influence the local client-share calculation and the finalize transcript before any SDK-side request/response binding check runs.
  - Current server-side validation makes an unauthorized final signature unlikely under the honest-server threat model, but the SDK still emits a client signature share before enforcing the response/request invariant.
  - The helper that would reject scope, expiry, signing-worker, and signing-payload drift already exists. The current boundary simply does not use it where the risk is highest.

- Recommendation:
  - Change `prepareRouterAbNormalSigningV2` to return a request-bound response, mirroring the ECDSA-HSS path in the same module.
  - Call `requireRouterAbNormalSigningPrepareMatchesRequest` before any use of `server_verifying_share_b64u`, `server_commitments`, `budget_reservation_id`, or `budget_operation_id`.
  - Add a small regression test that mutates prepare response scope, expiry, signing-payload digest, and signing-worker id and proves the SDK rejects the response before creating the client share.

### 2. Medium: presign-pool client ids silently downgrade to `Date.now()` and `Math.random()` when secure randomness is unavailable

- Evidence:
  - Normal signing request ids fail closed unless Web Crypto randomness is available: [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519PresignFinalize.ts:191`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519PresignFinalize.ts:191)
  - Presign-pool offer ids use the same environment, but the fallback drops to `Date.now()` and `Math.random()` instead of failing closed: [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519PresignFinalize.ts:669`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519PresignFinalize.ts:669)
  - Those ids feed directly into the presign-pool request and into the binding digest persisted for later finalize hits: [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigning.ts:549`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigning.ts:549), [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/threshold/ed25519/presignPool.ts:236`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/threshold/ed25519/presignPool.ts:236)

- Impact:
  - In degraded environments the SDK keeps running with predictable, collision-prone presign ids while the regular request-id path refuses to do the same.
  - That asymmetry can collapse multiple refill offers onto the same client id and makes replay/debug failures harder to reason about.
  - The id is not a secret nonce. This is cryptographic hygiene and replay/collision hardening rather than a direct key-exposure issue.

- Recommendation:
  - Use one shared secure-id helper for both request ids and client presign ids.
  - Fail closed when secure randomness is unavailable, or disable presign-pool refill in that environment.

## Refactor / Slimming Findings

### 1. Request-bound validation is split out into a helper file and bypassed at the RPC boundary

- `routerAbNormalSigningValidation.ts` only exists to compare request/response pairs, yet the main Ed25519 prepare RPC never uses it: [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigningValidation.ts:25`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigningValidation.ts:25), [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigning.ts:1029`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigning.ts:1029)
- The slimmer shape is already present in the ECDSA-HSS branch: parse the response for a specific request at the RPC boundary, then return the validated value: [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigning.ts:1043`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigning.ts:1043)
- Recommendation:
  - Inline request-bound parsing into the exported Ed25519 RPC functions.
  - Delete the standalone prepare matcher if no external caller needs it afterward.

### 2. The flow duplicates scope/byte comparison helpers and ID generation logic

- `sameScope` and `sameBytes` in the target file duplicate `sameRouterAbScope` and `sameRouterAbBytes` in the validation file: [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigning.ts:853`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigning.ts:853), [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigningValidation.ts:9`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigningValidation.ts:9)
- `createRouterAbNormalSigningRequestId` and `createClientPresignId` each implement their own entropy policy and drift on failure behavior: [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519PresignFinalize.ts:191`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519PresignFinalize.ts:191), [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519PresignFinalize.ts:669`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519PresignFinalize.ts:669)
- Recommendation:
  - Collapse the request/response comparison helpers into one request-bound parser path.
  - Collapse the ID generators into one secure helper and remove the weaker branch.

## Recommended Next Audit Candidates

1. `packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts`
   - Audit wallet-session claim rehydration and runtime material validation keys for Ed25519 Router A/B sessions.

2. `crates/router-ab-cloudflare/src/signing_worker/mod.rs`
   - Audit normal finalize materialization and add explicit invariant tests where the crypto layer currently enforces share consistency.

3. `crates/router-ab-cloudflare/src/lib.rs`
   - Audit the public Ed25519 prepare/finalize budget binding path and compare its operation-id checks with the ECDSA finalize handler.

## Finding Counts

- Security findings: `2`
- Refactor/slimming findings: `2`
- Total findings: `4`

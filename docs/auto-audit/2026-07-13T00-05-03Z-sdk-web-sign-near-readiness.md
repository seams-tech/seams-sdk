# Auto Audit Report

- Timestamp: `2026-07-13T00:05:03Z`
- Target file: `packages/sdk-web/src/core/signingEngine/flows/signNear/signNear.ts`
- Flow: `Wallet SDK NEAR Ed25519 lane selection, readiness planning, passkey or Email OTP reauth, confirmation funding, and transaction/delegate/NEP-413 signing entrypoints`

## Scope / Call Graph Summary

- Direct callers:
  - [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/useCases/signNear.ts:93`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/useCases/signNear.ts:93)
  - [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/runtime/createSigningRuntime.ts:140`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/runtime/createSigningRuntime.ts:140)
  - [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/SeamsWeb/signingSurface/BrowserSigningSurface.ts:448`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/SeamsWeb/signingSurface/BrowserSigningSurface.ts:448)
  - [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/SeamsWeb/operations/near/actions.ts:529`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/SeamsWeb/operations/near/actions.ts:529), [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/SeamsWeb/operations/near/delegateAction.ts:61`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/SeamsWeb/operations/near/delegateAction.ts:61), [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/SeamsWeb/operations/near/signNEP413.ts:87`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/SeamsWeb/operations/near/signNEP413.ts:87)
- Direct callees inside the audited flow:
  - [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/nearSigningFlow.ts:15`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/nearSigningFlow.ts:15)
  - [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/signTransactions.ts:193`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/signTransactions.ts:193)
  - [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/signDelegate.ts:110`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/signDelegate.ts:110)
  - [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/signNep413.ts:93`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/signNep413.ts:93)
  - [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/persistence/records.ts:4338`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/persistence/records.ts:4338)
  - [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/operationState/transactionState.ts:590`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/operationState/transactionState.ts:590)
  - [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/warmCapabilities/routerAbEd25519WalletSessionState.ts:38`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/warmCapabilities/routerAbEd25519WalletSessionState.ts:38)
- Transitive local imports that matter for the audited path:
  - Shared NEAR auth planning in [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/shared/signingSessionAuthMode.ts:304`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/shared/signingSessionAuthMode.ts:304)
  - Confirmation-time implicit-account funding in [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/uiConfirm/handlers/flows/signing.ts:237`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/uiConfirm/handlers/flows/signing.ts:237)
  - NEAR dep assembly in [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/assembly/ports/near.ts:16`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/assembly/ports/near.ts:16)

## Security Findings

1. Medium: runtime-validated transaction lanes ignore the live warm-session status they just fetched.
   - [`signNear.ts`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/signNear.ts:718) reads `liveStatus` from `getWarmThresholdEd25519SessionStatusForSession`, then the `hasRuntimeValidatedWorkerMaterial` branch at [`:727`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/signNear.ts:727) only checks local `remainingUses` and returns `ready` at [`:741`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/signNear.ts:741).
   - The same function already honors server status for `restore_available`, `material_hint_unvalidated`, and fallback branches at [`:743-791`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/signNear.ts:743), so the `runtime_validated` fast path is the outlier.
   - Impact: a server-expired or server-exhausted Ed25519 session can still be planned as a warm ready lane, reach confirmation, and only repair after a late admission or auth failure in [`signNear.ts:1886-1960`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/signNear.ts:1886). That leaks stale readiness into UX, budget planning, and retry behavior.

2. Medium: passkey reauth still feeds confirmation-time implicit-account funding with the stale pre-reauth wallet-session JWT.
   - `signNear.ts` freezes the transaction boundary JWT from the pre-step-up record in [`walletSessionJwtForPreparedNearExecution()` at :975-990`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/signNear.ts:975) and sends it into `ed25519SigningBoundary` at [`:1830-1843`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/signNear.ts:1830).
   - `signTransactions.ts` forwards that JWT into the confirmation request as `nearFundingAuth` at [`:450-479`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/signTransactions.ts:450).
   - The UI confirm flow uses that JWT to fund implicit NEAR accounts before worker prepare in [`uiConfirm/handlers/flows/signing.ts:245-260`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/uiConfirm/handlers/flows/signing.ts:245) and [`:600-616`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/uiConfirm/handlers/flows/signing.ts:600), while passkey reconnect does not happen until later in [`signTransactions.ts:550-577`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/signTransactions.ts:550).
   - Impact: transactions that require implicit-account funding can fail during confirmation with an expired wallet-session JWT even when the user is about to complete a successful passkey reconnect for the same signing session.

## Refactor / Slimming Findings

1. The transaction path duplicates NEAR Ed25519 readiness planning instead of reusing the shared auth-mode resolver, and the drift already produced finding #1.
   - `signNear.ts` carries a private readiness engine in [`resolveNearTransactionPlannerReadiness()` at :644-792](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/signNear.ts:644).
   - Delegate and NEP-413 already route through the shared resolver in [`shared/signingSessionAuthMode.ts:304-405`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/shared/signingSessionAuthMode.ts:304) and [`:443-485`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/shared/signingSessionAuthMode.ts:443).
   - This split increases code size and makes readiness semantics diverge across NEAR signing branches. The transaction path should consume the same boundary-normalized readiness type as the other branches.

2. Delegate and NEP-413 ad hoc session IDs are derived from a wallet-wide discovery record even though the record helpers mark that reader as non-authoritative.
   - `resolveAdHocSigningRequestSessionId()` in [`signNear.ts:1007-1020`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/signNear.ts:1007) asks `deps.resolveThresholdEd25519SessionId(walletId)` for a canonical session.
   - The concrete dep in [`assembly/ports/near.ts:31-35`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/assembly/ports/near.ts:31) answers with `getStoredThresholdEd25519SessionRecordForWallet(walletId)`.
   - The record layer explicitly says those broad wallet or account readers expose only default or discovery records and authority-bearing mutations must use exact helpers in [`records.ts:4336-4352`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/persistence/records.ts:4336).
   - This couples delegate or NEP-413 commit queues and operation IDs to a discovery record that can drift from the requested NEAR account. The flow should either derive an exact lane first or generate a fresh opaque session ID and keep authoritative session identity inside the lane planner.

## Recommended Next Audit Candidates

- `packages/sdk-web/src/core/signingEngine/flows/signNear/shared/signingSessionAuthMode.ts`
- `packages/sdk-web/src/core/signingEngine/uiConfirm/handlers/flows/signing.ts`
- `packages/sdk-web/src/core/signingEngine/assembly/ports/near.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/statusReader.ts`

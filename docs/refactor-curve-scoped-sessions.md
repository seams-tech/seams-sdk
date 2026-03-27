# Refactor Plan: Curve-Scoped Signing Sessions

## Goal

Eliminate the generic shared active signing-session slot and replace it with explicit curve-scoped session state.

This prevents cross-curve contamination where:

- threshold Ed25519 signing accidentally reads an ECDSA session id
- threshold ECDSA warm-up overwrites the active session used by NEAR Ed25519 signing
- generic session helpers hide incorrect assumptions behind one loose `nearAccountId -> sessionId` map

The new model must make it impossible for NEAR Ed25519 signing to consume ECDSA session state, and vice versa.

## Frozen Decisions

- There will be no cross-curve “best available session” lookup.
- Active signing sessions are scoped by signer curve or signer kind.
- NEAR threshold Ed25519 flows may only read threshold Ed25519 session state.
- Threshold ECDSA flows may only read threshold ECDSA session state.
- Breaking changes are fine.
- Legacy generic session helpers should be removed, not preserved.

## Target State

Replace:

- `nearAccountId -> active session id`

With one of:

- `nearAccountId + curve -> active session id`

or, more explicitly:

- `nearAccountId + signerKind -> active session id`

Recommended shape:

```ts
type ActiveSigningSessionKind = 'threshold-ed25519' | 'threshold-ecdsa-tempo' | 'threshold-ecdsa-evm';
```

and:

```ts
Map<string, string> // keyed by serialized account + signerKind
```

This is better than a plain `curve` enum because the existing ECDSA lifecycle is already chain-aware.

## Phase 1: Session State API Refactor

### Files

- [signingSessionState.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/api/session/signingSessionState.ts)
- [orchestrationDependencyFactory.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/bootstrap/orchestrationDependencyFactory.ts)

### Changes

Replace generic helpers:

- `getOrCreateActiveSigningSessionId`
- `setActiveSigningSessionId`
- `clearActiveSigningSessionId`
- `clearAllActiveSigningSessionIds`
- `getWarmSigningSessionStatus`

With scoped helpers:

- `getOrCreateActiveSigningSessionIdForKind`
- `setActiveSigningSessionIdForKind`
- `clearActiveSigningSessionIdForKind`
- `clearAllActiveSigningSessionIdsForKind`
- `getWarmSigningSessionStatusForKind`

Add explicit session-kind serialization helpers:

- `serializeActiveSigningSessionKey({ nearAccountId, signerKind })`
- `parseActiveSigningSessionKey(...)`

### Required behavior

- Ed25519 reads only Ed25519 active session ids.
- ECDSA Tempo reads only Tempo ECDSA active session ids.
- ECDSA EVM reads only EVM ECDSA active session ids.
- `clear...ForKind` only clears the requested kind.
- “clear all” should be explicit about whether it means:
  - all kinds for one account, or
  - all kinds for all accounts

## Phase 2: Dependency Bundle Cleanup

### Files

- [orchestrationDependencyFactory.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/bootstrap/orchestrationDependencyFactory.ts)
- [SigningEngine.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/SigningEngine.ts)

### Changes

Remove the generic convenience surface:

- `getOrCreateActiveSigningSessionId`
- `getWarmSigningSessionStatus`

Replace with explicit methods:

- `getOrCreateActiveThresholdEd25519SessionId`
- `getWarmThresholdEd25519SessionStatus`
- `getOrCreateActiveThresholdEcdsaSessionIdForChain`
- `getWarmThresholdEcdsaSessionStatusForChain`

Keep canonical persisted lookup explicit too:

- `resolveCanonicalThresholdEd25519SessionId`
- `resolveCanonicalThresholdEcdsaSessionIdForChain`

Do not keep one mixed helper that falls back from one signer family to another.

## Phase 3: Threshold Ed25519 Call-Site Migration

### Files

- [nearSigning.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/api/nearSigning.ts)
- [transactionsFlow.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/orchestration/near/transactionsFlow.ts)
- [delegateFlow.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/orchestration/near/delegateFlow.ts)
- [nep413Flow.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/orchestration/near/nep413Flow.ts)
- [thresholdAuthMode.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/orchestration/near/shared/thresholdAuthMode.ts)

### Changes

Ensure the NEAR signer path only uses:

- canonical threshold Ed25519 session id
- threshold Ed25519 warm-session readiness
- threshold Ed25519 auth-session persistence

Delete any residual use of generic active-session APIs from NEAR signing.

## Phase 4: Threshold ECDSA Call-Site Migration

### Files

- [thresholdSessionActivation.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/api/thresholdLifecycle/thresholdSessionActivation.ts)
- [login.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/TatchiPasskey/login.ts)
- [thresholdEcdsaLoginPrefill.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/api/thresholdLifecycle/thresholdEcdsaLoginPrefill.ts)
- ECDSA orchestration files under:
  - [/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/orchestration/walletOrigin/]( /Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/orchestration/walletOrigin/)
  - [/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/threshold/workflows/]( /Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/threshold/workflows/)

### Changes

Make ECDSA bootstrap and warm-up explicitly write only ECDSA session ids.

Important login cleanup:

- when Ed25519 warm-up runs first, it must not be overwritten in the Ed25519 namespace by later ECDSA bootstrap
- when ECDSA bootstrap reuses the Ed25519 session id intentionally for one-prompt flows, that reuse must stay local to the relay/auth logic, not mutate Ed25519 active-session state incorrectly

The key distinction is:

- relay/session coupling may reuse an id
- client-side active session ownership must still remain signer-kind scoped

## Phase 5: UI Session Readiness Clarification

### Files

- [walletSessionReadiness.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/react/context/walletSessionReadiness.ts)
- [useWalletIframeLifecycle.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/react/context/useWalletIframeLifecycle.ts)
- [useLoginStateRefresher.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/react/context/useLoginStateRefresher.ts)
- [useTatchiContextValue.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/react/context/useTatchiContextValue.ts)

### Changes

Clarify what “wallet session ready” means.

Today it implicitly mixes:

- login state
- warm signing session state

Decide whether UI readiness should be:

- any signer-ready state for the active account, or
- threshold Ed25519 readiness specifically for NEAR-only UI

At minimum:

- stop naming it generically if it is actually Ed25519-biased
- avoid surfacing one signer family’s readiness as another’s

## Phase 6: Error Surface Cleanup

### Files

- [canonicalSignerErrorCode.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/WalletIframe/host/canonicalSignerErrorCode.ts)
- [router.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/WalletIframe/client/router.ts)

### Changes

Add explicit raw details when signer-kind mismatch occurs.

Examples:

- `threshold_ed25519_session_not_ready`
- `threshold_ecdsa_session_not_ready`
- `threshold_session_kind_mismatch`

The canonical public message can stay concise, but details should make the underlying signer family visible.

## Phase 7: Test Coverage

### Add

- unit tests for session-state keying:
  - setting ECDSA active session does not affect Ed25519 lookup
  - clearing Ed25519 does not clear ECDSA
  - canonical fallback is signer-kind scoped
- unit tests for NEAR signing:
  - canonical Ed25519 session beats conflicting generic/other-kind active state
- unit tests for login warm-up:
  - Ed25519 warm-up remains intact after ECDSA bootstrap
- e2e test:
  - account with both Ed25519 and ECDSA signer state can still sign NEAR transactions immediately after login

### Existing tests to update

- [thresholdEd25519.immediateSignFallback.unit.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/unit/thresholdEd25519.immediateSignFallback.unit.test.ts)
- [tatchiPasskey.loginThresholdWarm.unit.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/unit/tatchiPasskey.loginThresholdWarm.unit.test.ts)
- [executeAction.twice.walletIframe.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/e2e/executeAction.twice.walletIframe.test.ts)
- [thresholdEd25519.batchSigning.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/e2e/thresholdEd25519.batchSigning.test.ts)

## Exact Legacy Symbols To Remove

These should not survive the refactor under their current semantics:

- `activeSigningSessionIds` as a single account-keyed map
- `getOrCreateActiveSigningSessionId`
- `setActiveSigningSessionId`
- `clearActiveSigningSessionId`
- `clearAllActiveSigningSessionIds`
- `getWarmSigningSessionStatus`

If any helper with these names remains, it should be a thin compatibility shim only temporarily during the refactor, then removed before merge.

## Migration Order

1. Refactor session-state storage and helper names.
2. Update dependency wiring in `orchestrationDependencyFactory.ts`.
3. Migrate NEAR threshold Ed25519 call sites.
4. Migrate threshold ECDSA call sites.
5. Update UI readiness helpers.
6. Update tests.
7. Remove dead generic helpers.

## Definition of Done

- No generic cross-curve active session slot remains.
- NEAR threshold Ed25519 signing never reads ECDSA session state.
- Threshold ECDSA flows never mutate Ed25519 active session state by accident.
- The relevant unit and e2e regressions pass.
- The codebase no longer contains legacy generic helper names for active signing-session management.

## Remaining High-Impact TODO

- [x] Harden UI readiness boundaries so Ed25519 NEAR readiness cannot be inferred from ECDSA readiness.
  - Scope: `walletSessionReadiness.ts`, `useWalletIframeLifecycle.ts`, `useLoginStateRefresher.ts`, `useTatchiContextValue.ts`
- [x] Add signer-kind-specific error details for session failures, with explicit Ed25519 vs ECDSA failure semantics.
  - Scope: `canonicalSignerErrorCode.ts`, wallet iframe host/client boundary normalization
- [x] Add or confirm e2e regression for login followed by immediate NEAR sign on accounts with both Ed25519 and ECDSA state.
  - Scope: `tests/e2e/executeAction.twice.walletIframe.test.ts` and `tests/e2e/worker_events.test.ts` (or equivalent)
- [x] Add `resolveCanonicalThresholdEcdsaSessionIdForChain(...)` to remove remaining ECDSA session selection ambiguity.
  - Scope: `orchestrationDependencyFactory.ts` and ECDSA orchestration consumers
- [x] Remove remaining dead shared-slot comments/assumptions that can reintroduce cross-curve session coupling.

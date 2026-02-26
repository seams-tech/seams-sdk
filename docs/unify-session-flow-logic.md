# Unify Session Flow Logic (NEAR + EVM/Tempo)

## Goal

Use one shared signing-session decision path across NEAR threshold signing and EVM/Tempo threshold ECDSA signing so session/auth behavior cannot drift.

## Non-goals

- No compatibility layer for legacy dual logic.
- No confirmation-behavior-to-auth mapping (`requireClick`/`skipClick` must stay UI-only).

## Contract to enforce

1. `confirmationConfig` controls confirmer UI only.
2. Signing auth/session mode is determined only by signing-session state.
3. Session creation is explicit (login or create-session API), not transaction-time.
4. Transaction flows consume existing warm session state or fail fast with canonical session errors.
5. Logout wipes all PRF session cache entries.

## Current duplication to remove

- NEAR has a dedicated planner path in `orchestration/near/shared/thresholdSessionPolicy.ts`.
- EVM/Tempo uses shared auth resolution plus separate high-level readiness checks.
- Transaction-time fallback and session mint logic exists in NEAR flows.

## Target architecture

Add a single shared planner module:

- `client/src/core/signingEngine/orchestration/shared/thresholdSigningSessionPlanner.ts`

Responsibilities:

1. Resolve required signing auth mode from warm session state.
2. Validate warm session readiness (`missing`, `expired`, `exhausted` checks).
3. Dispense PRF material for required uses.
4. Return canonical error codes/messages for session-not-ready.

All chain flows call this module, then run chain-specific signing only.

## Execution plan

### Phase 1: Lock behavior and tests first

1. Add cross-chain contract tests (NEAR + EVM + Tempo):
   - warm session cached => no TouchID prompt
   - missing/expired/exhausted => fail fast, same error family
   - `requireClick` vs `skipClick` changes UI only
2. Add unit coverage for planner output and error normalization.

### Phase 2: Build shared planner

1. Implement `thresholdSigningSessionPlanner.ts` in shared orchestration.
2. Move duplicated session readiness checks into the planner.
3. Move PRF dispense rules into the planner.
4. Expose typed result object used by all chain flows.

### Phase 3: Migrate NEAR flows

Refactor:

- `orchestration/near/transactionsFlow.ts`
- `orchestration/near/delegateFlow.ts`
- `orchestration/near/nep413Flow.ts`

Changes:

1. Remove NEAR-specific planner path usage.
2. Remove transaction-time WebAuthn fallback for missing warm session.
3. Remove transaction-time threshold session mint path from these flows.
4. Use shared planner output before signing.

### Phase 4: Migrate EVM/Tempo flows

Refactor:

- `api/evmSigning.ts`
- `orchestration/shared/touchConfirmSigning.ts`
- `orchestration/evm/evmSigningFlow.ts`
- `orchestration/tempo/tempoSigningFlow.ts`

Changes:

1. Remove remaining duplicate readiness checks outside planner.
2. Use planner as single source for warm session gating and PRF dispense.
3. Keep chain-specific signing intent and transport logic unchanged.

### Phase 5: Consolidate session lifecycle

1. Keep session creation only in login/create-session APIs.
2. Ensure session policy (`ttlMs`, `remainingUses`) is applied only there.
3. Ensure logout global clear always wipes full PRF cache.

### Phase 6: Delete legacy paths immediately

1. Delete `orchestration/near/shared/thresholdSessionPolicy.ts` after migration.
2. Delete obsolete helper functions duplicated in EVM/Tempo path.
3. Remove transaction API params that imply tx-time session creation if now invalid.
4. Remove dead tests tied to removed behavior.

## Acceptance criteria

1. NEAR and EVM/Tempo call the same planner for session/auth decisions.
2. No transaction flow creates or refreshes threshold session auth.
3. Same session error codes/messages across chains.
4. `confirmationConfig` does not affect session/auth selection.
5. All targeted unit/e2e tests pass.

## Risk controls

1. Keep refactor behind test-first contract checks to prevent behavior drift.
2. Migrate chain flows one by one but do not keep dual planners active long-term.
3. Use a short-lived stacked PR sequence if needed, then remove old code in the same series.

## Suggested PR breakdown

1. PR A: Add shared planner + tests.
2. PR B: Migrate NEAR flows + remove NEAR planner path.
3. PR C: Migrate EVM/Tempo duplicate checks + cleanup dead APIs/tests/docs.


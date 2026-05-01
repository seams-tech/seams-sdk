# Signing Session Refactor 2: Deterministic State Machine

Date created: 2026-05-01

## Purpose

This plan replaces the incremental signing-session restore cleanup with a simpler
architecture target: transaction signing is a deterministic state machine over one
concrete signing lane.

The product intent remains the same as
[`docs/signing-session-refresh-intent.md`](signing-session-refresh-intent.md):

1. Refresh is not exhaustion.
2. Missing worker memory is not exhaustion.
3. Durable sealed IndexedDB state is the restore source of truth.
4. Worker memory is only hot unsealed material.
5. Server status is authoritative for remaining wallet signing-session budget.
6. Status and snapshot reads are side-effect-free.
7. After budget exhaustion, OTP accounts step up with Email OTP and passkey
   accounts step up with passkey/TouchID.
8. NEAR Ed25519 and ECDSA restore independently and exactly.

The current code has repeatedly failed because transaction signing still contains
discovery-mode behavior. A critical signing path cannot depend on optional IDs,
auth-method inference, account-level fallbacks, broad restore, or post-sign
identity rediscovery. Those behaviors must be deleted, not wrapped.

## Non-Negotiable Rules

1. Transaction signing selects exactly one lane before auth, budget, signing, or
   finalization can mutate state.
2. Once selected, that lane is the only lane that may be restored, reauthed,
   published, reserved, signed, finalized, or cleaned up for the operation.
3. A transaction lane is concrete by type. It cannot have optional
   `walletSigningSessionId` or optional `thresholdSessionId`.
4. Raw reads may contain missing fields. Resolved transaction state may not.
5. Account auth metadata is a pre-selection policy input only. It cannot override
   a selected concrete lane.
6. Runtime records are not authoritative selectors. They may anchor a lane if
   they exactly match policy, but they cannot cause fallback to another auth
   method.
7. Restore is exact-purpose for transaction signing. No transaction path may
   restore by only `authMethod + curve + chain`.
8. Missing hot material for a selected lane is a readiness state, not permission
   to select a different lane.
9. Reauth creates a replacement prepared lane. It does not mutate a prepared
   operation behind its back.
10. Budget identity must be captured before the operation's authoritative spend,
    including sessions minted during OTP/passkey step-up.
11. Transaction step-up mints a single-operation session by default:
    `sessionBudgetUses = operationUsesNeeded`, normally `1`.
12. Reusable signing sessions are created only through an explicit reusable-session
    command, never as a side effect of transaction step-up.

## The Root Architecture Problem

The previous refactors added better helpers but did not remove enough old
authority. The transaction path can still be influenced by:

1. account auth metadata
2. collapsed snapshot lanes
3. candidate lists
4. stored runtime records
5. durable sealed records
6. restore side effects
7. worker live status
8. budget status
9. fresh-auth retry state
10. finalization-time re-reads

That is too many decision points. The new design has one decision point:
`selectTransactionLane(intent, snapshot, policy)`.

Everything after that either operates on the selected lane or returns a typed
state for that lane.

## Core Types

Resolved transaction types must be strict. Optional fields belong only in raw
records, snapshots, and untrusted external responses.

```ts
type TransactionSigningIntent = {
  operationId: SigningOperationId;
  walletId: string;
  curve: 'ed25519' | 'ecdsa';
  chain: 'near' | 'tempo' | 'evm';
  operationUsesNeeded: number;
  reusableSessionRequested: false;
};

type BaseTransactionLane = {
  walletId: string;
  authMethod: 'email_otp' | 'passkey';
  walletSigningSessionId: string;
  thresholdSessionId: string;
  operationUsesNeeded: number;
  sessionBudgetUses: number;
};

type Ed25519TransactionLane = BaseTransactionLane & {
  curve: 'ed25519';
  chain: 'near';
  relayerKeyId: string;
};

type EcdsaTransactionLane = BaseTransactionLane & {
  curve: 'ecdsa';
  chain: 'tempo' | 'evm';
  backingMaterialSessionId: string;
  signingRootId: string;
  signingRootVersion: string;
};

type TransactionLane = Ed25519TransactionLane | EcdsaTransactionLane;

type PreparedTransactionOperation = {
  intent: TransactionSigningIntent;
  lane: TransactionLane;
  readiness: TransactionReadiness;
  authPlan: TransactionAuthPlan;
  budgetIdentity?: PreparedBudgetIdentity;
  snapshotGeneration: number;
};
```

If a field is not available, the result is not a `TransactionLane`. It is a
`LaneSelectionFailure`.

```ts
type LaneSelectionFailure =
  | { kind: 'no_candidate'; authMethod?: 'email_otp' | 'passkey' }
  | { kind: 'ambiguous_candidates'; authMethod?: 'email_otp' | 'passkey' }
  | { kind: 'incomplete_candidate'; missing: readonly string[] }
  | { kind: 'policy_blocked'; reason: string };
```

## State Machine

Transaction signing has one state machine. NEAR, Tempo, ARC/EVM, OTP, and passkey
plug into the same states.

```text
IntentReceived
  -> SnapshotRead
  -> LaneSelected
  -> ExactRestoreAttempted
  -> ReadinessClassified
  -> AuthPlanned
  -> ConfirmationOwned
  -> AuthMaterialReady
  -> BudgetAdmitted
  -> SigningStarted
  -> Signed
  -> Finalized
```

Terminal states:

```text
Cancelled
SelectionFailed
RestoreFailed
AuthFailed
BudgetUnavailable
SigningFailed
FinalizationFailed
```

### Transition Table

| From | To | Owner | Rule |
| --- | --- | --- | --- |
| `IntentReceived` | `SnapshotRead` | snapshot reader | Read only. No restore, prompt, consume, publish, or cleanup. |
| `SnapshotRead` | `LaneSelected` | lane selector | Select one concrete lane or fail typed. No probing. |
| `LaneSelected` | `ExactRestoreAttempted` | restore executor | Restore only the selected lane identity. |
| `ExactRestoreAttempted` | `ReadinessClassified` | readiness reader | Classify selected lane only. Missing hot material is not lane failure. |
| `ReadinessClassified` | `AuthPlanned` | planner | Map readiness to warm, OTP reauth, passkey reauth, or terminal. |
| `AuthPlanned` | `ConfirmationOwned` | transaction confirmer | User-visible confirmation owns auth prompts. |
| `ConfirmationOwned` | `AuthMaterialReady` | auth executor | Warm lane, OTP result, or passkey reconnect returns a concrete lane. |
| `AuthMaterialReady` | `BudgetAdmitted` | budget coordinator | Capture budget identity before signing consumes budget. |
| `BudgetAdmitted` | `SigningStarted` | curve executor | Sign with the prepared lane only. |
| `SigningStarted` | `Signed` | curve executor | Return signed payload/result. |
| `Signed` | `Finalized` | finalizer | Finalize the same lane. No re-selection. |

## Readiness Model

Readiness is about the selected lane only.

```ts
type TransactionReadiness =
  | { status: 'ready'; remainingUses: number; expiresAtMs: number }
  | { status: 'missing_hot_material' }
  | { status: 'expired' }
  | { status: 'exhausted' }
  | { status: 'restore_failed'; reason: string }
  | { status: 'budget_unknown'; reason: string }
  | { status: 'policy_blocked'; reason: string };
```

Planner mapping:

1. `ready` with enough budget becomes `WarmSession`.
2. `missing_hot_material`, `expired`, and `exhausted` become same-method reauth:
   Email OTP lane to `EmailOtpReauth`, passkey lane to `PasskeyReauth`.
3. `restore_failed`, `budget_unknown`, and `policy_blocked` are terminal unless
   the error explicitly says same-method reauth can recover.
4. A selected OTP lane can never plan passkey reauth.
5. A selected passkey lane can never plan OTP reauth.

## Lane Selection Policy

Lane selection is pure and deterministic.

Inputs:

1. transaction intent
2. side-effect-free snapshot candidates
3. account policy/auth preference
4. optional current runtime record as a candidate, not as an override

Outputs:

1. one concrete `TransactionLane`
2. or one typed `LaneSelectionFailure`

Selection rules:

1. Filter by `walletId`, `curve`, and `chain`.
2. Filter by account policy before ranking candidates.
3. If a current runtime record exists for the selected auth method, it anchors
   selection only when the snapshot contains the same concrete identity or the
   runtime record itself can be normalized into a concrete candidate.
4. If a current runtime record exists but does not match any candidate, return
   `LaneSelectionFailure`; do not choose another candidate.
5. If multiple candidates remain, choose by explicit policy:
   ready runtime candidate, then restorable durable candidate, then newest stable
   metadata only if the ordering field is defined for all candidates.
6. If ordering metadata is missing or mixed, return `ambiguous_candidates`.
7. Never fall back from OTP to passkey or from passkey to OTP.
8. Never fall back to `candidates[0]` unless the candidate list was already
   filtered and deterministically sorted by the selector.

## Restore Model

Transaction restore has one input shape:

```ts
type TransactionRestoreInput = {
  reason: 'transaction';
  lane: TransactionLane;
};
```

Broad restore belongs only to maintenance commands:

```ts
type MaintenanceRestoreInput = {
  reason: 'session_status' | 'export' | 'startup_maintenance';
  walletId: string;
  authMethod?: 'email_otp' | 'passkey';
  curve?: 'ed25519' | 'ecdsa';
  chain?: 'near' | 'tempo' | 'evm';
};
```

Rules:

1. Transaction restore cannot compile without concrete lane IDs.
2. Transaction restore cannot change auth method, curve, chain, or session IDs.
3. Restore success publishes hot material for the selected lane only.
4. Restore failure returns `restore_failed` or `missing_hot_material` for the
   selected lane. It does not broaden.
5. Maintenance restore cannot be imported by transaction signing modules.

## Reauth Model

Reauth is a state transition that replaces the prepared lane.

```text
AuthPlanned(PasskeyReauth, oldLane)
  -> ConfirmationOwned
  -> PasskeyAssertionCollected
  -> NewLaneMinted
  -> PreparedOperationReplaced(newLane)
```

Rules:

1. Reauth does not mutate `oldLane`.
2. Reauth returns a new concrete lane with its own `walletSigningSessionId` and
   `thresholdSessionId`.
3. Finalization targets the new lane.
4. The old prepared operation is not finalized as success after a fresh-auth
   retry.
5. Reauth-created transaction sessions default to one operation use.

## Budget Model

Budget accounting is deterministic and server-authoritative.

Definitions:

1. `operationUsesNeeded`: cost of the current signing operation, normally `1`.
2. `sessionBudgetUses`: capacity minted by step-up or reusable-session creation.
3. `remainingUses`: trusted server remaining budget.
4. `availableUses`: local planning hint after same-projection in-flight holds.
5. `projectionVersion`: opaque causal token for the trusted server status.

Rules:

1. Transaction signing uses `operationUsesNeeded = 1` unless product policy
   explicitly changes the definition of a signing operation.
2. NEAR batched transactions remain one signing operation by default.
3. Transaction step-up uses `sessionBudgetUses = operationUsesNeeded`.
4. Reusable sessions require a separate explicit reusable-session intent.
5. Warm-session budget identity is captured before signing.
6. Reauth-created budget identity is captured immediately after mint/reconnect
   and before signing.
7. Ed25519 server-side signing may consume the authoritative budget during the
   signing ceremony. Finalization reconciles an already-consumed selected lane; it
   must not prepare budget identity after signing.
8. Local reservations never change `remainingUses`. They produce
   `inFlightReservedUses` and `availableUses`.
9. Projection-version comparison is equality only. Opaque versions are not
   ordered.
10. A stale prepared projection causes refresh/reprepare of budget identity, not
    same-method reauth.

## Storage Ownership

| Storage | Owns | Does Not Own |
| --- | --- | --- |
| IndexedDB sealed store | durable encrypted restore state and durable lane metadata | hot material, auth prompts, budget truth |
| runtime record store | current concrete runtime records | lane selection policy, budget truth |
| worker memory | hot unsealed material | durable identity, budget truth |
| server | authoritative budget and session validity | local lane selection |
| JS prepared operation | operation-local selected lane and budget identity | durable storage |
| sessionStorage | nothing required for signing correctness | lane identity |

Status reads and snapshots may combine storage into a read model. They may not
repair, restore, consume, publish, or prompt.

## Helper Function Rules

Helpers are allowed when they reduce visible complexity without hiding authority.

Allowed helpers:

1. pure normalizers
2. pure type guards
3. pure selectors with explicit inputs and typed failures
4. side-effect executors with exact command inputs
5. assertion helpers that compare complete concrete identity

Forbidden helpers in transaction signing:

1. helpers that accept partial lane identity and search globally
2. helpers that infer auth method after lane selection
3. helpers that restore broadly
4. helpers that catch restore failure and continue as if nothing happened
5. helpers that publish current runtime state for another curve
6. helpers that re-read mutable global session state during finalization
7. helpers whose fallback changes auth method, curve, chain, or session IDs

Naming rules:

1. `select*` returns one concrete value or a typed failure.
2. `try*` may return `null`, but may not mutate.
3. `restore*` mutates only through an exact command input.
4. `resolve*` must not prompt, consume, restore, publish, or delete.
5. `finalize*` receives the prepared operation; it does not discover identity.

## Implementation Plan

### Phase 1: Freeze The Current Regressions

Add failing tests before moving code:

1. OTP account, Ed25519 session exhausted, next NEAR tx shows OTP and succeeds.
2. Passkey account, Ed25519 session exhausted, next NEAR tx shows passkey and
   succeeds.
3. Passkey Ed25519 step-up mints one operation use and does not fail post-sign
   budget finalization.
4. OTP ECDSA step-up does not publish a current Ed25519 transaction lane.
5. OTP account with passkey durable state never shows passkey for NEAR Ed25519.
6. Passkey account with OTP durable state never shows OTP for NEAR Ed25519.
7. Refresh with durable sealed state and valid server budget signs without auth.
8. Missing worker memory with valid durable state signs without auth.
9. Missing worker memory with exhausted server budget shows same-method step-up.
10. Three fast sequential txs behave the same as three slow sequential txs.

### Phase 2: Introduce Concrete Transaction Types

1. Add `TransactionSigningIntent`.
2. Add `TransactionLane`.
3. Add `PreparedTransactionOperation`.
4. Add `LaneSelectionFailure`.
5. Convert transaction restore input to `TransactionRestoreInput`.
6. Convert transaction budget/finalizer inputs to accept `TransactionLane`.
7. Keep raw snapshot and storage types separate from resolved transaction types.

Acceptance:

1. No transaction module can compile with optional `walletSigningSessionId`.
2. No transaction module can compile with optional `thresholdSessionId`.
3. No transaction restore call can compile with only `authMethod + curve + chain`.

### Phase 3: Build The Pure Selector

1. Implement `selectTransactionLane(intent, snapshot, policy)`.
2. Move NEAR Ed25519 selection into this selector.
3. Move ECDSA selection into this selector.
4. Remove selection from lower transaction flows.
5. Delete `candidates[0]` fallback after runtime mismatch.
6. Delete account-primary fallback after concrete candidate selection.
7. Delete OTP/passkey probing.

Acceptance:

1. Given the same intent, snapshot, and policy, selection is deterministic.
2. Linked-auth accounts cannot drift to the other auth method.
3. Selection failures are typed and visible in tests.

### Phase 4: Collapse Prepare Into The State Machine

1. Create one `prepareTransactionSigningOperation(intent)` path.
2. It performs snapshot read, lane selection, exact restore, readiness
   classification, auth planning, and warm budget identity capture.
3. It returns `PreparedTransactionOperation`.
4. NEAR/EVM/Tempo transaction flows receive prepared operations only.
5. Lower flows no longer plan auth, select lanes, or restore sessions.

Acceptance:

1. `transactionsFlow.ts` cannot run without a prepared operation.
2. EVM-family execution cannot run without a prepared operation.
3. There is no production transaction path that calls the planner with an
   already-mutated or re-selected lane.

### Phase 5: Make Reauth Replace Prepared Operations

1. OTP reauth returns a new `TransactionLane`.
2. Passkey reauth returns a new `TransactionLane`.
3. Reauth result replaces the prepared operation before budget or signing.
4. Fresh-auth retry paths return the replacement prepared operation.
5. Mutable outer session objects are deleted from finalization paths.

Acceptance:

1. Old prepared lanes cannot be finalized after fresh auth.
2. Post-reauth signing and finalization use the new wallet/threshold session IDs.
3. Step-up sessions mint `sessionBudgetUses = operationUsesNeeded` unless the
   intent explicitly requests a reusable session.

### Phase 6: Fix Budget Timing

1. Capture budget identity before signing for warm lanes.
2. Capture budget identity immediately after OTP/passkey mint for reauth lanes.
3. For Ed25519, mark finalization as reconciliation of the already-consumed
   selected threshold session.
4. Remove budget-identity preparation from post-sign finalization.
5. Reprepare budget identity on stale projection if the server still has enough
   remaining budget; do not step up because of local projection staleness.

Acceptance:

1. Passkey Ed25519 step-up cannot sign successfully and then fail with wallet
   budget exhausted.
2. OTP Ed25519 step-up has the same budget behavior as passkey Ed25519 step-up.
3. Fast and slow signing use the same readiness and auth classification.

### Phase 7: Delete Discovery-Mode Transaction Code

Delete or move to maintenance-only modules:

1. broad transaction restore
2. transaction auth-method probing
3. collapsed-lane transaction selection
4. transaction fallback from runtime mismatch to durable candidate
5. transaction fallback from durable mismatch to account record
6. transaction finalization that reads current global session state
7. transaction helper APIs with optional resolved IDs
8. transaction paths that silently swallow exact restore failure
9. transaction paths that publish companion lanes as current lanes

Acceptance:

1. Static guards fail on every deleted pattern.
2. Maintenance restore remains available only outside transaction modules.
3. The transaction path is shorter after the migration, not larger.

### Phase 8: Update Docs And Ownership

1. Mark `signing-session-restore-refactor.md` as historical.
2. Update `signing-session-architecture.md` to point to this state-machine plan.
3. Keep `signing-session-refresh-intent.md` as the product intent.
4. Remove duplicate architecture specs that contradict the state machine.

## Static Guards

Add architecture guards for:

1. no transaction restore call without `TransactionLane`
2. no `reason: 'transaction'` restore with optional session IDs
3. no `?? passkeySigningAuthPlan()` fallback in transaction flows
4. no `candidates[0]` transaction fallback after runtime mismatch
5. no account-primary auth fallback after lane selection
6. no post-sign `prepareBudgetIdentity(...)`
7. no transaction finalizer that reads mutable current session state
8. no transaction step-up path using configured reusable-session defaults
9. no transaction module importing maintenance restore helpers
10. no transaction path that catches exact restore failure and continues to a
    generic not-ready error

## Definition Of Done

The refactor is done when:

1. Transaction signing has one state machine.
2. Every transaction state carries the same concrete lane unless reauth replaces
   it with a new concrete lane.
3. Missing worker memory restores exact durable state without auth.
4. Exhausted budget causes same-method step-up.
5. OTP accounts cannot drift to passkey prompts.
6. Passkey accounts cannot drift to OTP prompts.
7. ECDSA step-up cannot make Ed25519 transaction signing skip auth by accident.
8. Ed25519 step-up cannot fail post-sign budget finalization because budget was
   captured after signing.
9. No production transaction path accepts optional resolved lane IDs.
10. No production transaction path contains discovery-mode fallback logic.

## Implementation Stance

This is a critical path. Compatibility shims are not acceptable in the
transaction flow. If a helper or fallback exists only to keep old behavior alive,
delete it in the same patch that introduces the deterministic replacement.

Tests should prove the state machine. Static guards should prevent the old
architecture from returning.

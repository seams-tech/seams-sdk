# Signing Session Refactor 2: Deterministic State Machine

Date created: 2026-05-01

## Purpose

This plan replaces the incremental signing-session restore cleanup with a simpler
architecture target: transaction signing is a deterministic state machine over one
concrete signing lane.

## Document Authority

Active signing-session docs:

1. Product intent:
   [signing-session-refresh-intent.md](signing-session-refresh-intent.md).
2. Architecture summary:
   [signing-session-architecture.md](signing-session-architecture.md).
3. Auth and wallet-budget model:
   [signing-session-auth-and-budget.md](signing-session-auth-and-budget.md).
4. Email OTP secret and restore model:
   [email-otp-secret-restore.md](email-otp-secret-restore.md).

Legacy migration logs that conflicted with this state-machine design were
deleted. Current implementation work should start from the active docs listed
above.

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
   published, budget-admitted, signed, finalized, or cleaned up for the
   operation.
3. A transaction lane is concrete by type. It cannot have optional
   `walletSigningSessionId` or optional `thresholdSessionId`.
4. Raw reads may contain missing fields. Resolved transaction state may not.
5. Hard account policy may exclude lanes before selection. Account preference,
   primary-auth metadata, and profile hints may not hide or override a concrete
   current runtime lane.
6. A current runtime record is a lane anchor when present. It must be considered
   before account preference filters, and mismatch is a typed selection failure,
   not permission to choose another auth method.
7. Restore is exact-purpose for transaction signing. No transaction path may
   restore by only `authMethod + curve + chain`.
8. Missing hot material for a selected lane is a readiness state, not permission
   to select a different lane.
9. Reauth creates a replacement prepared lane. It does not mutate a prepared
   operation behind its back.
10. Budget identity must be captured before the operation's authoritative spend,
    including sessions minted during OTP/passkey step-up.
11. Transaction step-up mints a single-operation session:
    `sessionBudgetUses = operationUsesNeeded`, normally `1`.
12. Reusable signing sessions are created only through an explicit reusable-session
    command, never as a side effect of transaction step-up.

## The Root Architecture Problem

The previous refactors added better helpers but did not remove enough old
authority. The transaction path can still be influenced by:

1. account auth metadata
2. collapsed snapshot lanes
3. collapsed lanes mixed with candidate lists
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
  authSelectionPolicy: AuthSelectionPolicy;
  operationUsesNeeded: number;
};

type AuthSelectionPolicy =
  | { kind: 'explicit'; authMethod: 'email_otp' | 'passkey' }
  | { kind: 'account_class'; authMethod: 'email_otp' | 'passkey' }
  | { kind: 'current_lane'; authMethod: 'email_otp' | 'passkey' };

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

type ConcreteKeyExportLane = BaseTransactionLane & {
  operation: 'key_export';
  curve: 'ed25519' | 'ecdsa';
  chain: 'near' | 'tempo' | 'evm';
};

type PreparedTransactionOperation = {
  intent: TransactionSigningIntent;
  lane: TransactionLane;
  readiness: TransactionReadiness;
  authPlan: TransactionAuthPlan;
  snapshotGeneration: number;
};

type BudgetAdmittedTransactionOperation = PreparedTransactionOperation & {
  budgetAdmission: BudgetAdmission;
};

type SignedTransactionOperation = BudgetAdmittedTransactionOperation & {
  result: SigningResult;
};
```

If a field is not available, the result is not a `TransactionLane`. It is a
`LaneSelectionFailure`.

```ts
type LaneSelectionFailure =
  | { kind: 'no_candidate'; authMethod?: 'email_otp' | 'passkey' }
  | {
      kind: 'ambiguous_candidates';
      allowedAuthMethods: readonly ('email_otp' | 'passkey')[];
    }
  | { kind: 'incomplete_candidate'; missing: readonly string[] }
  | { kind: 'policy_blocked'; reason: string };
```

Snapshots must expose concrete candidate lists for both curves:

```ts
type TransactionSigningSnapshot = {
  candidates: {
    ed25519: {
      near: readonly RawEd25519LaneCandidate[];
    };
    ecdsa: {
      tempo: readonly RawEcdsaLaneCandidate[];
      evm: readonly RawEcdsaLaneCandidate[];
    };
  };
};
```

Collapsed `snapshot.lanes.*` values are status summaries only. They are not
transaction-selection authority.

### State Types And Transition Functions

Use a state-machine architecture implemented with TypeScript discriminated
unions and boring transition functions. Do not introduce a generic state-machine
framework unless it makes illegal transitions compile-time impossible.

```ts
type SigningState =
  | { tag: 'IntentReceived'; intent: TransactionSigningIntent }
  | {
      tag: 'SnapshotRead';
      intent: TransactionSigningIntent;
      snapshot: TransactionSigningSnapshot;
    }
  | { tag: 'LaneSelected'; intent: TransactionSigningIntent; lane: TransactionLane }
  | {
      tag: 'RestoreAttempted';
      intent: TransactionSigningIntent;
      lane: TransactionLane;
      restore: RestoreResult;
    }
  | {
      tag: 'ReadinessClassified';
      intent: TransactionSigningIntent;
      lane: TransactionLane;
      readiness: TransactionReadiness;
    }
  | {
      tag: 'AuthPlanned';
      intent: TransactionSigningIntent;
      lane: TransactionLane;
      authPlan: TransactionAuthPlan;
    }
  | {
      tag: 'AuthMaterialReady';
      operation: PreparedTransactionOperation;
      authMaterial: TransactionAuthMaterial;
    }
  | {
      tag: 'BudgetAdmitted';
      operation: BudgetAdmittedTransactionOperation;
    }
  | { tag: 'Signed'; operation: SignedTransactionOperation };
```

Transition functions should be explicit and exhaustive:

```ts
function selectLane(state: SnapshotRead): LaneSelected | SelectionFailed;
function restoreLane(state: LaneSelected): RestoreAttempted | RestoreFailed;
function classifyReadiness(state: RestoreAttempted): ReadinessClassified;
function planAuth(state: ReadinessClassified): AuthPlanned | TerminalFailure;
function admitBudget(state: AuthMaterialReady): BudgetAdmitted | BudgetUnavailable;
function sign(state: BudgetAdmitted): Signed | SigningFailed;
function finalize(state: Signed): Finalized | FinalizationFailed;
```

The module should be one owner of legal transaction transitions. NEAR/EVM/Tempo
curve adapters may restore exact lane material and perform curve-specific
signing, but they cannot select lanes, re-plan auth, discover budget identity, or
finalize a different lane.

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
3. hard account eligibility policy
4. current runtime record, when present

Outputs:

1. one concrete `TransactionLane`
2. or one typed `LaneSelectionFailure`

Selection rules:

1. Filter by `walletId`, `curve`, and `chain`.
2. Read only concrete candidate lists. Transaction selection must not consume
   collapsed `snapshot.lanes.*` summaries.
3. Hard policy may exclude impossible or disallowed lanes. Account preference,
   primary-auth metadata, and profile hints are not hard policy.
4. Define "current runtime record" as a verified concrete runtime candidate. An
   invalid or stale runtime record is not a selector anchor.
5. If runtime state is invalid or stale, the selector may run one cleanup/re-read
   pass that discards the invalid runtime hint and re-reads the side-effect-free
   snapshot. This cleanup pass must not restore, prompt, consume, publish a new
   lane, or switch auth method.
6. If a verified current runtime record exists, anchor selection to its exact
   concrete identity when that identity is present in the candidate list or can
   be normalized into a concrete candidate.
7. If a verified current runtime record exists but conflicts with the selected
   candidate set after cleanup/re-read, return `LaneSelectionFailure`; do not
   choose another candidate.
8. If multiple candidates remain, choose by explicit policy:
   ready runtime candidate, then restorable durable candidate, then newest stable
   metadata only if the ordering field is defined for all candidates.
9. If ordering metadata is missing or mixed, return `ambiguous_candidates`.
10. Never fall back from OTP to passkey or from passkey to OTP.
11. Never fall back to `candidates[0]`. Candidate ordering is an implementation
   detail unless the selector's policy explicitly defines it.

### Linked-Auth Selection Policy

Accounts may eventually have both passkey and Email OTP registered at the same
time. That must be modeled as explicit selection policy, not as a fallback.

If both auth methods have valid concrete lanes, either method can work, but the
choice must happen before restore, auth planning, budget admission, signing, or
finalization. Once selected, the operation cannot switch auth method.

Current implementation policy should stay minimal:

1. `{ kind: 'explicit' }`: select that auth method or return `no_candidate`.
2. `{ kind: 'account_class' }`: select the auth method implied by the current
   account class when it has a valid concrete candidate.
3. `{ kind: 'current_lane' }`: keep using the exact current lane's auth method
   when the lane has already been verified as concrete.

Future linked-auth UI can add explicit user-choice and persisted last-used
policy, but those should be added only when the product surface exists. Until
then, do not introduce unused policy variants in production types.

Future policy order:

1. explicit user-selected auth method
2. persisted last-used method, recorded only after successful finalization
3. product default method
4. typed ambiguity requiring user choice

Rules:

1. Future `last_used` must be persisted policy input. It must not be inferred
   from whichever runtime record happens to exist after restore or reauth side
   effects.
2. Explicit user choice outranks last-used, default, and current-account policy.
3. Last-used/default/account-class/current-lane policy may choose between valid
   lanes, but may not hide a selected concrete runtime lane mismatch.
4. If a policy-selected auth method has no concrete lane, selection returns a
   typed failure. It does not silently try the other auth method.
5. Ambiguity is a valid selector result. The UI can resolve it by resubmitting the
   same signing intent with `{ kind: 'explicit', authMethod }`.
6. Same-lane invariants remain unchanged after selection: OTP lanes can only plan
   OTP reauth, and passkey lanes can only plan passkey reauth.

Example:

```text
intent(authSelectionPolicy = { kind: 'explicit', authMethod: 'email_otp' })
  -> select concrete Email OTP lane
  -> exact Email OTP restore
  -> Email OTP readiness/auth/budget/sign/finalize
```

```text
intent(authSelectionPolicy = { kind: 'account_class', authMethod: 'passkey' })
  -> select concrete passkey lane if present
  -> exact passkey restore
  -> passkey readiness/auth/budget/sign/finalize
```

## Restore Model

Exact operation restore has concrete input shapes:

```ts
type ExactRestoreInput =
  | { reason: 'transaction'; lane: TransactionLane }
  | { reason: 'key_export'; lane: ConcreteKeyExportLane };
```

Key export is exact-purpose, like transaction signing. It must use an exact
export lane and same-method auth policy; it must not use broad maintenance
restore.

Broad restore belongs only to maintenance commands:

```ts
type MaintenanceRestoreInput = {
  reason: 'session_status' | 'startup_maintenance';
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
5. Maintenance restore cannot be imported by transaction signing or key-export
   modules.

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
2. `sessionBudgetUses`: capacity minted by transaction step-up.
3. `remainingUses`: trusted server remaining budget.
4. `availableUses`: local admission hint after same-projection in-flight holds.
5. `projectionVersion`: opaque causal token for the trusted server status.

Rules:

1. Transaction signing uses `operationUsesNeeded = 1` unless product policy
   explicitly changes the definition of a signing operation.
2. NEAR batched transactions remain one signing operation by default.
3. Transaction step-up uses `sessionBudgetUses = operationUsesNeeded`.
4. Reusable sessions are out of scope for transaction intent. They require a
   separate command and specs.
5. Warm-session budget identity is captured before signing.
6. Reauth-created budget identity is captured immediately after mint/reconnect
   and before signing.
7. `BudgetAdmitted` is the common state-machine phase. Curve adapters define
   whether admission means local in-flight hold, server consume, or
   already-consumed reconciliation.
8. Ed25519 server-side signing may consume the authoritative budget during the
   signing ceremony. Finalization reconciles an already-consumed selected lane; it
   must not prepare budget identity after signing.
9. Local in-flight holds never change `remainingUses`. They produce
   `inFlightReservedUses` and `availableUses`.
10. Projection-version comparison is equality only. Opaque versions are not
   ordered.
11. A stale prepared projection causes refresh/reprepare of budget identity, not
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

1. [x] OTP account, Ed25519 session exhausted, next NEAR tx shows OTP and succeeds.
2. [x] Passkey account, Ed25519 session exhausted, next NEAR tx shows passkey and
   succeeds.
3. [x] Passkey Ed25519 step-up mints one operation use and does not fail post-sign
   budget finalization.
4. [x] OTP ECDSA step-up does not publish a current Ed25519 transaction lane.
5. [x] OTP account with passkey durable state never shows passkey for NEAR Ed25519.
6. [x] Passkey account with OTP durable state never shows OTP for NEAR Ed25519.
7. [x] Refresh with durable sealed state and valid server budget signs without auth.
8. [x] Missing worker memory with valid durable state signs without auth.
9. [x] Missing worker memory with exhausted server budget shows same-method step-up.
10. [x] Three fast sequential txs behave the same as three slow sequential txs.
11. [x] Linked-auth account with both valid OTP and passkey candidates honors an
    explicit OTP selection and never prompts passkey.
12. [x] Linked-auth account with both valid OTP and passkey candidates honors an
    explicit passkey selection and never prompts OTP.
13. [x] Linked-auth account using account-class OTP policy selects OTP
    deterministically.
14. [ ] Future linked-auth user-choice mode returns typed `ambiguous_candidates`
    instead of silently choosing a method when policy requires user choice.

### Phase 2: Introduce Concrete Transaction Types

1. [x] Add `TransactionSigningIntent`.
2. [x] Add the minimal `AuthSelectionPolicy` and make it part of
   `TransactionSigningIntent`.
3. [x] Add `TransactionLane`.
4. [x] Add `PreparedTransactionOperation`.
5. [x] Add `BudgetAdmittedTransactionOperation`.
6. [x] Add `SignedTransactionOperation`.
7. [x] Add `LaneSelectionFailure`.
8. [x] Convert transaction restore input to `TransactionRestoreInput`.
9. [x] Convert transaction budget/finalizer inputs to accept `TransactionLane`.
   - [x] Transaction-state auth-planned, budget-admitted, and signed states are
     generic over `TransactionLane` instead of being NEAR Ed25519-only.
   - [x] Budget identity preparation accepts exact `TransactionLane` values.
   - [x] Budget finalization accepts exact `TransactionLane` values.
   - [x] NEAR Ed25519 finalization uses the admitted transaction lane instead
     of rebuilding a spend lane from mutable session state.
10. [x] Keep raw snapshot and storage types separate from resolved transaction types.

Acceptance:

1. No transaction module can compile with optional `walletSigningSessionId`.
2. No transaction module can compile with optional `thresholdSessionId`.
3. No transaction restore call can compile with only `authMethod + curve + chain`.
4. No transaction selector can run without an explicit `AuthSelectionPolicy`.
5. Signing cannot compile with a pre-budget `PreparedTransactionOperation`; it
   requires `BudgetAdmittedTransactionOperation`.
6. Finalization cannot compile without a `SignedTransactionOperation`.

### Phase 3: Build The Pure Selector

1. [x] Implement `selectTransactionLane(intent, snapshot, policy)`.
2. [x] Move NEAR Ed25519 selection into this selector.
3. [x] Move ECDSA selection into this selector.
   - [x] EVM-family ECDSA snapshot candidate selection now uses the shared
     transaction selector.
   - [x] EVM-family ECDSA runtime material lookup is anchored to the selected
     exact snapshot candidate when one exists.
   - [x] EVM-family ECDSA runtime material lookup receives the shared selector's
     transaction lane identity for exact snapshot candidates.
   - [x] EVM-family prepare now fails without an exact snapshot lane instead of
     falling back to curve-specific runtime lane discovery.
4. [x] Remove selection from lower transaction flows.
   - [x] EVM/Tempo lower signing flows now hard-fail threshold ECDSA
     execution without a prepared signing auth plan instead of defaulting to
     passkey/WebAuthn selection.
   - [x] NEAR Ed25519 lower signing flow receives the prepared auth plan and
     no longer selects lanes or plans threshold auth itself.
5. [x] Delete `candidates[0]` fallback after runtime mismatch.
6. [x] Delete account-primary fallback after concrete candidate selection.
7. [x] Delete OTP/passkey probing.
8. [x] Delete transaction selection from collapsed `snapshot.lanes.*` summaries for NEAR Ed25519.
9. [x] Implement the minimal linked-auth policy surface:
   - explicit auth method
   - account-class auth method
   - current-lane auth method
10. [x] Keep persisted last-used, product default, and user-choice ambiguity as
    future extensions until the linked-auth UI ships.
11. [x] Add the one allowed runtime cleanup path for NEAR Ed25519:
    - discard invalid/stale runtime hint before transaction selection
    - read the side-effect-free snapshot once after cleanup
    - continue only from a concrete durable candidate or typed failure
    - no restore, prompt, consume, publish, or auth-method switch during cleanup

Acceptance:

1. Given the same intent, snapshot, and policy, selection is deterministic.
2. Linked-auth accounts cannot drift to the other auth method.
3. Selection failures are typed and visible in tests.
4. Snapshot readers expose concrete Ed25519 and ECDSA candidate lists.
5. Transaction selection never treats collapsed lanes as authority.
6. If both OTP and passkey are valid, selector output is determined only by
   explicit, account-class, or current-lane policy for now.
7. Future user-choice mode returns `ambiguous_candidates` with both allowed auth
   methods.
8. Invalid runtime state can be cleaned up once without broadening restore or
   switching auth method.

### Phase 4: Collapse Prepare Into The State Machine

1. [x] Create the initial transaction state module with typed intent, lane,
   prepared/admitted operation, and lane-selection failures.
2. [x] Add full discriminated-union transition states and explicit transition
   functions.
3. [x] Create one `prepareTransactionSigningOperation(intent)` path.
   - [x] NEAR Ed25519 transaction prepare is isolated behind a named
     `prepareNearEd25519TransactionOperation(...)` path.
   - [x] Generalize that boundary across transaction curves.
   - [x] NEAR Ed25519 and EVM-family ECDSA transaction prepare now both call
     the shared `prepareTransactionSigningOperation(...)` boundary.
4. [x] NEAR Ed25519 prepare performs snapshot read, lane selection, exact restore, readiness
   classification, and auth planning.
5. [x] It returns `PreparedTransactionOperation`.
   - [x] NEAR Ed25519 prepare now produces a `PreparedTransactionOperation`
     from the typed readiness state.
   - [x] Generalize that return type across transaction curves.
   - [x] EVM-family ECDSA prepare now carries a generic
     `PreparedTransactionOperation<EvmFamilyEcdsaTransactionLane>`.
6. [x] `admitBudget(...)` converts `PreparedTransactionOperation` into
   `BudgetAdmittedTransactionOperation`.
   - [x] NEAR Ed25519 warm-session budget identity is converted into an
     explicit `BudgetAdmittedOperation` before the worker payload sees it.
   - [x] NEAR Ed25519 reauth-created sessions return a replacement
     `BudgetAdmittedOperation` immediately after OTP/passkey mint.
   - [x] Shared transaction prepare returns `BudgetAdmittedOperation` when the
     threshold planner admits trusted warm-session budget.
7. [ ] `sign(...)` accepts only `BudgetAdmittedTransactionOperation`.
   - [x] NEAR Ed25519 worker requests now require `BudgetAdmittedOperation`.
   - [x] NEAR Ed25519 signing now uses the shared
     `signPreparedTransactionOperation(...)` helper.
8. [ ] `finalize(...)` accepts only `SignedTransactionOperation`.
   - [x] NEAR Ed25519 success finalization now records a
     `SignedTransactionOperation` from the admitted worker state.
   - [x] NEAR Ed25519 success finalization now uses the shared
     `finalizeSignedTransactionOperation(...)` helper.
9. [ ] NEAR/EVM/Tempo transaction flows receive state-machine operation types only.
10. [x] NEAR Ed25519 lower flow no longer plans auth, selects lanes, or restores sessions.
11. [x] Lower flows no longer discover
   budget identity.
   - [x] NEAR Ed25519 post-confirm reauth asks the API prepare boundary to
     admit an exact transaction lane instead of calling budget discovery
     directly.

Acceptance:

1. `transactionsFlow.ts` cannot run without a prepared operation.
2. EVM-family execution cannot run without a prepared operation.
3. There is no production transaction path that calls the planner with an
   already-mutated or re-selected lane.
4. There is no generic state-machine framework; the implementation is a small
   module of typed states and boring transition functions.
5. Curve adapters cannot compile if they attempt to select lanes, plan auth, or
   discover budget identity.

### Phase 5: Make Reauth Replace Prepared Operations

1. OTP reauth returns a new `TransactionLane`.
2. Passkey reauth returns a new `TransactionLane`.
3. Reauth result replaces the prepared operation before budget or signing.
4. Fresh-auth retry paths return the replacement prepared operation.
5. Mutable outer session objects are deleted from finalization paths.

Acceptance:

1. Old prepared lanes cannot be finalized after fresh auth.
2. Post-reauth signing and finalization use the new wallet/threshold session IDs.
3. Transaction step-up sessions mint `sessionBudgetUses = operationUsesNeeded`.
4. Reusable sessions are not represented by transaction intent and cannot be
   minted by transaction step-up.

### Phase 6: Fix Budget Timing

1. Capture budget admission before signing for warm lanes.
   - [x] NEAR Ed25519 warm lanes carry `BudgetAdmittedOperation` before the
     budget identity is passed into transaction execution.
2. Capture budget admission immediately after OTP/passkey mint for reauth lanes.
   - [x] NEAR Ed25519 reauth-created lanes now prepare trusted budget identity
     before the signer worker request instead of rediscovering it only during
     finalization.
   - [x] Wrap that refreshed identity in a replacement `BudgetAdmittedOperation`
     so reauth and warm lanes use the same state-machine object.
3. Split pre-admission and post-admission types:
   `PreparedTransactionOperation` cannot be signed directly;
   `BudgetAdmittedTransactionOperation` is required.
   - [x] NEAR Ed25519 exposes both `PreparedTransactionOperation` and
     `BudgetAdmittedOperation` in the prepared session type.
   - [x] NEAR Ed25519 lower signing now requires a prepared transaction
     operation and replaces it with a budget-admitted operation after
     reauth-created lanes are minted.
   - [x] NEAR Ed25519 signing must require the admitted type for every worker
     request at the payload type boundary.
4. [x] For NEAR Ed25519, mark finalization as reconciliation of the already-consumed
   selected threshold session.
5. [x] Remove budget-identity preparation from NEAR Ed25519 post-sign finalization.
6. [x] Reprepare budget identity on stale projection if the server still has enough
   remaining budget; do not step up because of local projection staleness.

Acceptance:

1. Passkey Ed25519 step-up cannot sign successfully and then fail with wallet
   budget exhausted.
2. OTP Ed25519 step-up has the same budget behavior as passkey Ed25519 step-up.
3. Fast and slow signing use the same readiness and auth classification.
4. No signer accepts a state before `BudgetAdmitted`.
5. No finalizer accepts a state before `Signed`.

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
10. transaction `providedSessionId` overrides that do not equal prepared identity
11. account-level session lookup after prepare
12. key-export paths that import maintenance restore
13. transaction step-up paths that mint reusable-session capacity
14. generic state-machine framework code if it adds hidden callback authority

Acceptance:

1. Static guards fail on every deleted pattern.
2. Maintenance restore remains available only outside transaction modules.
3. The transaction path is shorter after the migration, not larger.

### Phase 8: Update Docs And Ownership

1. Delete stale migration logs instead of keeping them as parallel design
   authority.
2. Keep `signing-session-architecture.md` as a short pointer to this
   state-machine plan.
3. Keep `signing-session-refresh-intent.md` as the product intent.
4. Keep `signing-session-auth-and-budget.md` as the active auth/budget model.
5. Keep `email-otp-secret-restore.md` as the active Email OTP secret/restore
   model.
6. Remove duplicate architecture specs that contradict the state machine.

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
10. no key-export module importing maintenance restore helpers
11. no account-level session lookup after `PreparedTransactionOperation`
12. no `providedSessionId` override unless it equals prepared
    `thresholdSessionId`
13. no transaction selector reading collapsed `snapshot.lanes.*` as authority
14. no transaction path that catches exact restore failure and continues to a
    generic not-ready error

Prefer compile-time boundaries over text guards. Keep grep/static guards only for
historical footguns that the type system cannot easily prevent.

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

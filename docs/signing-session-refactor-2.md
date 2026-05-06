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
     execution without a budget-admitted transaction operation instead of
     defaulting to passkey/WebAuthn selection.
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
7. [x] Threshold transaction signing accepts only admitted transaction operation state.
   - [x] NEAR Ed25519 worker requests now require `BudgetAdmittedOperation`.
   - [x] NEAR Ed25519 signing now uses the shared
     `signPreparedTransactionOperation(...)` helper.
   - [x] EVM/Tempo lower threshold ECDSA flows receive a
     `BudgetAdmittedTransactionOperation` carrying both the admitted lane and
     auth plan before they can reserve budget or show confirmation.
8. [ ] `finalize(...)` accepts only `SignedTransactionOperation`.
   - [x] NEAR Ed25519 success finalization now records a
     `SignedTransactionOperation` from the admitted worker state.
   - [x] NEAR Ed25519 success finalization now uses the shared
     `finalizeSignedTransactionOperation(...)` helper.
9. [x] NEAR/EVM/Tempo transaction flows receive state-machine operation types only.
   - [x] NEAR Ed25519 lower signing receives `PreparedTransactionOperation`
     and `BudgetAdmittedOperation`.
   - [x] EVM/Tempo lower threshold ECDSA signing receives
     `BudgetAdmittedTransactionOperation` instead of loose `signingAuthPlan`
     plus unscoped budget reservation callbacks.
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
3. [x] Split pre-admission and post-admission types:
   `PreparedTransactionOperation` cannot be signed directly;
   `BudgetAdmittedTransactionOperation` is required.
   - [x] NEAR Ed25519 exposes both `PreparedTransactionOperation` and
     `BudgetAdmittedOperation` in the prepared session type.
   - [x] NEAR Ed25519 lower signing now requires a prepared transaction
     operation and replaces it with a budget-admitted operation after
     reauth-created lanes are minted.
   - [x] NEAR Ed25519 signing must require the admitted type for every worker
     request at the payload type boundary.
   - [x] EVM/Tempo threshold ECDSA signing receives
     `BudgetAdmittedTransactionOperation` before confirmation and budget
     reservation.
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

### Phase 9: Delete Remaining Side-Channel Authorities

Goal: remove the remaining paths that can select, reselect, admit, or finalize
signing-session state outside the transaction state machine. The transaction
state machine must be the only owner of lane identity, auth method, exact
restore, material lookup, budget admission, signing, and finalization.

#### 9.1 Remove Per-Account Ed25519 Runtime Selection

Current risk: `thresholdSessionStore.ts` still exposes a singleton
`getStoredThresholdEd25519SessionRecordForAccount(...)`. When transaction or
export prepare reads that record before lane selection, the latest runtime record
can become the auth-method authority even if it belongs to the wrong auth lane.

Implementation steps:

1. [x] Stop using `getStoredThresholdEd25519SessionRecordForAccount(...)` in
   pre-selection NEAR transaction code.
   - Edit `client/src/core/signingEngine/api/nearSigning.ts`.
   - Remove record-backed calls to `resolveNearEd25519AuthSelectionPolicy(...)`.
   - Make `prepareNearEd25519TransactionOperation(...)` read
     `snapshot.candidates.ed25519.near` first, then select a concrete lane.
2. [x] Replace `resolveNearEd25519AuthSelectionPolicy(...)` with a selector input
   derived from snapshot candidates.
   - Keep only explicit policy from caller/product state, account-class policy
     when no current lane exists, and selected concrete lane policy.
   - Do not derive `current_lane` from a per-account runtime record.
3. [x] After `selectTransactionLane(...)` returns a concrete
   `NearEd25519TransactionLane`, resolve runtime material by full lane identity.
   - Add or use a lane-keyed lookup:
     `getStoredThresholdEd25519SessionRecordForLane({ accountId, authMethod,
     walletSigningSessionId, thresholdSessionId })`.
   - If the exact runtime record is missing, restore exact durable state or
     classify readiness as missing/restorable. Do not inspect another account
     record.
4. [x] Delete the transaction-path stale-runtime account cleanup path.
   - Runtime candidates only anchor selection when the exact lane-keyed runtime
     record exists.
   - If the snapshot omits the exact lane, transaction selection fails instead
     of falling back to an account-scoped runtime record.

Data structures and functions to edit:

1. `client/src/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore.ts`
   - Add lane-keyed Ed25519 runtime accessors.
   - Deprecate or restrict account-keyed accessors to maintenance/status code.
2. `client/src/core/signingEngine/api/nearSigning.ts`
   - `resolveNearEd25519AuthSelectionPolicy(...)`
   - `prepareNearEd25519TransactionOperation(...)`
   - `resolveNearEd25519RuntimeRecordForSelectedIdentity(...)`
   - `publishNearEd25519RuntimeIdentityForRecord(...)`
3. `client/src/core/signingEngine/session/signingSession/transactionState.ts`
   - `selectTransactionLane(...)`
   - `TransactionAuthSelectionPolicy`
   - `TransactionSnapshotReadState.currentRuntimeLane`

Acceptance:

1. OTP accounts cannot show passkey prompts because a passkey Ed25519 runtime
   record was last published for the account.
2. Passkey accounts cannot show OTP prompts because an OTP Ed25519 runtime record
   was last published for the account.
3. Runtime material lookup happens only after a concrete lane has been selected.
4. Transaction selection never calls account-keyed Ed25519 runtime lookup.

#### 9.2 Make Transaction Execution Require Budget-Admitted State

Current risk: NEAR, EVM, and Tempo signing used to have a
`post_reauth_admission` boundary variant. That kept a callback authority inside
the lower signing flow: the lower flow could run confirmation/reauth, then ask a
callback to admit budget before signing. This was better than optional fields,
but it still meant execution could begin before the object was a
`BudgetAdmittedTransactionOperation`.

Implementation steps:

1. [x] Delete `post_reauth_admission` from:
   - `NearEd25519TransactionAdmissionBoundary`
   - `EvmThresholdEcdsaAdmissionBoundary`
   - `TempoThresholdEcdsaAdmissionBoundary`
   - `EvmFamilyThresholdEcdsaAdmissionBoundary`
2. [x] Delete the lower-flow admission callback authority.
   - EVM/Tempo reauth callbacks now return `{ keyRef, operation }`, where
     `operation` is the budget-admitted transaction operation for the fresh
     exact ECDSA lane.
   - NEAR no longer accepts a boundary callback; the transaction state-machine
     flow admits budget directly from the selected exact Ed25519 lane after
     confirmed reauth.
   - Guards now reject `post_reauth_admission` and `thresholdEcdsaBoundary.admit`.
3. [x] Make the lower NEAR/EVM/Tempo threshold signing boundary accept only:
   - `{ kind: 'not_required' }` for non-threshold signing, or
   - `{ kind: 'admitted'; operation: BudgetAdmittedTransactionOperation }`
     for threshold signing.
   - Pre-sign confirmation orchestration carries the selected auth plan and an
     `initialBudgetAdmittedOperation` slot, not a separate
     `confirmed_auth_required` boundary state.
4. [x] Move reauth completion and post-reauth budget admission before
   lower threshold signing execution.
   - NEAR Ed25519 reauth must return a fresh exact Ed25519 lane.
   - EVM/Tempo ECDSA reauth must return a fresh exact ECDSA lane.
   - The reauth completion callback immediately prepares/admites a replacement
     transaction operation for that lane.
   - Only the admitted replacement operation may enter lower signing.
5. [x] Remove finalization recovery that calls `ensurePreparedEcdsaBudgetIdentity`
   after signing.
   - Successful finalization should receive `SignedTransactionOperation`.
   - Failed finalization should receive the admitted operation that entered
     signing.

Data structures and functions to edit:

1. `client/src/core/signingEngine/interfaces/near.ts`
   - `NearEd25519TransactionAdmissionBoundary`
2. `client/src/core/signingEngine/orchestration/near/transactionsFlow.ts`
   - lower flow auth/admission derivation
   - remove `admitBudgetForTransactionLane(...)` callback authority
3. `client/src/core/signingEngine/api/nearSigning.ts`
   - construct admitted NEAR Ed25519 operations before calling
     `signPreparedTransactionsWithActions(...)`
   - replace reauth-created lane with a new admitted operation before signing
4. `client/src/core/signingEngine/orchestration/evm/evmSigningFlow.ts`
   - consumes `EvmFamilyThresholdEcdsaAdmissionBoundary`
   - lower flow auth/admission derivation
5. `client/src/core/signingEngine/orchestration/tempo/tempoSigningFlow.ts`
   - consumes `EvmFamilyThresholdEcdsaAdmissionBoundary`
   - lower flow auth/admission derivation
6. `client/src/core/signingEngine/api/evmFamily/transactionExecutor.ts`
   - `EvmFamilyThresholdEcdsaAdmissionBoundary`
   - `executeEvmFamilyTransactionSigning(...)`
7. `client/src/core/signingEngine/orchestration/shared/thresholdEcdsaTransactionAdmission.ts`
   - shared EVM-family admitted operation, reauth result, and boundary types
8. `client/src/core/signingEngine/api/evmSigning.ts`
   - `replacePreparedEcdsaSigningOperationAfterReauth(...)`
   - `ensurePreparedEcdsaBudgetIdentity(...)`
   - `thresholdEcdsaBoundary` construction
   - successful and failed finalization paths
9. `client/src/core/signingEngine/session/signingSession/transactionState.ts`
   - `BudgetAdmittedTransactionOperation`
   - `signPreparedTransactionOperation(...)`
   - `finalizeSignedTransactionOperation(...)`

Acceptance:

1. NEAR/EVM/Tempo threshold signing cannot call the lower executor without an
   admitted operation.
2. Reauth replaces the prepared operation before lower signing is called.
3. Finalization never prepares budget identity after signing.
4. The old “execute now, admit later” path does not compile.

#### 9.3 Remove Budget From Generic Prepared Threshold Operation

Current risk: `PreparedThresholdSigningOperation` still has
`budgetIdentity?` and `budgetProjectionVersion?`. That keeps generic threshold
prepare coupled to transaction budget admission and permits “maybe budget later”
behavior.

Implementation steps:

1. [x] Delete `budgetIdentity?` and `budgetProjectionVersion?` from
   `PreparedThresholdSigningOperation`.
2. [x] Change `prepareThresholdSigningOperation(...)` so it only returns
   threshold readiness, lane, plan, snapshot generation, and metadata.
3. [x] Move transaction budget admission fully into
   `prepareTransactionSigningOperation(...)`.
   - If `prepareBudgetIdentity: true`, return `budget.kind === 'admitted'`.
   - If budget admission is not requested, return `budget.kind ===
     'not_admitted'`.
4. [x] Update every caller that reads `thresholdOperation.budgetIdentity` to read
   `preparedTransaction.budget` instead.

Data structures and functions to edit:

1. `client/src/core/signingEngine/session/signingSession/preparedOperation.ts`
   - `PreparedThresholdSigningOperation`
   - `prepareThresholdSigningOperation(...)`
2. `client/src/core/signingEngine/session/signingSession/transactionState.ts`
   - `PreparedTransactionSigningOperation`
   - `PreparedTransactionBudgetState`
   - `prepareTransactionSigningOperation(...)`
3. `client/src/core/signingEngine/api/nearSigning.ts`
   - prepared Ed25519 transaction session construction
4. `client/src/core/signingEngine/api/evmFamily/preparedSigning.ts`
   - prepared ECDSA transaction session construction
5. `client/src/core/signingEngine/api/evmSigning.ts`
   - ECDSA budget admission and finalization state

Acceptance:

1. Only `BudgetAdmittedOperation` and `BudgetAdmittedTransactionOperation` carry
   budget identity.
2. Generic threshold prepare has no transaction budget fields.
3. No production transaction signer can read `budgetIdentity` from
   `PreparedThresholdSigningOperation`.

#### 9.4 Make Key Export Exact-Lane First

Current risk: key export still has auth-method-first helpers. Even if exact
restore exists later, selecting auth before selecting an export lane can restore
one lane and export from another.

Implementation steps:

1. [x] Delete `resolveNearEd25519ExportAuthMethod(...)`.
2. [x] Add `resolveNearEd25519ExportLane(accountId)` that returns a concrete
   export lane or fails with `no_candidate` / `ambiguous_candidates`.
3. [x] Add `resolveEcdsaExportLane(accountId, chain)` that returns a concrete
   export lane or fails with `no_candidate` / `ambiguous_candidates`.
4. [x] Make exact restore, material lookup, prompt selection, and export use that
   selected lane object.
5. [x] Reject export if selected lane and resolved material differ in
   `authMethod`, `walletSigningSessionId`, or `thresholdSessionId`.

Data structures and functions to edit:

1. `client/src/core/signingEngine/SigningEngine.ts`
   - `resolveNearEd25519ExportAuthMethod(...)`
   - `resolveNearEd25519ExportRestoreLane(...)`
   - `resolveEcdsaExportRestoreLane(...)`
   - `exportThresholdEcdsaKeyWithAuthorization(...)`
   - NEAR Ed25519 key export path
2. `client/src/core/signingEngine/session/signingSession/transactionState.ts`
   - add or reuse exact lane types for export, separate from transaction if
     export policy differs.
3. `client/src/core/signingEngine/session/restoreCoordinator.ts`
   - keep `reason: 'export'` exact-lane input mandatory when export uses a
     selected lane.

Acceptance:

1. Export prompt method is derived from the selected concrete export lane.
2. Export cannot broad-restore by auth method alone.
3. Export cannot restore lane A and export lane B.

#### 9.5 Add Guards For The Deleted Paths

Invert stale guards and add/tighten guards in
`tests/unit/signingSessionCoordinator.architecture.guard.unit.test.ts`.

Guard targets:

1. [x] `nearSigning.ts` transaction prepare does not call
   `getStoredThresholdEd25519SessionRecordForAccount(...)` before lane
   selection.
2. [x] `nearSigning.ts` does not expect or contain
   `resolveNearEd25519AuthSelectionPolicy(... record ...)`.
3. [x] `PreparedThresholdSigningOperation` does not contain `budgetIdentity?` or
   `budgetProjectionVersion?`.
4. [x] NEAR/EVM/Tempo lower execution boundaries do not contain
   `post_reauth_admission`.
5. [x] Export code does not contain auth-method-first helpers:
   `resolveNearEd25519ExportAuthMethod(...)` or equivalent.
6. [x] Transaction/export code does not use account-keyed Ed25519 runtime record
   lookup as selection authority.
7. [x] Existing guard expectations that currently require
   `resolveNearEd25519AuthSelectionPolicy` or `post_reauth_admission` are
   inverted in the same patch that deletes those paths.

#### 9.6 Closeout Audit Against Refresh Intent

After Phase 9.2 is fully implemented, audit the refactored flows against
`docs/signing-session-refresh-intent.md` before declaring Phase 9 complete.
This is a closeout gate, not a follow-up cleanup.

Audit scope:

1. [x] Page-refresh persistence.
   - OTP account: unlock, refresh, first Ed25519 transaction signs without OTP
     when budget is valid.
   - OTP account: unlock, refresh, first ECDSA transaction signs without OTP
     when budget is valid.
   - Passkey account: unlock, refresh, first Ed25519 transaction signs without
     passkey prompt when budget is valid.
   - Passkey account: unlock, refresh, first ECDSA transaction signs without
     passkey prompt when budget is valid.
2. [x] Exhaustion behavior.
   - OTP account: exhausted Ed25519 and ECDSA transactions prompt Email OTP and
     succeed after step-up.
   - Passkey account: exhausted Ed25519 and ECDSA transactions prompt passkey
     and succeed after step-up.
   - Refresh alone never causes an exhaustion classification.
3. [x] Storage ownership.
   - IndexedDB durable sealed records plus non-secret lane identity are enough
     to restore after reload.
   - Worker memory is treated only as hot unsealed material.
   - `sessionStorage` is not required for signing-session correctness.
   - JS memory carries only operation-local prepared identity.
4. [x] Read-side safety.
   - Status polling and snapshots do not unseal, restore, consume, delete, or
     prompt.
   - Snapshot states distinguish durable restorable state from true missing
     state.
5. [x] Per-curve exactness.
   - NEAR Ed25519 restore restores only Ed25519 material for the selected exact
     lane.
   - Tempo/EVM ECDSA restore restores only ECDSA material for the requested
     exact chain lane.
   - ECDSA and Ed25519 do not work because the other curve published companion
     state as a side effect.
6. [x] Command-boundary shape.
   - Transaction signing flows visibly follow: exact intent, exact lane
     selection, exact restore, trusted budget status, budget admission, sign,
     authoritative consume/finalize.
   - Lower signing flows cannot reselect lane/auth, restore broad state, or
     admit budget after signing has started.
7. [x] Key export sanity.
   - Ed25519 and ECDSA export prompt method comes from the selected exact export
     lane.
   - Export cannot restore lane A and export lane B.

Verification commands:

1. `pnpm build:sdk`
2. Focused unit suites covering transaction state, architecture guards,
   Ed25519 selection, ECDSA export, Email OTP bootstrap, and immediate Ed25519
   fallback.
3. Manual smoke tests for OTP and passkey accounts across refresh and
   exhaustion for Ed25519 and ECDSA.

### Phase 10: Delete Opaque Lane-Resolution Helpers

Current risk: some helpers look like plumbing, but still choose partial identity
such as `authMethod`, account class, or reauth/admission behavior. That obscures
the real lane-resolution flow and lets old loose paths re-enter through helper
boundaries. Exact-purpose code should make the selected concrete lane the first
authority-bearing value, then carry that same lane through restore, material
lookup, prompt selection, admission, signing, finalization, and export.

Implementation rules:

1. Helpers may be small, but they must be either pure or exact-lane based.
2. A helper must not choose only `authMethod`, account metadata class, current
   account record, or fallback session identity as a substitute for a concrete
   lane.
3. A helper that chooses authority must return the full concrete lane selection
   result, including failure kind, not a partial hint for another helper to
   reinterpret.
4. Restore, prompt, material, and export helpers must accept the selected lane
   object. They must not internally reselect auth method or lane.
5. Budget/admission helpers must not hide “admit later” callback authority below
   the transaction execution boundary.

Implementation steps:

1. [x] Replace export auth-method helpers with exact lane resolvers.
   - Delete `resolveNearEd25519ExportAuthMethod(...)`.
   - Delete `resolveEcdsaExportAuthMethod(...)`.
   - Add `resolveNearEd25519ExportLane(...)`.
   - Add `resolveEcdsaExportLane(...)`.
2. [x] Make key export read as a visible linear flow:
   - resolve exact export lane
   - restore that exact lane when needed
   - resolve material for that exact lane
   - select the prompt from that exact lane
   - export using that exact lane
3. [x] Delete or inline helpers that choose partial identity before lane
   selection.
   - No helper should return only `authMethod` when the caller really needs a
     lane.
   - No helper should use account metadata as lane-selection authority after a
     concrete runtime lane exists.
   - NEAR transaction selection now returns a selected Ed25519 lane directly via
     `selectNearEd25519TransactionLaneFromSnapshot(...)`.
   - ECDSA transaction prepare now calls `selectTransactionLane(...)` directly
     after deriving its candidate snapshot and runtime anchor.
4. [x] Keep pure helpers and exact-lane assertions.
   - Keep predicates such as `isConcrete...Lane(...)`.
   - Keep assertions such as `assert...MatchesLane(...)`.
   - Keep material lookup helpers only when they require full lane identity.
5. [x] Rename remaining helpers so their authority is obvious.
   - `resolve...Lane(...)` may select a lane and must return a full lane or a
     typed selection failure.
   - `assert...MatchesLane(...)` may only validate.
   - `get...ForLane(...)` may only perform exact-identity lookup.
   - Avoid names like `resolve...AuthMethod(...)` in exact-purpose flows.
   - Runtime-anchor lookup is named `getSingleRuntimeBackedEcdsaSnapshotLane(...)`
     to make clear it does not select a transaction lane by itself.
6. [x] Make ECDSA transaction prepare show the lane-resolution order directly.
   The code should make the sequence easy to audit:
   - read snapshot
   - derive concrete runtime anchor from candidates
   - derive fallback policy only when no runtime anchor or explicit selector
     applies
   - select concrete lane
   - exact restore
   - material lookup
7. [x] Remove lower-flow admission callback authority.
   Transaction execution should receive `admitted` or `not_required`; reauth
   that creates a new lane must return to the owner that can admit it before
   execution continues.
   - Phase 9.2 removed `post_reauth_admission`, `reauth_required`, and
     `confirmed_auth_required` as executable boundary states.

Data structures and functions to audit:

1. `client/src/core/signingEngine/SigningEngine.ts`
   - key export lane resolution
   - exact restore helpers
   - material lookup helpers
   - `exportThresholdEcdsaKeyWithAuthorization(...)`
2. `client/src/core/signingEngine/api/evmFamily/preparedSigning.ts`
   - ECDSA runtime-anchor and fallback-policy ordering
   - exact transaction restore boundary
3. `client/src/core/signingEngine/api/evmSigning.ts`
   - ECDSA admission boundary
4. `client/src/core/signingEngine/api/nearSigning.ts`
   - Ed25519 transaction and export lane preparation
5. `client/src/core/signingEngine/orchestration/**`
   - any lower-flow `post_reauth_admission` or equivalent callback authority

Acceptance:

1. Export code never selects an auth method before selecting a concrete export
   lane.
2. Export code never restores by auth method alone.
3. Export prompt method, material lookup, and authorization all come from the
   same selected lane.
4. Transaction prepare code has one visible lane-resolution sequence per curve.
5. Remaining helpers are pure predicates/assertions or exact-lane lookups.
6. No exact-purpose flow contains helper boundaries that can silently fall back
   to account metadata, account-keyed runtime records, or bootstrap behavior.

### Phase 11: Delete Transitional Cleanup Bloat

Current risk: after the deterministic lane model lands, transitional wrappers can
keep the old architecture alive under new names. The cleanup target is deletion,
not another abstraction layer. If a helper exists only to translate old partial
state into new exact-lane state, remove it and make callers pass the exact lane or
admitted operation directly.

Prune rule:

1. Delete helpers that exist only to translate partial identity into exact-lane
   identity.
2. Keep helpers only when they are pure predicates, exact-lane assertions,
   exact-lane lookups, or real shared algorithms.
3. Prefer compile-time boundaries over helper-name conventions.
4. After each phase lands, run a deletion pass before adding new wrappers.

Implementation steps:

1. [x] Remove partial-identity export selection entirely.
   - `selectExactExportSnapshotLane(...)` must not accept `accountAuthMethod` or
     use account metadata as a tie-breaker.
   - Exact export should resolve one concrete lane, receive an explicit selector,
     or fail with `ambiguous_candidates`.
   - Do not let export select an auth-method hint before lane selection.
2. [x] Collapse export into one visible lane-first flow.
   - Resolve exact export lane.
   - Restore that exact lane.
   - Resolve material for that exact lane.
   - Authorize using that exact lane.
   - Export using that exact lane.
   - Keep pure assertions, but delete helper chains that hide those phases.
3. [x] Delete lower execution-boundary reauth states.
   - [x] Remove `reauth_required` and `post_reauth_admission` callback states.
   - [x] Split EVM/Tempo auth-plan input from the budget-admission boundary so
     confirmed auth cannot masquerade as admitted budget state.
   - [x] Remove remaining lower-flow pre-sign reauth/admission states such as
     EVM/Tempo `not_admitted` and NEAR `confirmed_auth_required`.
   - NEAR, EVM, and Tempo lower execution must receive admitted state or a
     no-budget-required state, never an admission callback.
   - Reauth completion must return to the transaction owner, which creates and
     admits the replacement operation before execution continues.
4. [x] Remove duplicated EVM/Tempo flow bodies.
   - [x] Extract the shared post-confirm threshold ECDSA admission/reconnect
     step for EVM and Tempo so OTP, passkey, and key-ref reconnect validation
     live in one EVM-family boundary.
   - [x] Collapse the duplicated EVM/Tempo transaction-executor shell into one
     configured EVM-family executor while keeping nonce reservation explicit per
     chain.
   - Keep Tempo as a separate chain family when behavior differs.
   - Share one EVM-family signing executor with explicit chain config for
     adapter, display model, WebAuthn support, nonce handling, and copy.
   - Chain config must be explicit; do not probe chains to see which one works.
5. [x] Delete generic prepared-signing wrappers from transaction paths.
   - Remove transaction use of `executePreparedThresholdSigning(...)`.
   - Remove transaction use of `finalizePreparedThresholdSigning(...)`.
   - Transaction paths should use `signPreparedTransactionOperation(...)` and
     `finalizeSignedTransactionOperation(...)` only.
6. [x] Remove duplicated budget fields from ECDSA prepared session state.
   - Delete `budgetIdentity?`, `budgetProjectionVersion?`, and
     `budgetIdentityThresholdSessionId?` from
     `PreparedEvmFamilyEcdsaSigningSession`.
   - Budget data must live only in the budget-admitted transaction operation.
   - Signing and finalization must not read derived budget fields from mutable
     ECDSA prepared-session objects.
7. [x] Prune account-keyed Ed25519 runtime state as selection authority.
   - Keep lane-keyed Ed25519 records as the authoritative runtime state.
   - Replace account-level reads with status-only scans or explicit maintenance
     APIs.
   - Transaction and export selection must not read account-keyed Ed25519
     runtime state before selecting a concrete lane.
   - `resolveEvmFamilyTransactionAccountAuth(...)` no longer falls back to the
     account-keyed Ed25519 runtime record when account metadata is missing.
     Remaining account-keyed reads are status/maintenance paths, not
     exact-purpose selection authority.
8. [x] Simplify brittle architecture guards.
   - [x] Remove guard requirements for transitional helper names such as exact
     export resolver wrappers and lower-flow admitted-operation getter names.
   - [x] Remove guard requirements for generic prepared-wrapper definitions and
     concrete lane-selector helper names; guards now focus on transaction paths
     not calling those wrappers or fallback selectors.
   - Guards should forbid old authority paths, not require specific wrapper
     names.
   - Keep guards for historical footguns that types cannot easily prevent:
     partial export auth selection, lower-flow reauth admission, transaction
     generic prepared wrappers, account-keyed runtime selection, and mutable
     budget fields.
   - Delete guards that preserve transitional helper names after the helper is
     removed.

Data structures and functions to edit:

1. `client/src/core/signingEngine/SigningEngine.ts`
   - `selectExactExportSnapshotLane(...)`
   - exact export lane resolvers
   - export restore/material/authorization helpers
   - `exportThresholdEcdsaKeyWithAuthorization(...)`
2. `client/src/core/signingEngine/session/signingSession/preparedOperation.ts`
   - generic prepared-signing wrappers
   - transaction operation type boundaries
3. `client/src/core/signingEngine/api/evmFamily/preparedSigning.ts`
   - `PreparedEvmFamilyEcdsaSigningSession`
   - duplicated budget fields
4. `client/src/core/signingEngine/api/evmSigning.ts`
   - lower ECDSA execution/admission boundary
5. `client/src/core/signingEngine/orchestration/evm/evmSigningFlow.ts`
   - EVM lower execution body
6. `client/src/core/signingEngine/orchestration/tempo/tempoSigningFlow.ts`
   - Tempo lower execution body
7. `client/src/core/signingEngine/orchestration/near/transactionsFlow.ts`
   - NEAR lower execution/admission boundary
8. `client/src/core/signingEngine/session/thresholdSessionStore.ts`
   - account-keyed Ed25519 runtime state
   - lane-keyed Ed25519 runtime state
9. `tests/unit/signingSessionCoordinator.architecture.guard.unit.test.ts`
   - convert helper-name guards into old-path prohibition guards

Acceptance:

1. No exact-purpose export path accepts partial auth identity.
2. No transaction path executes through generic prepared-signing wrappers.
3. No lower NEAR/EVM/Tempo signing flow can admit budget after signing starts.
4. EVM and Tempo do not have duplicated flow bodies for shared EVM-family logic.
5. ECDSA prepared-session state does not duplicate budget-admitted operation
   fields.
6. Ed25519 transaction/export selection does not use account-keyed runtime state
   as authority.
7. Static guards fail on old authority paths and do not require deleted wrapper
   names.

Phase 12 preconditions:

Precondition completion rule: a precondition is not considered closed only
because the code path appears fixed. It must have either compile-time/type
boundaries that make the old path impossible or an explicit architecture guard
that fails on the historical footgun, and the relevant guard/test command must
be recorded before Phase 12 is closed.

1. [x] Finish export exactness before concrete chain identity work starts.
   - `selectExactExportSnapshotLane(...)` must not rank/select from multiple
     candidates on its own.
   - Exact export must receive an explicit full lane selector, observe exactly
     one concrete lane, or fail with `ambiguous_candidates`.
   - Delete account-auth filtering and account-metadata tie-breakers from the
     exact export path.
   - Guard requirement: production exact export must not select by
     account-auth metadata, rank multiple lanes internally, or continue without
     a concrete lane.
   - Guard proof status: [x] covered by
     `signingSessionCoordinator.architecture.guard.unit.test.ts` asserting
     export entrypoints use exact lane boundaries and deleted auth-method
     resolver names.
2. [x] Finish ECDSA admission-mode cleanup before concrete chain identity work
   starts.
   - Lower EVM-family signing must receive a discriminated mode that is already
     known by the callsite.
   - Delete resolver/build helpers that reconstruct signing mode from optional
     hook clusters.
   - The callsite must explicitly know whether the operation is OTP, passkey
     reconnect, already admitted, or budget-not-required.
   - Guard requirement: lower EVM-family execution must not accept optional
     hook clusters that infer admission mode or admit budget after signing.
   - Guard proof status: [x] covered by
     `signingSessionCoordinator.architecture.guard.unit.test.ts` asserting
     EVM-family execution rejects optional admission hooks and post-sign budget
     admission.

### Phase 12: Make ECDSA Chain Identity Concrete

Current risk: ECDSA session identity still collapses all EVM networks under
`chain: 'evm'`, while Tempo is modeled as the only separate EVM-like chain. That
is not precise enough for Arc, Polygon, Ethereum, MegaETH, Base, or their
testnets. The exact-lane model only remains deterministic if both the protocol
subject and chain target are part of the lane identity.

Long-term target:

1. ECDSA transaction, export, snapshot, runtime store, durable store, server
   auth, and budget identity must carry a protocol-neutral wallet subject plus a
   concrete ECDSA chain target.
2. NEAR account ids must not be foundational ECDSA identity. Named or implicit
   NEAR account ids belong only in NEAR-specific Ed25519 paths.
3. EVM networks are identified by numeric EIP-155 `chainId`; Arc testnet
   (`5042002`) and Ethereum mainnet (`1`) are different lanes even though both
   use EVM signing logic.
4. Tempo remains a separate chain kind because it is EVM-like but has extended
   behavior.
5. Implementation paths may be shared by EVM-family chains, but lane identity
   must never collapse those chains into `evm`.

Core data structures:

```ts
export type WalletSubjectId = string & { readonly __brand: 'WalletSubjectId' };

export function toWalletSubjectId(value: unknown): WalletSubjectId {
  // Validate and brand only at trusted subject-resolution boundaries.
}

export function walletSubjectIdFromAccountContext(args: {
  subjectId?: unknown;
  walletId?: unknown;
  profileId?: unknown;
}): WalletSubjectId {
  // Must not silently treat NEAR account ids as global ECDSA subject ids.
}

export type NearAccountRef =
  | { kind: 'named'; accountId: string }
  | { kind: 'implicit'; accountId: string };

export type EvmEip155ChainTarget = {
  kind: 'evm';
  namespace: 'eip155';
  chainId: number;
  // Metadata only. Do not use this field in canonical equality.
  networkSlug: string;
};

export type TempoChainTarget = {
  kind: 'tempo';
  chainId: number;
  // Metadata only. Do not use this field in canonical equality.
  networkSlug: string;
};

export type ThresholdEcdsaChainTarget = EvmEip155ChainTarget | TempoChainTarget;

export type EcdsaLaneIdentity = {
  subjectId: WalletSubjectId;
  authMethod: 'email_otp' | 'passkey';
  curve: 'ecdsa';
  chainTarget: ThresholdEcdsaChainTarget;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  walletSigningSessionId: string;
  thresholdSessionId: string;
};

export type Ed25519NearLaneIdentity = {
  nearAccount: NearAccountRef;
  authMethod: 'email_otp' | 'passkey';
  curve: 'ed25519';
  chain: 'near';
  walletSigningSessionId: string;
  thresholdSessionId: string;
};

export type ThresholdEcdsaRuntimeLane = EcdsaLaneIdentity & {
  source: 'runtime_session_record';
  remainingUses?: number;
  expiresAtMs?: number;
  updatedAtMs?: number;
};
```

Canonical identity:

```ts
export function thresholdEcdsaChainTargetKey(
  target: ThresholdEcdsaChainTarget,
): string {
  if (target.kind === 'evm') return `evm:eip155:${target.chainId}`;
  return `tempo:${target.chainId}`;
}

export function thresholdEcdsaLaneKey(lane: EcdsaLaneIdentity): string {
  const laneKeyPart = (value: unknown): string => {
    // Encode separators so canonical keys cannot collide through raw ':' joins.
    return encodeURIComponent(requireNonEmptyString(value));
  };
  return [
    laneKeyPart(lane.subjectId),
    laneKeyPart(lane.ecdsaThresholdKeyId),
    laneKeyPart(lane.authMethod),
    laneKeyPart(lane.curve),
    laneKeyPart(thresholdEcdsaChainTargetKey(lane.chainTarget)),
    laneKeyPart(lane.signingRootId),
    laneKeyPart(lane.signingRootVersion),
    laneKeyPart(lane.walletSigningSessionId),
    laneKeyPart(lane.thresholdSessionId),
  ].join(':');
}
```

Rules:

1. Never dedupe ECDSA runtime or durable state by `thresholdSessionId` alone.
2. Never dedupe ECDSA runtime or durable state by collapsed `chain: 'evm'`.
3. Never use `NearAccountId` as the global ECDSA account identity. ECDSA lanes
   use `WalletSubjectId`; NEAR lanes use `NearAccountRef`.
4. `networkSlug` is display/config/diagnostic metadata only. Canonical equality
   uses `kind`, namespace when relevant, and numeric `chainId`.
5. Exact ECDSA lane comparison must include:
   - `subjectId`
   - `ecdsaThresholdKeyId`
   - `authMethod`
   - `curve`
   - `chainTarget.kind`
   - `chainTarget.chainId`
   - `signingRootId`
   - `signingRootVersion`
   - `walletSigningSessionId`
   - `thresholdSessionId`
   All exact ECDSA comparisons must use `thresholdEcdsaLaneKey(...)` or one
   equivalent canonical comparator. Do not scatter partial field comparisons
   across transaction, export, restore, store, budget, or server code.
6. Snapshot runtime candidates must come from material-backed runtime lanes, not
   sealed resolved identities.
7. Durable sealed ECDSA records must still carry `subjectId`, concrete
   `chainTarget`, and `ecdsaThresholdKeyId`. They may contain additional raw
   metadata, but transaction and export selection must resolve them into
   concrete chain-target lanes before restore/material lookup.
8. Do not support legacy collapsed ECDSA records. Any ECDSA record without
   `subjectId`, concrete `chainTarget`, and `ecdsaThresholdKeyId` is invalid
   on read and must be deleted or dropped. Do not migrate collapsed
   `chain: 'evm'` records. Do not quarantine them for later recovery. Do not
   parse them into compatibility lane objects or infer Arc/Base/Ethereum from
   config defaults.
9. Raw chain strings such as `chain: 'evm' | 'tempo'` are boundary input only.
   SDK, iframe, config, and demo code may accept transitional request shapes
   only if they immediately normalize to `ThresholdEcdsaChainTarget`. Internal
   transaction, export, restore, runtime store, durable store, budget, and
   server APIs must reject raw collapsed chain strings.
10. ECDSA persistence must be keyed by `subjectId`, not `nearAccountId`.
    `nearAccountId` may exist only as NEAR-specific data or diagnostic metadata
    after the boundary has resolved the protocol-neutral subject. This is a hard
    migration, not a naming cleanup.
11. Do not keep optional identity fields for legacy compatibility. Once a field
    is required for concrete ECDSA identity, make it required in the internal
    type and break callers/tests that still construct partial identity. Rewrite
    or delete incompatible legacy fixtures and guard expectations rather than
    widening production types.
12. Public ECDSA command inputs must stop using `nearAccountId` as the ECDSA
    principal. UI/session-boundary code may translate the active wallet/profile
    into a `WalletSubjectId`, but SDK/iframe/signing-engine ECDSA export and
    signing commands must receive `subjectId + chainTarget` explicitly. NEAR
    account refs remain valid only for `kind: 'near'` commands.

Signing targets and publication targets are different concepts:

```ts
export type EcdsaSessionPublicationTarget =
  | { kind: 'evm_family'; targets: EvmEip155ChainTarget[] }
  | { kind: 'tempo'; target: TempoChainTarget };

export type EcdsaSigningTarget = ThresholdEcdsaChainTarget;
```

Transaction and export commands require one `EcdsaSigningTarget`. Wallet
unlock/bootstrap may publish multiple explicit lanes through
`EcdsaSessionPublicationTarget`. Production code must not probe multiple chains
to discover which one works.

Public export API target shape:

```ts
export type ExportKeypairWithUIInput =
  | {
      kind: 'near';
      nearAccount: NearAccountRef;
      options: {
        chain: 'near';
        variant?: 'drawer' | 'modal';
        theme?: 'dark' | 'light';
        onEvent?: KeyExportEventCallback;
      };
    }
      | {
          kind: 'ecdsa';
          subjectId: WalletSubjectId;
          chainTarget: ThresholdEcdsaChainTarget;
          walletSessionUserId: string;
          options: {
            variant?: 'drawer' | 'modal';
            theme?: 'dark' | 'light';
            onEvent?: KeyExportEventCallback;
          };
    };
```

Do not keep an ECDSA overload like `exportKeypairWithUI(nearAccountId, {
chain: 'evm' })` internally. If HSS prepare or audit logs still need an
account/user reference, model that as an explicit session/audit context field
separate from lane identity, for example `auditUserId` or `walletSessionUserId`.
The selected ECDSA lane identity remains `subjectId + chainTarget +
ecdsaThresholdKeyId + signingRoot + session ids`.

Store APIs:

```ts
type ThresholdEcdsaRuntimeLaneIndex = {
  laneKeysBySubject: Map<string, Set<string>>;
  laneKeysBySubjectTarget: Map<string, Set<string>>;
  laneKeysBySubjectTargetSource: Map<string, Set<string>>;
  laneKeysByThresholdSessionId: Map<string, Set<string>>;
};

export function listThresholdEcdsaRuntimeLanesForSubject(args: {
  subjectId: WalletSubjectId;
}): ThresholdEcdsaRuntimeLane[];

export function listThresholdEcdsaRuntimeLanesForSnapshot(args: {
  subjectId: WalletSubjectId;
  chainTargets: readonly ThresholdEcdsaChainTarget[];
}): ThresholdEcdsaRuntimeLane[];

export function getThresholdEcdsaRuntimeLaneByIdentity(args: {
  identity: EcdsaLaneIdentity;
}): ThresholdEcdsaRuntimeLane | null;
```

Do not implement one broad API with optional identity filters. That recreates
the old "maybe exact, maybe broad" helper shape. Use separate functions for
broad subject snapshot enumeration and exact identity lookup. Auth-method
selection should be an explicit caller policy over concrete lanes, not a second
store authority.

These APIs must be index-backed, not implemented as broad map scans:

1. Exact identity lookup computes `thresholdEcdsaLaneKey(identity)` and reads the
   record by that key.
2. Snapshot inventory reads `laneKeysBySubjectTarget` for each required concrete
   target, then materializes only those lane keys.
3. Auth-method scoped reads use `laneKeysBySubjectAuthMethod`.
4. Source-scoped target maintenance, such as clearing one Email OTP or passkey
   runtime lane set, uses `laneKeysBySubjectTargetSource`.
5. Threshold-session-id reads use `laneKeysByThresholdSessionId`; because one
   threshold session can publish multiple concrete chain lanes, this index maps
   to a set of lane keys, not a single lane.
6. Full-map scans such as `for (const record of recordsByLane.values())` are not
   allowed in transaction, export, snapshot, restore, readiness, or budget
   paths. They are only acceptable in explicit store maintenance/migration code,
   and Phase 12 should remove those too as concrete subject/target indexes
   replace account-keyed cleanup.

This replaces account-wide callers that currently loop over `['tempo', 'evm']`
inside `SigningEngine.ts`. If a temporary per-target port is needed during
migration, make the target required:

```ts
listRuntimeEcdsaRecordsForChainTarget(args: {
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
}): Promise<SigningSessionSnapshotRuntimeEcdsaRecord[]>;
```

The enumeration belongs in `snapshotReader.ts` while it owns the snapshot shape.
The `SigningEngine.ts` adapter should only map material-backed runtime lanes to
snapshot records; it should not carry hidden chain lists or selection policy.

Snapshot shape:

```ts
export type SigningSessionSnapshot = {
  subjectId: WalletSubjectId;
  generation: number;
  ecdsa: {
    byChainTarget: Record<
      string,
      {
        target: ThresholdEcdsaChainTarget;
        candidates: SigningSessionSnapshotEcdsaLane[];
        selected?: SigningSessionSnapshotEcdsaLane;
      }
    >;
  };
  ed25519: {
    near: {
      nearAccount: NearAccountRef;
      candidates: SigningSessionSnapshotEd25519Lane[];
      selected?: SigningSessionSnapshotEd25519Lane;
    };
  };
};
```

No committed production state should keep compatibility accessors such as
`snapshot.lanes.ecdsa.evm`, `snapshot.lanes.ecdsa.tempo`,
`snapshot.candidates.ecdsa.evm`, or `snapshot.candidates.ecdsa.tempo` after
the snapshot refactor lands. The migration should update callers to
`byChainTarget` in the same slice rather than preserving collapsed EVM accessors
as a compatibility layer.

Implementation steps:

1. [x] Introduce subject/account reference and chain target types.
   - Add `WalletSubjectId`, `NearAccountRef`, `ThresholdEcdsaChainTarget`,
     `EcdsaLaneIdentity`, and `Ed25519NearLaneIdentity`.
   - Prefer a new `ecdsaChainTarget.ts` or `laneIdentity.ts` module rather than
     adding more identity rules to `SigningEngine.ts`.
   - Include normalization helpers:
     `walletSubjectIdFromAccountContext(...)`,
     `nearAccountRefFromAccountId(...)`,
     `thresholdEcdsaChainTargetFromConfig(...)`,
     `thresholdEcdsaChainTargetFromRequest(...)`,
     `thresholdEcdsaChainTargetKey(...)`, and
     `thresholdEcdsaLaneKey(...)`.
   - Validate numeric `chainId` at API/iframe boundaries.
   - Initial bridge: EVM and Tempo bootstrap entrypoints now normalize their
     request/config input through `ThresholdEcdsaChainTarget` and always pass a
     resolved numeric `chainId` into iframe/local bootstrap calls.
2. [x] Add concrete chain target and subject id to runtime ECDSA state.
   - [x] `ThresholdEcdsaSessionRecord`
   - [x] `ThresholdEcdsaSecp256k1KeyRef`
   - [x] warm-session persistence types
   - [x] worker bootstrap/request payloads for Email OTP ECDSA bootstrap and
     restore now construct key refs with concrete `subjectId` and
     `chainTarget`.
   - [x] threshold session activation result types now create ECDSA key refs
     with concrete `subjectId` and `chainTarget`.
   - [x] diagnostic logs
   - [x] budget identity/admission records
   - [x] Replace runtime store keys for concrete records that currently start
     with `nearAccountId` with `subjectId` plus canonical ECDSA lane identity.
   - [x] Runtime materialization rejects key refs created from non-concrete
     records so tests and production code cannot silently use missing lane
     identity.
3. [x] Add concrete chain target and subject id to durable ECDSA state.
   - [x] sealed ECDSA restore metadata now requires concrete `chainTarget`
     and durable store keys include `thresholdEcdsaChainTargetKey(...)`
     instead of only the collapsed `evm | tempo` label.
   - [x] resolved signing-session identities require concrete ECDSA
     `chainTarget`, key/list by canonical target key, and use index-backed
     account reads instead of scanning the whole resolved-identity map.
   - [x] exact sealed-session record filters require concrete `chainTarget`
     and compare through canonical chain-target equality.
   - [x] durable restore leases include concrete `chainTarget` in ECDSA
     purpose/cache keys, so leases cannot cross Arc/Tempo/EVM targets.
   - [x] exact restore input and restore-purpose types require concrete
     `chainTarget`; account-wide restore receives configured concrete ECDSA
     targets instead of guessing from collapsed chain labels.
   - [x] export lane metadata carries concrete `chainTarget` through exact
     sealed-record lookup and restore.
   - [x] exact sealed-store filters, restore coordinator ports, Email OTP
     restore adapters, and passkey restore adapters no longer carry a duplicate
     raw `chain`; they accept the concrete `chainTarget` and derive
     `chainTarget.kind` only when building worker/server payloads that still
     need the execution-family label.
   - [x] durable sealed ECDSA restore metadata stores only concrete
     `chainTarget`; raw `chain` is no longer part of the sealed restore schema.
4. [x] Add split material-backed ECDSA runtime lane store APIs.
   - [x] Return material-backed runtime lanes only.
   - [x] Split broad subject snapshot enumeration and exact identity lookup
     into separate functions. Do not use optional identity filters to make one
     helper serve all modes.
   - [x] Delete the auth-method-scoped runtime lane listing helper; auth-method
     selection now happens as explicit caller policy over concrete subject lanes
     instead of a second store authority.
   - [x] Dedupe by `thresholdEcdsaLaneKey(...)`.
   - [x] Make exact runtime-lane lookup direct by canonical lane key, not by
     scanning runtime lane inventory.
   - [x] Add runtime-lane secondary indexes for subject+target,
     subject+auth-method, subject-wide status/readiness reads, account cleanup,
     and threshold-session id so snapshot, status, and auth-method reads no
     longer scan `recordsByLane.values()`.
   - [x] Do not read sealed resolved identities for runtime-ready ECDSA
     snapshot candidates.
   - [x] Initial bridge: Email OTP snapshot runtime candidates now read
     material-backed ECDSA records by lane instead of deriving runtime
     candidates from sealed resolved identities plus threshold-session id
     reverse lookup.
   - [x] Initial store API: `thresholdSessionStore.ts` now exposes split
     runtime lane helpers for broad snapshot enumeration and exact identity
     lookup. These helpers only return records that already carry concrete
     `subjectId` and `chainTarget`; collapsed records are not inferred into
     concrete lanes.
   - [x] SDK deep-import entry preserves `thresholdSessionStore.ts` exports so
     lane-boundary tests and migration tools exercise the same generated module
     shape used by browser builds.
   - [x] Added `listConcreteThresholdEcdsaSessionRecordsForSubject(...)` for
     wallet-session status/readiness so higher layers do not enumerate
     `['evm', 'tempo']` to discover ECDSA lanes.
   - [x] Warm-session ECDSA status reads now use subject-wide concrete records
     for list/status inventory and direct threshold-session lookup for exact
     status reads instead of chain-scoped lookup probes.
   - [x] ECDSA runtime lane clearing now uses `subjectId + chainTarget` indexes,
     including source-scoped clears, instead of `nearAccountId + chain`.
5. [x] Refactor `readSigningSessionSnapshot(...)`.
   - [x] Make the snapshot reader own ECDSA chain-target enumeration.
   - [x] Require callers to pass a protocol-neutral `subjectId` into
     `readSigningSessionSnapshot(...)`; the snapshot reader no longer derives
     ECDSA subject identity from `walletId`.
   - [x] Require the SigningEngine snapshot wrapper to receive `subjectId`
     explicitly; it no longer falls back to `toWalletSubjectId(walletId)`.
   - [x] Replace `listRuntimeEcdsaRecordsForAccount(...)` with
     `listRuntimeEcdsaLanesForSubject(...)`; snapshot adapters now receive a
     protocol-neutral `WalletSubjectId` and map material-backed runtime lanes
     without account-shaped runtime authority.
   - [x] Remove inline `['tempo', 'evm']` loops from `SigningEngine.ts` snapshot
     adapters.
   - [x] Remove inline `['tempo', 'evm']` loops from Email OTP snapshot/restore
     adapters; those helpers should receive a concrete target or a concrete
     target list from snapshotReader.
   - [x] Remove inline `['tempo', 'evm']` / `['evm', 'tempo']` loops from
     signing-session readiness lane discovery.
   - [x] Remove Email OTP Ed25519 reauth probing over ECDSA chains; the
     companion ECDSA key context now comes from material-backed concrete
     subject records only.
   - [x] Replace passkey registration/login ECDSA warm-up loops over raw
     `tempo | evm` strings with configured concrete publication targets.
   - [x] Replace login metadata warm-session reads over raw `tempo | evm`
     strings with subject-wide concrete ECDSA record reads.
   - [x] Replace warm-session status reader ECDSA inventory reads with concrete
     subject records and direct session-id lookup for exact status checks.
   - [x] ECDSA snapshot input now receives configured concrete chain targets,
     and snapshot ECDSA runtime candidates/lanes carry `chainTarget` instead
     of representing identity with only collapsed `evm | tempo`.
   - [x] Add required target-keyed ECDSA snapshot fields:
     `snapshot.ecdsa.targets`, `snapshot.ecdsa.lanesByTarget`, and
     `snapshot.ecdsa.candidatesByTarget`.
   - [x] Move production transaction, export, and wallet-session status callers
     to target-keyed snapshot helpers instead of reading the collapsed
     `snapshot.lanes.ecdsa.*` / `snapshot.candidates.ecdsa.*` compatibility
     buckets.
   - [x] Delete optional/fallback test fixture compatibility for missing
     `snapshot.ecdsa`; fixtures now construct the concrete target-keyed shape
     or fail type-check.
   - [x] Update legacy test fixtures that constructed ECDSA key refs or exact
     restore inputs without required `subjectId` and `chainTarget`; incompatible
     fixtures are rewritten to the concrete identity model instead of relaxing
     production types.
   - [x] Keep NEAR Ed25519 snapshots keyed by `NearAccountRef`, not
     `WalletSubjectId`.
6. [x] Refactor transaction and export intents.
   - EVM transaction signing input must include a concrete target such as
     `{ kind: 'evm', namespace: 'eip155', chainId: 5042002, networkSlug:
     'arc-testnet' }`.
   - Tempo signing input must include `{ kind: 'tempo', chainId: 42431,
     networkSlug: 'tempo-moderato' }`.
   - No transaction/export path may infer a chain target from `chain || 'tempo'`
     or probe multiple chains.
   - [x] Initial transaction boundary: EVM-family signing now normalizes
     `request.chain` plus `request.tx.chainId` into a concrete
     `EvmFamilySigningTarget` at entry, and ECDSA transaction intents/lanes
     require `chainTarget` instead of carrying only collapsed `evm | tempo`.
   - [x] EVM-family commit-queue readiness checks now derive a concrete
     `ThresholdEcdsaChainTarget` from the signing request and pass that target
     through warm-session budget/readiness checks instead of passing a raw
     `evm | tempo` chain label.
   - [x] Removed the ECDSA transaction selector fallback that treated
     non-EVM-family intents as `evm`; selector inputs must now already be an
     ECDSA EVM-family intent with a concrete target.
   - [x] Initial export boundary: ECDSA export now resolves `evm | tempo`
     requests through configured concrete `EvmFamilySigningTarget`, and exact
     export lanes carry `chainTarget` instead of any collapsed chain identity
     field.
7. [x] Split publication targets from signing targets.
   - Wallet unlock/bootstrap accepts `EcdsaSessionPublicationTarget`.
   - Transaction/export accepts exactly one `EcdsaSigningTarget`.
   - Publishing multiple lanes must be an explicit bootstrap action, not hidden
     fallback logic in transaction signing.
   - [x] Configured publication targets now use
     `EcdsaSessionPublicationTarget` with only a concrete `chainTarget`;
     registration/login bootstrap loops derive the execution adapter label from
     `chainTarget.kind` at the bootstrap boundary.
   - [x] Threshold session activation now accepts a concrete
     `ThresholdEcdsaChainTarget` internally; the old `activateEvm...` /
     `activateTempo...` wrapper split was removed and remaining execution
     labels are derived from `chainTarget.kind` at the activation boundary.
   - [x] `bootstrapEcdsaSessionValue(...)` now requires a concrete
     `chainTarget`; public registration/login/EVM/Tempo callers normalize
     boundary input before invoking the activation lifecycle.
8. [x] Refactor exact lane selection and restore.
   - `TransactionLane`
   - `ExactEcdsaExportLane`
   - `SigningSessionSnapshotEcdsaLane`
   - restore coordinator inputs
   - ECDSA material lookup
   - budget identity and finalization
   must compare concrete `EcdsaLaneIdentity`.
   - Route every exact ECDSA identity comparison through
     `thresholdEcdsaLaneKey(...)` or a single equivalent comparator.
   - [x] Initial export lane/material lookup: `ExactEcdsaExportLane` carries
     concrete `chainTarget` only, and ECDSA export record/keyRef matching
     rejects material whose chain target differs from the selected lane.
   - [x] Exact export selection no longer ranks or chooses among multiple
     concrete lanes internally. The helper now accepts exactly one selectable
     lane or fails with `no_candidate` / `ambiguous_candidates`.
   - [x] `ExactEcdsaExportLane` carries the full ECDSA lane identity:
     `subjectId`, `chainTarget`, `ecdsaThresholdKeyId`, `signingRootId`,
     `signingRootVersion`, `walletSigningSessionId`, and
     `thresholdSessionId`.
   - [x] Initial snapshot lane identity keying includes concrete
     `thresholdEcdsaChainTargetKey(...)`, so runtime/durable overlays no
     longer match only by collapsed chain plus session ids.
   - [x] Snapshot ECDSA identity keying includes `subjectId`,
     `ecdsaThresholdKeyId`, `signingRootId`, `signingRootVersion`,
     `walletSigningSessionId`, and `thresholdSessionId`; runtime/durable
     overlays cannot collapse distinct lanes that share a session id or chain
     target.
   - [x] Snapshot ECDSA identity keying now constructs `EcdsaLaneIdentity` and
     routes through `thresholdEcdsaLaneKey(...)`; it no longer locally joins raw
     identity fields.
   - [x] Exact export material lookup uses full `EcdsaLaneIdentity` direct
     record/keyRef lookup instead of broad target lookup plus filtering.
   - [x] Subject/target store lookup no longer picks a preferred record when
     multiple concrete lanes match. It returns exactly one record or fails
     ambiguous, keeping exact signing/export on full lane identity lookup.
   - [x] ECDSA signing helper APIs receive `WalletSubjectId` explicitly instead
     of deriving subject identity from `nearAccountId`.
   - [x] ECDSA `SigningLaneContext` adapters carry full transaction identity:
     `subjectId`, `chainTarget`, `ecdsaThresholdKeyId`, signing root, wallet
     signing session id, and threshold session id.
   - [x] Durable sealed ECDSA snapshot lanes require `subjectId` on the sealed
     record. Records missing `subjectId` are invalid on read instead of being
     inferred from wallet/user ids.
   - [x] Generic signing-lane types are discriminated by curve, so ECDSA lanes
     require `subjectId`, concrete `chainTarget`, `ecdsaThresholdKeyId`,
     signing root, wallet signing session id, and threshold session id by type.
   - [x] Signing keyRef helpers no longer select `list(...)[0]` from broad
     subject+target matches; they resolve through the same single-record or
     exact-identity path as session records.
   - [x] `SigningSessionSnapshotEcdsaLane` and
     `SigningSessionSnapshotRuntimeEcdsaRecord` no longer carry duplicate raw
     `chain`; ECDSA snapshot lanes use `chainTarget`, while the snapshot bucket
     or `chainTarget.kind` supplies any execution-family label.
   - [x] Committed production snapshot state no longer exposes collapsed ECDSA
     compatibility buckets (`snapshot.lanes.ecdsa.*` or
     `snapshot.candidates.ecdsa.*`); production callers use target-keyed
     snapshot helpers.
   - [x] Exact sealed-store lookup/list/update/delete/lease paths compare
     ECDSA `chainTarget`, not collapsed chain labels.
   - [x] ECDSA transaction lanes carry full concrete identity fields so
     downstream restore, material matching, budget, signing, and finalization
     can assert the selected identity by type.
   - [x] ECDSA transaction material matching checks full selected identity:
     `subjectId`, `chainTarget`, `ecdsaThresholdKeyId`, `signingRootId`,
     `signingRootVersion`, `walletSigningSessionId`, and
     `thresholdSessionId`.
   - [x] Passkey sealed-session restore updates and deletes durable policy by
     the exact restore purpose, not by rediscovering a current runtime record.
   - [x] ECDSA wallet-budget reserve/success/failure helpers receive the exact
     `EvmFamilyEcdsaTransactionLane`; budget finalization no longer accepts a
     separate raw chain plus mutable signing-lane pair.
9. [x] Extend concrete identity through server/auth boundaries.
   - [x] threshold ECDSA bootstrap payloads split registration/bootstrap from
     exact session bootstrap at the client worker boundary; session bootstrap
     now requires `ecdsaThresholdKeyId`, `sessionId`, and
     `walletSigningSessionId`.
   - [x] `/threshold-ecdsa/hss/prepare`
   - [x] HSS prepare request typing is discriminated by operation:
     registration and Email OTP bootstrap may create fresh material, while
     `session_bootstrap` and `explicit_key_export` require exact existing
     threshold key/auth inputs.
   - [x] HSS respond/finalize ceremony records and responses carry the exact
     `subjectId`, concrete `chainTarget`, and `ecdsaThresholdKeyId` selected
     during prepare.
   - [x] threshold-session JWT/session claims require `subjectId`, concrete
     `chainTarget`, and `ecdsaThresholdKeyId` for ECDSA session tokens.
   - [x] session policy creation and server-side mismatch checks reject
     mismatched `subjectId`, `chainTarget`, and `ecdsaThresholdKeyId` before
     HSS prepare can mint or reuse ECDSA session material.
   - [x] Email OTP worker local bootstrap handoff is mode-specific instead of
     one optional identity bag.
   - [x] passkey/WebAuthn reconnect payloads require planned
     `sessionId + walletSigningSessionId` by type before lower EVM-family
     admission runs.
   - [x] Smart-account registration, deployment manifest, deployment
     observation, link-device, and relay deploy boundaries now normalize
     boundary `chain/chain_id` inputs to concrete `chainTarget` once, then
     persist/pass `chainTarget` plus canonical `smartAccountChainTargetKey(...)`
     internally.
   - [x] Server smart-account deployment manifests and EVM deploy adapters now
     use concrete `chainTarget`; canonical deployment plans only run for
     `chainTarget.kind === 'evm'`.
   Server authorization must reject mismatched `subjectId`, `chainTarget`, and
   `ecdsaThresholdKeyId`, not only mismatched session ids.
10. [x] Remove collapsed EVM identity from production paths.
    - Delete production use of `chain: 'evm'` as a lane identity.
    - Keep EVM-family shared implementation naming only for execution adapters,
      not identity.
    - Compatibility helpers may exist only at SDK/iframe input boundaries and
      must return a validated `ThresholdEcdsaChainTarget`.
    - Delete raw `chain: 'evm' | 'tempo'` from internal transaction, export,
      restore, runtime store, durable store, budget, and server APIs.
    - [x] Exact sealed-session store/restore boundaries now use `chainTarget`
      only; raw chain labels are no longer accepted by exact sealed filters,
      restore purposes, restore leases, or restore adapter ports.
    - [x] Sealed durable ECDSA restore metadata no longer stores raw collapsed
      chain labels; internal callers derive any remaining execution adapter
      label from `chainTarget.kind`.
    - [x] Snapshot ECDSA lanes and runtime snapshot records no longer expose raw
      collapsed chain labels as lane identity.
    - [x] Wallet-session readiness discovery, local consume, clear grouping, and
      sealed-policy sync now carry ECDSA `chainTarget` on discovered lanes and
      dedupe/sync by `thresholdEcdsaChainTargetKey(...)` instead of raw chain
      labels.
    - [x] `clearThresholdEcdsaSessionRecordForLane(...)` accepts concrete
      `subjectId + chainTarget`; the old Email OTP-specific clear wrapper was
      deleted instead of preserving a raw-chain compatibility path.
    - [x] ECDSA post-sign signing-artifact cleanup now receives the concrete
      `ThresholdEcdsaSessionRecord` selected by policy instead of re-resolving
      material from `nearAccountId + chain + source`; the unused raw-chain
      `SigningEngine.clearThresholdEcdsaSigningArtifactsForLane(...)` wrapper was
      removed.
    - [x] TouchConfirm warm-session material claim/consume boundaries now carry
      ECDSA `chainTarget` instead of accepting raw `evm | tempo` chain labels.
    - [x] Warm-session ECDSA provision/reconnect helper boundaries now require
      `chainTarget`; reconnect in-flight keys use
      `thresholdEcdsaChainTargetKey(...)` instead of `chain + chainId`.
    - [x] Warm-session ECDSA status, readiness, post-sign policy, and login
      prefill boundaries now accept concrete `chainTarget` and derive
      `chainTarget.kind` only when bridging to remaining legacy envelope/store
      buckets.
    - [x] Warm-session transition events for ECDSA provision/reconnect carry
      `chainTarget` instead of raw `evm | tempo`.
   - [x] Exact ECDSA transaction and export lane types no longer carry a raw
     `chain: 'evm' | 'tempo'` identity field; any remaining boundary chain
     label is derived from `chainTarget.kind` at adapter calls.
   - [x] Signing-session lane construction no longer accepts an independently
     supplied ECDSA `chainFamily`; ECDSA lanes require `chainTarget` and derive
     the execution family from that target.
    - [x] `ThresholdEcdsaCanonicalExportArtifact` now persists `chainTarget`
      instead of a raw collapsed chain label; legacy chain-only cached export
      artifacts are dropped by normalization instead of being migrated.
   - [x] ECDSA transaction post-sign cleanup uses the selected ECDSA session
     record when one exists, and otherwise skips local cleanup for exact
     keyRef-only reauth material. The adapter no longer falls back to
     rediscovering the current ECDSA record after signing.
   - [x] Warm-session ECDSA capability/auth state no longer carries a duplicate
     raw `chain`; the concrete session record is the identity source and carries
     `chainTarget`.
   - [x] Warm-session ECDSA provisioning no longer accepts the legacy
     `bootstrapThresholdEcdsaSession({ chain, chainId })` fallback. Provisioning
     must go through the concrete `ProvisionWarmEcdsaCapabilityArgs.chainTarget`
     path.
   - [x] Warm-session ECDSA key-ref lookup dependencies accept
     `chainTarget`; remaining raw execution-family labels are derived only at
     the old store adapter edge.
   - [x] Wallet-session readiness no longer accepts
     `listThresholdEcdsaSessionRecordsForLookup({ chain })` as a fallback
     authority; ECDSA lane discovery uses concrete subject-wide runtime records
     or the existing exact warm-session record buckets.
   - [x] ECDSA post-sign Email OTP consumption now receives `chainTarget`; the
     raw execution-family label is derived only at the final legacy consumed
     marker bridge.
   - [x] EVM-family transaction material readers now accept concrete
     `chainTarget` for Email OTP/passkey record and keyRef lookup. The
     orchestration dependency bundle no longer exposes raw
     `listThresholdEcdsa*ForLookup({ chain })` authority to transaction signing.
   - [x] Selected ECDSA signing lanes carry the concrete `chainTarget` through
     capability record/keyRef reads; selected-lane material readers now fail
     when a lane has only the collapsed execution-family label.
   - [x] Warm-session account inventory no longer performs separate raw
     `evm`/`tempo` store lookups. It reads the account's concrete ECDSA records
     once and fills the remaining legacy buckets from each record's
     `chainTarget.kind`.
   - [x] ECDSA bootstrap persistence now accepts `chainTarget` and no longer
     writes mirror/unknown chain rows for the sibling EVM-family target.
   - [x] Email OTP worker bootstrap, enrollment, rehydrate, and ECDSA export
     messages now carry `chainTarget`; the worker no longer accepts raw
     `chain + chainId` pairs for those ECDSA bootstrap boundaries.
   - [x] Runtime ECDSA session records no longer carry a duplicate raw
     `chain`; `chainTarget` is the only persisted runtime chain identity.
   - [x] Warm-session, transaction material, and bootstrap dependency names now
     use target-based helpers instead of the legacy `*ForLookup({ chain })`
     shape.
   - [x] Email OTP signing-session auth lanes for ECDSA now carry concrete
     `chainTarget`; raw `evm | tempo` labels are derived only at the route or
     worker/server boundary that still needs an execution-family label.
   - [x] Worker-provisioned ECDSA session commits now carry
     `ThresholdEcdsaChainTarget` through persistence/upsert and derive
     `chainTarget.kind + chainTarget.chainId` only when bridging to sealed
     refresh parity and activation payloads.
   - [x] ECDSA threshold-session activation arguments no longer accept raw
     `chain + chainId`; activation receives the already-normalized concrete
     `ThresholdEcdsaChainTarget`.
   - [x] ECDSA commit queue keys now use
     `thresholdEcdsaChainTargetKey(chainTarget)` instead of raw `evm | tempo`
     labels, so Arc/Base/Ethereum/Tempo cannot collide on a shared
     threshold-session id.
   - [x] EVM-family nonce lifecycle metrics now receive a concrete
     `ThresholdEcdsaChainTarget`; display/debug chain labels are derived from
     the canonical target key rather than stored as a separate identity field.
   - [x] EVM-family touch-confirm signing config now uses
     `ThresholdEcdsaChainTarget['kind']` as a derived UI/adapter label instead
     of defining its own raw `chain: 'evm' | 'tempo'` execution identity.
   - [x] Public SDK/iframe ECDSA session bootstrap, Email OTP challenge,
     refresh, capability, and prefill inputs now require concrete
     `ThresholdEcdsaChainTarget`; they no longer accept raw
     `chain + chainId` option bags.
   - [x] Link-device ECDSA bootstrap and prepared-signer paths normalize raw
     relayer payloads at the boundary, then carry `chainTarget` through the
     internal linked-account structs, bootstrap persistence, and staged signer
     metadata.
   - [x] `thresholdEcdsaProvisioning.ts` no longer exports raw-chain provision
     helpers; provision/publication targets are derived from configured
     concrete chain targets.
   - [x] `orchestration/thresholdActivation.ts` no longer defines
     `ThresholdEcdsaActivationChain` or raw-chain activation adapters. ECDSA
     activation receives concrete `ThresholdEcdsaChainTarget` only.
   - [x] Export-confirm worker payloads no longer accept raw
     `chain: 'evm' | 'tempo'`; ECDSA export confirmation receives concrete
     `chainTarget` and derives display labels from that target inside the
     worker.
   - [x] IndexedDB account-chain key helpers now derive account chain keys from
     concrete `ThresholdEcdsaChainTarget` via `toIndexedDbChainTargetKey(...)`;
     bootstrap persistence and smart-account deployment lookup no longer pass
     raw `evm | tempo` labels into the IndexedDB normalization helper.
   - [x] Nonce lease persistence now stores concrete `chainTarget`; legacy
     raw-chain nonce rows are dropped on read, and adapter-local
     `evm | tempo` labels are derived only when reconstructing the runtime nonce
     adapter lane.
   - [x] Shared Email OTP ECDSA restore HKDF tuple inputs now require concrete
     `chainTarget` and no longer default a missing chain to Tempo.
   - [x] Client smart-account deployment and deployment-observation flows now
     send concrete `chainTarget` through the manifest/observe/deploy lifecycle
     and no longer pass `chain + chainIdCandidates` internally.
   - [x] Smart-account deployment no longer mirrors missing rows from a
     counterpart chain or creates `evm:unknown` rows; missing concrete target
     state is an explicit missing-account/deployment failure.
   - [x] Managed nonce sender resolution no longer searches counterpart chain
     accounts after exact target lookup fails.
11. [x] Delete/drop invalid legacy collapsed ECDSA records.
    - [x] Durable sealed ECDSA restore records without concrete `chainTarget`
      are rejected on write/read; no chain-only seal is inferred into a fresh
      concrete target.
    - [x] Treat any ECDSA record without `subjectId`, concrete `chainTarget`, and
      `ecdsaThresholdKeyId` as invalid on read.
    - [x] Remove optional compatibility identity fields from ECDSA runtime
      records. `ThresholdEcdsaSessionRecord` now requires `subjectId`,
      concrete `chainTarget`, and `walletSigningSessionId`, and runtime lane
      keys no longer fall back to `nearAccountId + chain`.
    - [x] Remove optional compatibility identity fields from durable record write
      helpers and ECDSA key refs. `writeExactSealedSession(...)` now requires
      `walletSigningSessionId`, sealed-store key helpers are discriminated by
      curve, and `ThresholdEcdsaSecp256k1KeyRef` requires both
      `thresholdSessionId` and `walletSigningSessionId`.
    - [x] Remove optional compatibility identity fields from ECDSA snapshot lanes.
      Snapshot ECDSA lanes are now split into missing lanes and concrete lanes;
      concrete ECDSA candidates require `authMethod`, `thresholdSessionId`, and
      `walletSigningSessionId` by type.
    - [x] Remove optional compatibility identity fields from transaction lanes,
      export lanes, budget state, and remaining server request types. Required
      lifecycle identity must be required by type.
    - [x] Do not migrate collapsed `chain: 'evm'` records.
    - [x] Do not quarantine them for later recovery.
    - [x] Do not parse them into compatibility lane objects.
    - [x] Exact-purpose signing/export may fail when no fresh concrete lane exists;
      the recovery path is explicit fresh bootstrap, not compatibility restore.
12. [x] Add tests.
    - [x] Arc testnet (`chainId: 5042002`) and Ethereum mainnet (`chainId: 1`) can
      coexist for the same subject without candidate collision.
    - [x] Two EVM testnets can coexist for the same subject, signing root, and
      `ecdsaThresholdKeyId` without candidate collision.
    - [x] Arc testnet and MegaETH testnet can share signing root and threshold key
      metadata but remain separate lanes by `chainId`.
    - [x] Tempo and an EVM network with the same numeric `chainId` remain separate
      lanes because their `chainTarget.kind` differs.
    - [x] Tempo Moderato (`chainId: 42431`) remains separate from EVM chain targets.
    - [x] Snapshot exposes separate candidates per target.
    - [x] Exact restore and export fail when chain target differs even if
      `walletSigningSessionId` and `thresholdSessionId` match.
    - [x] Exact restore and export fail when `ecdsaThresholdKeyId` differs even
      if session ids match. Concrete snapshot/export lanes now carry
      `ecdsaThresholdKeyId`; exact export keyRef/session/sealed material lookup
      rejects mismatched threshold keys, and canonical lane-key tests cover the
      same-session/different-key collision case.
    - [x] Budget reservation/finalization uses the same concrete chain target and
      subject id carried by the admitted operation.
    - [x] Legacy collapsed EVM records are deleted/dropped as invalid and never
      guessed into Arc/Base/Ethereum.
    - [x] Server HSS prepare rejects mismatched `subjectId`, `chainTarget`,
      `ecdsaThresholdKeyId`, or session policy claims; ECDSA JWT claims now
      require numeric concrete chain targets and the architecture guard covers
      the exact HSS identity checks.
    - [x] Delete or rewrite legacy test fixtures that manufacture partial ECDSA
      identity. No fixture may omit `subjectId`, concrete `chainTarget`, or
      `ecdsaThresholdKeyId` unless it is explicitly testing boundary rejection
      or invalid-record deletion.
13. [x] Add static guards.
    - [x] No production `SigningEngine.ts` snapshot adapter loops over
      `['tempo', 'evm']`.
    - [x] No ECDSA lane key omits `subjectId`, `ecdsaThresholdKeyId`, or `chainId`.
    - [x] No transaction/export restore input accepts collapsed `chain: 'evm'` as
      identity.
    - [x] No transaction/export path defaults chain input.
    - [x] No runtime ECDSA list API dedupes by `thresholdSessionId` only.
    - [x] No ECDSA runtime/session store type uses `nearAccountId` as its primary
      identity field.
    - [x] No internal ECDSA transaction/export/restore/store/budget/server API
      accepts raw `chain: 'evm' | 'tempo'`.
    - [x] No exact ECDSA comparison reimplements partial lane equality outside the
      canonical comparator.
    - [x] No production ECDSA runtime session record type marks required lane
      identity fields optional for compatibility.
    - [x] No production ECDSA key-ref type marks required lane identity fields
      optional for compatibility.
    - [x] No production ECDSA snapshot lane type marks required lane identity
      fields optional for compatibility.
    - [x] No production ECDSA transaction/export/budget/server type marks
      required lane identity fields optional for compatibility.
    - [x] Internal exact ECDSA transaction/export lane types must carry
      `chainTarget`, not raw `chain: 'evm' | 'tempo'`.
    - [x] No architecture guard requires legacy helper names, sentinel key refs,
      optional identity fields, collapsed snapshot fields, or deprecated fixture
      shapes. Guards should forbid old paths, not preserve transitional symbols.
    - [x] Smart-account registration/deployment/link-device/relay-deploy
      boundaries are guarded to carry `chainTarget` past parsing and to reject
      raw `chain_id`, `chainIdCandidates`, `evm:unknown`, and counterpart-row
      fallback patterns in production code.
    - Guard proof status: [x]
      `pnpm -C tests exec playwright test ./unit/signingSessionCoordinator.architecture.guard.unit.test.ts --reporter=line`
      passed on 2026-05-05.
14. [x] Delete obsolete signing abstraction bloat while touching these paths.
    - [x] Remove the unused `local-secp256k1` `KeyRef` arm.
    - [x] Remove `NearEd25519KeyRef`, `NEAR_ED25519_KEY_REF`, and the fake NEAR
      Ed25519 signer key-ref parameter. NEAR Ed25519 signing should call the
      exact engine/handlers directly instead of manufacturing a sentinel
      key-ref value.
    - [x] Delete the unused broad `listResolvedIdentitiesForAccount(...)` and
      `readResolvedIdentity(...)` sealed-store exports. The resolved identity map
      remains an internal exact-purpose replacement index behind
      `publishResolvedIdentity(...)`, not a partial-identity listing API.
    - [x] Delete unused generic prepared-signing execution wrappers:
      `executePreparedThresholdSigning(...)` and
      `finalizePreparedThresholdSigning(...)`. Transaction signing should use
      `signPreparedTransactionOperation(...)` and
      `finalizeSignedTransactionOperation(...)`; non-transaction paths should
      have explicit flow-specific functions.
    - [x] Remove or EVM-specialize `executeSigningIntent(...)` once it has only one
      production caller. Do not keep a generic sign-runner solely to preserve
      `SignerMap` / `resolveSignInput` / broad `keyRef` plumbing.
    - [x] Delete `keyRefsByAlgorithm`, `asThresholdEcdsaKeyRef(...)`, and
      `resolveKeyRefForSignRequest(...)` from EVM-family transaction signing.
      EVM-family signing should receive an explicit discriminated mode for:
      no threshold signer required, admitted ECDSA key ref, Email OTP reauth,
      passkey reconnect, and Tempo WebAuthn P256.
    - Keep the short variable name `keyRef` only after exact lane selection:
      `sessionLane -> sessionRecord -> keyRef`. A key ref must be signer-facing
      material/capability derived from the selected record; it must never be
      used to select a lane.
    - Update architecture guards so they forbid the old abstraction paths
      instead of requiring old helper names such as `executeSigningIntent(...)`
      in production flow files.
15. [ ] Replace public ECDSA export/signing inputs with explicit subject-based
    discriminated arguments.
    - [x] Add `ExportKeypairWithUIInput` with `kind: 'near'` and `kind: 'ecdsa'`
      variants.
    - [x] `kind: 'near'` requires `NearAccountRef` and `options.chain: 'near'`.
    - [x] `kind: 'ecdsa'` requires `WalletSubjectId` and
      `ThresholdEcdsaChainTarget`; it must not accept `nearAccountId` as a
      substitute for subject identity.
    - [x] Update SDK, iframe router, wallet host messages, demo app, and
      `SigningEngine.exportKeypairWithUI(...)` to use the discriminated input.
    - [x] Update public EVM-family signing inputs and iframe messages so
      `signTempo(...)` / `executeEvmFamilyTransaction(...)` carry explicit
      `subjectId` through SDK, iframe, orchestration, and signing-engine
      boundaries.
    - [x] Move public-command `nearAccountId -> WalletSubjectId` derivation into app/session
      boundary code that knows the active wallet subject. Do not perform that
      conversion inside exact ECDSA export/signing paths.
    - [x] Rename any HSS prepare `userId`/account field that is not lane identity to
      an audit/session context name, and ensure HSS identity validation uses
      `exportLane.subjectId`.
    - [x] Add/extend static guards forbidding ECDSA export/signing public or internal
      callsites from passing `nearAccountId` as the ECDSA principal.


Acceptance:

1. ECDSA exact lane identity includes subject id, ECDSA threshold key id, and
   concrete chain target everywhere after API boundary validation.
2. NEAR account ids are not the global ECDSA subject. NEAR account refs exist
   only in NEAR Ed25519-specific paths.
3. Arc, Polygon, Ethereum, MegaETH, Base, and their testnets cannot collide in
   runtime stores, snapshots, restore, export, server authorization, or budget
   finalization.
4. Tempo remains a separate chain kind, not an EVM `chainId` alias.
5. Snapshot reader, not `SigningEngine.ts`, owns any temporary fixed chain-target
   enumeration.
6. `SigningEngine.ts` snapshot adapters are dumb material-to-snapshot mappers.
7. No production exact-purpose ECDSA flow accepts optional or collapsed chain
   identity.
8. No production ECDSA flow probes multiple chains to find one that works.
9. Legacy collapsed EVM records are not supported: they are deleted/dropped as
   invalid on read and never guessed into concrete networks.
10. Server HSS/session authorization validates the same concrete lane identity
    that the client selected.
11. All tests and static guards pass with Arc testnet and Tempo Moderato
    configured by numeric chain id.
12. Legacy fixtures and guardrails are deleted or rewritten when they conflict
    with concrete identity. A failing legacy test must not be fixed by restoring
    optional identity fields or compatibility symbols.
13. Public ECDSA export/signing APIs use discriminated subject-based inputs.
    `nearAccountId` is not accepted as the ECDSA principal, and HSS
    user/account context is named separately from lane identity.

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

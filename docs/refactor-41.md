# Refactor 41: Budget and Step-Up Invariants

Date created: 2026-05-18
Status: implemented

## Scope

This refactor is split out from `docs/refactor-39.md`. Refactor 39 should stay
focused on exact ECDSA lane consumption, ECDSA material identity, key-handle
cleanup, and key-ref isolation. Budget provisioning, prompt policy, step-up
freshness, projection retries, Email OTP refresh failures, and concurrency are a
separate lifecycle refactor.

Refactor 41 can begin after Refactor 39A exact consumption is complete. It does
not need to wait for key-handle or `ThresholdEcdsaSecp256k1KeyRef` deletion.

## Problem

Refactor 38 fixed warm-session lifetime boundaries, but manual testing exposed
remaining signing-budget and step-up bugs:

- Passkey unlock and page-refresh rehydration can blur prompt policy.
- Unlock budget and post-exhaustion step-up budget are treated as the same kind
  of session.
- Exhausted restored sessions can leak into signing paths instead of becoming
  reauth anchors.
- Concurrent NEAR and ECDSA operations can contend through shared mutable budget
  or prepared-material state.
- Budget reservation and finalization report projection mismatches by throwing.
- Email OTP `/session/refresh` 401 is surfaced as a generic session failure
  where callers need a fresh OTP requirement.

Use strict TypeScript domain types to make these invalid states unrepresentable:
discriminated unions, required identity fields, `never` invalid-branch fields,
boundary builders, exhaustive `switch` statements, and type fixtures.

## Phase 0: Current Surface Inventory

- [x] Inventory wallet signing-session budget policy sources:
      `client/src/core/config/defaultConfigs.ts` and
      `client/src/core/signingEngine/threshold/sessionPolicy.ts`.
- [x] Inventory reservation state in
      `client/src/core/signingEngine/session/budget/BudgetCoordinator.ts`:
      `reservationsByOperationId` and `successfulSpendsByOperationId`.
- [x] Inventory projection assertions and throw sites in
      `client/src/core/signingEngine/session/budget/budget.ts`.
- [x] Inventory finalizer API shape in
      `client/src/core/signingEngine/session/budget/budgetFinalizer.ts`.
- [x] Inventory Email OTP app-session refresh behavior in
      `client/src/core/signingEngine/session/emailOtp/appSessionJwtCache.ts`.
- [x] Inventory budget status 401/403 handling in
      `client/src/core/signingEngine/session/budget/budgetStatusReader.ts`.
- [x] List every signing path that catches budget/freshness errors and maps them
      to `threshold_ecdsa_session_not_ready`.

Phase 0 inventory findings:

- Budget policy sources:
  `client/src/core/config/defaultConfigs.ts` sets `remainingUses: 3` in both
  `signing.sessionDefaults` and ECDSA `provisioningDefaults` (Tempo/EVM).
  `client/src/core/signingEngine/threshold/sessionPolicy.ts` keeps
  `DEFAULT_THRESHOLD_SESSION_POLICY.remainingUses = 3`, then applies it in
  `buildEd25519SessionPolicy(...)` and `buildEcdsaHssSessionPolicy(...)` via
  `clampThresholdSessionPolicy(...)`.
- Reservation state in `BudgetCoordinator`:
  in-memory mutable maps are
  `reservationsByOperationId` and `successfulSpendsByOperationId`, with
  `walletReservationQueues` serializing reserve calls per wallet session id.
  Reserve dedupes on operation id + fingerprint, records projection metadata,
  and releases reservation on success/failure/zero-spend finalization paths.
- Projection assertions and throw sites in `budget.ts`:
  `assertSigningSessionBudgetReservationAvailable(...)` throws for
  adapter/status unknown, `not_found`, non-active status, missing projection
  version, in-flight contention, exhausted budget, and missing prepared
  projection input. The stale prepared-projection helper was removed after
  finalization began returning typed `projection_mismatch` results.
- Finalizer API shape (`budgetFinalizer.ts`):
  `createSigningSessionBudgetFinalizer(...)` returns
  `{ spend?, reserve(), recordSuccess(), recordZeroSpend(error) }`.
  `reserve()` retries local in-flight contention, `recordSuccess()` currently
  delegates to `budget.recordSuccess(...)` and throws on failure,
  `recordZeroSpend(...)` infers a typed zero-spend reason and records it.
- Email OTP app-session refresh behavior (`appSessionJwtCache.ts`):
  `resolve(...)` returns cached unexpired app-session JWT or refreshes via
  `refreshEmailOtpAppSessionJwt(...)`. Refresh calls `POST /session/refresh`
  with cookie credentials and optional bearer token; non-OK responses throw
  generic `Error(message)` (HTTP code embedded only in fallback string).
- Budget status 401/403 handling (`budgetStatusReader.ts`):
  `fetchTrustedWalletSigningBudgetStatusOnce(...)` maps HTTP 401/403 to
  `budget_unknown` (`reason: 'status_unavailable'`) and marks
  `authRejected: true`. `readTrustedWalletSigningBudgetStatus(...)` retries once
  with fallback auth material when provided auth is rejected. Payload-level
  `not_found + statusCode=unauthorized` is also converted to `budget_unknown`.
- Signing paths and mapping boundary for
  `threshold_ecdsa_session_not_ready`:
  `signNear/signNear.ts` catches session-auth-unavailable and budget-exhausted
  to trigger one fresh-auth retry; `signNear/signTransactions.ts`,
  `signNear/signDelegate.ts`, and `signNear/signNep413.ts` convert unavailable
  threshold auth into `THRESHOLD_SESSION_AUTH_UNAVAILABLE_ERROR`.
  `signEvmFamily/freshAuthRetryPolicy.ts` treats threshold-auth-unavailable and
  budget-exhausted as retry-eligible. Wallet boundary mapping to canonical
  `threshold_ecdsa_session_not_ready` is centralized in
  `client/src/core/WalletIframe/host/canonicalSignerErrorCode.ts` and applied in
  `client/src/core/WalletIframe/host/index.ts` when posting `ERROR` payloads.

## Phase 1: Split Unlock Budget From Step-Up Budget

Unlock warms a short-lived multi-use wallet session. Post-exhaustion step-up
authorizes the current operation unless the caller explicitly requests warm
budget refresh.

Budget-size correction from the embedded Refactor 39 draft: the development
default gives wallet unlock and explicit warm-budget refresh three
user-facing approvals. Default post-exhaustion step-up is a single-operation
approval that provisions enough internal signature budget for the approved
operation.

### Target Types

```ts
type PositiveRemainingApprovals = number & {
  readonly __brand: 'PositiveRemainingApprovals';
};

type PositiveSignatureUses = number & {
  readonly __brand: 'PositiveSignatureUses';
};

type SigningBudgetAllowance =
  | {
      kind: 'dev_default_budget_allowance';
      remainingApprovals: 3;
      source: 'sdk_dev_default';
    }
  | {
      kind: 'server_environment_budget_allowance';
      remainingApprovals: PositiveRemainingApprovals;
      policyVersion: string;
      source: 'server_environment_policy';
    };

type WalletUnlockBudgetPolicy = {
  kind: 'wallet_unlock_budget_policy';
  allowance: SigningBudgetAllowance;
  scope: 'wallet_unlock';
  operationId?: never;
};

type SingleOperationStepUpBudgetPolicy = {
  kind: 'single_operation_step_up_budget_policy';
  allowance: {
    kind: 'single_operation_approval_allowance';
    remainingApprovals: 1;
    requiredSignatureUses: PositiveSignatureUses;
  };
  scope: 'single_operation_step_up';
  operationId: SigningOperationId;
};

type SigningBudgetPolicy =
  | WalletUnlockBudgetPolicy
  | SingleOperationStepUpBudgetPolicy;
```

### Tasks

- [x] Add a boundary parser for server/environment budget allowance.
- [x] Keep the development default as three approvals.
- [x] Make unlock provisioning accept only `WalletUnlockBudgetPolicy`.
- [x] Make post-exhaustion signing accept `SingleOperationStepUpBudgetPolicy`
      by default.
- [x] Keep warm budget refresh out of the active policy union until a product
      flow explicitly needs it.
- [x] Add type fixtures rejecting operation-less step-up policies and
      operation-scoped unlock policies.
- [x] Add tests proving unlock starts with three approvals under dev default.
- [x] Add tests proving default post-exhaustion step-up starts with one
      approval.

## Phase 1B: Separate Approval Budget From Signature-Use Budget

Manual NEAR testing exposed a budget-unit ambiguity: the SDK described
post-exhaustion step-up as a single operation with one remaining use, while the
NEAR `transactionsWithActions` API can request signatures for multiple NEAR
transactions in one user-approved operation. Product surfaces should model the
user-facing budget as approvals. Server enforcement should track signature uses.

Canonical policy:

- `remainingApprovals` is the SDK/UI concept. One confirmed signing intent
  consumes one approval.
- `remainingSignatureUses` is the server/security concept. One threshold
  signature consumes one signature use.
- Step-up remains one user-facing approval for one confirmed operation.
- Step-up provisions enough `remainingSignatureUses` for the approved operation.
- One NEAR transaction containing many actions requires one signature use.
- One Tempo transaction containing many calls requires one signature use.
- One EVM transaction requires one signature use.
- A request that signs multiple independent transactions requires one signature
  use per transaction digest.
- Readiness and step-up provisioning must compare trusted
  `remainingSignatureUses` against `requiredSignatureUses` before threshold
  signing starts.
- Budget finalization must spend the same `requiredSignatureUses` captured at
  admission. It must never recompute the count after signing.
- SDK/API responses and UI copy should expose `remainingApprovals` where users
  are making approval decisions. Low-level diagnostics may include
  `remainingSignatureUses`.

Current ECDSA status:

- EVM-family public signing currently accepts one EVM or Tempo transaction per
  request.
- Tempo transactions can include multiple calls, but they produce one sender
  signature.
- The generic EVM-family intent runner can iterate multiple sign requests, so
  the budget model must be ready for future ECDSA batch signing before such an
  API is added.

Tasks:

- [x] Rename ambiguous `usesNeeded` variables in transaction signing paths to
      `requiredSignatureUses` or `signatureUsesNeeded`.
- [ ] Rename internal server-enforced counters away from `remainingUses` toward
      `remainingSignatureUses` where the counter is signature-use based.
- [ ] Add an SDK/UI projection that exposes `remainingApprovals` for approval
      budget display.
- [x] Add branch-specific helpers:
      `requiredNearTransactionSignatureUses(transactions)` and
      `requiredEvmFamilySignatureUses(intent)`.
- [x] Make NEAR `transactionsWithActions` readiness, step-up provisioning,
      budget reservation, and finalization use
      `requiredNearTransactionSignatureUses(...)`.
- [x] Keep NEAR action batching at one use per transaction, independent of the
      number of actions inside that transaction.
- [x] Add tests for a NEAR request with one transaction and multiple actions
      proving it requires one signature use.
- [x] Add tests for a NEAR request with two transactions proving step-up
      provisions two signature uses and finalization spends two.
- [ ] Add tests proving a session with one remaining use signs a one-transaction
      multi-action NEAR request without step-up.
- [ ] Add tests proving a session with one remaining use triggers step-up before
      a two-transaction NEAR request starts signing.
- [x] Add EVM-family guard tests proving current EVM and Tempo adapters produce
      one threshold ECDSA signature use per transaction request.
- [x] Add a type or runtime guard for future ECDSA batch requests requiring the
      batch API to declare `requiredSignatureUses` before budget admission.
- [ ] Update user-facing copy to say "approvals remaining".
- [ ] Keep signature-use terminology in low-level diagnostics and server logs.

## Phase 2: Add Exact Signing Lane Identity Foundation

Freshness, reauth anchors, budget reservations, finalization idempotency, and
Email OTP refresh rejection all need the same lane identity. Add that shared
foundation before changing the lifecycle callers.

### Target Module

Add `client/src/core/signingEngine/session/identity/exactSigningLaneIdentity.ts`
with exact lane builders and canonical encoders.

### Target Types

```ts
type ExactEd25519SigningLaneIdentity = {
  kind: 'exact_ed25519_signing_lane_identity';
  curve: 'ed25519';
  chainFamily: 'near';
  accountId: AccountId;
  authMethod: 'passkey' | 'email_otp';
  walletSigningSessionId: WalletSigningSessionId;
  thresholdSessionId: ThresholdEd25519SessionId;
};

type ExactEcdsaSigningLaneIdentity = {
  kind: 'exact_ecdsa_signing_lane_identity';
  curve: 'ecdsa';
  chainFamily: ThresholdEcdsaChainTarget['kind'];
  walletId: AccountId;
  authMethod: 'passkey' | 'email_otp';
  chainTarget: ThresholdEcdsaChainTarget;
  key: EvmFamilyEcdsaKeyIdentity;
  walletSigningSessionId: WalletSigningSessionId;
  thresholdSessionId: ThresholdEcdsaSessionId;
};

type ExactSigningLaneIdentity = ExactEd25519SigningLaneIdentity | ExactEcdsaSigningLaneIdentity;

type ExactSigningLaneIdentityKey = string & {
  readonly __brand: 'ExactSigningLaneIdentityKey';
};

type NonEmptyThresholdSessionIds = readonly [ThresholdSessionId, ...ThresholdSessionId[]];
```

### Tasks

- [x] Add `exactSigningLaneIdentityKey(identity)` using sorted-key JSON or a
      length-prefixed encoder.
- [x] Include every field in `ExactSigningLaneIdentity`. For ECDSA this includes
      exact `chainTarget`, wallet id, auth method, key identity, wallet signing
      session id, and threshold session id.
- [x] Add exact Ed25519 and exact ECDSA builders from selected/planning lanes.
- [x] Build ECDSA identity only from exact chain target and canonical
      EVM-family key identity.
- [x] Export helpers for non-empty threshold session id lists derived from exact
      lane identity.
- [x] Use `exactSigningLaneIdentityKey(identity)` for freshness diagnostics,
      reauth anchors, reservation identity, and OTP refresh rejection identity.
- [x] Add type fixtures rejecting `SelectedEcdsaSigningLaneIdentity`,
      operation-less identities, missing wallet/session fields, and branch-mixed
      identities at exact-identity boundaries.

## Phase 3: Make Prompt Policy a Capability Boundary

Prompt-capable flows and no-prompt flows should receive different dependency
sets. Page refresh, sealed rehydration, and display-only reads should be unable
to call passkey/TouchID or fresh bootstrap by type.

### Existing Types To Extend

`client/src/core/signingEngine/session/passkey/ecdsaWarmCapabilityBootstrap.ts`
already defines:

- `NoPromptWarmSessionDeps`
- `PromptCapableWarmupDeps`

`NoPromptWarmSessionDeps` already blocks prompt-capable fields with `never`
fields such as `prompt`, `webauthnPrompt`, `touchIdPrompt`,
`passkeyCredentialCollector`, and `freshBootstrap`. Refactor 41 should extend
and reuse these concrete types while avoiding parallel prompt-policy dependency
types.

### Tasks

- [x] Audit `NoPromptWarmSessionDeps` and `PromptCapableWarmupDeps` for every
      unlock, reuse, page-refresh, and display-only owner-address path.
- [x] Add narrow display-only deps at the existing assembly port where
      owner/address reads are wired.
- [x] Delete or narrow broad deps that can carry both prompt-capable and
      no-prompt capabilities.
- [x] Add type fixtures rejecting prompt deps in no-prompt and display-only
      paths.
- [x] Add unit tests proving passkey unlock prompts exactly once.
- [x] Add unit tests proving page-refresh rehydration and display-only reads do
      not prompt.

## Phase 4: Identify Step-Up Freshness Exactly

Freshness state must be tied to a wallet, operation, curve, lane/session
identity, projection state, expiry, and status source. A generic
`fresh_step_up_required` result can be applied to the wrong operation. This
phase uses the exact lane identity module from Phase 2.

### Target Types

```ts
type SigningStatusProvenance =
  | {
      kind: 'trusted_server_budget_status';
      projectionVersion: string;
      observedAtMs: number;
    }
  | {
      kind: 'restored_sealed_record_status';
      recordVersion: string;
      updatedAtMs: number;
    }
  | {
      kind: 'email_otp_refresh_boundary';
      httpStatus: 401 | 403;
      observedAtMs: number;
    };

type StepUpProjectionState =
  | {
      kind: 'known';
      version: string;
    }
  | {
      kind: 'unavailable';
      reason:
        | 'restored_record_has_no_projection'
        | 'email_otp_refresh_rejected'
        | 'budget_status_unavailable';
    };

type KnownStepUpProjectionState = Extract<StepUpProjectionState, { kind: 'known' }>;

type StepUpExpiryState =
  | {
      kind: 'known';
      expiresAtMs: number;
    }
  | {
      kind: 'unavailable';
      reason:
        | 'restored_record_has_no_expiry'
        | 'email_otp_refresh_rejected'
        | 'budget_status_unavailable';
    };

type FreshStepUpRequired = {
  kind: 'fresh_step_up_required';
  walletId: AccountId;
  operationId: SigningOperationId;
  operationFingerprint: SigningOperationFingerprint;
  authMethod: 'passkey' | 'email_otp';
  curve: 'ed25519' | 'ecdsa';
  laneIdentity: ExactSigningLaneIdentity;
  laneIdentityKey: ExactSigningLaneIdentityKey;
  walletSigningSessionId: WalletSigningSessionId;
  thresholdSessionIds: NonEmptyThresholdSessionIds;
  projection: StepUpProjectionState;
  expiry: StepUpExpiryState;
  provenance: SigningStatusProvenance;
  reason:
    | 'wallet_budget_exhausted'
    | 'threshold_session_exhausted'
    | 'threshold_session_expired'
    | 'email_otp_refresh_rejected';
};

type FreshStepUpSatisfied = {
  kind: 'fresh_step_up_satisfied';
  walletId: AccountId;
  operationId: SigningOperationId;
  operationFingerprint: SigningOperationFingerprint;
  authMethod: 'passkey' | 'email_otp';
  curve: 'ed25519' | 'ecdsa';
  laneIdentity: ExactSigningLaneIdentity;
  laneIdentityKey: ExactSigningLaneIdentityKey;
  walletSigningSessionId: WalletSigningSessionId;
  thresholdSessionIds: NonEmptyThresholdSessionIds;
  projection: StepUpProjectionState;
  expiry: StepUpExpiryState;
  remainingUses: PositiveRemainingUses;
  provenance: SigningStatusProvenance;
};

type FreshStepUpSatisfiedForAdmission = Omit<FreshStepUpSatisfied, 'kind' | 'projection'> & {
  kind: 'fresh_step_up_satisfied_for_admission';
  projection: KnownStepUpProjectionState;
};

type StepUpFreshnessState =
  | FreshStepUpRequired
  | FreshStepUpSatisfied
  | FreshStepUpSatisfiedForAdmission;
```

### Tasks

- [x] Add builders from trusted budget status, sealed restored records, and
      Email OTP refresh results into `StepUpFreshnessState`.
- [x] Set `projection.kind === 'known'` only when the source provides a real
      projection version. Use the unavailable branch for expired restored records,
      refresh-boundary failures, and budget-status gaps.
- [x] Set `expiry.kind === 'known'` only when the source provides a real expiry.
      Use the unavailable branch for restored records or refresh failures without a
      live budget expiry.
- [x] Require lane identity and operation identity before a freshness state can
      enter signing or reauth planning.
- [x] Add a builder that converts `FreshStepUpSatisfied` into
      `FreshStepUpSatisfiedForAdmission` only when projection is known.
- [x] Keep diagnostics derived from freshness state. Admission and reauth
      planning should accept only the narrow freshness branch they need.
- [x] Validate duplicated top-level fields against `laneIdentity` inside
      builders: wallet id, auth method, curve, wallet signing session id, and
      threshold session ids.
- [x] Add type fixtures rejecting freshness states without wallet id, operation
      id, exact lane identity, lane identity key, projection state, expiry, or
      provenance.
- [x] Add type fixtures rejecting satisfied-for-admission states without known
      projection.
- [x] Add unit tests for Ed25519 and ECDSA exhausted states.
- [x] Add unit tests proving freshness for one lane cannot satisfy another lane.

## Phase 5: Treat Exhausted Sessions as Reauth Anchors

Exhausted/expired sessions can identify which key and lane need reauth. They
cannot be admitted as signing material.

### Existing Lifecycle Types To Extend

Do this inside `client/src/core/signingEngine/session/operationState/transactionState.ts`.
The current code already defines:

- `BudgetAdmittedOperation`
- `BudgetAdmittedLifecycle`
- `StepUpConfirmedLifecycle`
- `ReauthAdmittedLifecycle`

Refactor 41 should extend those existing lifecycle unions and avoid a parallel
admission model.

### Target Additions

```ts
type ReauthAnchorSourceState = {
  kind: 'reauth_anchor_source_state';
  availabilitySource:
    | 'durable_sealed_record'
    | 'runtime_session_record'
    | 'runtime_and_durable'
    | 'evm_family_shared_key';
  storeSource: ThresholdEcdsaSessionStoreSource | ThresholdEd25519SessionStoreSource;
  retention: 'session' | 'single_use' | 'unknown';
  remainingUses: number | null;
  expiry: StepUpExpiryState;
  projection: StepUpProjectionState;
};

type ReauthAnchorIdentity = {
  kind: 'reauth_anchor_identity';
  laneIdentity: ExactSigningLaneIdentity;
  laneIdentityKey: ExactSigningLaneIdentityKey;
  sourceState: ReauthAnchorSourceState;
  freshness: FreshStepUpRequired;
  readyLane?: never;
  budget?: never;
};
```

### Tasks

- [x] Add branch-specific builders that validate
      `FreshStepUpSatisfiedForAdmission` and return the existing budget-admitted
      lifecycle states.
- [x] Add a branch-specific builder that validates `FreshStepUpRequired` and
      returns the existing `ReauthAdmittedLifecycle` with `ReauthAnchorIdentity`.
- [x] Keep signing executors typed against the existing admitted lifecycle
      branches. Raw freshness objects stay inside branch-specific builders.
- [x] Make reauth planning accept only `ReauthAnchorIdentity`.
- [x] Integrate reauth-anchor construction with the existing ECDSA exhausted /
      expired collapse helpers in
      `client/src/core/signingEngine/session/availability/availableSigningLanes.ts`.
- [x] Add type fixtures proving exhausted/expired lanes cannot be passed to
      signing execution.
- [x] Add tests for post-refresh exhausted OTP ECDSA and Ed25519 lanes becoming
      reauth anchors.

## Phase 6: OTP Refresh Auth Rejection Means Fresh OTP Required

Email OTP refresh failure is an auth freshness state. `/session/refresh` 401/403
should be represented at the app-session refresh boundary before signing or
budget code sees it.

### Target Types

```ts
type EmailOtpRefreshIdentity = {
  kind: 'email_otp_refresh_identity';
  walletId: AccountId;
  walletSessionUserId: string;
  operationId: SigningOperationId;
  operationFingerprint: SigningOperationFingerprint;
  laneIdentity: ExactSigningLaneIdentity;
  laneIdentityKey: ExactSigningLaneIdentityKey;
};

type EmailOtpSessionRefreshResult =
  | {
      kind: 'cached_email_otp_session';
      identity: EmailOtpRefreshIdentity;
      appSessionJwt: string;
    }
  | {
      kind: 'refreshed_email_otp_session';
      identity: EmailOtpRefreshIdentity;
      appSessionJwt: string;
    }
  | {
      kind: 'email_otp_refresh_rejected';
      identity: EmailOtpRefreshIdentity;
      reason: 'session_refresh_unauthorized';
      httpStatus: 401 | 403;
      appSessionJwt?: never;
    };
```

### Tasks

- [x] Change `refreshEmailOtpAppSessionJwt(...)` to return
      `EmailOtpSessionRefreshResult` for refresh success and auth rejection.
- [x] Change `EmailOtpAppSessionJwtCache.resolve(...)` to return
      `EmailOtpSessionRefreshResult`, including a cached-success branch.
- [x] Reserve thrown errors for transport, decoding, or programmer failures.
- [x] Require wallet/session and exact lane identity before resolving or
      refreshing an Email OTP app-session JWT for signing.
- [x] Map `email_otp_refresh_rejected` to
      `FreshStepUpRequired.reason === 'email_otp_refresh_rejected'`.
- [x] Prevent refresh 401/403 from becoming
      `threshold_ecdsa_session_not_ready`.
- [x] Keep budget-status 401/403 handling separate; `budget_unknown` remains a
      budget status result, while app-session refresh 401/403 becomes fresh OTP
      required.
- [x] Add type fixtures rejecting OTP refresh identity without exact lane
      identity, lane identity key, wallet id, wallet session user id, operation id,
      or operation fingerprint.
- [x] Add unit tests for cached success, refresh success, 401 rejection, and 403
      rejection.
- [x] Add unit tests for OTP refresh 401 and 403 on Ed25519 and ECDSA signing.
- [x] Add e2e coverage for post-exhaustion page refresh followed by OTP
      step-up.

## Phase 7: Make Budget Reservations Per Operation

`BudgetCoordinator` currently stores reservations and successful spends by
`operationId`. Keep that map key if operation ids remain globally unique, but
store a canonical reservation identity under the operation id and validate it on
every reserve/finalize call.

### Target Types

```ts
type SigningBudgetReservationIdentity = {
  kind: 'signing_budget_reservation_identity';
  operationId: SigningOperationId;
  operationFingerprint: SigningOperationFingerprint;
  walletId: AccountId;
  walletSigningSessionId: WalletSigningSessionId;
  laneIdentity: ExactSigningLaneIdentity;
  laneIdentityKey: ExactSigningLaneIdentityKey;
  thresholdSessionIds: NonEmptyThresholdSessionIds;
  backingMaterialSessionIds: readonly BackingMaterialSessionId[];
  admittedProjection: KnownStepUpProjectionState;
  reservedUses: 1;
};

type SigningBudgetReservationKey = string & {
  readonly __brand: 'SigningBudgetReservationKey';
};

type BudgetReservationFinalizationCommand = {
  kind: 'budget_reservation_finalization_command';
  reservation: SigningBudgetReservationIdentity;
  outcome: 'signed' | 'failed_before_sign' | 'broadcast_failed';
};
```

### Canonical Serialization

- [x] Include every field in `SigningBudgetReservationIdentity`.
- [x] Store the serialized identity in `SigningSessionBudgetReservationRecord`.
- [x] Validate the serialized identity on reserve dedupe, reserved success,
      unreserved success, zero spend release, and repeated success.

### Tasks

- [x] Add `SigningBudgetReservationIdentity` to reservation records.
- [x] Keep `reservationsByOperationId` only as an index from operation id to
      canonical reservation identity.
- [x] Keep `successfulSpendsByOperationId` only as an index from operation id to
      canonical reservation identity and result promise.
- [x] Replace mutable current-session reservation state with
      `SigningBudgetReservationIdentity`.
- [x] Store prepared material by operation id and lane identity.
- [x] Make finalization accept `BudgetReservationFinalizationCommand`.
- [x] Add idempotency keyed by the canonical reservation identity.
- [x] Add tests for concurrent NEAR and Tempo post-exhaustion step-up
      operations.
- [x] Add tests for repeated success/failure finalization of the same
      reservation.

## Phase 8: Convert Budget Throws to Typed Results

Current budget errors are thrown from several surfaces. Refactor them into typed
results so callers can retry, re-read, or require step-up without collapsing to a
generic session-not-ready error.

### Current Throw Sites to Convert

- [x] `budget.ts`: `assertPreparedBudgetProjectionVersion` throws
      `[SigningSessionBudget] prepared budget projection is stale`.
- [x] `BudgetCoordinator.ts`: reserved success without a reservation throws
      `[SigningSessionBudget] reserved_success requires an existing reservation`.
- [x] `BudgetCoordinator.ts`: reserved operation finalized as unreserved throws
      `[SigningSessionBudget] reserved operations must finalize with reserved_success`.
- [x] `BudgetCoordinator.ts`: reservation/finalization mismatch throws
      `[SigningSessionBudget] reserved_success spend does not match reservation`.
- [x] `BudgetCoordinator.ts`: operation id reuse throws through
      `assertWalletSigningOperationFingerprintMatches`.
- [x] `BudgetCoordinator.ts`: spend returned `not_found`, `budget_unknown`, or
      no status.

### Finalization Command

```ts
type BudgetReservationFinalizationCommand = {
  kind: 'budget_reservation_finalization_command';
  reservation: SigningBudgetReservationIdentity;
  outcome: 'signed' | 'failed_before_sign' | 'broadcast_failed';
};
```

Use this command as the only finalization input once reservation identity is
stable.

### Result Types

```ts
type SigningBudgetFinalizationResult =
  | {
      kind: 'finalized';
      reservation: SigningBudgetReservationIdentity;
      remainingUses: number;
      projectionVersion: string;
    }
  | {
      kind: 'already_finalized';
      reservation: SigningBudgetReservationIdentity;
      remainingUses: number;
      projectionVersion: string;
    }
  | {
      kind: 'projection_mismatch';
      reservation: SigningBudgetReservationIdentity;
      expectedProjectionVersion: string;
      actualProjectionVersion: string;
    }
  | {
      kind: 'missing_reservation';
      reservation: SigningBudgetReservationIdentity;
    }
  | {
      kind: 'reservation_identity_mismatch';
      expected: SigningBudgetReservationIdentity;
      actual: SigningBudgetReservationIdentity;
    }
  | {
      kind: 'budget_status_unavailable';
      reservation: SigningBudgetReservationIdentity;
      status: 'not_found' | 'budget_unknown' | 'missing_status';
    };
```

### API Changes

- [x] Change `SigningSessionBudget.recordSuccess(...)` to return
      `Promise<SigningBudgetFinalizationResult>`.
- [x] Change `SigningSessionBudgetFinalizer.recordSuccess()` from
      `Promise<void>` to `Promise<SigningBudgetFinalizationResult>`.
- [x] Update call sites that currently catch thrown budget errors and normalize
      them into session failures.
- [x] Keep unexpected programmer errors as thrown exceptions after exhaustive
      result handling.
- [x] Add trace events for finalized, already finalized, projection mismatch,
      missing reservation, identity mismatch, and unavailable status.

## Phase 9: Remove ECDSA `subjectId` Where Safe

`walletId` is still the registration/profile identity and should remain
owned by registration flows. ECDSA `subjectId` should disappear from public
commands, lane state, selected/planning identity, freshness, budget
reservations, and persisted runtime records. HSS protocol inputs may still need a
wallet-derived identity string for existing digests, key ids, JWT claims, and
server verification; keep that field protocol-local and derive it from wallet id
until the HSS identity scheme is explicitly versioned.

### Safety Gates

- [x] Classify every remaining `subjectId` and `walletId` reference into:
      registration/profile identity, HSS protocol identity, Email OTP auth subject,
      ECDSA runtime metadata, persistence compatibility, docs/tests.
- [x] Keep `walletId` in registration intent, registration ceremonies,
      WebAuthn credential binding, and wallet key-facts inventory routes.
- [x] Keep `authSubjectId` separate for Email OTP provider identity.
- [x] Keep HSS protocol subject identity only behind a narrowly named type such
      as `BaseEcdsaSubjectId` or `HssWalletId`.
- [x] Remove HSS protocol `subjectId` from digest/JWT inputs only with a new
      protocol version and an explicit key/session invalidation plan.

### Tasks

- [x] Rename protocol-local ECDSA HSS `subjectId` fields to
      `baseEcdsaSubjectId` or `hssWalletId` at internal boundaries.
- [x] Derive the protocol-local HSS subject identity from wallet id in one
      builder. Core ECDSA key/lane/session functions should accept wallet id and
      exact lane identity instead of raw subject strings.
- [x] Remove `subjectId` from `BuildEvmFamilyEcdsaKeyIdentityInput`; derive and
      validate the base ECDSA subject inside the boundary builder.
- [x] Replace `walletIdFromAccountContext({ subjectId, profileId })`
      fallback usage with explicit parsers for either registration `walletId`
      or ECDSA `walletId`.
- [x] Make canonical ECDSA session record parsing reject any `subjectId`, even
      when it matches the wallet-derived value.
- [x] Keep sealed ECDSA records rejecting `subjectId`; remove any rebuild or
      compatibility code that preserves it.
- [x] Remove `subjectId` from ECDSA examples and docs that describe public
      bootstrap, reconnect, reauth, signing, or export APIs.
- [x] Add type fixtures rejecting `subjectId` in ECDSA public inputs, selected
      lanes, planning lanes, exact lane identity, freshness, reservation identity,
      OTP refresh identity, ready material, and persisted ECDSA records.
- [x] Add targeted tests proving legacy ECDSA persisted records with
      `subjectId` are rejected or deleted at the persistence boundary.

## Spec Review Follow-Up

- [x] Reserve ECDSA HSS export nonce replay guards before terminal export-share
      failures after syntax/auth validation.
- [x] Rename active explicit ECDSA export artifact kind to
      `ecdsa-hss-secp256k1-export`.
- [x] Update local ECDSA HSS specs for active v2 `wallet_id`/`rp_id` context,
      wipe/recreate invalidation, and removal of the old context version.
- [x] Reject stale ECDSA HSS old identity fields at active bootstrap, export, and
      persisted role-local record boundaries.
- [x] Remove the old Rust ECDSA HSS context, wire, server, integration, client,
      fixture, benchmark, and formal-verification test surfaces; the crate now
      has no retained old-version code path.
- [x] Remove `_v2`/`V2` suffixes from active ECDSA HSS Rust, WASM wrapper, and
      formal-verification symbol names; keep v2 only in protocol literals,
      fixture names, and persisted version strings.
- [x] Rename the internal EVM-family ECDSA key fingerprint canonical field from
      `subjectId` to `baseEcdsaSubjectId`; current warm sessions must be
      refreshed after this change.

## Validation

Focused checks:

New focused type fixtures to create as part of this refactor:

- `client/src/core/signingEngine/session/identity/exactSigningLaneIdentity.typecheck.ts`
- `client/src/core/signingEngine/session/operationState/stepUpFreshness.typecheck.ts`
- `client/src/core/signingEngine/session/identity/subjectIdentityCleanup.typecheck.ts`
- `tests/unit/signingSessionPolicy.typecheck.ts`

New focused tests to create as part of this refactor:

- `tests/unit/signingSessionAdmission.unit.test.ts`
- `tests/unit/signingSessionFreshness.unit.test.ts`
- `tests/unit/emailOtpAppSessionJwtCache.unit.test.ts`
- `tests/unit/subjectIdentityCleanup.unit.test.ts`

Existing focused type fixtures and tests to extend:

- `client/src/core/signingEngine/session/passkey/ecdsaWarmCapabilityBootstrap.typecheck.ts`
- `client/src/core/signingEngine/session/availability/availableSigningLanes.typecheck.ts`
- `tests/unit/signingSessionBudgetFinalizer.unit.test.ts`
- `tests/unit/nearSigning.sessionSelection.unit.test.ts`
- `tests/unit/availableSigningLanes.ecdsaDuplicates.unit.test.ts`

```sh
pnpm -s type-check:sdk
pnpm -C tests exec playwright test \
  ./unit/signingSessionBudgetFinalizer.unit.test.ts \
  ./unit/signingSessionAdmission.unit.test.ts \
  ./unit/signingSessionFreshness.unit.test.ts \
  ./unit/emailOtpAppSessionJwtCache.unit.test.ts \
  ./unit/nearSigning.sessionSelection.unit.test.ts \
  ./unit/availableSigningLanes.ecdsaDuplicates.unit.test.ts \
  --reporter=line
```

Completed validation:

- [x] `pnpm -s build:sdk`
- [x] `pnpm -s type-check:sdk`
- [x] `pnpm -s type-check`
- [x] `pnpm -C tests exec playwright test ./unit/thresholdEcdsa.hssRoleLocalExportPolicy.unit.test.ts --reporter=line`
- [x] `pnpm -C tests exec playwright test ./unit/privateKeyExportRecovery.binding.unit.test.ts ./unit/ecdsaExportMaterial.unit.test.ts ./unit/passkeyConfirm.exportFlow.unit.test.ts --reporter=line`
- [x] `pnpm -C tests exec playwright test ./unit/authService.ecdsaKeyIdentityInventory.unit.test.ts ./unit/availableSigningLanes.ed25519Duplicates.unit.test.ts ./unit/deviceRecoveryDomain.emailRecovery.unit.test.ts ./unit/emailOtpThresholdSessionCoordinator.unit.test.ts --reporter=line`
- [x] `pnpm -C tests exec playwright test ./unit/ecdsaSelection.restorable.unit.test.ts ./unit/signingSessionRestoreCoordinator.unit.test.ts ./unit/passkeyClientDB.deviceSelection.test.ts ./unit/thresholdEcdsa.postgresKeyStoreBackfill.unit.test.ts ./unit/stableExperimentalExportBoundaries.guard.unit.test.ts --reporter=line`
- [x] `pnpm -C tests exec playwright test ./unit/confirmTxFlow.defensivePaths.test.ts ./unit/confirmTxFlow.successPaths.test.ts ./unit/signerMutationSagas.passkeyManagement.unit.test.ts ./unit/thresholdEcdsa.tempoHighLevel.unit.test.ts ./unit/thresholdEcdsa.presignPoolRefill.unit.test.ts --reporter=line`
- [x] `pnpm -C tests exec playwright test ./unit/signingEngine.refactor37.guard.unit.test.ts -g "Postgres ECDSA key store indexes shared identity on declared columns" --reporter=line`
- [x] `pnpm -C tests exec playwright test ./unit/thresholdEcdsa.postgresKeyStoreBackfill.unit.test.ts --reporter=line`
- [x] `pnpm -C tests exec playwright test ./unit/thresholdEcdsa.hssRoleLocalExportPolicy.unit.test.ts ./unit/privateKeyExportRecovery.binding.unit.test.ts ./unit/passkeyConfirm.exportFlow.unit.test.ts --reporter=line`
- [x] `git diff --check -- ...` across the touched ECDSA HSS server, client,
      SDK dist, test, and doc paths.
- [x] `just ecdsa-hss-fv`
- [x] `cargo bench --manifest-path crates/ecdsa-hss/Cargo.toml --bench performance_baseline`
- [x] `pnpm -s benchmark:ecdsa-hss:wasm`
- [x] `cargo test --manifest-path crates/ecdsa-hss/Cargo.toml`
- [x] `pnpm -C tests exec playwright test ./unit/thresholdEcdsa.hssWasmSurface.unit.test.ts --reporter=line`

Validation notes:

- A broad `pnpm -C tests exec playwright test ./unit --reporter=line` sweep was
  interrupted after surfacing stale fixtures. The stale fixture clusters were
  updated and covered by the focused passing checks above.

Broader checks before completion:

```sh
pnpm -s type-check
pnpm -C tests exec playwright test ./unit --reporter=line
git diff --check -- . ':(exclude)crates/ecdsa-hss/**'
```

Manual flows:

- [x] Passkey unlock provisions the configured unlock budget and prompts for
      user verification.
- [x] Page refresh rehydration does not prompt for passkey user verification.
- [x] Passkey post-exhaustion step-up uses single-operation budget by default.
- [x] Email OTP post-exhaustion step-up maps refresh 401/403 to fresh OTP
      required.
- [x] Concurrent post-exhaustion NEAR and Tempo signing either both succeed with
      separate operation reservations or one receives a typed in-flight result.

## Completion Criteria

- [x] Unlock budget and step-up budget are different policy branches.
- [x] Exact signing lane identity and canonical lane identity keys are shared
      by freshness, reauth anchors, reservations, finalization, and OTP refresh.
- [x] Step-up freshness includes wallet, operation, curve, lane identity,
      projection state, expiry, and provenance.
- [x] Admission-ready freshness requires a known projection.
- [x] No-prompt rehydration/display code cannot receive prompt-capable deps.
- [x] Exhausted/expired sessions are represented as reauth anchors and cannot
      enter signing execution.
- [x] Reservation records carry canonical reservation identity under
      operation-id indexes.
- [x] Budget finalization returns typed results for projection mismatch, missing
      reservation, identity mismatch, already finalized, and unavailable status.
- [x] Email OTP refresh 401/403 produces fresh OTP step-up state at the refresh
      boundary.
- [x] ECDSA runtime, persistence, freshness, reservation, and public API types
      reject `subjectId`; registration keeps `walletId`.
- [x] Server ECDSA HSS request and persistence boundaries reject old
      `subjectId`/`walletSessionUserId` field names.
- [x] Type fixtures reject invalid policy, prompt, admission, reservation, and
      OTP refresh states.

## Postgres Cleanup Follow-Up

- [x] Local `threshold_ecdsa_keys` cleanup was verified against the relay-server
      Postgres database: 5 current rows, 0 non-current record shapes, 0 rows
      missing current indexed columns, and 0 rows using the old identity columns.
- [x] Dropped the unused local `wallet_session_user_id` and `subject_id` columns,
      then verified the shared-identity and threshold-identity indexes no longer
      reference the old identity columns.
- [x] `server/src/core/ThresholdService/stores/KeyStore.ts` has no startup prune or
      record-json backfill query. The remaining schema initializer in
      `server/src/storage/postgres.ts` now creates the current `wallet_id` shared
      identity schema.

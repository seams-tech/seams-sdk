# Refactor 40: Budget and Step-Up Invariants

Date created: 2026-05-18
Status: planned

## Scope

This refactor is split out from `docs/refactor-39.md`. Refactor 39 should stay
focused on exact ECDSA lane consumption, ECDSA material identity, key-handle
cleanup, and key-ref isolation. Budget provisioning, prompt policy, step-up
freshness, projection retries, Email OTP refresh failures, and concurrency are a
separate lifecycle refactor.

Refactor 40 can begin after Refactor 39A exact consumption is complete. It does
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
  projection input. `assertPreparedBudgetProjectionVersion(...)` throws for
  missing expected projection, missing trusted projection, and stale projection.
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

Budget-size correction from the embedded Refactor 39 draft: `remainingUses = 3`
applies to wallet unlock and explicit warm-budget refresh under the development
default. Default post-exhaustion step-up is single-operation and uses
`remainingUses = 1`.

### Target Types

```ts
type PositiveRemainingUses = number & {
  readonly __brand: 'PositiveRemainingUses';
};

type SigningBudgetAllowance =
  | {
      kind: 'dev_default_budget_allowance';
      remainingUses: 3;
      source: 'sdk_dev_default';
    }
  | {
      kind: 'server_environment_budget_allowance';
      remainingUses: PositiveRemainingUses;
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
  allowance: { kind: 'single_operation_allowance'; remainingUses: 1 };
  scope: 'single_operation_step_up';
  operationId: SigningOperationId;
};

type WarmBudgetRefreshStepUpPolicy = {
  kind: 'warm_budget_refresh_step_up_policy';
  allowance: SigningBudgetAllowance;
  scope: 'warm_budget_refresh';
  operationId: SigningOperationId;
};

type SigningBudgetPolicy =
  | WalletUnlockBudgetPolicy
  | SingleOperationStepUpBudgetPolicy
  | WarmBudgetRefreshStepUpPolicy;
```

### Tasks

- [x] Add a boundary parser for server/environment budget allowance.
- [x] Keep the development default as literal `remainingUses: 3`.
- [x] Make unlock provisioning accept only `WalletUnlockBudgetPolicy`.
- [x] Make post-exhaustion signing accept `SingleOperationStepUpBudgetPolicy`
  by default.
- [x] Require explicit opt-in for `WarmBudgetRefreshStepUpPolicy`.
- [x] Add type fixtures rejecting operation-less step-up policies and
  operation-scoped unlock policies.
- [x] Add tests proving unlock starts with 3 uses under dev default.
- [x] Add tests proving default post-exhaustion step-up starts with 1 use.

## Phase 2: Make Prompt Policy a Capability Boundary

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
`passkeyCredentialCollector`, and `freshBootstrap`. Refactor 40 should extend and
reuse these concrete types instead of adding parallel prompt-policy dependency
types.

### Tasks

- [ ] Audit `NoPromptWarmSessionDeps` and `PromptCapableWarmupDeps` for every
  unlock, reuse, page-refresh, and display-only owner-address path.
- [ ] Add narrow display-only deps at the existing assembly port where
  owner/address reads are wired.
- [ ] Delete or narrow broad deps that can carry both prompt-capable and
  no-prompt capabilities.
- [ ] Add type fixtures rejecting prompt deps in no-prompt and display-only
  paths.
- [ ] Add unit tests proving passkey unlock prompts exactly once.
- [ ] Add unit tests proving page-refresh rehydration and display-only reads do
  not prompt.

## Phase 3: Identify Step-Up Freshness Exactly

Freshness state must be tied to a wallet, operation, curve, lane/session
identity, projection state, expiry, and status source. A generic
`fresh_step_up_required` result can be applied to the wrong operation.

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

type KnownStepUpProjectionState = Extract<
  StepUpProjectionState,
  { kind: 'known' }
>;

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

type ExactSigningLaneIdentity =
  | ExactEd25519SigningLaneIdentity
  | ExactEcdsaSigningLaneIdentity;

type ExactSigningLaneIdentityKey = string & {
  readonly __brand: 'ExactSigningLaneIdentityKey';
};

// Refactor 39B replaces this ECDSA key field with the key-handle /
// verified-public-facts model once that cleanup lands.

type FreshStepUpRequired = {
  kind: 'fresh_step_up_required';
  walletId: AccountId;
  operationId: SigningOperationId;
  operationFingerprint: SigningOperationFingerprint;
  authMethod: 'passkey' | 'email_otp';
  curve: 'ed25519' | 'ecdsa';
  laneIdentity: ExactSigningLaneIdentity;
  walletSigningSessionId: WalletSigningSessionId;
  thresholdSessionIds: readonly ThresholdSessionId[];
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
  walletSigningSessionId: WalletSigningSessionId;
  thresholdSessionIds: readonly ThresholdSessionId[];
  projection: StepUpProjectionState;
  expiry: StepUpExpiryState;
  remainingUses: PositiveRemainingUses;
  provenance: SigningStatusProvenance;
};

type StepUpFreshnessState = FreshStepUpRequired | FreshStepUpSatisfied;
```

### Tasks

- [ ] Add builders from trusted budget status, sealed restored records, and
  Email OTP refresh results into `StepUpFreshnessState`.
- [ ] Set `projection.kind === 'known'` only when the source provides a real
  projection version. Use the unavailable branch for expired restored records,
  refresh-boundary failures, and budget-status gaps.
- [ ] Set `expiry.kind === 'known'` only when the source provides a real expiry.
  Use the unavailable branch for restored records or refresh failures without a
  live budget expiry.
- [ ] Require lane identity and operation identity before a freshness state can
  enter signing or reauth planning.
- [ ] Build ECDSA freshness from exact chain target and canonical EVM-family key
  identity. Add type fixtures rejecting `SelectedEcdsaSigningLaneIdentity` at
  this boundary.
- [ ] Add type fixtures rejecting freshness states without wallet id, operation
  id, lane identity, projection state, expiry, or provenance.
- [ ] Add unit tests for Ed25519 and ECDSA exhausted states.
- [ ] Add unit tests proving freshness for one lane cannot satisfy another lane.

## Phase 4: Treat Exhausted Sessions as Reauth Anchors

Exhausted/expired sessions can identify which key and lane need reauth. They
cannot be admitted as signing material.

### Existing Lifecycle Types To Extend

Do this inside `client/src/core/signingEngine/session/operationState/transactionState.ts`.
The current code already defines:

- `BudgetAdmittedOperation`
- `BudgetAdmittedLifecycle`
- `StepUpConfirmedLifecycle`
- `ReauthAdmittedLifecycle`

Refactor 40 should extend those existing lifecycle unions instead of adding a
parallel admission model.

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
  sourceState: ReauthAnchorSourceState;
  freshness: FreshStepUpRequired;
  readyLane?: never;
  budget?: never;
};
```

### Tasks

- [ ] Add branch-specific builders that validate `FreshStepUpSatisfied` and
  return the existing budget-admitted lifecycle states.
- [ ] Add a branch-specific builder that validates `FreshStepUpRequired` and
  returns the existing `ReauthAdmittedLifecycle` with `ReauthAnchorIdentity`.
- [ ] Keep signing executors typed against the existing admitted lifecycle
  branches. Raw freshness objects stay inside branch-specific builders.
- [ ] Make reauth planning accept only `ReauthAnchorIdentity`.
- [ ] Integrate reauth-anchor construction with the existing ECDSA exhausted /
  expired collapse helpers in `availableSigningLanes.ts`.
- [ ] Add type fixtures proving exhausted/expired lanes cannot be passed to
  signing execution.
- [ ] Add tests for post-refresh exhausted OTP ECDSA and Ed25519 lanes becoming
  reauth anchors.

## Phase 5: Make Budget Reservations Per Operation

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
  thresholdSessionIds: readonly ThresholdSessionId[];
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

Canonical serialization:

- [ ] Add one shared `exactSigningLaneIdentityKey(identity)` encoder that uses
  sorted-key JSON or a length-prefixed encoder.
- [ ] Include every field in `ExactSigningLaneIdentity`. For ECDSA this includes
  exact `chainTarget`, wallet id, auth method, key identity, wallet signing
  session id, and threshold session id.
- [ ] Use `exactSigningLaneIdentityKey(identity)` for reservation identity,
  reauth anchors, freshness diagnostics, and OTP refresh rejection identity.
- [ ] Include every field in `SigningBudgetReservationIdentity`.
- [ ] Store the serialized identity in `SigningSessionBudgetReservationRecord`.
- [ ] Validate the serialized identity on reserve dedupe, reserved success,
  unreserved success, zero spend release, and repeated success.

### Tasks

- [ ] Add `SigningBudgetReservationIdentity` to reservation records.
- [ ] Keep `reservationsByOperationId` only as an index from operation id to
  canonical reservation identity.
- [ ] Keep `successfulSpendsByOperationId` only as an index from operation id to
  canonical reservation identity and result promise.
- [ ] Replace mutable current-session reservation state with
  `SigningBudgetReservationIdentity`.
- [ ] Store prepared material by operation id and lane identity.
- [ ] Make finalization accept `BudgetReservationFinalizationCommand`.
- [ ] Add idempotency keyed by the canonical reservation identity.
- [ ] Add tests for concurrent NEAR and Tempo post-exhaustion step-up
  operations.
- [ ] Add tests for repeated success/failure finalization of the same
  reservation.

## Phase 6: Convert Budget Throws to Typed Results

Current budget errors are thrown from several surfaces. Refactor them into typed
results so callers can retry, re-read, or require step-up without collapsing to a
generic session-not-ready error.

### Current Throw Sites to Convert

- [ ] `budget.ts`: `assertPreparedBudgetProjectionVersion` throws
  `[SigningSessionBudget] prepared budget projection is stale`.
- [ ] `BudgetCoordinator.ts`: reserved success without a reservation throws
  `[SigningSessionBudget] reserved_success requires an existing reservation`.
- [ ] `BudgetCoordinator.ts`: reserved operation finalized as unreserved throws
  `[SigningSessionBudget] reserved operations must finalize with reserved_success`.
- [ ] `BudgetCoordinator.ts`: reservation/finalization mismatch throws
  `[SigningSessionBudget] reserved_success spend does not match reservation`.
- [ ] `BudgetCoordinator.ts`: operation id reuse throws through
  `assertWalletSigningOperationFingerprintMatches`.
- [ ] `BudgetCoordinator.ts`: spend returned `not_found`, `budget_unknown`, or
  no status.

### Target Types

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

- [ ] Change `SigningSessionBudget.recordSuccess(...)` to return
  `Promise<SigningBudgetFinalizationResult>`.
- [ ] Change `SigningSessionBudgetFinalizer.recordSuccess()` from
  `Promise<void>` to `Promise<SigningBudgetFinalizationResult>`.
- [ ] Update call sites that currently catch thrown budget errors and normalize
  them into session failures.
- [ ] Keep unexpected programmer errors as thrown exceptions after exhaustive
  result handling.
- [ ] Add trace events for finalized, already finalized, projection mismatch,
  missing reservation, identity mismatch, and unavailable status.

## Phase 7: OTP Refresh Auth Rejection Means Fresh OTP Required

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
};

type EmailOtpSessionRefreshResult =
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

- [ ] Change `refreshEmailOtpAppSessionJwt(...)` to return
  `EmailOtpSessionRefreshResult` for both success and auth rejection.
- [ ] Change `EmailOtpAppSessionJwtCache.resolve(...)` to propagate
  `EmailOtpSessionRefreshResult` and reserve thrown errors for transport,
  decoding, or programmer failures.
- [ ] Require wallet/session and exact lane identity before resolving or
  refreshing an Email OTP app-session JWT for signing.
- [ ] Map `email_otp_refresh_rejected` to
  `FreshStepUpRequired.reason === 'email_otp_refresh_rejected'`.
- [ ] Prevent refresh 401/403 from becoming
  `threshold_ecdsa_session_not_ready`.
- [ ] Keep budget-status 401/403 handling separate; `budget_unknown` remains a
  budget status result, while app-session refresh 401/403 becomes fresh OTP
  required.
- [ ] Add unit tests for OTP refresh 401 and 403 on Ed25519 and ECDSA signing.
- [ ] Add e2e coverage for post-exhaustion page refresh followed by OTP
  step-up.

## Validation

Focused checks:

New focused tests to create as part of this refactor:

- `tests/unit/signingSessionPolicy.typecheck.ts`
- `tests/unit/signingSessionAdmission.unit.test.ts`

Existing focused tests to extend:

- `tests/unit/signingSessionBudgetFinalizer.unit.test.ts`
- `tests/unit/nearSigning.sessionSelection.unit.test.ts`

```sh
pnpm -s type-check:sdk
pnpm -C tests exec playwright test \
  ./unit/signingSessionBudgetFinalizer.unit.test.ts \
  ./unit/signingSessionPolicy.typecheck.ts \
  ./unit/signingSessionAdmission.unit.test.ts \
  ./unit/nearSigning.sessionSelection.unit.test.ts \
  --reporter=line
```

Broader checks before completion:

```sh
pnpm -s type-check
pnpm -C tests exec playwright test ./unit --reporter=line
git diff --check -- . ':(exclude)crates/ecdsa-hss/**'
```

Manual flows:

- [ ] Passkey unlock provisions the configured unlock budget and prompts for
  user verification.
- [ ] Page refresh rehydration does not prompt for passkey user verification.
- [x] Passkey post-exhaustion step-up uses single-operation budget by default.
- [ ] Email OTP post-exhaustion step-up maps refresh 401/403 to fresh OTP
  required.
- [ ] Concurrent post-exhaustion NEAR and Tempo signing either both succeed with
  separate operation reservations or one receives a typed in-flight result.

## Completion Criteria

- [x] Unlock budget and step-up budget are different policy branches.
- [ ] Step-up freshness includes wallet, operation, curve, lane identity,
  projection state, expiry, and provenance.
- [ ] No-prompt rehydration/display code cannot receive prompt-capable deps.
- [ ] Exhausted/expired sessions are represented as reauth anchors and cannot
  enter signing execution.
- [ ] Reservation records carry canonical reservation identity under
  operation-id indexes.
- [ ] Budget finalization returns typed results for projection mismatch, missing
  reservation, identity mismatch, already finalized, and unavailable status.
- [ ] Email OTP refresh 401/403 produces fresh OTP step-up state at the refresh
  boundary.
- [ ] Type fixtures reject invalid policy, prompt, admission, reservation, and
  OTP refresh states.

## Postgres Cleanup Follow-Up

- [ ] After the one-time Postgres `threshold_ecdsa_keys` legacy-row cleanup has
  been run and verified in the target environments, remove the temporary
  startup prune query in
  `server/src/core/ThresholdService/stores/KeyStore.ts` and keep strict schema
  enforcement only.

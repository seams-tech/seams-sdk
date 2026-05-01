# Signing Session Architecture

Status: active architecture summary. The deterministic transaction state-machine
plan lives in [signing-session-refactor-2.md](signing-session-refactor-2.md).

## Document Authority

1. Product intent:
   [signing-session-refresh-intent.md](signing-session-refresh-intent.md).
2. Active implementation plan:
   [signing-session-refactor-2.md](signing-session-refactor-2.md).
3. Auth and wallet-budget model:
   [signing-session-auth-and-budget.md](signing-session-auth-and-budget.md).
4. Email OTP secret and restore model:
   [email-otp-secret-restore.md](email-otp-secret-restore.md).

Legacy migration logs that conflicted with this architecture were deleted. If a
missing historical detail matters, recover it from git history and revalidate it
against this document before reintroducing it.

## Core Rule

Transaction signing is a deterministic state machine over one concrete lane.

The selected lane includes:

1. wallet id
2. auth method
3. curve
4. chain
5. wallet signing-session id
6. threshold session id
7. operation use count

Once selected, that lane is the only lane that can be restored, reauthed,
published, budget-admitted, signed, finalized, or cleaned up for the operation.

## State Machine

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

No production transaction path should skip these boundaries or recompute lane
identity after `LaneSelected`.

## Ownership

1. Snapshot readers are queries. They do not restore, prompt, consume, publish, or
   delete.
2. Lane selectors are pure functions over intent, concrete snapshot candidates,
   hard account policy, and current runtime record anchors.
3. Restore executors receive one concrete transaction lane.
4. Readiness classification describes only the selected lane.
5. The planner maps selected-lane readiness to warm session, Email OTP reauth,
   passkey reauth, or terminal failure.
6. Reauth returns a replacement concrete lane.
7. Budget admission happens before signing consumes authoritative budget.
8. Finalization receives the prepared operation and never discovers identity.

## Storage Ownership

| Store | Owns | Does Not Own |
| --- | --- | --- |
| IndexedDB sealed store | durable encrypted restore state and durable lane metadata | hot material, prompts, budget truth |
| runtime record store | current concrete runtime records | lane selection policy, budget truth |
| worker memory | hot unsealed signing material | durable identity, budget truth |
| server | authoritative validity and remaining budget | local lane selection |
| prepared operation | operation-local lane and budget identity | durable storage |
| sessionStorage | nothing required for signing-session correctness | lane identity |

## Current Migration Rule

The codebase may still contain legacy discovery-mode helpers. Do not treat those
helpers as architecture. During the refactor, remove transaction-path fallbacks as
soon as their deterministic replacement exists.

Forbidden in production transaction signing:

1. optional resolved lane ids
2. broad restore by only auth method, curve, and chain
3. auth-method probing
4. fallback to account metadata after lane selection
5. fallback to another candidate after runtime mismatch
6. post-sign budget identity preparation
7. finalization that reads mutable global session state
8. transaction selection from collapsed snapshot lanes
9. `providedSessionId` overrides that do not equal the prepared identity
10. transaction or key-export imports of maintenance restore helpers

## Supporting Specs

1. Ed25519 model:
   [stateless-shared-root-ed25519.md](stateless-shared-root-ed25519.md).
2. ECDSA model:
   [ecdsa_threshold_signing.md](ecdsa_threshold_signing.md).
3. Route auth planes:
   [auth-gating-routes.md](auth-gating-routes.md).
4. Linked OTP/passkey account policy:
   [addkey-otp-passkey-accounts.md](addkey-otp-passkey-accounts.md).

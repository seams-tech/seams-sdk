# Signing Session Coordinator Test Plan

Date created: 2026-04-24

## Objective

Track the security and edge-case test work needed to keep the chain-specific
signing session coordinators as the real transaction-signing boundary.

The coordinator must continue to:

1. Resolve or receive exactly one signing lane.
2. Read warm-session readiness without choosing policy in warm-session services.
3. Call `SigningSessionPlanner` for auth routing.
4. Drive `SigningExecutionMachine` for legal command order.
5. Delegate side effects to executors only after confirmation owns the flow.
6. Finalize budget and cleanup from the confirmed operation id plus selected lane.

## Security Test Plan

### 1. Budget Atomicity

Risk:

The client ledger protects one shared runtime instance, but cross-tab,
cross-device, and multi-runtime attempts can still race unless the authoritative
wallet signing-session budget consume path is server-side atomic.

Tests to add:

1. [x] Unit test two distinct in-process operations racing for the last
       remaining wallet signing-session use.
2. [x] Unit test two retries with the same `operationId` are deduped and consume
       at most once.
3. [ ] Integration-style test that NEAR, Tempo, and EVM all reserve before
       threshold signing and release or zero-spend on failure.
4. [ ] Server-side or relay-facing test for atomic consume when two clients
       submit distinct operations against the same last remaining use.
5. [x] Unit test that success finalization fails closed when the authoritative
       consume path is missing or returns no status.

Acceptance checks:

1. [x] Distinct operations cannot overspend in one runtime.
2. [x] Same-operation retries remain idempotent.
3. [ ] Cross-runtime atomicity is covered at the authoritative budget boundary.
4. [x] A missing or malformed success consume result does not silently count as
       a successful signature budget spend.

### 2. Stale Readiness

Risk:

A lane can be ready at planning time and expired or exhausted by the time the
signer worker needs material.

Tests to add:

1. [ ] Warm session expires after confirmation display but before PRF claim.
2. [ ] Warm session is exhausted after planner readiness but before threshold
       signing.
3. [ ] `SigningExecutionMachine` path still performs just-in-time readiness or
       claim validation before signing.
4. [x] EVM/Tempo commit queue readiness fails closed when the session expires
       while waiting in the queue.

Acceptance checks:

1. [x] Pre-confirm readiness is advisory, not final authority for signing.
2. [ ] Expired or exhausted material cannot produce a signature.
3. [ ] Failure releases or zero-spends reserved budget.

### 3. Lane-Exact Restore

Risk:

Sealed restore is safe only when it restores the exact selected lane. Any
fallback from exact lane matching to "some usable session" can sign with the
wrong auth method, wallet session, curve, chain, or retention.

Tests to add:

1. [ ] Reject restore when account id matches but wallet signing-session id
       differs.
2. [ ] Reject restore when threshold session id matches but chain/source differs.
3. [ ] Reject restore when auth method differs between Email OTP and passkey.
4. [x] Reject restore when curve differs between Ed25519 and ECDSA.
5. [ ] Reject restore when retention differs for single-use vs session-retained
       material.
6. [ ] Static guard that transaction signing never falls back from a selected
       lane to generic source search.

Acceptance checks:

1. [ ] Restore requires exact account, wallet session, threshold session, auth
       method, curve, chain/source, and retention.
2. [ ] No transaction path can restore or sign from a secondary lane.

### 4. Cleanup Idempotency

Risk:

Cleanup can race with retry, cancellation, or repeated finalization. It must be
safe to run more than once and must never revive consumed material.

Tests to add:

1. [ ] Post-sign cleanup can run twice for the same operation without throwing.
2. [ ] Single-use Email OTP cleanup is idempotent after success.
3. [ ] Cleanup failure after a successful signature does not double-spend budget
       on retry.
4. [ ] Cleanup failure is visible in trace/error reporting without leaking
       session material.

Acceptance checks:

1. [ ] Repeated cleanup does not alter budget consumption.
2. [ ] Consumed single-use material cannot be reused after cleanup retry.

### 5. Budget Release Paths

Risk:

Any failure after budget reservation can leak reserved budget or accidentally
consume budget for an unsigned operation.

Tests to add:

1. [ ] User cancels after confirmation display.
2. [ ] OTP challenge is prepared, then user cancels.
3. [ ] OTP verification fails.
4. [ ] Passkey prompt fails or is cancelled.
5. [ ] Nonce preparation fails.
6. [ ] Threshold reconnect fails.
7. [ ] Signer worker fails after reservation.
8. [ ] Broadcast fails after signature creation, with the expected budget
       semantics documented and tested.

Acceptance checks:

1. [ ] Every cancellation or failure path records exactly one zero-spend or
       release outcome.
2. [ ] Successful signature paths record exactly one success spend.

### 6. Operation Id Scope

Risk:

`operationId` dedupe is useful only when ids are scoped to the same confirmed
operation. Reusing an id across different transactions can suppress legitimate
spend.

Tests to add:

1. [ ] Same transaction retry with same operation id dedupes spend.
2. [x] Different transaction with same caller-provided operation id is rejected
       or treated according to an explicit documented policy.
3. [ ] Operation id includes enough transaction identity in trace/debug context
       to diagnose accidental reuse without leaking payload secrets.

Acceptance checks:

1. [x] Idempotency cannot mask a distinct signed operation without an explicit
       policy decision.
2. [ ] Tests cover caller-provided operation ids and internally generated ids.

### 7. Worker And PRF Failure Modes

Risk:

Worker responses can be malformed, unavailable, or race with cleanup.

Tests to add:

1. [ ] Worker returns `ok: true` with missing PRF material.
2. [ ] Worker returns unavailable status while a local record exists.
3. [ ] SecureConfirm material is cleared before signer worker receives it.
4. [ ] Signer worker times out waiting for warm material.
5. [ ] Trace output redacts session ids, PRF bytes, keys, and sealed material.

Acceptance checks:

1. [ ] Malformed worker success is treated as failure.
2. [ ] Unavailable worker status fails closed for signing.
3. [ ] No secret-bearing material appears in traces or thrown errors.

## Static Guards

Add or keep guards for these boundaries:

1. [ ] `SigningSessionPlanner` imports no storage, worker, OTP, passkey, ledger,
       or threshold provisioner modules.
2. [ ] `WarmSessionStore` imports no planner, execution machine, transaction
       confirmation, or budget ledger modules.
3. [x] Chain-facing composition stays in explicit chain-specific coordinators
       and adapters (`createEvmFamilySigningSessionCoordinator`,
       `createNearSigningSessionCoordinator`, and touch-confirm orchestration)
       rather than a single concrete `SigningSessionCoordinator.ts` file.
4. [ ] Transaction signing code cannot call generic source-less ECDSA lookup
       helpers.
5. [ ] No code path synthesizes wallet signing-session ids from threshold
       session ids.
6. [ ] No auth side effect can start before the confirmation-displayed boundary.

## Implementation Order

1. [ ] Add missing static guards first, because they catch architecture drift
       cheaply.
2. [x] Add stale-readiness and budget-release tests next, because they protect
       the highest-risk runtime failures.
3. [x] Add lane-exact sealed restore tests before expanding restore behavior.
4. [ ] Add cross-runtime/server atomic consume coverage when the authoritative
       budget endpoint is available.
5. [ ] Keep this file as the open test backlog; move completed architecture
       narrative to `docs/signing-session-architecture.md`.

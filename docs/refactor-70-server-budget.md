# Refactor 70: Server-Authoritative Wallet Session Budget

Date created: June 19, 2026

Status: in progress

Primary source of truth:

- [refactor-41.md](./refactor-41.md)
- [refactor-49-stepup-budget.md](./refactor-49-stepup-budget.md)
- [refactor-68-wallet-session-v2.md](./refactor-68-wallet-session-v2.md)
- [router-a-b-cleanup.md](./router-a-b-cleanup.md)

## Goal

Make the Router server the source of truth for Wallet Session signature-use
budget.

Wallet unlock currently mints a Wallet Session with `remainingUses=3`, which is
the existing wire/store name for server-enforced signature uses. Router A/B
transaction signing reads that server budget, then returns signatures without
decrementing it. The SDK can locally project spends, but local projection is
only a UX/concurrency hint. It must never be the policy authority.

Target invariant:

- A Wallet Session with three remaining signature uses can authorize exactly
  three successful transaction signatures across NEAR Ed25519, Tempo ECDSA-HSS,
  and EVM ECDSA-HSS.
- The fourth signing operation requires step-up auth before any Router A/B
  SigningWorker signature can be returned.
- The server consumes budget for successful signing, and the SDK only mirrors
  server state.
- Budget is shared by `walletSigningSessionId` while still bound to the exact
  curve and `thresholdSessionId` that owns the Wallet Session JWT.

## Relationship To Refactor 41 And Refactor 49

Refactor 41 is the implemented SDK budget and step-up lifecycle foundation. It
established these rules:

- Wallet unlock and post-exhaustion step-up are separate policy branches.
- The development unlock budget gives three user-facing approvals.
- Default post-exhaustion step-up is one user-facing approval for the current
  operation.
- `remainingApprovals` is the SDK/UI concept.
- `remainingSignatureUses` is the server/security concept.
- Step-up provisions enough signature uses for the approved operation.
- Budget admission captures `requiredSignatureUses`, and finalization spends
  that captured value.

Refactor 49 then made budget ownership signer-bound with:

```text
walletSigningSessionId + curve + thresholdSessionId
```

Refactor 70 preserves those decisions. The missing work is Router A/B
integration: Router A/B public signing routes must reserve and commit the
server-side signature-use budget before returning signatures.

Terminology for this plan:

- Use `remainingSignatureUses` for the conceptual server/security counter.
- Use `remainingApprovals` only for user-facing approval budget.
- Treat existing `remainingUses` fields as current wire/store compatibility
  names until the refactor-41 Phase 1B rename task is completed at the
  persistence/request boundary.

## Current Problem

Server-side Wallet Session budget already exists:

- `WalletSessionStore.getSessionStatus()`
- `WalletSessionStore.consumeUseCount()`
- `WalletSessionStore.consumeUseCountOnce()`
- `/session/signing-budget/status`
- signing-session seal paths that can consume through `consumeUseCount`

Router A/B normal signing currently treats budget status as read-only. The SDK
asks `/session/signing-budget/status`, receives the original `remainingUses`
wire field, signs, and then records a local projection. Since the server budget
is not decremented by signing, a fresh browser status read can still see the
original budget and admit more signatures.

This is why the server did not fail the fourth transaction. There was no
server-side budget consume at the Router A/B signing boundary.

## Non-Negotiable Invariants

- Server budget is authoritative.
- SDK projection is never policy authority.
- No public signing route may return a signature after budget exhaustion.
- Budget consumption must be idempotent by operation/request identity.
- Abandoned prepare requests must not permanently burn budget.
- Concurrent signing attempts must not overspend budget.
- NEAR, Tempo, and EVM share the same wallet-session budget when they share the
  same `walletSigningSessionId`.
- A Wallet Session budget remains signer-bound by `curve + thresholdSessionId`.
- Compatibility code stays at persistence/request boundaries only.

## Target Model

Introduce a server-side budget reservation lifecycle:

```ts
type WalletSigningBudgetReservation = {
  kind: 'wallet_signing_budget_reservation_v1';
  walletSigningSessionId: string;
  curve: 'ed25519' | 'ecdsa';
  thresholdSessionId: string;
  operationId: string;
  requestDigest: string;
  signatureUses: number;
  reservationId: string;
  expiresAtMs: number;
};
```

Router A/B signing flow:

```text
prepare
  -> validate Wallet Session JWT
  -> validate scope and signer binding
  -> reserve required server signature uses for walletSigningSessionId
  -> forward admitted prepare to private SigningWorker
  -> return prepare response with budgetReservationId

finalize/sign
  -> validate Wallet Session JWT
  -> validate scope, request digest, and reservation binding
  -> commit the reserved server signature uses exactly once
  -> forward admitted finalize to private SigningWorker
  -> return signature only if budget commit and SigningWorker finalization both succeed
```

The reservation protects concurrency. The commit makes successful signing
authoritative. A short reservation TTL releases abandoned prepares.

## Reservation Identity And Error Contract

Use one canonical reservation identity everywhere:

```ts
type RouterAbBudgetOperationIdentity = {
  walletSigningSessionId: string;
  curve: 'ed25519' | 'ecdsa';
  thresholdSessionId: string;
  signingWorkerId: string;
  operationId: string;
  requestDigest: string;
};
```

Definitions:

- `operationId` is the user-approved signing operation identity. It is stable
  across prepare/finalize retry for the same operation.
- `requestDigest` is the canonical digest of the final Router A/B signing
  request scope and payload. It must change if the message, signing digest,
  account, key scope, chain target, SigningWorker, or expiration changes.
- `requestId` is a transport/request replay identifier. It may be accepted as a
  compatibility input only at route boundaries, then normalized into
  `operationId` and `requestDigest`. Core budget code should not treat raw
  `requestId` as sufficient identity.
- `reservationId` is server-generated and bound to the operation identity above.
  It is returned by prepare and required by finalize.

HTTP status and error codes:

- `401 unauthorized`: missing or invalid Wallet Session JWT.
- `403 wallet_budget_forbidden`: valid auth, but the grant does not match the
  curve, threshold session, signer set, RP, relayer key, SigningWorker, or
  runtime scope.
- `409 wallet_budget_exhausted`: insufficient remaining signature uses.
- `409 wallet_budget_in_flight`: another unexpired reservation holds the needed
  signature uses.
- `409 wallet_budget_reservation_mismatch`: finalize presents a reservation
  that does not match the operation identity.
- `410 wallet_budget_reservation_expired`: finalize presents an expired
  reservation.
- `422 invalid_budget_request`: malformed request, missing reservation id,
  missing operation id, bad request digest, or invalid `signatureUses`.
- `500 wallet_budget_internal`: store or invariant failure.

Refactor 69C added an interim direct-consume guard before private SigningWorker
forwarding. Refactor 70 replaces that with prepare-time reservation plus
finalize-time commit. The direct-consume helper should be removed or reduced to
an internal compatibility shim after all public Router A/B signing routes use
reservation/commit.

Multi-signature operations:

- `signatureUses` is captured during operation planning and carried through
  prepare and finalize. It must not be recomputed from the request body after
  signing starts.
- NEAR multi-transaction signing may reserve and commit more than one signature
  use.
- ECDSA EVM and Tempo single-digest signing reserve one signature use.
- Ed25519 presign-pool hit and miss both commit the same captured signature-use
  count when a signature is returned.
- Presignature refill routes do not consume Wallet Session signing budget unless
  they return a transaction signature.

Failure and release semantics:

- Validation failure before prepare forwarding releases no reservation because
  none should exist yet.
- Prepare failure after reservation but before returning a prepare response must
  release the reservation.
- Prepare response returned to the client leaves a short-lived reservation open.
- Finalize validation failure releases the reservation only when the request
  proves ownership of the same reservation id and operation identity.
- Private SigningWorker failure before a signature is returned releases the
  reservation.
- Duplicate finalize after a successful commit is idempotent and returns the
  same budget-commit result. It must not double-consume.
- Network timeout after the server commits and returns a signature is treated as
  committed. Client retry must use the same reservation id and operation
  identity.

Backend atomicity requirements:

- InMemory: hold reservation and consume updates in one synchronous critical
  section over the map entry.
- Redis/Upstash: use Lua or an equivalent compare-and-set transaction for
  reserve, commit, release, expiry cleanup, and duplicate commit.
- Postgres: use a transaction with row locking or unique constraints for active
  reservations and idempotent commits.
- Cloudflare Durable Object: perform reservation/commit/release inside the DO
  storage turn that owns the Wallet Session budget record.
- All backends must expose the same observable behavior for duplicate prepare,
  duplicate finalize, expired reservation, in-flight reservation, and release.

## Phase 0: Complete Budget Boundary Inventory

- [x] Inventory every Wallet Session budget status read:
  - `/session/signing-budget/status`
  - SDK `SigningSessionCoordinator.prepareBudgetIdentity`
  - SDK ECDSA pre-confirm readiness
  - SDK NEAR readiness
  - key export and recovery budget checks
- [x] Inventory every existing server budget consume call:
  - signing-session seal `consumeUseCount`
  - Email OTP session policy consume paths
  - Cloudflare Durable Object wallet-session consume paths
  - Postgres/Redis/InMemory wallet-session stores
- [x] Inventory every Router A/B public signing route that must enforce budget:
  - `POST /v2/router-ab/ed25519/sign/prepare`
  - `POST /v2/router-ab/ed25519/sign/presign-pool/prepare`
  - `POST /v2/router-ab/ed25519/sign`
  - `POST /v1/hss/ecdsa/sign/prepare`
  - `POST /v1/hss/ecdsa/sign`
- [x] Mark presign-pool refill routes as non-consuming unless they return a
      transaction signature.
- [x] Reconcile the open refactor-41 Phase 1B naming tasks that affect this
      implementation:
  - server/security counters are `remainingSignatureUses`
  - current `remainingUses` wire/store fields are normalized once at the
    request/persistence boundary
  - UI copy and SDK display state use `remainingApprovals`
- [x] Confirm Router A/B admission uses `requiredSignatureUses` captured during
      operation planning and never recomputes it after signing starts.
- [x] Add the inventory results to this file.

Inventory results:

- Server status authority lives in `Ed25519WalletSessionStore.getSessionStatus`
  plus `/session/signing-budget/status`. Express and Cloudflare adapters call
  `parseWalletSigningBudgetStatusRequest`, then normalize to the public status
  response at the route boundary.
- SDK budget reads flow through
  `core/signingEngine/session/budget/budgetStatusReader.ts`,
  `BudgetCoordinator`, and `SigningSessionCoordinator.prepareBudgetIdentity`.
  ECDSA pre-confirm and NEAR readiness still carry local `remainingUses`
  signals as UX hints; Refactor 70 Phase 5 owns reducing them to mirrors.
- Existing server budget consumes are signing-session seal
  `consumeUseCount`, Email OTP session policy helpers, store-level
  `consumeUseCount`/`consumeUseCountOnce`, and the interim Router A/B
  presign-pool final-sign direct consume.
- Router A/B normal Ed25519 prepare and ECDSA-HSS prepare reserve budget in
  `routerAbPrivateSigningWorker.ts`. Normal Ed25519 and ECDSA-HSS finalize
  commit the reservation. Ed25519 presign-pool finalize remains on direct
  consume because presign-pool prepare does not yet carry the final operation
  identity.
- Presignature refill/admission routes are non-consuming unless they return a
  transaction signature. The final-sign routes own signature-use budget.
- `remainingUses` stays as the wire/store compatibility field. Internal status
  projections now expose committed, reserved, and available use counts.

Acceptance:

- Every signing-capable route has an explicit budget role:
  `reserve`, `commit`, `read-only`, or `not-applicable`.

## Phase 1: Add Server Budget Reservation Primitives

- [x] Extend `Ed25519WalletSessionStore` with reservation methods:

```ts
reserveUseCountOnce(input: {
  walletSigningSessionId: string;
  curve: 'ed25519' | 'ecdsa';
  thresholdSessionId: string;
  operationId: string;
  requestDigest: string;
  signatureUses: number;
  expiresAtMs: number;
}): Promise<WalletSessionBudgetReservationResult>;

commitReservedUseCountOnce(input: {
  walletSigningSessionId: string;
  reservationId: string;
  operationId: string;
  requestDigest: string;
}): Promise<WalletSessionConsumeUsesResult>;

releaseReservedUseCount(input: {
  walletSigningSessionId: string;
  reservationId: string;
}): Promise<WalletSessionBudgetReleaseResult>;
```

- [x] Implement reservation primitives for:
  - InMemory store
  - Redis store
  - Upstash store
  - Postgres store
  - Cloudflare Durable Object store
- [x] Reservation must decrement available budget for subsequent status reads
      without committing a permanent consume.
- [x] Commit must be idempotent for the same
      `walletSigningSessionId + operationId + requestDigest`.
- [x] Commit must reject mismatched reservation identity.
- [x] Expired reservations must be ignored and cleaned up.
- [ ] Add store-level tests for reserve, commit, release, duplicate commit,
      exhausted budget, expired reservation, and identity mismatch.

Validation added:

- `tests/unit/walletSessionBudgetReservation.store.unit.test.ts` covers the
  in-memory store reserve, duplicate reserve, in-flight rejection, commit
  idempotency, release, and visible available budget projection.
- Cross-backend behavioral tests for Redis, Upstash, Postgres, and Cloudflare
  remain open.

Acceptance:

- Two concurrent prepares against a budget of one cannot both receive committed
  signatures.
- A prepare abandoned past TTL does not permanently spend the Wallet Session.

## Phase 2: Wire Budget Reservation Into Router A/B Prepare

- [x] Add a shared server helper:

```ts
reserveRouterAbWalletSigningBudget(input: {
  walletSessionClaims: RouterAbWalletSessionClaims;
  curve: 'ed25519' | 'ecdsa';
  thresholdSessionId: string;
  walletSigningSessionId: string;
  requestDigest: string;
  operationId: string;
  signatureUses: number;
  expiresAtMs: number;
}): Promise<RouterAbBudgetReservation>;
```

- [x] Call the helper from Ed25519 normal-signing prepare routes.
- [ ] Call the helper from Ed25519 presign-pool prepare routes.
- [x] Call the helper from ECDSA-HSS normal-signing prepare routes.
- [x] Bind the reservation to:
  - Wallet Session JWT kind
  - wallet id/account id
  - `walletSigningSessionId`
  - `thresholdSessionId`
  - curve
  - SigningWorker id
  - request digest
  - operation id
  - expiry
- [x] Include `budgetReservationId` and budget status in reservation-backed
      prepare responses.
- [x] Reject prepare with a typed `wallet_budget_exhausted` error when
      insufficient signature uses remain.
- [x] Reject prepare with a typed `wallet_budget_reserved` or
      `wallet_budget_in_flight` error when the short-window budget is held by an
      active request.

Implemented scope:

- Ed25519 normal-signing prepare returns `budget_reservation_id` plus
  `budget_operation_id` and `budget_status`; finalize sends both identifiers
  back.
- ECDSA-HSS normal-signing prepare returns `budget_reservation_id`; finalize
  sends it back. The prepare response also returns `budget_status`.
- Ed25519 presign-pool signing remains on the interim direct final-sign consume
  path. The presign-pool prepare protocol does not yet carry the eventual
  transaction operation identity, so operation-bound reservation evidence must
  be added before this checkbox can be closed.
- Reservation-backed prepare responses include committed, reserved, and
  available server budget counts.

Acceptance:

- Budget exhaustion is detected before private SigningWorker prepare work.
- Prepare response carries enough budget reservation evidence for finalize to
  commit the same reservation.

## Phase 3: Commit Budget At Router A/B Finalize

- [x] Add a shared server helper:

```ts
commitRouterAbWalletSigningBudget(input: {
  walletSessionClaims: RouterAbWalletSessionClaims;
  reservationId: string;
  walletSigningSessionId: string;
  thresholdSessionId: string;
  requestDigest: string;
  operationId: string;
}): Promise<WalletSessionConsumeUsesResult>;
```

- [x] Require `budgetReservationId` on reservation-backed Router A/B
      finalize/sign request bodies.
- [x] Validate reservation identity before forwarding to the private
      SigningWorker.
- [x] Commit exactly once per successful signing request.
- [x] Return `401` or `403` with `wallet_budget_exhausted` when budget commit
      fails.
- [x] Do not return a signature when commit fails.
- [ ] Release reservation on validation failure before SigningWorker forwarding.
- [ ] Release reservation on private SigningWorker failure that occurs before a
      signature is returned.
- [x] Preserve idempotent retry behavior for repeated finalize with the same
      request digest and reservation id.

Implemented scope:

- Operation-bound Ed25519 and ECDSA-HSS normal finalize require reservation
  metadata and commit before private SigningWorker forwarding.
- Ed25519 presign-pool finalization remains on the interim direct consume path.
- Finalize private-worker failure after a successful commit is still governed by
  the existing commit-before-forward policy; release-after-private-failure needs
  a separate store state if it remains a required behavior.
- The current reservation store releases active reservations. It does not undo
  committed reservations, so the private-worker failure compensation item
  remains open.

Acceptance:

- The server returns no signature after the budget is exhausted.
- Retrying the same finalized request does not double-consume budget.
- A failed finalize does not silently burn a use unless the server already
  returned a signature.

## Phase 4: Make Budget Status Reflect Reservations And Commits

- [x] Update `/session/signing-budget/status` to include:
  - committed remaining signature uses
  - in-flight reserved signature uses
  - available signature uses
  - projection version that changes after reserve, commit, and release
- [x] Preserve signer-bound validation from the step-up budget plan.
- [x] Keep response shape compatible only at the request boundary; normalize to
      strict internal status immediately.
- [x] Add server route tests for active, exhausted, in-flight reserved, expired,
      and unauthorized status.

Implemented scope:

- `/session/signing-budget/status` now returns `committedRemainingUses`,
  `reservedUses`, `availableUses`, compatibility `remainingUses`, and a
  projection version derived from the server budget projection.
- Express and Cloudflare adapters share the strict parser projection shape.
- Focused route coverage proves active in-flight projection, exhausted
  projection, expired Wallet Session claims, and unauthorized/not-found
  responses for both adapters.

Acceptance:

- SDK reads a server status that reflects active Router A/B prepares before
  finalize.

## Phase 5: Simplify SDK Budget Authority

- [ ] Keep SDK `BudgetCoordinator` projection only as an optimistic local mirror.
- [ ] Remove any code path that treats IndexedDB `remainingUses` as authoritative
      for Router A/B signing.
- [ ] Ensure `prepareBudgetIdentity` always uses server-trusted status when a
      Wallet Session JWT is available.
- [ ] Ensure local completed-spend projection does not double-subtract after the
      server projection version changes.
- [ ] Map server `wallet_budget_exhausted` and `wallet_budget_in_flight` into
      the existing step-up auth planner.
- [ ] Add SDK tests showing:
  - fourth sign after three committed server spends triggers step-up
  - local stale records with `remainingUses=3` cannot override exhausted server
    status
  - in-flight server reservation blocks over-budget concurrent signing
  - one step-up approval can mint multiple signature uses for a multi-transaction
    NEAR request

Acceptance:

- The SDK cannot sign past server-authoritative budget by refreshing or
  re-reading local records.

## Phase 6: Browser And Local Runtime Evidence

- [ ] Add a local harness that unlocks once, then signs:
  - NEAR
  - Tempo
  - EVM
  - a fourth operation that must show step-up auth
- [ ] Capture server logs proving server budget status changes:
  - `remainingSignatureUses=3` or current wire field `remainingUses=3`
  - `remainingSignatureUses=2` or current wire field `remainingUses=2`
  - `remainingSignatureUses=1` or current wire field `remainingUses=1`
  - `remainingSignatureUses=0` or current wire field `remainingUses=0`
  - fourth request rejected or step-up minted a new Wallet Session
- [ ] Verify no TouchID prompt appears before budget exhaustion.
- [ ] Verify exactly one step-up auth appears after budget exhaustion.
- [ ] Verify a new Wallet Session after step-up resets the shared budget.

Acceptance:

- Manual browser behavior matches the intended UX:
  three silent signs after unlock, then one step-up auth, then signing resumes.

## Phase 7: Cloudflare Strict Parity

- [ ] Port the same budget reservation/commit lifecycle to Cloudflare strict
      worker bindings.
- [ ] Ensure Durable Object budget store supports reservation, commit, release,
      duplicate finalize, and expiry cleanup.
- [ ] Verify Cloudflare SigningWorker private routes never receive finalize
      requests whose budget cannot commit.
- [ ] Add `router:deploy:check` guard coverage for budget enforcement hooks on:
  - Ed25519 prepare/finalize
  - Ed25519 presign-pool prepare/finalize
  - ECDSA-HSS prepare/finalize
- [ ] Add strict browser evidence after deployment setup is ready.

Acceptance:

- Local and Cloudflare deployments enforce the same server-authoritative budget
  semantics.

## Phase 8: Delete Client-Only Budget Authority

- [ ] Remove any local-client-only logic that was needed only because the server
      did not consume signing budget.
- [ ] Keep local projection only for:
  - optimistic UI
  - in-flight operation dedupe
  - avoiding duplicate prompts while a server request is pending
- [ ] Add source guards rejecting:
  - direct Router A/B sign-ready decisions from raw persisted `remainingUses`
  - signing success paths that do not call server budget commit
  - new public signing routes without budget reservation and commit
- [ ] Update docs that describe SDK-local budget as the authority.

Acceptance:

- Budget policy is owned by the Router server. SDK logic mirrors it, and tests
  fail if a signing path bypasses server consume.

## Required Tests

- Unit: store reservation/commit/release for every backend.
- Unit: budget status includes reservations and committed consumes.
- Unit: Router A/B Ed25519 prepare rejects exhausted budget.
- Unit: Router A/B Ed25519 finalize rejects missing or mismatched reservation.
- Unit: Router A/B ECDSA-HSS prepare rejects exhausted budget.
- Unit: Router A/B ECDSA-HSS finalize rejects missing or mismatched reservation.
- Unit: duplicate finalize is idempotent.
- Integration: NEAR + Tempo + EVM share a single `walletSigningSessionId`
  budget.
- Integration: refactor-41 unlock policy gives three approvals and
  post-exhaustion step-up gives one approval with captured
  `requiredSignatureUses`.
- Integration: a multi-transaction NEAR step-up provisions and spends the
  captured signature-use count.
- Integration: refactor-49 signer-bound identity still blocks cross-curve and
  cross-threshold-session budget stealing.
- Integration: fourth signing operation requires step-up.
- Guard: every Router A/B public signing route has budget reservation/commit
  coverage.

## Completion Criteria

- Server state decrements on successful Router A/B transaction signing.
- A stale browser cannot sign past server budget exhaustion.
- Concurrent signing attempts cannot overspend the Wallet Session.
- The SDK still provides responsive local UX, but server status is the final
  authority.
- Local browser testing shows exactly three post-unlock signs before step-up.
- Cloudflare strict deployment has the same budget semantics before release.

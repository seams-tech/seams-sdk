# Refactor 70: Server-Authoritative Wallet Session Budget

Date created: June 19, 2026

Status: in progress

Primary source of truth:

- [refactor-41.md](./refactor-41.md)
- [refactor-49-stepup-budget.md](./refactor-49-stepup-budget.md)
- [refactor-68-wallet-session-v2.md](./refactor-68-wallet-session-v2.md)
- [router-a-b-cleanup.md](./router-a-b-cleanup.md)

## Current Task Board

Refactor 70 owns server-authoritative signing-session budget and post-exhaustion
step-up behavior. It does not own worker-material restore/readiness; those tasks
are tracked in `router-a-b-cleanup.md` Phase 15.9 through Phase 15.12 and
`refactor-74-login-no-hss.md`.

- [x] Inventory existing Wallet Session budget reads, consumes, and Router A/B
      signing routes.
- [x] Add server budget reservation primitives and backend tests.
- [x] Reserve budget at Router A/B prepare/admission boundaries.
- [x] Commit budget only after successful Router A/B signing finalization.
- [x] Make budget status reflect committed, reserved, and available uses.
- [x] Reduce SDK budget logic to a mirror of server authority.
- [x] Add local evidence harness for the shared budget flow.
- [x] Port strict reserve/commit/release lifecycle to Cloudflare strict Router.
- [x] Rebuild SDK dist and run the opt-in local evidence harness once against the
      local Router stack.
- [x] Record the current local evidence blocker explicitly instead of treating it
      as budget evidence.
- [x] Unblock the code-side Ed25519 worker-material readiness prerequisite owned by
      `refactor-74-login-no-hss.md`.
- [x] Rerun the Refactor 70 evidence harness against the live local Router stack.
- [x] Capture local evidence for shared budget `3 -> 2 -> 1 -> 0`.
- [x] Verify no TouchID prompt appears before budget exhaustion.
- [x] Verify exactly one step-up auth appears after budget exhaustion.
- [x] Verify the step-up mint creates a new Wallet Session grant/counter.

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
- Budget is shared by `signingGrantId` while still bound to the exact
  curve and `thresholdSessionId` that owns the Wallet Session JWT.

Shared-budget interpretation:

- `signingGrantId` owns one server counter for the Wallet Session.
- Every spend still carries `curve + thresholdSessionId + signingWorkerId` in the
  reservation identity, so a request cannot spend budget through a signer lane
  that the Wallet Session JWT did not authorize.
- Refactor 49's signer-bound isolation is enforced at validation time. It does
  not create separate three-use counters for Ed25519, Tempo, and EVM when they
  share one Wallet Session grant.
- A step-up auth mint creates a new grant/counter for the approved operation
  scope. It does not refill the exhausted grant in place.

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
- NEAR Ed25519 transaction signing uses exactly one signature use. A single NEAR
  transaction may still contain multiple actions.

Refactor 49 then made budget ownership signer-bound with:

```text
signingGrantId + curve + thresholdSessionId
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

## Original Problem

Server-side Wallet Session budget already exists:

- `WalletSessionStore.getSessionStatus()`
- `WalletSessionStore.consumeUseCount()`
- `WalletSessionStore.consumeUseCountOnce()`
- `/router-ab/wallet-budget/status`
- signing-session seal paths that can consume through `consumeUseCount`

Router A/B normal signing treated budget status as read-only. The SDK
asks `/router-ab/wallet-budget/status`, receives the original `remainingUses`
wire field, signs, and then records a local projection. Since the server budget
was not decremented by signing, a fresh browser status read could still see the
original budget and admit more signatures.

This was why the server did not fail the fourth transaction. There was no
server-side budget consume at the Router A/B signing boundary.

Current implementation status: Router A/B normal-signing routes now use server
reservation and commit in both local Router code and strict Cloudflare route
handlers. Local/browser evidence and deployed Cloudflare evidence remain open
release gates.

## Non-Negotiable Invariants

- Server budget is authoritative.
- SDK projection is never policy authority.
- No public signing route may return a signature after budget exhaustion.
- Budget consumption must be idempotent by operation identity plus request
  digest.
- Abandoned prepare requests must not permanently burn budget.
- Concurrent signing attempts must not overspend budget.
- NEAR, Tempo, and EVM share the same wallet-session budget when they share the
  same `signingGrantId`.
- A Wallet Session budget remains signer-bound by `curve + thresholdSessionId`.
- Compatibility code stays at persistence/request boundaries only.

## Target Model

Introduce a server-side budget reservation lifecycle:

```ts
type WalletSigningBudgetReservation = {
  kind: 'wallet_signing_budget_reservation_v1';
  signingGrantId: string;
  curve: 'ed25519' | 'ecdsa';
  thresholdSessionId: string;
  signingWorkerId: string;
  operationId: string;
  requestDigest: string;
  signatureUses: number;
  reservationId: string;
  expiresAtMs: number;
};
```

Wallet Session grant lifecycle:

```text
wallet unlock / registration / step-up
  -> mint Wallet Session JWT with signingGrantId
  -> create or replace server budget record for signingGrantId
  -> initial remaining signature uses come from the issuance policy
  -> signing routes can reserve only after that record exists
```

Router A/B signing flow:

```text
prepare
  -> validate Wallet Session JWT
  -> validate scope and signer binding
  -> reserve required server signature uses for signingGrantId
  -> forward admitted prepare to private SigningWorker
  -> return prepare response with budgetReservationId

finalize/sign
  -> validate Wallet Session JWT
  -> validate scope, request digest, and reservation binding
  -> forward admitted finalize to private SigningWorker
  -> release the active reservation if private SigningWorker finalization fails
  -> commit the reserved server signature uses exactly once
  -> return signature only if SigningWorker finalization and budget commit both succeed
```

The reservation protects concurrency and blocks exhausted Wallet Sessions before
private SigningWorker work. The commit makes returned signatures authoritative. A
short reservation TTL releases abandoned prepares.

Reservation TTL:

- Budget reservation expiry is a short server TTL, independent from the
  cryptographic request expiry.
- Default TTL: `10_000ms`.
- Effective expiry:

```text
min(request.expires_at_ms, wallet_session.expires_at_ms, now_unix_ms + 10_000)
```

- The request's cryptographic expiry still binds the signed protocol request.
  The budget TTL only bounds in-flight quota pressure and abandoned prepares.

## Reservation Identity And Error Contract

Use one canonical reservation identity everywhere:

```ts
type RouterAbBudgetOperationIdentity = {
  signingGrantId: string;
  curve: 'ed25519' | 'ecdsa';
  thresholdSessionId: string;
  signingWorkerId: string;
  operationId: string;
  requestDigest: string;
};
```

Definitions:

- `curve` has one canonical external value set: `ed25519 | ecdsa`. Rust may use
  an internal `EcdsaHss` enum variant for precision, but storage JSON,
  telemetry, public responses, and cross-language tests must serialize that
  branch as `ecdsa`. Do not introduce `ecdsa_hss`, `ecdsa-hss`, or `EcdsaHss`
  as external budget identity strings.
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
forwarding. Refactor 70 replaces that with reservation plus finalize-time commit.
The direct-consume helper is deleted from active Router A/B signing routes.

Signature-use rules:

- NEAR Ed25519 transaction signing reserves and commits one signature use.
- ECDSA EVM and Tempo single-digest signing reserve one signature use.
- Ed25519 presign-pool hit and miss both commit one signature use when a
  signature is returned.
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

Missing budget records:

- A valid Wallet Session JWT whose `signingGrantId` has no server budget record
  is not signable.
- Route result: `403 wallet_budget_forbidden`.
- The SDK must treat that as a step-up/repair boundary, not as an exhausted
  budget retry.

## Phase 0: Complete Budget Boundary Inventory

- [x] Inventory every Wallet Session budget status read:
  - `/router-ab/wallet-budget/status`
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
  - `POST /router-ab/ed25519/sign/prepare`
  - `POST /router-ab/ed25519/sign/presign-pool/prepare`
  - `POST /router-ab/ed25519/sign`
  - `POST /router-ab/ecdsa-hss/sign/prepare`
  - `POST /router-ab/ecdsa-hss/sign`
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
  plus `/router-ab/wallet-budget/status`. Express and Cloudflare adapters call
  `parseWalletSigningBudgetStatusRequest`, then normalize to the public status
  response at the route boundary.
- SDK budget reads flow through
  `core/signingEngine/session/budget/budgetStatusReader.ts`,
  `BudgetCoordinator`, and `SigningSessionCoordinator.prepareBudgetIdentity`.
  ECDSA pre-confirm and NEAR readiness still carry local `remainingUses`
  signals as UX hints; Refactor 70 Phase 5 owns reducing them to mirrors.
- Existing server budget consumes outside Router A/B normal signing are
  signing-session seal `consumeUseCount`, Email OTP session policy helpers, and
  store-level `consumeUseCount` / `consumeUseCountOnce`.
- Router A/B normal Ed25519 prepare and ECDSA-HSS prepare reserve budget in
  `routerAbPrivateSigningWorker.ts`. Normal Ed25519 and ECDSA-HSS finalize
  commit the reservation after private SigningWorker success and before returning
  a signature. Ed25519 presign-pool finalize now reserves and commits by
  `operationId + requestDigest` from the final signing request, while
  presign-pool refill prepare stays non-consuming.
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
  signingGrantId: string;
  curve: 'ed25519' | 'ecdsa';
  thresholdSessionId: string;
  signingWorkerId: string;
  operationId: string;
  requestDigest: string;
  signatureUses: number;
  expiresAtMs: number;
}): Promise<WalletSessionBudgetReservationResult>;

commitReservedUseCountOnce(input: {
  signingGrantId: string;
  reservationId: string;
  signingWorkerId: string;
  operationId: string;
  requestDigest: string;
}): Promise<WalletSessionConsumeUsesResult>;

validateReservedUseCount(input: {
  signingGrantId: string;
  reservationId: string;
  signingWorkerId: string;
  operationId: string;
  requestDigest: string;
}): Promise<WalletSessionConsumeUsesResult>;

releaseReservedUseCount(input: {
  signingGrantId: string;
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
      `signingGrantId + signingWorkerId + operationId + requestDigest`.
- [x] Commit must reject mismatched reservation identity.
- [x] Validate must reject mismatched or expired reservation identity before
      private SigningWorker forwarding.
- [x] Expired reservations must be ignored and cleaned up.
- [x] Add in-memory store-level tests for reserve, commit, release, duplicate
      commit, exhausted budget, expired reservation, and identity mismatch.
- [x] Add cross-backend reservation behavior tests for Cloudflare Durable Object
      stores locally, with Redis, Upstash, and Postgres variants enabled when
      their environment URLs/tokens are configured.

Validation added:

- `tests/unit/walletSessionBudgetReservation.store.unit.test.ts` covers the
  in-memory store reserve, duplicate reserve, in-flight rejection, commit
  idempotency, release, exhausted reserve, expired reservation, reservation
  identity mismatch, SigningWorker mismatch, and visible available budget
  projection.
- The same contract now rejects reserve-after-commit for the same
  `signingWorkerId + operationId + requestDigest`, while duplicate commit by
  reservation id remains idempotent.
- `tests/unit/walletSessionBudgetReservation.store.unit.test.ts` also proves a
  Wallet Session with three committed signature-use spends rejects the fourth
  reserve with `wallet_budget_exhausted`.
- Cross-backend behavioral contract coverage now runs against in-memory and
  Cloudflare Durable Object stores locally. Redis, Upstash, and Postgres variants
  run when `REDIS_URL`, `UPSTASH_REDIS_REST_URL` / `UPSTASH_REDIS_REST_TOKEN`,
  or `POSTGRES_URL` are configured.

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
  signingWorkerId: string;
  signingGrantId: string;
  requestDigest: string;
  operationId: string;
  signatureUses: number;
  expiresAtMs: number;
}): Promise<RouterAbBudgetReservation>;
```

- [x] Call the helper from Ed25519 normal-signing prepare routes.
- [x] Call the helper from Ed25519 presign-pool final-sign routes.
- [x] Call the helper from ECDSA-HSS normal-signing prepare routes.
- [x] Bind the reservation to:
  - Wallet Session JWT kind
  - wallet id/account id
  - `signingGrantId`
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
- ECDSA-HSS normal-signing prepare returns `budget_reservation_id`,
  canonical `budget_operation_id`, and `budget_status`; finalize sends the
  reservation id and canonical operation id back.
- ECDSA-HSS `budget_operation_id` is derived from active SigningWorker state,
  threshold session id, key scope, activation epoch, public identity,
  presignature id, expiry, and signing digest. It deliberately excludes the
  transport `request_id`.
- Ed25519 presign-pool signing reserves and commits by the final signing
  request's operation identity. The presign-pool refill prepare route stays
  non-consuming because it does not return a transaction signature.
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
  signingGrantId: string;
  thresholdSessionId: string;
  signingWorkerId: string;
  requestDigest: string;
  operationId: string;
}): Promise<WalletSessionConsumeUsesResult>;
```

- [x] Require `budgetReservationId` on reservation-backed Router A/B
      finalize/sign request bodies.
- [x] Validate reservation identity before returning the private SigningWorker
      signature.
- [x] Commit exactly once per successful signing request.
- [x] Return `409` with `wallet_budget_exhausted` when budget validation or
      commit fails because remaining signature uses are insufficient.
- [x] Do not return a signature when commit fails.
- [x] Validate reservation identity and liveness before private SigningWorker
      forwarding.
- [x] Release reservation on validation failure before SigningWorker forwarding
      only when the request proves ownership of the same reservation identity.
- [x] Release reservation on private SigningWorker failure that occurs before a
      signature is returned.
- [x] Preserve idempotent retry behavior for repeated finalize with the same
      request digest and reservation id.

Implemented scope:

- Operation-bound Ed25519 and ECDSA-HSS normal finalize require reservation
  metadata, validate the reservation before private SigningWorker forwarding,
  release the active reservation on private SigningWorker failure, and commit
  before returning the signature.
- Budget reservation identity now includes the SigningWorker id. Cross-worker
  validation and commit attempts fail with `wallet_budget_reservation_mismatch`.
- ECDSA-HSS budget `requestDigest` uses the canonical Router A/B request digest,
  not the ECDSA signing digest alone.
- ECDSA-HSS budget `operationId` uses the canonical `budget_operation_id`
  returned by prepare. Finalize rejects transport `request_id` or any other
  non-canonical value with `wallet_budget_reservation_mismatch` before private
  SigningWorker forwarding.
- Ed25519 presign-pool finalization now uses the reservation store. It reserves
  by operation id and canonical Router A/B request digest, releases on private
  SigningWorker failure, then commits before returning the signature.
- Normal Ed25519 and ECDSA-HSS prepare failures release active reservations
  after private SigningWorker prepare failure.

Validation added:

- `tests/unit/routerAbEd25519BudgetRouteCore.unit.test.ts` proves
  presign-pool finalization rejects exhausted budget before private SigningWorker
  forwarding and normal prepare private-worker failure releases the active
  reservation with `phase: "prepare"`.
- `tests/unit/routerAbEd25519BudgetRouteCore.unit.test.ts` also proves normal
  Ed25519 prepare rejects an exhausted server budget before private
  SigningWorker forwarding.
- `tests/unit/routerAbEd25519BudgetRouteCore.unit.test.ts` proves presign-pool
  hit finalization reserves and commits canonical `operationId + requestDigest`
  budget identity, and normal finalize private-worker failure releases the
  active reservation without committing budget.
- `tests/unit/routerAbEd25519BudgetRouteCore.unit.test.ts` proves normal
  Ed25519 finalize validates an existing reservation before private
  SigningWorker forwarding, releases the reservation by exact identity when
  validation fails, and does not forward the failed request to the private
  SigningWorker.
- `tests/unit/routerAbEd25519BudgetRouteCore.unit.test.ts` proves normal
  Ed25519 prepare and finalize share the same canonical budget request digest,
  and that changing request expiry changes the digest.
- `tests/unit/routerAbEcdsaHssBudgetRouteCore.unit.test.ts` proves ECDSA-HSS
  prepare rejects exhausted budget before private SigningWorker forwarding,
  ECDSA-HSS finalize validates an existing reservation before private
  SigningWorker forwarding, releases the reservation by exact identity when
  validation fails, and private-worker finalize failure releases the active
  reservation without committing budget.
- `tests/unit/routerAbEcdsaHssBudgetRouteCore.unit.test.ts` proves ECDSA-HSS
  finalize rejects a transport `request_id` masquerading as
  `budget_operation_id` before budget validation, commit, release, or private
  SigningWorker forwarding.

Acceptance:

- The server returns no signature after the budget is exhausted.
- Retrying the same finalized request does not double-consume budget.
- A failed finalize does not silently burn a use unless the server already
  returned a signature.

## Phase 4: Make Budget Status Reflect Reservations And Commits

- [x] Update `/router-ab/wallet-budget/status` to include:
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

- `/router-ab/wallet-budget/status` now returns `committedRemainingUses`,
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

- [x] Keep SDK `BudgetCoordinator` projection only as an optimistic local mirror.
- [x] Remove any code path that treats IndexedDB `remainingUses` as authoritative
      for Router A/B signing.
- [x] Ensure `prepareBudgetIdentity` always uses server-trusted status when a
      Wallet Session JWT is available.
- [x] Ensure local completed-spend projection does not double-subtract after the
      server projection version changes.
- [x] Treat Router A/B Ed25519 and ECDSA-HSS successful signing as
      server-consumed budget when updating SDK projection state.
- [x] Map server `wallet_budget_exhausted` and `wallet_budget_in_flight` into
      the existing step-up auth planner.
- [x] Add SDK tests showing:
  - [x] fourth sign after three committed server spends triggers step-up
  - [x] local stale records with `remainingUses=3` cannot override exhausted server
    status
  - [x] in-flight server reservation blocks over-budget concurrent signing
  - [x] NEAR rejects multi-transaction signing before budget admission
  - [x] NEAR exposes only `signAndSendTransaction`; the plural
    `signAndSendTransactions` public method and iframe RPC were deleted.
  - [x] NEAR sign-only public/iframe APIs are singular
    `signTransactionWithActions` / `PM_SIGN_TX_WITH_ACTIONS` and accept one
    transaction.

Implemented scope:

- SDK admission now treats server `availableUses` as the available signing
  budget when present, so server-side in-flight reservations cannot be masked by
  a stale positive `remainingUses` projection.
- The active trusted budget projection type now requires `availableUses`, and
  `trustedStatusProjectionState` uses that server field as the active signing
  authority. Compatibility `remainingUses` remains available for display and
  boundary normalization only.
- `tests/unit/evmFamilyBudgetSpending.unit.test.ts` proves the SDK rejects the
  fourth signing admission after three committed server spends by surfacing
  `SIGNING_SESSION_BUDGET_EXHAUSTED_ERROR`, which feeds the existing step-up
  auth planner.
- Local completed-spend projections only subtract while the server projection
  version still matches the projection that admitted the spend. Once the server
  status advances, the SDK uses the server projection directly.
- Existing multi-use coordinator coverage proves one admitted operation can
  reserve and record multiple signature uses. Browser step-up evidence remains
  open in Phase 6.
- Router A/B RPC clients now map server `wallet_budget_exhausted`,
  `wallet_budget_in_flight`, and `wallet_budget_reserved` responses into the
  SDK signing-session budget domain errors used by NEAR and ECDSA fresh-auth
  retry planning.

Validation added:

- `tests/unit/signingSessionBudgetFinalizer.unit.test.ts` covers server
  in-flight availability, exhausted trusted server status, stale local projection
  rejection, and projection-version advancement.
- `tests/unit/evmFamilyBudgetSpending.unit.test.ts` covers
  `prepareBudgetIdentity` rejecting server in-flight budget.
- `tests/unit/routerAbNormalSigningValidation.unit.test.ts` covers Router A/B
  server budget error mapping at the RPC boundary.
- `tests/unit/evmFamilyFreshAuthRetryPolicy.unit.test.ts` covers ECDSA
  fresh-auth retry admission for in-flight server budget errors.

Acceptance:

- The SDK cannot sign past server-authoritative budget by refreshing or
  re-reading local records.

## Phase 6: Browser And Local Runtime Evidence

- [x] Add a local harness that unlocks once, then signs:
  - [x] NEAR
  - [x] Tempo
  - [x] EVM
  - [x] a fourth operation that must show step-up auth
- [x] Capture local evidence snapshots or server logs proving server budget
      status changes:
  - `remainingSignatureUses=3` or current wire field `remainingUses=3`
  - `remainingSignatureUses=2` or current wire field `remainingUses=2`
  - `remainingSignatureUses=1` or current wire field `remainingUses=1`
  - `remainingSignatureUses=0` or current wire field `remainingUses=0`
  - fourth request rejected or step-up minted a new Wallet Session
- [x] Verify no TouchID prompt appears before budget exhaustion.
- [x] Verify exactly one step-up auth appears after budget exhaustion.
- [x] Verify a new Wallet Session after step-up resets the shared budget.

Acceptance:

- Manual browser behavior matches the intended UX:
  three silent signs after unlock, then one step-up auth, then signing resumes.

Implemented scope:

- `tests/e2e/routerAb.serverBudgetEvidence.walletIframe.test.ts` is an opt-in
  local evidence harness gated by `RUN_ROUTER_AB_BUDGET_EVIDENCE=1`. It
  registers and unlocks once, signs NEAR, Tempo, and EVM without additional
  WebAuthn gets, then performs a fourth sign and asserts exactly one step-up
  WebAuthn get. It hard-asserts setup `remainingUses=3`, then NEAR `2`,
  Tempo `1`, EVM `0`, and a new `signingGrantId` on the fourth sign. It also
  records per-stage Wallet Session status snapshots for the local evidence pass
  and attaches them as
  `router-ab-server-budget-evidence.json` in the Playwright report.
- Run it against a live local Router stack with:
  `RUN_ROUTER_AB_BUDGET_EVIDENCE=1 pnpm -C tests exec playwright test --reporter=line e2e/routerAb.serverBudgetEvidence.walletIframe.test.ts`.

Current evidence status:

- June 20, 2026: local Router evidence passed after rebuilding SDK dist and
  running:
  `RUN_ROUTER_AB_BUDGET_EVIDENCE=1 pnpm -C tests exec playwright test --reporter=line e2e/routerAb.serverBudgetEvidence.walletIframe.test.ts`.
- The harness now hard-asserts shared budget transitions `3 -> 2 -> 1 -> 0`,
  no WebAuthn get before exhaustion, exactly one WebAuthn get on the fourth
  sign, and a new Wallet Session `signingGrantId` after exhaustion.
- Deployed Cloudflare browser evidence remains open until deployment setup is
  ready.

## Phase 7: Cloudflare Strict Parity

- [x] Port the same budget reservation/commit lifecycle to Cloudflare strict
      worker bindings.
- [x] Ensure Durable Object budget store supports reservation, commit, release,
      duplicate finalize, and expiry cleanup.
- [x] Add strict Cloudflare Wallet Session claim/model binding for
      `signingGrantId`, so budget identity can be
      `signingGrantId + curve + thresholdSessionId`.
- [x] Fail closed in strict Cloudflare public signing routes until real
      Wallet Session budget reservation/commit is wired.
- [x] Verify current strict Cloudflare SigningWorker private routes cannot receive
      requests whose budget cannot commit.
- [x] Add `router:deploy:check` guard coverage for budget enforcement hooks on:
  - Ed25519 prepare/finalize
  - Ed25519 presign-pool prepare/finalize
  - ECDSA-HSS prepare/finalize
- [x] Replace the fail-closed strict Cloudflare budget guard with real
      reserve/commit/release calls.

Implemented scope:

- Strict Cloudflare Router owns a `RouterWalletBudget` Durable Object binding
  and validates that only the Router role can access it.
- Ed25519 prepare and ECDSA-HSS prepare reserve one server signature use before
  private SigningWorker forwarding and release the reservation on private
  prepare failure.
- Ed25519 normal finalize and ECDSA-HSS finalize require
  `budget_reservation_id + budget_operation_id`, validate the reservation before
  private SigningWorker forwarding, release on private finalize failure, and
  commit before returning the signature.
- Ed25519 presign-pool prepare reads budget status without reserving because it
  does not return a transaction signature.
- Ed25519 pool-hit finalize reserves and commits in the same public request.
- Strict Wrangler Router config declares the Wallet Budget DO class, binding,
  migration, and env vars for base, staging, and production.
- `router:deploy:check` guard coverage now fails if a strict public signing
  route can forward without the expected budget helper, if the fail-closed marker
  returns, or if the Wallet Budget DO config is missing.

Open Cloudflare strict work:

- Wire `PutGrant` at the strict Cloudflare Wallet Session grant issuance or
  grant-acceptance boundary. The DO operation exists, but no strict Cloudflare
  issuer path currently initializes a grant before signing routes read it.
- Add strict Cloudflare status-route parity if strict Cloudflare becomes the
  browser-facing Wallet Session Router for `/router-ab/wallet-budget/status`.
- Prove private SigningWorker finalize replay is idempotent by request identity,
  or add a Router-owned pending worker-success result store before deployment.
  Without that, a private finalize success followed by budget commit failure may
  leave the client unable to retry because one-use nonce or presignature material
  has already been consumed.

### Phase 7.1: Strict Cloudflare Budget Lifecycle Spec

This phase fills the implementation gap for the real strict Cloudflare
reserve/commit/release lifecycle. The fail-closed guard has been removed after
the strict route handlers were wired to Wallet Budget DO reserve, validate,
commit, release, and status operations.

#### Strict Bindings

Add one Router-owned Durable Object binding for Wallet Session budget state:

```rust
pub const ROUTER_WALLET_BUDGET_DO_BINDING_ENV: &str =
    "ROUTER_WALLET_BUDGET_DO_BINDING";
pub const ROUTER_WALLET_BUDGET_DO_OBJECT_ENV: &str =
    "ROUTER_WALLET_BUDGET_DO_OBJECT";
pub const ROUTER_WALLET_BUDGET_DO_KEY_PREFIX_ENV: &str =
    "ROUTER_WALLET_BUDGET_DO_KEY_PREFIX";
```

Add a new strict storage scope and operation family:

```rust
CloudflareDurableObjectScopeV1::RouterWalletBudget

CloudflareDurableObjectOperationKindV1::RouterWalletBudgetReserve
CloudflareDurableObjectOperationKindV1::RouterWalletBudgetValidate
CloudflareDurableObjectOperationKindV1::RouterWalletBudgetCommit
CloudflareDurableObjectOperationKindV1::RouterWalletBudgetRelease
CloudflareDurableObjectOperationKindV1::RouterWalletBudgetStatus
CloudflareDurableObjectOperationKindV1::RouterWalletBudgetPutGrant
```

Extend `CloudflareRouterBindingsV1` with:

```rust
pub wallet_budget: CloudflareDurableObjectBindingV1
```

Validation rules:

- The binding scope must be `RouterWalletBudget`.
- Only the Router Worker may access it.
- The key prefix must be non-empty and environment-scoped.
- Strict Wrangler config must bind the Durable Object and env vars before deploy.
- Signer A, Signer B, and SigningWorker must not receive this binding.

#### Strict DO Request And Response Types

Add a Router-owned budget request enum:

```rust
pub enum CloudflareRouterWalletBudgetRequestV1 {
    PutGrant(CloudflareRouterWalletBudgetPutGrantRequestV1),
    Reserve(CloudflareRouterWalletBudgetReserveRequestV1),
    Validate(CloudflareRouterWalletBudgetValidateRequestV1),
    Commit(CloudflareRouterWalletBudgetCommitRequestV1),
    Release(CloudflareRouterWalletBudgetReleaseRequestV1),
    Status(CloudflareRouterWalletBudgetStatusRequestV1),
}
```

`PutGrant` input:

```rust
pub struct CloudflareRouterWalletBudgetPutGrantRequestV1 {
    pub signing_grant_id: String,
    pub wallet_id: String,
    pub rp_id: String,
    pub authorized_signers: Vec<CloudflareRouterWalletBudgetSignerBindingV1>,
    pub initial_signature_uses: u32,
    pub expires_at_ms: u64,
    pub issuer_jwt_id: String,
    pub now_unix_ms: u64,
}

pub struct CloudflareRouterWalletBudgetSignerBindingV1 {
    pub curve: CloudflareRouterWalletBudgetCurveV1,
    pub threshold_session_id: String,
    pub signing_worker_id: String,
}
```

`PutGrant` rules:

- It is called by the same strict Router boundary that mints or accepts a new
  Wallet Session grant.
- It creates a fresh server-authoritative budget record for
  `signing_grant_id`.
- Reusing a `signing_grant_id` with a different `issuer_jwt_id`,
  `wallet_id`, `rp_id`, signer binding set, expiry, or initial budget is a
  conflict.
- Replaying the same `PutGrant` is idempotent.
- Step-up auth mints a new `signing_grant_id`; it does not mutate an exhausted
  prior grant.
- If strict Cloudflare accepts a Wallet Session JWT that was minted by another
  Router boundary, that issuer must call a Router-owned budget initialization
  endpoint before the JWT can be used for signing. A JWT with a valid
  `signingGrantId` but no matching budget record remains non-signable.
- The budget initialization endpoint is service-authenticated and Router-owned;
  it is not a browser public endpoint.

`Reserve` input:

```rust
pub struct CloudflareRouterWalletBudgetReserveRequestV1 {
    pub signing_grant_id: String,
    pub curve: CloudflareRouterWalletBudgetCurveV1, // external JSON: ed25519 | ecdsa
    pub threshold_session_id: String,
    pub signing_worker_id: String,
    pub operation_id: String,
    pub request_digest: PublicDigest32,
    pub signature_uses: u32,
    pub expires_at_ms: u64,
    pub now_unix_ms: u64,
}
```

`Validate` and `Commit` input:

```rust
pub struct CloudflareRouterWalletBudgetReservationIdentityV1 {
    pub signing_grant_id: String,
    pub reservation_id: String,
    pub signing_worker_id: String,
    pub operation_id: String,
    pub request_digest: PublicDigest32,
    pub now_unix_ms: u64,
}
```

`Release` input:

```rust
pub struct CloudflareRouterWalletBudgetReleaseRequestV1 {
    pub signing_grant_id: String,
    pub reservation_id: String,
    pub now_unix_ms: u64,
}
```

Responses:

```rust
pub enum CloudflareRouterWalletBudgetResponseV1 {
    GrantPut(CloudflareRouterWalletBudgetGrantPutV1),
    Reserved(CloudflareRouterWalletBudgetReservedV1),
    Validated(CloudflareRouterWalletBudgetValidatedV1),
    Committed(CloudflareRouterWalletBudgetCommittedV1),
    Released(CloudflareRouterWalletBudgetReleasedV1),
    Status(CloudflareRouterWalletBudgetStatusV1),
}
```

Every response must carry the same observable fields as the server TS route
helpers:

- `remaining_uses`
- `committed_remaining_uses`
- `reserved_uses`
- `available_uses`
- `projection_version`
- `expires_at_ms`
- `reservation_id` for reserve, validate, commit, and release branches

Error mapping:

- exhausted budget: `409 wallet_budget_exhausted`
- active conflicting reservation: `409 wallet_budget_reserved`
- mismatched reservation identity: `409 wallet_budget_reservation_mismatch`
- expired reservation: `410 wallet_budget_reservation_expired`
- malformed budget input: `422 invalid_budget_request`
- missing grant record or unauthorized signer binding: `403 wallet_budget_forbidden`
- storage invariant failure: `500 wallet_budget_internal`

The strict Rust protocol may use internal `RouterAbProtocolErrorCode` values
inside Durable Object calls. Public Router JSON responses must normalize those
internal codes to the budget error contract above.

#### Storage Model

The DO storage key is:

```text
{key_prefix}/wallet-budget/{signing_grant_id}
```

The stored record contains:

- `signing_grant_id`
- `wallet_id`
- `rp_id`
- `issuer_jwt_id`
- authorized signer bindings:
  `curve + threshold_session_id + signing_worker_id`
- `committed_remaining_uses`
- `reserved_uses`
- `available_uses`
- `expires_at_ms`
- active reservation map keyed by `reservation_id`
- committed operation map keyed by
  `signing_worker_id + operation_id + request_digest`

Reservation records contain:

- `reservation_id`
- `curve`
- `threshold_session_id`
- `signing_worker_id`
- `operation_id`
- `request_digest`
- `signature_uses`
- `expires_at_ms`
- `status: reserved | committed`
- `remaining_uses_after_commit` when committed

The DO must clean expired `reserved` reservations at the start of every
reserve, validate, commit, release, and status operation. Committed reservations
remain until the Wallet Session expires so duplicate finalize can be idempotent.

Reserve validation must prove the requested
`curve + threshold_session_id + signing_worker_id` is present in the grant's
authorized signer binding set before checking available budget.

Curve serialization rule:

- `CloudflareRouterWalletBudgetCurveV1::Ed25519` serializes as `ed25519`.
- `CloudflareRouterWalletBudgetCurveV1::EcdsaHss` serializes as `ecdsa`.
- Internal Rust type names may mention HSS; budget storage, telemetry, public
  JSON, and test fixtures use only `ed25519 | ecdsa`.

#### Canonical Identity Builders

Budget identity must be built by named helpers, never inline string
concatenation or caller-provided transport fields.

Required strict Rust helpers:

```rust
fn cloudflare_router_ed25519_normal_signing_budget_operation_id_v2(
    request: &RouterAbEd25519NormalSigningPrepareRequestV2,
) -> RouterAbProtocolResult<String>;

fn cloudflare_router_ed25519_normal_signing_budget_request_digest_v2(
    request: &RouterAbEd25519NormalSigningPrepareRequestV2,
) -> RouterAbProtocolResult<PublicDigest32>;

fn cloudflare_router_ed25519_finalize_budget_request_digest_v2(
    request: &RouterAbEd25519NormalSigningFinalizeRequestV2,
) -> RouterAbProtocolResult<PublicDigest32>;

fn cloudflare_router_ed25519_presign_pool_hit_budget_identity_v2(
    request: &RouterAbEd25519PresignPoolHitFinalizeRequestV2,
) -> RouterAbProtocolResult<CloudflareRouterWalletBudgetOperationIdentityV1>;

fn cloudflare_router_ecdsa_hss_budget_operation_id_v1(
    request: &RouterAbEcdsaHssEvmDigestSigningRequestV1,
    threshold_session_id: &str,
    signing_worker_id: &str,
) -> RouterAbProtocolResult<String>;

fn cloudflare_router_ecdsa_hss_budget_request_digest_v1(
    request: &RouterAbEcdsaHssEvmDigestSigningRequestV1,
) -> RouterAbProtocolResult<PublicDigest32>;

fn cloudflare_router_ecdsa_hss_finalize_budget_request_digest_v1(
    request: &RouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1,
) -> RouterAbProtocolResult<PublicDigest32>;
```

Builder rules:

- Ed25519 normal prepare and finalize must derive the same
  `request_digest` for the same signed operation.
- Ed25519 `operation_id` comes from the approved signing intent, not from
  `scope.request_id`.
- Ed25519 pool-hit finalization derives both operation id and request digest
  from the final signing request.
- ECDSA-HSS `budget_operation_id` must match the SDK helper
  `deriveRouterAbEcdsaHssBudgetOperationId`.
- ECDSA-HSS `budget_operation_id` must include active SigningWorker state,
  threshold session id, key scope, activation epoch, public identity,
  presignature id, expiry, and signing digest.
- ECDSA-HSS `budget_operation_id` must exclude transport `request_id`.
- Request digest must change when account, session, SigningWorker, expiry,
  signing payload/digest, key scope, activation epoch, or public identity
  changes.

Add shared vector tests:

- TS and Rust derive the same ECDSA-HSS `budget_operation_id`.
- Ed25519 prepare and finalize derive the same request digest.
- Changing only transport `request_id` does not change ECDSA-HSS
  `budget_operation_id`.
- Changing expiry changes request digest.

#### Public Response Surface

Strict Cloudflare public signing responses must expose the same budget metadata
as the local Router responses, using snake_case public wire names:

```json
{
  "budget_reservation_id": "wbr_...",
  "budget_operation_id": "op_...",
  "budget_status": {
    "remaining_uses": 2,
    "committed_remaining_uses": 2,
    "reserved_uses": 0,
    "available_uses": 2,
    "projection_version": "wbp_...",
    "expires_at_ms": 1780000000000
  }
}
```

Rules:

- Prepare responses that reserve budget must include
  `budget_reservation_id`, `budget_operation_id`, and `budget_status`.
- Finalize responses that commit budget must include the updated
  `budget_status`.
- `budget_status.available_uses` is the policy value used for signing
  admission. SDK display may still translate this into approval language.
- Public JSON must not expose Durable Object keys, internal storage versions,
  raw Wallet Session JWTs, or private service-binding details.
- Strict Cloudflare budget status uses snake_case `remaining_uses` as the
  backwards-compatible public field inside `budget_status`. CamelCase
  `remainingUses` is compatibility-only at the local Router/SDK request
  boundary.

#### Status Endpoint Parity

Strict Cloudflare deployment must provide the same server-authoritative budget
status semantics as local Router:

- If strict Cloudflare is the browser-facing Router, it must expose the current
  signing-budget status route from the Wallet Budget DO.
- If another Router process remains the browser-facing Wallet Session issuer,
  strict Cloudflare signing routes must still read the same Wallet Budget DO
  record keyed by `signing_grant_id`.
- Budget status must include committed remaining uses, active reserved uses,
  available uses, projection version, grant expiry, and signer binding
  membership.
- A status read for a missing grant returns `403 wallet_budget_forbidden`.
- A status read with an expired Wallet Session JWT returns `401 unauthorized`.
- A status read with an unexpired JWT whose server grant record has expired
  returns `403 wallet_budget_forbidden`.

#### Route State Machines

`POST /router-ab/ed25519/sign/prepare`:

1. Validate Wallet Session JWT and require `signingGrantId`.
2. Validate Ed25519 scope, expiry, SigningWorker id, and request digest.
3. Reserve replay for the prepare request.
4. Evaluate Router project-policy, quota, and abuse DOs.
5. Reserve one Wallet Session signature use with:
   `curve=Ed25519`, `signature_uses=1`, canonical `operation_id`, canonical
   prepare `request_digest`.
6. Forward admitted prepare to the private SigningWorker.
7. If private prepare fails before a prepare response is returned, release the
   budget reservation.
8. Return prepare response with:
   `budget_reservation_id`, `budget_operation_id`, and `budget_status`.

`POST /router-ab/ed25519/sign` normal finalize:

1. Validate Wallet Session JWT and require `signingGrantId`.
2. Require `budget_reservation_id` and `budget_operation_id`.
3. Derive the same canonical request digest used by prepare.
4. Validate the reservation identity before private SigningWorker forwarding.
5. Forward admitted finalize to the private SigningWorker.
6. If private finalize fails before a signature is returned, release the
   reservation.
7. Commit the reservation after private SigningWorker success and before the
   Router returns the signature.
8. Return no signature if commit fails.

`POST /router-ab/ed25519/sign/presign-pool/prepare`:

1. Validate Wallet Session JWT and require `signingGrantId`.
2. Validate Ed25519 scope, expiry, SigningWorker id, and pool request binding.
3. Read strict budget status and require at least one available use.
4. Do not reserve or commit budget because this route returns no transaction
   signature.
5. Forward admitted pool refill prepare to the private SigningWorker.

`POST /router-ab/ed25519/sign` pool-hit finalize:

1. Validate Wallet Session JWT and require `signingGrantId`.
2. Derive canonical final-sign `operation_id` and `request_digest` from the
   final signing request.
3. Reserve one Wallet Session signature use immediately before private
   SigningWorker forwarding.
4. Forward admitted pool-hit finalize to the private SigningWorker.
5. If private finalize fails before a signature is returned, release the
   reservation.
6. Commit the reservation before returning the signature.

`POST /router-ab/ecdsa-hss/sign/prepare`:

1. Validate Wallet Session JWT and require `signingGrantId`.
2. Validate active ECDSA-HSS scope, activation epoch, public identity,
   SigningWorker id, expiry, and request digest.
3. Reserve replay for the prepare request.
4. Evaluate Router project-policy, quota, and abuse DOs.
5. Reserve one Wallet Session signature use with:
   `curve=ecdsa`, `signature_uses=1`, canonical ECDSA-HSS
   `budget_operation_id`, and canonical Router A/B request digest.
6. Forward admitted prepare to the private SigningWorker.
7. If private prepare fails before a prepare response is returned, release the
   reservation.
8. Return prepare response with:
   `budget_reservation_id`, `budget_operation_id`, and `budget_status`.

`POST /router-ab/ecdsa-hss/sign`:

1. Validate Wallet Session JWT and require `signingGrantId`.
2. Require `budget_reservation_id` and `budget_operation_id`.
3. Reject transport `request_id` used as `budget_operation_id`.
4. Derive canonical ECDSA-HSS final request digest.
5. Validate the reservation identity before private SigningWorker forwarding.
6. Forward admitted finalize to the private SigningWorker.
7. If private finalize fails before a signature is returned, release the
   reservation.
8. Commit the reservation after private SigningWorker success and before the
   Router returns the signature.
9. Return no signature if commit fails.

Shared ordering rules:

- Replay admission happens immediately after auth and route-body validation for
  prepare routes. A duplicate prepare rejected by replay admission must not
  evaluate project-policy, quota, abuse, or budget reserve.
- Budget reserve happens before private SigningWorker prepare/finalize
  forwarding for every route that can return a transaction signature.
- Project-policy, abuse, and per-RP quota checks happen before budget reserve.
- A route that validates budget status without reserving, such as
  presign-pool prepare, must not make a private SigningWorker call when
  `available_uses < 1`.
- Release calls are best-effort compensation after a private worker failure.
  Release failure is logged as `wallet_budget_release_failed` and does not
  authorize returning a signature.

#### Failure Semantics

- Validation failures before reserve do not release anything.
- Private prepare/finalize failure after reserve releases the reservation.
- Reservation validation failure before private finalize forwarding does not
  release unless the request proves the exact reservation identity.
- Commit failure after private SigningWorker success returns no signature and
  reports `wallet_budget_internal`. The DO must preserve the reservation state
  for operator inspection and idempotent retry.
- After private SigningWorker success, a commit failure must not release the
  reservation because the nonce or presignature may already be consumed. The
  user-visible response is an internal failure, and retry behavior must use the
  same reservation identity.
- A retry after private SigningWorker success plus budget commit failure must be
  well-defined. Either the private SigningWorker finalize path is idempotent for
  the same request identity, or the Router persists the successful private
  worker response as a pending worker-success result and retries only the budget
  commit/response step. A strict implementation must choose one of these before
  deployment.
- Duplicate finalize with the same
  `signing_worker_id + operation_id + request_digest` returns the committed
  budget result and does not decrement again.
- A conflicting duplicate finalize returns
  `wallet_budget_reservation_mismatch`.

#### Audit And Telemetry

Every strict budget operation must emit safe structured telemetry:

- `phase`: `put_grant | reserve | validate | commit | release | status`
- `result_code`
- `signing_grant_id_hash` or other non-secret stable grant fingerprint
- `curve`
- `threshold_session_id_hash`
- `signing_worker_id`
- `operation_id_hash`
- `request_digest`
- `reservation_id`
- `committed_remaining_uses`
- `reserved_uses`
- `available_uses`
- `projection_version`
- `duration_ms`

Telemetry must not log raw JWTs, private shares, signatures, passkey material,
PRF output, HPKE plaintext, or raw user payloads. User/account identifiers should
use the same redaction policy already used by strict Router A/B logs.

#### Source Guards And Tests

Add source guards proving:

- strict Router bindings include `wallet_budget`
- strict Wrangler Router config includes the Wallet Budget DO binding and env
  vars
- strict Wrangler Router config fails deploy when the Wallet Budget DO binding
  or key-prefix env var is absent
- Signer A/B and SigningWorker Wrangler configs do not expose Wallet Budget DO
- strict private workers cannot import or call Wallet Budget DO helpers
- every strict public signing route calls the correct budget helper before any
  private SigningWorker finalize/prepare forwarding
- every strict grant-issuing boundary calls `PutGrant` before returning or
  accepting a signable Wallet Session JWT
- public strict responses include `budget_status` on reservation/commit paths
- the fail-closed marker
  `STRICT_CLOUDFLARE_WALLET_SESSION_BUDGET_ENFORCEMENT_REQUIRED_V1` is deleted
  after real helpers land

Add focused Rust tests:

- `PutGrant` creates a grant and replaying the same request is idempotent
- `PutGrant` with a reused grant id and different signer binding conflicts
- signing with a valid JWT but missing grant record returns
  `wallet_budget_forbidden`
- unauthorized signer binding returns `wallet_budget_forbidden`
- missing `signingGrantId` Wallet Session JWT is rejected
- Ed25519 prepare reserves budget before private forwarding
- Ed25519 prepare private-worker failure releases reservation
- Ed25519 finalize validates before private forwarding
- Ed25519 finalize private-worker failure releases reservation
- Ed25519 finalize commits before returning signature
- Ed25519 pool-hit finalize reserves and commits exactly once
- Ed25519 presign-pool prepare validates budget status without reserving
- ECDSA-HSS prepare reserves budget before private forwarding
- ECDSA-HSS finalize validates before private forwarding
- ECDSA-HSS finalize rejects transport `request_id` as budget operation id
- duplicate finalize is idempotent
- expired reservation is rejected and cleaned up
- cross-worker, cross-curve, and cross-threshold-session reservation attempts
  are rejected
- strict status returns committed, reserved, and available counts from the same
  grant record used by signing
- release failure after private worker failure is logged and still returns no
  signature

Completion for Phase 7.1:

- [x] `pnpm router:deploy:check` no longer fails on the strict budget marker.
- [x] The release check fails if any strict public signing route can forward to the
  private SigningWorker without the appropriate budget helper.
- [x] Strict Cloudflare grant issuance or grant acceptance calls `PutGrant`
  before returning or accepting a signable Wallet Session JWT.
- [x] Strict Cloudflare and local Router expose the same user-visible budget
  behavior.

Implemented scope:

- Strict Cloudflare now exposes a Router-private service-auth
  `/router-ab/router/wallet-budget/put-grant` endpoint. It accepts the typed
  `CloudflareRouterWalletBudgetPutGrantRequestV1`, overwrites timing with Router
  time at the boundary, and writes the grant through the Wallet Budget Durable
  Object `PutGrant` operation before signable JWTs can spend that grant.
- Strict public signing routes still require the Wallet Session JWT
  `signingGrantId`; missing grant records fail at reserve/validate/status time.
- Strict Cloudflare now exposes the same browser-facing
  `/router-ab/wallet-budget/status` route shape as local Router, backed by the
  Wallet Budget Durable Object.
- The release guard now requires the private grant endpoint, internal service
  auth, `PutGrant` execution, and strict status-route DO reads.

Acceptance:

- Local and Cloudflare deployments enforce the same server-authoritative budget
  semantics.

## Phase 8: Delete Client-Only Budget Authority

- [x] Remove any local-client-only logic that was needed only because the server
      did not consume signing budget.
- [x] Keep local projection only for:
  - [x] optimistic UI
  - [x] in-flight operation dedupe
  - [x] avoiding duplicate prompts while a server request is pending
- [x] Add source guards rejecting:
  - [x] direct Router A/B sign-ready decisions from raw persisted
        `remainingUses`
  - [x] signing success paths that do not call server budget commit
  - [x] new public signing routes without budget reservation and commit
- [x] Update docs that describe SDK-local budget as the authority.

Implemented scope:

- `tests/unit/routerAbNormalSigningSdk.guard.unit.test.ts` now guards the TS
  Ed25519 and ECDSA-HSS public Router route cores so current reservation-backed
  prepare/finalize paths keep server budget reservation and commit hooks. It
  also rejects reintroducing the deleted Router A/B direct-consume helper.
- The same source guard proves active SDK budget projection requires server
  `availableUses` and does not derive the active signing allowance from
  compatibility `remainingUses`.
- `SigningSessionCoordinator` no longer synthesizes successful budget-spend sync
  from `touchConfirm`, Email OTP local consume ports, or Ed25519 consumed-mark
  helpers. Server-consumed Router A/B signs reconcile by rereading the
  server-authoritative budget status, and explicit `consumeUse` remains the only
  success-sync override.
- The source guard now rejects reintroducing implicit local warm-session consume
  fallback as Wallet Session budget authority.
- `docs/refactor-27-nonce-coordinator.md` now describes Router-owned
  reserve/commit budget admission instead of a local ledger consuming budget
  after signing.

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
- Integration: NEAR + Tempo + EVM share a single `signingGrantId`
  budget.
- Integration: refactor-41 unlock policy gives three approvals and
  post-exhaustion step-up gives one approval with captured
  `requiredSignatureUses`.
- Unit: NEAR rejects multi-transaction signing before budget admission.
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

# Gas Sponsorship + Prepaid Balance Plan

Last updated: 2026-03-19

## Objective

Tie gas sponsorship admission and settlement to org prepaid balances.

Target behavior:

- an org can use gas sponsorship only when:
  - the request matches an active sponsorship policy
  - the policy spend cap still has room
  - the org has enough available prepaid balance for the estimated sponsored spend
- if prepaid balance is exhausted before any policy spend cap is exhausted, sponsorship stops immediately
- sponsorship resumes only after the org balance is refilled
- policy spend caps remain in force even when the org still has prepaid balance

This is a clean development-phase refactor. Do not preserve the current split where sponsorship budgeting and prepaid billing are mostly independent.

## Implementation status

Current status:

- [x] Phase 1 is complete
- [x] Phase 2 is complete
- [x] Phase 3 core route integration is landed for both EVM and NEAR
- [x] dedicated `SPONSORED_EXECUTION_DEBIT` billing support is landed
- [x] sponsored execution is no longer billed through the MAW path
- [x] billing statements and account activity now have a first-class sponsored execution debit shape
- [x] prepaid sponsorship reservations now exist as a dedicated org-scoped operational layer
- [x] shared sponsorship routes now reserve prepaid balance before execution and gate sponsorship on available org balance
- [x] sponsored execution records now include explicit billing linkage fields such as `billingLedgerEntryId`, `prepaidReservationId`, `charged`, `chargedReason`, and `settledAt`
- [x] sponsored execution records now include first-class settlement/pricing fields: `estimatedSpendMinor`, `settledSpendMinor`, `pricingVersion`, `pricingSource`
- [x] sponsored settlement now requires one atomic Postgres path; the non-atomic fallback path has been removed
- [x] relayer sponsored-route tests are aligned to the atomic Postgres settlement contract (they run with Postgres-backed billing/prepaid/sponsored-call services when `POSTGRES_URL` is set)
- [x] 90-day sponsored execution history APIs and supporting Postgres indexes are landed
- [x] the console billing surface now exposes sponsored execution history at `/console/billing/sponsored-executions`
- [x] reconciliation API surface now compares sponsored execution history against linked `SPONSORED_EXECUTION_DEBIT` billing entries
- [x] billing overview now exposes reserved sponsorship plus 30/90-day sponsored spend summary fields
- [x] billing account views now surface reserved sponsorship from the live reservation summary
- [x] sponsorship balance webhook transitions now emit `billing.balance.low_balance`, `billing.balance.blocked`, and `billing.balance.recovered`
- [x] sponsorship balance transitions now also surface as console observability log events
- [x] sponsorship reserve rejections now emit `billing.sponsorship.blocked` observability events

Still not implemented:

- [ ] customer email delivery once explicit billing contacts / templates are wired

## Why this is a separate plan

This work sits on top of two already-existing systems:

- the generalized sponsorship engine in [docs/generalized-gas-sponsorship.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/generalized-gas-sponsorship.md)
- the org-scoped prepaid billing model in [docs/prepaid-billing.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/prepaid-billing.md)

The original gap was that sponsored execution already had:

- policy matching
- idempotency
- execution history
- spend-cap reservation / settlement

while prepaid billing already has:

- org credit balances
- ledger-backed projections
- low-balance / blocked readiness

That gap is now closed for the shared EVM and NEAR sponsorship routes. The remaining work is around customer-facing/dashboard surfacing; outbound email is deferred for now in favor of webhook plus observability-log visibility.

## Current state

Implemented today:

- sponsored execution history is stored in [server/src/console/sponsoredCalls/types.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/sponsoredCalls/types.ts) and [server/src/console/sponsoredCalls/postgres.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/sponsoredCalls/postgres.ts)
- sponsorship policy spend caps reserve and settle billable `spendMinor` in [server/src/sponsorship/spendCaps.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/sponsorship/spendCaps.ts)
- prepaid org balance and blocked/low-balance readiness already exist in [server/src/console/billing/service.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/billing/service.ts) and [server/src/console/billing/readiness.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/billing/readiness.ts)
- sponsored execution now records dedicated `SPONSORED_EXECUTION_DEBIT` billing entries through:
  - [server/src/router/sponsorshipExecution.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/sponsorshipExecution.ts)
  - [server/src/console/billing/postgres.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/billing/postgres.ts)
- billing statements and account activity now expose sponsored execution debits separately from MAW usage in:
  - [server/src/console/billing/service.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/billing/service.ts)
  - [server/src/console/billing/postgres.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/billing/postgres.ts)
- sponsored execution records already carry explicit billing linkage fields in:
  - [server/src/console/sponsoredCalls/types.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/sponsoredCalls/types.ts)
  - [server/src/router/relaySponsoredEvmCall.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/relaySponsoredEvmCall.ts)
  - [server/src/router/relaySignedDelegate.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/relaySignedDelegate.ts)
- atomic settlement path now requires prepaid reservation settlement, billing debit, and sponsored call record creation to happen in one DB transaction backed by shared Postgres billing/prepaid/sponsored-call services
- prepaid balance admission now accepts negative posted balance from underestimation, naturally blocking all future sponsorship until the org refills
- prepaid sponsorship reservations now exist in:
  - [server/src/console/billingPrepaidReservations/service.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/billingPrepaidReservations/service.ts)
  - [server/src/console/billingPrepaidReservations/postgres.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/billingPrepaidReservations/postgres.ts)
- last-90-days sponsored execution history is now queryable through:
  - [server/src/console/sponsoredCalls/service.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/sponsoredCalls/service.ts)
  - [server/src/console/sponsoredCalls/postgres.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/sponsoredCalls/postgres.ts)
  - [server/src/router/express/createConsoleRouter.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/express/createConsoleRouter.ts)
  - [server/src/router/cloudflare/createCloudflareConsoleRouter.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/cloudflare/createCloudflareConsoleRouter.ts)
- the dashboard billing API client now has a sponsored execution history fetcher in:
  - [examples/tatchi-site/src/pages/dashboard/routes/billing/consoleBillingApi.ts](/Users/pta/Dev/rust/simple-threshold-signer/examples/tatchi-site/src/pages/dashboard/routes/billing/consoleBillingApi.ts)
- sponsored execution reconciliation is now queryable through:
  - [server/src/console/sponsoredCalls/reconciliation.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/sponsoredCalls/reconciliation.ts)
  - [server/src/router/express/createConsoleRouter.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/express/createConsoleRouter.ts)
  - [server/src/router/cloudflare/createCloudflareConsoleRouter.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/cloudflare/createCloudflareConsoleRouter.ts)
  - [examples/tatchi-site/src/pages/dashboard/routes/billing/consoleBillingApi.ts](/Users/pta/Dev/rust/simple-threshold-signer/examples/tatchi-site/src/pages/dashboard/routes/billing/consoleBillingApi.ts)
- billing overview now includes reserved sponsorship and sponsored-spend summary through:
  - [server/src/router/express/createConsoleRouter.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/express/createConsoleRouter.ts)
  - [server/src/router/cloudflare/createCloudflareConsoleRouter.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/cloudflare/createCloudflareConsoleRouter.ts)
  - [server/src/console/sponsoredCalls/service.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/sponsoredCalls/service.ts)
  - [server/src/console/sponsoredCalls/postgres.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/sponsoredCalls/postgres.ts)
  - [server/src/console/billingPrepaidReservations/service.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/billingPrepaidReservations/service.ts)
  - [server/src/console/billingPrepaidReservations/postgres.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/billingPrepaidReservations/postgres.ts)
- the billing account UI now surfaces reserved sponsorship and recent sponsored-spend summary in:
  - [examples/tatchi-site/src/pages/dashboard/routes/billing/BillingConsoleShell.tsx](/Users/pta/Dev/rust/simple-threshold-signer/examples/tatchi-site/src/pages/dashboard/routes/billing/BillingConsoleShell.tsx)
- sponsorship balance state transitions now emit billing-category webhook events from:
  - [server/src/router/sponsorshipBillingEvents.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/sponsorshipBillingEvents.ts)
  - [server/src/router/sponsorshipExecution.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/sponsorshipExecution.ts)
  - [server/src/router/relaySignedDelegate.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/relaySignedDelegate.ts)
  - [server/src/router/express/createConsoleRouter.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/express/createConsoleRouter.ts)
  - [server/src/router/cloudflare/createCloudflareConsoleRouter.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/cloudflare/createCloudflareConsoleRouter.ts)
- sponsorship balance transitions now also surface in console observability logs through:
  - [server/src/console/observability/adapters.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/observability/adapters.ts)
  - [server/src/console/observability/policy.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/observability/policy.ts)
  - [server/src/router/sponsorshipBillingEvents.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/sponsorshipBillingEvents.ts)
- sponsorship reserve failures now emit `billing.sponsorship.blocked` observability events from:
  - [server/src/router/sponsorshipBillingEvents.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/sponsorshipBillingEvents.ts)
  - [server/src/router/relaySponsoredEvmCall.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/relaySponsoredEvmCall.ts)
  - [server/src/router/relaySignedDelegate.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/relaySignedDelegate.ts)
  - [server/src/console/observability/adapters.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/observability/adapters.ts)
- billing invoice list/detail views now keep monthly documents aggregated while linking operators back to:
  - [examples/tatchi-site/src/pages/dashboard/routes/billing/BillingInvoicesView.tsx](/Users/pta/Dev/rust/simple-threshold-signer/examples/tatchi-site/src/pages/dashboard/routes/billing/BillingInvoicesView.tsx)
  - [examples/tatchi-site/src/pages/dashboard/routes/billing/BillingInvoiceDetailView.tsx](/Users/pta/Dev/rust/simple-threshold-signer/examples/tatchi-site/src/pages/dashboard/routes/billing/BillingInvoiceDetailView.tsx)
  - [examples/tatchi-site/src/pages/dashboard/routes/billing/BillingConsoleShell.tsx](/Users/pta/Dev/rust/simple-threshold-signer/examples/tatchi-site/src/pages/dashboard/routes/billing/BillingConsoleShell.tsx)

Missing today:

- no customer email delivery for sponsorship balance transitions; use webhook + observability logs for now

## Core product decisions

These decisions should be treated as locked for implementation.

### 1. Prepaid balance is an org-level hard gate

Sponsorship admission requires both:

- policy-level authorization
- org-level economic authorization

If prepaid balance is depleted, sponsorship stops even if a policy spend cap still has room.

### 2. Policy spend caps and prepaid balances are different controls

They answer different questions:

- `spendCap`: how much this policy may consume
- prepaid balance: whether the org can pay for any more sponsorship at all

Both must be enforced. The stricter one wins.

### 3. Sponsored executions must become prepaid billing events

Successful or failed sponsored executions that actually burn sponsor-paid gas must become billable prepaid usage.

Charge actual sponsor-paid gas, not just successful business outcomes.

Examples:

- EVM tx mined and reverted: charge actual gas paid
- NEAR delegate execution burns gas and fails: charge actual `tokens_burnt`
- pre-broadcast auth/policy rejection: charge zero
- RPC rejection before sponsor spend is incurred: charge zero

### 4. NEAR deposit stays out of sponsorship billing

For `near_delegate`:

- gas sponsorship is gas-only
- attached deposit is user-paid
- attached deposit is not part of sponsorship caps
- attached deposit is not part of sponsorship pricing
- attached deposit is not part of sponsorship billing

### 5. Balances come from the billing ledger, not from sponsorship history

Sponsored execution history is for:

- audit
- support
- dispute handling
- reconciliation
- customer reporting

It is not the source of truth for org balance.

Org balance must continue to come from the billing ledger and its projections.

### 6. Chargeability is based on sponsor-paid gas, not business success

Lock the terminal-outcome mapping as:

- `success` -> charge actual settled spend
- `reverted` -> charge actual settled spend
- `broadcast_failed` -> charge zero unless the system can prove sponsor spend was actually incurred
- `rpc_rejected` -> charge zero unless the system can prove sponsor spend was actually incurred

The rule is:

- charge sponsor-paid gas
- do not charge merely because an attempt was made

### 7. Settlement and prepaid debit are atomic

When a sponsored execution settles, these operations must occur in one DB transaction:

- settle the prepaid reservation
- append the billing ledger debit
- link the sponsored execution record to the resulting billing entry

Do not allow reservation settlement to commit without the billing debit, or vice versa.

### 8. Underestimation may drive the org slightly negative

If estimated spend is lower than actual settled spend:

- settle the real actual spend
- allow the org balance to go slightly negative if necessary
- block all future sponsorship immediately until the prepaid balance is refilled

Do not clip the final debit down to the reserved estimate. The ledger must reflect the real settled sponsored spend.

### 9. Balance enforcement is org-wide

Prepaid balance gating for sponsorship is org-wide, not environment-scoped.

That means:

- all sponsorship requests consume the same org prepaid pool
- any environment can be blocked by depleted prepaid balance
- refilling the org restores sponsorship availability across environments

### 10. Reservations always apply, not only at low balance

Do not make prepaid reservations conditional on low balance or a threshold like `$5`.

Why:

- the reservation exists for concurrency correctness, not just low-balance protection
- oversubscription races can happen at any balance
- conditional reservation rules create two accounting models and harder-to-audit edge cases

The rule is:

- always reserve estimated sponsored spend before execution
- always compute available balance as posted balance minus active reservations
- block only when available balance is insufficient

## Is it a good idea to store sponsored transaction history for 3 months?

Yes, but with one important correction:

- keeping at least 3 months of detailed sponsored-execution history in the primary DB is a good idea
- using that history as the source of truth for prepaid balance is a bad idea

Recommended approach:

- keep append-only sponsored execution records for every sponsored request
- keep at least 90 days of detailed records queryable in the main DB for dashboard, support, and reconciliation
- keep billing ledger entries indefinitely, because they are the financial source of truth
- if storage becomes a concern later, archive raw sponsored-execution records older than 90 days rather than deleting them outright

In early development, the simplest acceptable approach is:

- keep `console_sponsored_call_records` indefinitely
- optimize query surfaces around a default last-90-days window

That is cleaner than building archival machinery too early.

## Target model

### Source of truth

Use two complementary data layers:

1. Billing ledger
   - financial source of truth
   - debit prepaid balance on settled sponsored spend
   - credit prepaid balance on top-up / support adjustments

2. Sponsored execution history
   - append-only operational and audit history
   - one row per sponsored execution attempt
   - holds gas details, chain details, pricing version, policy/template ids, and reconciliation references

### New operational layer: prepaid sponsorship reservations

To avoid concurrent overspend, add an operational reservation layer for sponsored executions.

Why:

- billing balance is ledger-derived
- execution is concurrent
- two requests can both see the same positive balance unless the system reserves estimated spend first

Recommended shape:

- add a dedicated reservation store such as `billing_prepaid_reservations`
- one reservation per sponsorship idempotency key / source event
- statuses:
  - `RESERVED`
  - `SETTLED`
  - `RELEASED`
  - `EXPIRED`
- store:
  - `orgId`
  - `environmentId`
  - `policyId`
  - `sourceEventId`
  - `estimatedSpendMinor`
  - `settledSpendMinor`
  - `pricingVersion`
  - `txOrExecutionRef`
  - `createdAt`
  - `settledAt`
  - `releasedAt`

This reservation store is operational state, not accounting truth.

#### What a reservation is

A reservation is a temporary hold on part of an org's prepaid balance before execution begins.

Example:

- org posted prepaid balance: `$25.00`
- active sponsorship request estimated spend: `$0.18`
- system creates a reservation for `$0.18`
- available balance becomes `$24.82` while the request is in flight

Then:

- if the execution settles at `$0.16`, the reservation is settled and the billing ledger is debited `$0.16`
- if the execution settles at `$0.21`, the reservation is settled at `$0.21` and the org may go slightly negative if needed
- if execution never incurs sponsor spend, the reservation is released back to available balance

The reservation exists to prevent two concurrent requests from both spending the same prepaid dollars.

### Available balance

Admission control should use:

- `availableBalanceMinor = postedCreditBalanceMinor - activeReservedSpendMinor`

Where:

- `postedCreditBalanceMinor` comes from the billing ledger projection
- `activeReservedSpendMinor` is the sum of unresolved sponsorship reservations for that org

### Reservation expiry policy

Lock this behavior:

- use a short TTL for unresolved reservations
- release immediately for confirmed zero-spend pre-execution failures
- run a sweeper job that expires stale unresolved reservations

Recommended first pass:

- reservations remain `RESERVED` only while execution state is unresolved
- reservations transition to:
  - `SETTLED` when final spend is known and billed
  - `RELEASED` when final spend is known to be zero
  - `EXPIRED` only when the system cannot complete the normal settlement path

`EXPIRED` should be treated as an exceptional recovery path, not a normal execution outcome.

### Burst traffic considerations

This design intentionally introduces a small same-org serialization point.

Implications:

- requests across different orgs should still proceed in parallel
- requests for the same org contend on that org's prepaid pool
- this is acceptable because the economic constraint is org-scoped anyway

The implementation must keep the critical section small:

- one short DB transaction to reserve prepaid balance
- no chain/RPC execution inside the reservation transaction
- one short DB transaction later to settle the reservation and billing debit

This is expected to be good enough for the current product even if one org sends hundreds of sponsorship requests in a short burst.

If same-org burst traffic later becomes a real bottleneck, the first remedies should be:

- lock one org balance row or one org reservation state row, not a broad query
- maintain an explicit reserved-balance projection instead of summing all open reservations per request
- use one atomic reserve statement for admission
- keep replay/idempotency strict so duplicate retries collapse cleanly
- add per-org smoothing such as queueing or rate limiting only if real traffic justifies it

Do not change the accounting semantics to optimize this:

- reservations should still always apply
- optimizations should preserve the same balance and admission rules

## Billing model changes

### Add a dedicated sponsored-execution debit type

Do not keep routing sponsored execution through the MAW usage path.

Add a dedicated billing shape for sponsored spend:

- new `BillingLedgerEntryType`, such as `SPONSORED_EXECUTION_DEBIT`
- new invoice/account-activity representation for sponsored spend
- new line-item type if usage statements continue to be generated from ledger activity

This keeps sponsored gas charges distinct from:

- MAW pricing
- manual adjustments
- top-ups

### Billing document shape

Lock this customer-facing shape:

- billing documents should aggregate sponsored spend into statement-friendly rows
- per-transaction detail should stay in sponsored execution history, not in invoice line-item explosion

Recommended first pass:

- usage statements show aggregated sponsored spend by period, optionally by chain family or policy
- `/dashboard/billing/account` and a dedicated sponsored-history view show the per-tx detail

### Required journal effect

When a sponsored execution settles with billable spend:

- debit `org_prepaid_liability:{orgId}`
- credit `revenue_usage` or a more explicit `revenue_sponsored_execution`

If the org is refunded later for an operator issue, use compensating entries, not mutation.

## Sponsored execution record changes

Keep using `console_sponsored_call_records`, but strengthen it as the canonical sponsorship audit trail.

Already landed as explicit fields:

- `billingLedgerEntryId`
- `prepaidReservationId`
- `charged` boolean
- `chargedReason`
- `settledAt`
- `estimatedSpendMinor`
- `settledSpendMinor`
- `pricingVersion`
- `pricingSource`

Avoid hiding critical reconciliation data only inside `detailsJson`.

## Admission and settlement flow

The shared sponsorship engine should become:

1. Authenticate and resolve org/environment/api key context.
2. Match the sponsorship policy.
3. Estimate `spendMinor` using the shared pricing adapter.
4. Reserve policy spend cap.
5. Reserve org prepaid balance.
6. If either reservation fails, reject before execution.
7. Execute sponsorship.
8. Finalize actual billable spend.
9. Settle policy spend-cap reservation.
10. Settle prepaid reservation.
11. Append the billing ledger debit for settled sponsored spend.
12. Record sponsored execution history with prepaid/billing linkage.
13. Recompute balance readiness transitions.
14. Emit state-transition events and notifications if needed.

Failure handling rules:

- if prepaid reservation fails after policy-cap reservation succeeds, release the policy-cap reservation
- if execution never broadcasts and no sponsor spend is incurred, settle to zero and release unused reservation
- if execution broadcasts and sponsor gas is paid, charge actual finalized spend even if the user-visible action failed
- all steps must remain idempotent on the request `idempotencyKey`

## Precedence rules

These rules should be explicit in code and docs.

### Admission precedence

A request is allowed only if all are true:

- auth succeeds
- policy matches
- policy spend cap reservation succeeds
- prepaid balance reservation succeeds

### Blocking precedence

- if prepaid balance is depleted first, sponsorship stops even if caps remain
- if policy cap is exhausted first, that policy stops even if org balance remains positive
- if both are exhausted, return the more economically useful operator-facing error first:
  - prefer prepaid-balance-blocked over generic policy mismatch

## Events and notifications

Yes, add an events system for this. But do it as state transitions, not per-request spam.

### Events to emit

Use the existing `billing` webhook/event category and add explicit event types such as:

- `billing.balance.low`
- `billing.balance.blocked`
- `billing.balance.recovered`
- `billing.sponsorship.blocked`

Semantics:

- `billing.balance.low`: balance crossed from `HEALTHY` to `LOW_BALANCE`
- `billing.balance.blocked`: balance crossed to `BLOCKED`
- `billing.balance.recovered`: balance crossed from `BLOCKED` or `LOW_BALANCE` back to `HEALTHY`
- `billing.sponsorship.blocked`: a sponsorship request was rejected because prepaid balance could not cover the estimated spend

Event policy:

- balance events are transition-based
- `billing.sponsorship.blocked` is observability-first and must be deduped aggressively if exposed to customers

### Logging behavior

For now, surface transition visibility through webhook events plus console observability logs, not customer email.

Logging rules:

- log once per meaningful transition
- keep `billing.sponsorship.blocked` observability-first
- do not emit per-request balance-transition spam while the org remains blocked

Implementation shape:

- sponsorship/billing writes state
- state transition emits webhook and observability log events
- dashboard/operator tooling reads those events

## Dashboard and operator UX

### Billing account page

Add sponsored-usage visibility to `/dashboard/billing/account`:

- current prepaid balance
- reserved sponsorship amount
- settled sponsored spend in the last 30/90 days
- low-balance and blocked banners tied to sponsorship impact
- recent sponsored execution charges

### Gas sponsorship page

Add balance-aware state to `/dashboard/gas-sponsorship`:

- policy cap status
- org prepaid balance status
- clear indication that prepaid balance can block sponsorship even when caps remain

### Customer-facing history

Provide a last-90-days sponsored usage view, backed by `console_sponsored_call_records`.

Backend API support is now landed at `/console/billing/sponsored-executions`, and reconciliation support is landed at `/console/billing/sponsored-executions/reconciliation`; the dedicated dashboard UI still needs to be wired.

The view should include:

- timestamp
- chain
- policy
- target/account
- tx/execution ref
- settled spend
- receipt status
- charged / not charged

## Retention and projections

Recommended retention model:

- keep billing ledger indefinitely
- keep sponsored execution history indefinitely for now
- optimize queries for last 90 days
- if scale requires it later, partition or archive old sponsored execution rows

Optional projection tables:

- daily sponsored spend by org
- daily sponsored spend by policy
- daily sponsored spend by chain

These should be derived read models, not source of truth.

## Phased implementation

### Phase 1: Billing contract changes

- [x] add `SPONSORED_EXECUTION_DEBIT` billing ledger entry type
- [x] add customer/account activity projection support for sponsored debits
- [x] add invoice/statement line-item support if statements continue to show usage debits
- [x] remove sponsored execution from the MAW-only metering path

### Phase 2: Prepaid reservation layer

- [x] add a prepaid sponsorship reservation store
- [x] compute org available balance as posted balance minus active reservations
- [x] make reservation and settlement idempotent on sponsorship `idempotencyKey`
- [x] add expiration / recovery logic for orphaned reservations
- [x] use a short TTL plus a sweeper for stale unresolved reservations
- [x] keep reservation transactions short and org-scoped so same-org burst contention stays bounded

### Phase 3: Shared sponsorship engine integration

- [x] add prepaid-balance reservation to the shared sponsorship engine
- [x] enforce org-balance gating for both EVM and NEAR
- [x] settle prepaid reservations from finalized spend
- [x] append billing ledger debits from settled sponsored spend
- [x] remove the non-atomic settlement fallback and require a shared Postgres runtime for settlement
- [x] release policy-cap reservations correctly on prepaid-balance failures
- [x] allow slight negative balance on underestimation, then block future sponsorship

### Phase 4: History and reconciliation

- [x] strengthen `console_sponsored_call_records` with explicit settled spend and pricing fields
- [x] add 90-day history APIs and indexes
- [x] add reconciliation views comparing sponsored execution history to billing debits

### Phase 5: Events and notifications

- [x] emit low-balance / blocked / recovered transition events
- [x] surface low-balance / blocked / recovered transitions in console observability logs
- [x] emit sponsorship-blocked events for operator observability
- [ ] decide later whether to add customer email delivery once billing contacts exist

### Phase 6: Dashboard and account UX

- [x] extend billing/account API surfaces with reserved sponsorship and sponsored-spend summary fields
- [x] surface reserved sponsorship amount in billing account views
- [x] show sponsored usage history and recent charges
- [x] show balance-blocked state in gas sponsorship UI
- [x] add actionable refill prompts when sponsorship is blocked by balance
- [x] keep billing documents aggregated while linking to per-tx sponsored history

### Phase 7: Validation and rollout

- [x] concurrency tests for reservation oversubscription
- [x] idempotency tests across retry/replay paths
- [x] EVM and NEAR charge/no-charge outcome tests
- [x] same-org burst tests, including hundreds of requests over a short interval
- [x] balance transition tests:
  - [x] healthy -> low
  - [x] low -> blocked
  - [x] blocked -> healthy
- [ ] notification dedupe tests

### Optional hardening after rollout

- [ ] explicit reserved-balance projection table or cached counter per org
- [ ] narrower locking strategy around one org balance/reservation row
- [ ] per-org queueing or rate limiting for extreme burst traffic
- [ ] operator observability for reservation contention and same-org sponsorship latency

## Testing expectations

Minimum required coverage:

- [x] sponsor execution settles real billable spend into prepaid debit
- [x] zero or negative available balance rejects sponsorship before execution
- [x] concurrent requests cannot overspend the same prepaid balance
- [x] reverted-but-gas-burned executions still debit prepaid balance correctly
- [x] non-broadcast failures do not create sponsored-execution debits
- [ ] NEAR gas-only charging excludes attached deposit
- [x] webhook/event transitions fire only once per state transition

## Recommended implementation order

1. Add the dedicated sponsored-execution billing debit model.
2. Add prepaid sponsorship reservations.
3. Integrate the reservation/debit path into the shared sponsorship engine.
4. Strengthen sponsored execution history and reporting.
5. Add transition events and email notifications.
6. Finish dashboard/account UX.

## Final desired state

After this plan lands:

- gas sponsorship is prepaid-backed
- policy caps and prepaid balance are enforced together
- prepaid balance depletion stops sponsorship automatically
- refilling prepaid balance restores sponsorship automatically
- each sponsored execution has:
  - execution history
  - settled billable spend
  - billing ledger linkage
- customers and operators can inspect the last 90 days of sponsored spend
- low-balance / blocked / recovered transitions trigger event-driven notifications

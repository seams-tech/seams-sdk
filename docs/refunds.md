# Refunds Plan

## Goal

Support narrow, operator-initiated refunds for obvious mistaken prepaid top-ups, without turning refunds into a general-purpose balance editing tool.

This is an exception workflow, not a change to the overall prepaid policy. Prepaid credits remain generally non-refundable. The supported carve-out is accidental duplicate or mistaken purchase handling.

## Product Rules

Refunds should be allowed only for purchase receipts, not for arbitrary account balance state.

Supported refund cases:

- duplicate accidental purchase
- immediate mistaken top-up
- duplicate settlement caused by retry or provider error

Not supported in the generic refund workflow:

- goodwill or SLA credits
- general commercial concessions
- fraud or chargeback handling
- hidden balance edits
- invoice row mutation

Those remain separate:

- goodwill or remediation uses manual support credit
- mistaken operator credits use manual admin debit
- disputes and chargebacks stay provider-driven reversal flows

## Eligibility Rules

Initial implementation should use the simplest safe rule set:

- purchase must be `SETTLED`
- purchase must have a linked purchase receipt
- purchase must not already be `REFUNDED` or `DISPUTED`
- refund must be full, not partial
- refund is allowed only if the credited amount is still fully unused
- refund action must require platform finance/admin permissions

Explicitly defer:

- partial refunds
- refunds after partial consumption
- self-serve customer refunds
- cross-purchase balance attribution logic

If credits from a purchase have already been consumed, the refund button should be blocked and the operator should use a separate finance/support process instead of forcing a mixed refund + clawback flow.

## Ledger Rules

Refunds must remain append-only.

Required accounting behavior:

- append a `REFUND` ledger entry
- never delete or rewrite the original `CREDIT_PURCHASE` entry
- never mutate historical activity rows in place
- update purchase status to `REFUNDED`
- keep the purchase receipt visible as historical evidence
- project resulting balance from ledger state

Chargebacks and disputes should not reuse the refund flow. They should remain separate reversal or clawback projections.

## Data Model Changes

### Purchase state

Update the billing purchase model to support refund and dispute lifecycle explicitly.

Planned changes:

- extend `BillingCreditPurchaseStatus` with:
  - `REFUNDED`
  - `DISPUTED`
- add purchase fields for:
  - `refundedAmountMinor`
  - `refundedAt`
  - `refundReasonCode`
  - `providerRefundRef`
  - `disputedAmountMinor`
  - `disputedAt`
  - `providerDisputeRef`
  - `lastProviderEventId`

### Ledger and documents

Use existing ledger support for:

- `REFUND`
- `REVERSAL`

Invoice projections should support:

- purchase receipt remains visible
- receipt/activity timeline shows refund event
- invoice status may remain `PAID` for the original receipt while timeline shows the later refund

Do not overload invoice voiding for purchase refunds. Invoice reversal should remain a separate document workflow.

## Backend Plan

### Phase 1: Domain model

- [ ] Extend `BillingCreditPurchaseStatus` with `REFUNDED` and `DISPUTED`.
- [ ] Add refund/dispute metadata to billing purchase records in memory and Postgres.
- [ ] Add typed refund result structures to the billing service interface.

### Phase 2: Service methods

- [ ] Add `refundCreditPurchase(...)` to the billing service.
- [ ] Add `canRefundCreditPurchase(...)` or equivalent eligibility helper.
- [ ] Add in-memory refund projection support.
- [ ] Add Postgres refund projection support.
- [ ] Enforce full-unused-only eligibility in one shared helper.

### Phase 3: Router surface

- [ ] Add a finance/platform route for refunding a purchase receipt or purchase ID.
- [ ] Validate actor role, idempotency key, reason code, and operator note.
- [ ] Reject requests for already-used or already-refunded purchases with explicit error codes.
- [ ] Return the updated purchase, resulting balance, and affected receipt/activity projections.

### Phase 4: Audit and observability

- [ ] Append `billing.credit_purchase.refunded` audit rows.
- [ ] Include metadata:
  - `organizationId`
  - `organizationName`
  - `purchaseId`
  - `receiptId`
  - `amountMinor`
  - `resultingBalanceMinor`
  - `reasonCode`
  - `note`
  - `providerRefundRef`
  - `created`
- [ ] Add observability events for refund processing failures and provider mismatch cases.

### Phase 5: UI

- [ ] Surface refund eligibility on purchase receipts and platform customer account activity.
- [ ] Add a dedicated refund action on the purchase/receipt detail, not in the generic manual-adjustment form.
- [ ] Show an explicit refund preview:
  - refund amount
  - resulting balance
  - purchase/receipt target
  - eligibility state
- [ ] Show blocked states clearly when credits have already been consumed.
- [ ] Surface refunded purchase state in platform billing and customer billing timelines.

## Disputes And Chargebacks

Do not merge these into the refund UI.

Plan them separately:

- ingest provider webhook events for disputes or chargebacks
- append `billing.credit_purchase.disputed` audit rows
- append `REVERSAL` or dispute-specific ledger effects as required by finance rules
- surface them in billing history and audit

This should remain a provider-driven or finance workflow, not a manual support action.

## Invoice Reversal Handling

Invoice reversal is related but separate.

Use cases:

- voiding an incorrectly generated usage statement
- marking a document `VOID` or `UNCOLLECTIBLE`
- preserving immutable history while changing current document state

Plan:

- [ ] Add explicit invoice reversal or void service methods instead of piggybacking on refunds.
- [ ] Emit `billing.invoice.voided` or `billing.invoice.canceled` audit rows.
- [ ] Surface reversed document state in invoice detail and platform audit.
- [ ] Keep purchase refunds and invoice reversal as separate operator actions.

## Guardrails

- Refunds must be append-only and auditable.
- Refunds must require explicit operator reason and note.
- Refunds must be idempotent.
- Refunds must be scoped to a specific purchase or receipt.
- Refunds must not silently repair unrelated balance problems.
- Refunds must not be exposed as a customer self-serve action in this phase.

## Recommended First Slice

Implement the smallest useful version first:

1. Add refund state to purchases.
2. Add backend eligibility checks for fully unused settled purchases.
3. Add a platform-admin or finance-only refund endpoint.
4. Append `REFUND` ledger entries and `billing.credit_purchase.refunded` audit rows.
5. Show refunded state in purchase receipt detail and `/dashboard/audit`.

Defer partial refunds, consumed-balance refunds, and dispute recovery until there is a real operational need.

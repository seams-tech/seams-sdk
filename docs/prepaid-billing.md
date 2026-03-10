# Prepaid Billing Plan

## Objective

Replace subscription lifecycle billing with an org-scoped prepaid billing system built on a ledger-first model.

Target properties:

1. immutable journal entries
2. strict per-org account segregation
3. balances derived from postings, not edited state
4. compensating entries instead of record mutation
5. receipts, statements, and account views generated from stable projections

This is a hard model replacement. We are in development, so no legacy subscription compatibility layer should remain.

## Document Role

This is the canonical billing architecture and migration document.

Use this file for:

- billing domain language
- ledger model
- journal and projection design
- schema direction
- phased migration order

Use [billing-2.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/billing-2.md) only for the remaining operational follow-up work after the core prepaid migration.

## Status Snapshot (2026-03-11)

Implemented now:

- Billing is split into `/dashboard/billing/account`, `/dashboard/invoices`, and `/dashboard/invoices/:invoiceId`
- One-time Stripe checkout settles prepaid credit purchases
- Usage is rated into debit entries and surfaced in usage statements
- Receipt and statement history, filters, pagination, detail pages, and PDF export are live
- Subscription lifecycle routes, UI, DTOs, and settlement rails have been removed
- Direct invoice-settlement tables and routes have been removed from the active backend surface
- Billing activity is document-and-ledger based, not payment-intent based
- Postgres billing test coverage has been rewritten to prepaid-only semantics
- The Postgres billing path now has canonical `ledger_accounts`, `ledger_entries`, and `ledger_postings`
- Active credit-purchase settlement and usage debit writes now create balanced journal postings
- Org balance sync in the Postgres billing path is now derived from ledger postings
- The Postgres billing path now rebuilds receipt and usage-statement projections from purchase and journal state
- Invoice/account reads in the Postgres billing path now refresh document projections before serving
- The in-memory billing service now derives invoices, line items, and activity from purchase and ledger state instead of mutable invoice/document maps
- The invoice console no longer fans out account-shell billing reads on `/dashboard/invoices`
- The Postgres billing path now uses a consistent overview/MAW lock order to avoid the observed `deadlock detected` failure on invoice entry
- Regression coverage now exists for the invoice-route shell fetch path and the concurrent overview/MAW billing-service path

Still to finish:

- Finish routing any future financial writes, including operator adjustments, through the canonical journal
- Prove projection rebuilding end-to-end against a real Postgres instance
- Enforce zero-balance and low-balance policy in the real production execution path
- Add internal operator adjustments as append-only journal entries
- Decide the final Stripe account-management path and delete the unused one
- Validate the final ledger-first model against a real Postgres instance with `POSTGRES_URL` set
- Validate the overview/MAW deadlock regression against a live Postgres instance

## Product Shape

Expose billing through two sidebar routes:

- `/dashboard/billing/account`
- `/dashboard/invoices`
- `/dashboard/invoices/:invoiceId`

View responsibilities:

- `Billing account`
  - projected prepaid balance
  - recent usage and spend summary
  - top-up actions
  - payment methods
  - low-balance / blocked-state messaging
  - internal operator adjustment tools, if enabled for staff
- `Invoices`
  - purchase receipts
  - usage statements
  - status and period filters
  - PDF download
- `Invoice detail`
  - document metadata
  - line items
  - ledger-linked activity
  - PDF download

## Core Principles

1. Append-only journal.
   - Billing writes must only append new records.
   - No updates or deletes to settled billing history.

2. Balances are projections.
   - Customer balance is derived from journal postings.
   - Cached balance rows are projections, not source of truth.

3. Compensating entries only.
   - Corrections append new entries.
   - Historical billing records are never edited in place.

4. Strict account segregation.
   - Each org has its own prepaid liability account.
   - Platform-side accounts remain separate from customer-scoped accounts.

5. Idempotent financial writes.
   - Every external billing event must carry an idempotency key or stable source event id.
   - Replays must not create duplicate financial impact.

6. Full traceability.
   - Every journal entry must capture actor, reason, source reference, related document ids, and timestamps.

## Canonical Target Model

### Source of truth

The source of truth is the journal, not `billing_account.credit_balance_minor` or any mutable balance field.

Canonical write model:

- `ledger_account`
- `ledger_entry`
- `ledger_posting`

Canonical read models:

- org balance projection
- receipt projection
- usage statement projection
- account activity projection
- low-balance / blocked-state projection

### Recommended accounting model

Use double-entry accounting.

Each business event creates one journal entry with two or more postings that net to zero.

That gives us:

- invariant checks for balanced writes
- safer reconciliation
- better auditability
- cleaner reporting and finance integration later

## Ledger Accounts

### Customer-scoped accounts

Per org:

- `org_prepaid_liability:{orgId}`
- `org_usage_consumption:{orgId}` if a supporting customer-side account is useful for reporting

### Platform accounts

Platform-level:

- `processor_clearing:stripe`
- `revenue_usage`
- `expense_support_credit`
- `suspense_admin_debit`
- `loss_chargeback` if needed later
- `suspense_reconciliation` for exceptional system-only recovery flows

## Canonical Business Events And Postings

### Credit purchase settlement

When Stripe checkout settles:

- debit `processor_clearing:stripe`
- credit `org_prepaid_liability:{orgId}`

Effects:

- projected customer balance increases
- purchase receipt is generated or refreshed

### Usage debit

When usage is rated:

- debit `org_prepaid_liability:{orgId}`
- credit `revenue_usage`

Effects:

- projected customer balance decreases
- usage statement projection updates

### Manual support credit

When internal staff grants corrective credit:

- debit `expense_support_credit`
- credit `org_prepaid_liability:{orgId}`

Effects:

- projected customer balance increases
- account activity shows a manual credit entry

### Manual admin debit

When internal staff appends a corrective debit:

- debit `org_prepaid_liability:{orgId}`
- credit `suspense_admin_debit` or another explicit correction account

Effects:

- projected customer balance decreases
- account activity shows a manual debit entry
- the action stays visible and correctable through future compensating entries

### Refund or chargeback

Do not expose this as a generic support tool.

If we implement it later, it should be a dedicated system or finance workflow, not a broad dashboard action.

## Operator Policy

Supported operator actions:

- append manual support credits
- append manual admin debits

Not supported:

- direct balance mutation
- editing or deleting historical billing rows
- hidden or in-place reversals
- direct SQL correction as an operating procedure

Principle:

- operators may add or remove value only through explicit journal entries that remain visible forever

## Operator Use Cases

### Manual support credits should cover

- processor charged successfully but settlement projection failed
- duplicate usage debit or overbilling bug
- migration correction in the customer's favor
- SLA / incident remediation credit
- promotional or goodwill credit
- temporary recovery credit during provider outage

### Manual admin debits should cover

- mistaken support credit that must be corrected
- duplicate purchase settlement that credited the org twice
- migration over-credit correction
- explicit internal billing correction approved by finance or ops

### Cases that should not use generic operator tooling

- chargeback clawbacks
- fraud clawbacks
- platform-side reconciliation mismatches that need engineering repair
- settlement anomalies that require provider-specific recovery logic

## Required Guardrails

1. Only internal billing admins may append manual credits or debits.
2. Every operator adjustment must require:
   - positive amount
   - reason code
   - operator note
   - idempotency key
3. Every operator adjustment must be append-only.
4. Large debits should require stronger authorization or secondary approval.
5. Every operator adjustment must be audit-logged.
6. The UI must preview the resulting projected balance before confirmation.
7. Normal org admins must not see internal adjustment controls.

## Schema Direction

### Canonical write tables

- `console_billing_ledger_accounts`
- `console_billing_ledger_entries`
- `console_billing_ledger_postings`

### Projection tables

- `console_billing_account_balances`
- `console_billing_documents`
- `console_billing_document_line_items`
- `console_billing_activity_projection`

### Minimum fields

`console_billing_ledger_accounts`

- `namespace`
- `id`
- `scope_type`
- `scope_org_id`
- `account_code`
- `currency`
- `status`
- `created_at_ms`

`console_billing_ledger_entries`

- `namespace`
- `id`
- `entry_type`
- `actor_type`
- `actor_user_id`
- `reason_code`
- `note`
- `source_event_id`
- `idempotency_key`
- `created_at_ms`

`console_billing_ledger_postings`

- `namespace`
- `id`
- `entry_id`
- `account_id`
- `org_id`
- `direction`
- `amount_minor`
- `currency`
- `related_document_id`
- `related_purchase_id`
- `created_at_ms`

`console_billing_account_balances`

- `namespace`
- `org_id`
- `projected_balance_minor`
- `low_balance_threshold_minor`
- `enforcement_state`
- `updated_at_ms`

## Migration Policy

Breaking changes are acceptable.

Migration rules:

1. Keep the prepaid product behavior already shipped.
2. Replace the remaining single-entry-style implementation with double-entry journal tables.
3. Rebuild balance and document projections from the journal.
4. Delete superseded balance/account code in the same phase.
5. Do not support dual billing models long term.
6. Do not retain subscription-era concepts once their replacement is live.

## Phased Todo List

### Phase 0: Remove subscriptions and settlement rails

Backend logic:

- [x] Delete subscription lifecycle services, DTOs, and controller logic.
- [x] Delete direct invoice-settlement routes and provider-specific settlement flows.
- [x] Remove subscription-specific webhook handling from the active prepaid path.

DB schema:

- [x] Drop subscription-era tables, columns, and indexes.
- [x] Drop invoice-settlement tables and related schema objects.

Console UI:

- [x] Remove subscription lifecycle UI and wording.
- [x] Split billing into account and invoices surfaces.

### Phase 1: Stabilize prepaid purchase and usage flows

Backend logic:

- [x] Add one-time checkout sessions for credit packs.
- [x] Settle purchases into prepaid balance.
- [x] Rate usage into debit entries.
- [x] Keep reusable payment-method flows.

DB schema:

- [x] Add prepaid purchase tables and usage/balance support tables.
- [x] Add idempotency-safe purchase and usage constraints.

Console UI:

- [x] Add top-up actions, balance summary, receipts, statements, and PDF export.
- [x] Remove all recurring-plan semantics.

### Phase 2: Introduce ledger accounts, entries, and postings

Backend logic:

- [x] Add a journal writer that creates entries plus balanced postings.
- [x] Add invariant checks that reject unbalanced entries.
- [x] Route purchase settlement through the journal writer.
- [x] Route usage debits through the journal writer.
- [ ] Route operator credits and debits through the journal writer.
- [ ] Define canonical entry types:
  - `CREDIT_PURCHASE_SETTLED`
  - `USAGE_DEBIT_RECORDED`
  - `MANUAL_SUPPORT_CREDIT_GRANTED`
  - `MANUAL_ADMIN_DEBIT_APPENDED`

DB schema:

- [x] Add `console_billing_ledger_accounts`.
- [x] Add `console_billing_ledger_entries`.
- [x] Add `console_billing_ledger_postings`.
- [x] Add uniqueness constraints for idempotency keys.
- [x] Add balanced-entry and positive-posting invariants where practical.

Migrations:

- [x] Seed platform accounts.
- [x] Seed per-org prepaid liability accounts.
- [ ] Backfill opening journal entries if needed.
- [x] Backfill postings for legacy single-entry rows during schema bootstrap.
- [ ] Delete superseded single-entry helper paths after cutover.

### Phase 3: Rebuild projections from the journal

Backend logic:

- [x] Build org balance projections from journal postings.
- [x] Build receipt projections from settlement entries.
- [x] Build usage statement projections from usage entries.
- [x] Build account activity projections from journal + document links.

DB schema:

- [ ] Add or revise projection tables for balances, documents, and activity.
- [ ] Add indexes for org/account/document lookups.

Migrations:

- [ ] Recompute projected balances from journal state.
- [ ] Recompute receipts and statements from journal state.
- [ ] Delete deprecated projection code that reads pre-ledger semantics.

Console UI:

- [x] Keep the Postgres-backed `/dashboard/billing/account` reads projection-only.
- [x] Keep the Postgres-backed `/dashboard/invoices` and detail pages projection-only.
- [x] Surface ledger-linked activity cleanly.

### Phase 4: Enforce balance policy in the real execution path

Backend logic:

- [ ] Add a single enforcement helper that consumes projected available balance.
- [ ] Define enforcement states:
  - `HEALTHY`
  - `LOW_BALANCE`
  - `BLOCKED`
- [ ] Enforce zero-balance / low-balance policy in the production execution path.
- [ ] Allow explicit local/dev bypass only if intentionally configured.

DB schema:

- [ ] Add `enforcement_state` to balance projections if useful.
- [ ] Add any projection metadata needed for efficient gating.

Console UI:

- [ ] Show low-balance and blocked states clearly.
- [ ] Explain what happens at zero balance.
- [ ] Optionally show projected runway.

### Phase 5: Internal operator adjustments

Backend logic:

- [ ] Add `grantManualSupportCredit`.
- [ ] Add `appendManualAdminDebit`.
- [ ] Implement both as journal entries plus balanced postings.
- [ ] Restrict both to internal billing admins only.
- [ ] Require positive amount, reason code, note, and idempotency key.
- [ ] Audit-log every invocation.

DB schema:

- [ ] Add any missing operator-adjustment metadata fields.
- [ ] Add indexes for operator review and audit queries.

Console UI:

- [ ] Add an internal-only billing-adjustments panel on `/dashboard/billing/account`.
- [ ] Show impact preview before confirmation.
- [ ] Surface both manual credits and manual debits in account activity.

### Phase 6: Documents, audit, and exports

Backend logic:

- [ ] Audit-log every operator adjustment and PDF export.
- [ ] Keep document activity projection in sync with ledger-linked events.
- [ ] Decide whether immutable document snapshots are required beyond deterministic rendering.

DB schema:

- [ ] Add snapshot storage only if deterministic rendering is insufficient.
- [ ] Add structured audit payload fields if current audit storage is too generic.

Console UI:

- [ ] Show manual adjustment activity where document-linked.
- [ ] Keep PDF export policy explicit for internal vs customer-facing visibility.

### Phase 7: Stripe account-management decision and final cleanup

Decision:

Choose one path and delete the other.

Option A: Keep customer portal

- use it only for billing-profile / payment-method management
- keep top-ups as checkout sessions
- keep all copy strictly prepaid

Option B: Remove customer portal

- use setup-intent plus app-owned payment-method CRUD only
- delete customer-portal session creation entirely

Cleanup tasks:

- [ ] Pick one path.
- [ ] Delete the unused backend route, service, and provider hook.
- [ ] Delete the unused UI controls and copy.
- [ ] Update tests and docs.
- [ ] Run full validation against a real Postgres instance.

### Validation Note

The `deadlock detected` issue previously seen on `/dashboard/invoices` came from two separate problems:

- the invoices route was still issuing account-shell fetches it did not need
- `getOverview()` and `getMonthlyActiveWallets()` acquired Postgres locks in different orders

Both code paths are now fixed. The remaining work is to validate that fix against a real Postgres instance with `POSTGRES_URL` set and keep regression coverage in place.

## Next Implementation Steps

1. Introduce ledger accounts, entries, and postings as the canonical write path.
2. Rebuild balances and documents as projections from the journal.
3. Enforce zero-balance / low-balance policy in the real production path.
4. Add internal operator credits and debits as append-only journal actions.
5. Choose a single Stripe account-management path and delete the unused one.

## Definition Of Done

This migration is done when:

- billing writes go through an append-only journal
- customer balances are derived projections, not mutable source rows
- customer prepaid value is segregated per org
- receipts and statements are projection-only views over journal-backed data
- production balance enforcement works end-to-end
- internal staff can append audited corrective credits and debits without direct DB edits
- account and invoice pages contain no subscription-era concepts
- Postgres-backed billing suites pass against a real database

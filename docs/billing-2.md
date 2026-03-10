# Billing Phase 2 Follow-Up

## Objective

Track the remaining operational work after the prepaid migration.

This document is not the canonical billing architecture spec.

The canonical source of truth for the billing model is [prepaid-billing.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/prepaid-billing.md).

Use this file only for:

- remaining implementation work
- rollout sequencing
- operator workflow decisions
- validation and cleanup tasks

## Assumptions

This follow-up plan assumes the canonical model defined in `prepaid-billing.md`:

- append-only journal
- balances as projections
- strict per-org account segregation
- double-entry postings as the target write path
- operator credits and debits as explicit journal entries
- receipts and statements as projection views, not mutable source records

## Current State

Already done:

- account and invoice routes are split and live
- prepaid top-ups, receipts, statements, filters, and PDF export are live
- subscription lifecycle and direct settlement rails have been removed
- billing activity is already document-and-ledger oriented
- test coverage has been rewritten to prepaid-only behavior

Still open:

- move the current prepaid write path onto canonical ledger accounts, entries, and postings
- rebuild balances and documents as explicit projections from the journal
- enforce zero-balance and low-balance policy in the real production execution path
- add internal operator adjustments as append-only journal events
- choose the final Stripe account-management path and delete the unused one
- validate the final model against a real Postgres instance

## Operator Adjustment Policy

Operator actions are allowed, but only as append-only journal events.

Supported operator actions:

- manual support credit
- manual admin debit

Not allowed:

- direct balance edits
- editing or deleting historical billing rows
- hidden or in-place reversals
- direct SQL correction workflows

Required guardrails:

1. Only internal billing admins may append operator adjustments.
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

Supported use cases:

- missed purchase settlement projection
- duplicate usage debit or overbilling correction
- mistaken support credit correction
- duplicate purchase settlement correction
- migration correction
- incident or goodwill credit
- explicit internal finance / ops correction

Cases that should stay outside generic operator tooling:

- chargeback clawbacks
- fraud clawbacks
- provider-specific reconciliation repair
- platform-side accounting repair that is not customer-scoped

## Workstreams

### Workstream 1: Canonical ledger write path

Goal:

Replace the remaining prepaid write implementation with canonical journal writes backed by:

- `console_billing_ledger_accounts`
- `console_billing_ledger_entries`
- `console_billing_ledger_postings`

Tasks:

- add balanced journal writer
- add invariant checks for unbalanced entries
- route purchase settlement through journal entries
- route usage debits through journal entries
- route operator credits and debits through journal entries
- add idempotency enforcement on journal writes

Exit criteria:

- all billing writes go through journal entries plus postings
- no mutable balance field remains a source of truth

### Workstream 2: Projection rebuild

Goal:

Make account balance, receipts, statements, and activity explicit projections from the journal.

Tasks:

- build org balance projections from postings
- build receipt projections from purchase settlement entries
- build statement projections from usage entries
- build account and document activity projections from journal-linked events
- keep projection rebuilding deterministic and replayable

Exit criteria:

- `/dashboard/billing/account` is projection-only
- `/dashboard/invoices` and detail pages are projection-only
- projection rebuilding is deterministic from journal state

### Workstream 3: Balance enforcement

Goal:

Block or degrade production usage when projected balance policy requires it.

Tasks:

- add a single enforcement helper
- define `HEALTHY`, `LOW_BALANCE`, and `BLOCKED`
- wire enforcement into the real execution path
- allow explicit local/dev bypass only if intentionally configured
- surface low-balance and blocked states in the billing UI

Exit criteria:

- production usage is gated by projected balance state
- low-balance warnings are visible in the account UI

### Workstream 4: Operator adjustments and auditability

Goal:

Add internal operator adjustments without compromising journal integrity.

Tasks:

- add `grantManualSupportCredit`
- add `appendManualAdminDebit`
- require positive amount, reason code, note, and idempotency key
- audit-log every operator adjustment
- surface operator adjustments in account activity
- surface document-linked adjustment activity where relevant

Exit criteria:

- internal staff can append fully auditable corrective credits and debits
- adjustments are visible in projections and timelines

### Workstream 5: Stripe path decision

Goal:

Delete one of the remaining account-management paths.

Decision:

Choose one:

- keep customer portal only for billing-profile / payment-method management
- remove customer portal and keep setup-intent plus app-owned payment-method CRUD only

Tasks:

- choose one path
- delete the unused backend route/service/provider hook
- delete the unused UI controls and copy
- update tests and docs

Exit criteria:

- only one Stripe account-management path remains

### Workstream 6: Postgres validation and cleanup

Goal:

Validate the final ledger-first model and remove leftover naming or migration clutter.

Tasks:

- run billing Postgres suites against a real Postgres instance
- validate schema bootstrap on an existing dev database
- confirm deleted settlement tables stay gone
- confirm runtime reads use journal/projection tables only
- remove stale migration helpers and outdated naming where worth the churn

Exit criteria:

- Postgres billing suites pass against a real database
- no old settlement or subscription storage remains in the active path

## Recommended Execution Order

1. Canonical ledger write path
2. Projection rebuild
3. Balance enforcement
4. Operator adjustments and auditability
5. Stripe path decision
6. Postgres validation and cleanup

## Definition Of Done

This follow-up phase is done when:

- the canonical ledger write path is active
- balances and documents are derived projections
- production balance enforcement works end-to-end
- operator credits and debits are append-only and fully auditable
- only one Stripe account-management path remains
- Postgres-backed billing suites pass against a real database

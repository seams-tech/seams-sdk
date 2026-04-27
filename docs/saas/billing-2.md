# Billing Phase 2 Follow-Up

## Objective

Track the remaining operational work after the prepaid migration.

This document is not the canonical billing architecture spec.

The canonical source of truth for the billing model is [prepaid-billing.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/prepaid-billing.md).

This follow-up plan also assumes [billing-cleanup.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/billing-cleanup.md) is authoritative for removing stored payment methods and Stripe billing-management flows. Remaining work in this file must not preserve or reintroduce those deleted paths.

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
- Postgres billing now has canonical ledger accounts, entries, and postings
- Active purchase settlement and usage debit writes now create balanced journal postings
- Postgres org balance sync now derives from ledger postings
- Postgres receipt and usage-statement projections now rebuild from purchase and journal state
- Postgres invoice reads now refresh projections before serving account and invoice data
- The in-memory billing service now derives invoices, line items, and activity from purchase and ledger state instead of mutable invoice/document maps
- `/dashboard/invoices` no longer issues account-shell billing fetches that it does not need
- The Postgres billing overview and MAW read paths now use a consistent lock order to prevent the observed invoice-page deadlock
- Regression coverage now exists for the invoice-route shell fetch path and the concurrent overview/MAW billing-service path
- The dashboard billing Playwright harness now mounts `/dashboard/billing/account` and `/dashboard/invoices` again after fixing the SDK worker bundle export mismatch that was crashing the app before render
- Backend operator adjustment methods and routes now exist for manual support credits and manual admin debits
- Operator adjustments now append audited `MANUAL_ADJUSTMENT` journal entries without reviving removed payment-method flows
- `/dashboard/billing/account` now exposes ledger-backed account activity that includes manual credits and debits
- `/dashboard/billing/account` now includes admin-only adjustment controls with projected-balance impact preview
- UI coverage now asserts admin-only visibility and preview behavior for manual adjustments
- Manual adjustment requests now support optional `relatedInvoiceId` linking, and linked adjustments surface on invoice activity timelines
- Linked manual adjustments are now explicitly marked as internal-only timeline events, and exported PDFs now use a customer-facing policy that excludes internal ledger adjustments
- Large manual admin debits now require `owner` role when amount is at least $500.00
- Billing overview now exposes shared `HEALTHY`, `LOW_BALANCE`, and `BLOCKED` readiness state derived from projected balance
- Project creation, live-environment gating, onboarding readiness, and billing warning UI now share one projected-balance enforcement helper
- Console routers now support an explicit `allowLiveEnvironmentBillingBypass` escape hatch for local/dev provisioning, with regression coverage for both Express and Cloudflare paths

Still open:

- finish the remaining journal migration for any future financial write paths
- prove deterministic projection rebuilding against a real Postgres instance
- keep the prepaid Stripe surface checkout-only and prevent legacy Stripe-management flows from reappearing
- validate the final model against a real Postgres instance with `POSTGRES_URL` set
- validate the deadlock fix against a live Postgres instance
- confirm there are no unintended runtime entry points that bypass the shared readiness helper outside the explicit `allowLiveEnvironmentBillingBypass` option
- the current environment still does not expose `POSTGRES_URL`, so live-Postgres validation remains blocked here

## Remaining Steps

1. Real Postgres validation
   - run the rewritten Postgres suites
   - validate concurrent overview / MAW reads, operator adjustments, and readiness-state enforcement on live Postgres
   - confirm projection rebuild and schema bootstrap behavior
   - unblock by running with `POSTGRES_URL` set
2. Operator adjustment UI and visibility
   - keep document-link behavior explicit in customer-facing vs internal surfaces
   - no separate adjustment-linked immutable snapshots; linked adjustments stay internal timeline events only
3. Cleanup follow-through
   - keep the prepaid checkout flow only
   - prevent any removed Stripe-management surface from reappearing after `billing-cleanup.md`
   - finish legacy deletion once the ledger-first flow is complete

## Next Steps (2026-03-11)

### Phase A: Operator controls

- [x] Add internal-only adjustment controls on `/dashboard/billing/account`.
- [x] Add projected-balance impact preview before operator confirmation.
- [x] Add UI tests for admin-only visibility and preview behavior.

### Phase B: Document-linked visibility

- [x] Surface adjustment activity on relevant document timelines.
- [x] Decide whether adjustment-linked document snapshots are required.
- [x] Keep PDF visibility rules explicit for internal vs customer-facing views.

### Phase C: Live Postgres validation

- [ ] Run billing Postgres suites with `POSTGRES_URL` set and record outcomes.
- [ ] Validate schema bootstrap + projection rebuild on an existing dev database.
- [ ] Re-run concurrent `getOverview()` / `getMonthlyActiveWallets()` validation on live Postgres.

### Phase D: Enforcement path

- [x] Implement one projected-balance enforcement helper.
- [x] Define `HEALTHY`, `LOW_BALANCE`, and `BLOCKED`.
- [x] Wire `HEALTHY`, `LOW_BALANCE`, and `BLOCKED` to real production execution.
- [x] Add explicit local/dev bypass only if intentionally configured.
- [x] Expose low-balance / blocked state messaging consistently in the UI.
- [ ] Validate the shared readiness helper against live Postgres and any remaining runtime entry points.

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
   - implemented: owner role required for manual admin debits >= $500.00
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

## Phased Todo List

### Phase 1: Canonical ledger write path

- [x] Add `console_billing_ledger_accounts`.
- [x] Add `console_billing_ledger_entries`.
- [x] Add `console_billing_ledger_postings`.
- [x] Add balanced journal writer invariants.
- [x] Route purchase settlement through journal entries and postings.
- [x] Route usage debits through journal entries and postings.
- [x] Route operator credits and debits through journal entries and postings.
- [x] Add idempotency enforcement on journal writes.

### Phase 2: Projection rebuild

- [x] Build org balance projections from ledger postings.
- [x] Build receipt projections from purchase settlement entries.
- [x] Build usage statement projections from usage entries.
- [x] Build account and document activity projections from journal-linked events.
- [x] Make the Postgres-backed `/dashboard/billing/account` reads projection-only.
- [x] Make the Postgres-backed `/dashboard/invoices` and invoice detail reads projection-only.
- [x] Remove duplicated mutable invoice/document state from the in-memory billing helper path.
- [ ] Ensure projection rebuilding is deterministic from journal state.

### Phase 3: Balance enforcement

- [x] Add a single projected-balance enforcement helper.
- [x] Define `HEALTHY`, `LOW_BALANCE`, and `BLOCKED`.
- [x] Wire enforcement into the real production execution path.
- [x] Add explicit local/dev bypass only if intentionally configured.
- [x] Surface low-balance and blocked states in the billing UI.

### Phase 4: Operator adjustments and auditability

- [x] Add `grantManualSupportCredit`.
- [x] Add `appendManualAdminDebit`.
- [x] Require positive amount, reason code, note, and idempotency key.
- [x] Audit-log every operator adjustment.
- [x] Surface operator adjustments in account activity.
- [x] Surface document-linked adjustment activity where relevant.
- [x] Add stronger authorization or approval for large debits.

### Phase 5: Stripe prepaid-path cleanup

- [x] Decide Stripe surface: checkout-session top-ups only.
- [x] Remove customer-portal route, service, and provider hook.
- [x] Remove setup-intent route, service, and provider hook.
- [x] Remove app-owned payment-method CRUD route, service, and storage path.
- [x] Delete unused UI controls and copy.
- [x] Update tests and docs to the single supported path.

### Phase 6: Postgres validation and cleanup

- [ ] Run billing Postgres suites against a real Postgres instance.
- [ ] Validate schema bootstrap on an existing dev database.
- [ ] Validate concurrent `getOverview()` and `getMonthlyActiveWallets()` reads against live Postgres.
- [x] Keep regression coverage for the invoice-route deadlock path.
- [ ] Confirm deleted settlement tables stay gone.
- [ ] Confirm runtime reads use journal/projection tables only.
- [ ] Remove stale migration helpers and outdated naming where worth the churn.

### Phase 6.5: Dashboard billing validation cleanup

- [x] Repair the dashboard billing Playwright harness to mount the canonical billing routes again.
- [x] Re-enable passing browser coverage for top-ups, manual adjustments, and invoice navigation.

### Phase 7: Legacy removal and hard cleanup

- [ ] Remove any remaining legacy billing code paths that bypass the canonical journal/projection model.
- [ ] Remove deprecated billing service methods, adapters, DTOs, and request parsers tied to the old model.
- [ ] Remove legacy data structures that duplicate balance, document, or activity state outside the target ledger/projection design.
- [ ] Drop any leftover DB tables, columns, indexes, constraints, triggers, or helper functions associated with the old billing model.
- [ ] Remove stale tests, fixtures, and seeding paths that still describe pre-ledger or pre-prepaid billing behavior.
- [ ] Remove obsolete docs and comments that describe the retired billing model.
- [ ] Verify there are no remaining runtime reads or writes against retired billing storage.

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

- all active financial writes go through journal entries plus postings
- no mutable balance field remains a source of truth for active read paths

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

### Workstream 5: Stripe prepaid-path cleanup

Goal:

Keep only prepaid checkout-session top-ups and remove retired account-management surfaces.

Decision:

- remove customer portal
- remove setup intent
- remove app-owned payment-method CRUD
- keep checkout-session top-up flow only

Tasks:

- remove retired backend routes/service/provider hooks
- remove retired UI controls and copy
- update tests and docs

Exit criteria:

- only the checkout-session prepaid top-up path remains

### Workstream 6: Postgres validation and cleanup

Goal:

Validate the final ledger-first model and remove leftover naming or migration clutter.

Tasks:

- run billing Postgres suites against a real Postgres instance
- validate schema bootstrap on an existing dev database
- validate concurrent overview/MAW reads against live Postgres
- keep deadlock regression coverage for the invoice route and billing service
- confirm deleted settlement tables stay gone
- confirm runtime reads use journal/projection tables only
- remove stale migration helpers and outdated naming where worth the churn

Exit criteria:

- Postgres billing suites pass against a real database
- no old settlement or subscription storage remains in the active path

### Workstream 7: Legacy removal and hard cleanup

Goal:

Delete the remaining code, data structures, and schema artifacts associated with the retired billing model.

Tasks:

- remove legacy billing code paths that bypass the canonical journal/projection flow
- remove deprecated service methods, adapters, DTOs, and request parsers
- remove duplicated legacy balance/document/activity structures
- drop retired DB tables, columns, indexes, constraints, triggers, and helper functions
- remove stale tests, fixtures, and seed data for the retired billing model
- remove obsolete docs and comments that describe the old billing behavior

Exit criteria:

- no legacy billing runtime path remains
- no legacy billing schema object remains
- no active tests or docs describe the retired model as current behavior

## Recommended Execution Order

1. Canonical ledger write path
2. Projection rebuild
3. Operator adjustments and auditability
4. Balance enforcement
5. Stripe prepaid-path cleanup
6. Postgres validation and cleanup
7. Legacy removal and hard cleanup

## Definition Of Done

This follow-up phase is done when:

- the canonical ledger write path is active
- balances and documents are derived projections
- production balance enforcement works end-to-end
- operator credits and debits are append-only and fully auditable
- only the checkout-session prepaid top-up path remains
- Postgres-backed billing suites pass against a real database
- no legacy billing code path, data structure, or schema object remains in the active product

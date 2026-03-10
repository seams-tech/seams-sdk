# Prepaid Billing Plan

## Objective

Replace subscription lifecycle billing with an org-scoped prepaid balance model.

Customers should:

1. Buy prepaid credit packs.
2. Consume balance as they use the product.
3. View current balance, usage, receipts, and statements from the dashboard.

The target model is closer to usage-based compute platforms than subscription SaaS:

- no recurring subscription status
- no cancel / resume lifecycle
- no renewal state
- no "current period" subscription semantics
- no mandatory customer portal dependency for plan lifecycle

We are in development, so this should be treated as a hard model replacement, not a legacy-compatible layer.

## Status snapshot (2026-03-10)

Implemented now:

- Prepaid balance overview, credit-pack top-ups, and payment-method management on `/dashboard/billing/account`
- Receipt / usage-statement history, filters, pagination, detail pages, and PDF export on `/dashboard/invoices`
- One-time Stripe checkout settlement into prepaid balance with receipt generation
- Usage debits rated into ledger entries and synced into monthly usage statements
- Legacy subscription routes removed from the dashboard and console router surface
- Dead dashboard billing client helpers for direct payment intents and stablecoin invoice settlement removed
- Remaining direct invoice-settlement backend routes removed from the console router surface
- Shared billing service contracts, request parsers, provider hooks, and dashboard DTOs now expose prepaid-only fields
- Invoice detail activity is now document-and-ledger only; payment-intent and rail metadata are removed from the active prepaid surface
- Postgres billing bootstrap now destructively drops the deleted settlement tables and removes invoice/webhook rail fields that no longer belong to the prepaid model
- Postgres billing service and tenant-isolation suites are rewritten to prepaid-only receipt / statement / ledger coverage

Still to finish:

- Enforce zero-balance or low-balance gating in the production product path
- Add manual adjustment / reversal flows with audit logging
- Decide whether PDF exports need stored immutable snapshots beyond the current deterministic statement / receipt model

## Product shape

Expose billing through two sidebar routes:

- `/dashboard/billing/account`
- `/dashboard/invoices`
- `/dashboard/invoices/:invoiceId`

View responsibilities:

- `Billing account`
  - current prepaid balance
  - recent spend summary
  - top-up actions
  - payment methods
  - balance warning / depletion state
- `Invoices`
  - purchase receipts
  - usage statements
  - invoice / receipt statuses
  - PDF download
- `Invoice detail`
  - receipt or statement metadata
  - line items
  - debits / credits summary
  - PDF download

## Canonical product rules

These rules should be locked before implementation starts:

1. Balance is org-scoped.
2. Customers buy credits, not months and not subscriptions.
3. Usage burns down credits.
4. Credit purchases are one-time checkout actions.
5. Payment methods remain reusable, but subscription lifecycle management is deleted.
6. Receipts are generated for credit purchases.
7. Statements or invoices may still be generated for usage reporting, but they no longer drive subscription collection state.
8. When balance reaches zero, production usage is blocked unless we intentionally define a grace policy.

Open policy decisions that must be made explicitly:

- pack sizes and pricing, for example `$50`, `$200`, `$500`, `$1,000`
- whether credits expire
- whether negative balance is ever allowed
- whether statements are monthly, rolling, or only generated on demand
- whether stablecoin top-ups launch in phase 1 or later

## Phased todo list

This is the execution checklist. Each phase should end with the old subscription-era code deleted for that area before the next phase begins.

### Phase 1: Lock the prepaid model and delete subscription concepts

Backend logic:

- [x] Delete subscription lifecycle services, DTOs, and controller logic that model recurring plan state.
- [x] Rename billing service interfaces around `balance`, `ledger`, `credit purchase`, and `statement`.
- [x] Remove subscription-specific webhook handling that exists only to maintain recurring state.
- [ ] Replace readiness and enforcement checks that read subscription status with balance-policy checks.

DB schema:

- [x] Add canonical prepaid entities:
  - `billing_account`
  - `billing_ledger_entry`
  - `billing_credit_purchase`
  - `billing_statement`
- [x] Add immutable event references and audit columns required for ledger correctness.
- [x] Add low-balance threshold and available-balance fields at the org billing-account level.

Migrations:

- [x] Create new prepaid tables in a single forward-only migration set.
- [x] Delete obsolete subscription tables or columns that are no longer part of the target model.
- [x] Drop indexes and foreign keys that only support subscription-era reads and writes.
- [x] Remove old SQL queries, schema helpers, and repository code in the same phase as the schema cutover.

Console UI:

- [x] Remove all subscription labels, cards, and lifecycle actions from `/dashboard/billing/account`.
- [x] Replace plan terminology with balance terminology throughout the billing console.
- [x] Remove navigation affordances that imply recurring-plan management.

### Phase 2: Implement prepaid purchase flows

Backend logic:

- [x] Add one-time checkout session creation for predefined credit packs.
- [x] Add purchase-settlement handling that writes credit ledger entries idempotently.
- [x] Keep reusable payment-method setup, replacement, deletion, and default selection flows.
- [x] Ensure purchase settlement updates account balance atomically.

DB schema:

- [x] Add provider reference columns required to map checkout sessions, payment intents, and payment methods to purchases.
- [x] Add purchase status and settlement timestamp fields needed for reconciliation.
- [x] Add uniqueness constraints to prevent duplicate settlement writes for the same provider event.

Migrations:

- [x] Backfill or initialize billing-account rows for all orgs before enabling top-ups.
- [x] Remove obsolete subscription checkout references from persisted records.
- [x] Remove direct payment-intent / stablecoin settlement request parsers and provider adapter hooks from the active prepaid API surface.
- [ ] Delete migration helpers or compatibility code once prepaid purchase flows are live.

Console UI:

- [x] Add top-up purchase cards or buttons for fixed credit packs on `/dashboard/billing/account`.
- [x] Show current balance, low-balance warning threshold, and recent credit purchases.
- [x] Keep payment-method management on `/dashboard/billing/account`, but remove subscription wording and actions.
- [x] Remove any account-page controls that attempt to cancel, resume, or otherwise manage a subscription.

### Phase 3: Rate usage into debits and enforce balance policy

Backend logic:

- [x] Implement deterministic rating from usage events into `USAGE_DEBIT` ledger entries.
- [x] Make debit application idempotent and concurrency-safe.
- [ ] Enforce zero-balance or low-balance policy in the product path that gates production usage.
- [ ] Add reversal and manual-adjustment flows for operator correction.

DB schema:

- [x] Add source-event identifiers and uniqueness constraints for debit deduplication.
- [ ] Add any required balance snapshot or sequence columns used for concurrency control.
- [ ] Add tables or columns needed for adjustment and reversal audit trails.

Migrations:

- [x] Stop writing any new usage data into subscription-era billing tables.
- [ ] Delete old usage-to-subscription aggregation tables if they only exist for recurring billing.
- [ ] Remove cron jobs, workers, or queue consumers that compute subscription-period charges.

Console UI:

- [x] Add recent usage and debit summaries to `/dashboard/billing/account`.
- [x] Surface low-balance and insufficient-balance states clearly.
- [x] Update `/dashboard/invoices` to distinguish credit purchases from usage statements.
- [x] Remove "upcoming charge" language that implies end-of-period subscription billing.

### Phase 4: Cut over invoices, receipts, and account history

Backend logic:

- [x] Make invoice history serve only prepaid-model documents:
  - purchase receipts
  - usage statements
  - manual adjustments if intentionally exposed
- [x] Keep server-side PDF generation, but rename and scope it to the new document types.
- [ ] Audit-log every PDF export and every manual balance adjustment.

DB schema:

- [ ] Store stable receipt and statement snapshots for deterministic exports.
- [x] Add document-type fields and indexes for receipt vs statement filtering.
- [x] Add any metadata required for PDF filenames, document numbering, and export audits.

Migrations:

- [ ] Migrate existing invoice-history rows into receipt or statement categories if those rows are kept.
- [x] Delete invoice fields that only exist for subscription collection state.
- [ ] Drop old "subscription invoice" concepts from schema names and code identifiers.

Console UI:

- [x] Make `/dashboard/invoices` the canonical history view for receipts and statements only.
- [x] Add filtering by document type and status.
- [x] Keep `/dashboard/invoices/:invoiceId` for detail, but rename the content model away from subscription invoices.
- [x] Update visible copy and download filenames to reflect receipts and statements.

### Phase 5: Hard migration and cleanup

Backend logic:

- [ ] Convert or grant starting balances for existing orgs according to the chosen migration policy.
- [ ] Remove feature flags and dual-path routing once the prepaid model is live.
- [x] Delete dead subscription services, validators, webhook handlers, and tests.

DB schema:

- [x] Drop all remaining subscription-era tables, columns, constraints, and indexes.
- [ ] Rename any holdover schema objects that still expose subscription terminology.
- [ ] Remove legacy enum values and stored-state representations that no longer exist in the product.

Migrations:

- [x] Run a final destructive migration that leaves only the prepaid model in the database.
- [x] Do not retain fallback reads or writes for the old model after cutover.
- [ ] Remove migration-only scripts once production data has been converted.

Console UI:

- [ ] Delete any remaining subscription components, route helpers, and API clients.
- [ ] Verify `/dashboard/billing/account` shows only balance, top-up, payment-method, and usage information.
- [ ] Verify `/dashboard/invoices` shows only prepaid receipts and statements.
- [ ] Remove any legacy redirects that preserve old subscription page structures.

## Phase 0: Model definition and deletion plan

- [ ] Delete `subscription` as a first-class product concept from the target billing model.
- [ ] Define the canonical balance entity:
  - current balance
  - pending debits
  - available balance
  - low-balance threshold
- [ ] Define the canonical ledger event types:
  - `CREDIT_PURCHASE`
  - `PROMOTIONAL_CREDIT`
  - `USAGE_DEBIT`
  - `MANUAL_ADJUSTMENT`
  - `REFUND`
  - `REVERSAL`
- [ ] Define the rating unit for product usage so debits are deterministic.
- [ ] Decide whether MAW remains the primary rating dimension or whether another usage unit becomes canonical.
- [ ] Decide how zero-balance enforcement works for development, staging, and production environments.
- [ ] Document exactly which subscription-era fields and states will be deleted.

Required deletion target:

- subscription status
- cancel-at-period-end
- resume / cancel flows
- checkout sessions for subscription creation
- subscription readiness gates and messaging

## Next implementation steps

1. Implement zero-balance or low-balance enforcement in the production execution path.
2. Add manual balance adjustment / reversal flows with audit logging.
3. Decide whether to keep the Stripe customer portal or reduce account mutations to setup-intent-only flows.

## Phase 1: Data model and backend primitives

- [ ] Introduce a canonical org balance store.
- [ ] Introduce an append-only billing ledger.
- [ ] Introduce a usage rating pipeline that converts usage events into balance debits.
- [ ] Make debit application idempotent and concurrency-safe.
- [ ] Ensure every ledger mutation has an audit trail and source event id where applicable.
- [ ] Define receipt and statement records separately from the ledger so PDFs and exports use stable snapshots.

Suggested entities:

- `billing_account`
  - org id
  - available balance minor
  - pending balance minor
  - currency
  - low balance threshold minor
- `billing_ledger_entry`
  - id
  - org id
  - type
  - amount minor
  - currency
  - occurred at
  - source event id
  - actor type / actor id
  - related invoice id or purchase id
- `billing_credit_purchase`
  - id
  - org id
  - amount purchased minor
  - checkout provider refs
  - payment method refs
  - settled at
- `billing_statement`
  - id
  - org id
  - period start / end
  - opening balance
  - closing balance
  - total debits
  - total credits

## Phase 2: Checkout and payment collection flows

- [x] Replace subscription checkout with one-time credit purchase checkout.
- [x] Define top-up pack SKUs and provider mapping.
- [x] Keep payment-method add / replace / remove / set-default flows where useful.
- [x] Remove subscription cancel / resume / customer-portal language from the UI and API.
- [ ] Decide whether the Stripe customer portal remains available only for payment-method and billing-profile management.
- [ ] Decide whether top-up checkout can reuse the existing Stripe customer object and payment methods.

Target API surface:

- [ ] `GET /console/billing/account`
- [ ] `GET /console/billing/ledger?cursor=...`
- [ ] `GET /console/billing/purchases?cursor=...`
- [ ] `POST /console/billing/credit-purchases/checkout-session`
- [x] `POST /console/billing/payment-methods`
- [x] `DELETE /console/billing/payment-methods/:id`
- [x] `POST /console/billing/payment-methods/:id/default`
- [x] `POST /console/billing/stripe/setup-intent`
- [x] `POST /console/billing/stripe/customer-portal-session`

Delete or replace:

- [x] `GET /console/billing/subscription`
- [x] `POST /console/billing/subscription/cancel`
- [x] `POST /console/billing/subscription/resume`
- [ ] subscription-oriented Stripe webhook handling that exists only to maintain subscription state

## Phase 3: Rating usage into debits

- [x] Convert billing usage events into rated debits against prepaid balance.
- [ ] Define exactly when a usage event becomes billable.
- [ ] Define how retries and replayed events avoid double-debiting.
- [ ] Decide whether debits happen synchronously during product execution or asynchronously through a durable rating worker.
- [ ] Add insufficient-balance handling that is deterministic and testable.
- [ ] Define observability around rating failures and stuck debits.

Critical technical requirements:

- idempotent debit creation
- exactly-once or effectively-once debit application
- balance floor enforcement under concurrency
- auditable reversal path for bad debits

## Phase 4: Console UX rewrite

- [x] Replace the account page subscription card with a balance card.
- [x] Add top-up CTAs for predefined packs.
- [x] Show:
  - available balance
  - recent spend
  - low-balance threshold
  - default payment method
- [x] Remove all subscription lifecycle copy and controls.
- [x] Update invoice history to distinguish:
  - credit purchase receipts
  - usage statements
  - manual adjustments if exposed
- [x] Keep invoice detail, but adapt it to the new receipt / statement model.
- [x] Ensure the dashboard always displays human-readable org / project / environment labels, not raw ids.

Recommended account-page language:

- `Balance`
- `Top up credits`
- `Recent usage`
- `Low balance warning`
- `Payment methods`

Language to delete:

- `subscription`
- `renewal`
- `cancel at period end`
- `resume subscription`
- `upcoming charge estimate` if it still implies subscription billing

## Phase 5: Receipts, statements, and PDFs

- [x] Define two document types clearly:
  - purchase receipt
  - usage statement
- [x] Decide whether both use the same invoice detail route and PDF export mechanism.
- [x] Keep deterministic server-side PDF generation.
- [x] Update filenames and visible copy so PDFs reflect the new model.
- [ ] Ensure exported documents are snapshot-based and audit logged.

Examples:

- `receipt_<date>_<id>.pdf`
- `statement_<period>_<id>.pdf`

## Phase 6: Migration strategy

- [ ] Freeze creation of new subscriptions.
- [ ] Decide how existing subscription-backed orgs migrate:
  - convert remaining paid time into credits
  - grant a starting promotional balance
  - manually migrate selected tenants first
- [ ] Remove subscription gating from production enablement and replace it with prepaid-balance gating.
- [ ] Backfill any required balance or ledger records for existing tenants.
- [ ] Define rollback strategy before deleting subscription-era persistence.
- [ ] Delete dead code and dead schema once the migration is complete.

Important rule:

- do not leave parallel subscription and prepaid billing logic in the steady state
- do not retain compatibility layers once the destructive migration is complete
- delete old schema, routes, types, and UI copy as each area is cut over

## Phase 7: Tests and rollout

- [ ] Add backend tests for:
  - credit purchase settlement
  - debit idempotency
  - insufficient balance enforcement
  - concurrent debit safety
  - receipt / statement PDF export
  - tenant isolation
- [ ] Add dashboard tests for:
  - top-up checkout
  - low-balance warning state
  - payment-method mutation
  - receipt and statement navigation
- [ ] Add observability for:
  - failed rating jobs
  - negative balance attempts
  - orphaned purchases
  - reconciliation mismatches
- [ ] Roll out behind a short-lived development flag only if necessary for migration sequencing.
- [ ] Remove the flag after migration. No permanent dual model.

## Recommended implementation order

1. Phase 0
2. Phase 1
3. Phase 2
4. Phase 3
5. Phase 4
6. Phase 5
7. Phase 6
8. Phase 7

Reasoning:

- The billing model must be locked before UI or API cleanup is safe.
- Ledger and rating correctness matter more than frontend polish.
- Checkout should only ship after the balance primitives exist.
- Migration should start only after the prepaid model is operational and testable.

## Immediate decisions needed

1. Choose the prepaid pack sizes and prices.
2. Decide whether credits expire.
3. Decide the zero-balance behavior for production usage.
4. Decide whether monthly statements remain necessary or whether receipts plus ledger history are sufficient.
5. Decide whether stablecoin top-up is phase 1 or deferred.

## Definition of done

- Subscription lifecycle is deleted from the product model.
- Customers buy prepaid credits through one-time checkout.
- Usage burns down org balance deterministically.
- The account page shows balance, not subscription state.
- Invoice history shows receipts and statements that match the prepaid model.
- Production gating depends on prepaid balance policy, not subscription status.
- Legacy subscription-era billing code is deleted.

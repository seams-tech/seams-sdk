# Billing Console Plan

## Objective

Split the current `/dashboard/billing` experience into two clear product surfaces:

1. Billing account
   - payment methods
   - subscription lifecycle
2. Bill history and invoices
   - invoice list and statuses
   - invoice detail
   - PDF export/download

The current page mixes org-scoped account settings with invoice-scoped ledger artifacts and payment execution flows. That makes the page harder to understand and harder to extend. The new structure should separate those concerns cleanly.

## Product shape

Expose billing as two dedicated sidebar routes and keep invoice detail under the invoice history route:

- `/dashboard/billing` -> redirect to `/dashboard/billing/account`
- `/dashboard/billing/account`
- `/dashboard/invoices`
- `/dashboard/invoices/:invoiceId`

View responsibilities:

- `Account`
  - current plan
  - subscription state
  - checkout / portal / cancel / resume actions
  - payment methods list
  - add / replace / remove / set-default payment method actions
- `Invoices`
  - bill history table
  - invoice statuses
  - filters and period navigation
  - download PDF from list rows
- `Invoice detail`
  - invoice header and status timeline
  - line items
  - payment attempts / rail lock
  - payment execution actions
  - download PDF

Important ownership rule:

- Payment execution is invoice-scoped, not account-scoped. Move Stripe payment intent and stablecoin settlement actions out of the account view and into invoice detail.

Important product rule:

- "Edit payment method" should not mean raw card field editing in our DB. Card changes should flow through Stripe setup/update flows or the customer portal. In-app edits should be limited to supported metadata such as default selection or an optional local label if we add one.

## Phase 0: Information architecture and cleanup

- [x] Lock the canonical route structure: `account`, `invoices`, `invoice detail`.
- [x] Split billing account and invoice history into dedicated sidebar routes instead of page-local tabs.
- [x] Decide whether `/dashboard/billing` redirects or renders the `account` view directly. Prefer redirect for clean deep links.
- [x] Define canonical empty, loading, unauthorized, and error states for each billing subview.
- [x] Remove invoice-scoped payment execution controls from the account surface in the target design.
- [x] Define the canonical invoice status copy and badge mapping in one shared place.
- [x] Confirm whether `billing_admin` can mutate payment methods or whether mutating card actions remain `admin`-only. Keep backend and UI rules aligned.

## Phase 1: Account view for subscriptions and payment methods

- [x] Create a dedicated `BillingAccountPage` view.
- [x] Move current subscription summary and subscription actions into the account view.
- [x] Move current payment methods list and add/remove/default flows into the account view.
- [x] Replace generic billing copy with account-specific copy so the page reads as org billing settings, not invoice history.
- [x] Keep or improve the current checkout and customer portal flows.
- [x] Add a first-class "Replace payment method" action if the provider flow supports it cleanly; otherwise route users through the customer portal.
- [x] Keep auto-refresh on page access and remove redundant manual refresh controls.
- [x] Preserve role-based mutation guards in both UI and backend.

Backend/API follow-up for this phase:

- [x] Reuse existing endpoints where possible:
  - `GET /console/billing/subscription`
  - `POST /console/billing/subscription/cancel`
  - `POST /console/billing/subscription/resume`
  - `GET/POST/DELETE /console/billing/payment-methods`
  - `POST /console/billing/payment-methods/:id/default`
  - `POST /console/billing/stripe/setup-intent`
  - `POST /console/billing/stripe/checkout-session`
  - `POST /console/billing/stripe/customer-portal-session`
- [x] Add a provider-backed replace/update flow only if it is materially different from setup intent or portal behavior.

## Phase 2: Bill history and invoice list

- [x] Create a dedicated `BillingInvoicesPage` view for bill history.
- [x] Move the invoice table off the account page.
- [x] Make the invoice list the canonical place to view billing periods and invoice states.
- [x] Add filters for at least:
  - status
  - billing period
  - open / overdue / paid
- [x] Add deep links from each invoice row to `/dashboard/invoices/:invoiceId`.
- [x] Show the fields operators actually use:
  - invoice id
  - status
  - billing period
  - due date
  - amount due
  - amount paid
  - created date
  - rail lock summary
- [x] Decide whether bill history needs pagination now or whether the current result size is safe. Add pagination if invoice volume can grow materially.

Backend/API follow-up for this phase:

- [x] Reuse `GET /console/billing/invoices`.
- [x] Add query params for filters and pagination if the current list endpoint is not sufficient.
- [ ] Add a small summary field for latest payment state if it avoids extra per-row requests.

## Phase 3: Invoice detail and payment execution

- [x] Create a dedicated `BillingInvoiceDetailPage` view.
- [x] Move invoice line items to invoice detail.
- [x] Move Stripe payment intent creation and stablecoin payment flows to invoice detail.
- [x] Show invoice-specific state together:
  - invoice status
  - line items
  - outstanding balance
  - rail lock
  - latest payment intent state
  - stablecoin quote / intent state
- [x] Add a status timeline so operators can understand where an invoice is stuck.
- [x] Keep destructive actions invoice-local and confirm them clearly.
- [x] Ensure invoice detail can refresh after payment actions without reloading the entire dashboard shell.

Backend/API follow-up for this phase:

- [x] Reuse or finish wiring:
  - `GET /console/billing/invoices/:id`
  - `GET /console/billing/invoices/:id/line-items`
  - `POST /console/billing/stripe/payment-intent`
  - `GET /console/billing/stablecoins/assets`
  - `POST /console/billing/stablecoins/quotes`
  - `POST /console/billing/stablecoins/payment-intents`
  - `GET /console/billing/stablecoins/payment-intents/:id`
  - `POST /console/billing/stablecoins/payment-intents/:id/cancel`
- [x] Add any missing invoice-level payment history endpoint only if the existing invoice payload cannot carry enough state.

## Phase 4: PDF export

- [x] Add a canonical invoice export endpoint:
  - `GET /console/billing/invoices/:id/pdf`
- [x] Return `application/pdf` with `Content-Disposition: attachment`.
- [x] Generate PDFs server-side from canonical invoice data. Do not render ad hoc browser DOM into PDFs.
- [x] Include the information finance users expect:
  - invoice number
  - org billing identity
  - billing period
  - issue date
  - due date
  - status
  - line items
  - subtotal / credits / total
  - payment summary
- [x] Add "Download PDF" actions from both the invoice list and invoice detail.
- [x] Decide whether export should be allowed only for finalized invoices or for all invoice states.
- [x] Add audit logging if invoice export should be tracked for compliance or enterprise support workflows.

Backend/API follow-up for this phase:

- [x] Add PDF generation abstraction with deterministic tests.
- [x] Ensure tenant isolation for the PDF endpoint.
- [x] Ensure exported data reflects a stable invoice snapshot, not mutable UI-only derivations.
- [x] Add sensible filename conventions, for example `invoice_<period>_<id>.pdf`.

## Phase 5: Removal, tests, and rollout

- [x] Remove the current monolithic billing page once `account`, `invoices`, and `invoice detail` are live. No legacy combined layout should remain.
- [x] Delete obsolete billing-only layout code and styles from the old page.
- [x] Add route-level tests for:
  - account view
  - invoice list
  - invoice detail
  - PDF download
- [x] Add backend tests for:
  - invoice export authorization
  - tenant isolation
  - PDF response headers
  - not-found and invalid-state handling
- [x] Add e2e coverage for checkout return, payment method mutation, invoice detail navigation, and PDF download behavior.
- [ ] Update product and operator docs once the new structure is live.

## Next steps

1. Decide whether to keep the manual card-entry form once embedded Stripe Elements or hosted setup-intent completion exists.
2. Consider syncing invoice filters into the dashboard URL so operators can deep-link a filtered bill-history view.
3. Optimize invoice list summaries further if org invoice volume grows beyond what aggregate queries comfortably cover.

## Recommended implementation order

1. Phase 0
2. Phase 1
3. Phase 2
4. Phase 3
5. Phase 4
6. Phase 5

Reasoning:

- Account view and invoice view split is the structural change.
- Invoice detail should exist before payment execution is moved.
- PDF export should be added after invoice detail settles, so the server-side export model matches the final invoice detail model.

## Definition of done

- Billing account tasks are no longer mixed with invoice history on the same page.
- Invoice actions live on invoice detail, not on the account screen.
- Operators can view invoice statuses quickly from bill history.
- Operators can open an invoice detail page and download a PDF.
- The old combined billing layout is deleted.

# Billing Cleanup Plan (Remove Payment Methods)

## Objective

Remove all backend, API, and schema surface area tied to stored `Payment Methods`, aligned with the prepaid-credit model.

This is a hard cleanup. No feature flags, no deprecated routes, and no compatibility shims.

## Scope

In scope:

- billing service contract and implementations
- router endpoints (Express + Cloudflare)
- request/response types and parsers
- D1 schema and migration setup
- onboarding/readiness logic that depends on payment methods
- tests (unit/integration/e2e) that still assert payment-method behavior

Out of scope:

- prepaid checkout session flow
- credit purchase settlement webhook flow
- invoice/receipt/statement document flow

## Current Backend Surface To Remove

- `console_payment_methods` table and related indexes/policies
- billing service methods:
  - `listPaymentMethods`
  - `addCardPaymentMethod`
  - `removeCardPaymentMethod`
  - `setDefaultCardPaymentMethod`
- Stripe setup/portal methods if not needed in prepaid model:
  - `createStripeSetupIntent`
  - `createStripeCustomerPortalSession`
- router endpoints:
  - `GET /console/billing/payment-methods`
  - `POST /console/billing/payment-methods`
  - `DELETE /console/billing/payment-methods/:id`
  - `POST /console/billing/payment-methods/:id/default`
  - `POST /console/billing/stripe/setup-intent`
  - `POST /console/billing/stripe/customer-portal-session`

## Key Decisions (Resolve Before Implementation)

1. Live environment readiness gate:
   - Decision: replace "has payment method" with "has positive prepaid balance" (`creditBalanceMinor > 0`)
2. Stripe customer portal:
   - Decision: remove fully from prepaid model surface area

Default recommendation: remove setup-intent and customer-portal endpoints entirely unless a clear prepaid use case exists.

## Phased TODO Checklist

### Phase 0: Decisions and Baseline

- [x] Decide live-environment readiness gate replacement:
  - no gate
  - positive prepaid balance
  - billing configured
- [x] Decide whether Stripe customer portal remains in scope.
- [x] Capture the decisions in this file and update acceptance criteria.
- [x] Record baseline grep output for payment-method references.

### Phase 1: Domain and Service Contract Cleanup

- [x] Remove billing payment-method DTOs from `types.ts`.
- [x] Remove setup-intent/customer-portal DTOs if decision is remove.
- [x] Remove payment-method methods from `ConsoleBillingService`.
- [x] Remove in-memory `paymentMethods` store and related logic.
- [x] Remove setup-intent/customer-portal methods from service if out of scope.
- [x] Update provider adapter interface to match retained Stripe operations.
- [x] Verify TypeScript passes for `packages/console-server-ts/src/billing`.

### Phase 2: Router and Parser Cleanup

- [x] Remove payment-method request parser(s).
- [x] Remove setup-intent/customer-portal parser(s) if out of scope.
- [x] Remove payment-method routes in Express router.
- [x] Remove setup-intent/customer-portal routes in Express router if out of scope.
- [x] Remove payment-method routes in Cloudflare router.
- [x] Remove setup-intent/customer-portal routes in Cloudflare router if out of scope.
- [x] Remove now-dead admin card role guard helpers/messages.
- [x] Verify router typecheck/build passes.

### Phase 3: Onboarding and Readiness Refactor

- [x] Replace payment-method based readiness rule in `billing/readiness.ts`.
- [x] Remove `listPaymentMethods` dependency in onboarding state resolution.
- [x] Remove `listPaymentMethods` dependency in project creation gating.
- [x] Update any onboarding copy/messages that mention payment methods.
- [x] Add/adjust tests for new readiness behavior.

### Phase 4: D1 Schema and Query Cleanup

- [x] Remove `console_payment_methods` create-table block.
- [x] Remove `console_payment_methods` index creation.
- [x] Remove `console_payment_methods` RLS policy registration.
- [x] Remove all payment-method CRUD SQL methods.
- [x] Add `DROP TABLE IF EXISTS console_payment_methods` migration step.
- [x] Run schema-ensure path on a test DB and confirm idempotence.

### Phase 5: Public Exports and Client Surface Cleanup

- [x] Remove deleted billing exports from `console/billing/index.ts`.
- [x] Remove deleted provider types from adaptor exports.
- [x] Remove frontend `consoleBillingApi.ts` functions for removed endpoints.
- [x] Remove any remaining UI wiring that calls removed endpoints.
- [x] Verify end-to-end typecheck across server + dashboard packages.

### Phase 6: Test Migration and Final Verification

- [x] Remove or rewrite relayer billing tests for payment-method lifecycle.
- [x] Remove or rewrite router tests for payment-method/setup-intent/customer-portal endpoints.
- [x] Remove tenant-isolation assertions tied to `console_payment_methods`.
- [x] Update e2e API-wiring mocks to prepaid-only behavior.
- [x] Run full targeted suites (billing, router, onboarding, e2e billing pages).
- [x] Run final grep and ensure no production references remain.
- [ ] Commit as one breaking-change cleanup series.

## Implementation Plan

### Phase 1: Domain and Service Contract Cleanup

- Remove payment-method DTOs from billing types:
  - `BillingPaymentMethod`
  - `AddCardPaymentMethodRequest`
  - `StripeSetupIntentRequest/StripeSetupIntent` (if decision is remove)
  - `StripeCustomerPortalSessionRequest/StripeCustomerPortalSession` (if decision is remove)
- Remove service interface methods listed above.
- Remove in-memory billing store `paymentMethods` map and all associated logic.
- Update provider adapter contract:
  - remove `createSetupIntent` and `createCustomerPortalSession` from Stripe adapter if removed.

Exit criteria:

- `ConsoleBillingService` only exposes prepaid-relevant operations.

### Phase 2: Router and Request Parser Cleanup

- Remove parser functions:
  - `parseAddCardPaymentMethodRequest`
  - `parseStripeSetupIntentRequest` (if removed)
  - `parseStripeCustomerPortalSessionRequest` (if removed)
- Remove endpoint handlers from:
  - `packages/sdk-server-ts/src/router/express/createConsoleRouter.ts`
  - `packages/sdk-server-ts/src/router/cloudflare/createCloudflareConsoleRouter.ts`
- Remove now-unused role guard text/functions related to card actions.

Exit criteria:

- Payment-method/setup-intent/customer-portal routes no longer exist.

### Phase 3: Onboarding and Readiness Logic

- Replace readiness logic in:
  - `packages/console-server-ts/src/billing/readiness.ts`
  - `packages/console-server-ts/src/onboarding/service.ts`
- Remove any dependency on `listPaymentMethods`.
- Keep behavior explicit and deterministic for prepaid model.

Exit criteria:

- Onboarding and live-environment gating have no payment-method dependency.

### Phase 4: D1 Schema and Data Cleanup

- Remove create-path for `console_payment_methods` and its indexes.
- Remove RLS policy registration for `console_payment_methods`.
- Remove all SQL CRUD queries touching `console_payment_methods`.
- Add explicit destructive cleanup migration line:
  - `DROP TABLE IF EXISTS console_payment_methods`

Exit criteria:

- Fresh schema and migrated schema both run without `console_payment_methods`.

### Phase 5: Exports, Adaptors, and API Surface Hygiene

- Remove stale exports from:
  - `packages/console-server-ts/src/billing/index.ts`
  - `packages/sdk-server-ts/src/router/express-adaptor.ts`
  - `packages/sdk-server-ts/src/router/cloudflare-adaptor.ts`
- Remove frontend API functions still referencing removed endpoints.

Exit criteria:

- No compile-time references to removed types/functions/routes remain.

### Phase 6: Test Rewrite and Verification

- Delete or rewrite tests that assert payment-method behavior.
- Update API wiring tests/mocks to stop stubbing removed endpoints.
- Update tenant-isolation tests that use `console_payment_methods`.
- Ensure current billing/router tests no longer clean up `console_payment_methods`.
- Run full billing and router test suites.

Exit criteria:

- No test references to payment-method flows.
- Billing test matrix passes with prepaid-only semantics.

## Verification Checklist

- `rg -n "payment-method|payment_methods|setup-intent|customer-portal|listPaymentMethods|addCardPaymentMethod|removeCardPaymentMethod|setDefaultCardPaymentMethod" packages/sdk-server-ts/src tests apps/seams-site -S` returns only intentional docs/history references.
- Typecheck and tests pass for:
  - SDK server billing modules
  - router suites
  - dashboard billing API wiring tests
- Manual smoke:
  - prepaid top-up checkout still works
  - webhook settlement still credits balance
  - invoices/receipts still render

## Implementation Status (2026-03-11)

- Completed: backend/service/router/schema cleanup and prepaid readiness refactor.
- Completed: frontend billing account view and API client no longer reference payment methods, setup intents, or customer portal.
- Completed: dashboard billing prepaid e2e wiring is back to green on the canonical `/dashboard/billing/account` and `/dashboard/invoices` routes.
- Completed: final cleanup grep across `packages/sdk-server-ts/src`, `tests`, and `apps/seams-site` now returns only intentional migration/history references.
- Completed: legacy billing plan doc `docs/billing-console.md` was removed so the repo no longer carries a contradictory subscription/payment-method plan.
- Verification:
  - `pnpm -C apps/seams-site exec tsc --noEmit` passed.
  - `pnpm --dir packages/sdk-server-ts type-check` passed.
  - Refactor 82 update: live-Postgres relayer suites were deleted. Current billing/router validation lives in `./relayer/console-billing.service.test.ts`, `./relayer/console-d1-adapters.test.ts`, `./relayer/router-api-keys.test.ts`, and `./relayer/console-router.test.ts`.
  - `pnpm -C tests exec playwright test ./e2e/dashboard.billing.console.apiWiring.test.ts --reporter=line` passed (`4 passed`).
  - `pnpm -C tests exec playwright test ./e2e/dashboard.consoleConfigPages.apiWiring.test.ts --reporter=line` is still outside billing scope and may fail due unrelated dashboard UI expectation drift.

## Rollout Notes

- This is a breaking API change; remove endpoints in one cut.
- Coordinate frontend merge so UI does not call removed routes.
- Announce removal in release notes as prepaid-billing hard transition.

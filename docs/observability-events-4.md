# Audit And Observability Event Surfacing TODO

This document is the implementation backlog for event taxonomy and dashboard surfacing.

It complements `docs/observability-events-3.md`, which covers the observability storage and noise-reduction architecture. This file focuses on which events should appear in `/dashboard/audit` and `/dashboard/observability`, and what code and UI changes are still needed.

## Desired product split

- `/dashboard/audit` is the durable control-plane history for state changes, approvals, permissions, billing mutations, and other compliance-friendly records.
- `/dashboard/observability` is the operator health view for incidents, degradation, retries, dead letters, and failure transitions.
- A single business flow may write to both surfaces when it both changes durable state and fails or degrades in an operator-actionable way.
- Do not add routine successful reads or generic happy-path traffic to `/dashboard/observability`.

## TODO: Audit events

- [x] Add `policy.create` audit rows for policy creation.
- [x] Add `policy.update` audit rows for policy edits.
- [x] Add `policy.delete` audit rows for policy deletion.
- [x] Add `policy.assignment.upsert` audit rows for policy assignment changes.
- [x] Add `policy.assignment.delete` audit rows for policy assignment removal.
- [x] Keep `policy.publish` audit rows and ensure metadata always includes `policyId`, `policyName`, `policyKind`, `version`, `status`, and effective scope.
- [x] Add `billing.credit_purchase.settled` audit rows for successful Stripe top-ups from both webhook settlement and checkout reconcile flows.
- [ ] Add `billing.credit_purchase.refunded` audit rows when refund handling exists.
- [ ] Add `billing.credit_purchase.disputed` audit rows when dispute handling exists.
- [x] Add `billing.invoice.generated` audit rows for invoice generation.
- [ ] Add `billing.invoice.voided` or `billing.invoice.canceled` audit rows if invoice reversal is supported.
- [ ] Keep `billing.adjustment.support_credit` and `billing.adjustment.admin_debit` as audited events.
- [ ] Keep `billing.invoice.pdf_export` as an audited event.
- [x] Add `webhook.endpoint.create`, `webhook.endpoint.update`, `webhook.endpoint.delete`, and `webhook.delivery.replay_requested` audit rows.
- [ ] Add `member.invite`, `member.role.update`, and `member.remove` audit rows.
- [ ] Add `wallet.create`, `wallet.archive`, and `wallet.policy_assignment.change` audit rows where those flows exist.
- [ ] Add key export lifecycle audit rows for request, approval, completion, and denial.
- [ ] Add runtime snapshot publish audit rows.
- [ ] Add failure-outcome audit rows for sensitive mutations where the attempt itself matters for compliance or operator review.

## TODO: Observability events

- [ ] Keep the durable observability stream incident-only. Do not reintroduce happy-path request noise.
- [ ] Keep `approval.policy_publish.failed` as a durable observability event.
- [ ] Keep `billing.invoice_finalization.failed` as a durable observability event.
- [x] Add `billing.payment_reconcile.failed` for failed prepaid settlement reconciliation.
- [x] Add `billing.stripe_webhook.invalid_signature` for invalid or rejected Stripe callbacks.
- [x] Add `billing.stripe_webhook.processing.failed` for accepted callback payloads that fail during processing.
- [x] Keep `webhook.delivery.dead_letter` as a durable observability event.
- [x] Add `webhook.delivery.retry_exhausted` for terminal delivery failure.
- [x] Add `webhook.endpoint.degraded` when repeated delivery failures cross a service-health threshold.
- [ ] Add wallet runtime incident events such as `wallet.rpc.failed`, `wallet.rpc.degraded`, `wallet.signing.failed`, `wallet.paymaster.failed`, `wallet.bundler.failed`, and `wallet.sponsored_call.simulation.failed`.
- [ ] Keep `session.exchange.failed` in the observability stream and add similar auth/bootstrap failures that are operator-actionable.
- [ ] Add recovery or degradation transition events only when system state changes, not on every failing request.

## TODO: Dashboard surfacing

- [x] Make `/dashboard/audit` show org-level events even when a project or environment is selected, or add an explicit toggle for including org-scoped rows.
- [x] Add explicit action-aware labels to audit rows so policy, approval, billing, and webhook rows read clearly without opening metadata.
- [x] Surface actor, scope, and resource identifiers consistently in audit row details.
- [x] Link audit rows to relevant policy, approval, invoice, receipt, or webhook detail pages when those destinations exist.
- [x] Make successful Stripe credit purchases visible on `/dashboard/audit` with purchase ID, receipt ID, amount, provider reference, and source metadata.
- [x] Make policy create/update/delete/publish rows visible on `/dashboard/audit` with policy name, kind, version, and scope metadata.
- [x] Keep `/dashboard/observability` filtered by `service`, `component`, `eventType`, `level`, and time window.
- [x] Keep the observability default window narrow enough to be operationally useful, such as the last 24 hours.
- [x] Show billing, approvals, webhooks, wallets, and auth as first-class observability services.
- [x] Add empty-state copy that explains `/dashboard/observability` is incident-driven and may be empty during healthy operation.

## TODO: Backend implementation

- [x] Add the missing audit emitters in `server/src/router/express/createConsoleRouter.ts`.
- [x] Keep Cloudflare parity by adding the same emitters in `server/src/router/cloudflare/createCloudflareConsoleRouter.ts`.
- [ ] Extend audit response typing and row rendering to support the new action families.
- [x] Extend observability builders and policy definitions in `server/src/console/observability`.
- [x] Ensure Stripe settlement writes audit rows even when the actor is system-driven.
- [x] Ensure duplicate Stripe webhook delivery or reconcile retries do not create duplicate success audit rows unless the stored outcome changes.
- [x] Ensure org-scoped billing events do not disappear behind project/environment filters.
- [x] Add tests for event metadata shape so policy, billing, and webhook rows remain stable as the UI evolves.

## TODO: Validation

- [x] Creating a policy appends a `policy.create` audit row.
- [x] Publishing a policy appends a `policy.publish` audit row with the final version and status metadata.
- [x] Successfully adding prepaid credits through Stripe appends a `billing.credit_purchase.settled` audit row.
- [x] Webhook endpoint create/update/delete and delivery replay append `WEBHOOK` audit rows with stable endpoint and delivery metadata.
- [x] Healthy policy creation and healthy Stripe top-up do not create durable observability rows.
- [x] Forced policy publish failure creates an observability row.
- [x] Forced billing invoice finalization failure creates an observability row.
- [x] Forced billing payment reconcile failure creates an observability row.
- [x] Invalid Stripe webhook signatures create an observability row.
- [x] Stripe webhook processing failures create an observability row.
- [x] Refreshing `/dashboard/observability` does not create durable observability events.
- [x] Express and Cloudflare remain behaviorally aligned for both audit and observability emission.

## Likely touch points

- `server/src/router/express/createConsoleRouter.ts`
- `server/src/router/cloudflare/createCloudflareConsoleRouter.ts`
- `server/src/console/observability/policy.ts`
- `server/src/console/observability/types.ts`
- `server/src/console/audit/types.ts`
- `examples/tatchi-site/src/pages/dashboard/routes/audit/page.tsx`
- `examples/tatchi-site/src/pages/dashboard/routes/audit/consoleAuditApi.ts`
- `examples/tatchi-site/src/pages/dashboard/routes/observability/page.tsx`
- `examples/tatchi-site/src/pages/dashboard/routes/observability/consoleObservabilityApi.ts`
- `tests/relayer/console-router.test.ts`
- `tests/relayer/console-observability.ingestion.test.ts`

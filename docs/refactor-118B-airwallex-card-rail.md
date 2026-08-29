# Refactor 118B — Airwallex card rail

Date created: August 29, 2026

Status: scaffolded implementation plan. Begin after R118A freezes prepared
execution, budget reservation, purchase, and audit boundaries.

Parent plan:

- [R118A — Expense domain and direct stablecoin rail](refactor-118A-agent-expense-domain.md)

Related references:

- [Stablecoin-linked virtual card](stablecoin-linked-virtual-card.md)
- [Refactor 130 Airwallex sandbox integration](refactor-130-airwallex-sandbox-integration.md)

## Supersession

R118B is the product-aligned authority for the Airwallex card rail and
supersedes Refactor 130. R130 remains historical reference material for the
sandbox client, webhook, simulation, and provider-boundary work that is still
valid.

R118B must absorb useful R130 decisions directly. No implementation maintains
parallel `stablecoinCards` and agent-expense card models.

## Goal

Let an approved R118A purchase execute at an ordinary card-accepting merchant
through a bounded Airwallex virtual card, then reconcile the complete financial
outcome into the originating Seams expense operation.

```text
R118A approved spend
  -> Airwallex card selection or issuance
  -> card authorization
  -> capture, reversal, or expiry
  -> settlement and refund
  -> R118A budget and audit linkage
```

The first operating path uses the Airwallex sandbox and simulated transactions.
Production cards remain unavailable until provider, regulatory, treasury,
capital, fraud, dispute, and support gates are satisfied.

## Ownership

R118B owns:

- Airwallex sandbox configuration and authentication;
- provider-boundary request builders and response parsers;
- cardholder and virtual-card provider records;
- card assignment to an approved spend or Agent Grant;
- authorization controls and remote authorization when available;
- verified webhook ingestion and provider-event idempotency;
- authorization, capture, reversal, expiry, refund, dispute, and reconciliation
  records;
- Airwallex-specific error normalization and operational evidence; and
- the provider side of reserve, settlement, and liquidity integration.

R118B consumes from R118A:

- exact agent, connection, grant, purchase, and approval identities;
- canonical purchase-intent digest;
- budget reservation and stable operation identity;
- prepared payment execution;
- audit linkage; and
- authoritative revocation and policy decision.

R118B cannot create a second mandate, budget, replay, approval, or agent
identity model.

## Provider boundary

Airwallex raw objects remain inside the Airwallex adapter. Core expense code
receives exact normalized records with branded IDs, integer minor-unit amounts,
normalized currencies, and exhaustive lifecycle events.

Application code must not receive, persist, proxy, or log PAN, CVV, bearer
tokens, API keys, webhook secrets, or remote-authorization shared secrets.
Sensitive card display uses a provider-hosted surface when the approved card
program supports one.

Provider capability is explicit:

```text
configured and available
unconfigured
missing required issuing capability
temporarily unavailable
```

No missing capability activates a fake or permissive production branch.

## Card and payment lifecycle

Model card identity separately from purchase execution.

Card lifecycle must distinguish at least:

```text
pending
active
frozen
closed
failed
```

Card payment lifecycle must distinguish:

```text
authorization_pending
authorized
partially_captured
captured
reversed
expired
failed
partially_refunded
refunded
disputed
outcome_unknown
```

Provider events project into the R118A expense operation. They do not mutate
Agent Grant policy or restore budget without an explicit R118A reconciliation
decision.

## Card allocation decision

Before implementation, choose one first branch:

- one card per approved purchase;
- one card per Agent Grant; or
- one shared card governed by remote authorization.

The first branch should minimize credential reuse and provider complexity while
still demonstrating an ordinary ecommerce purchase. Do not implement all three
for the sandbox proof.

## Implementation sequence

### Phase 1: Sandbox client

- [ ] Parse complete sandbox configuration once at startup and reject production
      origins.
- [ ] Authenticate, cache the provider token until its exact expiry, and prove
      one balance read.
- [ ] Normalize credential, capability, timeout, rate-limit, and provider
      failures without leaking secrets.

### Phase 2: Cardholder and card

- [ ] Create one sandbox cardholder through an exact branch-specific request.
- [ ] Create one virtual card with stable Seams idempotency identity.
- [ ] Persist safe card projection data only.
- [ ] Implement retrieve, freeze, and close for the selected card branch.

### Phase 3: Approved-spend execution

- [ ] Consume one R118A prepared Airwallex execution branch.
- [ ] Bind the selected card, amount, currency, merchant constraints, grant,
      purchase, approval, and budget reservation.
- [ ] Simulate authorization, capture, reversal, failure, and refund.
- [ ] Map every event to one exact expense operation.

### Phase 4: Webhooks and reconciliation

- [ ] Verify the exact raw body and provider signature before parsing.
- [ ] Persist provider event identity before applying a transition.
- [ ] Make duplicate and reordered delivery converge safely.
- [ ] Reconcile unknown or mismatched state against authoritative provider
      reads and emit discrepancy records.

### Phase 5: Remote authorization

- [ ] Begin only after Airwallex enables the capability for the sandbox account.
- [ ] Verify provider authenticity and replay identity before policy lookup.
- [ ] Resolve the exact active card allocation and R118A budget state.
- [ ] Approve or decline within the provider deadline and fail closed on timeout
      or unavailable state.
- [ ] Perform no chain, conversion, or bank operation on the synchronous path.

### Phase 6: Stablecoin reserve simulation

- [ ] Connect card holds to one testnet or simulated reserve allocation.
- [ ] Reconcile capture, reversal, expiry, and refund against that allocation.
- [ ] Keep redemption, banking, and Airwallex Wallet replenishment behind exact
      treasury ports.
- [ ] Produce complete sandbox evidence for production-partner review.

## Exit criteria

R118B is complete when one R118A-approved sandbox purchase executes through one
Airwallex virtual card and authorization, capture, reversal, refund, duplicate
webhook, and reconciliation paths converge on the correct expense and budget
state without exposing sensitive card data.

## Production gate

Production requires explicit approval for:

- supported region and card program;
- cardholder and customer classification;
- KYC, KYB, AML, sanctions, and fraud controls;
- reserve, settlement liquidity, and treasury operations;
- disputes, chargebacks, refunds, and customer support;
- stablecoin custody, conversion, and regulatory structure; and
- incident response and business continuity.

## Non-goals

- redefining Agent Grants, mandates, purchases, approvals, or budgets
- using Airwallex as the canonical Seams expense ledger
- production credentials, live cards, real customer funds, or real settlement
- merchant discovery or checkout browser automation
- multiple issuers or provider-routing optimization
- direct access to PAN or CVV from Seams application code

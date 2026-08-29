# Refactor 118C — Agent expense Console and dashboard

Date created: August 29, 2026

Status: scaffolded implementation plan. Begin after R118A freezes the customer
read models and supported mutations.

Parent plan:

- [R118A — Expense domain and direct stablecoin rail](refactor-118A-agent-expense-domain.md)

Related plans:

- [R118B — Airwallex card rail](refactor-118B-airwallex-card-rail.md)
- [R118D — Agent connections](refactor-118D-agent-connections.md)
- [R117 — Console operating tests](refactor-117-console-tests.md)

## Goal

Turn the existing custody, policy, and execution foundation into a direct
expense-management product for people and teams operating AI agents.

```text
fund account
  -> connect agent
  -> create Agent Grant
  -> allocate budget and approval policy
  -> review activity and exceptions
  -> inspect settlement, refund, and audit evidence
```

R118C owns presentation and customer workflow. R118A and R118B remain the only
authorities for admission, financial lifecycle, and provider state.

## Product surfaces

The first Console surface includes:

### Overview

- available balance;
- allocated agent budgets;
- pending reservations and card holds;
- settled spend;
- refunds and released commitments; and
- grants or connections requiring attention.

### Agents

- connected-agent list;
- connection kind and status;
- exact Agent Grants;
- current budget, validity, and revocation state; and
- actions to connect, replace policy, suspend, or revoke.

### Agent Grant editor

- merchant and category rules;
- aggregate and per-purchase budget;
- item, currency, geography, delivery, fee, and recurrence rules;
- approval thresholds;
- validity and expiry; and
- supported payment rails.

The editor constructs an exact reviewed R118A mutation. It does not persist a
partial domain record or derive policy from UI diagnostics.

### Approvals

- pending exact purchase;
- agent and grant identity;
- merchant, items, amount, fees, delivery, and payment rail;
- reason approval is required;
- expiry and consequences; and
- approve exact purchase or deny purchase.

Approval cannot edit the purchase. A changed merchant, amount, cart, or payment
parameter creates a new purchase intent.

### Activity

- proposed, blocked, awaiting-approval, executing, completed, failed, and
  ambiguous purchases;
- stablecoin transaction or card execution projection;
- authorization, capture, reversal, settlement, refund, and dispute state when
  applicable;
- receipt and reconciliation references; and
- concise policy and audit evidence.

### Funding and cards

- supported stablecoin funding source;
- balance and reserve state;
- safe virtual-card projection;
- freeze and close actions when R118B supports them; and
- no PAN or CVV outside the provider-hosted display surface.

## Read-model boundary

Console routes receive product read models assembled by server services. They do
not join raw wallet, budget, Airwallex, audit, and connection records in React.

Every mutation consumes a narrow lifecycle branch:

- create grant from eligible account and active connection;
- replace policy from an active grant;
- approve from an unexpired pending approval;
- revoke from an active or suspended grant;
- freeze from an active card; and
- close from an eligible card lifecycle.

Raw route bodies are parsed once. Core product functions never accept partial
forms or optional identity fields.

## First customer journey

The first operating path should demonstrate:

1. open the agent-expense dashboard;
2. inspect the funded stablecoin account;
3. connect or select one R118D agent;
4. create one Agent Grant;
5. submit a purchase from the connected agent;
6. approve an above-threshold purchase;
7. observe direct stablecoin execution;
8. inspect durable activity and audit evidence; and
9. revoke the grant and observe denied reuse.

Add the Airwallex card state to this journey after R118B proves its sandbox
boundary.

## Implementation sequence

### Phase 1: Information architecture and read models

- [ ] Add one agent-expense navigation group and route family.
- [ ] Define server-owned overview, agent, grant, approval, activity, funding,
      and card read models.
- [ ] Reuse existing Console layout, table, detail, audit, and mutation patterns.
- [ ] Remove wallet-infrastructure terminology from the primary expense flow.

### Phase 2: Direct-product mutations

- [ ] Add connection selection and Agent Grant creation.
- [ ] Add exact policy replacement, suspension, and revocation.
- [ ] Add purchase approval and denial.
- [ ] Add funding and supported card lifecycle actions.

### Phase 3: Activity and reconciliation

- [ ] Show one chronological purchase and payment lifecycle.
- [ ] Distinguish pending, ambiguous, settled, reversed, and refunded money.
- [ ] Link default explanations to advanced audit evidence.
- [ ] Keep raw provider and cryptographic internals out of the primary view.

### Phase 4: Operating test

- [ ] Extend the R117 real-service Console harness.
- [ ] Add one durable end-to-end agent-expense journey.
- [ ] Assert mutations through reload, server reads, audit, and payment outcome.
- [ ] Keep pure component tests only for state the operating path cannot own.

When implementation touches `tests/`, read `tests/AGENTS.md` before changing the
suite.

## Exit criteria

R118C is complete when a customer can fund or inspect one account, connect one
agent, create and revoke one grant, approve one exact purchase, and understand
the resulting balance and activity through a real-service Console operating
test.

## Non-goals

- authorizing spend inside React
- duplicating R118A policy or budget state
- parsing Airwallex responses in the Console
- displaying wallet roots, shares, lanes, or provider secrets in the normal flow
- general workflow automation or agent orchestration
- merchant discovery and product recommendation

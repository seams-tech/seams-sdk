---
title: Ecommerce agents
description: Give shopping and merchant agents scoped wallet authority with budgets, merchant limits, approval thresholds, and revocation.
---

# Ecommerce agents

An ecommerce agent can search, reserve, purchase, refund, or reconcile within
a mandate. Its authority should be narrower than the user's wallet and narrower
than a merchant administrator credential.

## Example mandate

Allow one agent to purchase approved product categories from named merchants,
up to a per-order and weekly budget, until a fixed expiry. Require human
approval when the shipping address changes, the price exceeds a threshold, or
the merchant is new.

## Execution path

```mermaid
flowchart LR
  Owner["Wallet owner"] --> Mandate["Scoped mandate"]
  Mandate --> Agent["Delegated agent lane"]
  Agent --> Intent["Typed commerce intent"]
  Intent --> Policy["Merchant, budget, risk, and expiry"]
  Policy --> Approval["Approve, deny, or step up"]
  Approval --> Payment["Wallet signing"]
  Payment --> Audit["Receipt and audit"]
```

Keep catalog browsing outside wallet authority. Enter the signing path only
when an operation reserves value, moves funds, changes an order, or uses a
privileged merchant capability. Revoke the agent lane without rotating the
owner's credential.

Start with [delegated agents](/guides/delegated-agents) and [policies and
mandates](/guides/policies-and-mandates).

# Seams product vision

Date created: August 26, 2026

Last revised: August 27, 2026

Status: draft product vision; use as customer, positioning, and product-scope
guidance.

Related docs:

- [Expense management for agents](product-vision.md)
- [Stablecoin-linked virtual card](stablecoin-linked-virtual-card.md)
- [Embedded wallet card checkout](embedded-wallet-card-checkout.md)

## Vision

Seams is an expense-management product for AI agents.

People and businesses fund one Seams account, connect the agents they use, and
grant each agent a precise spending mandate. Seams checks every proposed
purchase, requests approval when required, executes through a supported payment
rail, and preserves the evidence from instruction through refund.

Internal shorthand:

```text
Ramp for agents, initially stablecoin-funded.
```

Customer-facing promise:

```text
Fund once. Connect an agent. Control exactly what it can spend.
```

The wallet, custody, signing, and embedded SDK remain essential infrastructure.
They operate underneath the expense-management experience.

## Customer

The initial customer is an AI-native individual, team, or small business that
wants agents to make repeated purchases without sharing an unrestricted wallet
or card and without approving every routine transaction.

Strong initial customer profiles include:

- operators using agents for procurement, travel, or ecommerce work
- developers using agents to purchase approved software, domains, API services,
  or cloud resources
- small teams that need budgets and an audit trail for agent activity
- stablecoin-native users who want agents to shop at ordinary merchants
- agent developers who need a controlled spending account for their own agents

The defining behavior is repeated delegated spending. Stablecoin ownership is
an initial funding characteristic rather than the customer category.

## Product model

```text
Person or business
  -> Seams funding account
  -> agent connection
  -> spending mandate and budget
  -> exact purchase intent
  -> allow, block, or request approval
  -> stablecoin, virtual-card, or future payment execution
  -> receipt, settlement, refund, and audit history
```

### One funding account

A customer funds one Seams account. The product displays:

- available balance
- allocated agent budgets
- pending authorizations and holds
- settled purchases
- refunds and released commitments

Agent budgets are ledger allocations and policy grants by default. Seams may
create an isolated wallet, card, or payment credential underneath when an
execution rail requires one. Customers should not need to rebalance a collection
of delegated wallets for ordinary use.

### Agent connections

Customers connect Codex, ChatGPT, custom agents, and other runtimes through
OAuth, MCP, API credentials, or SDK adapters.

An agent connection proves which integration is calling Seams. A separate Agent
Grant defines what that connection may spend. Revoking either one removes the
corresponding access without changing ownership of the funding account.

### Spending mandates

Each Agent Grant carries a versioned spending mandate. A mandate may constrain:

- total and per-purchase amount
- merchant and merchant category
- item, quantity, and substitution
- currency, geography, and delivery destination
- shipping, tax, fee, and final-price ceilings
- recurring payments
- time window and expiry
- human-approval thresholds
- supported payment rail

Agents propose typed purchase intents. Seams normalizes the final commercial
details, evaluates the active mandate, and produces one of three decisions:

```text
allow
block
request approval
```

### Payment reach

Stablecoins provide the initial native funding and settlement rail. Virtual
cards extend the product to ordinary ecommerce merchants that have no Seams or
stablecoin integration.

Airwallex is the first planned virtual-card provider. Airwallex should own card
issuance, regulated onboarding, sensitive card data, network processing, 3DS,
and card lifecycle. Seams should own the agent mandate, budget, policy decision,
approval, reserve or funding allocation, reconciliation, and audit evidence.

A payment rail makes the mandate useful. The expense-management account remains
the product.

## Primary use cases

### Agent procurement

An agent buys approved software, services, supplies, or inventory within a team
budget. New merchants, subscriptions, and purchases above a threshold require
approval.

### Agent travel

An agent books flights, hotels, and transport within an itinerary, geography,
date range, and total budget. Seams checks the final booking before payment.

### Agent shopping

A user gives an agent an item, quantity, merchant, delivery, substitution, and
price mandate. The agent may pay at an ordinary card-accepting merchant through
a bounded virtual card.

### Agent-operated services

A developer or operator lets an agent buy approved domains, API credits, cloud
services, or other digital inputs while retaining control over merchant,
frequency, and total spend.

## Product surfaces

### Direct Seams product

The direct product owns:

- onboarding and funding
- connected-agent management
- budgets and mandate authoring
- pending approvals
- purchase and refund activity
- receipts and reconciliation
- revocation and audit history

This experience belongs in the Seams Console and customer dashboard.

### Agent integration

The agent surface provides narrow intent-oriented operations such as:

- read spending authority
- propose a purchase
- request approval
- execute an approved purchase
- read purchase status
- cancel an eligible purchase
- read remaining budget

Agents should not receive a generic unrestricted signing or money-transfer tool
through the normal expense-management interface.

### Embedded platform SDK

The existing embedded wallet and signing SDK remains available. After the direct
product proves demand, agent platforms can embed Seams accounts, mandates, and
payment execution for their own customers.

Platform wallets become an enterprise distribution channel for the proven
expense-management product.

## Existing foundation

Seams has already built much of the security and integration foundation:

- wallet provisioning, authentication, recovery, and device linking
- threshold signing and custody boundaries
- delegated authority, budgets, and policy enforcement
- transaction authorization and audit primitives
- an embedded wallet SDK for platform integrations

The next work should turn these primitives into a direct product instead of
expanding the wallet infrastructure in isolation.

## Product priority

1. **Direct agent spending product.** Build the funding account, agent list,
   budgets, approvals, and activity experience into the Console and dashboard.
2. **Universal agent connection.** Add OAuth, MCP, API credentials, and SDK
   adapters for Codex, ChatGPT, and other agent runtimes.
3. **Payment reach.** Complete stablecoin execution and integrate Airwallex
   virtual cards for ordinary merchants.
4. **Policy and audit.** Productize the existing merchant rules, limits, expiry,
   approvals, receipts, refunds, revocation, and evidence.
5. **Wallet infrastructure.** Maintain the existing custody, recovery, signing,
   and delegated-authority foundation as the secure execution layer.
6. **Embedded platform SDK.** Offer the proven agent-expense system to platforms
   that want it for their own users.

## Product boundary

Seams should own the control and evidence path from agent instruction through
commercial outcome. Merchant discovery, general agent orchestration, broad
identity management, and card-network infrastructure remain integration
surfaces.

The product should complete an expense-management job:

```text
Give this agent a budget and mandate, let it complete eligible purchases, and
show me exactly what it attempted, spent, settled, and recovered.
```

Wallet creation alone does not complete that job.

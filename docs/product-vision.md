# Product vision: Expense management for agents

Date created: June 20, 2026

Last revised: August 27, 2026

Status: draft product vision; use as product-direction and implementation
context.

Related docs:

- [Seams product vision](vision.md)
- [Stablecoin-linked virtual card](stablecoin-linked-virtual-card.md)
- [Airwallex sandbox integration](refactor-130-airwallex-sandbox-integration.md)
- [Router A/B protocol](./router-ab/protocol.md)
- [Wallet key and execution lanes](refactor-101-wallet-execution-lanes.md)
- [Agent identity and delegated spending](refactor-104-agent-id-spending.md)

## Thesis

Seams is an expense-management account for AI agents.

The customer funds one account, connects one or more agents, and defines what
each agent may buy. Seams binds those permissions to typed purchase intents,
enforces them before payment, and preserves the evidence needed to understand
authorizations, denials, approvals, settlement, and refunds.

Internal category shorthand:

```text
Ramp for agents, initially stablecoin-funded.
```

Developer-facing line:

```text
Give every agent a budget and spending mandate without giving it unrestricted
control of a wallet or card.
```

Customer-facing line:

```text
Fund once. Connect an agent. Control exactly what it can spend.
```

## Why this is the product

Embedded wallets and threshold signing solve custody and execution. They do not
by themselves complete the customer's expense-management job.

The direct product must answer:

```text
Which agent is acting?
What did its principal authorize?
Does this exact purchase satisfy the active mandate?
Should Seams allow, block, or escalate it?
How was it paid?
What settled, reversed, or refunded afterward?
```

This product can reach individuals and teams directly. It does not depend on a
new platform deciding to add wallets or an existing wallet application replacing
its infrastructure.

## Customer and buyer

The initial customer is an AI-native individual, operator, or small business
that already delegates repeated work to agents and wants those agents to make
bounded purchases.

The customer may also be the account administrator and funding principal. In a
larger organization, these roles can separate:

| Role | Responsibility |
| --- | --- |
| Economic buyer | Pays for controlled agent spending and expense operations. |
| Account administrator | Connects agents, sets policy, and manages funding. |
| Funding principal | Owns the stablecoin, fiat, or payment account. |
| Approver | Reviews purchases that cross defined thresholds. |
| Agent | Proposes or executes purchases within an Agent Grant. |

Strong first workflows include:

- software, API, domain, and cloud-service procurement
- business travel booking
- ecommerce inventory and supplies
- user-directed shopping at unrelated merchants
- recurring operational purchases with merchant and amount controls

## Product model

```text
Seams account
  -> funding balance
  -> agent connection
  -> Agent Grant
  -> spending mandate
  -> purchase intent
  -> policy decision
  -> approval when required
  -> payment execution
  -> settlement, receipt, refund, and audit
```

### Funding account

A customer should fund one primary Seams account. The account ledger separates:

- available balance
- budget allocated to active Agent Grants
- pending payment authorizations and holds
- settled spend
- reversed or expired holds
- refunds and recoverable balance

Budget allocation does not require an onchain transfer into a separate agent
wallet. Seams may provision isolated wallets, cards, or credentials underneath
for execution isolation, chain identity, privacy, or provider requirements.

### Agent connection

An Agent Connection identifies and authenticates one installed agent integration.
Supported connection surfaces should include:

- OAuth for user-authorized hosted agents
- a remote MCP server for Codex, ChatGPT, and compatible runtimes
- scoped API credentials for custom backends
- SDK adapters for agent frameworks

Connection authority and spending authority are separate lifecycle states.
Connecting an agent gives it access to the Seams API surface. An active Agent
Grant gives it bounded permission to propose or execute spend.

### Agent Grant

An Agent Grant binds:

- one Seams account
- one agent connection or agent identity
- one versioned spending mandate
- one budget and currency policy
- one validity period
- one approval policy
- one revocation epoch
- one set of permitted payment rails

The grant is narrow, expiring, and independently revocable. It carries no
authority to change account ownership, broaden its own mandate, export owner
keys, or create another grant.

### Spending mandate

A spending mandate defines what the agent may do. Its first policy vocabulary
should cover:

- per-purchase and cumulative budgets
- merchant and merchant-category rules
- item, quantity, and substitution constraints
- currency and geography
- shipping, tax, fee, and final-price ceilings
- delivery destination
- one-time and recurring-payment rules
- validity window and expiry
- human-approval thresholds
- payment-rail restrictions

The mandate is versioned, signed where required, and bound to a revocation
epoch. Natural-language authoring may propose a policy, but the enforcement
boundary is the reviewed typed mandate.

### Purchase intent

The agent submits a canonical purchase intent containing the final commercial
details available before payment:

```text
merchant
items and quantities
currency
subtotal
shipping
tax
fees
total
delivery terms
recurring-payment status
payment rail
```

Seams normalizes untrusted merchant and agent inputs once, computes the intent
digest, and evaluates the exact intent against the active grant.

### Policy decision

Every decision is explicit:

```text
allow
  -> the active grant permits execution

block
  -> the purchase violates a hard constraint

request approval
  -> the purchase matches an escalation rule and awaits a named approver
```

Diagnostics and model reasoning may explain a decision. The typed mandate,
normalized intent, account state, and approval state determine control flow.

### Execution and reconciliation

An allowed purchase executes through one supported rail. Seams links the policy
decision to every subsequent payment state:

```text
authorized
captured or settled
reversed
expired
partially refunded
refunded
disputed
```

The customer sees one evidence chain from agent instruction through final
financial outcome.

## Payment reach

### Stablecoin

Stablecoin is the initial funding and native settlement rail. It fits the
existing Seams wallet and signing foundation and gives customers an explicit,
programmable source of funds.

The first path should support one stablecoin on one production-approved chain
after the required operational and regulatory gates are satisfied. Testnet and
sandbox environments remain the development path until then.

### Virtual cards

Virtual cards let agents purchase from ordinary ecommerce merchants with no
Seams, agent, or stablecoin integration. This makes card reach central to the
shopping and procurement experience.

Airwallex is the first planned provider. The integration boundary should be:

| Seams owns | Airwallex owns |
| --- | --- |
| Agent identity and connection | Card program and issuance |
| Spending mandate and budget | Cardholder onboarding |
| Purchase-intent normalization | Sensitive card data |
| Policy decision and approval | Visa network access |
| Stablecoin funding allocation | 3DS and card authentication |
| Hold and settlement evidence | Card authorization and transaction events |
| Cross-rail activity and audit | Card lifecycle and provider settlement |

Seams should issue or assign bounded cards only when the purchase workflow needs
card reach. Per-order, per-agent, or shared card models remain execution choices
under the Agent Grant.

The [stablecoin-linked virtual-card plan](stablecoin-linked-virtual-card.md)
defines the longer-term reserve architecture. The first operating proof should
use the smallest Airwallex sandbox path that demonstrates one policy-bound
purchase, settlement, reversal, and refund.

## Direct product surface

### Console and dashboard

The direct customer experience should provide:

- account onboarding and funding
- available, allocated, pending, settled, and refunded balances
- connected-agent list and connection status
- Agent Grant creation, editing, expiry, and revocation
- budget and mandate templates
- approval inbox
- purchase activity and receipts
- blocked-attempt explanations
- card and stablecoin execution status
- audit and reconciliation detail

The primary dashboard actions should use expense-management language:

```text
Fund account
Connect agent
Create Agent Grant
Set budget
Review purchase
Revoke access
```

Wallet roots, shares, lanes, and provider credentials remain implementation and
advanced diagnostic concepts.

### Agent API and MCP surface

The normal agent surface should expose intent-oriented operations:

- `get_spending_authority`
- `propose_purchase`
- `request_purchase_approval`
- `execute_approved_purchase`
- `get_purchase_status`
- `cancel_purchase`
- `get_remaining_budget`

A generic unrestricted `send_money` or `sign` operation is outside the default
expense-management surface. Advanced wallet APIs may remain available through a
separately authorized integration.

Client-side tool approval can add a useful human checkpoint. Seams' server-side
mandate and account state remain the enforcement authority.

## Policy and audit foundation

The policy engine should make these guarantees practical:

- every execution is tied to one authenticated agent connection
- every agent connection spends through one active grant
- every grant has a budget, validity period, and revocation epoch
- every payment is bound to a normalized purchase intent
- an agent cannot broaden its own permissions
- approval is bound to the exact intent presented to the approver
- settlement and refunds remain linked to the original decision
- customers can reconstruct why Seams allowed, blocked, or escalated an action

The existing wallet policy, budget, authorization, and audit primitives provide
the foundation. The next work should expose them as a coherent expense product
through the Console, dashboard, API, and MCP server.

## Relationship to wallet infrastructure

Seams' wallet infrastructure provides:

- passkey and application-native authentication
- wallet provisioning and recovery
- device linking and authority revocation
- threshold custody and signing
- session and budget enforcement
- chain execution
- export and transfer of control where supported

These capabilities protect the funding account and execute supported payments.
The customer buys the agent-expense workflow built on top of them.

The embedded platform SDK remains valuable as a later distribution path. Agent
platforms can eventually provision Seams spending accounts and grants for their
own users after the direct product proves the workflow.

## Roadmap and current state

| Priority | Product layer | Current state | Next outcome |
| --- | --- | --- | --- |
| 1 | Direct agent spending product | Needs product surface | Build funding, agents, budgets, approvals, and activity into the Console and dashboard. |
| 2 | Universal agent connection | Needs product surface | Add OAuth, remote MCP, scoped API credentials, and SDK adapters. |
| 3 | Payment reach | Stablecoin foundation exists; card reach needs integration | Integrate one Airwallex sandbox card path, then satisfy production gates. |
| 4 | Policy and audit | Core primitives built | Productize merchant rules, limits, expiry, approvals, receipts, refunds, revocation, and evidence. |
| 5 | Wallet infrastructure | Built | Maintain as the custody and execution foundation. |
| 6 | Embedded platform SDK | Built | Offer as a later enterprise distribution channel. |

This order makes the requested operating path visible to a direct customer
before expanding infrastructure or enterprise integration breadth.

## First operating proof

The first proof should demonstrate one complete purchase lifecycle:

```text
Customer funds a Seams account
  -> connects one agent
  -> creates one Agent Grant and budget
  -> agent proposes an exact purchase
  -> Seams allows, blocks, or requests approval
  -> an allowed purchase executes in the Airwallex sandbox or testnet
  -> the dashboard shows authorization, settlement, receipt, and refund state
```

Success requires one real agent integration and one repeated customer workflow.
Creating wallets and policies without completing purchases is insufficient
evidence of product demand.

## Product boundaries

Near-term scope:

- direct Seams account and dashboard
- stablecoin funding
- connected agents
- typed purchase intents
- Agent Grants, budgets, approvals, and revocation
- Airwallex sandbox virtual-card execution
- purchase, receipt, refund, and audit history

Later scope:

- embedded agent-platform distribution
- additional card issuers and payment rails
- fiat funding and treasury integrations
- organization roles and multi-approver workflows
- subscription management
- AP2-compatible mandate import and export
- policy templates for more expense categories

Deferred scope:

- general-purpose identity platform
- broad agent orchestration
- merchant discovery and product recommendation
- consumer banking unrelated to agent spending
- generic workflow automation
- robotics and physical-action policy

## Product principles

- Start with a repeated expense-management job.
- Keep one primary funding account and allocate authority through the ledger.
- Give agents typed intent tools instead of unrestricted credentials.
- Require an explicit budget, validity period, and revocation path for every
  Agent Grant.
- Bind approval to the exact purchase that will execute.
- Treat stablecoin and cards as payment rails under one policy model.
- Preserve one audit chain through settlement and refund.
- Keep custody and signing details below the normal customer experience.
- Prove the direct workflow before expanding platform distribution.

## Open questions

- Which first workflow has the strongest repeated demand: software procurement,
  travel, ecommerce operations, or personal shopping?
- Should the first Airwallex proof use one card per order, one card per agent, or
  a shared card with remote authorization?
- Which agent runtime should be the first OAuth and MCP integration?
- Which purchases may execute automatically in the first release?
- Which funding and regulatory model can support the first production customer?
- Which evidence should appear in the default activity view and which belongs in
  an advanced audit view?

## Reference links

- Google Agent Payments Protocol announcement:
  <https://cloud.google.com/blog/products/ai-machine-learning/announcing-agents-to-payments-ap2-protocol>
- AP2 protocol: <https://ap2-protocol.org/>
- Airwallex issuing overview: <https://www.airwallex.com/docs/issuing/overview>
- Airwallex supported card programs:
  <https://www.airwallex.com/docs/issuing/supported-card-programs>
- OpenAI MCP documentation: <https://learn.chatgpt.com/docs/extend/mcp>

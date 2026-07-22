# Product Vision: Policy Harness For Agentic Commerce

Date created: June 20, 2026

Status: draft product vision; use as positioning and product-direction context.

Related docs:

- [Router A/B sales pitch](router-a-b-sales-pitch.md)
- [Router A/B spec](./router-ab/protocol.md)
- [Router A/B deployment](./router-ab/deployment.md)
- [Wallet key and execution lanes](refactor-96-wallet-execution-lanes.md)
- [Physical device linking](refactor-98-device-linking.md)
- [Agent identity and delegated spending](refactor-99-agent-id-spending.md)
- [Voice agent GTM](../voiceId/docs/voice-agent-gtm.md)
- [VoiceID engine specification](../voiceId/docs/voiceId-mvp-1.md)

## Thesis

The key product is a policy engine attached to cryptographic proofs.

The product should help users, merchants, marketplaces, and organizations define
what an AI agent may do, bind that permission to a verifiable intent, enforce it
before execution, and revoke it cryptographically when authority changes.

Short version:

```text
Prove who is acting.
Prove what they approved.
Enforce what they can do.
```

Product category:

```text
Policy Harness for Agentic Commerce
```

Buyer-facing line:

```text
Give agents permission to act without giving them unlimited authority.
```

Developer-facing line:

```text
Define what an agent may do. Bind it to signed intent. Enforce it before money,
inventory, or authority moves.
```

## Why This Is Stronger Than A Broad Identity Pivot

A wallet-as-a-service product resembling Dynamic centers on wallet creation,
authentication, embedded wallets, signing flows, and key management.

A generalized identity platform resembling Veridas centers on identity proofing,
document verification, biometrics, liveness, reusable credentials, and
authentication.

Both categories are adjacent to this product, but neither is the exact wedge.
The stronger wedge is authorization for autonomous action:

```text
Who is acting?
What did they approve?
What is the agent allowed to do?
Can that authority be revoked before execution?
Can the system prove what happened afterward?
```

The wallet/key layer remains valuable because autonomous agents eventually need
to execute through payment rails, wallets, marketplace accounts, merchant APIs,
or signing systems. The identity layer remains valuable because high-risk agent
actions need subject proof, role proof, device proof, biometric proof, or
credential proof.

The policy harness is the control layer between those surfaces.

## Core Product Primitive

The core object is a signed mandate:

```text
This subject may perform this class of action, under this policy, until this
expiry, within this budget, against this exact intent shape.
```

A signed mandate should be:

- scoped to a subject, agent, device, org role, or wallet
- bound to typed intent data
- constrained by budget, merchant, marketplace, geography, time, and risk rules
- versioned by policy epoch
- revocable before execution
- auditable after execution

## Product Layers

| Layer | Responsibility |
| --- | --- |
| Policy Studio | Prompt or visually define agent authority. |
| Policy Compiler | Convert natural language and templates into typed policy. |
| Intent Harness | Canonicalize cart, order, bid, refund, payment, and shipment intents. |
| Proof Layer | Bind user, org role, wallet, passkey, device, biometric, or credential proof. |
| Simulation Layer | Check totals, merchant, inventory, fees, settlement, substitutions, and risk flags. |
| Enforcement Gateway | Allow, deny, escalate, or require human approval. |
| Revocation And Audit | Track policy epochs, signed mandates, revocation state, and evidence trails. |
| Signing And Execution | Execute through wallets, payment rails, marketplaces, merchant APIs, or agent tools. |

The engine is the enforcement core. The harness is the runtime around agents,
tools, payment systems, and signing systems. The studio is the interface for
authoring, inspecting, testing, and debugging policies.

## Policy Engine Guarantees

The policy engine should make these guarantees practical:

- Harder to spoof: high-risk authority requires cryptographic, biometric,
  device, credential, wallet, or org-role proof.
- Harder to fake prompts and intents: the approved user-visible action is bound
  to a canonical typed intent digest.
- Cryptographically revocable policy and intents: policy epochs, delegates,
  sessions, credentials, and pending intents can be revoked before execution.
- Auditable execution: every action has a verifiable chain from proof to policy
  decision to intent digest to signature, payment, bid, or API call.

## Policy Studio

A Tines-style visual studio is a good interface metaphor for inspection and
debugging. The user should be able to see triggers, policy checks, agent steps,
human approvals, simulation, execution, and audit output as a graph.

The first version should be template-first and prompt-assisted:

1. User describes the delegation in plain language.
2. The studio proposes a typed policy.
3. The user reviews constraints, approval paths, budgets, and revocation rules.
4. The system simulates allowed and denied examples.
5. The policy is signed, versioned, and deployed.

The visual canvas should show the generated policy rather than forcing every
user to manually draw a workflow from scratch.

Useful studio blocks:

- trigger
- agent identity
- user or org proof
- device proof
- credential proof
- intent normalization
- cart/order/bid/refund simulation
- merchant or marketplace checks
- budget checks
- condition
- human approval
- signer or payment rail
- revocation check
- audit sink

## Relationship To Aomi

Aomi is a useful neighboring reference because it frames itself as a harness for
agentic blockchain actions. Its core ideas include intent-first interaction,
structured action generation, contextual intent sanitization, simulation
guardrails, and execution.

The policy harness direction should focus on authorization:

```text
Is this agent allowed to perform this exact commercial action right now?
```

The product should work across off-chain and on-chain commerce:

- shopping carts
- checkout flows
- marketplace listings
- bidding systems
- refunds
- promotions
- supplier orders
- stablecoin settlement
- wallet signatures
- merchant APIs

This keeps the product tied to commerce outcomes instead of becoming a generic
agent workflow tool.

## Relationship To AP2-Style Mandates

Agentic commerce protocols such as AP2 validate the need for signed mandates,
verifiable credentials, and accountable agent payments.

The product should integrate with emerging mandate-style standards where they
fit. The value should be the policy authoring, testing, enforcement, revocation,
and audit layer around those mandates.

Practical position:

```text
Author mandates.
Test mandates.
Sign mandates.
Enforce mandates.
Revoke mandates.
Audit mandates.
```

## First Wedge: Shopping And Ecommerce Agents

Shopping and ecommerce are the strongest first wedge because the failure modes
are concrete:

- agent buys the wrong item
- prompt injection changes the cart
- seller substitutes a product
- fees or shipping push the order outside budget
- agent spends after authority was revoked
- refund or support agent exceeds policy
- marketplace bid crosses the approved ceiling
- merchant cannot prove what the user authorized

The product should make delegated shopping safe enough for real commerce.

Example policy:

```text
This shopping agent may buy one jacket under USD 500 from approved merchants in
Japan, with no refurbished substitutions, no recurring payments, and human
approval required if shipping exceeds USD 40 or delivery is later than 14 days.
The mandate expires in 24 hours.
```

Example execution chain:

```text
User proof
  -> signed shopping mandate
  -> agent finds quote
  -> cart intent digest
  -> simulation checks price, merchant, shipping, taxes, substitutions
  -> policy decision
  -> payment/signing execution
  -> receipt and audit trail
```

Stable commerce abstraction:

```text
one approved quote -> one customer payment -> one purchase order -> one receipt
trail -> one refund/support policy
```

## Use Case: AI Shopping Agents

AI shopping agents need delegated spend with narrow authority.

Useful controls:

- signed purchase mandates
- merchant allowlists and category rules
- max price and fee ceilings
- shipping and delivery constraints
- substitution rules
- refund and support policy
- per-order mandate expiry
- quote-to-payment linkage
- payment rail constraints
- revocation before checkout

The product prevents a web page, seller, tool result, or prompt injection from
silently turning a narrow shopping instruction into broader spend authority.

## Use Case: Robotics Fleets

Robotics fleets need delegated physical authority.

Useful controls:

- robot device identity
- operator or owner proof
- site and zone policy
- action class limits
- time windows
- safety budgets
- human-approved delegated sessions
- emergency revocation
- audit trails for physical actions

Clean framing:

```text
Humans approve. Robots act. Keys never move.
```

Example robot flow:

```text
Human approval
  -> delegated robot session
  -> robot device proof
  -> typed physical intent
  -> policy, expiry, budget, revocation, and location checks
  -> execution
  -> audit evidence
```

Robotics should remain future scope until the commerce wedge is proven.

## Use Case: AI Managed Storefronts

AI storefronts make commercial commitments on behalf of a seller.

Useful controls:

- discount limits
- margin floors
- inventory reservation rules
- refund limits
- customer segment rules
- supplier reorder policy
- campaign authority
- promotion expiry
- approval paths for exceptions
- audit trails for customer-facing commitments

The model can suggest commercial actions. The policy harness decides which
actions can become binding offers, refunds, promotions, orders, or payments.

## Use Case: AI Managed Bidding And Marketplace Agents

Bidding agents need strict spend, listing, and settlement controls.

Useful controls:

- auction-specific mandates
- max bid and fee ceiling
- bid cadence limits
- marketplace allowlists
- listing metadata hash binding
- seller trust checks
- settlement constraints
- per-auction and per-day budgets
- strategy approval
- revocation before settlement

Example policy:

```text
This bidding agent may bid up to USD 2,000 on this exact listing until Friday at
18:00 UTC. It may increase bids only in USD 25 increments, may not bid if seller
trust falls below the approved threshold, and must stop if total fees exceed
8 percent.
```

## Competitive Positioning

| Reference | Their Center | Useful Lesson | Our Center |
| --- | --- | --- | --- |
| Dynamic | Wallet auth, embedded wallets, key management, signing flows | Key infrastructure and developer UX matter. | Policy-bound authorization over wallet, payment, and agent execution. |
| Veridas | Identity verification, biometrics, liveness, reusable identity credentials | Strong identity proof can be a policy input. | Use identity and presence proofs to authorize exact agent actions. |
| Tines | Visual workflow automation and governed AI workflows | Canvas inspection helps teams trust and debug complex automations. | Policy Studio for mandate authoring, simulation, revocation, and audit. |
| Aomi | Harness for agentic blockchain actions | Intent-first execution and simulation are valuable for agents. | Commerce-wide authorization harness across carts, bids, payments, APIs, and signatures. |
| AP2-style protocols | Signed mandates for accountable agent payments | Standard mandate objects can become interoperability rails. | Author, test, sign, enforce, revoke, and audit mandates. |

## Product Surface

Initial product surfaces:

- policy template library
- prompt-to-policy authoring
- typed commerce intent schemas
- mandate signing and verification
- policy simulation against allowed and denied examples
- revocation registry
- audit log and evidence viewer
- agent gateway API
- tool or MCP gateway for agents
- payment and wallet execution adapters

Future surfaces:

- visual policy canvas
- marketplace-specific bid policy packs
- Shopify and ecommerce platform integrations
- AP2-compatible mandate tooling
- org role and approval workflows
- robotics policy packs
- physical device identity and site policy
- AI storefront policy packs

## Implementation Principles

Keep the policy model precise:

- use typed intents rather than raw prompts as the enforcement boundary
- normalize untrusted tool, agent, wallet, merchant, and marketplace inputs once
  at boundaries
- make policy branches explicit and versioned
- require expiry for delegated authority
- require a policy epoch for revocation-sensitive decisions
- bind every execution to a canonical intent digest
- preserve a verifiable audit chain for high-risk actions

Keep product scope concrete:

- start with shopping and ecommerce agents
- use robotics, storefronts, and bidding as expansion paths
- treat identity vendors as proof providers where useful
- treat wallet/key infrastructure as the execution layer
- treat the policy harness as the product center

## Near-Term MVP

MVP goal:

```text
Let a user or merchant create a signed commerce mandate, let an AI agent propose
an action, simulate and enforce the policy, then execute or deny with an audit
trail.
```

Suggested MVP sequence:

1. Define typed commerce intents for quote, cart, checkout, refund, and bid.
2. Define a minimal signed mandate schema.
3. Build a policy compiler for a small template set.
4. Add simulation fixtures for allowed and denied shopping actions.
5. Add mandate signing, policy epoch, expiry, and revocation checks.
6. Add an enforcement gateway for one shopping-agent flow.
7. Add an audit viewer that shows proof, mandate, intent digest, decision, and
   execution result.
8. Add prompt-to-policy after the typed policy model is stable.
9. Add a visual studio after templates and audits prove the workflow.

## Open Questions

- Which commerce wedge is first: personal shopping, merchant-side storefront
  agents, marketplace bidding, or procurement?
- Which mandate format should be internal-only, and which should align with AP2
  or other emerging agent-commerce standards?
- Which execution rail should be first: wallet signing, stablecoin payment,
  merchant API, marketplace API, or simulated checkout?
- Which proof input is required for v1: passkey, wallet, email, org role,
  biometric presence, or external identity credential?
- What is the smallest policy studio that gives users trust without requiring a
  full workflow-builder product?

## Reference Links

- Dynamic wallet infrastructure: <https://www.dynamic.xyz/features/wallet-infrastructure>
- Dynamic embedded wallets: <https://www.dynamic.xyz/features/embedded-wallets>
- Veridas identity verification: <https://veridas.com/en/identity-verification-platform/>
- Veridas ID wallet: <https://veridas.com/en/id-wallet/>
- Tines AI platform: <https://www.tines.com/platform/ai/>
- Tines AI agent action: <https://www.tines.com/docs/actions/types/ai-agent/>
- Aomi: <https://aomi.dev/>
- AP2 protocol: <https://ap2-protocol.org/>
- Google AP2 announcement: <https://cloud.google.com/blog/products/ai-machine-learning/announcing-agents-to-payments-ap2-protocol>

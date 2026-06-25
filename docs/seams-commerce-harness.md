# Seams Commerce Harness Plan

Status: business, product, and go-to-market plan

Last updated: June 25, 2026

Document scope:

This plan is self-contained. It covers the business thesis, customer pain,
product surface, go-to-market path, validation plan, revenue model, and the
core implementation assumptions required to understand the product. A deeper
engineering spec can exist separately, and this file should still stand alone
for strategy review, visa review, investor discussion, and first-principles
product iteration.

## 1. Executive Summary

Seams Commerce Harness is the merchant-side control layer for agentic
ecommerce.

It helps merchants safely use AI agents to sell more, manage commerce
operations, and expose better offers to the agentic web.

Reference pitch lines:

```text
Seams helps merchants safely use agents to sell more, manage commerce
operations, and expose better offers to the agentic web.
```

```text
Seams gives merchants wallet/auth and AI store-management controls so their own
agents can sell, promote, price, and procure safely.
```

The product starts from the Seams SDK foundation: MPC signing, embedded
wallets, account/auth primitives, and a policy engine. The Commerce Harness
turns that foundation into merchant workflows: visitor assistance,
abandoned-cart recovery, discounts, campaigns, dynamic pricing, inventory,
procurement, offer feeds, support, refunds, and audit.

The first wedge should stay narrow and revenue-adjacent:

```text
Abandoned-cart recovery + discount policy + onsite assistance +
merchant-approved offer feed + audit.
```

Architecture assumption:

Agents propose ecommerce actions through Seams-controlled tools. Seams converts
each request into a typed `CommerceIntent`, checks merchant policy, asks for
human approval when needed, executes through approved connector or signer
envelopes, and records audit evidence. This keeps the product grounded in the
wallet/auth SDK: the SDK creates secure accounts, agent credentials, policy
checks, approval UX, and MPC signing gates.

## 2. Motivation

### 2.1 Platform Risk For Merchants

OpenAI, Google, Stripe, Visa, Mastercard, PayPal, and other large platforms are
building buyer-side agentic commerce surfaces. These systems can help buyers
discover and purchase products. They also shift discovery, intent, checkout,
and relationship control toward the platform.

Merchants still carry the hard operating work:

- product data quality;
- margin protection;
- inventory and stockouts;
- discount strategy;
- fulfillment and shipping;
- returns and refunds;
- chargebacks and disputes;
- customer support;
- loyalty and repeat purchase;
- account ownership;
- regulatory and payment partner obligations.

The merchant needs their own agent infrastructure. The agent should work for the
merchant, inside merchant policies, with the merchant's customers, data, and
storefront.

### 2.2 Buyer-Side AI Has A Weak Consumer Value Proposition

Many buyer-side shopping-agent pitches assume consumers want agents to recommend
more products and complete more purchases. That is a weak emotional pitch for
users who already feel overwhelmed by ads, recommendations, upsells, and
low-quality product discovery.

The stronger wedge is merchant value:

- recover abandoned carts;
- answer visitor questions;
- apply strategic discounts;
- protect margin;
- improve campaign timing;
- publish approved offers;
- manage marketplace listings;
- source inventory before stockouts;
- reduce support load;
- keep customers on the merchant's platform.

This makes agentic commerce a revenue and operations tool, grounded in merchant
workflows.

### 2.3 The MAI Analogy

MAI helps marketers connect ads, analytics, and Shopify data; understand
performance in real time; optimize spend; and act across ad platforms.

Seams applies that operating pattern to ecommerce:

```text
Connect store data.
Understand visitors, carts, orders, inventory, campaigns, and offers.
Let approved agents act across storefront, campaigns, pricing, procurement,
support, and feeds.
Record every action and approval.
```

MAI is a performance marketing agent. Seams Commerce Harness is a merchant
commerce operations agent harness with wallet/auth, policy, and execution
controls.

## 3. Product Category

Primary category:

```text
Merchant-side agentic commerce control layer.
```

Secondary category descriptions:

- ecommerce agent operations SDK;
- commerce policy and delegation layer;
- wallet/auth infrastructure for merchant agents;
- merchant-owned agentic storefront infrastructure;
- control plane for AI-operated commerce.

Avoid reducing the product to a chatbot, a buyer shopping assistant, a virtual
card wrapper, an embedded wallet provider, or an ACP/AP2/UCP implementation.
Those are surfaces or adapters. The product value is merchant authority,
control, execution, and evidence.

## 4. Target Customers

### 4.1 First ICP

The first ICP should be Japan-origin ecommerce operators with real operational
pain and clear revenue upside:

- export merchants selling Japanese goods overseas;
- proxy-shopping and forwarding services;
- vertical ecommerce operators;
- niche marketplaces;
- auction or bidding platforms;
- collectible, hobby, fashion, food, beauty, craft, anime, game, and specialty
  goods merchants.

### 4.2 Buyer Persona

Primary buyer:

- founder/operator of a small or medium ecommerce business;
- ecommerce manager;
- marketplace operator;
- proxy-shopping service operator;
- head of growth or retention at a merchant;
- technical founder building a marketplace or auction app.

### 4.3 User Personas

Merchant admin:

- owns store policy;
- connects ecommerce tools;
- approves sensitive actions;
- monitors revenue, margin, support, and audit.

Merchant staff:

- handles campaigns, inventory, support, fulfillment, and procurement;
- delegates bounded tasks to agents;
- reviews escalations.

Merchant agent:

- operates store workflows through Codex, Claude, OpenAI, OpenClaw, Hermes,
  Ironclaw, or a custom agent runtime;
- uses Seams credentials and policies to act safely.

Store visitor:

- receives onsite help;
- receives approved offers;
- creates an embedded wallet/account on the merchant's site;
- approves high-risk or wallet-linked actions when needed.

Marketplace or auction participant:

- uses embedded wallet/account for login, bidding identity, KYC attachment,
  deposits, settlement, or future virtual card use.

## 5. Core Jobs To Be Done

For merchants:

- Help me recover revenue from abandoned carts.
- Help me answer visitors before they leave.
- Help me apply discounts without damaging margin.
- Help me publish offers that agents and deal surfaces can discover.
- Help me keep product, inventory, pricing, and campaign operations current.
- Help me use agents without giving them uncontrolled authority.
- Help me prove which agent acted, what policy applied, and who approved it.
- Help me keep customer accounts and relationships on my storefront.

For technical merchants and platforms:

- Give me an SDK for wallet/auth, delegated agent credentials, policies, and
  commerce actions.
- Let my own agent stack call controlled commerce tools.
- Let me integrate stablecoin wallets, virtual cards, checkout, KYC, and
  marketplace workflows over time.
- Let me publish ACP/UCP/MCP-friendly feeds from one canonical merchant data
  model.

For non-technical merchants:

- Give me a hosted agent option.
- Let me connect Shopify, ads, analytics, email, inventory, and support tools.
- Let me configure plain-English policies and approve sensitive actions.
- Show clear logs and results.

## 6. Product Pillars

### 6.1 Wallet/Auth Infrastructure

The Seams SDK provisions identity and authority primitives:

- merchant wallets;
- staff accounts and roles;
- embedded user wallets/accounts;
- agent credentials;
- MPC signing;
- wallet sessions;
- authentication and recovery;
- policy-scoped approvals;
- revocation and audit.

### 6.2 Commerce Policy Engine

The policy engine answers:

```text
Who or what is acting?
What action is requested?
Which merchant, staff, user, agent, wallet, and store context applies?
What budget, margin, campaign, inventory, or approval constraint applies?
Can the action execute now?
Does a human need to approve?
What evidence must be stored?
```

### 6.3 Merchant AI Harness

The harness turns policy into store workflows:

- onsite visitor assistance;
- abandoned-cart recovery;
- discount and coupon authority;
- campaign and outreach actions;
- dynamic pricing;
- marketplace listing updates;
- inventory monitoring;
- procurement recommendations;
- supplier outreach;
- support drafts;
- refund preparation;
- agent-initiated payment authorization;
- offer feed publication;
- audit.

### 6.4 Agent-Neutral Runtime

The merchant can bring any agent:

- Codex;
- Claude;
- OpenAI models;
- OpenClaw;
- Hermes;
- Ironclaw;
- cloud model endpoint;
- OpenRouter-style gateway;
- self-hosted custom agent;
- Seams-hosted OpenClaw/Hermes for non-technical merchants.

The harness exposes typed tools and policies. The model provider remains
replaceable.

### 6.5 Protocol And Feed Adapters

Seams should be friendly to ACP, UCP, AP2, MCP, A2A, Google Merchant Center,
OpenAI product feeds, affiliate feeds, and future shopping-agent systems.

The native Seams model remains merchant-owned. Protocol adapters are outputs
and inputs around that core.

## 7. Feature Scope

### 7.1 Merchant Wallets

Purpose:

Create a merchant-owned authority root for store operations.

Key features:

- merchant org wallet;
- owner account;
- staff roles;
- passkey or biometric login;
- recovery flow;
- stablecoin receiving address where relevant;
- treasury metadata;
- policy admin permissions;
- audit export;
- agent credential issuance;
- revocation.

Use cases:

- accept stablecoin payments in future merchant workflows;
- authorize agent budget policies;
- manage staff and agent permissions;
- sign merchant policy versions;
- sign public offer feed attestations;
- manage marketplace or auction treasury workflows.

### 7.2 Agent Credentials

Purpose:

Give an AI agent scoped, revocable authority to operate merchant workflows.

Key features:

- agent identity record;
- runtime type: Codex, Claude, OpenAI, OpenClaw, Hermes, Ironclaw, custom;
- credential binding to merchant org;
- allowed tools;
- allowed actions;
- budget limits;
- discount limits;
- time windows;
- approval thresholds;
- policy version binding;
- revocation;
- per-action audit logs.

### 7.3 Embedded User Wallets

Purpose:

Let merchants create wallet-backed user accounts inside their own storefront,
marketplace, or auction site.

Use cases:

- ecommerce account login;
- marketplace bidding account;
- auction identity and deposit gating;
- customer reward wallet;
- stablecoin payment receipt;
- future buyer-agent delegation;
- virtual cards for marketplace spending or refunds.

### 7.4 Policy Studio

Purpose:

Let merchants define, test, and deploy policies without reading code.

MVP interface:

- template-first setup;
- prompt-assisted policy creation;
- plain-language explanation;
- rule preview;
- allowed and denied examples;
- human approval thresholds;
- budget and margin guardrails;
- policy versioning;
- publish and rollback.

### 7.5 Onsite Assistant

Purpose:

Let a merchant-owned agent help visitors on the merchant site.

Capabilities:

- answer product questions;
- compare products within the merchant catalog;
- ask clarifying questions;
- apply eligible offers;
- help with shipping or returns;
- capture email with consent;
- save preferences to embedded wallet/account;
- escalate to merchant support.

### 7.6 Abandoned-Cart Recovery

Purpose:

Recover measurable revenue while protecting discount margin and user consent.

Capabilities:

- ingest cart abandonment events;
- segment carts by value, product, inventory, margin, user status, geography,
  and return probability;
- propose recovery action;
- choose discount under policy;
- draft email/SMS/push message;
- send through configured provider after policy check;
- record offer, copy, discount, expiry, and outcome;
- attribute recovered revenue.

### 7.7 Discount And Promotion Control

Purpose:

Let agents apply promotions strategically.

Capabilities:

- product/category-level margin data;
- discount floor and ceiling;
- coupon creation;
- bundle offers;
- limited-time offers;
- user segment rules;
- inventory-aware promotion;
- approval thresholds;
- feed publication.

### 7.8 Dynamic Pricing And Marketplace Listings

Purpose:

Manage prices across storefront and marketplace channels.

Initial scope:

- recommendation-only pricing;
- human-approved price updates;
- limited marketplace listing updates;
- simulation before execution.

Later scope:

- automatic price movement within strict bands;
- auction reserve adjustment;
- multi-channel price synchronization;
- seasonal or event-driven rules.

### 7.9 Inventory And Procurement

Purpose:

Help merchants avoid stockouts and manage sourcing.

MVP:

- proactive inventory alerts;
- reorder suggestions;
- supplier email drafts;
- human-approved procurement requests.

Future:

- agent-initiated procurement under policy;
- wallet or virtual-card payment for supplier orders;
- marketplace sourcing;
- bidding on P2P inventory;
- shipment and receipt evidence.

### 7.10 Ad Spend And Campaign Budgets

Purpose:

Give agents bounded marketing authority.

Initial stance:

Campaigns should start as recommendations and drafts. Execution can be added
after the merchant trusts policies and audit.

### 7.11 Support, Refunds, Returns, And Disputes

Purpose:

Turn support and post-purchase workflows into policy-controlled agent actions.

Actions:

- draft response;
- classify issue;
- request missing evidence;
- recommend refund, replacement, or store credit;
- escalate to staff;
- prepare dispute packet;
- record final outcome.

### 7.12 Offer Feeds And Commerce Cues

Purpose:

Expose merchant-approved offers to external shopping agents, affiliates, deal
surfaces, and protocol platforms.

Native object:

```text
CommerceCue
```

Cue types:

- offer;
- discount;
- coupon;
- bundle;
- product drop;
- abandoned-cart recovery offer;
- marketplace listing;
- auction listing;
- procurement request;
- supplier request;
- restock notice;
- merchant request for buyer demand.

Outputs:

- ACP product and promotion feeds;
- UCP catalog/search/checkout endpoints;
- MCP tools;
- affiliate feeds;
- merchant-owned public feeds;
- partner marketplace feeds;
- AP2 mandate/payment metadata where relevant.

### 7.13 Cross-Border Commerce Control

Purpose:

Make Japan/APAC export operations a first-class control layer for agentic
commerce.

Capabilities:

- market profiles for destination countries;
- localized catalog projections;
- market price books with FX, rounding, margin floors, discount caps, and
  effective dates;
- payment-route selection by market;
- landed-cost estimates;
- shipping promise quotes;
- restricted-goods checks;
- attribution for agent, search, social, marketplace, and affiliate channels.

### 7.14 AP2 Payment Credential Layer

Purpose:

Use AP2-style Checkout Mandates and Payment Mandates as the authorization
envelope for agent-initiated payments. Seams can act as both the Trusted Surface
and the internal Credential Provider for Seams-controlled wallets, virtual cards,
stablecoin accounts, or payment-token vaults. Purchase authority is dual-control:
the agent has a delegated threshold signing share, and the Seams backend must
contribute the policy-controlled MPC share before a valid P-256 mandate signature
exists.

Role mapping:

- user or merchant owner: grants payment authority;
- Seams Trusted Surface: renders the approval UI and signs open mandates after
  passkey, biometric, or wallet-backed approval;
- shopping agent: assembles the checkout and initiates closed mandate signing
  with its delegated threshold signing share;
- Seams MPC policy co-signer: validates the typed mandate, then contributes the
  backend MPC share when policy, budget, consent, and revocation checks pass;
- Seams Credential Provider: verifies completed threshold-signed mandates, checks
  budget and revocation state, and releases a scoped payment JWT or credential;
- merchant or SaaS vendor: receives normal card, wallet, bank, or stablecoin
  payment unless it supports native AP2 verification;
- payment rail or processor: settles the payment and returns evidence.

Agent transaction flow:

```text
1. User approves an open Checkout Mandate and open Payment Mandate in Seams.
2. Open mandates constrain merchant, product or plan, max amount, recurrence,
   expiry, payment instrument, and delegated agent public key.
3. Agent finds the exact checkout and starts threshold signing with its delegated
   share.
4. Seams checks checkout hash, merchant, amount, recurrence, budget, consent,
   revocation, replay, and policy version.
5. Seams contributes the backend MPC share; a valid P-256 signature exists only
   when both the agent share and Seams policy share participate.
6. Seams Credential Provider verifies the signed mandates and releases a scoped
   payment JWT, payment credential, or spend authorization.
7. Checkout executor pays through normal rails or an AP2-native merchant flow.
8. Audit stores mandates, credential authorization, receipts, and execution
   evidence.
```

Guardrails:

- the agent never receives raw card details, wallet private keys, or broad
  payment credentials;
- the agent can initiate threshold signing, then Seams policy co-signing is
  required to complete the P-256 signature;
- Seams cannot unilaterally create a purchase-authorizing mandate or credential
  without a valid user-approved open mandate and agent threshold participation;
- delegated signing authority is limited to typed AP2 mandate payloads;
- open mandates must be short-lived and tied to explicit constraints;
- payment JWT or credential release requires mandate verification and budget
  reservation;
- the credential layer encodes scoped authorization after mandate verification;
- overlapping or replayed mandate use fails closed;
- receipts and mandate evidence must be retained for refunds, disputes, and
  audit.

## 8. Commerce Agent Deployment Strategy

Seams should support three deployment routes:

1. Agent routes ecommerce calls through Seams.
2. Seams-hosted agents for non-technical merchants.
3. Self-hosted setups for technical merchants, agencies, and marketplace
   builders.

The business point is simple: merchants can choose their agent stack while
Seams remains the policy, approval, connector, signing, feed, and audit layer.

Common control flow:

```text
Agent proposes an action.
Seams converts it into a typed commerce intent.
Seams checks merchant policy, budget, consent, inventory, margin, and risk.
Merchant or user approves sensitive actions.
Seams executes through store, email, ads, wallet, payment, or feed connectors.
Audit records intent, policy decision, approval, execution, and result.
```

Route 1: agent routes ecommerce calls through Seams.

This is the default BYO-agent path. A merchant can use Codex, Claude, OpenClaw,
Hermes, a cloud model endpoint, an OpenRouter-style gateway, or a custom agent.
The agent receives only Seams tools. Store credentials, payment credentials,
raw wallet signing authority, campaign credentials, and feed publication rights
stay behind the Seams policy layer.

Example:

```text
Codex / Claude / OpenClaw / custom merchant agent
  -> Seams MCP, API, plugin, SDK, CLI, or sidecar
  -> Commerce policy engine
  -> approval service
  -> execution connectors
  -> audit
```

Route 2: Seams-hosted agents.

This path is for merchants who want the outcome without running agent
infrastructure. Seams can host an OpenClaw/Hermes/Ironclaw-style agent runtime,
connect it to merchant tools, apply policies, and give the merchant a dashboard
or chat surface for approvals, configuration, and review.

Route 3: self-hosted setups.

Technical merchants can run their own agent runtime on a Mac mini, private
server, cloud VM, or internal workstation. The recommended shape is a local
Seams sidecar or proxy that exposes MCP tools to the agent, forwards proposed
actions to Seams for policy checks, receives approved envelopes, and either
executes local connectors or calls Seams cloud connectors.

Advanced self-hosted mode can keep connector credentials on the merchant's own
machine. Even in that mode, mutating actions should require a current policy
epoch, valid device binding, valid agent credential, approved action envelope,
and replay protection.

Core technical assumptions:

- agents are planners and operators, not raw authority holders;
- connector credentials live in Seams vault or a merchant-controlled sidecar;
- privileged actions execute only from approved action envelopes;
- wallet or payment signing goes through an approved signer envelope;
- AP2-style payment credential release requires mandate verification, budget
  reservation, and audit evidence;
- every action creates evidence for support, refunds, disputes, and audit.

## 9. First Wedge And MVP

The MVP should prove:

```text
A merchant can safely delegate a revenue-generating store workflow to an AI
agent and see measurable business value.
```

MVP business scope:

- abandoned-cart recovery;
- discount guardrails;
- onsite assistance;
- merchant-approved offer feed;
- approval UX;
- audit log;
- one agent path, ideally Codex/MCP for technical demos or hosted OpenClaw for
  merchant demos.

MVP exclusions:

- live card issuing;
- broad dynamic pricing automation;
- autonomous procurement payment;
- external AP2 network interoperability;
- full UCP checkout implementation;
- complex KYC workflows;
- multi-marketplace bid execution.

## 10. Validation Plan

### 10.1 Discovery Questions

For merchants:

- How many carts are abandoned weekly?
- What recovery tactics do you use today?
- How do you decide when to discount?
- Which actions would you trust an agent to do automatically?
- Which actions require approval?
- What store tools do you use now?
- How much time do you spend on campaigns, support, inventory, and pricing?
- Would you expose approved offers to ChatGPT, Google, affiliates, or shopping
  agents if you kept control?
- Do you need wallet-backed customer accounts, bidding identity, KYC, or
  stablecoin payments?

For proxy-shopping and marketplace operators:

- Do users need wallet/account identity?
- Do bidders need KYC or deposits?
- Are refunds, disputes, and support evidence painful?
- Can agents help with buyer questions, offers, or procurement?
- Which actions have real fraud or margin risk?

### 10.2 Pilot Success Metrics

Revenue:

- recovered-cart revenue;
- conversion lift after onsite assistance;
- offer-feed attributed sales;
- campaign conversion;
- average discount versus margin target.

Operations:

- time saved on campaign setup;
- support tickets avoided or shortened;
- inventory alerts acted on;
- procurement drafts approved;
- manual approval rate.

Trust:

- number of allowed agent actions;
- number of escalated actions;
- number of denied unsafe actions;
- audit completeness;
- merchant confidence score.

### 10.3 Pass/Fail Threshold

Initial pilot passes if:

- 3 merchants connect store data and define policies;
- 2 merchants run real cart recovery or offer-feed workflows;
- at least 1 merchant sees measurable recovered revenue or time savings;
- merchant can explain why the agent action was safe;
- audit log can reconstruct every executed action.

## 11. Business Model

Setup fee:

- storefront integration;
- policy configuration;
- agent workflow setup;
- data import;
- feed setup.

Monthly SaaS:

- wallet/auth SDK;
- merchant dashboard;
- policy engine;
- agent credentials;
- audit logs;
- offer feed;
- support.

Hosted agent fee:

- managed OpenClaw/Hermes/Ironclaw instance;
- merchant-specific memory and context;
- runtime monitoring;
- tool permissioning.

Usage fees:

- agent actions;
- recovered-cart workflows;
- offer-feed publishing;
- dynamic pricing runs;
- procurement workflows;
- payment/card-control events;
- protocol adapter calls.

Expansion modules:

- marketplace/auction module;
- procurement module;
- support/refund/dispute module;
- protocol readiness module;
- payment/virtual-card module;
- KYC and bidding identity module.

## 12. Competitive Positioning

Against buyer-side platforms:

- They own consumer surfaces and discovery.
- Seams owns merchant policy, agent authority, wallet/auth, evidence, and
  operations.

Against merchant copilots:

- Many copilots suggest actions.
- Seams controls which actions can execute and records proof.

Against Shopify apps:

- Apps solve individual workflows.
- Seams coordinates agent authority across workflows.

Against wallet providers:

- Wallet providers create accounts and sign.
- Seams applies wallet authority to merchant operations.

Against payment protocols:

- Protocols define message formats and payment flows.
- Seams creates merchant-controlled policies, approvals, offers, and evidence
  that can feed those protocols.

## 13. Open Questions

Product:

- Which wedge is strongest for first merchants: cart recovery, onsite
  assistance, offer feeds, inventory, or procurement?
- Should hosted OpenClaw/Hermes launch in MVP or after BYO-agent pilots?
- Should embedded user wallets be visible in MVP or stay behind the scenes?
- Which merchant category should be first in Japan?

Business:

- Do merchants pay more readily for recovered revenue, agent controls, or
  protocol readiness?
- Should usage pricing be tied to recovered revenue or action volume?
- Which APAC payment/issuer partner matters first?
- Is stablecoin acceptance a core merchant feature or an optional wallet module?

Compliance:

- When does KYC attachment become regulated activity?
- Which virtual-card flows require licensed partners?
- Which stablecoin receiving flows are safe as merchant self-custody?
- What evidence should be retained for refunds, disputes, and audit?

Technical:

- What is the first `CommerceIntent` union for cart recovery, discounts, offer
  feeds, and onsite assistance?
- Which action envelope fields are required before a connector or MPC signer can
  execute?
- Should Codex/MCP, hosted OpenClaw, or a merchant dashboard anchor the first
  pilot?
- Which connector should be first: Shopify, email, coupon, feed, or wallet?
- How should self-hosted sidecars handle policy epoch expiry, revocation, and
  local connector credentials?

## 14. Recommended Next Steps

1. Validate first wedge with 10 merchant interviews.
2. Build a fake-store sandbox for cart recovery and discount policy.
3. Define `CommerceIntent`, `CommerceCue`, `PolicyDecision`, `Approval`,
   `Execution`, and `AuditEvent` as first-class domain objects.
4. Add an approved signing envelope in front of the existing MPC signer.
5. Build the first policy template: abandoned-cart discount guardrails.
6. Build one MCP tool server for a merchant agent.
7. Build one offer feed endpoint from `CommerceCue`.
8. Run a pilot with a Japan-origin merchant or proxy-shopping workflow.
9. Use pilot results to decide whether the second workflow is onsite
   assistance, procurement, or marketplace pricing.

## 15. North Star

The long-term product should make this true:

```text
Any merchant can connect their store, provision wallets and agent credentials,
define policies in plain language, and safely let AI agents operate commerce
workflows while the merchant keeps customer ownership, budget control, and a
complete audit trail.
```

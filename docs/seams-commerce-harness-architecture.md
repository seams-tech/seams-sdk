# Seams Commerce Harness Architecture Plan

Status: technical architecture and implementation plan

Last updated: June 25, 2026

Document scope:

This plan is self-contained. It covers the technical architecture and
implementation plan for Seams Commerce Harness, and it includes the product and
business context needed to understand the architecture without reading any
other document.

## 1. Purpose

This document contains the technical architecture for Seams Commerce Harness.

Seams Commerce Harness is a merchant-side control layer for agentic ecommerce.
It helps merchants use AI agents to sell more, manage store operations, recover
abandoned carts, apply discounts, publish approved offers, manage inventory,
support customers, and procure inventory while keeping authority inside
merchant-defined policy.

The commercial wedge is:

```text
Abandoned-cart recovery + discount policy + onsite assistance +
merchant-approved offer feed + audit.
```

The SDK foundation is:

- MPC signing;
- embedded merchant and user wallets;
- wallet/auth primitives;
- agent credentials;
- passkey or biometric approval UX;
- account recovery;
- policy checks before privileged execution.

The target customers are ecommerce merchants, proxy-shopping services,
marketplaces, auction platforms, agencies, and Japan/APAC export sellers that
need AI-assisted commerce operations with approval, budget control, evidence,
and audit.

The core implementation goal:

```text
Let merchants safely delegate ecommerce operations to AI agents without giving
those agents raw ecommerce credentials, payment credentials, or arbitrary wallet
signing authority.
```

The core security invariant:

```text
Agent proposes.
Seams normalizes and checks policy.
Merchant or user approves sensitive actions.
Seams executes through connectors or signer.
Audit records what happened.
```

## 2. Architecture Principles

Agents are planners, not authority holders.

The AI agent should reason, draft, compare, recommend, and propose actions. It
should not receive raw Shopify credentials, email provider credentials, ad
platform tokens, payment credentials, wallet private keys, MPC signer access, or
unrestricted mutation APIs.

Seams is the policy enforcement point.

All privileged commerce actions should pass through Seams:

- create coupon;
- send campaign;
- update listing;
- change price;
- spend ad budget;
- request procurement;
- issue refund;
- authorize virtual card;
- sign stablecoin payment;
- publish official offer feed;
- change user wallet, KYC, bidding, or account state.

Typed intents are the execution boundary.

Raw prompts, webhook payloads, connector payloads, and agent tool calls should
be normalized into typed `CommerceIntent` objects before policy evaluation.
Core logic should not operate on raw external shapes.

Execution accepts approved envelopes only.

Connectors and signers should execute only after an action has been normalized,
simulated, checked, approved when needed, and wrapped in an approved action or
signing envelope.

Audit is part of the product.

Every privileged action should produce evidence: actor, intent, policy version,
decision, approval, connector request, connector response, and outcome.

## 3. High-Level Architecture

```text
Merchant Storefront / Admin / Agent Workstation
  -> Seams SDK
  -> Commerce Harness API
  -> Boundary Parser
  -> Intent Normalizer
  -> State Snapshot
  -> Simulation And Guards
  -> Policy Engine
  -> Approval Service
  -> Execution Gateway
  -> MPC Signer / Commerce Connectors
  -> Audit And Evidence Store
  -> Feeds And Protocol Adapters
```

The agent-facing surface can be MCP, REST API, plugin tools, SDK helpers, CLI,
or a local sidecar. The privileged execution path stays the same.

## 4. Commerce Agent Architecture

The harness should support three deployment routes.

### 4.1 Route 1: Agent Routes Ecommerce Calls Through Seams

This is the default BYO-agent architecture.

Flow:

```text
Codex / Claude / OpenClaw / Hermes / custom agent
  -> Seams MCP, API, plugin, or SDK tools
  -> Commerce Harness API
  -> Intent Normalizer
  -> Policy Engine
  -> Approval Service
  -> Execution Gateway
  -> Shopify / email / ads / wallet / payment connectors
  -> Audit
```

Merchant setup:

1. Merchant installs the Seams Shopify app or OAuth integration.
2. Seams stores provider credentials in a server-side vault.
3. Seams syncs store state: products, carts, inventory, orders, customers,
   margins, campaigns, and consent state.
4. Merchant issues an agent credential with allowed tools and limits.
5. Agent calls Seams tools to read context and propose actions.
6. Seams calls ecommerce APIs only after policy approval.

This route is best for technical merchants and power users who already work in
Codex, Claude Desktop, OpenClaw, Hermes, or a custom agent stack.

### 4.2 Codex Plugin Path

Codex should integrate through a Seams Codex plugin that bundles MCP
configuration and merchant-ops instructions.

Concrete shape:

```text
Seams Codex Plugin
  -> bundled Seams Commerce MCP server config
  -> merchant-ops skill/instructions
  -> OAuth or bearer-token login to Seams
  -> tool allowlist based on merchant policy
  -> Shopify, email, ads, wallet, payment, and feed connectors behind Seams
```

Plugin responsibilities:

- authenticate the Codex user to Seams;
- let the user choose a merchant org and environment;
- expose only tools enabled for that org and agent credential;
- provide merchant-ops instructions for analyzing carts, proposing offers,
  respecting approval states, and avoiding raw connector mutation;
- surface approval links or approval summaries when an action needs merchant
  confirmation;
- send every mutating request to Seams as a typed commerce action.

Initial MCP tools:

- `seams.listAbandonedCarts`;
- `seams.getCartContext`;
- `seams.proposeRecoveryOffer`;
- `seams.draftRecoveryMessage`;
- `seams.submitRecoveryAction`;
- `seams.createDiscountDraft`;
- `seams.requestDiscountApproval`;
- `seams.publishCommerceCue`;
- `seams.recommendReorder`;
- `seams.requestProcurementApproval`;
- `seams.getAuditTrail`.

Connector handling:

- Shopify credentials live in Seams vault through app install or OAuth.
- Email provider credentials live in Seams vault.
- Ad platform credentials live in Seams vault.
- Wallet/MPC signer access lives behind approved signing envelopes.
- Codex receives only Seams MCP tool access.

Example workflow:

```text
User: Review abandoned carts from the last 48 hours. Draft recovery offers for
high-margin carts and submit anything under 8 percent discount for approval.

Codex:
  1. calls seams.listAbandonedCarts
  2. calls seams.getCartContext
  3. drafts offer and message
  4. calls seams.submitRecoveryAction
  5. receives allow, deny, or approval-required decision
  6. shows the merchant the action summary and audit reference
```

### 4.3 Route 2: Seams-Hosted Agents

This route lets a merchant provision an agent through Seams.

Flow:

```text
Merchant dashboard / chat
  -> Seams-hosted OpenClaw / Hermes / Ironclaw instance
  -> Seams tool server
  -> Policy Engine
  -> Approval Service
  -> Execution Gateway
  -> Store, campaign, wallet, payment, and feed connectors
  -> Audit
```

Merchant setup:

1. Merchant connects storefront, email, inventory, and campaign tools.
2. Merchant chooses a policy template, such as cart recovery or discount
   control.
3. Seams provisions a hosted agent runtime for that merchant.
4. Merchant manages the agent through a dashboard or chat interface.
5. Hosted agent uses only Seams tools and scoped credentials.
6. Sensitive actions route to merchant approval.

Seams hosts:

- agent runtime;
- merchant-specific prompt/config;
- tool allowlist;
- memory/context store;
- scheduled jobs;
- queues;
- observability;
- eval traces;
- audit logs.

This route is best for non-technical merchants who want the product outcome
without managing MCP servers, API keys, local agents, prompts, memory, or
deployment.

### 4.4 Route 3: Self-Hosted Setups

This route lets a merchant run their own agent infrastructure, such as OpenClaw
on a Mac mini or private server.

Recommended pattern:

```text
Self-hosted OpenClaw / Hermes / custom agent
  -> Seams remote MCP server
  -> Seams cloud policy and execution gateway
  -> Store, campaign, wallet, payment, and feed connectors
  -> Audit
```

Local sidecar pattern:

```text
Self-hosted agent
  -> local Seams sidecar / proxy / CLI
  -> Seams policy API
  -> approved execution envelope
  -> local or cloud connector
  -> Audit
```

The local sidecar is useful when the agent expects local tools or shell
commands. It can expose local MCP tools, cache read-only state, forward action
requests to Seams, and execute only approved envelopes.

### 4.5 Mac Mini / Self-Hosted OpenClaw Path

Concrete path:

```text
Mac mini
  -> OpenClaw agent runtime
  -> Seams local sidecar MCP server
  -> Seams cloud policy API
  -> approved action envelope
  -> Seams cloud connector or local connector
  -> Shopify / email / ads / wallet / feed API
  -> Seams audit
```

Merchant setup:

1. Install `seams` CLI or sidecar on the Mac mini.
2. Log in to Seams and bind the device to a merchant org.
3. Configure OpenClaw to use the local Seams MCP endpoint, such as
   `http://localhost:<port>/mcp`.
4. Choose whether connectors run in Seams cloud or locally.
5. Issue a scoped agent credential for the OpenClaw instance.
6. Start the sidecar as a launch agent, daemon, or supervised process.

Sidecar responsibilities:

- expose local MCP tools to OpenClaw;
- authenticate the local device and agent credential to Seams;
- forward proposed actions to the Seams policy API;
- cache read-only store context when allowed;
- redact sensitive state before passing it to the agent;
- receive approved action envelopes;
- execute local connectors only when the envelope is valid;
- stream audit events back to Seams.

Cloud-connector mode:

```text
OpenClaw -> local Seams sidecar -> Seams cloud -> Shopify/email/ads/wallet
```

This is safest and simplest because provider credentials stay in the Seams
vault.

Local-connector mode:

```text
OpenClaw -> local Seams sidecar -> Seams policy API -> local connector -> Shopify
```

This is useful for merchants who want local control over provider credentials.
The local connector must still reject raw agent requests and execute only
approved envelopes from Seams.

Advanced self-hosted mode:

```text
Self-hosted agent
  -> local Seams sidecar
  -> local policy cache and deterministic guards
  -> Seams cloud policy attestation or sync
  -> local approved-envelope verifier
  -> local Shopify/email/ads/wallet connector
  -> local audit buffer
  -> Seams audit sync
```

Advanced self-hosted mode is for technical merchants who want maximum local
control. Connector credentials can stay on the merchant's Mac mini or private
server. Seams still defines the policy model, policy epochs, signed approval
envelope format, audit schema, and remote attestation/sync path.

Advanced self-hosted mode should support:

- local storage of Shopify, email, ad, marketplace, or payment connector
  credentials;
- local deterministic guard evaluation for margin, discount, inventory,
  consent, budget, and replay checks;
- local execution only after an approved envelope is verified;
- periodic policy sync from Seams;
- policy epoch pinning so stale policies cannot execute indefinitely;
- offline read-only operation when Seams cloud is unavailable;
- fail-closed behavior for mutating actions when policy attestation, approval,
  revocation, or envelope verification is unavailable;
- local audit buffering with later sync to Seams;
- device binding and revocation for the Mac mini or private server;
- remote kill switch for compromised agent credentials or connector scopes.

The local policy cache is an optimization, not a separate source of authority.
Seams remains the canonical policy and audit system. Local execution should
require a current policy epoch, valid device binding, valid agent credential,
approved action envelope, and replay protection.

Advanced self-hosted mode should reject:

- raw agent connector calls;
- local connector execution without an approved envelope;
- execution under a revoked policy epoch;
- execution when the device binding is revoked;
- broad "admin API" requests that do not map to a typed `CommerceIntent`;
- wallet or payment signing requests without a signer envelope.

CLI fallback:

```bash
seams commerce carts list-abandoned
seams commerce offer propose --cart cart_123 --discount 8
seams commerce action submit action_456
```

## 5. Module Boundaries

Core SDK:

- wallet creation;
- MPC signer;
- auth/session;
- passkey/biometric auth;
- account recovery;
- basic signing API;
- core policy API;
- embedded wallet UI.

Commerce Harness SDK module:

- commerce intent builders;
- agent tool definitions;
- merchant policy templates;
- connector clients;
- approval UI components;
- audit viewer components;
- offer feed helpers;
- protocol adapters.

Server services:

- policy service;
- approval service;
- connector service;
- feed service;
- audit service;
- hosted agent service;
- sandbox service.

Optional hosted runtime:

- hosted OpenClaw/Hermes/Ironclaw agents;
- tool permission sandbox;
- merchant-specific memory and context;
- execution limits;
- observability.

Potential package layout:

```text
@seams/sdk
  core wallet/auth/MPC signer primitives

@seams/commerce
  commerce intent builders
  policy templates
  agent tools
  approval components
  connector interfaces
  feed adapters

@seams/commerce-react
  merchant dashboard widgets
  onsite assistant widget
  approval UI
  audit UI

@seams/commerce-server
  server-side policy enforcement
  connector callbacks
  feed publishing
  webhook handlers
```

## 6. Domain Model

Core entities:

- `MerchantOrg`;
- `MerchantWallet`;
- `StaffPrincipal`;
- `AgentPrincipal`;
- `UserWallet`;
- `CommerceIntent`;
- `Policy`;
- `PolicyDecision`;
- `Approval`;
- `Execution`;
- `CommerceCue`;
- `MarketProfile`;
- `LocalizedCatalogProjection`;
- `MarketPriceBookEntry`;
- `PaymentRoute`;
- `AP2OpenMandate`;
- `AP2ClosedMandate`;
- `PaymentCredentialAuthorization`;
- `LandedCostQuote`;
- `ShippingPromise`;
- `RestrictedGoodsDecision`;
- `CommerceAttribution`;
- `AuditEvent`.

Initial intent union:

- `visitor_assistance_request`;
- `cart_recovery_offer`;
- `discount_create`;
- `coupon_apply`;
- `campaign_draft`;
- `campaign_send`;
- `offer_publish`;
- `listing_price_update`;
- `inventory_reorder_recommendation`;
- `procurement_request`;
- `supplier_message_draft`;
- `support_response_draft`;
- `refund_prepare`;
- `wallet_sign`;
- `virtual_card_authorize`;
- `ap2_open_mandate_issue`;
- `ap2_closed_mandate_sign`;
- `payment_credential_authorize`;
- `stablecoin_payment_receive`;
- `user_wallet_create`;
- `agent_credential_issue`;
- `policy_deploy`;
- `cue_revoke`;
- `localized_catalog_publish`;
- `market_price_quote`;
- `landed_cost_quote`;
- `shipping_promise_quote`;
- `restricted_goods_check`;
- `cross_border_checkout_prepare`;
- `commerce_attribution_record`.

Future intent union:

- `auction_bid`;
- `p2p_seller_message`;
- `escrow_release`;
- `dispute_submit`;
- `return_approve`;
- `loyalty_reward_issue`;
- `marketplace_deposit_lock`;
- `KYC_request`;
- `virtual_card_issue`;
- `UCP_checkout_create`;
- `ACP_checkout_session_create`.

Policy decisions should be explicit:

```text
allow
deny
requires_human_approval
requires_user_approval
requires_merchant_owner_approval
requires_additional_evidence
requires_connector_reauth
requires_policy_update
```

## 7. Request Lifecycle

Every privileged commerce action should follow this lifecycle:

```text
raw request
  -> boundary parser
  -> typed CommerceIntent
  -> state snapshot
  -> simulation and deterministic guards
  -> policy evaluation
  -> approval if required
  -> approved action envelope
  -> MPC signer or connector
  -> audit event
```

Example: abandoned-cart discount offer.

```text
1. Cart abandoned event enters harness.
2. Intent normalizer creates cart_recovery_offer intent.
3. Agent proposes 10 percent discount and email copy.
4. Policy engine checks margin, consent, inventory, frequency, and discount cap.
5. Decision returns allow or requires_human_approval.
6. Approval UI shows merchant-visible summary if needed.
7. Execution gateway creates coupon and sends email through connectors.
8. Audit records intent, policy decision, approval, coupon, message, and result.
9. Feed service publishes cue if merchant policy allows public offer discovery.
```

Example: procurement request.

```text
1. Inventory connector reports low stock.
2. Agent proposes supplier reorder.
3. Intent normalizer creates procurement_request intent.
4. Policy engine checks supplier allowlist, budget, lead time, and approver.
5. Decision requires merchant owner approval.
6. Owner approves with passkey.
7. MPC signer signs payment or connector sends purchase order if configured.
8. Audit records approval, supplier message, payment reference, and shipment
   evidence requirements.
```

## 8. Integration With Existing Seams SDK

Assumed current SDK foundation:

- MPC signer;
- embedded wallets;
- authentication/session primitives;
- policy engine;
- signing requests;
- account recovery path;
- merchant or app integration surface.

The Commerce Harness should be an additive module around this foundation. The
MPC signer remains a low-level execution primitive. The harness must ensure that
merchant policies are checked before any privileged signing or connector action.

All privileged commerce actions should follow this integration pattern:

```text
raw request
  -> boundary parser
  -> typed CommerceIntent
  -> policy evaluation
  -> approval if required
  -> execution request
  -> MPC signer or connector
  -> audit event
```

The MPC signer should accept only an approved signing envelope:

```text
ApprovedSigningEnvelope
  - org ID
  - wallet ID
  - actor principal
  - intent digest
  - policy version
  - decision ID
  - approval ID when required
  - signing payload
  - expiry
```

This prevents the signer from becoming a generic remote signing service.

Signer should reject:

- raw signing payloads from agents;
- expired approvals;
- revoked policy versions;
- missing decision IDs;
- decision/action mismatches;
- broad untyped requests;
- replayed envelopes;
- unsupported action kinds.

### 8.1 AP2 Internal Credential Provider Pattern

Seams can play multiple AP2 roles when the payment credential is controlled by
Seams or by a Seams-connected payment partner. The external credential-provider
round trip can collapse into an internal JWT or credential release, while the MPC
signing round trip remains explicit. Purchase authority requires both the
agent's delegated threshold signing share and the Seams backend policy share.

Role mapping:

```text
AP2 Shopping Agent
  -> merchant-selected agent runtime with delegated threshold signing share

AP2 Trusted Surface
  -> Seams approval UI backed by passkey, biometric, wallet, or MPC auth; grants
     open mandates and delegated agent signing authority

AP2 Credential Provider
  -> Seams payment credential service that verifies completed threshold-signed
     mandates and issues scoped JWTs, virtual card authorizations, wallet
     authorizations, stablecoin approvals, or payment-token vault releases

AP2 Merchant
  -> Shopify, SaaS vendor, merchant storefront, marketplace, or AP2-native seller

AP2 Merchant Payment Processor
  -> card processor, wallet rail, bank/PISP rail, stablecoin rail, or merchant PSP
```

Autonomous payment lifecycle:

```text
1. Agent proposes payment task.
2. Seams creates open Checkout and Payment Mandate content from typed policy.
3. Trusted Surface renders the constraints and gets user or merchant approval.
4. Trusted Surface signs open mandates with P-256/ES256 authority and binds the
   delegated agent public key.
5. Agent assembles the exact checkout and initiates closed mandate threshold
   signing with its delegated share.
6. Seams MPC policy co-signer checks open mandates, checkout hash, agent key
   binding, merchant, amount, recurrence, budget, expiry, revocation, and replay
   state.
7. Seams MPC policy co-signer contributes the backend share. A valid P-256
   signature exists only when both the agent share and Seams policy share
   participate.
8. Seams Credential Provider verifies open mandates, closed mandates, and the
   completed threshold signature.
9. Seams Credential Provider creates a scoped payment JWT, payment credential, or
   spend authorization.
10. Checkout executor completes payment through normal rails or an AP2-native
    merchant flow.
11. Audit stores open mandates, closed mandates, credential authorization,
    payment receipt, checkout receipt, and execution evidence.
```

The Seams MPC policy co-signer should accept only typed AP2 mandate signing
envelopes from an agent-controlled threshold signing session:

```text
AP2MandateSigningEnvelope
  - org ID
  - user or merchant principal
  - agent principal
  - agent P-256 public key
  - threshold signing session ID
  - agent share participation proof
  - Seams backend share ID
  - open checkout mandate reference
  - open payment mandate reference
  - checkout JWT hash
  - merchant/payee identity
  - payment amount and currency
  - recurrence and budget reservation
  - payment instrument reference
  - policy version
  - approval ID
  - nonce
  - expiry
```

The Seams Credential Provider should release only scoped JWTs or credentials:

```text
PaymentCredentialAuthorization
  - authorization ID
  - mandate signing decision ID
  - completed mandate signature reference
  - credential reference
  - allowed merchant/payee
  - max amount and currency
  - checkout hash when present
  - recurrence rule when present
  - expiry
  - revocation state
```

Security rules:

- the LLM cannot access payment credentials, card numbers, wallet keys, or the
  Seams backend MPC share;
- the agent can initiate threshold signing with its delegated share, and Seams
  policy co-signing is required to complete the P-256 signature;
- Seams cannot unilaterally create a purchase-authorizing mandate or credential
  without a valid user-approved open mandate and agent threshold participation;
- delegated P-256/MPC authority is limited to typed AP2 mandate payloads that
  pass deterministic policy checks;
- credential release requires independent verification of the completed mandate
  by the Seams Credential Provider, even when it runs inside the same Seams
  backend;
- budget reservation happens before credential release;
- closed mandates must be linked to the open mandates through hashes and agent
  key binding;
- overlapping mandate use requires a rejection receipt or released reservation;
- revocation of user session, agent credential, open mandate, policy version, or
  payment instrument blocks signing and credential release;
- normal card or wallet rails can execute the final checkout while AP2 provides
  signed intent, constraints, evidence, and dispute records.

## 9. Client, Server, And Agent Responsibilities

Browser SDK:

- initialize merchant context;
- provision user wallet;
- authenticate user;
- render onsite assistant;
- capture visitor cue;
- create typed client-side intent draft;
- request merchant or user approval;
- display wallet approval;
- call server harness API;
- receive audit references.

Admin SDK:

- authenticate merchant owner/staff;
- manage agent credentials;
- configure policies;
- approve sensitive actions;
- inspect audit;
- manage feeds;
- connect integrations.

Agent SDK:

- expose allowed tools;
- attach agent identity;
- create action requests;
- receive policy decisions;
- handle approval-required responses;
- record outcomes.

Server-side enforcement:

- validate merchant session;
- validate agent credential;
- normalize raw requests;
- evaluate policy;
- create approval request;
- call execution connectors;
- call MPC signer through approved envelope;
- write audit events;
- publish feeds.

Client-side checks are UX hints. Server-side policy gates are authoritative.

## 10. Boundary Parsers

Every external system should have a parser:

- Shopify webhook parser;
- WooCommerce parser;
- marketplace listing parser;
- Google Merchant Center parser;
- OpenAI ACP feed parser;
- UCP request parser;
- AP2 mandate parser;
- AP2 credential authorization parser;
- email provider parser;
- ad platform parser;
- virtual card authorization parser;
- agent tool request parser.

Boundary parsers convert raw external payloads into precise internal types.
Core logic should work only with typed domain objects.

## 11. Connectors

Storefront connectors:

- Shopify;
- custom storefront API;
- WooCommerce;
- BigCommerce;
- marketplace APIs;
- auction site APIs.

Communication connectors:

- email provider;
- SMS provider;
- support inbox;
- LINE;
- WhatsApp;
- push notifications;
- CRM tools.

Marketing connectors:

- campaign draft export;
- Google Analytics or event ingestion;
- UTM attribution;
- Google Ads;
- Meta Ads;
- Microsoft Ads;
- affiliate network.

Payment and wallet connectors:

- Seams wallet;
- stablecoin receive address;
- mock virtual card issuer;
- sandbox card issuer adapter;
- Seams internal AP2 credential provider;
- Seams AP2 mandate signer;
- Airwallex;
- Nium;
- Lithic for US sandbox/reference;
- APAC white-label issuer partners;
- payment provider token adapters;
- AP2 mandate adapter.

Protocol and feed connectors:

- ACP product feed export;
- merchant-owned public JSON feed;
- MCP server tools;
- UCP catalog/search/checkout endpoint;
- Google Merchant Center integration;
- AP2 mandate metadata;
- affiliate feeds;
- A2A agent endpoints.

Cross-border operations connectors:

- FX rates;
- duty and tax estimates;
- shipping quote APIs;
- carrier tracking;
- restricted-goods screening;
- translation and localization;
- marketplace attribution;
- analytics attribution.

## 12. Security Model

Authority chain:

```text
merchant org
  -> merchant wallet / owner authority
  -> policy version
  -> agent credential or staff role
  -> typed commerce intent
  -> policy decision
  -> approval if required
  -> execution
  -> audit
```

Action digest:

```text
digest = hash(canonical_intent + policy_version + actor + org + expiry)
```

The digest should appear in:

- approval prompt;
- policy decision;
- signer envelope;
- connector execution metadata;
- audit log;
- feed attestation where useful.

Revocation targets:

- agent credential;
- staff session;
- policy version;
- pending approval;
- commerce cue;
- wallet session;
- connector token;
- public feed item;
- AP2 mandate metadata where applicable.
- AP2 open mandate;
- AP2 closed mandate;
- payment credential authorization.

Budget dimensions:

- daily ad spend;
- weekly campaign spend;
- discount value;
- procurement spend;
- refund amount;
- virtual-card authorization amount;
- AP2 mandate budget reservation;
- stablecoin payment limit;
- listing price delta;
- customer-message frequency.

Budget reservations should be explicit:

```text
available -> reserved -> executed -> settled | released | expired
```

Audit evidence should include:

- raw event reference;
- normalized intent;
- visible summary shown to human;
- policy decision;
- approval proof;
- execution request and response;
- connector outcome;
- feed publication;
- external protocol reference;
- final business result.

## 13. Protocol Strategy

The canonical internal model should be Seams-native:

```text
CommerceIntent
Policy
PolicyDecision
Approval
Execution
CommerceCue
AuditEvent
```

ACP, UCP, AP2, MCP, A2A, affiliate feeds, and marketplace APIs should adapt to
and from these objects.

ACP adapter:

- generate clean feeds from merchant catalog and `CommerceCue` objects;
- apply merchant eligibility rules;
- keep merchant approval and audit inside Seams;
- map ACP checkout/cart events into `CommerceIntent` objects if integrated.

UCP adapter:

- expose UCP endpoints from Seams-controlled store policy;
- map UCP requests into typed intents;
- keep checkout and customer relationship under merchant policy.

AP2 adapter:

- issue or verify AP2-compatible mandate metadata where useful;
- bind mandate to merchant policy, user approval, and wallet/auth proof;
- store mandate evidence;
- treat AP2 as a payment authorization adapter.

MCP adapter:

- expose merchant tools for agent workstations;
- provide tools for search offers, create cart, request discount, propose
  campaign, request approval, publish cue, and record outcome.

## 14. UX And Developer Interfaces

Merchant admin screens:

- overview dashboard;
- recovered revenue;
- active agent actions;
- approvals inbox;
- policies;
- agent credentials;
- wallet/auth settings;
- embedded user wallets;
- offers and feeds;
- campaigns;
- inventory and procurement;
- audit.

Approval prompt should show:

- action summary;
- actor;
- affected customer or segment;
- budget/spend;
- discount/margin impact;
- inventory impact;
- expiry;
- policy rule;
- evidence to be recorded;
- allow/deny/edit options.

Developer should be able to:

- install SDK;
- connect store;
- create merchant org;
- create agent credential;
- define policy template;
- expose MCP tools;
- publish offer feed;
- run sandbox actions;
- view audit log.

Conceptual API:

```ts
const commerce = seams.commerce({
  orgId,
  merchantWalletId,
});

const intent = commerce.intents.cartRecoveryOffer({
  cartId,
  discountPercent: 8,
  channel: "email",
});

const decision = await commerce.policy.evaluate(intent);

if (decision.kind === "allow") {
  await commerce.execute(decision);
}
```

Actual implementation should use precise TypeScript domain states,
discriminated unions, narrow inputs, required identity fields, boundary parsers,
and exhaustive decision handling.

## 15. Implementation Roadmap

### Phase 0: Specification And Sandbox

- define domain model;
- define policy decision union;
- define `CommerceIntent` union;
- define `CommerceCue` schema;
- define approved signer envelope;
- build fake store connector;
- build fake email/coupon connector;
- build fake feed publisher;
- build fake MPC signer adapter for tests;
- build MCP server prototype.

### Phase 1: Wallet/Auth And Policy Integration

- merchant org wallet;
- staff roles;
- agent credentials;
- embedded user wallet creation;
- signer envelope gate;
- policy evaluation before execution;
- audit log.

### Phase 2: First Revenue Workflow

First wedge:

```text
abandoned-cart recovery + discount policy + onsite assistance + offer feed
```

Deliverables:

- Shopify or custom storefront connector;
- email connector;
- coupon connector;
- offer feed endpoint;
- dashboard metrics.

### Phase 3: Cross-Border Market Layer

- market profiles;
- localized catalog projection;
- market price book;
- landed cost quote;
- shipping promise quote;
- restricted goods check;
- payment route selection;
- attribution record.

### Phase 4: Agent Workstation Integration

- MCP server for Codex/Claude/OpenClaw/Hermes;
- hosted OpenClaw/Hermes option;
- agent tool permissioning;
- action simulation;
- approval flows from agent workspace.

### Phase 5: Merchant Operations Expansion

- dynamic pricing recommendations;
- inventory alerts;
- supplier outreach drafts;
- procurement approvals;
- support and refund drafts.

### Phase 6: Protocol Adapters

- ACP product feed export;
- UCP readiness adapter;
- AP2 mandate metadata adapter;
- public merchant offer feed;
- affiliate feed export.

### Phase 7: Payment And Marketplace Expansion

- stablecoin receiving flows;
- virtual-card provider adapters;
- marketplace bidding policies;
- KYC attachment;
- auction deposits;
- payment evidence.

## 16. MVP Technical Scope

MVP scope:

- merchant org wallet;
- staff login;
- one agent credential;
- one policy template for cart recovery;
- one discount policy;
- one onsite assistant prompt;
- one email connector;
- one coupon/store connector;
- one offer feed;
- one cross-border market profile;
- one localized catalog projection;
- one market price book;
- one shipping/landed-cost quote path;
- one attribution event model;
- approval UI;
- audit log;
- MCP tool prototype.

MVP exclusions:

- live card issuing;
- broad dynamic pricing automation;
- autonomous procurement payment;
- external AP2 network interoperability;
- full UCP checkout implementation;
- complex KYC workflows;
- multi-marketplace bid execution.

## 17. Testing And Evals

The harness should have deterministic tests for:

- policy decisions;
- margin math;
- budget accounting;
- connector envelope validation;
- signer envelope validation;
- revocation;
- replay protection;
- raw connector mutation rejection;
- consent checks;
- inventory availability;
- audit completeness.

Agent evals should test:

- whether the agent chooses the right tool;
- whether it asks for approval when needed;
- whether it avoids unsupported claims;
- whether it respects discount and margin rules;
- whether it avoids raw credentials;
- whether it handles denial and approval-required states.

Private eval scenarios should become strategic IP. They should cover common and
adversarial merchant workflows: abandoned carts, refunds, low inventory, high
discount pressure, stale carts, missing consent, product-claim ambiguity, and
connector failures.

## 18. Open Technical Questions

- Which storefront connector should anchor the first pilot: Shopify, custom
  storefront, or static feed?
- Should MCP be shipped before hosted agent runtime?
- How much policy logic lives client-side for UX previews?
- Which signing payloads can bind intent digest directly?
- What is the first canonical `CommerceCue` schema?
- Which local sidecar guarantees are required before self-hosted execution?
- How should policy epoch expiry work for advanced self-hosted mode?
- Which connector credentials can safely stay local in early pilots?

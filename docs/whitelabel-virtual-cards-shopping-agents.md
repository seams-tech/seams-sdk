# Chat 8 Context - Seams Deck, Product Vision, Agentic Commerce, And Virtual Cards

Last updated: 2026-06-23

Working directory:

`/Users/pta/Library/CloudStorage/Dropbox/Nomad Visas/seams-startup-visa`

## Purpose Of This Chat

This chat developed the Seams startup pitch, product vision, and virtual-card
partner strategy.

The work started with research into AI-enabled deck makers, then moved into
deck structure for a Japan Startup Visa / investor-style pitch. The product
scope expanded from embedded wallet infrastructure into a broader commerce
authority layer for Japan-first cross-border ecommerce, agentic shopping, deal
intelligence, shopping-agent policy, VoiceID approval, and virtual card
execution rails.

## User Writing And Process Preferences

Important preferences stated during this chat:

- Discuss product-vision changes before writing to `product-vision.md` unless
  the user explicitly asks for an update.
- Avoid "not X, but Y" phrasing.
- Keep the startup visa pitch aligned with the roadmap and business plan that
  have already been sent out.
- Keep the Japan Startup Visa narrative anchored on Japan export commerce,
  merchant tools, checkout, shipment evidence, and settlement.
- When the user says `MOCT`, it means "mark off completed tasks".
- When the user says `ONSAP`, it means "outline next steps and proceed".

## Key Files Created Or Updated

- `deck.md`
  - Created as the Seams startup pitch deck iteration plan.
  - Later expanded with virtual card issuer partner strategy.

- `product-vision.md`
  - Updated after discussion to reframe the product as a commerce authority
    layer for agentic export commerce.

- `whitelabel-virtual-cards-adaptors.md`
  - Created as the dedicated architecture and partner-evaluation plan for
    white-label virtual card issuer adaptors.

## Deck Maker Research

The chat began by researching AI-enabled deck makers and discussion around
those products.

Products considered:

- Chronicle
- Claude Design / Anthropic Labs
- Gamma
- Alai
- Plus AI
- Pitch
- Beautiful.ai
- Presentations.AI
- Figma Slides
- Canva
- Tome

Working ranking from the discussion:

1. Gamma
2. Alai
3. Chronicle
4. Claude Design
5. Plus AI
6. Pitch
7. Beautiful.ai
8. Presentations.AI
9. Figma Slides
10. Canva

Tome was deprioritized.

Claude Design conclusion:

- Claude Design is an Anthropic Labs visual design workspace.
- It is related to Claude, though it is more than a normal chat response with a
  "design skill".
- It can import/export PPTX and send to Canva.
- Native Google Slides control was not identified as a core capability.

Codex deck-making conclusion:

- Codex can help create, edit, render, and verify PPTX files with the
  Presentations skill.
- Codex can work with Google Drive / Google Slides when the relevant plugin is
  available.
- Codex does not provide the same Claude Design-style visual canvas, though it
  can generate and verify actual deck files.

## Startup Pitch Deck Direction

The user wanted a 7-slide maximum startup pitch deck for Seams Technologies.

Main pitch constraints:

- The deck should structure the first 10 minutes of a pitch.
- It should explain the business without sounding like Form 1-3 is being read
  aloud.
- It should answer:
  1. Why Tokyo?
  2. What is the business plan across product, GTM, and pricing?

Initial slide spine:

1. Company Overview
2. Problem
3. Product
4. Why Tokyo
5. Business Model
6. 12-Month Roadmap

The plan evolved into a 7-slide structure with a clearer GTM slide:

1. Company Overview
2. Problem
3. Product
4. Why Tokyo
5. Go-To-Market
6. Business Model
7. 12-Month Roadmap

Core deck framing:

```text
Seams Technologies builds policy-controlled commerce infrastructure for
cross-border ecommerce, starting from Japan-based export merchants.
```

Integrated product hypothesis added to `deck.md`:

```text
Seams helps customers and agents discover, evaluate, negotiate, approve, and
execute cross-border purchases under merchant and customer policy. For Japanese
export merchants, that connects deal discovery, buyer or agent purchase intent,
wallet-enabled checkout, shipment evidence, refunds, and settlement.
```

## Product Vision Review And Expansion

The user asked to review `product-vision.md` and expand the product scope so
Seams was not limited to wallet-only fintech paths.

The agreed goal was to find the overlap between:

- delegated wallets
- shopping harnesses
- policy engine for agentic commerce
- the current embedded wallet SDK for commerce
- VoiceID as another way to express shopping intent

The product was reframed around a commerce-intent boundary:

```text
Customer or agent intent
  -> deal, listing, merchant, shipping, and trust signals
  -> typed commerce intent
  -> proof of authority
  -> policy check
  -> wallet, merchant API, shipment, refund, or settlement action
  -> audit trail
```

Short version:

```text
Capture intent.
Prove authority.
Execute commerce.
Audit the result.
```

Product category:

```text
Policy-controlled commerce infrastructure
```

Buyer-facing line:

```text
Let customers and agents shop safely while merchants can prove what was
approved, what happened, and why money, inventory, refunds, or settlement moved.
```

Developer-facing line:

```text
Embed accounts, wallets, voice or agent intent, deal discovery, policy checks,
shipment evidence, settlement, and audit into cross-border commerce flows.
```

## Agentic Commerce And Shopping Scope

The user asked about adding:

- Dealproof-style agentic bidding and dealmaking.
- Cue-style shopping preference learning.
- Discount/deal APIs as inputs to shopping agents.
- Possible AT Proto feeds for curated deals.

Decisions:

- Drop Dealproof as a named product dependency for now.
- Keep the scope simpler:
  - shopping agents help source deals
  - shopping agents help bid on P2P marketplaces
  - shopping agents message sellers for better deals
- Add Shopping Cue Engine as a product surface.
- Add Seams Shopping Feed as a discovery input.
- Add Verifiable Bidding / Haggling as future expansion.
- Keep ATProto-style deal feeds out of core infrastructure.
- Keep deal sourcing internal so Seams can monetize canonical, typed,
  policy-aware deal data.

Core framing added:

```text
Seams helps customers and agents discover, evaluate, negotiate, approve, and
execute cross-border purchases under merchant/customer policy.
```

Use cases added:

- P2P marketplaces
- auctions
- buyer/seller negotiation
- "agent found a bargain, prove the terms before payment"

Shopping Cue Engine:

```text
Learn what is routine, what is sensitive, what needs research, and what
requires explicit approval.
```

Deal Intelligence Feed framing:

```text
Seams normalizes deal, coupon, listing, merchant, shipping, and trust signals
so shopping agents can recommend better purchases under policy.
```

Distribution note:

```text
Publish curated deal streams, shopping requests, product drops, or merchant
offers as open feeds, while Seams keeps the canonical deal data internally
typed and policy-aware.
```

## Wallet Delegation And Agent Spending

The user asked how to present the embedded wallet as a biometric platform for
delegating constrained shopping budgets and policy to shopping agents.

Working answer:

- The embedded wallet becomes a wallet and policy orchestration layer.
- Biometric approval binds user intent to a signed shopping mandate.
- Shopping agents receive scoped authority:
  - budget
  - merchant/category
  - geography
  - expiry
  - shipping constraints
  - approval thresholds
  - refund/support rules
  - revocation before execution

The stronger product line:

```text
Seams lets customers and shopping agents execute purchases through the
customer's chosen wallet, card issuer, or payment provider, while Seams enforces
intent, budget, merchant, shipping, and approval policy.
```

## PCI DSS And Card Issuing Research

PCI DSS conclusions:

- PCI DSS is an industry standard, not a government license.
- PCI SSC maintains the PCI standards.
- Card networks and acquiring/sponsor banks enforce compliance contractually.
- QSAs and ASVs validate compliance, depending on merchant/service-provider
  level and scope.
- Self-assessment is possible for some lower-risk scopes; high-volume or
  service-provider setups typically require formal assessment.

Marqeta:

- Marqeta publicly describes itself as PCI DSS Level 1.
- The user rejected Marqeta and Stripe as primary partners because Seams may
  compete with them.

Virtual card issuing conclusion:

- MPC wallet technology can control user authorization and mandate signing, but
  it does not directly create Visa/Mastercard/JCB card credentials.
- To issue virtual cards, Seams needs a card program path:
  - sponsor bank / BIN sponsor
  - licensed issuer / card issuer partner
  - issuer processor
  - program manager
  - card network integration

Sponsor-bank / principal membership conclusion:

- Sponsor-bank route is the practical first route.
- Direct network principal membership is heavier and requires licensing,
  network membership, BIN/IIN setup, processor certification, KYC/AML, fraud,
  disputes, settlement, reserves, PCI DSS, and operational readiness.

## APAC And Japan Virtual Card Partners

The user wanted HK/SG/Japan issued virtual-card providers.

APAC / Japan shortlist:

1. Reap Card Issuing
   - HK-first lead.
   - Public product page describes branded physical/virtual Visa cards, API
     integration, real-time authorization, and fiat/stablecoin funding options.

2. Infcurion Xard
   - Best Japan-local route.
   - API-based original JCB/Visa card programs.
   - Strongest fit for a Japan-based KK story.

3. Nium Card Issuing
   - Singapore, Hong Kong, and APAC/global fit.
   - Cross-border card issuing, wallets, FX, and card lifecycle APIs.

4. MatchMove
   - Singapore/APAC white-label embedded finance.

5. Thredd
   - Issuer processor route for more configurable card-program design.

6. Airwallex Issuing
   - Technically strong API issuing and multi-currency card benchmark.
   - Potential overlap with Seams' own wallet/payment ambitions.

7. Aspire Card Issuance API
   - Lightweight business virtual-card API candidate.

Recommended APAC outreach order:

1. Reap
2. Infcurion Xard
3. Nium
4. MatchMove
5. Thredd

## US Virtual Card Providers

The user asked for popular US-based virtual-card issuers and API providers.

US partner shortlist:

1. Lithic
2. Extend
3. Increase
4. Highnote
5. Unit
6. Galileo / SoFi Tech Solutions
7. i2c
8. Corpay Card Issuing APIs
9. Treasury Prime
10. Moov Card Issuing

Benchmark products:

- Ramp
- Brex
- BILL Spend & Expense / Divvy
- Mercury
- Marqeta
- Stripe Issuing

Recommended US ranking:

1. Lithic
2. Extend
3. Increase
4. Highnote
5. Unit
6. Galileo / i2c
7. Corpay
8. Treasury Prime
9. Moov

## Multi-Issuer Strategy

The user suggested that Seams could integrate with multiple virtual card
issuers and allow each business to choose its preferred provider.

This became a central strategy:

```text
Seams is issuer-neutral. Businesses can bring or select the virtual card
provider they trust, while Seams normalizes card creation, agent spending
limits, mandate enforcement, authorization policy, receipt and shipment
evidence, refund state, and audit records across providers.
```

This gives Seams a stronger position:

- Seams owns the wallet, identity, biometric approval, shopping-agent mandates,
  budgets, policy, evidence, and audit trail.
- Issuers own regulated card issuance, network access, PAN/token lifecycle,
  KYC/KYB where required, fraud, disputes, chargebacks, and settlement.
- Businesses can choose issuer paths by jurisdiction, pricing, card controls,
  currency support, settlement model, compliance requirements, and existing
  banking relationships.

## White-Label Virtual Card Adaptor Architecture

The user asked to research card issuer APIs and assess what a general adaptor
wrapper should look like.

Main conclusion:

- The abstraction should be capability-driven because providers vary across
  funding, card controls, authorization, card-data display, webhooks, and
  compliance roles.

Authorization modes:

```ts
type AuthorizationMode =
  | { kind: "provider_rules" }
  | { kind: "realtime_delegate"; timeoutMs: number }
  | { kind: "observe_only" };
```

Funding modes:

```ts
type FundingMode =
  | { kind: "issuer_held_balance" }
  | { kind: "seams_wallet_delegated_auth" }
  | { kind: "prefunded_card" }
  | { kind: "credit_or_charge_program" };
```

Control model:

```ts
type CardControl =
  | { kind: "single_use" }
  | {
      kind: "amount_limit";
      amountMinor: number;
      currency: string;
      interval: "per_transaction" | "lifetime" | "daily" | "monthly";
    }
  | { kind: "merchant_lock"; merchantRef: string }
  | { kind: "mcc_allowlist"; mccs: string[] }
  | { kind: "geo_allowlist"; countryCodes: string[] }
  | { kind: "expiry"; expiresAt: string };
```

Adaptor branches:

- `RealtimeAuthorizingAdaptor`
- `ProviderRulesOnlyAdaptor`
- `ObserveOnlyAdaptor`

Core design rule:

```text
The Seams mandate remains the source of truth. Provider controls are execution
constraints compiled from that mandate.
```

## Sandbox And Prototype Strategy

The user asked whether the APIs could be tested through developer sandboxes.

Conclusion:

- Yes, several providers have sandbox or test environments.
- Sandbox cards usually cannot be used at real merchants.
- The useful prototype is an issuer adaptor conformance suite that simulates
  card creation, authorization, clearing, refund, reversal, timeout, decline,
  and webhooks.

Recommended conformance suite:

```text
create cardholder
issue virtual card
attach mandate metadata
simulate authorization
approve under policy
decline over budget
decline revoked mandate
simulate timeout
simulate clearing
simulate refund
freeze card
close card
normalize webhook/event into Seams audit log
```

## Selected First Three Prototype Providers

The user proposed:

- Lithic
- Airwallex
- Nium

The plan accepted these as the first three prototype targets:

1. Lithic
   - Fastest sandbox-backed adaptor validation.
   - Public sandbox docs, virtual cards, spend limits, simulated
     authorizations, webhook simulation, and Auth Stream Access.

2. Airwallex
   - APAC/global issuing and remote authorization path.
   - Card creation, authorization controls, transaction simulation in sandbox,
     and remote authorization.
   - Issuing and Remote Authorization must be enabled for the account.

3. Nium
   - Cross-border wallet, card, and Dynamic Authorization path.
   - Wallet funding, virtual card lifecycle, hosted card widget, sandbox
     testing, and Dynamic Authorization models.

Direct references added to the plan:

- Lithic API basics and sandbox testing.
- Lithic simulated transactions.
- Lithic Auth Stream Access.
- Airwallex sandbox overview.
- Airwallex simulated transactions on issued cards.
- Airwallex remote authorization and authorization controls.
- Nium getting started and sandbox funding.
- Nium Dynamic Authorization prerequisites.
- Nium hosted authorization model.
- Nium card controls and card widget.

## Authorization Mode Recommendation

The user asked which authorization mode best fits wallet delegation to agent
spending.

Recommendation:

```ts
type AgentSpendAuthorizationMode = {
  kind: "realtime_delegate";
  timeoutMs: number;
  timeoutPolicy: "decline";
  providerHardControlsRequired: true;
};
```

Reasoning:

- Shopping agents need enforceable, revocable, context-aware spend authority.
- Provider-controlled cards are useful as hard outer limits.
- Seams still needs to evaluate mandate state, wallet state, agent identity,
  quote terms, merchant data, revocation state, and approval thresholds at
  authorization time.
- Observe-only cards are useful for audit and reconciliation, with weaker
  enforcement.

Recommended model:

```text
Merchant authorization request
  -> issuer calls Seams
  -> Seams loads mandate, wallet state, card state, quote, and revocation state
  -> Seams approves, declines, or escalates
  -> issuer completes network authorization
  -> Seams stores decision and event evidence
```

Provider-controlled hard outer limits:

- single-use or limited-use card
- max amount
- currency
- expiry window
- merchant lock where available
- MCC/category allowlist where available
- online-only or channel restrictions where available
- velocity controls where available

Agent-initiated purchases should fail closed if Seams cannot evaluate a
required mandate at authorization time.

## Current File Status At End Of Chat

Observed status:

```text
?? deck.md
?? product-vision.md
?? whitelabel-virtual-cards-adaptors.md
```

These files are untracked in git. They were intentionally created or edited as
planning documents during this chat.

## Next Useful Steps

Potential next steps from this state:

1. Draft outreach emails for Lithic, Airwallex, and Nium requesting sandbox or
   partner-test access.
2. Create an `issuer-adaptor-lab` prototype plan or small test harness.
3. Add a concise virtual-card execution rail slide to the pitch deck notes.
4. Decide whether the Japan Startup Visa deck should mention card issuers by
   name or keep them as partner examples.
5. Continue refining the Seams product story around:
   - Japan export commerce
   - shopping-agent mandates
   - deal intelligence
   - issuer-neutral virtual card execution
   - shipment evidence and settlement audit

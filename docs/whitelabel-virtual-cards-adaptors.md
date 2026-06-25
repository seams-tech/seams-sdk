# White-Label Virtual Card Adaptors Plan

Date created: June 22, 2026

Status: draft architecture and partner evaluation plan, expanded with provider
research and implementation gaps.

Related docs:

- [Startup pitch deck iteration plan](deck.md)
- [Product vision](product-vision.md)

## Purpose

This plan describes how Seams can integrate with multiple white-label virtual
card issuers through one common adaptor layer.

The product goal is issuer choice:

```text
Businesses choose the virtual card issuer they prefer. Seams provides the
wallet, biometric approval, shopping-agent mandate, budget policy, card-control
normalization, transaction evidence, and audit layer across those issuers.
```

This keeps Seams focused on the software layer that matters most for agentic
commerce:

- delegated shopping authority
- biometric or passkey approval
- merchant and marketplace policy
- budget controls
- virtual card execution
- quote, receipt, shipment, refund, and settlement evidence
- audit records across issuers

## Provider Landscape

### Strong Public API Candidates

| Provider | Region fit | Public API surface | Notes for Seams |
| --- | --- | --- | --- |
| [Airwallex Issuing](https://www.airwallex.com/docs/issuing/get-started/create-cards) | HK, SG, global | Cardholder and card creation, card controls, remote authorization, card details. | Strong APAC-style API benchmark. Good for testing multi-currency and remote authorization assumptions. |
| [Nium Cards](https://docs.nium.com/docs/cards) | SG, HK, APAC, global | Cards, card lifecycle, travel cards, dynamic authorization, hosted sensitive-data widget. | Strong cross-border and APAC candidate. Dynamic authorization maps well to Seams policy. |
| [Lithic](https://docs.lithic.com/reference/postcards) | US | Card creation, virtual cards, spend limits, auth stream access, card lifecycle. | Strong US programmable issuing candidate and agentic-payment benchmark. |
| [Highnote](https://docs.highnote.com/docs/issuing/about-issuing) | US | Full issuing platform, card products, spend rules, ledger, compliance operations. | Good full-program route if Seams wants a managed issuing stack. |
| [Increase Cards](https://increase.com/products/cards.html) | US | Visa card issuing, limits, real-time approvals, banking API. | Strong real-time authorization and developer-control fit. |
| [Unit Card Issuing](https://www.unit.co/card-issuing) | US | Embedded cards, virtual cards, programmatic authorization, white-label components. | Useful if Seams needs embedded accounts plus cards. |
| [Moov Card Issuing](https://docs.moov.io/guides/issue-cards/) | US | Wallet-funded Visa virtual cards, card details, events. | Interesting wallet-funded model; current docs describe issuing as closed beta. |

### Processor And Program Platforms

| Provider | Region fit | Public API surface | Notes for Seams |
| --- | --- | --- | --- |
| [Thredd](https://cardsapidocs.thredd.com/docs/create-card-2) | APAC-capable, global | Card creation, card lifecycle, processor APIs. | Good route when Seams wants more program design control and sponsor-bank matching. |
| [Galileo](https://www.galileo-ft.com/payments-and-cards/card-issuing/) | US, global | Enterprise card issuing and processing. | Large-scale processor route; API details may require sales access. |
| [i2c](https://www.i2cinc.com/who-we-serve/developers/) | US, global | Issuer processor and developer program. | Mature processor for credit, debit, prepaid, wallet provisioning, and real-time controls. |

### Multi-Issuer Reference

| Provider | Region fit | Public API surface | Notes for Seams |
| --- | --- | --- | --- |
| [Extend Virtual Card API](https://www.paywithextend.com/virtual-card-api) | US | Multi-issuer virtual card API. | Closest public reference for Seams' issuer-neutral strategy because it supports virtual cards through a customer's chosen issuer. |

### APAC Sales-Gated Candidates

| Provider | Region fit | Public API surface | Notes for Seams |
| --- | --- | --- | --- |
| [Reap Card Issuing](https://reap.global/products/card-issuing) | Hong Kong | Public product page confirms branded physical/virtual cards, API integration, real-time authorization, and funding options. | Strong HK-first lead. Needs API and eligibility diligence. |
| [Infcurion Xard](https://infcurion.com/en/news/news-20251008_001/) | Japan | Public material describes API-based original JCB/Visa card programs. | Best Japan-local route for KK and Japan Startup Visa credibility. Needs issuer/program diligence. |
| [MatchMove Card Issuing](https://www.matchmove.com/solutions/card-issuing) | Singapore, APAC | Public material describes white-label card issuing and embedded finance. | Strong APAC white-label candidate. Needs API and Japan eligibility diligence. |
| [Aspire Card Issuance API](https://aspireapp.com/card-issuance-api) | Singapore, Southeast Asia | Public material describes virtual card API, controls, and business payments. | Lightweight candidate for business and supplier-payment flows. |

## Initial Prototype Providers

Start with three providers:

| Priority | Provider | Prototype role | Why start here |
| --- | --- | --- | --- |
| 1 | [Lithic](https://docs.lithic.com/docs/api-basics) | Fastest developer validation path. | Lithic has public sandbox documentation, virtual card creation, spend limits, simulated authorizations, webhook simulation, and Auth Stream Access for custom authorization decisioning. Use it to validate the Seams adaptor contract quickly. |
| 2 | [Airwallex Issuing](https://www.airwallex.com/docs/issuing/get-started/create-cards) | APAC-style issuing and remote authorization path. | Airwallex supports commercial and consumer card creation, authorization controls, transaction simulation in sandbox, and remote authorization. This is the best first APAC-style test target if Issuing and Remote Authorization are enabled for the account. |
| 3 | [Nium Cards](https://docs.nium.com/docs/cards/card-lifecycle) | Cross-border wallet, card, and dynamic authorization path. | Nium supports wallet funding, virtual card lifecycle, card controls, a hosted card widget for sensitive card data, sandbox testing, and Dynamic Authorization models. This is the strongest first test for a wallet-led APAC program. |

Why these three:

- Lithic gives the shortest route to a working adaptor conformance suite.
- Airwallex gives an APAC/global issuing API with remote authorization and
  simulated transaction testing.
- Nium gives the best match for cross-border wallets, hosted card data display,
  and dynamic authorization.

Keep these as later partner diligence targets:

- Reap for Hong Kong-issued white-label Visa cards.
- Infcurion Xard for Japan-local Visa/JCB issuing.
- MatchMove for Singapore/APAC white-label embedded finance.
- Aspire for lightweight business virtual-card API coverage.

Sandbox and authorization references:

| Provider | Sandbox / test reference | Authorization reference |
| --- | --- | --- |
| Lithic | [API basics and sandbox testing](https://docs.lithic.com/docs/api-basics), [simulate card transactions](https://docs.lithic.com/docs/simulating-transactions) | [Auth Stream Access](https://docs.lithic.com/docs/auth-stream-access-asa), [spend limits](https://docs.lithic.com/docs/spend-limits) |
| Airwallex | [sandbox overview](https://www.airwallex.com/docs/developer-tools/sandbox-environment/sandbox-environment-overview), [simulate transactions on issued cards](https://www.airwallex.com/docs/issuing/transactions/simulate-transactions-on-issued-cards) | [remote authorization](https://www.airwallex.com/docs/issuing/card-controls/remote-authorization), [configure remote authorization](https://www.airwallex.com/docs/issuing/card-controls/remote-authorization/configure-remote-authorization), [authorization controls](https://www.airwallex.com/docs/issuing/card-controls/authorization-controls) |
| Nium | [getting started and sandbox funding](https://docs.nium.com/docs/getting-started), [testing Nium](https://docs.nium.com/docs/testing) | [Dynamic Authorization prerequisites](https://docs.nium.com/docs/cards/dynamic-authorization/prerequisites), [hosted authorization model](https://docs.nium.com/docs/cards/dynamic-authorization/hosted-model), [card controls](https://docs.nium.com/docs/cards/manage-cards), [card widget](https://docs.nium.com/docs/cards/card-widget) |

## Provider Categories After Research

The providers fall into different integration classes. Seams should classify
them by operating role before comparing API features.

| Category | Providers | Integration meaning |
| --- | --- | --- |
| API-first issuing platforms | Lithic, Airwallex, Nium, Highnote, Increase, Unit, Moov | Best candidates for early adaptor work because docs expose card issue, controls, events, and sandbox or test paths. |
| Issuer processors and program platforms | Thredd, Galileo, i2c | Better for mature program design, sponsor-bank matching, and processor-level control. Usually partner or sales gated. |
| Issuer-neutral commercial card middleware | Extend, Corpay | Useful reference for bring-your-own-issuer or commercial-card program workflows. Strong fit for customer-selected issuer strategy. |
| APAC and Japan sales-gated issuer routes | Reap, Infcurion Xard, MatchMove, Aspire | Strong regional credibility. Treat as RFI and partner diligence targets until API access and eligibility are confirmed. |
| Benchmarks or currently deprioritized competitors | Marqeta, Stripe Issuing, Ramp, Brex | Technically useful references for JIT funding, real-time auth, embedded card display, and agentic card positioning. Keep outside first partner shortlist if competitive overlap remains a concern. |

### Removed From Active Evaluation

| Provider | Reason |
| --- | --- |
| Paymentology | The Sprint developer sign-up page says sign-up is currently unavailable while they migrate to a new developer portal. Remove from the active shortlist until direct partner access or a working developer onboarding path exists. |

### Provider Research Matrix

| Provider | Category | Useful public docs | Seams adaptor fit | Notes and gaps |
| --- | --- | --- | --- | --- |
| Lithic | API-first issuing | [Create card](https://docs.lithic.com/docs/create-card), [Auth Stream Access](https://docs.lithic.com/docs/auth-stream-access-asa), [simulate transactions](https://docs.lithic.com/docs/simulating-transactions), [embedded card UI](https://docs.lithic.com/docs/embedded-card-ui), [webhooks](https://docs.lithic.com/docs/events-api) | Strong first conformance target. Supports card issue, spend limits, sandbox simulation, embedded card display, and realtime authorization through ASA. | ASA has a documented response window and fail-closed behavior. Spend limits do not cover every settlement edge case, so Seams still needs clearing and overrun reconciliation. |
| Airwallex | API-first APAC/global issuing | [Issuing overview](https://www.airwallex.com/docs/issuing/overview), [authorization controls](https://www.airwallex.com/docs/issuing/card-controls/authorization-controls), [remote authorization](https://www.airwallex.com/docs/issuing/card-controls/remote-authorization), [secure iframes](https://www.airwallex.com/docs/issuing/manage-cards/retrieve-sensitive-card-details/secure-iframes), [simulate transactions](https://www.airwallex.com/docs/issuing/transactions/simulate-transactions-on-issued-cards) | Strong APAC-style target if Issuing and Remote Authorization are enabled. Good for multi-currency, wallet-funded issuing, hosted card detail display, and remote auth. | Remote authorization has a short response window and configurable default behavior. Account/product enablement is a gating item. |
| Nium | API-first cross-border cards | [Cards](https://docs.nium.com/docs/cards), [manage cards](https://docs.nium.com/docs/cards/manage-cards), [Dynamic Authorization prerequisites](https://docs.nium.com/docs/cards/dynamic-authorization/prerequisites), [Delegated Model](https://docs.nium.com/docs/cards/dynamic-authorization/delegated-model), [card widget](https://docs.nium.com/docs/cards/card-widget), [travel virtual cards](https://docs.nium.com/travel/docs/virtual-cards) | Strong wallet-led APAC/global candidate. Useful for prefunded, single-spend, multi-currency, and delegated authorization models. | Delegated and extended authorization require setup with Nium. Travel-card APIs and general cards APIs may differ by program. |
| Highnote | Full issuing platform | [Highnote docs](https://docs.highnote.com/), [developer resources](https://docs.highnote.com/docs/developers/about-developers), [collaborative authorization](https://docs.highnote.com/docs/issuing/spend-controls/collaborative-authorization), [spend rules](https://docs.highnote.com/docs/issuing/spend-controls/spend-rules), [card viewer SDK](https://docs.highnote.com/docs/developers/sdks/issuing/card-viewer-sdk) | Strong full-program US route with GraphQL API, spend rules, webhooks, SDK-based card display, and collaborative authorization. | Live collaborative authorization needs Highnote enablement. Best for managed issuing stack rather than APAC-first card issuance. |
| Increase | Banking API and cards | [Cards API](https://increase.com/documentation/api/cards), [programmatic card processing](https://increase.com/documentation/programmatic-card-processing), [card payments API](https://increase.com/documentation/api/card-payments), [launch card program](https://increase.com/documentation/launch-a-card-program) | Strong realtime authorization and sandbox simulation reference. Good for a US banking-led card product. | Fit depends on whether Seams wants Increase-hosted accounts and good-funds model. |
| Unit | Embedded banking cards | [Card issuing](https://www.unit.co/card-issuing), [card issuance guide](https://unit.co/docs/card-issuance/), [cards API overview](https://unit.co/docs/api/cards/overview/), [programmatic authorization](https://unit.co/docs/api/cards-authorization-requests/overview/), [card UI component](https://unit.co/docs/white-label-uis/cards/), [sandbox simulations](https://www.unit.co/docs/api/cards/simulations/) | Strong if Seams wants embedded accounts plus cards. Has real-time approval flows, sandbox simulations, events, and PCI-light white-label UI. | Programmatic authorization requires enablement through Unit. Some features depend on bank partner and program type. |
| Moov | Wallet-funded issuing | [Issue cards](https://docs.moov.io/guides/issue-cards/), [issuing tutorial](https://docs.moov.io/guides/issue-cards/issuing-tutorial/), [manage issued transactions](https://docs.moov.io/guides/issue-cards/manage-issued-cards/), [capabilities](https://docs.moov.io/guides/accounts/capabilities/) | Interesting wallet-funded virtual card path. Useful model for wallet balance as the source of card spend. | Card issuing is described as closed beta. Treat as later candidate until beta access is available. |
| Thredd | Issuer processor/program platform | [Cards API](https://cardsapidocs.thredd.com/v2.0/), [create card](https://cardsapidocs.thredd.com/v0.0/docs/create-card-2), [card status](https://cardsapidocs.thredd.com/v2/docs/card-status), [webhooks](https://cardsapidocs.thredd.com/v2.0/docs/introduction-to-webhooks), [API hub access](https://cardsapidocs.thredd.com/v2/docs/accessing-api-hub) | Good processor-level route when Seams needs sponsor-bank matching and program design control. | More implementation burden than API-first issuer platforms. Requires program setup and likely sponsor/program manager decisions. |
| Galileo | Enterprise processor/platform | [Card issuing](https://www.galileo-ft.com/payments-and-cards/card-issuing/), [virtual card setup](https://docs.galileo-ft.com/pro/docs/setup-for-virtual-cards) | Mature enterprise route for white-label card programs and virtual cards. | API details and production access are likely sales-gated. Good later-stage partner if Seams wants a larger processor relationship. |
| i2c | Enterprise processor/platform | [Developers](https://www.i2cinc.com/who-we-serve/developers/) | Mature processor for credit, debit, prepaid, instant issuance, wallet provisioning, and real-time controls. | Public docs are high-level. Treat as RFI and enterprise diligence path. |
| Extend | Multi-issuer virtual card API | [Virtual Card API](https://www.paywithextend.com/virtual-card-api) | Best public reference for issuer-neutral, customer-selected issuer strategy. Supports on-demand virtual cards, auth controls, and multi-issuer connectivity. | Likely commercial-card oriented. Need diligence on API access, issuer coverage, and whether Seams can attach mandate metadata. |
| Corpay | Commercial card issuing API | [Card issuing APIs](https://www.corpay.com/ap-automation/partnerships/card-api), [virtual cards](https://www.corpay.com/commercial-cards/virtual-cards) | Useful for AP automation, invoice-bound cards, real-time transaction tracking, and programmable spend rules. | More commercial-card and AP-focused than consumer agentic shopping. API docs appear sales-led. |
| Treasury Prime | Banking platform plus partner card issuing | [Developer resources](https://www.treasuryprime.com/developers), [card issuance API article](https://www.treasuryprime.com/blog/card-issuance-api), [white-label card issuing](https://www.treasuryprime.com/blog/white-label-card-issuing) | Useful bank-partner route when Seams wants banking APIs plus card issuing through partner integrations. | Card issuing path depends on partner processor relationships. Treat as RFI. |
| Reap | APAC card issuing and stablecoin/fiat funding | [Card issuing](https://reap.global/products/card-issuing), [Reap home](https://reap.global/) | Strong Hong Kong lead. Public material maps well to Seams because it mentions Visa cards, stablecoin or fiat funding, and real-time authorization. | API docs and jurisdiction eligibility need partner diligence. Good outreach target for HK-first story. |
| Infcurion Xard | Japan card issuing and processing | [Xard B2C expansion](https://infcurion.com/en/news/news-20250922_001/), [Xard launch PDF](https://assets.ctfassets.net/tb7n53plo58o/tYBWLBi9mQK4NBVCZNdDO/a36646da027d88982904a176e8d58b65/20220726_infcurion_release_.pdf) | Best Japan-local credibility path. Public material describes API-based Visa/JCB card programs and virtual/physical cards. | Public developer docs are limited. Needs direct partner diligence on API access, startup eligibility, and program ownership. |
| MatchMove | APAC embedded finance/card issuing | [Card issuing](https://www.matchmove.com/solutions/card-issuing) | Strong APAC white-label candidate with instant virtual cards, tokenization, limits, Apple Pay/Google Pay, and multi-pouch controls. | API details appear sales-gated. Need diligence on Japan/HK/SG issuance and delegated auth. |
| Aspire | Southeast Asia business card API | [Card issuance API](https://aspireapp.com/card-issuance-api) | Lightweight supplier-payment and business virtual-card candidate. Public material mentions real-time issuance, 30+ currencies, limits, merchant locks, expiration, freeze/cancel. | Likely best for business payables rather than full card program control. Need API docs and account eligibility. |
| Marqeta | Benchmark/deprioritized competitor | [JIT Funding](https://www.marqeta.com/docs/developer-guides/about-jit-funding), [JIT platform](https://www.marqeta.com/platform/jit-funding) | Useful benchmark for just-in-time funding and realtime transaction control. | Deprioritized as primary partner because of competitive overlap. |
| Stripe Issuing | Benchmark/deprioritized competitor | [Issuing](https://docs.stripe.com/issuing), [real-time authorizations](https://docs.stripe.com/issuing/controls/real-time-authorizations), [authorizations](https://docs.stripe.com/issuing/purchases/authorizations) | Useful benchmark for real-time authorization, spending controls, and agentic-card positioning. | Deprioritized as primary partner because of competitive overlap. |
| Ramp and Brex | Commercial-card benchmarks | [Ramp virtual cards](https://docs.ramp.com/developer-api/v1/virtual-cards), [Brex API](https://developer.brex.com/) | Useful references for embedded card display, virtual card APIs, budgets, limits, and card management. | These are customer-account card platforms more than issuer adaptors. Treat as competitive/product benchmarks. |

## Core Architecture

Seams should treat each provider as a card execution adaptor behind one
provider-neutral interface.

```text
Shopping mandate
  -> Seams policy compiler
  -> provider capability resolver
  -> card-control plan
  -> issuer adaptor
  -> virtual card
  -> authorization, clearing, receipt, refund, and shipment evidence
  -> audit trail
```

The adaptor should normalize:

- program capabilities
- cardholder references
- card creation
- card display sessions
- card-control compilation
- real-time authorization decisions
- webhook and event formats
- clearing, refund, reversal, dispute, and chargeback events
- transaction metadata attachment

The most important design rule:

```text
The Seams mandate remains the source of truth. Provider controls are execution
constraints compiled from that mandate.
```

## Authorization Modes

Different providers enforce spend controls in different places. The adaptor
must model this explicitly.

```ts
type AuthorizationMode =
  | { kind: "provider_rules" }
  | { kind: "realtime_delegate"; timeoutMs: number }
  | { kind: "observe_only" };
```

## Authorization Mode Recommendation

For delegated wallet spending by shopping agents, the default should be:

```ts
type AgentSpendAuthorizationMode = {
  kind: "realtime_delegate";
  timeoutMs: number;
  timeoutPolicy: "decline";
  providerHardControlsRequired: true;
};
```

Use delegated real-time authorization as the active policy decision layer:

```text
Merchant authorization request
  -> issuer calls Seams
  -> Seams loads mandate, wallet state, card state, quote, and revocation state
  -> Seams approves, declines, or escalates
  -> issuer completes network authorization
  -> Seams stores decision and event evidence
```

Compile provider-controlled cards as hard outer limits:

- single-use or limited-use card
- max amount
- currency
- expiry window
- merchant lock where available
- MCC/category allowlist where available
- online-only or channel restrictions where available
- velocity controls where available

This gives Seams two layers of protection:

1. The issuer blocks simple policy breaches using native card controls.
2. Seams makes the final agent-spend decision using the full mandate context.

Observe-only cards should be limited to:

- business-owned cards that already exist outside Seams
- reconciliation and audit pilots
- low-risk spend monitoring
- compatibility integrations where hard enforcement is unavailable

Agent-initiated purchases should fail closed when Seams cannot evaluate a
required mandate at authorization time.

### Provider Rules

Seams creates a card with amount, currency, merchant, MCC, expiry, or velocity
controls. The issuer approves or declines based on those controls.

Use when:

- provider supports strong card controls
- Seams does not need to approve each authorization synchronously
- the shopping mandate can be safely reduced to provider-native controls

Risk:

- unsupported mandate constraints need pre-issue approval or escalation
- Seams may learn about edge cases after the authorization event

### Realtime Delegate

The issuer sends an authorization request to Seams. Seams approves, denies, or
escalates under its mandate policy.

Use when:

- provider supports remote authorization or delegated authorization
- Seams needs to enforce policy at payment time
- Seams holds the wallet balance or must check agent mandate state at the point
  of sale

Risk:

- timeout behavior must be explicit
- fallback must fail closed for agentic purchases
- Seams needs high availability and low-latency authorization handling

### Observe Only

Seams issues or tracks cards and receives events after provider decisions.

Use when:

- provider offers limited controls
- card is used for lower-risk business payments
- Seams needs audit and reconciliation more than hard enforcement

Risk:

- policy enforcement is weaker
- high-risk delegated shopping should require explicit approval before card
  issuance

## Funding Modes

Funding should also be explicit. The same card API can represent different
economic structures.

```ts
type FundingMode =
  | { kind: "issuer_held_balance" }
  | { kind: "seams_wallet_delegated_auth" }
  | { kind: "prefunded_card" }
  | { kind: "credit_or_charge_program" };
```

### Issuer-Held Balance

The issuer or program account holds fiat funds. Seams directs card creation and
records events.

### Seams Wallet Delegated Authorization

Seams or a Seams-controlled wallet ledger authorizes each card transaction. This
is the cleanest architecture for mandate-bound shopping agents if the partner
supports delegated authorization.

### Prefunded Card

Seams loads a limited card balance before checkout. This is practical for
single-use cards and pilot flows.

### Credit Or Charge Program

The issuer extends credit or charge-card capacity. This is useful for business
customers, though underwriting, repayment, and credit regulation make it a later
path.

## Control Model

Seams should compile its own mandate policy into a provider-specific
`CardControlPlan`.

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

type ControlEnforcement =
  | { kind: "provider_hard_control"; control: CardControl }
  | { kind: "seams_realtime_control"; control: CardControl }
  | { kind: "approval_before_issue"; control: CardControl }
  | { kind: "unsupported"; control: CardControl; reason: string };
```

Examples:

- A max amount can usually become a provider card limit.
- A merchant lock may become a provider merchant rule, a realtime Seams check,
  or a pre-approved single merchant checkout.
- A shipping-risk condition usually remains a Seams policy check because card
  networks do not know shipment evidence.
- A coupon or deal-quality requirement should stay in the Seams Shopping Feed
  and Shopping Cue Engine, then bind to the approved quote before card issue.

## Domain Objects

Use provider-neutral internal objects. Provider-specific raw shapes should be
validated once at the adaptor boundary.

```ts
type IssuerProgram =
  | {
      kind: "card_program";
      programId: string;
      provider: IssuerProvider;
      region: IssuerRegion;
      networks: CardNetwork[];
      authorizationMode: AuthorizationMode;
      fundingMode: FundingMode;
      cardDataMode: CardDataMode;
    };

type CardDataMode =
  | { kind: "hosted_widget" }
  | { kind: "provider_sensitive_api"; pciScope: "expanded" }
  | { kind: "network_token_only" };

type VirtualCardState =
  | { kind: "requested"; requestId: string; mandateId: string }
  | { kind: "issued"; cardId: string; providerCardId: string; mandateId: string }
  | { kind: "frozen"; cardId: string; providerCardId: string; reason: string }
  | { kind: "closed"; cardId: string; providerCardId: string; reason: string };

type AuthorizationDecision =
  | { kind: "approved"; authorizationId: string; approvedAmountMinor: number }
  | { kind: "declined"; authorizationId: string; reason: DeclineReason }
  | { kind: "escalated"; authorizationId: string; approvalRequestId: string };

type IssuerEvent =
  | { kind: "card_issued"; cardId: string; providerCardId: string }
  | { kind: "authorization_requested"; authorizationId: string; cardId: string }
  | { kind: "authorization_approved"; authorizationId: string; cardId: string }
  | { kind: "authorization_declined"; authorizationId: string; cardId: string }
  | { kind: "transaction_cleared"; transactionId: string; cardId: string }
  | { kind: "refund_posted"; transactionId: string; cardId: string }
  | { kind: "reversal_posted"; transactionId: string; cardId: string }
  | { kind: "dispute_opened"; disputeId: string; transactionId: string }
  | { kind: "chargeback_posted"; disputeId: string; transactionId: string };
```

## Adaptor Interface

The interface should be branch-specific so unsupported operations are impossible
to call on the wrong provider mode.

```ts
type IssuerResult<T> =
  | { kind: "ok"; value: T }
  | { kind: "provider_error"; provider: IssuerProvider; code: string; message: string }
  | { kind: "capability_error"; provider: IssuerProvider; unsupported: CardControl[] }
  | { kind: "compliance_error"; provider: IssuerProvider; reason: string };

type RealtimeAuthorizingAdaptor = {
  kind: "realtime_authorizing";
  provider: IssuerProvider;
  capabilities: IssuerCapabilities;
  createCardholder(input: CreateCardholderRequest): Promise<IssuerResult<CardholderRef>>;
  issueVirtualCard(input: IssueVirtualCardRequest): Promise<IssuerResult<IssuedCard>>;
  createCardDisplaySession(input: CardDisplayRequest): Promise<IssuerResult<CardDisplaySession>>;
  decideAuthorization(input: AuthorizationRequest): Promise<IssuerResult<AuthorizationDecision>>;
  normalizeWebhook(input: RawIssuerWebhook): IssuerResult<IssuerEvent>;
};

type ProviderRulesOnlyAdaptor = {
  kind: "provider_rules_only";
  provider: IssuerProvider;
  capabilities: IssuerCapabilities;
  createCardholder(input: CreateCardholderRequest): Promise<IssuerResult<CardholderRef>>;
  issueVirtualCard(input: IssueVirtualCardRequest): Promise<IssuerResult<IssuedCard>>;
  createCardDisplaySession(input: CardDisplayRequest): Promise<IssuerResult<CardDisplaySession>>;
  normalizeWebhook(input: RawIssuerWebhook): IssuerResult<IssuerEvent>;
};

type ObserveOnlyAdaptor = {
  kind: "observe_only";
  provider: IssuerProvider;
  capabilities: IssuerCapabilities;
  linkExternalCard(input: LinkExternalCardRequest): Promise<IssuerResult<LinkedCard>>;
  normalizeWebhook(input: RawIssuerWebhook): IssuerResult<IssuerEvent>;
};

type IssuerAdaptor =
  | RealtimeAuthorizingAdaptor
  | ProviderRulesOnlyAdaptor
  | ObserveOnlyAdaptor;
```

Open implementation note:

- A hosted card-display session should be required for providers that support
  it.
- Direct PAN/CVV handling should be treated as a separate PCI-scoped product
  decision.
- The first implementation should prefer hosted widgets and provider-managed
  sensitive-data display.

## Provider Capability Resolver

Each adaptor should expose capabilities in a way the policy compiler can use.

```ts
type SupportedControl =
  | { kind: "single_use" }
  | { kind: "amount_limit"; intervals: SpendingInterval[] }
  | { kind: "merchant_lock"; matcher: "network_merchant_id" | "merchant_name" | "provider_merchant_ref" }
  | { kind: "mcc_allowlist" }
  | { kind: "geo_allowlist" }
  | { kind: "currency_allowlist" }
  | { kind: "velocity_limit"; intervals: SpendingInterval[] }
  | { kind: "remote_authorization"; timeoutMs: number }
  | { kind: "hosted_card_display" }
  | { kind: "metadata_passthrough"; keys: string[] };

type IssuerCapabilities = {
  provider: IssuerProvider;
  programId: string;
  controls: SupportedControl[];
  events: SupportedIssuerEvent[];
  fundingMode: FundingMode;
  authorizationMode: AuthorizationMode;
  cardDataMode: CardDataMode;
};
```

The compiler output should show exactly how Seams will enforce each requested
mandate control:

```text
Requested mandate controls
  -> provider-hard controls
  -> Seams realtime controls
  -> approval-before-issue controls
  -> unsupported controls
```

High-risk agent flows should fail closed if a required control is unsupported.

## Architecture Review After Provider Research

The initial plan is feasible and mostly complete for a prototype. The missing
parts are implementation axes that affect provider selection, runtime behavior,
and compliance boundaries.

### Missing Architecture Dimensions

Add these as first-class capability dimensions:

| Dimension | Why it matters |
| --- | --- |
| Program access state | A provider can have public docs while production card issuing, remote authorization, or card display remains account-enabled or partner-enabled. |
| Compliance responsibility model | KYC/KYB, AML, sanctions, fraud, disputes, settlement, reserves, PCI, and cardholder support can sit with different parties per provider. |
| Ledger owner | Some providers hold balances, some issue cards against customer wallets, and some call Seams or a Seams-controlled ledger at authorization time. |
| Sensitive card data mode | Hosted iframe/widget/SDK, provider-sensitive API, network token only, and no display support need separate branches. |
| Authorization SLA | Lithic, Airwallex, Unit, Highnote, and processor-style providers expose different request deadlines, timeout defaults, and stand-in behavior. |
| Webhook delivery semantics | Providers vary across HMAC/signature scheme, retry model, batching, historical replay, event IDs, and at-least-once delivery. |
| Settlement exception handling | Force-posts, overcaptures, incremental authorization, authorization expiry, reversal, refund, dispute, and chargeback events need explicit states. |
| Simulation support | Sandbox card issue, simulated auth, clearing, refund, reversal, timeout, webhook replay, and provider test credentials differ sharply. |
| Metadata preservation | Mandate ID, quote ID, agent ID, order ID, receipt ID, shipment evidence ID, and refund ID may not survive every provider event. |
| 3DS and cardholder challenge flow | Some providers can trigger challenge flows through issuer-managed SMS or customer-orchestrated prompts. This matters for VoiceID and passkey approval. |
| Tokenization and wallet provisioning | Apple Pay, Google Pay, network tokenization, and push provisioning should be outside the first card issue surface, then added as a module. |
| Card topology | The architecture needs to decide whether a mandate can issue one card, many single-use cards, or a reusable merchant/session card. |

### Modular Adaptor Shape

Avoid a monolithic adaptor. Compose provider modules from small connectors and
make unavailable capabilities explicit.

```ts
type ConnectorAvailability<TAvailable> =
  | { kind: "available"; connector: TAvailable; reason?: never }
  | { kind: "unavailable"; connector?: never; reason: string };

type ProgramAccessState =
  | { kind: "public_sandbox"; credentialMode: "self_service" }
  | { kind: "partner_sandbox"; partnerContact: string }
  | { kind: "production_enabled"; programId: string }
  | { kind: "sales_gated"; nextStep: string };

type ProviderRole =
  | { kind: "issuer_platform" }
  | { kind: "issuer_processor" }
  | { kind: "multi_issuer_middleware" }
  | { kind: "commercial_card_platform" };

type ComplianceResponsibility = {
  kybOwner: ComplianceOwner;
  kycOwner: ComplianceOwner;
  amlOwner: ComplianceOwner;
  fraudOwner: ComplianceOwner;
  disputeOwner: ComplianceOwner;
  settlementOwner: ComplianceOwner;
  pciOwner: ComplianceOwner;
  cardholderSupportOwner: ComplianceOwner;
};

type ComplianceOwner =
  | { kind: "seams" }
  | { kind: "provider" }
  | { kind: "issuer_bank" }
  | { kind: "shared"; evidenceRequired: string };

type IssuerProviderProfile = {
  kind: "issuer_provider_profile";
  provider: IssuerProvider;
  role: ProviderRole;
  accessState: ProgramAccessState;
  compliance: ComplianceResponsibility;
  capabilities: IssuerCapabilities;
};
```

The runtime adaptor should be assembled from capability-specific connectors:

```ts
type IssuerIntegration = {
  kind: "issuer_integration";
  profile: IssuerProviderProfile;
  program: ProgramConnector;
  cardholders: ConnectorAvailability<CardholderConnector>;
  cards: CardLifecycleConnector;
  controls: CardControlConnector;
  cardData: CardDataConnector;
  authorization: AuthorizationConnector;
  events: IssuerEventConnector;
  reconciliation: ReconciliationConnector;
  simulation: ConnectorAvailability<SimulationConnector>;
};
```

This gives each provider a clear map:

- Lithic: available card lifecycle, card controls, embedded card UI, realtime
  authorization, events, and simulation.
- Airwallex: available card lifecycle, controls, secure iframes, remote
  authorization, events, and simulation once Issuing and Remote Authorization are
  enabled.
- Nium: available wallet/cards/card widget with dynamic authorization behind
  setup.
- Extend and Corpay: likely provider-rules or middleware routing first, with
  realtime behavior confirmed during diligence.

### Authorization Connector

Model timeout and stand-in behavior as data. Agentic purchases should require a
decline-on-timeout branch unless a human approval happened before issue.

```ts
type AuthorizationConnector =
  | {
      kind: "realtime_delegate";
      timeout: AuthorizationTimeoutPolicy;
      decideAuthorization(input: AuthorizationRequest): Promise<IssuerResult<AuthorizationDecision>>;
    }
  | {
      kind: "provider_rules";
      timeout?: never;
      decideAuthorization?: never;
    }
  | {
      kind: "observe_only";
      timeout?: never;
      decideAuthorization?: never;
    };

type AuthorizationTimeoutPolicy =
  | { kind: "decline"; timeoutMs: number }
  | { kind: "provider_default"; timeoutMs: number; configuredDefault: "approve" | "decline" }
  | { kind: "network_stand_in"; timeoutMs: number; expectedOutcome: "approve" | "decline" | "unknown" };
```

### Card Data Connector

Keep card detail display separate from card lifecycle so PCI scope is visible in
the type system.

```ts
type CardDataConnector =
  | {
      kind: "hosted_frame";
      createDisplaySession(input: CardDisplayRequest): Promise<IssuerResult<CardDisplaySession>>;
      retrieveSensitiveDetails?: never;
    }
  | {
      kind: "provider_sensitive_api";
      pciScope: "expanded";
      createDisplaySession?: never;
      retrieveSensitiveDetails(input: SensitiveCardDataRequest): Promise<IssuerResult<SensitiveCardData>>;
    }
  | {
      kind: "network_token_only";
      createDisplaySession?: never;
      retrieveSensitiveDetails?: never;
    };
```

First implementation rule:

```text
Only implement hosted_frame and network_token_only paths in the MVP. Add
provider_sensitive_api after a separate PCI product decision.
```

### Event And Reconciliation Connector

Authorization and settlement are different state machines. Store both.

```ts
type IssuerEventConnector = {
  kind: "issuer_event_connector";
  verifyEnvelope(input: RawIssuerWebhookEnvelope): IssuerResult<VerifiedIssuerWebhookEnvelope>;
  normalizeEvent(input: VerifiedIssuerWebhookEnvelope): IssuerResult<IssuerEvent>;
};

type ReconciliationConnector = {
  kind: "reconciliation_connector";
  applyIssuerEvent(input: ApplyIssuerEventInput): IssuerResult<CardLedgerTransition>;
};

type CardLedgerTransition =
  | { kind: "authorization_hold_created"; authorizationId: string; amountMinor: number }
  | { kind: "authorization_hold_released"; authorizationId: string; reason: string }
  | { kind: "clearing_posted"; transactionId: string; amountMinor: number }
  | { kind: "overcapture_posted"; transactionId: string; authorizedAmountMinor: number; clearedAmountMinor: number }
  | { kind: "force_posted_transaction"; transactionId: string; amountMinor: number }
  | { kind: "refund_posted"; transactionId: string; amountMinor: number }
  | { kind: "chargeback_posted"; disputeId: string; amountMinor: number };
```

### Capability-Aware Compiler

The compiler should return a plan with no hidden fallbacks. Unsupported required
controls fail before card issue.

```ts
type CardControlPlan =
  | {
      kind: "issuable";
      provider: IssuerProvider;
      mandateId: string;
      providerHardControls: CardControl[];
      seamsRealtimeControls: CardControl[];
      approvalBeforeIssueControls: CardControl[];
      auditExplanation: string;
    }
  | {
      kind: "not_issuable";
      provider: IssuerProvider;
      mandateId: string;
      unsupportedRequiredControls: UnsupportedControl[];
      auditExplanation: string;
    };

type UnsupportedControl = {
  kind: "unsupported_control";
  control: CardControl;
  reason: string;
  possibleFallback: ControlFallback;
};

type ControlFallback =
  | { kind: "human_approval_before_issue" }
  | { kind: "switch_provider"; requiredCapability: SupportedControl }
  | { kind: "reduce_mandate_scope"; explanation: string }
  | { kind: "no_safe_fallback"; explanation: string };
```

### Clean Package Boundary

Recommended package split:

| Package area | Responsibility |
| --- | --- |
| `packages/shared-ts/src/virtual-cards` | Provider-neutral domain types, result unions, control plan types, event enums, type fixtures. |
| `packages/sdk-server-ts/src/virtual-cards` | Compiler, adaptor registry, provider profiles, webhook verification, authorization responder, reconciliation service. |
| `packages/sdk-server-ts/src/virtual-cards/providers/*` | Provider-specific raw request builders, response parsers, webhook normalizers, and API clients. |
| `apps/web-server/src` | Route wiring, credentials, concrete storage, external webhook endpoints, and environment config. |
| `tests/unit/virtual-cards` | Type fixtures, compiler tests, fake adaptor conformance suite, provider webhook normalization tests. |

Provider-specific modules should parse raw API responses immediately and return
only internal domain types. Core compiler and reconciliation logic should never
accept raw provider strings or raw webhook payloads.

## Example Flows

### Agent Finds A Bargain

```text
1. Agent finds a listing and shipping quote.
2. Seams Shopping Feed normalizes listing, merchant, coupon, shipping, and trust signals.
3. Shopping Cue Engine decides whether the purchase is routine, sensitive, or approval-required.
4. Buyer approves a mandate or existing mandate is checked.
5. Seams compiles mandate controls into issuer controls.
6. Issuer adaptor creates a scoped virtual card.
7. Agent checks out with Visa, Mastercard, or JCB.
8. Authorization event is approved by provider rules or by Seams realtime policy.
9. Receipt, shipment evidence, refund state, and settlement references attach to the audit trail.
```

### Buyer-Seller Negotiation

```text
1. Agent messages seller within a negotiation mandate.
2. Seller agrees to price, condition, shipping, and return terms.
3. Seams binds the negotiated terms to a quote digest.
4. Buyer approves or prior policy allows the purchase.
5. Seams issues a single-use virtual card capped at the negotiated total.
6. Payment, receipt, messages, shipment evidence, and refund windows are recorded.
```

### Business Chooses Its Issuer

```text
1. Business selects Reap, Infcurion Xard, Nium, Lithic, Extend, or another provider.
2. Seams stores the provider program and capabilities.
3. The same Seams mandate policy runs regardless of issuer.
4. Provider-specific controls and webhooks are normalized behind the adaptor.
5. The business sees one Seams audit trail across card providers.
```

## MVP Build Order

### Phase 0: Provider Profiles And Diligence

- Create `IssuerProviderProfile` entries for Lithic, Airwallex, Nium, Highnote,
  Increase, Unit, Moov, Thredd, Extend, Reap, Infcurion Xard,
  MatchMove, Aspire, Corpay, Treasury Prime, Galileo, and i2c.
- Record access state, compliance responsibility, funding mode, authorization
  mode, card-data mode, webhook signature model, simulation support, and
  production gating.
- Start RFI outreach for Reap, Infcurion Xard, Nium, MatchMove, Thredd, and
  Aspire.
- Request sandbox or partner-test credentials for Lithic, Airwallex, Nium,
  Highnote, Increase, and Unit.

### Phase 1: Provider-Neutral Core

- Define issuer program, cardholder, virtual card, card-control plan, event, and
  authorization decision types.
- Define provider profile, compliance ownership, connector availability,
  authorization timeout, card-data mode, webhook envelope, and reconciliation
  transition types.
- Build the mandate-to-card-control compiler.
- Build event normalization, card ledger transitions, and audit storage.
- Implement hosted card-display session handling as the preferred PCI-light
  pattern.
- Build a fake provider adaptor and conformance suite before any live provider
  client.
- Add type fixtures for invalid branch combinations, unsupported controls,
  unsafe provider-sensitive card data access, and missing timeout policies.

### Phase 2: Prototype Provider Adaptors

Target the first providers in this order:

1. Lithic for the fastest sandbox-backed adaptor validation.
2. Airwallex for APAC/global issuing, simulated transactions, card controls, and
   remote authorization.
3. Nium for cross-border wallet/card lifecycle, hosted card display, and
   Dynamic Authorization.
4. Increase or Highnote as a second US realtime authorization benchmark.
5. Unit if embedded accounts plus cards become important for the pilot.

Deliver:

- cardholder creation
- virtual card issue
- controls
- hosted or provider-managed card detail display
- authorization or event webhooks
- refund, reversal, and clearing normalization
- provider profile fixtures
- simulation-backed conformance tests

### Phase 3: Realtime Authorization Adaptor

Target delegated real-time authorization as the default agent-spend mode:

- Lithic Auth Stream Access for custom authorization decisioning in the US
  sandbox/prototype path.
- Airwallex remote authorization for APAC/global issuing, with the default
  action configured as `DECLINED`.
- Nium Dynamic Authorization delegated or extended model, with Seams responding
  to authorization requests under mandate policy.
- Unit programmatic authorization and Highnote collaborative authorization as
  US secondary benchmarks if credentials arrive earlier than APAC credentials.

Deliver:

- realtime authorization endpoint
- timeout handling
- fail-closed policy for agentic commerce
- mandate lookup and revocation check
- receipt and audit binding
- replay-safe request handling
- provider request-signature or encryption verification
- provider response mapping from Seams policy decisions
- provider-specific stand-in behavior captured in audit evidence

### Phase 4: Multi-Issuer Routing

Add provider selection:

- business-selected issuer
- jurisdiction match
- currency match
- control-depth match
- authorization-mode match
- cost and FX preference
- fallback rules for unavailable providers
- access state and sandbox/live readiness
- compliance responsibility match
- card-data display mode
- webhook/reconciliation completeness

Routing should explain the chosen provider in audit logs:

```text
Selected provider: Nium
Reason: business preference, HK/SG issuing path, USD support, dynamic authorization enabled.
```

### Phase 5: Sales-Gated APAC Integrations

After RFI and partner calls, add adaptors for:

- Reap
- Infcurion Xard
- MatchMove
- Aspire

These should use the same core interface once API access is available.

## Partner RFI Questions

Ask each issuer:

- Do you support white-label or co-branded virtual cards?
- Which jurisdictions can issue cards for Japan-based companies or
  Japan-resident users?
- Which networks are supported: Visa, Mastercard, JCB, UnionPay, or others?
- Are cards prepaid, debit, charge, credit, commercial, consumer, or
  business-only?
- Can Seams create cards by API?
- Can Seams create single-use or limited-use cards?
- Which controls are enforced by the issuer: amount, merchant, MCC, geography,
  currency, expiry, velocity, and card balance?
- Do you support remote authorization or delegated authorization?
- What is the authorization timeout and default behavior on timeout?
- Can Seams attach mandate IDs, agent IDs, quote IDs, order IDs, shipment
  evidence IDs, refund IDs, and settlement references to card metadata?
- Do you provide hosted card-detail display to reduce PCI scope?
- Who owns KYC/KYB, AML, sanctions, fraud monitoring, disputes, chargebacks,
  customer support, settlement, and reserves?
- What are setup fees, monthly minimums, per-card fees, authorization fees, FX
  markups, interchange share, reserve requirements, dispute fees, and
  chargeback fees?

## Open Technical Decisions

- Which provider grants usable sandbox credentials first: Lithic, Airwallex, or
  Nium.
- Whether the first live pilot should use Airwallex or Nium for APAC execution
  after the Lithic-style sandbox conformance test passes.
- Whether low-risk merchant payments can use provider rules only.
- Whether Seams should support observe-only cards for business customers that
  already have a card issuer.
- How much transaction metadata each provider can preserve.
- Whether card limits should be created per quote, per cart, per merchant, or
  per shopping session.
- Whether the same mandate can issue multiple cards or one mandate maps to one
  card.
- How refund and chargeback events should affect the shopping-agent mandate and
  merchant settlement state.
- Which providers can preserve Seams mandate metadata through authorization,
  clearing, refund, dispute, and reporting surfaces.
- Which providers can support hosted card display in a PCI-light path without
  Seams handling PAN or CVV.
- Which providers let Seams configure decline-on-timeout for delegated
  authorization.
- How webhook retry, ordering, and replay should be normalized into one
  idempotent event ingestion contract.
- Whether 3DS, cardholder challenge, VoiceID, and passkey approval should share
  one approval state machine.
- Whether Seams should support network tokenization and mobile wallet
  provisioning in the first issuer-neutral version.
- How to represent overcapture, force-post, offline authorization, incremental
  authorization, and authorization expiry in the Seams ledger.
- Which commercial model is acceptable for each provider: setup fee, monthly
  minimum, interchange share, FX markup, reserve, and dispute fee.

## Recommended Near-Term Position

For the deck and partner conversations:

```text
Seams integrates with multiple white-label virtual card issuers. Businesses can
choose their preferred issuer, while Seams provides one policy, budget,
approval, agent-spend, evidence, and audit layer across card providers.
```

For the technical roadmap:

```text
Build the provider-neutral mandate-to-card-control compiler first. Validate it
against Lithic, Airwallex, and Nium sandbox or partner-test environments. Add
APAC sales-gated adaptors after partner diligence.
```

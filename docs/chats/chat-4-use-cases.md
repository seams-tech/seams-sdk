# Chat 4: Use Cases, Japan Commerce, and Stablecoin Cards

Date: June 9, 2026

Status: active strategy and payments handoff.

## Goal

Clarify which commercially plausible use cases the wallet and identity
infrastructure should pursue, with focus on Japan/APAC/US, ecommerce, and the
payment architecture for an agentic shopping product.

The current product direction is:

```text
English-first smart personal shopper and life-admin purchasing agent for Japan
  -> user describes what they need in English
  -> agent handles Japanese listings, forms, merchant questions, delivery, and
     follow-up
  -> user approves a bounded budget through the wallet/auth SDK
  -> payment executes through PSP checkout, single-use virtual cards, or human
     concierge fallback
```

The product should sell completed local tasks. Crypto infrastructure stays
behind the scenes.

## Current Direction

The strongest near-term wedge is ecommerce execution for foreigners in Japan.

The user pain is execution after translation. Translation tools work when the
user only needs to understand a label, phrase, or short conversation. The
painful workflow starts when the user needs an action completed:

- compare Japanese listings and choose a local substitute
- ask seller or staff follow-up questions
- fill Japanese checkout, booking, or municipal forms
- format hotel or apartment delivery instructions correctly
- schedule delivery, assembly, garbage pickup, or service appointments
- pay from a user-approved budget
- handle receipts, cancellations, refunds, and follow-up

The consumer pitch is:

```text
Your English-speaking personal shopper for Japan.
Translation helps you understand. This gets the thing done.
```

Voice is an input mode. The product should keep chat and visual approval as
first-class surfaces because review, correction, and final payment approval need
precision.

## Repo Capability Fit

The repo is strongest as delegated authority infrastructure:

- passkey wallet identity
- scoped spending mandates
- threshold signing for higher-value delegated authority
- exact signing lanes for user, agent, merchant, task, and budget identity
- intent digest binding for cart, merchant, amount, delivery, and terms
- recoverable wallet sessions
- audit logs for agent actions, receipts, refunds, and support replay

The durable primitive is a signed purchase mandate:

```text
user authorizes this agent
for this task
up to this amount
from this merchant or category
to this delivery address
before this expiry
with step-up for risky changes
```

The wallet is the authorization layer. Money movement should stay behind a PSP,
card issuer, stablecoin-card provider, or licensed partner until the legal
structure is settled.

## Japan Product Scope

Prioritize categories with high friction, repeat usage, and manageable risk:

- pet food and litter
- household supplies
- tools, adapters, chargers, luggage, and daily essentials
- furniture and home setup
- bulky waste and garbage-removal booking
- appliance delivery and assembly coordination
- recurring replenishment for safe categories

Defer medicine and pet medicine until category-specific guardrails exist. The
medicine flow should be guided commerce through licensed retailers, with
pharmacist handoff where needed. Medical advice is out of scope.

## Friend Critique And Response

The friend raised useful objections:

- a simpler translation product may solve many cases
- payments may sit below the user-facing pain
- voice can be polarizing
- end-to-end ecommerce may be cleaner than voice over arbitrary merchants
- robotics and home AI may be a larger long-term direction

The response:

- the product should avoid translation-only tasks
- the wedge is execution: forms, questions, delivery, booking, payment, and
  follow-up
- voice should speed up intake, while chat and visual approval handle precision
- payments matter when an agent acts with bounded authority
- ecommerce validates the wallet mandate model faster than robotics because it
  can be tested without hardware distribution

Robotics remains a valid adjacent use case for the same primitive:

```text
authorized non-human actor
  -> bounded task authority
  -> signed intent
  -> policy check
  -> auditable action
```

## Standards-Led GTM Rejection

The chat considered Google AP2, Visa Trusted Agent Protocol, Mastercard Agent
Pay, and related agent-commerce standards.

Current position:

- keep these protocols out of the Japan MVP path
- Japanese merchants are unlikely to support them in the near term
- merchant-side value is unclear today
- these protocols may be early attempts by large networks or platforms to
  control agentic commerce distribution before merchant demand is proven

The near-term merchant problem is:

- completed orders
- fewer broken checkouts
- lower fraud and support load
- payment methods they already accept
- reliable delivery and post-purchase handling

Revisit external agent-commerce protocols only if a target merchant, PSP,
issuer, or processor already supports them and they clearly improve checkout
coverage or fraud/support outcomes.

## Payment Direction

The active payment thread is stablecoin-linked virtual cards.

Target architecture:

```text
user funds wallet with stablecoin or stablecoin-backed balance
  -> agent prepares quote
  -> user signs bounded PaymentMandate with passkey wallet
  -> backend reserves stablecoin value plus FX/tolerance buffer
  -> provider creates a single-use virtual card for the task
  -> agent uses card at Japanese ecommerce checkout
  -> card is canceled after success, failure, or expiry
  -> clearing, refunds, and receipts reconcile back to the wallet
```

The merchant sees a normal card payment in JPY. The user sees a wallet-funded
task with bounded agent authority.

Minimum virtual-card controls:

- one card per task
- max amount plus small FX buffer
- expiry in minutes or hours
- online-only
- no ATM or cash access
- no recurring payments unless separately approved
- merchant, MCC, country, or domain restriction where the provider supports it
- auto-cancel after success, failure, or expiry
- receipt and clearing metadata bound back to the signed mandate

The provider diligence question:

```text
Can our backend create, approve, or release each card only after verifying a
signed mandate from our wallet SDK?
```

## Provider View

Current working ranking for a Japan-oriented stablecoin-linked virtual-card
strategy:

1. Rain: best public fit to investigate first. Rain publicly markets
   stablecoin-powered cards, agentic commerce, and single-use virtual cards with
   transaction-level limits. Rain also announced APAC expansion.
2. Immersve: strong candidate if real-time authorization can check the signed
   mandate against the user's stablecoin-backed ledger before approval.
3. Gnosis Pay: useful wallet-native/self-custody watchlist. Japan is listed as
   coming soon, so keep it as a watchlist item for now.
4. Bridge: interesting card and stablecoin infrastructure, especially outside
   Japan. Public docs said Bridge services were unavailable for individuals and
   businesses located in Japan during this chat, so treat it as a US/global
   pilot option unless that changes.

All provider claims need sales and compliance confirmation before commitment.
Card geography, KYC coverage, 3DS support, BIN behavior, and Japan acceptance
can change quickly.

## Japan Payment Risks

The important Japan-specific risks:

- stablecoin onboarding has too much first-run friction for ordinary users
- JPYC account opening, identity checks, address registration, bank funding, and
  minimum amounts make it a poor first-run requirement
- many Japanese ecommerce sites have fragile forms, katakana fields, domestic
  address assumptions, and occasional foreign-card issues
- 3DS, phone verification, name formatting, and delivery instructions can break
  checkout
- refunds and partial captures need careful reconciliation
- stablecoin custody, exchange, redemption, stored balances, or money movement
  likely require licensed partners or a clear regulated structure

Consumer onboarding should start with familiar JPY task budgets and card/Apple
Pay/PSP rails. Stablecoins and JPYC should become backend rails or power-user
funding options only where they reduce cost, settlement time, or refund friction.

## Working Payment Model

Start with a practical ladder:

1. Manual concierge purchase with signed task budget.
2. PSP-backed task budget with wallet authorization.
3. Single-use virtual cards for controlled merchant checkout.
4. Stablecoin-backed virtual cards through a partner.
5. Direct merchant partnerships or settlement where demand is proven.

The wallet mandate model should be the stable internal layer across all phases.
The payment rail can change without changing the user-consent primitive.

## Existing Artifacts

- `docs/voice-agent-gtm.md`: updated GTM plan for the Japan smart personal
  shopper, including the translation-versus-execution boundary and
  standards-led GTM rejection.

Related prior chat handoffs:

- `docs/chats/chat-2-voice-auth.md`: robotics and embedded owner-presence
  thread.
- `docs/chats/chat-3-rotate-k-org.md`: signing-root custody and threshold
  signing authority thread.

## Next Steps

1. Add a payment-specific plan or section for stablecoin-linked virtual cards.
   It should cover mandate lifecycle, card issuance lifecycle, refunds,
   clearing, disputes, expiry, and reconciliation.

2. Contact Rain and Immersve with a precise requirements checklist:
   single-use virtual cards, Japan/APAC coverage, 3DS support, real-time auth,
   merchant/MCC restrictions, stablecoin funding, user KYC model, refunds, and
   whether the wallet SDK can remain the approval layer.

3. Build a small provider-neutral `PaymentMandate` domain model before choosing
   a card provider. It should be rail-neutral and exact about amount, merchant,
   address, expiry, category, recurrence, refund rights, and step-up policy.

4. Test merchant reality with a concierge prototype:
   Amazon Japan, Rakuten, Yodobashi, Bic Camera, Nitori, IKEA Japan, and one
   municipal bulky-waste workflow.

5. Keep JPYC/stablecoins out of first-run consumer onboarding until a concrete
   user-visible advantage is proven.

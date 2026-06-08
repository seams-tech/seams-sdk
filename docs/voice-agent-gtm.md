# Smart Personal Shopper Japan GTM Plan

Date created: 2026-06-06
Status: proposed

## Goal

Launch an English-first smart personal shopper and life-admin purchasing agent
for Japan, backed by a passkey-controlled wallet and bounded spending mandates.

The product lets English-speaking users in Japan describe what they need,
approve a specific task budget, and let an agent find, ask, fill, buy, book, or
arrange local Japanese commerce tasks without giving the agent broad card or
account access.

Voice is an input mode. The core product is delegated execution with constrained
payment authority.

Positioning:

```text
Your English-speaking personal shopper for Japan.
Say what you need. Approve a budget.
The agent handles Japanese listings, forms, vendor questions, payment, delivery,
and follow-up within the limits you set.
```

Short pitch:

```text
Translation helps you understand. This gets the thing done.
```

## Core Thesis

Japan is a strong wedge because the pain is local, recurring, and hard to solve
with translation alone:

- product labels, checkout forms, delivery rules, and service bookings are
  Japanese-first
- address formatting and hotel delivery instructions are easy to get wrong
- many everyday categories require local context and merchant judgment
- tourists and new residents have urgent needs before they have local fluency
- commerce tasks often cross ecommerce, phone calls, delivery, and municipal
  workflows

Translation-only tools are enough when the user just needs to understand a
label, sign, phrase, or short conversation. They break down when the task
requires multiple steps, merchant judgment, form completion, payment, delivery,
or post-purchase handling.

The product boundary is execution. A task belongs in this product when it ends
in an action:

- compare Japanese listings and pick the right local substitute
- ask seller or staff follow-up questions
- fill Japanese checkout, booking, or municipal forms
- format a hotel or apartment delivery address correctly
- call, message, book, buy, return, cancel, or reschedule
- pay from a user-approved budget and produce an audit trail

Tasks that only require text comprehension should stay outside the core funnel.
The product should intentionally avoid becoming a generic translation app.

The wallet is the trust primitive. The agent receives bounded authority:

```text
This agent may spend up to JPY 7,500
for this category,
from these merchants,
to this address,
before this expiry,
with passkey step-up above the configured risk threshold.
```

## Target Customers

Primary initial users:

- English-speaking residents who recently moved to Japan
- long-stay travelers and business travelers
- tourists staying in hotels or serviced apartments
- foreign employees supported by HR or relocation firms
- expats handling recurring household, pet, and maintenance purchases

Primary buyers and distribution partners:

- hotels and serviced apartments
- relocation companies
- corporate HR and global mobility teams
- language schools and universities
- property managers and share houses
- expat communities and local concierge services

## Why Now

Relevant market signals:

- Japan had 42,683,600 inbound visitors in 2025, according to JNTO.
- Japan's foreign resident population reached about 4.125 million at the end of
  2025, according to Immigration Services Agency figures reported by Nippon.com.
- LLMs and browser agents are now good enough to complete multi-step commerce
  workflows with human review, especially when the merchant set and task
  categories are narrow.
- JPYC EX is live as an official yen stablecoin service. User onboarding still
  requires account opening, My Number/JPKI identity verification, wallet
  address registration, bank-transfer funding, and minimum issuance/redemption
  amounts. That makes JPYC a poor first-run requirement for this user segment.

The first product should sell task completion and controlled spending. JPYC can
become an optional settlement or refund rail after the core experience works.

## Product Shape

The user-facing app is an English-first mobile assistant with voice, chat, and a
visual approval surface. Voice should make intake fast. Chat should make review
and corrections precise. The final commitment should happen through a clear
quote and passkey approval screen.

Core surfaces:

- passkey wallet creation
- payment method or task-budget funding
- voice and chat request intake
- agent clarification
- quote comparison
- passkey approval
- task execution
- tracking, receipts, refunds, and remaining budget

The internal product boundary is a signed spending mandate. Agent card access
stays outside the authority model.

Example mandate:

```ts
type AgentPurchaseMandate = {
  mandateId: string;
  userWalletId: string;
  agentId: string;
  taskId: string;
  category: "pet_supplies" | "household" | "tools" | "furniture" | "service_booking";
  maxSpendJpy: number;
  allowedMerchants: readonly string[];
  deliveryAddressId: string;
  expiresAt: string;
  approvalMode: "single_purchase" | "auto_under_budget_with_step_up";
  forbiddenTerms: readonly string[];
};
```

## First User Flow

1. User opens app and creates a passkey wallet.
2. User adds a payment method or creates a small task budget, for example
   JPY 5,000 or JPY 10,000.
3. User says or types in English:

   ```text
   I need unscented cat litter delivered to my hotel tomorrow under JPY 3,000.
   ```

4. Agent asks only necessary clarifying questions.
5. Agent returns 2-3 purchase options with English explanations:
   price, shipping ETA, merchant, return risk, and substitution risk.
6. User approves the selected option with passkey.
7. Wallet signs the spending mandate and purchase intent.
8. Backend executes through an approved payment and merchant path.
9. User receives tracking, receipt, refund status, and remaining budget.

Repeat task flow:

```text
Buy this same cat food every two weeks, max JPY 4,000, cheapest reliable seller.
```

Repeat tasks require explicit recurrence terms, spend caps, expiry, and easy
revocation from the wallet.

Representative execution tasks:

```text
Find me the right pet litter, confirm it works with this automatic litter box,
buy two bags, and ship them to my apartment.
```

```text
Buy this shelf, confirm delivery includes stair carry-up, and schedule it for
Saturday afternoon.
```

```text
Book oversized garbage pickup for this item and pay the disposal fee.
```

```text
Find a replacement part for this appliance and ask the seller if it fits my
model number.
```

## MVP Categories

Start with categories that have high pain, low regulatory exposure, and
repeatable merchant paths.

Priority 1:

- pet food and litter
- household supplies
- tools, adapters, chargers, luggage, and daily essentials
- furniture and home setup items

Priority 2:

- bulky waste and garbage-removal booking
- appliance delivery and assembly coordination
- recurring replenishment orders

Priority 3:

- OTC medicine guided purchase from licensed retailers
- pet medicine or veterinary-related items only where retail rules are clear

Make medicine a later category. It is painful and valuable, and it introduces
regulatory, safety, and advice boundaries. The first version should treat
medicine as guided commerce through licensed sellers, with clear pharmacist
handoff and product-label translation. Medical advice stays out of scope.

## Payment And JPYC Strategy

Avoid JPYC or stablecoin onboarding during first-run.

Initial payment model:

- use card, Apple Pay, or a PSP-backed stored task budget
- keep all user-facing values in JPY
- use the wallet to authorize spend and store receipt rights
- keep merchant payment execution behind an approved PSP, virtual card, or
  merchant integration

Legal and payments rule:

- customer funds require a clear licensed structure before direct custody
- evaluate prepaid payment instrument, money transmission, escrow, and
  merchant-of-record implications before taking custody of funds
- use partners for regulated payment movement until the legal structure is
  settled

JPYC roadmap:

- v1: no consumer JPYC requirement
- v2: optional JPYC refunds, wallet-to-wallet credits, or partner settlement
- v3: JPYC power-user funding for users who already completed JPYC onboarding
- v4: merchant or marketplace settlement rail if a regulated partner flow
  supports it cleanly

JPYC is useful as infrastructure once the product has demand. Activation should
use the lowest-friction payment path available to the target segment.

## Standards-Led GTM Rejection

Do not build the Japan MVP around emerging agentic-commerce protocols.

Protocols from card networks, large platforms, or AI commerce consortia may
become useful later, and they may also be early attempts to control agentic
commerce distribution before merchant demand is proven. Their value to Japanese
merchants is unclear today. A merchant already accepts cards and already has an
online checkout. The near-term merchant problem is completed orders, lower fraud,
lower support cost, and fewer broken checkouts, not support for a new agent
protocol.

Revisit external agentic-payment protocols only when one of these conditions is
true:

- a target Japanese merchant or PSP already supports the protocol
- the protocol reduces checkout failure, fraud review, or customer-support load
- the protocol unlocks a merchant relationship that cannot be accessed through
  PSP, virtual card, affiliate, or direct partnership paths
- a card issuer or processor requires the protocol for real-time agent
  authorization

Until then, the wallet mandate model should stay provider-neutral and practical:
signed user intent, bounded spend, exact cart and delivery approval, virtual card
or PSP execution, and human fallback for fragile flows.

## Wallet SDK Role

The wallet SDK should provide:

- passkey wallet identity
- spending mandates
- exact task and merchant intent digests
- task-budget admission and finalization
- passkey step-up for risky purchases
- recovery through the existing wallet recovery model
- signed receipts and refund authorization
- audit logs for agent actions
- mandate enforcement for PSP-backed checkout, virtual card controls, manual
  review, and refund/cancellation authority

Relevant existing architecture fit:

- origin-isolated wallet runtime protects the user from app-origin compromise
- threshold signing supports higher-value delegated authority
- exact signing lanes map to user, agent, merchant, budget, and task identity
- wallet signing-session budgets map to task budgets and recurring mandates
- intent-digest binding maps to cart, price, merchant, delivery, and terms
- sealed restore supports real consumer sessions across refreshes and devices

## Domain Model Direction

Core domain types should make invalid authority states unrepresentable.

Suggested internal types:

```ts
type AgentWallet =
  | { kind: "unfunded"; walletId: string; userId: string }
  | { kind: "funded"; walletId: string; userId: string; activeBudgetId: string };

type TaskBudget =
  | { kind: "single_use"; budgetId: string; maxSpendJpy: number; expiresAt: string }
  | {
      kind: "recurring";
      budgetId: string;
      maxSpendJpy: number;
      period: "weekly" | "monthly";
      expiresAt: string;
    };

type PurchaseIntent =
  | { kind: "quote_requested"; taskId: string; normalizedRequest: string }
  | { kind: "quote_selected"; taskId: string; quoteId: string; cartDigest: string }
  | { kind: "approved"; taskId: string; mandateId: string; signedIntentDigest: string }
  | { kind: "executed"; taskId: string; orderId: string; receiptDigest: string };
```

Boundary rules:

- parse raw agent output once at the agent boundary
- normalize merchant quotes before wallet approval
- never let a free-form agent message become signing authority
- sign exact cart, merchant, amount, delivery address, and terms
- fail closed if final checkout differs from the approved digest

## Agent Safety Rules

The agent must never have open-ended authority.

Hard rules:

- no purchase without a signed mandate
- no address change after approval unless the user re-approves
- no subscription enrollment without explicit recurring mandate
- no medicine purchase flow without category-specific checks
- no age-restricted, controlled, illegal, or obviously unsafe items
- no substitution above configured tolerance without re-approval
- no merchant credential sharing with the model runtime
- no hidden service fees

Step-up triggers:

- final amount exceeds quote tolerance
- new merchant
- new address
- medicine or health-related item
- recurring purchase
- high return-risk item
- service booking with cancellation penalties
- any purchase above user-configured spend threshold

## Merchant Execution Strategy

Start with reliable execution paths and narrow merchant coverage.

Allowed execution methods:

- merchant APIs where available
- affiliate or partner checkout flows
- PSP virtual card purchase through controlled browser automation where terms
  permit it
- user-facing checkout handoff for merchants with fragile automation
- human-assisted operations during concierge MVP

Avoid early dependence on brittle scraping or passworded user-account access.
The first reliable product is narrower merchant coverage with high completion
rates.

Initial merchant targets:

- Amazon Japan
- Rakuten
- Yodobashi
- Bic Camera
- Nitori
- IKEA Japan
- Matsukiyo or other licensed pharmacy retailers for later medicine flows
- local municipal or ward services for bulky waste where workflows are stable

## GTM Plan

### Phase 0: Concierge Validation

Objective:

- prove that users pay for English-first Japan task completion where translation
  alone leaves the task unfinished

Todo:

- [ ] create a landing page with 5 action-oriented target tasks
- [ ] recruit 30-50 users from expat and traveler communities
- [ ] run tasks manually with AI assistance and human review
- [ ] capture task taxonomy, merchant paths, failure reasons, and price
      sensitivity
- [ ] measure willingness to prefund a small wallet budget
- [ ] classify failed leads as translation-only, execution-needed, payment-risk,
      merchant-fragile, or regulated-category

Exit criteria:

- 100 completed paid or high-intent tasks
- at least 40 percent of users request a second task
- human intervention reasons are well understood
- translation-only tasks are filtered out of the product funnel

### Phase 1: Wallet Mandate MVP

Objective:

- connect passkey wallet approval to bounded agent spend

Todo:

- [ ] add passkey wallet creation to the mobile app
- [ ] add task-budget creation through PSP-backed payment
- [ ] model single-use spending mandates
- [ ] sign cart, merchant, amount, delivery address, and task terms
- [ ] require passkey approval before execution
- [ ] store signed receipts and task logs
- [ ] add refund and cancellation flows
- [ ] define the canonical `PaymentMandate` shape used by PSP, virtual-card,
      manual-review, refund, and cancellation flows

Exit criteria:

- user can create wallet, fund budget, approve task, and receive receipt
- agent cannot execute when final checkout differs from approved mandate
- support can replay the signed audit trail for any task

### Phase 2: Category Depth

Objective:

- become clearly better than generic agents for specific Japan tasks

Todo:

- [ ] build pet supply replenishment flows
- [ ] build furniture sizing, delivery, and assembly checks
- [ ] build tool and adapter equivalence guides
- [ ] build hotel delivery address templates
- [ ] build bulky-waste booking playbooks for initial wards
- [ ] add recurring mandates for safe replenishment categories

Exit criteria:

- 80 percent or higher task completion in the top 3 categories
- median time from voice request to approved order under 5 minutes
- refund/cancellation rate is stable and explainable

### Phase 3: Partner Distribution

Objective:

- lower CAC through places where the pain appears naturally

Todo:

- [ ] pilot with one hotel or serviced apartment operator
- [ ] pilot with one relocation company
- [ ] pilot with one corporate HR/global mobility team
- [ ] add partner admin links for invited users
- [ ] add partner-specific address and delivery instructions
- [ ] add monthly partner reporting

Exit criteria:

- at least one partner drives repeat usage without paid acquisition
- task margin stays positive after support costs

### Phase 4: JPYC And Stablecoin Optionality

Objective:

- add stablecoin rails only where they improve the product

Todo:

- [ ] identify use cases where JPYC beats card or PSP settlement
- [ ] evaluate regulated partner requirements
- [ ] support JPYC wallet connect for users already onboarded
- [ ] test JPYC refunds or wallet credits with power users
- [ ] evaluate merchant settlement pilots

Exit criteria:

- JPYC flow reduces cost, settlement time, or refund friction for a real segment
- JPYC activation does not reduce first-task conversion

## Monetization

Potential revenue streams:

- per-task fee, for example JPY 300-1,000
- service fee for complex errands
- monthly resident subscription
- hotel or relocation partner fee
- affiliate or referral revenue where available
- B2B plan for HR and global mobility teams

Affiliate margin alone is weak. Task completion and trusted authorization are
the durable monetization wedge.

## Metrics

Acquisition:

- visitor to wallet-created conversion
- wallet-created to first-task conversion
- CAC by channel
- partner activation rate

Task quality:

- task completion rate
- quote selection rate
- median time to approved quote
- human intervention rate
- agent failure reason distribution
- cancellation and refund rate

Wallet and risk:

- average budget funded
- budget utilization
- step-up frequency
- approval abandonment
- mandate mismatch blocks
- chargeback or dispute rate

Retention:

- second-task rate
- monthly active task users
- recurring mandate adoption
- resident subscription conversion

Unit economics:

- gross margin per task
- support minutes per task
- payment processing cost
- refund loss
- partner revenue per active user

## Risks

Payments and regulation:

- prefunded budgets may trigger stored-value, escrow, or money-movement issues
- JPYC or stablecoin flows add regulated onboarding and risk disclosures
- merchant-of-record structure must be designed before scaling payments

Merchant execution:

- merchant automation can be brittle
- account-based checkout can violate terms or trigger fraud controls
- return and cancellation handling can consume support time
- translation-only tasks can pollute the funnel and make the product feel like a
  wrapper around existing tools

Product liability:

- OTC medicine and pet medicine need strict category rules
- the agent must avoid medical advice
- regulated, age-restricted, controlled, or unsafe products need hard blocks

Trust and safety:

- voice recognition errors can create wrong orders
- translation mistakes can create bad product matches
- address mistakes are expensive in hotels and apartment buildings
- users need visible control over agent spend and cancellation
- users need a visual approval surface before irreversible payment or booking
  actions

Unit economics:

- human fallback can make early tasks expensive
- low-AOV tasks may not support high support load
- partner channels may require custom workflows

## Open Questions

- Which segment is the first beachhead: tourists, new residents, hotels, or
  relocation companies?
- Which PSP and legal structure handles task budgets?
- Is the company merchant of record, agent of the user, or a checkout
  facilitator?
- Which 3 merchants produce the highest completion rate in MVP categories?
- Should the first app lead with chat and visual approval, voice intake, or an
  equal split?
- What support SLA is required for hotel delivery and urgent medicine-adjacent
  requests?
- What is the minimum signed receipt artifact merchants, users, and support
  need?
- Which payment execution path should be tested first: PSP checkout, single-use
  virtual card, manual concierge purchase, or direct merchant partnership?

## Source References

- JNTO 2025 visitor arrivals:
  https://www.jnto.go.jp/news/press/20260121_monthly.html
- Foreign residents in Japan, end of 2025:
  https://www.nippon.com/en/japan-data/h02750/
- JPYC EX service details:
  https://jpyc.co.jp/

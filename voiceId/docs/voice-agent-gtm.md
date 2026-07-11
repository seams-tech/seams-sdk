# Smart Personal Shopper Japan GTM Plan

Date created: 2026-06-06
Status: proposed

## Goal

Launch an English-first smart personal shopper and proxy-purchasing agent for
Japan, backed by a passkey-controlled wallet and bounded spending mandates.

The product lets English-speaking users in Japan describe what they need,
approve a specific task budget, and let an agent find, ask, fill, buy, book, or
arrange local Japanese commerce tasks without giving the agent broad card or
account access.

The same infrastructure can serve overseas customers who want Japanese goods.
For those customers, the company acts as a proxy shopper: quote the purchase,
collect payment from the customer, buy from the Japanese merchant, and arrange
domestic receiving, inspection, consolidation, and international forwarding.

Voice is an input mode. The core product is delegated execution with constrained
payment authority.

Voice creates and edits a draft. Browser voice supplies no biometric signing
authority. The user visually reviews the exact quote and spending mandate, then
approves the final commitment with passkey.

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
- overseas buyers often need Japanese-native search, seller questions, domestic
  receiving, inspection, consolidation, and forwarding before they can get the
  goods

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
- recruit a human shopper when the task needs in-store purchase, inspection, or
  local pickup
- receive, inspect, consolidate, and forward goods to an overseas customer

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
- overseas buyers who want Japanese goods from domestic-only merchants
- collectors, hobbyists, and niche buyers who need Japanese-native search and
  seller communication

Primary buyers and distribution partners:

- hotels and serviced apartments
- relocation companies
- corporate HR and global mobility teams
- language schools and universities
- property managers and share houses
- expat communities and local concierge services
- international forwarding warehouses
- proxy-shopping communities and niche marketplaces

## Why Now

Relevant market signals:

- Japan had 42,683,600 inbound visitors in 2025, according to JNTO.
- Japan's foreign resident population reached about 4.125 million at the end of
  2025, according to Immigration Services Agency figures reported by Nippon.com.
- Narrow LLM/browser-agent workflows are a concierge-validation hypothesis.
  Measure completion, correction, and human-intervention rates before claiming
  autonomous readiness.
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

The product has two modes:

1. Local Japan life-admin purchasing:
   user is in Japan, needs goods or services delivered locally, and wants the
   agent to handle Japanese-language ecommerce, forms, questions, and scheduling.
2. Overseas proxy shopping:
   user is outside Japan, pays the company for an approved order, and the
   company buys the item from Japanese merchants through agent or human-shopper
   execution.

Core surfaces:

- passkey wallet creation
- payment method or task-budget funding
- voice and chat request intake
- agent clarification
- quote comparison
- passkey approval
- task execution
- tracking, receipts, refunds, and remaining budget
- domestic receiving, inspection, consolidation, and international forwarding
  for proxy-shopping orders

The internal product boundary is a signed spending mandate. Agent card access
stays outside the authority model.

Example mandate:

```ts
type PurchaseCategory =
  | 'pet_supplies'
  | 'household'
  | 'tools'
  | 'furniture'
  | 'service_booking'
  | 'japanese_goods';

type MandateBase = {
  mandateId: string;
  userWalletId: string;
  agentId: string;
  taskId: string;
  category: PurchaseCategory;
  maxSpendJpy: number;
  allowedMerchants: readonly string[];
  expiresAt: string;
  approvalMode: 'single_purchase' | 'auto_under_budget_with_step_up';
  forbiddenTerms: readonly string[];
};

type LocalJapanPurchaseMandate = MandateBase & {
  purchaseMode: 'local_japan';
  deliveryAddressId: string;
  forwardingAddressId?: never;
  inspectionRequired: false;
};

type OverseasProxyPurchaseMandate = MandateBase & {
  purchaseMode: 'overseas_proxy';
  warehouseAddressId: string;
  forwardingAddressId: string;
  inspectionRequired: boolean;
  deliveryAddressId?: never;
};

type AgentPurchaseMandate = LocalJapanPurchaseMandate | OverseasProxyPurchaseMandate;
```

`auto_under_budget_with_step_up` operates only inside a mandate the user already
reviewed and signed with passkey. A spoken or typed change creates a new draft.
It cannot raise the cap, widen merchants/categories, change delivery scope, or
extend expiry without a new visual review and passkey signature.

## First User Flow

Local Japan flow:

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

Overseas proxy-shopping flow:

1. User outside Japan asks for a Japanese product, brand, replacement part,
   collectible, or marketplace item.
2. Agent searches Japanese merchants and asks seller questions when needed.
3. Agent returns a quote with item price, domestic shipping, service fee,
   inspection/consolidation fee, estimated international shipping, taxes, and
   refund limitations.
4. User approves the exact purchase terms with passkey.
5. User pays the company directly by card, Apple Pay, bank transfer, or a
   stablecoin route for supported users.
6. Company issues a one-order internal purchasing credential, such as a
   single-use virtual card, for the agent or operator.
7. Agent, operator, or recruited human shopper buys the item from the Japanese
   merchant.
8. Item is shipped to a warehouse, human shopper, or local receiving partner.
9. Company inspects, consolidates, photographs, and forwards the item overseas
   if the customer selected those services.
10. User receives purchase receipt, shipping proof, customs documents where
    needed, refund status, and support history.

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

```text
Find this discontinued Japanese keyboard part, ask the seller if it is unused,
buy it if the total is under JPY 12,000, inspect it, and forward it to me in
Singapore.
```

## MVP Categories

Start with categories that have high pain, low regulatory exposure, and
repeatable merchant paths.

Priority 1:

- pet food and litter
- household supplies
- tools, adapters, chargers, luggage, and daily essentials
- furniture and home setup items
- Japanese goods from domestic-only merchants
- replacement parts, hobby goods, niche electronics accessories, books, and
  collectibles where seller questions matter

Priority 2:

- bulky waste and garbage-removal booking
- appliance delivery and assembly coordination
- recurring replenishment orders
- warehouse inspection, photo proof, consolidation, and international forwarding
- human shopper pickup for stores or marketplaces with fragile online checkout

Priority 3:

- OTC medicine guided purchase from licensed retailers
- pet medicine or veterinary-related items only where retail rules are clear
- fragile, high-value, regulated, restricted, or customs-sensitive goods after
  prohibited-goods rules and insurance policies are mature

Make medicine a later category. It is painful and valuable, and it introduces
regulatory, safety, and advice boundaries. The first version should treat
medicine as guided commerce through licensed sellers, with clear pharmacist
handoff and product-label translation. Medical advice stays out of scope.

## Payment And JPYC Strategy

Avoid JPYC or stablecoin onboarding during first-run for mainstream users.

Initial payment model:

- user pays the company directly for an approved order or task
- use card, Apple Pay, bank transfer, or a PSP-backed task payment
- keep all user-facing values in JPY
- show item price, service fee, domestic shipping, international shipping
  estimate, FX/tax buffer, and refund rules before approval
- use the wallet to authorize the purchase terms and store receipt rights
- keep merchant payment execution behind company-controlled cards, virtual
  cards, PSP rails, human shopper operations, or direct merchant integrations

Legal and payments rule:

- customer funds require a clear legal structure before scale
- evaluate prepaid payment instrument, money transmission, escrow, and
  merchant-of-record implications before holding reusable balances
- for the proxy-shopping MVP, structure payments around specific quoted orders
  with no reusable stored balance
- use partners for regulated payment movement, stablecoin custody, conversion,
  and card issuing until the legal structure is settled

Proxy-shopping commercial model:

```text
customer pays the company for a specific approved order
  -> company buys from the Japanese merchant
  -> company receives, inspects, consolidates, or forwards the goods
  -> company handles customer support, refunds, and shipping claims
```

This model is operationally simpler than issuing customer-owned cards for the
first version. It makes the company the purchasing service in the customer's
eyes, while internal virtual cards constrain how agents and human operators
spend company funds.

Virtual-card role:

- use company-controlled virtual cards as internal purchasing credentials
- create one card per approved order or merchant checkout
- cap the card at the approved amount plus a small tolerance buffer
- restrict by merchant, merchant category, country, domain, or channel where the
  provider supports it
- expire the card quickly
- disable ATM, cash, and recurring payments
- cancel after success, failure, or expiry
- bind card metadata, merchant order id, receipt, and clearing/refund events
  back to the signed purchase mandate

Human shopper role:

- inspect items that require condition judgment
- buy from stores or marketplaces where online checkout is fragile
- pick up local goods
- ask seller or staff questions
- photograph goods before forwarding
- report substitutions, damage, or ambiguity before final shipment

The agent should never expose reusable payment credentials to a human shopper.
Human shoppers receive task instructions, budget boundaries, and a controlled
payment instrument for the specific job.

Cardholder model decision:

1. Company card model for MVP:
   customer pays the company for a specific order, and the company buys with
   company-controlled virtual cards or operator payment rails. This is the
   cleanest path for concierge validation, overseas proxy shopping, and human
   shopper fallback.
2. Customer card model later:
   customer owns a stablecoin-linked card or wallet-backed card, and the agent
   can spend from it only after wallet approval. This is technically elegant and
   much heavier operationally because it adds cardholder KYC, card support,
   chargeback handling, 3DS, issuer rules, and provider geography.

Stablecoin-linked cards fit best after the proxy-shopping loop works. They can
serve crypto-native overseas buyers, reduce treasury friction, or fund company
purchasing rails, while ordinary customers continue to see familiar order
payments and JPY-denominated quotes.

JPYC roadmap:

- v1: no consumer JPYC requirement
- v2: optional JPYC or stablecoin payment for crypto-native overseas buyers
- v3: JPYC power-user funding for users who already completed JPYC onboarding
- v4: stablecoin-backed virtual cards or merchant settlement if a regulated
  partner flow supports it cleanly

JPYC is useful as infrastructure once the product has demand. Activation should
use the lowest-friction payment path available to the target segment.

## Standards-Led GTM Rejection

Keep emerging agentic-commerce protocols outside the Japan MVP path.

Protocols from card networks, large platforms, or AI commerce consortia may
become useful later, and they may also be early attempts to control agentic
commerce distribution before merchant demand is proven. Their value to Japanese
merchants is unclear today. A merchant already accepts cards and already has an
online checkout. The near-term merchant problem is completed orders, lower fraud,
lower support cost, and fewer broken checkouts. A new agent protocol matters
only when it helps those outcomes.

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
- signed quote approval for proxy-shopping orders
- virtual-card policy binding for company-controlled purchasing credentials
- human-shopper task authorization with exact budget, merchant, pickup,
  inspection, and reimbursement constraints

Relevant existing architecture fit:

- origin-isolated wallet runtime reduces app-origin exposure
- threshold signing protects key custody for delegated authority; it cannot
  validate a bad mandate or authorization decision
- exact signing lanes map to user, agent, merchant, budget, and task identity
- wallet signing-session budgets map to task budgets and recurring mandates
- intent-digest binding maps to cart, price, merchant, delivery, and terms
- sealed restore supports real consumer sessions across refreshes and devices

## Domain Model Direction

Core domain types should make invalid authority states unrepresentable.

Suggested internal types:

```ts
type AgentWallet =
  | { kind: 'unfunded'; walletId: string; userId: string }
  | { kind: 'funded'; walletId: string; userId: string; activeBudgetId: string };

type TaskBudget =
  | { kind: 'single_use'; budgetId: string; maxSpendJpy: number; expiresAt: string }
  | {
      kind: 'recurring';
      budgetId: string;
      maxSpendJpy: number;
      period: 'weekly' | 'monthly';
      expiresAt: string;
    };

type PurchaseIntent =
  | { kind: 'quote_requested'; taskId: string; normalizedRequest: string }
  | { kind: 'quote_selected'; taskId: string; quoteId: string; cartDigest: string }
  | { kind: 'approved'; taskId: string; mandateId: string; signedIntentDigest: string }
  | { kind: 'purchased'; taskId: string; orderId: string; receiptDigest: string }
  | { kind: 'received'; taskId: string; warehouseReceiptId: string; inspectionDigest: string }
  | { kind: 'forwarded'; taskId: string; shipmentId: string; customsDigest: string };

type PurchasingCredential =
  | {
      kind: 'company_virtual_card';
      cardPolicyId: string;
      mandateId: string;
      maxSpendJpy: number;
      expiresAt: string;
    }
  | {
      kind: 'human_shopper_task';
      operatorTaskId: string;
      mandateId: string;
      maxSpendJpy: number;
      requiredEvidence: readonly ('receipt' | 'item_photo' | 'pickup_photo')[];
      expiresAt: string;
    };
```

Boundary rules:

- parse raw agent output once at the agent boundary
- normalize merchant quotes before wallet approval
- never let a free-form agent message become signing authority
- sign exact cart, merchant, amount, delivery address, and terms
- sign proxy-shopping quote terms before collecting customer payment
- bind every virtual card, human-shopper task, warehouse receipt, and shipment
  back to the mandate
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
- no human shopper receives reusable credentials
- no forwarding shipment without customer-approved destination, declared value,
  and prohibited-goods check
- no inspection substitution or condition downgrade without re-approval

Step-up triggers:

- final amount exceeds quote tolerance
- new merchant
- new address
- medicine or health-related item
- recurring purchase
- high return-risk item
- service booking with cancellation penalties
- any purchase above user-configured spend threshold
- human shopper assignment
- warehouse inspection mismatch
- international forwarding change

## Merchant Execution Strategy

Start with reliable execution paths and narrow merchant coverage.

Allowed execution methods:

- merchant APIs where available
- affiliate or partner checkout flows
- company-controlled virtual card purchase through controlled checkout where
  terms permit it
- user-facing checkout handoff for merchants with fragile automation
- human-assisted operations during concierge MVP
- recruited human shopper for in-store purchase, pickup, seller questions, or
  condition inspection
- warehouse receiving, inspection, consolidation, and international forwarding
  for overseas proxy-shopping orders

Avoid early dependence on brittle scraping or passworded user-account access.
The first reliable product is narrower merchant coverage with high completion
rates.

Human shopper execution rules:

- assign each operator one signed task
- disclose item, merchant, budget, pickup location, required evidence, and
  deadline
- fund the task with a single-use virtual card, controlled reimbursement flow,
  or prepaid operator allowance tied to that task
- require receipt and item photos before closeout
- block substitutions, used-condition changes, higher prices, and address
  changes until the customer re-approves
- keep operator identity, evidence, and payout records attached to the task

Overseas forwarding rules:

- receive goods at a known warehouse, partner, or operator location
- photograph and inspect goods before international shipment when the customer
  pays for inspection
- require prohibited-goods and customs checks before forwarding
- bind shipping label, declared value, insurance choice, and tracking number to
  the purchase mandate
- separate domestic purchase completion from international forwarding
  completion so support can reason about each failure point

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

- prove that users pay for English-first Japan task completion and proxy
  shopping where translation alone leaves the task unfinished

Todo:

- [ ] create a landing page with 5 action-oriented target tasks
- [ ] recruit 30-50 users from expat and traveler communities
- [ ] recruit 20-30 overseas buyers from proxy-shopping, collector, hobbyist,
      and expat communities
- [ ] run tasks manually with AI assistance and human review
- [ ] capture task taxonomy, merchant paths, failure reasons, and price
      sensitivity
- [ ] measure willingness to pay a quoted order total plus service fee
- [ ] classify failed leads as translation-only, execution-needed, payment-risk,
      merchant-fragile, or regulated-category
- [ ] test receiving, photo inspection, consolidation, and one international
      forwarding flow manually

Exit criteria:

- 100 completed paid or high-intent tasks
- at least 40 percent of users request a second task
- human intervention reasons are well understood
- translation-only tasks are filtered out of the product funnel
- at least 20 completed overseas proxy-shopping orders
- refund, customs, and forwarding failure modes are understood

### Phase 1: Wallet Mandate MVP

Objective:

- connect passkey wallet approval to quoted order payment and bounded company
  purchasing spend

Todo:

- [ ] add passkey wallet creation to the mobile app
- [ ] add quoted-order payment through PSP-backed checkout
- [ ] model single-use purchase mandates
- [ ] sign cart, merchant, amount, delivery address, forwarding address, service
      fees, refund terms, and task terms
- [ ] require passkey approval before execution
- [ ] store signed receipts and task logs
- [ ] add refund and cancellation flows
- [ ] define the canonical `PaymentMandate` shape used by PSP, virtual-card,
      manual-review, refund, and cancellation flows
- [ ] create one company-controlled virtual card per approved order where the
      provider supports it
- [ ] add human-shopper task assignment, evidence upload, and closeout

Exit criteria:

- user can create wallet, approve quote, pay, and receive receipt
- agent or human shopper cannot execute when final checkout differs from the
  approved mandate
- support can replay the signed audit trail for any task
- virtual card metadata, merchant order id, receipt, warehouse receipt, and
  shipment tracking reconcile to the same mandate

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
- [ ] build Japanese goods proxy-shopping playbooks for domestic-only merchants
- [ ] build warehouse inspection and consolidation templates
- [ ] build human shopper playbooks for pickup, seller questions, and condition
      checks

Exit criteria:

- 80 percent or higher task completion in the top 3 categories
- median time from voice/text intake to passkey-approved order under 5 minutes
- refund/cancellation rate is stable and explainable
- proxy-shopping order margin stays positive after human and forwarding costs

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
- [ ] pilot with one warehouse or forwarding partner
- [ ] pilot with one proxy-shopping community, collector group, or niche
      marketplace

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
- [ ] evaluate stablecoin-linked virtual cards for company purchasing rails or
      crypto-native overseas buyers

Exit criteria:

- JPYC flow reduces cost, settlement time, or refund friction for a real segment
- JPYC activation does not reduce first-task conversion
- stablecoin-linked card flow improves purchasing coverage or treasury
  operations without hurting first-order conversion

## Monetization

Potential revenue streams:

- per-task fee, for example JPY 300-1,000
- service fee for complex errands
- monthly resident subscription
- hotel or relocation partner fee
- affiliate or referral revenue where available
- B2B plan for HR and global mobility teams
- proxy-shopping service fee
- percentage markup on sourced goods where acceptable
- inspection, photo proof, consolidation, storage, and forwarding fees
- urgent pickup or human shopper surcharge

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
- human shopper assignment rate
- agent failure reason distribution
- cancellation and refund rate
- receiving, inspection, and forwarding completion rate

Wallet and risk:

- average budget funded
- budget utilization
- step-up frequency
- approval abandonment
- mandate mismatch blocks
- virtual card decline rate
- virtual card overage blocks
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
- virtual card issuing and FX cost
- human shopper cost per task
- warehouse, inspection, consolidation, and forwarding cost
- refund loss
- customs, shipping claim, and lost-package loss
- partner revenue per active user

## Risks

Payments and regulation:

- prefunded budgets may trigger stored-value, escrow, or money-movement issues
- JPYC or stablecoin flows add regulated onboarding and risk disclosures
- merchant-of-record structure must be designed before scaling payments
- proxy-shopping terms must clearly define who is seller of record, who owns
  goods during purchase/forwarding, and how refunds, cancellations, customs, and
  shipping claims work
- company-controlled virtual cards need issuer rules, cardholder controls,
  disputes, 3DS, and operator access policies

Merchant execution:

- merchant automation can be brittle
- account-based checkout can violate terms or trigger fraud controls
- return and cancellation handling can consume support time
- translation-only tasks can pollute the funnel and make the product feel like a
  wrapper around existing tools
- Japanese merchants may cancel orders when card BIN, address, phone number, or
  account profile looks mismatched
- marketplace sellers may misrepresent condition, ship late, or refuse returns
- human shoppers can create quality, fraud, labor, and reimbursement risk
- international forwarding adds customs, prohibited-goods, insurance, and lost
  package risk

Product liability:

- OTC medicine and pet medicine need strict category rules
- the agent must avoid medical advice
- regulated, age-restricted, controlled, or unsafe products need hard blocks
- import/export restricted goods, lithium batteries, food, cosmetics, medicine,
  alcohol, blades, and high-value goods need category-specific blocks or review

Trust and safety:

- voice recognition output remains a draft until visual confirmation and
  passkey approval; recognition errors can still create misleading drafts
- translation mistakes can create bad product matches
- address mistakes are expensive in hotels and apartment buildings
- users need visible control over agent spend and cancellation
- users need a visual approval surface before irreversible payment or booking
  actions
- overseas users need clear photos, condition reports, quote history, and
  approval receipts before goods are forwarded

Unit economics:

- human fallback can make early tasks expensive
- low-AOV tasks may not support high support load
- partner channels may require custom workflows
- international shipping and customs surprises can consume margin
- proxy-shopping orders can tie up working capital while refunds or claims are
  pending

## Open Questions

- Which segment is the first beachhead: tourists, new residents, hotels, or
  overseas proxy-shopping buyers?
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
- Which warehouse, forwarding, or human-shopper partner can support the first
  proxy-shopping orders?
- What prohibited-goods, customs, inspection, and insurance policy is required
  before overseas forwarding?
- Which virtual-card provider supports single-order cards, merchant controls,
  3DS, Japan acceptance, refunds, and stablecoin-funded treasury?

## Source References

- JNTO 2025 visitor arrivals:
  https://www.jnto.go.jp/news/press/20260121_monthly.html
- Foreign residents in Japan, end of 2025:
  https://www.nippon.com/en/japan-data/h02750/
- JPYC EX service details:
  https://jpyc.co.jp/

# Seams wallet vision

Date created: August 26, 2026

Status: draft product vision; use as customer and product-scope guidance.

Related docs:

- [Policy harness for agentic commerce](product-vision.md)
- [Stablecoin-linked virtual card](stablecoin-linked-virtual-card.md)
- [Embedded wallet card checkout](embedded-wallet-card-checkout.md)

## Vision

Seams gives platforms, wallet applications, and shopping agents secure wallets
that can hold value, authorize transactions, and enforce precise spending
rules.

The primary customer is an application that needs a persistent wallet for each
user or agent. The wallet becomes part of the application's account model and
supports repeated financial or onchain activity.

```text
Application account
  -> embedded wallet
  -> balance or owned assets
  -> authentication and recovery
  -> user or agent authorization
  -> payments, trading, transfers, or purchases
  -> durable activity and audit evidence
```

Seams serves three principal use cases:

1. Platform wallets provisioned for a platform's users.
2. Shopping wallet applications used across independent merchants.
3. Shopping-agent wallets with delegated authority to purchase from unrelated
   ecommerce stores.

## Use case 1: Platform wallets

Platforms use Seams to make a wallet part of every user account. Users can
receive, hold, transfer, trade, or spend assets without installing a separate
wallet or managing a seed phrase.

The platform needs more than wallet creation. It needs the complete wallet
lifecycle:

- account-linked wallet provisioning
- passkey or application-native authentication
- safe recovery and device linking
- transaction signing and policy enforcement
- sponsored or automated onchain execution
- delegated authority with budgets and expiry
- durable transaction history and audit evidence
- wallet export or transfer of control where supported

### Strong platform categories

- Ecommerce marketplaces with buyers, sellers, balances, escrow, and payouts.
- Trading and investment platforms.
- Games and digital-asset platforms.
- Creator and gig-economy platforms.
- Stablecoin account and remittance applications.
- Loyalty, rewards, and store-credit networks.
- Agentic commerce and automated purchasing platforms.
- Applications that sponsor or automate onchain operations.

### Why these platforms need wallets

These products maintain an ongoing financial relationship with their users. A
balance, asset, payout, position, reward, or delegated budget persists after a
single session. An embedded wallet gives that state a secure execution and
ownership boundary.

Examples include:

- A marketplace provisions wallets for buyers and sellers, holds escrowed value,
  pays sellers, and records refunds.
- A trading platform provisions wallets that hold assets and authorize trades or
  withdrawals.
- A game provisions wallets for digital items, rewards, and marketplace trades.
- A gig platform pays earnings into worker wallets and supports transfers or
  optional external spending.
- A remittance application provisions stablecoin accounts for repeated receipt,
  conversion, and transfer.

### Platform qualification

A platform is a strong fit when most of these conditions are true:

- Users have persistent accounts.
- Users hold value or assets between sessions.
- Users perform repeated financial or onchain actions.
- The application needs recovery without seed phrases.
- The application sponsors, automates, or constrains transactions.
- Users or agents need scoped authority instead of unrestricted signing access.
- The platform needs an auditable link from authorization to execution.

## Use case 2: Shopping wallet applications

A shopping wallet is a user-facing application, such as an iOS wallet, that
holds stablecoins or other supported assets and helps its owner pay across many
independent merchants.

The wallet may support two payment rails:

```text
Merchant supports wallet payment
  -> pay the merchant directly with stablecoin

Merchant accepts cards only
  -> pay through an optional stablecoin-linked virtual card
```

The virtual card extends merchant reach. It converts a bounded wallet reserve
into a credential that existing ecommerce checkouts understand. The customer
can spend at stores that have no Seams integration and require no knowledge of
stablecoins.

Useful shopping-wallet capabilities include:

- a clear available balance across wallet and card reserves
- direct stablecoin payments where merchants support them
- optional virtual-card issuance for card-only merchants
- card freeze, limits, closure, and transaction history
- transparent authorization, capture, reversal, and refund states
- explicit fees, exchange rates, and reserve-release timing
- secure card display through provider-hosted components

A virtual card is an outbound spending rail. It is most useful in a wallet that
serves its owner across many merchants. It adds little value when a store
provisions a card solely so the customer can pay that same store.

## Use case 3: Shopping-agent wallets

A shopping agent needs authority to purchase from ecommerce stores that have no
agent or wallet integration. Seams gives the agent a wallet or spending
credential governed by a signed mandate.

```text
User funds wallet
  -> user defines purchase mandate
  -> Seams binds budget, merchant, item, time, and approval rules
  -> agent finds an eligible offer
  -> policy verifies the final cart
  -> wallet or virtual card executes payment
  -> Seams records the decision, payment, receipt, and refund trail
```

The agent receives the narrow authority needed for a purchase. It does not
receive unrestricted control of the user's wallet.

Useful controls include:

- per-order and cumulative budgets
- merchant, category, and geography allowlists
- exact product and quantity constraints
- shipping, tax, fee, and total-price ceilings
- substitution and recurring-payment rules
- mandate expiry and revocation
- human approval for defined exceptions
- per-agent, per-order, or shared cards where justified
- receipt, cancellation, refund, and support evidence

Virtual cards are especially useful here because most ecommerce stores already
accept cards and have no protocol for agent mandates or stablecoin payment. The
card supplies compatibility; Seams supplies the authorization boundary.

## Shared product foundation

The three use cases share one foundation:

| Capability | Product responsibility |
| --- | --- |
| Wallet lifecycle | Provision, authenticate, recover, link devices, and export. |
| Custody | Protect wallet authority without exposing seed phrases to applications or agents. |
| Signing | Execute supported onchain transactions through precise signing states. |
| Policy | Constrain users, sessions, applications, and agents by intent, budget, time, and risk. |
| Delegation | Grant narrow, expiring, and revocable authority. |
| Payments | Support direct stablecoin transfers and optional external payment rails. |
| Audit | Preserve evidence from authorization through execution and reconciliation. |

The embedded wallet SDK is the platform integration surface. Consumer shopping
wallets and shopping agents use the same custody, signing, policy, and audit
primitives through different product experiences.

## Product boundaries

### Ordinary ecommerce checkout

A conventional ecommerce store that only wants to receive payment is a weak fit
for per-shopper wallet provisioning. A customer who already holds stablecoins
can connect an existing wallet and pay the store directly.

That merchant may still need payment-intent creation, supported asset
validation, chain confirmation, order reconciliation, refunds, and accounting.
Those are checkout capabilities rather than reasons to create a persistent
wallet for every shopper.

An ecommerce business becomes a stronger fit when it operates as a marketplace,
maintains customer balances, pays sellers, issues rewards, manages escrow, or
supports repeated user-controlled transactions.

### Virtual cards

Virtual cards are an optional outbound-spending capability for users and agents
who need to purchase from unrelated card-accepting merchants. They are not the
default payment path for a merchant already able to accept a direct wallet
payment.

Card issuance introduces provider enablement, cardholder onboarding, fraud,
chargebacks, working capital, reconciliation, customer support, and regulatory
responsibilities. Seams should offer it only to qualified wallet applications
and balance-holding platforms with a demonstrated external-spending need.

## Product positioning

Primary positioning:

```text
Embed secure, recoverable wallets into every user account.
```

Expanded positioning:

```text
Seams lets platforms provision policy-controlled wallets for users and agents,
then safely authorize payments, trading, transfers, and purchases.
```

Shopping-wallet positioning:

```text
Hold stablecoins once. Pay directly where supported and use an optional virtual
card everywhere else.
```

Shopping-agent positioning:

```text
Give shopping agents a precise budget and purchase mandate without giving them
unrestricted control of the wallet.
```

## Product priority

1. Make platform wallet provisioning, authentication, recovery, signing, and
   policy enforcement reliable.
2. Prove repeated platform use cases involving balances, assets, payouts, or
   automated execution.
3. Build shopping-agent mandates and constrained payment execution on the shared
   wallet foundation.
4. Add stablecoin-linked virtual cards for qualified products that need external
   merchant reach.

This order keeps the wallet lifecycle as the reusable core and treats payment
rails as use-case-specific execution options.

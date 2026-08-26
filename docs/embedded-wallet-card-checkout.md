# Embedded Wallet Card Checkout Plan

Date created: August 22, 2026

Status: deferred reference design; outside the active wallet-product roadmap.

Related docs:

- [Seams wallet vision](vision.md)
- [Product vision](product-vision.md)
- [Stablecoin-linked virtual card](stablecoin-linked-virtual-card.md)

## Purpose

This document records a possible card-on-file checkout product for participating
merchants:

```text
A customer adds a credit, debit, or externally issued virtual card once, then
uses the Seams wallet for fast checkout at participating ecommerce sites.
```

The proposed experience resembles Stripe Link:

```text
Pay with Seams
Visa •••• 4242
JPY 12,800
[Confirm with passkey]
```

Seams provides the portable customer wallet, checkout approval, payment-method
selection, merchant binding, and audit record. A payment service provider (PSP)
provides hosted card collection, tokenization, card-network access, 3DS, payment
processing, refunds, disputes, and settlement.

Virtual-card issuance is outside the first operating path. A virtual card issued
by another company can be saved to Seams in the same way as any other supported
card.

## Product decision

Defer tokenized, card-on-file checkout. It does not serve the primary customer
profile defined in the [wallet vision](vision.md).

A conventional store that only needs to collect payment is a weak fit for
per-shopper wallet provisioning. A shopper with an existing wallet can pay the
store directly when the store accepts stablecoin. Platforms become strong fits
when users retain balances, assets, payouts, rewards, or repeated transaction
authority inside the product.

Revisit this design only after demand exists for one portable checkout identity
across multiple participating merchants and a provider supports the required
cross-merchant credential model.

The deferred design is:

```text
Participating merchant embeds Seams
  -> customer opens or creates a Seams wallet
  -> customer adds a card through PSP-hosted fields
  -> PSP returns a payment-method reference
  -> Seams associates that reference with the wallet
  -> merchant creates an exact checkout intent
  -> customer approves the intent once
  -> merchant's PSP account charges the saved card
  -> Seams records the result
```

The merchant remains the merchant of record for the sale. The merchant owns its
product, order, tax, fulfilment, refund, and customer-support obligations. Seams
provides checkout software and authorization evidence without taking custody of
the merchant's sale proceeds.

Under this deferred design, participating merchants use connected accounts
under one PSP platform. This gives Seams one supported way to save a card once
and use a provider-approved merchant-scoped credential at multiple
participating merchants.

## User Value

For customers:

- add an existing card once
- reuse it across participating merchants
- see the merchant, order, amount, and card before approval
- confirm with the same passkey or biometric flow used by the Seams wallet
- keep card details inside the PSP's secure collection and vault surfaces
- inspect payment and refund history in one wallet

For merchants:

- add a `Pay with Seams` checkout option through the wallet SDK
- reduce repeated card entry and account creation
- receive payment into the merchant's own connected PSP account
- retain their merchant-of-record role
- receive a stable checkout result tied to the merchant order
- obtain evidence of the exact intent approved by the customer

For Seams:

- test whether a portable wallet identity improves multi-merchant checkout
- connect the existing wallet authorization system to card checkout
- establish a shared checkout identity across merchants
- create a direct path from signed commerce intent to payment evidence
- preserve a future path to agents and delegated spending

## Contingent scope

### If reactivated

- one PSP platform
- connected merchant accounts
- one-time card payments
- user-present checkout
- credit, debit, and externally issued virtual cards accepted by the PSP
- PSP-hosted card collection and tokenization
- save, list, select, and remove payment methods
- exact merchant, order, amount, and currency confirmation
- one passkey or biometric confirmation gesture
- Seams wallet signature over the checkout intent
- 3DS and other PSP-required cardholder action
- payment success, failure, cancellation, and expiry
- webhook verification and idempotent reconciliation
- merchant-initiated full and partial refunds
- customer payment and refund history

### Deferred

- Seams-issued stablecoin-linked virtual cards
- autonomous agent checkout without a present customer
- recurring subscriptions
- merchant-initiated off-session charges
- instalments and buy-now-pay-later methods
- bank-account and local alternative payment methods
- portable card credentials across unrelated PSPs
- payment-provider routing and cost optimization
- network token provisioning to Apple Pay or Google Pay
- Seams acting as merchant of record
- card-present payments
- chargeback operations beyond ingesting and displaying provider state

## Core Checkout Flow

### Add A Card

```text
1. Customer opens the Seams wallet on a participating merchant site.
2. Seams creates a single-use card setup session with the PSP.
3. The PSP's hosted component collects card and billing details.
4. The PSP performs setup-time cardholder authentication when required.
5. The PSP returns a reusable payment-method reference.
6. Seams validates the provider response at the boundary.
7. Seams stores the reference with safe display data: brand, last four, expiry.
8. The customer can select the card for checkout.
```

Seams application code must never receive, persist, log, or proxy PAN or CVV.

### Returning Customer Checkout

```text
1. Merchant backend creates an order with final amount and currency.
2. Merchant backend sends the order to the Seams checkout-intent API.
3. Seams validates the merchant and creates an expiring checkout intent.
4. Embedded wallet displays merchant, amount, currency, order, and selected card.
5. Customer confirms once with the wallet's passkey or biometric flow.
6. Seams binds the wallet signature to the canonical checkout-intent digest.
7. Seams consumes the single-use authorization and submits the PSP payment.
8. The PSP completes immediately or requests cardholder action such as 3DS.
9. The PSP webhook determines the durable payment result.
10. Seams returns the result to the merchant and adds it to wallet history.
```

### New Customer Checkout

The first checkout combines wallet access and card setup:

```text
open Seams wallet
  -> register or sign in
  -> add card through hosted fields
  -> review exact checkout
  -> confirm once
  -> complete provider challenge if required
  -> receive result
```

Registration, card setup, and checkout remain separate lifecycle states even
when the UI presents them as one short flow.

### Refund

```text
1. Merchant requests a full or partial refund against its order.
2. Seams validates merchant ownership and refundable amount.
3. PSP creates the refund against the original payment.
4. PSP webhook confirms pending, succeeded, or failed state.
5. Seams updates merchant order evidence and customer wallet history.
```

## Merchant Integration Contract

The browser must never define the payable amount. A merchant backend creates the
checkout intent using authenticated server credentials.

Minimum merchant input:

```ts
type CreateCardCheckoutIntentRequest = {
  kind: "create_card_checkout_intent_request_v1";
  merchantId: MerchantId;
  orderId: MerchantOrderId;
  amount: FiatAmount;
  cartDigest: CartDigest;
  returnUrl: string;
  expiresAtMs: number;
  idempotencyKey: CheckoutIdempotencyKey;
};
```

The merchant receives a Seams checkout intent identifier and an SDK client
token scoped to that intent. The token cannot create a different amount, change
the merchant, select another order, or initiate a second payment.

The embedded SDK should expose one primary operation:

```ts
const result = await seams.checkout({ checkoutIntentId, clientToken });
```

The result is a discriminated union:

```ts
type EmbeddedCheckoutResult =
  | { kind: "succeeded"; checkoutIntentId: CheckoutIntentId; paymentId: PaymentId }
  | { kind: "cancelled"; checkoutIntentId: CheckoutIntentId }
  | { kind: "expired"; checkoutIntentId: CheckoutIntentId }
  | { kind: "failed"; checkoutIntentId: CheckoutIntentId; reason: CheckoutFailure };
```

The merchant treats the result as immediate UI state. Its backend treats a
verified Seams webhook or status query as the durable payment result.

## Checkout Intent

Card checkout needs a fiat-specific intent. The existing
`SpecificPurchasePaymentIntent` is shaped around chain assets and destinations,
so it should remain unchanged for its current protocols.

```ts
type CardCheckoutIntentV1 = {
  kind: "card_checkout_intent_v1";
  checkoutIntentId: CheckoutIntentId;
  walletId: WalletId;
  merchant: CheckoutMerchant;
  orderId: MerchantOrderId;
  amount: FiatAmount;
  paymentCredentialId: PaymentCredentialId;
  cartDigest: CartDigest;
  expiresAtMs: number;
  nonce: CheckoutNonce;
};

type FiatAmount = {
  kind: "fiat_amount_v1";
  amountMinor: FiatAmountMinor;
  currency: IsoCurrencyCode;
};

type CheckoutMerchant = {
  kind: "checkout_merchant_v1";
  merchantId: MerchantId;
  displayName: string;
  checkoutOrigin: CheckoutOrigin;
  providerAccountId: ProviderMerchantAccountId;
};
```

Raw merchant requests, provider objects, URLs, currency codes, amounts, and IDs
must be parsed once at request or provider boundaries. Core checkout functions
accept only validated domain objects.

The canonical intent digest must change when any security-relevant field
changes. The confirmation UI must render values from the canonical intent that
is actually signed and executed.

## Payment Credential Model

The Seams wallet stores a reference to a PSP-vaulted credential. The card number
and CVV remain outside Seams.

```ts
type WalletPaymentCredential =
  | {
      kind: "ready_card_credential";
      credentialId: PaymentCredentialId;
      walletId: WalletId;
      provider: CheckoutProvider;
      providerCustomerId: ProviderCustomerId;
      providerPaymentMethodId: ProviderPaymentMethodId;
      display: CardDisplayData;
    }
  | {
      kind: "disabled_card_credential";
      credentialId: PaymentCredentialId;
      walletId: WalletId;
      provider: CheckoutProvider;
      display: CardDisplayData;
      reason: DisabledCredentialReason;
    };

type CardDisplayData = {
  kind: "card_display_data_v1";
  brand: CardBrand;
  lastFour: CardLastFour;
  expiryMonth: CardExpiryMonth;
  expiryYear: CardExpiryYear;
};
```

Only `ready_card_credential` may enter checkout authorization. Removal disables
the Seams reference and detaches or retires the provider credential according to
provider rules.

The provider credential's reuse scope must be explicit:

- stored on the platform customer
- copied or attached to one connected merchant for a single charge
- attached to a connected merchant customer for a future supported recurring
  use case

The first version uses only the first two scopes.

## Checkout Lifecycle

Model lifecycle as explicit states with required evidence:

```ts
type CardCheckoutState =
  | { kind: "awaiting_customer"; intent: CardCheckoutIntentV1 }
  | {
      kind: "authorized";
      intent: CardCheckoutIntentV1;
      authorization: CheckoutAuthorizationProof;
    }
  | {
      kind: "payment_submitted";
      intent: CardCheckoutIntentV1;
      authorization: CheckoutAuthorizationProof;
      providerPaymentId: ProviderPaymentId;
    }
  | {
      kind: "requires_cardholder_action";
      intent: CardCheckoutIntentV1;
      authorization: CheckoutAuthorizationProof;
      providerPaymentId: ProviderPaymentId;
      action: CardholderAction;
    }
  | {
      kind: "succeeded";
      intent: CardCheckoutIntentV1;
      payment: SettledCardPayment;
    }
  | {
      kind: "failed";
      intent: CardCheckoutIntentV1;
      failure: CheckoutFailure;
    }
  | { kind: "cancelled"; intent: CardCheckoutIntentV1; cancelledAtMs: number }
  | { kind: "expired"; intent: CardCheckoutIntentV1; expiredAtMs: number };
```

Every transition is idempotent. Terminal states cannot return to an executable
state. A retry creates a new provider attempt under the same checkout intent
only when the previous attempt is durably safe to replace.

## Role Of Passkeys And MPC

The customer should experience one confirmation gesture.

```text
passkey or local biometric confirmation
  -> unlock wallet authorization
  -> sign the canonical checkout-intent digest
  -> verify and consume the authorization
  -> submit the tokenized card payment
```

The signed proof provides:

- evidence of the exact merchant, order, amount, currency, and card reference
  approved by the wallet
- protection against browser code silently changing the approved intent
- one authorization model that can later support shopping-agent mandates
- an audit link between wallet approval and PSP payment

The card network does not verify the Seams wallet signature. The PSP and issuer
still perform payment authorization, fraud checks, and 3DS. Seams must enforce
the wallet authorization as a required gate before its payment execution path
submits a charge.

MPC must add no second prompt and no additional customer-visible ceremony. If
the signing path cannot meet checkout latency and availability requirements,
the team should measure and repair that operating path before claiming a
one-click checkout experience.

## PSP And Merchant Account Model

The first provider must support:

- platform and connected merchant accounts
- merchants as merchant of record
- platform-level customer and card setup
- provider-approved reuse of saved cards across connected merchant accounts
- hosted card collection
- setup-time and payment-time 3DS
- JPY and the first target merchant jurisdictions
- one-time payments
- full and partial refunds
- signed, replay-safe webhooks
- sandbox setup, payment, challenge, failure, and refund simulations
- clear responsibility for negative balances, disputes, and chargebacks

Stripe Connect documents one reference model: save payment details on the
platform, then clone supported payment methods to connected accounts for direct
charges. The eventual provider choice should be based on commercial and
jurisdictional diligence rather than the reference implementation alone.

Do not build multi-PSP routing for the MVP. Define one narrow payment-execution
port because the PSP is an external boundary, implement one real provider, and
use one fake provider for deterministic tests.

## Trust And Security Boundaries

### Merchant Boundary

- authenticate every merchant backend request
- bind merchant credentials to one `merchantId` and provider account
- accept amount and order creation only from the merchant backend
- validate return URLs against registered merchant origins
- issue browser client tokens scoped to one checkout intent
- display the registered merchant identity in confirmation UI

### Wallet Boundary

- run wallet confirmation on a Seams-controlled origin
- validate the embedding origin and registered merchant relationship
- bind passkey and wallet authorization to the canonical intent digest
- consume each authorization once
- reject expired, cancelled, changed, or already-paid intents

### PSP Boundary

- use provider-hosted card collection
- keep provider secret credentials on the server
- parse and normalize provider responses once
- verify webhook signatures before normalization
- store provider event IDs and apply them idempotently
- reconcile amount, currency, merchant account, and payment reference
- treat redirect or client callback state as provisional

### Stored Data

Seams may store:

- provider customer and payment-method references
- card brand, last four digits, and expiry
- wallet, merchant, order, and checkout identifiers
- canonical intent and digest
- authorization proof
- provider payment, refund, dispute, and event references
- timestamps and normalized state transitions

Seams application storage must exclude PAN, CVV, magnetic-stripe data, card PIN,
and raw provider secrets.

## Package Boundary

Use the existing repository structure:

| Area | Responsibility |
| --- | --- |
| `packages/shared-ts/src/checkout` | Provider-neutral IDs, money, checkout intent, credential, lifecycle, result, and event types. |
| `packages/wallet/src/SeamsWeb/checkout` | Embedded checkout orchestration, payment-method UI, confirmation, and provider client handoff. |
| `packages/wallet-server/src/checkout` | Intent creation, authorization verification, lifecycle transitions, payment execution port, and audit records. |
| `apps/web-server/src` | Merchant routes, concrete PSP client, provider credentials, webhook endpoint, and runtime configuration. |
| `tests/unit/checkout` | Domain type fixtures, lifecycle tests, provider-boundary tests, and fake-provider behavioral tests. |
| `tests/e2e/intended-behaviours` | Add-card, returning checkout, 3DS, failure, retry, and refund contracts. |

The existing console Stripe billing code provides useful patterns for provider
webhook verification, checkout reconciliation, and idempotency. Checkout-wallet
domain types and storage must remain separate because console credit purchases
have a different customer, merchant, and settlement model.

## MVP Build Order

### Phase 0: Provider Diligence

- confirm the connected-account merchant-of-record model
- prove card setup once and use at two test connected merchants
- confirm JPY, target jurisdictions, 3DS, refunds, and webhook simulations
- document PSP fees, reserves, dispute ownership, and negative-balance ownership
- confirm how customer consent for future card use is represented

The multi-merchant sandbox proof is a launch gate. A provider that requires the
customer to re-enter the same card for every merchant cannot deliver the target
product.

### Phase 1: Provider-Neutral Checkout Core

- add precise checkout IDs, fiat amounts, merchant records, card display data,
  and lifecycle unions
- add boundary parsers for merchant requests and raw provider responses
- add canonical `CardCheckoutIntentV1` digest computation
- add a fake PSP with setup, success, challenge, decline, timeout, and refund
  behavior
- add static fixtures rejecting raw provider IDs, missing merchant identity,
  invalid money, invalid lifecycle combinations, and execution without approval

### Phase 2: Save A Card

- create provider customer on first card setup
- render PSP-hosted card collection in the Seams-controlled wallet surface
- normalize setup results into a `ready_card_credential`
- list, select, and remove saved cards
- prove that application logs and storage contain no sensitive card data

### Phase 3: One Merchant Checkout

- create checkout intent from authenticated merchant backend input
- display canonical merchant, order, amount, currency, and card
- produce and verify the wallet authorization proof
- submit one idempotent provider payment
- handle success, decline, cancellation, expiry, and 3DS
- reconcile durable state from signed webhooks
- return a stable result to merchant frontend and backend

### Phase 4: Cross-Merchant Reuse

- connect a second merchant account
- reuse the same platform-saved card without collecting card details again
- create merchant-scoped provider payment credentials as required
- verify each merchant receives only its own order and payment state
- show combined customer payment history inside the Seams wallet

### Phase 5: Refunds And Pilot Readiness

- support full and partial refunds
- reconcile asynchronous refund states
- expose merchant order payment and refund status
- add observability for setup, authorization, provider challenge, payment, and
  webhook latency
- run the intended-behaviour contracts for new and returning customers

## Contingent acceptance criteria

The first operating path is complete when:

- a customer adds a test card once through PSP-hosted fields
- the same card is used at two connected test merchants without card re-entry
- each checkout shows and signs the exact merchant, order, amount, and currency
- one customer confirmation starts payment
- a 3DS challenge can complete inside or return safely to the checkout flow
- retries cannot create duplicate charges
- signed webhooks produce the durable payment state
- a merchant can issue and reconcile a refund
- the wallet displays payment and refund history
- Seams application storage and logs contain no PAN or CVV

## Do We Need To Issue Virtual Cards?

No virtual-card issuance is required for embedded checkout.

The customer already has a funding card. Seams stores a PSP token for that card
and uses it at merchants that have embedded Seams. Issuing another card would
add an extra payment instrument, funding relationship, issuer integration, and
compliance surface to a flow that already has a direct payment path.

Virtual-card issuance becomes useful for a different distribution problem:

```text
The merchant has no Seams integration, yet a customer or shopping agent needs a
policy-constrained card credential that works at the merchant's normal checkout.
```

Potential future uses:

- a shopping agent pays on an arbitrary external site
- a business gives an agent or employee a per-order spend credential
- a single-use card limits exposure to one purchase
- a merchant-locked card enforces an outer spend boundary
- a wallet balance funds card-network purchases outside the Seams merchant
  network

The strongest future use is a stablecoin-linked virtual card: a customer locks
part of a Seams wallet balance in an onchain card-reserve escrow, then spends
against that reserve at external card merchants. Conversion occurs only when
card clearing or settlement requires fiat. That product is defined in
`stablecoin-linked-virtual-card.md`.

It requires an issuer or program partner for the conventional card rail, while
Seams owns the onchain reserve, authorization-time holds, settlement conversion,
and audit evidence. Keep it as a separate execution rail from embedded checkout.

Production stablecoin-card issuance is deferred pending jurisdiction-specific
licensing, registration, capital, banking, and card-program approval. Technical
readiness may proceed only through testnet escrow, Airwallex demo integration,
and simulated treasury and settlement.

Add issuance only when all of these are true:

- Seams has the required regulatory authorization or licensed-partner structure
- customers or agents need to pay merchants that cannot embed Seams
- a scoped card credential provides enforcement that the external checkout
  cannot provide
- an issuer partner supports the target users and jurisdictions
- Seams has a clear funding, compliance, support, and dispute operating model
- the additional conversion or revenue justifies the operational burden

## Open Decisions

- Which PSP supports the required cross-merchant credential model in Japan and
  the first export markets?
- Which party is responsible for PSP fees, disputes, negative balances, and
  chargebacks under the connected-account configuration?
- How should a returning customer discover and unlock the same Seams wallet
  across merchant sites?
- Should billing address remain provider-held or be reusable as Seams wallet
  profile data with explicit customer consent?
- Which shipping fields belong in the signed checkout intent for the first
  merchant pilot?
- Does the PSP require a merchant-scoped payment-method copy per charge or a
  persistent connected-account customer?
- What checkout latency can the current wallet signing path sustain at target
  percentiles?
- Which refund controls belong to the merchant, Seams, and the PSP?

## Recommended Near-Term Position

For the product portfolio:

```text
Prioritize platforms that provision persistent wallets for their users. Support
shopping wallet applications and shopping agents as products built on that
wallet foundation.
```

For the technical roadmap:

```text
Do not build the PSP-backed card-on-file checkout path without validated demand
from a multi-merchant wallet product. Keep the design as a deferred reference.
```

## References

- [Stripe Link with Checkout](https://docs.stripe.com/payments/link/checkout-link)
- [Stripe Connect: share payment methods across accounts](https://docs.stripe.com/connect/direct-charges-multiple-accounts)
- [Stripe Connect direct charges](https://docs.stripe.com/connect/direct-charges)
- [W3C Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/)
- [EMVCo 3-D Secure](https://www.emvco.com/emv-technologies/3-d-secure/)

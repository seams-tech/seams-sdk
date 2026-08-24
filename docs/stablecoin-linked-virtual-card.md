# Stablecoin-Linked Virtual Card Plan

Date created: August 22, 2026

Status: production deferred pending regulatory authorization; testnet technical
readiness is active.

Related docs:

- [Embedded wallet card checkout](embedded-wallet-card-checkout.md)
- [Airwallex sandbox integration](airwallex-sandbox-integration.md)
- [Product vision](product-vision.md)

## Purpose

This plan defines a second payment use case for the Seams wallet:

```text
A customer locks stablecoin in an onchain Seams card-reserve escrow, then spends
against that reserve through a virtual card at merchants that have no Seams
integration.
```

Seams owns the stablecoin reserve protocol, authorization policy, card holds,
conversion orchestration, and audit trail. Airwallex is the first card and fiat
execution provider. It provides Airwallex Issuing funding, virtual card issuance,
Visa network access, card lifecycle, remote authorization, transaction events,
disputes, and fiat settlement.

Airwallex does not need to custody customer stablecoin, maintain the onchain
reserve ledger, or perform Seams' stablecoin conversion.

## Relationship To Embedded Checkout

| Product                        | Merchant relationship             | Customer funding source                                  |
| ------------------------------ | --------------------------------- | -------------------------------------------------------- |
| Embedded wallet card checkout  | Merchant embeds Seams             | Customer's existing saved credit, debit, or virtual card |
| Stablecoin-linked virtual card | Merchant accepts the card network | Stablecoin locked in Seams onchain escrow                |

Use embedded checkout where Seams is integrated. Use a stablecoin-linked card
to extend wallet spending to external card merchants.

The virtual card should not be inserted into an embedded checkout that already
has a direct PSP payment path.

## Product Decision

Use a Seams-controlled onchain escrow as the stablecoin source of truth:

```text
Seams MPC wallet
  -> customer locks stablecoin in card-reserve escrow
  -> Seams authorization ledger allocates spendable reserve
  -> issuer requests or reports card authorization
  -> Seams creates a stablecoin-backed hold
  -> merchant clears card transaction
  -> Seams settles from program liquidity
  -> escrowed stablecoin is converted or used for settlement
  -> unused reserve remains withdrawable under exposure rules
```

There is no provider-held stablecoin balance. The issuer sees a normal card
program with conventional authorization and settlement interfaces.

The customer sees:

- wallet stablecoin available
- stablecoin locked in card reserve
- stablecoin available for new card spend
- stablecoin held for authorizations
- stablecoin pending settlement
- stablecoin eligible for withdrawal

The first implementation supports one stablecoin contract on one chain, one
Airwallex adaptor, one dedicated Seams card-settlement multisig, and one
institutional USDC-to-USD redemption route.

## Delivery Status And Production Gate

Build the complete target UX and a simulated operating path on testnet. Keep
every live-money and production-card operation unavailable until Seams has the
required regulatory, banking, issuer, capital, and operational authority.

```text
Active now
  -> testnet escrow
  -> mock stablecoin
  -> Airwallex sandbox environment
  -> simulated fiat working capital
  -> simulated redemption and bank funding
  -> complete ledger and audit evidence

Deferred
  -> mainnet customer funds
  -> live Airwallex cards
  -> real USDC redemption
  -> real bank and Airwallex funding-pool funding
  -> production card authorizations
```

The first runtime type should expose only the testnet branch:

```ts
type StablecoinCardRuntime = {
  kind: 'testnet_stablecoin_card_runtime';
  chain: SupportedTestnetChain;
  stablecoin: VerifiedTestStablecoin;
  escrow: VerifiedTestnetCardReserveEscrow;
  airwallex: AirwallexSandboxConfiguration;
  redemption: SimulatedRedemptionConfiguration;
  bankFunding: SimulatedBankFundingConfiguration;
};
```

Production support is a future domain branch introduced only after the
production gate is satisfied. Initial code must reject mainnet chain IDs, live
stablecoin contracts, Airwallex production hosts, real redemption credentials,
and real bank destinations.

### Japan Regulatory Classification

Do not assume one generic payment-service-provider licence covers the complete
model. The final Japanese classification depends on the exact custody, escrow,
conversion, transfer, card-program, and customer relationships.

The Japan FSA states, among other things:

- conducting funds transfer as a business generally requires registration as a
  Funds Transfer Service Provider
- business sale or exchange of electronic payment instruments can require
  registration as an Electronic Payment Instruments Service Provider
- control of a private key sufficient to proactively transfer users' electronic
  payment instruments can constitute management on behalf of others
- a payment-only exception may apply where electronic payment instruments are
  used solely to purchase goods or services

The planned escrow, settlement debit, redemption, refund conversion, and reserve
exit may extend beyond a simple payment-only flow. Japanese regulatory counsel
and, where appropriate, the FSA FinTech Support Desk must classify the final
design before any production implementation or solicitation.

Production may require one or more Seams registrations, a licensed-partner
structure, a revised control model, or a combination of these.

### Testnet Readiness Evidence

The testnet build should produce evidence useful for licensing and partner
diligence:

- complete system and funds-flow diagrams
- escrow and authorization invariants
- customer-asset and corporate-treasury separation
- canonical ledger and reconciliation rules
- settlement-key and multisig policy
- access control and operator-role matrix
- AML, sanctions, KYC/KYB, and travel-rule integration points
- incident response, pause, recovery, and reserve exit procedures
- business continuity and authorization-timeout behavior
- synthetic transaction, refund, force-post, and chargeback evidence
- smart-contract property, invariant, and adversarial test artifacts; independent
  audit and formal verification remain production-candidate gates
- append-only audit records linking chain, Airwallex, redemption, and treasury
  simulation

## What Onchain Escrow Solves

Onchain escrow keeps the core balance independent of the card issuer:

- an issuer never controls the customer's stablecoin reserve
- switching issuers does not require moving the reserve to a new custodian
- Seams can integrate issuers that have no stablecoin infrastructure
- reserve deposits, settlement debits, and releases have onchain evidence
- wallet value cannot be spent simultaneously onchain and through the card
- agent budgets can be backed by an explicit locked amount
- issuer failure can block the card while leaving escrowed value recoverable
  under the reserve exit protocol

Issuer replacement still requires a new card credential. Card numbers and
network tokens belong to an issuer program and cannot fail over transparently.

## Remaining Critical Dependencies

Card issuance cannot eliminate issuer and network dependencies. The architecture
reduces their authority and makes the execution layer replaceable.

Seams must provide or contract for:

- a sponsor bank, issuer, processor, or program platform
- program-level settlement liquidity or collateral
- stablecoin-to-settlement conversion where the issuer requires fiat
- high-availability card authorization when delegated authorization is used
- card operations, fraud, disputes, chargebacks, and customer support

If the product requirement is zero critical card partner, the execution rail
must be direct stablecoin payment rather than a Visa, Mastercard, JCB, or other
network card.

## Customer Value

- spend supported stablecoin at ordinary ecommerce merchants
- keep the backing reserve onchain and separate from issuer custody
- lock a reserve smaller than the total wallet balance
- inspect authorization, clearing, conversion, refund, and fee evidence
- freeze or close the card without moving the underlying wallet seed
- recover unused reserve through a defined exit path

Future shopping-agent value:

- allocate a narrow onchain-backed budget
- issue or assign per-agent and per-order cards where supported
- constrain merchant, category, geography, amount, and time
- revoke delegated authority independently of wallet ownership
- preserve a verifiable chain from mandate to card transaction

## Target Customer Experience

### Where The Experience Appears

The stablecoin card is a wallet-owned product surface. A customer can open it
from a Seams wallet embedded in a partner site or from a future Seams-owned
wallet application. The embedding site may open or close the wallet surface but
cannot read cardholder onboarding data, sensitive card details, or reserve
authorization state.

```text
Partner site
  -> opens embedded Seams wallet
  -> customer selects Cards
  -> Seams-controlled wallet surface owns setup, reserve, card, and activity UI
  -> Airwallex-hosted surfaces own regulated onboarding and sensitive card data
```

The card is designed for purchases at external merchants that do not integrate
Seams. When a merchant already offers the direct `Pay with Seams` checkout path,
the wallet should present that path and omit the stablecoin card as a redundant
payment option.

An ordinary card purchase does not open Seams or request an MPC or passkey
confirmation. The customer enters or selects the virtual card in the merchant's
normal checkout, the issuer performs any required 3DS challenge, and Seams
creates the reserve hold through delegated authorization in the background.

### Experience Goal

The product should feel like allocating part of a wallet balance for card
spending:

```text
Open Cards
  -> check eligibility
  -> complete provider-hosted identity review
  -> choose how much stablecoin to reserve
  -> confirm the exact escrow deposit once
  -> wait for card setup and deposit confirmation
  -> use the virtual card at supported online merchants
  -> track purchases, holds, refunds, and reserve release in the wallet
```

Customers should understand four facts without reading technical documentation:

1. Their stablecoin remains locked in a Seams escrow allocation until it is
   settled or released.
2. The card spends prefunded fiat from the card program; merchants do not receive
   the customer's stablecoin.
3. A card authorization can remain pending, reverse, expire, or settle for a
   different final amount.
4. Closing the card can require a disclosed wait before the remaining reserve is
   released.

### Experience Principles

- Show one primary action for the current state.
- Lead with `Available to spend` in the card's billing currency.
- Keep wallet balance, card reserve, and corporate program liquidity distinct.
- Display pending work as a resumable operation with a stable reference.
- Describe authorization and settlement as separate states.
- Put fees, FX, exit timing, data sharing, and irreversible consequences beside
  the decision that creates them.
- Keep identity collection and PAN/CVV display inside provider-hosted surfaces.
- Preserve transaction evidence without exposing provider internals on the
  primary screen.
- Use text and icons for status; color is a secondary cue.
- Keep production claims out of the testnet runtime.

### Card Home

The compact embedded surface uses a single column and presents the spendable
amount before technical reserve detail:

```text
+------------------------------------------------+
| TESTNET ONLY · No real funds or purchases      |
|                                                |
| Stablecoin card                         Ready  |
|                                                |
| Available to spend                             |
| USD 100.00                                     |
| 102.50 USDC reserved                           |
|                                                |
| VISA                                      4242 |
| [Show card details]                            |
|                                                |
| [Add reserve]                 [Freeze card]    |
|                                                |
| Recent activity                                |
| ACME STORE                 -USD 24.00  Pending |
| Reserve deposit           +100 USDC  Confirmed |
|                                                |
| [View all activity]                            |
+------------------------------------------------+
```

At wider container sizes, the card and balance summary may sit beside recent
activity. The hierarchy and reading order remain the same. Controls stay within
the wallet margins and safe areas. A narrow embed never reduces the interface to
an icon-only card carousel or hides the primary action below a fixed-height pane.

The primary summary contains:

- `Available to spend`: the lower of confirmed reserve availability and the
  synchronized provider limit, after the required buffer
- card status, network or program brand, and last four digits
- one state-specific primary action
- a permanent testnet marker in every active testnet environment

Expandable reserve detail contains:

- wallet stablecoin available
- total card reserve
- held for authorizations
- pending settlement
- pending release
- currently eligible for withdrawal
- supported token, chain, and escrow contract

The UI must never label escrowed stablecoin as money stored on the card.

### Customer-Facing State Model

The UI derives one customer-facing projection from the separate eligibility,
card, reserve, provider-limit, and exit lifecycles. The projection is not an
independent source of truth.

| Customer state       | Primary message                                                        | Primary action        |
| -------------------- | ---------------------------------------------------------------------- | --------------------- |
| Unavailable          | `Stablecoin card is unavailable for this wallet or region.`            | `View availability`   |
| Eligibility required | `Check whether you can create a stablecoin card.`                      | `Check eligibility`   |
| Eligibility pending  | `Eligibility review is in progress.`                                   | `View requirements`   |
| Setup in progress    | `Your virtual card is being prepared.`                                 | `View setup progress` |
| Reserve required     | `Card setup is complete. Add a reserve to enable spending.`            | `Add reserve`         |
| Deposit pending      | `Your reserve deposit is confirming onchain.`                          | `View deposit`        |
| Limit sync pending   | `Reserve confirmed. Spending will start after the card limit updates.` | `Refresh status`      |
| Ready                | `Your card is ready to spend.`                                         | `Show card details`   |
| Frozen               | `New card purchases are blocked.`                                      | `Unfreeze card`       |
| Needs attention      | `This card cannot be used until its provider status is resolved.`      | `View card status`    |
| Exit in progress     | `Your card is frozen while existing activity settles.`                 | `View exit progress`  |
| Closed               | `This card is permanently closed.`                                     | `View activity`       |
| Reserve released     | `Your remaining reserve has returned to your wallet.`                  | `View wallet`         |

Every pending state includes the operation start time, current step, last update,
technical reference, and a support path. Reloading the embed, changing sites, or
signing in on a linked device must resume the same operation without creating a
second card, deposit, refund, or exit request.

### First-Time Setup

#### 1. Entry And Preflight

The empty state explains the product and gives one action:

```text
Spend from stablecoin

Lock part of your supported stablecoin balance for card purchases at supported
online merchants. Unused reserve can be withdrawn after pending card activity
has settled.

[Create virtual card]
```

Before regulated onboarding starts, show:

- supported cardholder country and residence requirements
- card issuer or program provider
- supported stablecoin, chain, and card billing currency
- expected fees and FX treatment
- the reserve-exit rule and expected timing range
- the identity data shared with the card provider
- links to cardholder terms and privacy information

An unavailable customer should learn that outcome before entering identity data
whenever the provider can determine it from existing wallet and jurisdiction
information.

#### 2. Provider-Hosted Eligibility

Airwallex-hosted or Airwallex-backed onboarding collects the required identity
information. The Airwallex boundary maps documented cardholder states into:

- `INCOMPLETE`: more information required
- `PENDING`: review in progress
- `READY`: eligibility confirmed and card issuance allowed
- `DISABLED`: cardholder disabled by the provider

Region unavailable, provider temporarily unavailable, and a documented
provider-declared rejection are separate eligibility or call outcomes. They must
not be invented as Airwallex cardholder statuses.

The customer can leave and resume provider review. Seams stores provider
references and normalized status only. Raw identity documents and regulated
onboarding fields remain in the provider boundary whenever Airwallex supports
that model.

#### 3. Add A Card Reserve

The reserve form shows:

- wallet stablecoin available
- amount to reserve
- supported token and chain
- escrow contract
- network fee
- estimated card-currency amount available after confirmation
- FX or safety buffer and program fees
- whether existing card holds remain unchanged

The confirmation action repeats the consequence, for example `Lock 100 USDC`.
Passkey or biometric confirmation signs the exact chain, token, escrow, amount,
fees, and allocation intent.

After submission, use a persistent stepper:

```text
Submitted
  -> Confirming onchain
  -> Reserve recorded
  -> Card limit synchronizing
  -> Ready to spend
```

A submitted transaction never appears as spendable. The pending screen shows the
chain transaction and disables duplicate submission for the same intent. A
failed or replaced transaction gives a recovery action beside the failed step.

Card issuance and reserve confirmation may run concurrently after eligibility is
confirmed. The provider card remains inactive or unavailable to spend until both
the reserve and provider limit are ready.

#### 4. Show Card Details

The card home displays only safe card data. `Show card details` requires a fresh
wallet confirmation and opens an Airwallex-hosted secure display session.

The secure surface owns:

- full card number
- expiry date
- security code
- `Copy card number`, `Copy expiry date`, and `Copy security code` actions
- explicit `Hide card details` and close actions

The provider session expires independently. Closing it clears sensitive display
state and restores focus to `Show card details`. Seams application state, logs,
analytics, and clipboard helpers never receive PAN or CVV. When secure display is
unavailable in the sandbox, the UI states that limitation instead of calling a
sensitive card-details API.

### Purchase And Activity Experience

The customer uses the virtual card in an external merchant's ordinary checkout.
The merchant or issuer may present 3DS or another cardholder challenge. Seams
does not add a second approval ceremony for an ordinary card purchase.

Wallet activity distinguishes the complete sequence:

```text
Authorization requested
  -> reserve held
  -> approved or declined by Seams
  -> issuer result received
  -> cleared, reversed, or expired
  -> settled
```

Single-message transactions combine authorization and clearing in one provider
event. The UI still presents their resulting hold and settlement truthfully.

Purchase detail shows:

- merchant name and timestamp
- card last four digits
- merchant amount and currency
- estimated and final stablecoin amount
- FX rate, buffer, and fees when known
- amount held, settled, and released
- current status and recovery action
- provider, settlement, and chain evidence under `View supporting evidence`

`Approved by Seams` is an intermediate state. Airwallex can still decline through
its risk and regulatory controls. A provider-final decline releases or reconciles
the reserve hold before the UI claims that funds are available again.

Recommended recovery messages include:

| Situation                           | Message                                                                                  | Action                      |
| ----------------------------------- | ---------------------------------------------------------------------------------------- | --------------------------- |
| Insufficient reserve                | `Payment declined. Add reserve or try a smaller amount.`                                 | `Add reserve`               |
| Card frozen                         | `Payment declined because this card is frozen.`                                          | `Unfreeze card`             |
| Unsupported currency                | `This card cannot use the requested currency.`                                           | `View supported currencies` |
| Issuer decline after Seams approval | `The issuer declined this payment. The reserve hold is being reconciled.`                | `View activity`             |
| Provider outage                     | `Card payments are temporarily unavailable. Your reserve remains locked.`                | `View status`               |
| Reconciliation delay                | `This activity is being checked. Your reserve remains protected while it is reconciled.` | `Contact support`           |

The first release uses manual `Add reserve`. Automatic top-up is deferred because
it would introduce continuing wallet authorization, fee, and custody decisions.

### Activity And Evidence

Use one chronological history with `Card activity` and `Reserve activity`
filters. Each entry opens a detail timeline. Example entries include:

- reserve deposit submitted or confirmed
- authorization hold created, adjusted, or released
- purchase settled, reversed, or expired
- refund pending or credited
- dispute opened or resolved
- card frozen or closed
- reserve exit started or released

Human-readable amount and status come first. Provider IDs, chain transactions,
settlement instructions, conversion records, and treasury batch references appear
inside `View supporting evidence`. Raw webhook bodies, secrets, PAN, and CVV are
never displayed.

### Freeze, Close, And Reserve Exit

These operations have separate controls and consequences.

Freeze confirmation:

```text
Freeze card?

New purchases will be declined. Existing authorizations can still settle.

[Cancel] [Freeze card]
```

Close confirmation:

```text
Close card permanently?

This card number cannot be restored. Existing activity and reserve records will
remain available.

[Cancel] [Close card]
```

Reserve exit is a guided flow:

1. Show available reserve, open authorizations, pending settlement, and the
   amount currently eligible for release.
2. Explain that starting exit freezes the card and blocks new purchases.
3. Confirm with `Start reserve exit`.
4. Display progress while authorization, clearing, refund, and dispute exposure
   follows the program policy.
5. Show the final stablecoin amount and chain transaction only after release.

The exit screen must show a maximum customer-facing timeline or an explicit
reason why a date is not yet available. The production policy must define the
customer reserve tail and the corporate program-loss reserve before this screen
can promise a final release date.

### Refunds And Disputes

A refund remains pending until Airwallex has posted it and Seams has confirmed
the stablecoin credit. Show the original purchase, merchant refund amount,
expected stablecoin credit, final FX and fees, and destination.

- An active card receives the confirmed credit into its reserve.
- A closed card or released allocation receives the credit in the customer's
  supported stablecoin wallet, or in a claimable refund balance when direct
  credit is temporarily unavailable.

`Request a merchant refund` and `Report a card transaction` are separate entry
points. Dispute states include submitted, under review, more information needed,
resolved, and rejected. The UI explains that a dispute review does not guarantee
a refund.

### Responsive And Accessible Behavior

- Use a single-column compact layout first; expand based on the wallet
  container's available width rather than the viewport width.
- Keep one page-level heading and a coherent heading order inside the wallet
  surface.
- Use native buttons, links, forms, and dialogs. Every pointer operation has a
  keyboard path.
- Dialogs trap focus, close with Escape when safe, and restore focus to their
  trigger. Destructive confirmations initially focus `Cancel`.
- Keep visible `:focus-visible` indicators and touch targets near 44 by 44 CSS
  pixels where the wallet density permits.
- Give every form control a visible label. Inline errors identify the field,
  explain recovery, and receive focus on failed submission.
- Announce deposit, authorization, refund, and exit progress through a stable
  polite status region. Urgent failures use an alert only when focus does not
  already announce them.
- Status never depends on color alone. Pending, succeeded, failed, frozen, and
  testnet states include text.
- Support 200% zoom, 320 CSS-pixel reflow, keyboard-only operation, reduced
  motion, long translated labels, and right-to-left layout.
- Keep sticky actions inside safe areas and reachable when the embed scrolls or
  the on-screen keyboard opens.

### UX Acceptance Criteria

- The wallet shows the current combined card and reserve state on every card
  screen.
- A customer can identify the valid next action without reading technical docs.
- Testnet surfaces always say `Testnet only — no real funds or merchant
purchases.`
- `Ready to spend` requires confirmed escrow funding and synchronized provider
  limits.
- Reserve confirmation shows chain, token, escrow, amount, fee, and the exact
  passkey-confirmed consequence.
- A submitted deposit becomes a resumable, non-duplicable pending operation.
- Full card details appear only in the provider-hosted secure surface.
- Purchase history distinguishes authorization, provider result, clearing,
  settlement, reversal, expiry, refund, and dispute.
- Every customer-visible amount identifies its fiat or stablecoin currency.
- Freeze, close, and exit confirmations repeat their consequences in the primary
  action label.
- Exit never reports release while unresolved exposure remains under the program
  policy.
- Late refunds have a defined customer destination after card closure.
- Every pending or failed state provides a recovery action or support path.
- The complete setup, funding, card-control, activity, refund, and exit flows work
  with keyboard-only input and at 320 CSS pixels and 200% zoom.
- The host page and Seams application never receive PAN, CVV, raw identity
  documents, provider secrets, or raw webhook data through the UX path.

## Scope

### Active Testnet Build

- one test stablecoin contract on one testnet chain
- one testnet onchain card-reserve escrow
- one Airwallex Issuing adaptor
- Airwallex sandbox environment only
- one simulated Airwallex platform Wallet funding configuration
- one program settlement currency
- one simulated conversion and liquidity route
- one testnet Seams card-settlement multisig
- test-data cardholder onboarding
- Airwallex sandbox cards or a fake provider when sandbox issuance is unavailable
- sandbox or fake hosted sensitive-card-detail display
- MPC-signed escrow deposit and exit intents
- Seams-owned available, held, and pending-settlement ledger
- Airwallex remote authorization with `DECLINED` as the default action
- provider hard limits as an outer boundary
- authorization, clearing, reversal, refund, and decline events from Airwallex;
  dispute states from a precise fake boundary
- card activation, freeze, unfreeze, and close
- simulated redemption, bank funding, and Wallet replenishment
- deterministic failure and replay simulation

### Deferred Production

- mainnet escrow deployment
- real customer stablecoins
- production cardholder onboarding
- live Airwallex Issuing and cards
- production Airwallex PLP or Wallet funding
- real USDC redemption and bank transfers
- real card authorizations, clearing, refunds, and disputes
- customer solicitation or public production availability
- any operation requiring a licence, registration, approval, or capital position
  that Seams has not obtained

### Later Product Features

- multiple stablecoins or chains
- multiple active issuer adaptors
- automatic issuer routing
- physical cards
- consumer credit or charge products
- Apple Pay and Google Pay provisioning
- single-use and per-agent cards
- direct network membership
- direct stablecoin network settlement operated by Seams
- yield on escrowed reserve
- permissionless conversion routing
- instant reserve exit while unresolved card exposure exists

## Reserve And Authorization Model

Card-network authorization deadlines are too short to depend on an onchain
transaction reaching finality for every purchase. The testnet model therefore separates
onchain collateral from the low-latency authorization ledger:

```text
Onchain escrow
  authoritative total locked per wallet and card allocation

Seams authorization ledger
  available
  held
  pending settlement
  released
```

The complete onchain card allocation remains locked while the card is active.
Seams places sub-balance holds atomically in its durable authorization ledger.
The contract prevents the customer from withdrawing locked collateral while
unresolved card exposure may exist.

This gives the issuer a fast response without allowing the customer to race a
card authorization with an onchain withdrawal.

### Safe Exit

The first exit protocol is intentionally simple:

```text
1. Customer requests reserve exit.
2. Seams freezes the virtual card.
3. New authorizations are declined.
4. Existing authorizations clear, reverse, or expire.
5. Refund and dispute exposure required by the program is resolved or reserved.
6. Seams commits the final settlement state.
7. Escrow releases the unencumbered stablecoin to the customer's wallet.
```

Partial instant withdrawal while a card remains active is deferred. It requires
a stronger onchain commitment scheme for the authorization ledger or explicit
program collateral covering withdrawal races and late card events.

## Card Authorization Modes

### Realtime Delegate

Airwallex Remote Authorization is the first implementation:

```text
Merchant authorization
  -> Airwallex calls Seams
  -> Seams validates card, reserve, policy, FX, and revocation state
  -> Seams atomically creates stablecoin hold
  -> Seams approves or declines
  -> Airwallex completes risk checks and network authorization
```

Requirements:

- Airwallex Remote Authorization enabled for the platform and cards
- authenticated and replay-safe authorization requests
- response within Airwallex's documented 2.5-second window
- `DECLINED` configured as the default action
- no Airwallex stand-in approval for reserve-backed purchases
- idempotent retries under the same authorization reference
- Airwallex hard limits matching the maximum escrow allocation
- sufficient fiat available in the configured Airwallex funding Wallet

Airwallex does not understand the escrow balance. It receives an approve or
decline decision and uses its fiat Wallet as the card's execution balance.
Airwallex can still decline a Seams-approved transaction through its internal
risk and regulatory checks.

### Provider Rules

A later compatibility mode for issuers without delegated authorization:

```text
Customer allocates a fixed escrow budget
  -> Seams configures matching issuer card limits
  -> issuer authorizes within those hard limits
  -> Seams reconciles transaction events after authorization
```

The full card limit remains encumbered in escrow until issuer events prove it
can be released. This mode provides coarser policy, slower balance reuse, and
greater program liquidity requirements. Agent spending that requires live
mandate or revocation checks should use realtime delegation.

## Airwallex Funding And Settlement Liquidity

Airwallex documents the Airwallex Wallet and Platform Liquidity Program as
Issuing funding sources. Remote authorization controls whether a transaction
should proceed; it does not create the fiat that funds the card transaction.
Seams must therefore maintain adequate working capital inside the configured
Airwallex funding source before authorizations occur.

Use two separate value planes:

```text
Customer collateral
  Seams MPC wallet
    -> onchain card-reserve escrow
    -> Seams authorization holds

Card execution
  Seams USD working capital
    -> Airwallex PLP Settlement Account or platform Wallet
    -> Airwallex virtual cards
    -> merchants
```

The preferred production configuration is Airwallex PLP. It uses one centrally
prefunded PLP Settlement Account and a Program Spending Account for each enabled
Connected Account. Cards reference the resulting `funding_source_id`. This
avoids preloading fiat into every customer Wallet while preserving separate
customer ledger projections.

PLP still requires fiat in advance and Airwallex program enablement. The exact
consumer-card, Connected Account, PLP, currency, limit, settlement, and loss
configuration is a production gate. The self-service sandbox path uses the
ordinary sandbox Wallet and a precise fake PLP boundary until Airwallex enables
the platform capabilities.

### Replenishment Loop

Airwallex must already have fiat when a transaction is authorized. Settlement
from escrow replenishes that prefunded fiat rather than funding the same
authorization in real time.

```text
1. Seams prefunds its Airwallex PLP Settlement Account or Wallet with USD working capital.
2. Airwallex sends a card authorization request.
3. Seams creates the corresponding stablecoin hold and approves.
4. Airwallex uses available fiat and later sends the clearing event.
5. Seams validates clearing and calculates the exact stablecoin obligation.
6. Escrow debits that amount to the Seams card-settlement multisig.
7. Seams redeems USDC to USD through an institutional off-ramp.
8. USD arrives in the Seams settlement bank account.
9. Seams replenishes the Airwallex funding pool.
10. Unused stablecoin authorization hold returns to available reserve.
```

Customer settlement remains transaction-specific. Treasury redemption, bank
receipt, and Airwallex replenishment run as reconciled batches based on liquidity
thresholds. A customer purchase does not wait for its corresponding redemption
or bank transfer.

Circle Mint is the first USDC redemption diligence target. Treat the redemption
client as a replaceable treasury boundary so Circle does not become part of the
card or escrow protocol.

Seams is responsible for:

- Airwallex funding-pool working capital
- bank-transfer and wallet-funding latency
- stablecoin redemption and conversion
- authorization-to-clearing FX movement
- liquidity during redemption or banking outages
- Airwallex reserves and settlement requirements
- force-post, overcapture, and chargeback exposure
- exact treasury and customer-reserve reconciliation

The settlement loop must handle:

- authorization and clearing in different amounts
- incremental authorization and partial clearing
- tips and overcapture
- authorization expiry and reversal
- foreign-exchange movement
- force-post and offline transactions
- refunds and chargebacks after reserve exit is requested
- conversion failure or delayed fiat delivery

## Core Flows

### Cardholder Enrollment And Card Issue

```text
1. Customer opens the stablecoin card surface in the Seams wallet.
2. Seams checks jurisdiction and wallet eligibility.
3. Airwallex-hosted or Airwallex-backed onboarding collects required cardholder information.
4. Seams maps documented Airwallex cardholder state and any separate eligibility outcome.
5. Seams requests an Airwallex virtual card only for a `READY` cardholder.
6. Seams stores provider references and safe display data.
7. The card remains unavailable to spend until reserve and provider-limit state are ready.
8. A fresh customer request opens Airwallex secure card display when that capability is enabled.
```

Seams application code must never receive, persist, log, or proxy PAN or CVV.

### Deposit Stablecoin Into Escrow

```text
1. Customer chooses a supported stablecoin amount.
2. Wallet shows escrow contract, chain, token contract, amount, and fees.
3. Customer confirms once with passkey or biometric presence.
4. MPC signing authorizes the exact escrow deposit intent.
5. Wallet submits the onchain deposit once.
6. Seams waits for the configured confirmation policy.
7. Authorization ledger credits the card allocation exactly once.
8. Seams configures the matching issuer hard limit.
9. Wallet reports `Ready to spend` only after the limit synchronization is confirmed.
```

A submitted transaction is insufficient funding evidence. Only a confirmed,
validated escrow event can create card availability.

### Card Purchase

```text
1. Airwallex sends a signed authorization request to Seams.
2. Seams normalizes merchant amount, currency, card, and network data.
3. Seams resolves a preloaded bounded FX and fee quote without a network call.
4. Seams atomically creates a stablecoin hold in the authorization ledger.
5. Seams approves or declines within 2.5 seconds.
6. Airwallex completes its checks and later sends clearing, reversal, or expiry.
7. Seams settles the exact obligation through the settlement multisig and
   releases unused hold.
```

### Refund

```text
1. Airwallex posts a refund against the original card transaction.
2. Seams matches original clearing and settlement evidence.
3. The Airwallex funding pool or Seams settlement account receives the fiat value.
4. Seams uses that value to mint or acquire the supported stablecoin.
5. An active card receives one escrow credit; a closed card receives one wallet
   or claimable-refund credit.
6. Wallet history links Airwallex refund, conversion, and destination evidence.
```

The rate and fees for returning a fiat card refund to stablecoin must be
disclosed. The product cannot create an unexplained residual fiat balance.

### Freeze, Close, And Exit

- Freeze blocks new authorizations while existing events continue to settle.
- Close permanently disables the issuer credential.
- Exit freezes the card, reconciles exposure, and releases stablecoin.
- Closing a card preserves ledger and audit evidence.
- Issuer failure triggers the same exposure-resolution and escrow-release path.

## Onchain Escrow Contract

Keep the contract small. Its purpose is collateral isolation and replay-safe
movement, not card policy evaluation.

Required operations:

- deposit supported stablecoin into a wallet/card allocation
- record allocation identity and owner wallet
- debit an allocation under an evidence-backed settlement instruction
- credit refunds and settlement corrections
- freeze allocation exit while card exposure remains open
- release unencumbered allocation to the owner wallet
- prevent settlement or release replay
- pause new deposits and settlement in a security emergency

Core invariants:

- total debits and releases never exceed confirmed deposits and refund credits
- one settlement reference can execute once
- one release reference can execute once
- funds cannot be both settled and released
- only the supported chain and token contract enter an allocation
- allocation ownership cannot change through an unvalidated raw address
- emergency pause cannot grant arbitrary withdrawal authority
- contract accounting reconciles to token balance

The contract must not expose a general treasury sweep. Use a constrained
settlement instruction:

```ts
type EscrowSettlementInstructionV1 = {
  kind: 'escrow_settlement_instruction_v1';
  settlementId: CardSettlementId;
  allocationId: CardReserveAllocationId;
  airwallexClearingId: AirwallexClearingId;
  amount: StablecoinAmount;
  destination: ApprovedCardSettlementVault;
  clearingEvidenceDigest: ClearingEvidenceDigest;
  expiresAtMs: number;
};
```

The first testnet contract cannot independently inspect the offchain held or
pending-settlement balance. The authorization ledger validates that exposure and
a dedicated threshold settlement authority attests the instruction. The contract
enforces the attestor quorum, one execution per `settlementId`, cumulative debits
within the confirmed unreleased allocation, instruction expiry, and a destination
on the settlement-vault allowlist.

The resulting customer guarantee is explicit: escrow isolates the allocation and
caps settlement to its remaining amount, while Seams is trusted to attest which
card clearing justifies each debit. A future onchain state commitment may reduce
that trust after the operating path demonstrates a need for the added complexity.

### Seams Card-Settlement Multisig

Use a dedicated multisig for card settlement, separate from the general
corporate treasury:

```text
Onchain card-reserve escrow
  -> exact settlement debit
  -> Seams card-settlement multisig
  -> Circle Mint or another approved USDC off-ramp
  -> Seams USD settlement bank account
  -> Airwallex PLP Settlement Account or Wallet
```

The settlement multisig may receive only evidence-backed escrow debits and
refund liquidity. Its signers and policy are separate from contract
administration and ordinary corporate spending.

The settlement authority should use a threshold-controlled key or equivalent
multi-party control separate from ordinary application credentials. Contract
upgrade and emergency recovery policy must be decided before mainnet deployment.

An onchain contract can still create custody, money-transmission, safeguarding,
or virtual-asset obligations depending on jurisdiction and control design.
Legal classification must be established before live funds.

## Domain Model

Validate raw chain, issuer, FX, and webhook data once at their boundaries. Core
reserve and card logic accepts precise internal types.

```ts
type SupportedStablecoin = {
  kind: 'supported_stablecoin_v1';
  chainId: StablecoinChainId;
  contractAddress: StablecoinContractAddress;
  symbol: StablecoinSymbol;
  decimals: StablecoinDecimals;
};

type StablecoinAmount = {
  kind: 'stablecoin_amount_v1';
  amountAtomic: StablecoinAmountAtomic;
  asset: SupportedStablecoin;
};

type CardMerchantAmount = {
  kind: 'card_merchant_amount_v1';
  amountMinor: CardMerchantAmountMinor;
  currency: IsoCurrencyCode;
};
```

Amounts use validated integer strings or branded integers with explicit
decimals. Floating-point values must never cross a money boundary.

### Deposit Intent

```ts
type CardReserveDepositIntentV1 = {
  kind: 'card_reserve_deposit_intent_v1';
  depositId: CardReserveDepositId;
  walletId: WalletId;
  cardId: StablecoinVirtualCardId;
  escrow: VerifiedCardReserveEscrow;
  amount: StablecoinAmount;
  expiresAtMs: number;
  nonce: CardReserveDepositNonce;
};
```

The canonical digest binds every field. A different escrow, token, amount,
wallet, or card requires a new authorization.

### Reserve Lifecycle

```ts
type CardReserveState =
  | {
      kind: 'active';
      allocationId: CardReserveAllocationId;
      walletId: WalletId;
      cardId: StablecoinVirtualCardId;
      locked: StablecoinAmount;
      available: StablecoinAmount;
      held: StablecoinAmount;
      pendingSettlement: StablecoinAmount;
    }
  | {
      kind: 'exit_pending';
      allocationId: CardReserveAllocationId;
      walletId: WalletId;
      cardId: StablecoinVirtualCardId;
      locked: StablecoinAmount;
      held: StablecoinAmount;
      pendingSettlement: StablecoinAmount;
      exitTailReserve: StablecoinAmount;
      releasable: StablecoinAmount;
      exitRequestedAtMs: number;
    }
  | {
      kind: 'released';
      allocationId: CardReserveAllocationId;
      walletId: WalletId;
      released: StablecoinAmount;
      releaseTransactionId: StablecoinTransactionId;
    };
```

Only an active reserve may back a new authorization. `exit_pending` always maps
to a frozen or closed card. Every amount in one reserve state names the same
stablecoin asset. Active state enforces `locked = available + held +
pendingSettlement`. Exit state enforces `locked = held + pendingSettlement +
exitTailReserve + releasable`. These balances are projections derived from the
immutable ledger rather than independently mutable counters.

### Card Lifecycle

```ts
type StablecoinVirtualCardState =
  | {
      kind: 'issuance_pending';
      cardId: StablecoinVirtualCardId;
      walletId: WalletId;
      issuer: IssuerProvider;
      requestId: StablecoinCardRequestId;
    }
  | {
      kind: 'issued';
      cardId: StablecoinVirtualCardId;
      issuer: IssuerProvider;
      providerCardId: ProviderCardId;
      display: SafeCardDisplayData;
    }
  | {
      kind: 'frozen';
      cardId: StablecoinVirtualCardId;
      issuer: IssuerProvider;
      providerCardId: ProviderCardId;
      display: SafeCardDisplayData;
      reason: CardFreezeReason;
    }
  | {
      kind: 'provider_unavailable';
      cardId: StablecoinVirtualCardId;
      issuer: IssuerProvider;
      providerCardId: ProviderCardId;
      display: SafeCardDisplayData;
      reason: ProviderCardUnavailableReason;
    }
  | {
      kind: 'closed';
      cardId: StablecoinVirtualCardId;
      issuer: IssuerProvider;
      providerCardId: ProviderCardId;
      closedAtMs: number;
    };

type IssuedStablecoinVirtualCard = Extract<StablecoinVirtualCardState, { kind: 'issued' }>;

type ActiveCardReserve = Extract<CardReserveState, { kind: 'active' }>;

type SpendReadyStablecoinCardV1 = {
  kind: 'spend_ready_stablecoin_card_v1';
  card: IssuedStablecoinVirtualCard;
  reserve: ActiveCardReserve;
  providerLimit: SynchronizedProviderCardLimit;
};
```

Card resource state remains separate from reserve state because Airwallex may
issue a card before an escrow allocation is ready. Only the branch-specific
builder for `SpendReadyStablecoinCardV1` may combine an issued card, its matching
active allocation, and a synchronized provider limit. The authorization service
accepts that narrow state. Frozen, unavailable, closed, deposit-pending, and
limit-sync-pending combinations cannot reach authorization.

## Ledger And Reconciliation

```ts
type StablecoinCardLedgerTransition =
  | { kind: 'escrow_deposit_observed'; deposit: ObservedEscrowDeposit }
  | { kind: 'escrow_deposit_confirmed'; deposit: ConfirmedEscrowDeposit }
  | { kind: 'escrow_deposit_reverted'; deposit: RevertedEscrowDeposit }
  | { kind: 'authorization_request_recorded'; request: CardAuthorizationRequest }
  | { kind: 'authorization_hold_created'; hold: StablecoinAuthorizationHold }
  | { kind: 'authorization_hold_adjusted'; adjustment: StablecoinHoldAdjustment }
  | { kind: 'authorization_hold_released'; release: StablecoinHoldRelease }
  | { kind: 'provider_authorization_finalized'; result: ProviderAuthorizationResult }
  | { kind: 'clearing_obligation_created'; clearing: CardClearingObligation }
  | { kind: 'clearing_obligation_adjusted'; adjustment: CardClearingAdjustment }
  | { kind: 'force_post_obligation_created'; forcePost: CardForcePostObligation }
  | { kind: 'escrow_settlement_debited'; settlement: EscrowSettlementDebit }
  | { kind: 'refund_receivable_created'; refund: CardRefundReceivable }
  | { kind: 'refund_escrow_credited'; refund: EscrowRefundCredit }
  | { kind: 'refund_wallet_credited'; refund: WalletRefundCredit }
  | { kind: 'exit_tail_reserved'; reserve: CardExitTailReserve }
  | { kind: 'escrow_allocation_released'; release: EscrowAllocationRelease }
  | { kind: 'chargeback_posted'; chargeback: CardChargeback };
```

Each transition requires a unique authoritative reference. Issuer webhooks are
treated as at-least-once delivery. Replayed and reordered chain or provider
events must converge without duplicate credit, hold, settlement, refund, or
release. Provider lifecycle, card-transaction, and transaction-event identifiers
remain distinct. Customer-reserve postings and corporate-treasury postings use
separate ledgers and reconcile through immutable settlement-batch references.

## Role Of Passkeys And MPC

MPC directly controls onchain reserve deposits and customer-authorized exits:

```text
passkey or local biometric confirmation
  -> unlock wallet authorization
  -> sign exact escrow intent
  -> submit onchain operation
  -> reconcile chain and card state
```

An ordinary card purchase does not carry an MPC signature through the network.
Seams' delegated authorization endpoint enforces the stablecoin-backed hold.

For future agent spending, a signed mandate can bind agent, merchant, budget,
category, geography, expiry, and revocation state. Seams evaluates that mandate
before creating the authorization hold.

## Airwallex Adaptor Boundary

The first adaptor is Airwallex-specific and card-focused. It contains no
stablecoin custody, escrow, conversion, or redemption interfaces.

Required testnet adaptor operations:

- create one eligible Airwallex cardholder in the configured sandbox account
- issue Airwallex virtual card
- create secure card-display session
- set Airwallex hard limits
- freeze, unfreeze, and close card
- verify Airwallex remote authorization request
- return approve or decline response
- verify and normalize Airwallex events
- retrieve transaction and settlement state for reconciliation
- simulate authorization, clearing, reversal, refund, and timeout

Connected Accounts, consumer-program onboarding, and PLP funding remain explicit
provider-enabled paths. The self-service sandbox path must use a fake boundary for
any capability that Airwallex has not enabled.

Provider-specific raw values stay inside the adaptor. Core reserve, policy,
authorization, and settlement logic receives normalized domain objects.

Add a second issuer only after the complete Airwallex escrow-to-card path works.
This preserves a replaceable boundary without building routing machinery before
there is a demonstrated need.

## Compliance And Operational Ownership

Moving reserve custody away from the issuer moves responsibility toward Seams.
The operating model must assign:

- escrow contract control and incident response
- stablecoin screening and supported asset policy
- fiat conversion and liquidity
- issuer settlement funding and reserves
- KYC/KYB, sanctions, and cardholder eligibility
- fraud, disputes, chargebacks, and cardholder support
- force-post and negative-exposure losses
- smart-contract audit, monitoring, and emergency pause
- customer disclosure for FX, fees, exit delay, and insolvency risk
- regulatory classification in every launch jurisdiction

The plan should proceed to mainnet or live funds only after these roles are
legally and contractually resolved and the production gate is approved.

## Package Boundary

| Area                                                        | Responsibility                                                                                                                                                  |
| ----------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `packages/shared-ts/src/stablecoin-cards`                   | Stablecoin asset, escrow intent, reserve state, card lifecycle, authorization, ledger transition, and event types.                                              |
| `packages/wallet/src/SeamsWeb/stablecoinCards`              | Enrollment, escrow deposit, card controls, reserve display, exit, and transaction history UI.                                                                   |
| `packages/wallet-server/src/router/domains/stablecoinCards` | Authorization ledger, policy checks, Airwallex adaptor port and implementation, settlement orchestration, reconciliation, and audit records.                    |
| `apps/web-server/src`                                       | Runtime composition, raw-body remote authorization and Airwallex webhook routes, FX, redemption, bank-funding clients, credentials, and provider-facing routes. |
| `crates/` or `wasm/` selected after chain decision          | Minimal card-reserve escrow contract and canonical instruction encoding.                                                                                        |
| `tests/unit`                                                | Boundary parser, intent digest, authorization, ledger, adaptor, replay, and customer-facing state-projection tests.                                             |
| `tests/e2e/intended-behaviours`                             | Deterministic fake-provider enrollment, deposit, issue, purchase, reversal, refund, freeze, close, exit, and resumability contracts.                            |
| Dedicated opt-in provider integration suite                 | Credentialed Airwallex authentication, card, simulation, webhook, and Remote Authorization contract.                                                            |

Reuse existing intent digest, branded domain ID, Result union, MPC signing,
idempotency, and webhook verification patterns. Keep stablecoin-card records
separate from console billing and embedded checkout records.

## UX-Led Testnet Build Order

Build the target experience against deterministic fake boundaries first. Each
later phase replaces one fake with an Airwallex sandbox or onchain testnet
boundary while preserving the customer-facing state contract. This exposes UX
and lifecycle mistakes before the team commits to a card program, chain, or
settlement architecture.

### Phase 0: Product, Program, And Testnet Decisions

- choose one target customer profile and one test jurisdiction
- choose one testnet chain, one mock stablecoin, and one card billing currency
- obtain written Airwallex guidance for the intended consumer card program,
  cardholder type, supported regions, Connected Accounts, Remote Authorization,
  secure card display, and PLP
- choose the testnet settlement-attestation trust model
- define the reserve-exit tail, late-refund destination, and simulated corporate
  loss-reserve policy
- freeze the user-facing balance terms, customer-state table, and setup sequence
- define the fees, FX, privacy, issuer, and exit disclosures required in the
  prototype
- obtain Airwallex sandbox credentials without committing them
- reject production provider hosts, mainnet assets, live off-ramp credentials,
  and real bank destinations in the runtime type

Phase exit:

- the happy path and every pending, failure, refund, and exit state have an owner
  and recovery action
- no target UX depends on an unconfirmed Airwallex capability
- the prototype can use a precise fake for Connected Accounts, PLP, KYC review,
  secure card display, and disputes

### Phase 1: Interactive Fake Vertical Slice

- define precise eligibility, card, reserve, provider-limit, transaction, refund,
  exit, customer-state, and ledger unions
- add branch-specific builders and boundary parsers
- implement deterministic fake card provider, reserve, chain confirmation,
  authorization ledger, conversion, treasury, and dispute boundaries
- build the wallet-owned compact card home and all setup, reserve, card-detail,
  activity, freeze, close, refund, dispute, and exit surfaces
- make pending operations durable and resumable in the fake runtime
- exercise success, cancellation, timeout, decline, reversal, expiry, late refund,
  provider outage, and reconciliation-delay states
- add permanent testnet marking and non-sensitive fake card display
- verify keyboard-only completion, focus restoration, 320 CSS-pixel reflow, 200%
  zoom, reduced motion, long labels, and right-to-left structure

Phase exit:

- a new customer completes the complete flow without external credentials
- every retry is idempotent and no UI action can create duplicate value
- a customer can identify `Available to spend`, explain where the stablecoin is,
  distinguish authorization from settlement, and explain the exit delay
- the fake provider lifecycle contract passes in the intended-behaviour suite

### Phase 2: Thin Airwallex Sandbox Slice

- implement strict sandbox configuration, authentication, token refresh, and a
  read-only balance probe
- use one sandbox organisation, account, and Individual cardholder
- normalize documented `INCOMPLETE`, `PENDING`, `READY`, and `DISABLED`
  cardholder states without inventing provider statuses
- issue one personalized sandbox virtual card when the account program permits it
- implement retrieve, freeze, unfreeze, and close
- use Airwallex secure iframe display only when PAN delegation is enabled; retain
  the honest non-sensitive fake state otherwise
- implement authorization, capture, reversal, expiry, and refund simulations
- ingest signed Airwallex webhooks through a durable inbox and reconcile reordered
  provider events
- preserve separate lifecycle, card-transaction, and transaction-event IDs
- keep reserve, conversion, bank, PLP, and dispute behavior fake in this phase

Phase exit:

- Airwallex card and transaction outcomes project into the same UI states used by
  the fake provider
- the product clearly labels every capability that the self-service sandbox cannot
  prove
- application storage, logs, and analytics contain no PAN, CVV, provider bearer
  token, or raw identity document

### Phase 3: Testnet Escrow And Reserve

- deploy one mock stablecoin and minimal card-reserve escrow on the chosen testnet
- allowlist only the chosen chain, token, escrow, and settlement-vault addresses
- define canonical deposit, allocation, settlement, refund, and release
  instructions with replay protection
- sign the exact reserve deposit through the existing passkey and MPC path
- reconcile observed, confirmed, and reorged chain events
- make a confirmed allocation drive the same deposit and balance UI proven in
  Phase 1
- synchronize a fake provider limit and keep the card unavailable until both
  reserve and limit projections are ready
- prove conservation, authorization, settlement, refund, and release invariants
- use a testnet settlement multisig with no production treasury authority

Phase exit:

- submitted or reorged deposits never create spendable reserve
- a confirmed deposit creates one allocation and one resumable customer operation
- duplicate chain events, settlement instructions, and release instructions cannot
  duplicate value

### Phase 4: Delegated Authorization And Card Activity

- enable Airwallex Remote Authorization Version 2 when the sandbox account permits
  it
- explicitly configure and read back `DECLINED` as the failure default before any
  test card becomes spendable
- verify the Airwallex nonce signature and echo the exact transaction-event ID
- resolve one active card to one ready reserve allocation
- use one USD billing currency and mock-USDC obligation for the first critical
  path, or a preloaded bounded quote with no authorization-time network call
- atomically create one hold and respond within the 2.5-second provider window
- reconcile the separate Seams decision and final Airwallex authorization result
- reconcile dual-message and single-message transactions, clearing, reversal,
  expiry, incremental authorization, and partial capture
- project each provider result into the activity timeline and customer-facing
  recovery state
- configure the provider hard limit no higher than the buffered reserve exposure

Phase exit:

- repeated Remote Authorization requests return the stored decision without a
  second hold
- timeout, storage failure, stale price, unknown card, frozen card, invalid
  currency, and insufficient reserve all fail closed
- provider-final decline reconciles the hold before the UI restores availability

### Phase 5: Refund, Exit, And Simulated Treasury

- separate customer reserve postings from corporate treasury postings
- create per-transaction customer obligations and batch simulated treasury
  redemption, bank receipt, and PLP or Airwallex Wallet replenishment
- simulate active-card refunds back into the reserve
- simulate post-close refunds into the customer wallet or claimable refund balance
- implement the fake dispute lifecycle and keep it clearly outside the Airwallex
  sandbox proof boundary
- freeze the card on exit request and expose open authorization, clearing, refund,
  and dispute exposure
- apply the defined customer reserve tail and simulated corporate loss reserve
- release only the amount made eligible by the exit policy
- exercise conversion, provider, banking, chain, and reconciliation outage recovery

Phase exit:

- every refund has one final customer destination
- exit progress explains what remains open and never invents a release date
- one treasury batch reconciles exactly to its customer settlement obligations
- a late force-post, chargeback, or refund cannot create duplicate or unexplained
  customer value

### Phase 6: UX And Pilot Readiness Evidence

- run deterministic intended-behaviour contracts against the fake provider
- run credentialed Airwallex checks in a dedicated opt-in integration suite
- verify every customer-state row with a component or browser contract
- test interruption and resume across reload, host-site change, and linked-device
  sign-in
- test screen-reader announcements, keyboard order, focus trapping, reduced motion,
  320 CSS-pixel reflow, 200% zoom, long translated labels, and right-to-left layout
- measure setup completion, deposit confirmation latency, authorization latency,
  provider-limit synchronization, refund latency, exit duration, and support-path
  entry
- run comprehension walkthroughs for reserve custody, fiat card execution,
  authorization versus settlement, fees, and exit timing
- produce funds-flow, trust-boundary, ledger, reconciliation, security, incident,
  support, and test evidence for partner and regulatory diligence

Phase exit:

- the complete target UX works with fake infrastructure and the supported
  Airwallex sandbox subset
- every sandbox limitation and deferred production dependency is visible in the
  evidence pack
- smart-contract property and invariant tests pass; independent audit and formal
  verification remain production-candidate gates after the contract design is
  stable

## Testnet Acceptance Criteria

- one confirmed mock-stablecoin deposit produces one escrow allocation
- duplicate chain or Airwallex events cannot create duplicate value
- Airwallex holds no customer stablecoin reserve
- Airwallex Remote Authorization, when enabled, creates one atomic Seams ledger
  hold and preserves the separate provider-final result
- configured and read-back timeout behavior produces a decline
- card succeeds within available reserve and declines above it
- clearing consumes the exact settled obligation and releases unused hold
- clearing creates one constrained escrow debit to the settlement multisig
- one reconciled redemption and bank-funding batch replenishes the simulated
  Airwallex funding pool exactly once
- reversal and expiry release the correct hold
- an active-card refund creates one escrow credit; a post-close refund creates one
  wallet or claimable-refund credit under disclosed FX and fees
- exit freezes the card and releases only unencumbered reserve
- Airwallex outage cannot transfer escrowed stablecoin
- Seams application code never handles PAN or CVV
- every movement links to chain, authorization, Airwallex, redemption, bank, and
  settlement evidence
- no testnet path accepts a mainnet asset, live Airwallex credential, production
  off-ramp credential, or real bank destination
- every customer-facing state in the target UX has a deterministic fake-provider
  contract and one valid recovery action
- card setup, reserve funding, activity, refund, and exit remain resumable after
  reload without creating duplicate operations
- the target UX passes keyboard, focus, screen-reader, 320 CSS-pixel reflow, 200%
  zoom, reduced-motion, long-label, and right-to-left checks

## Deferred Production Activation Gate

Production work begins only after all required evidence exists:

- a written jurisdiction-by-jurisdiction regulatory classification
- required Seams registrations, licences, approvals, or a legally sufficient
  licensed-partner structure
- Airwallex production program approval and agreed responsibility matrix
- approved bank, redemption, and Airwallex funding-pool relationships
- documented working-capital, reserve, liquidity, and loss-absorption policy
- audited and formally verified mainnet escrow contract
- production settlement-multisig ceremony and key-management policy
- AML, sanctions, KYC/KYB, travel-rule, fraud, dispute, and reporting controls
- independent security assessment of authorization, treasury, and reconciliation
- tested incident response, business continuity, customer support, and reserve
  exit procedures
- executive approval of the production risk and capital model

Production activation is a separate implementation change. It must introduce
precise production domain types, configuration, credentials, contracts, and
tests rather than widening the testnet runtime with permissive flags.

## Open Decisions

- Which chain should host the first escrow contract?
- Which exact stablecoin contract is supported?
- Which Airwallex consumer program, account, Connected Account, and PLP
  configuration supports the first cardholders?
- What Airwallex PLP Settlement Account or Wallet balance and external liquidity
  buffer backs peak spend?
- Which redemption venues provide resilient settlement without becoming a
  single critical dependency?
- How long must a card remain frozen before reserve exit?
- How are force-posts and chargebacks covered after exit?
- Which authority can debit escrow for validated settlement?
- Should the contract be immutable, upgradeable under delay, or replaceable by
  versioned allocations?
- What emergency pause and recovery powers are acceptable?
- Which onchain commitments should represent offchain authorization-ledger
  state?
- How are FX buffer, spread, network fees, and refund conversion disclosed?
- Which bank account is approved to fund the Airwallex funding pool?
- Which Seams legal entity holds Airwallex, Circle Mint or off-ramp, banking,
  card program, and settlement treasury relationships?
- Which Japanese classifications apply to escrow control, stablecoin management,
  conversion, redemption, funds transfer, and card settlement?
- Does the payment-only exception apply to any part of the final flow?
- Which registrations or licensed-partner relationships are required before
  mainnet deployment and customer solicitation?

## Recommended Near-Term Position

For the product portfolio:

```text
Embedded checkout lets customers pay participating merchants with existing
cards. Stablecoin-linked virtual cards remain a deferred production product
while Seams proves the target experience and simulated operating path on testnet.
```

For the active technical roadmap:

```text
Prove the complete wallet experience against deterministic fake boundaries.
Replace the card boundary with the supported Airwallex sandbox subset, then add
testnet escrow, delegated authorization, and simulated batched treasury. Keep
mainnet and live payment paths structurally unavailable until the production
regulatory gate is satisfied.
```

## References

- [Airwallex: how Issuing works](https://www.airwallex.com/docs/issuing/how-airwallex-issuing-works)
- [Airwallex consumer cards](https://www.airwallex.com/docs/issuing/get-started/create-cards/create-consumer-cards)
- [Airwallex cardholder types](https://www.airwallex.com/docs/issuing/get-started/create-cardholders/cardholder-types)
- [Airwallex cardholder statuses](https://www.airwallex.com/docs/issuing/get-started/create-cardholders/cardholder-statuses)
- [Airwallex secure card-detail iframes](https://www.airwallex.com/docs/issuing/manage-cards/retrieve-sensitive-card-details/secure-iframes)
- [Airwallex Issuing funding sources and PLP](https://www.airwallex.com/docs/issuing/get-started/fund-your-issuing-balance)
- [Airwallex transaction lifecycle](https://www.airwallex.com/docs/issuing/transactions/transaction-lifecycle)
- [Airwallex sandbox environment](https://www.airwallex.com/docs/developer-tools/sandbox-environment)
- [Airwallex Remote Authorization](https://www.airwallex.com/docs/issuing/card-controls/remote-authorization)
- [Airwallex: configure Remote Authorization](https://www.airwallex.com/docs/issuing/card-controls/remote-authorization/configure-remote-authorization)
- [Airwallex connected-account wallets and funds flow](https://www.airwallex.com/docs/connected-accounts/about/wallets-and-funds-flow)
- [Circle Mint](https://developers.circle.com/circle-mint)
- [Japan FSA FinTech Support Desk](https://www.fsa.go.jp/en/news/2018/20180717.html)
- [Japan FSA list of registered financial institutions](https://www.fsa.go.jp/en/regulated/licensed/index.html)
- [Visa: stablecoin-linked cards and money movement](https://www.visa.com/en-us/thought-leadership/innovation/stablecoin-linked-cards-monetize-money-movement)
- [Visa: stablecoins and the future of onchain finance](https://corporate.visa.com/en/solutions/crypto/stablecoins/stablecoins-and-the-future-of-onchain-finance.html)
- [Visa: B2B stablecoin settlement](https://corporate.visa.com/en/solutions/commercial-solutions/knowledge-hub/b2b-stablecoin-payments.html)
- [Mastercard digital asset and stablecoin solutions](https://www.mastercard.com/global/en/business/payments/consumer-payments/next-gen-payments/digital-asset-solutions.html)

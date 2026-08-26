---
title: Shopping wallet apps
description: Build a user-facing wallet that holds stablecoins and pays independent merchants through direct transfers or an optional virtual card.
---

# Shopping wallet apps

A shopping wallet is a user-facing application, such as an iOS wallet, that
holds stablecoins or other supported assets and helps its owner pay across many
independent merchants.

The wallet can choose the payment rail that the merchant supports:

```text
Merchant accepts stablecoin
  -> pay directly from the wallet

Merchant accepts cards only
  -> pay with an optional stablecoin-linked virtual card
```

The virtual card extends reach to existing ecommerce checkouts. It is an
outbound spending credential for the wallet owner. A store gains little from
issuing a card solely so a shopper can use it at that same store.

## Product responsibilities

- show wallet funds, card reserve, pending holds, and available spend separately
- support direct stablecoin payment where the merchant accepts it
- allocate a bounded reserve before enabling card spending
- expose authorization, capture, reversal, refund, freeze, and close states
- disclose fees, exchange rates, provider limits, and reserve-release timing
- keep PAN and CVV inside provider-hosted secure surfaces
- reconcile wallet, issuer, and settlement evidence without duplicating value

Virtual-card issuance adds cardholder onboarding, fraud, chargebacks, liquidity,
support, reconciliation, and regulatory responsibilities. It is an optional
product for qualified wallet operators with demonstrated external-spending
demand.

Read the [stablecoin-linked virtual card plan](https://github.com/web3-authn/sdk/blob/main/docs/stablecoin-linked-virtual-card.md)
for the deferred testnet and provider design.

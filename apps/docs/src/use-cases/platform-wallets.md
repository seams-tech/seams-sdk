---
title: Platform wallets
description: Provision secure, recoverable wallets for users of marketplaces, trading platforms, games, payout products, and account-based applications.
---

# Platform wallets

A platform wallet is a persistent wallet attached to an application account.
The platform provisions it during onboarding, and the user returns to it for
balances, assets, payments, trades, transfers, rewards, or payouts.

```text
Platform account
  -> embedded wallet
  -> balance or owned assets
  -> repeated signing or payment activity
  -> recovery, policy, and audit
```

## Strong fits

- Ecommerce marketplaces with buyers, sellers, balances, escrow, and payouts.
- Trading and investment platforms.
- Games and digital-asset platforms.
- Creator and gig-economy platforms.
- Stablecoin account and remittance applications.
- Loyalty, rewards, and store-credit networks.
- Agentic commerce and automated purchasing platforms.
- Applications that sponsor or automate onchain operations.

These products maintain an ongoing financial relationship with their users. A
balance, asset, payout, position, reward, or delegated budget persists after a
single session.

## What Seams provides

- wallet provisioning linked to an application account
- passkey and application-native authentication
- recovery and linked-device flows
- threshold signing and self-hostable infrastructure
- sponsored and repeated signing sessions
- scoped, expiring, and revocable authority
- intent-bound approvals and audit evidence
- export or transfer of wallet control where supported

## Qualification

Platform wallets are a strong fit when users hold value or assets between
sessions, perform repeated financial or onchain actions, or need constrained
automation. A conventional store collecting a one-time payment can use the
shopper's existing wallet and does not need to provision another one.

Start with [embedded wallets](/guides/embedded-wallets) and [create a
wallet](/getting-started/create-wallet).

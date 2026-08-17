---
title: Guides
description: Task-focused guidance for the boundaries around Seams wallet integrations.
---

# Guides

Start with a runnable example, then use a guide for the decisions and safety
checks around that flow. Guides keep the application boundary clear without
repeating the full SDK reference.

## Start with an example

- [Wallet setup and authentication](/examples/wallet-setup-and-authentication):
  configure the provider, register a wallet, and unlock it.
- [Signing](/examples/signing): submit a NEAR transaction, sign a NEP-413
  message, or execute an EVM-family transaction.
- [Advanced wallet operations](/examples/advanced-wallet-operations): link a
  device, recover a wallet, or export a key.
- [UI customization](/examples/ui-customization): keep app-owned and
  wallet-owned surfaces in sync.

## Keep building

- [Authentication](/guides/authentication) — choose factors and handle
  cancellation, expiry, and retry states.
- [Embedded wallets](/guides/embedded-wallets) — keep wallet credentials and
  signing runtime on the wallet origin.
- [Policies and mandates](/guides/policies-and-mandates) — bind each operation
  to an exact subject, target, and budget.
- [Wallet sessions and signing lanes](/guides/wallet-sessions-and-signing-lanes)
  — carry exact session identity into signing.
- [Delegated agents](/guides/delegated-agents) and [linked
  devices](/guides/linked-devices) — add independently revocable authority.
- [Recovery, export, and rotation](/guides/recovery-export-and-rotation) —
  treat high-impact account changes as fresh operations.
- [Theming](/guides/theming) — align app-owned and wallet-owned surfaces.

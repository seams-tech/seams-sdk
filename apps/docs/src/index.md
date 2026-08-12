---
title: Start here
description: Install Seams, create an embedded wallet, sign a first operation, then add recovery or delegated authority.
---

# Start here

Build the shortest working wallet path first: configure the isolated wallet
origin, register a user-controlled wallet, and sign one policy-bound operation.
Add recovery, delegation, and rotation after that path works end to end.

## Install

Add the SDK to the application that owns the account experience.

```sh
pnpm add @seams/sdk
```

## Configure the wallet

Wrap the application once with `SeamsWebProvider`. This complete example
includes a minimal `WalletApp`; replace it with your product UI.

<<< ./examples/setup.tsx

Keep the wallet service and SDK assets on the configured wallet origin. The
application origin should not mirror those protected runtime routes.

## Create and sign

```text
create wallet -> approve intent -> sign with policy -> audit
```

1. [Create a wallet](/getting-started/create-wallet) and handle every
   registration result branch.
2. [Sign with policy](/getting-started/sign-with-policy) using an exact wallet
   session and account or chain reference.
3. [Add recovery, export, or rotation](/guides/recovery-export-and-rotation)
   when the product needs a controlled return or exit path.
4. [Delegate or rotate](/getting-started/delegate-or-rotate) when another
   device or agent needs independently revocable authority.

## Choose the next section

- [Guides](/guides/) cover authentication, embedded wallets, policies,
  sessions, devices, delegation, recovery, and theming.
- [SDK reference](/reference/) documents the supported public package
  entrypoints and result unions.
- [Concepts and security](/concepts/) explains custody, policy, sessions,
  threshold signing, and Router A/B.
- [Deploy and operate](/deploy-and-operate/) covers hosted integration,
  security boundaries, production checks, observability, and troubleshooting.
- [Use cases](/use-cases/) applies the same authority model to agents, access,
  shipping, and embedded devices.

For production integration, review the [hosted wallet
boundary](/deploy-and-operate/hosted-integration) and [production
checklist](/deploy-and-operate/production-checklist) before launch.

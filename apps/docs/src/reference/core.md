---
title: Core browser SDK
description: Public classes, capabilities, builders, and result types exported from the main @seams/wallet entrypoint.
---

# Core browser SDK

Import the framework-neutral browser API from `@seams/wallet`.

```ts [Import example]
import { SeamsWeb, type SeamsConfigsInput } from '@seams/wallet';
```

## Primary surface

`SeamsWeb` is the browser client. Its capability groups keep lifecycle inputs
explicit:

| Capability        | Responsibility                                                               |
| ----------------- | ---------------------------------------------------------------------------- |
| `registration`    | Register a wallet or add a signer.                                           |
| `auth`            | Unlock, lock, restore, and inspect wallet sessions.                          |
| `near`            | Sign and send NEAR transactions, delegate actions, and NEP-413 messages.     |
| `evm` and `tempo` | Register and sign for EVM-family networks and manage threshold sessions.     |
| `recovery`        | Configure recovery, synchronize account state, and rotate recovery material. |
| `devices`         | Start, approve, and inspect linked-device flows.                             |
| `keys`            | Run freshly authorized export flows.                                         |

Signing functions require an exact wallet-session reference and chain or
account subject. Create those references with the builders from
[`@seams/wallet/advanced`](/reference/advanced); avoid passing raw identity strings
through an application.

## Public values and types

The main entrypoint includes:

- `SeamsWeb`, `PASSKEY_MANAGER_DEFAULT_CONFIGS`, and `buildConfigsFromEnv`;
- registration intent and signer-selection types;
- `RegistrationResult`, `LoginResult`, `LoginAndCreateSessionResult`,
  `WalletSession`, and `ActionResult`;
- account and action types, including `toAccountId` and `ActionType`;
- wallet-flow event constructors, phases, and event unions;
- device-linking and NEP-413 result types;
- hosted auth-menu request builders and boundary-safe message types.

## Lifecycle rule

Obtain a successful registration or login result, retain its exact wallet
identity, create a wallet session, then pass a reference to each signing call.
Treat every public result as a discriminated union and handle all branches.

Continue with [results and recoverable errors](/reference/results-and-errors) or
follow the [first-signing guide](/getting-started/sign-with-policy).

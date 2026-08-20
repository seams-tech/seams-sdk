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

| Capability     | Responsibility                                                               |
| -------------- | ---------------------------------------------------------------------------- |
| `registration` | Register a wallet, add a signer, await NEAR provisioning.                    |
| `auth`         | Unlock, lock, restore, and inspect wallet sessions.                          |
| `near`         | Sign and send NEAR transactions, delegate actions, and NEP-413 messages.     |
| `evm`          | Sign and execute EIP-1559 transactions on configured EVM chains.             |
| `tempo`        | Sign and execute EIP-2718 Tempo transactions, and manage the fee token.      |
| `recovery`     | Configure recovery, synchronize account state, and rotate recovery material. |
| `devices`      | Start, approve, and inspect linked-device flows.                             |
| `keys`         | Run freshly authorized export flows.                                         |

`evm` and `tempo` mirror each other — `signTransaction`, `executeTransaction`,
and an `advanced` group for post-broadcast lifecycle reporting. They stay
separate because the envelopes differ: a Tempo transaction is EIP-2718 and its
signed result carries `senderHashHex`, an EVM transaction is EIP-1559 and
carries `txHashHex`.

## Naming the subject and the chain

Every operation names the wallet it authorizes and, for EVM-family calls, the
chain it targets. Both are optional:

- Omit `walletSession` and the call resolves the **authenticated** wallet.
  Supply a `WalletSessionRef` — or just a wallet id — to name an exact one,
  which is what an application managing several wallets should do.
- Omit `nearAccount` and NEAR calls resolve the authenticated wallet's account.
  A bare account id is accepted.
- `chainTarget` accepts a configured network slug such as `'tempo-testnet'`.
  Resolution requires exactly one configured match; a selector matching two
  throws and names both rather than picking one.

The exact-reference builders (`walletSessionRefFromSession`,
`nearAccountRefFromAccountId`, `thresholdEcdsaChainTargetFromConfig`) are
exported from this entrypoint and from `@seams/wallet/react`.

## Public values and types

The main entrypoint includes:

- `SeamsWeb`, `PASSKEY_MANAGER_DEFAULT_CONFIGS`, and `buildConfigsFromEnv`;
- `defineSeamsConfig` and `seamsTestnetConfig`, which take the values an
  application must supply and default the rest;
- the boundary reference builders and their types (`WalletSessionRef`,
  `NearAccountRef`, `ThresholdEcdsaChainTarget`, `WalletId`);
- action builders — `functionCall`, `transfer`, `stake`, `addKey`,
  `deleteKey`, `deleteAccount`, `createAccount`, `deployContract`;
- `logWalletEvents`, a ready-made `onEvent` handler;
- registration intent and signer-selection types;
- `RegistrationResult`, `LoginResult`, `LoginAndCreateSessionResult`,
  `WalletSession`, and `ActionResult`;
- account and action types, including `toAccountId` and `ActionType`;
- wallet-flow event constructors, phases, and event unions;
- Google email-OTP wallet-auth flow types;
- device-linking and NEP-413 result types;
- hosted auth-menu request builders and boundary-safe message types.

## Lifecycle rule

Obtain a successful registration or login result and retain its `walletId` —
that is the stable identifier every later operation uses. Signing calls resolve
the authenticated wallet on their own; name one explicitly when your application
holds more than one at a time. Treat every public result as a discriminated
union and handle all branches.

Continue with [results and recoverable errors](/reference/results-and-errors) or
follow the [first-signing guide](/getting-started/sign-with-policy).

---
title: Custody model
description: Understand why isolated wallet and split-server infrastructure cannot produce a wallet signature alone.
---

# Custody model

Seams is non-custodial because hosted infrastructure cannot produce wallet
signatures or export wallet keys by itself. Signing requires holder-side
participation, Wallet Session admission, policy checks, replay checks, quota
checks, budget admission, and the correct server-side signing material for the
selected lane.

Export uses a separate, freshly authorized flow. Ordinary signing consumes
shares and presignature state; it does not reconstruct the full private key.

## Who holds what

| Location                | May hold                                                                           | Must never hold                                                                                       |
| ----------------------- | ---------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| App origin              | Public wallet ids, request intents, non-secret SDK state.                          | Holder shares, server shares, PRF outputs, Email OTP secret material, VoiceID templates, root shares. |
| Wallet iframe           | Wallet UI state, encrypted IndexedDB records, session markers.                     | Server root shares, Deriver A/B plaintext, unrelated wallet-origin records.                           |
| Browser signing workers | Hot holder material, compact lifecycle inputs, operation-local secrets.            | Deriver A/B root shares, joined server contribution.                                                  |
| Email OTP worker        | Email OTP factor-derived secret material and hot signing handles.                  | Plaintext export output outside the authorized export flow.                                           |
| Router                  | Public routing metadata, policy decisions, Wallet Session admission, replay state. | Plaintext holder shares, root shares, joined wallet private keys.                                     |
| Deriver A               | A-side sealed root share and A-side protocol state.                                | B-side root share, joined root, joined wallet key.                                                    |
| Deriver B               | B-side sealed root share and B-side protocol state.                                | A-side root share, joined root, joined wallet key.                                                    |
| SigningWorker           | Activated server signing material and one-use presignature state.                  | Client holder share, exported wallet key, Deriver A/B root custody shares.                            |

## Custody invariants

### Tenant derivation roots

R120 gives each tenant an independently randomized server-side derivation root.
Deriver A and B each retain only their own encrypted operational share in a
role-private D1 store, with a separately encrypted managed backup in that role's
R2 bucket. Router coordinates public lifecycle state and receipts.

These tenant-root shares support derivation ceremonies. Wallet custody seeds,
client signing roots, and provisioned holder/SigningWorker signing shares have
separate custody paths. Refreshing the tenant-root shares preserves the root
and wallet identities; it does not replace a wallet custody seed or rekey a
wallet. See [tenant-root backups](/deploy-and-operate/tenant-root-backups).

### Signing and authorization

1. Router cannot sign by itself.
2. A single Deriver cannot derive the full server contribution by itself.
3. SigningWorker cannot export wallet keys.
4. App-origin code receives public results and explicit export results only.
5. Agents and linked devices receive lane-scoped authority.
6. Revocation, expiry, and budget exhaustion are checked before signing work.

## Recovery and portability

Users can recover through the auth methods and recovery material configured for
their wallet. Export is a sensitive operation with fresh authorization, route
policy, and exact lane binding.

R121's planned tenant-controlled recovery restores the exact logical tenant
root into an empty destination with a fresh custody lineage. R122's planned
portability moves wallet inventory and signing participants, with explicit
identity mapping and cutover. Restoring a tenant root alone does not move wallet
records, signing lanes, domains, or permissions. See
[recovery and portability](/deploy-and-operate/recovery-and-portability) for
availability and artifact boundaries.

Read next:

- [Wallet Iframe](/concepts/custody/wallet-iframe)
- [Recovery And Export](/concepts/custody/recovery-and-export)

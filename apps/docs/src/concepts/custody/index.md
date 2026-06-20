---
title: Custody Model
---

# Custody Model

Seams is non-custodial because hosted infrastructure cannot produce wallet
signatures or export wallet keys by itself. Signing requires holder-side
participation, Wallet Session admission, policy checks, replay checks, quota
checks, budget admission, and the correct server-side signing material for the
selected lane.

Export uses a separate, freshly authorized flow. Ordinary signing consumes
shares and presignature state; it does not reconstruct the full private key.

## Who Holds What

| Location | May hold | Must never hold |
| --- | --- | --- |
| App origin | Public wallet ids, request intents, non-secret SDK state. | Holder shares, server shares, PRF outputs, Email OTP secret material, VoiceID templates, root shares. |
| Wallet iframe | Wallet UI state, encrypted IndexedDB records, session markers. | Server root shares, Deriver A/B plaintext, unrelated wallet-origin records. |
| Browser signing workers | Hot holder material, client HSS material handles, operation-local secrets. | Deriver A/B root shares, joined server contribution. |
| Email OTP worker | Email OTP factor-derived secret material and hot signing handles. | Plaintext export output outside the authorized export flow. |
| Router | Public routing metadata, policy decisions, Wallet Session admission, replay state. | Plaintext holder shares, root shares, joined wallet private keys. |
| Deriver A | A-side sealed root share and A-side protocol state. | B-side root share, joined root, joined wallet key. |
| Deriver B | B-side sealed root share and B-side protocol state. | A-side root share, joined root, joined wallet key. |
| SigningWorker | Activated server signing material and one-use presignature state. | Client holder share, exported wallet key, Deriver A/B root custody shares. |

## Custody Invariants

1. Router cannot sign by itself.
2. A single Deriver cannot derive the full server contribution by itself.
3. SigningWorker cannot export wallet keys.
4. App-origin code receives public results and explicit export results only.
5. Agents and linked devices receive lane-scoped authority.
6. Revocation, expiry, and budget exhaustion are checked before signing work.

## Recovery And Portability

Users can recover through the auth methods and recovery material configured for
their wallet. Export is a sensitive operation with fresh authorization, route
policy, and exact lane binding. Self-hosting or migration depends on
signing-root custody and export ceremonies.

Read next:

- [Wallet Iframe](/concepts/custody/wallet-iframe)
- [Recovery And Export](/concepts/custody/recovery-and-export)

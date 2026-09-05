---
title: Glossary
description: Define the wallet, custody, policy, session, signing, and Router A/B terms used throughout Seams documentation.
---

# Glossary

| Term                  | Meaning                                                                                                                                               |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| Auth plane            | A boundary for one kind of authority, such as app login, Wallet Session, capability grant, delegation grant, or API credential.                       |
| Credential            | A proof input used by policy, such as passkey, Email OTP, VoiceID, device proof, org role proof, wallet proof, or configured external credential.     |
| Deriver A / Deriver B | Split server roles used during derivation-time operations such as registration, export, refresh, recovery, and activation.                            |
| Delegated-agent lane  | A distinct signing lane issued to an agent or service under policy.                                                                                   |
| Holder share          | The user, device, agent, or auth-method side of a threshold key.                                                                                      |
| Linked-device lane    | A distinct signing lane issued to another user-controlled device.                                                                                     |
| Mandate               | A scoped, signed authority object that defines what a subject may do under policy.                                                                    |
| Policy epoch          | Versioned policy state used for revocation-sensitive decisions.                                                                                       |
| Router                | The public service boundary for auth, policy, replay, quota, budget, and request routing.                                                             |
| Server share          | The hosted or self-hosted server side of a threshold key.                                                                                             |
| Tenant derivation root | Independently randomized server-side derivation origin for one tenant, held as separate A/B operational shares. |
| Tenant-root operational share | One Deriver's secret share of the tenant root; refresh changes the pair while preserving the effective root. |
| Share epoch | Metadata identifying an operational-share generation; it is not key material. |
| Custody lineage | The identity of one tenant-root custody lifecycle, used to isolate commands and replay state across restored destinations. |
| Managed tenant-root backup | A service-held encrypted role-share backup used by the authorized managed restore path. |
| Tenant recovery set | Planned tenant-held A/B recovery packages and a public manifest for exact-root restoration, separate from wallet portability. |
| SigningWorker         | The hot normal-signing server role that uses activated server signing material.                                                                       |
| Wallet Session quota  | A bounded reusable allowance with TTL and remaining uses for signing.                                                                                 |
| Capability grant      | One-operation authority bound to an exact capability and intent.                                                                                      |
| Signing lane          | The exact signing capability selected for one operation.                                                                                              |
| Signed mandate        | A user, org, wallet, device, or agent authority object bound to policy.                                                                               |
| Streaming Yao         | The fixed-circuit two-party computation used by Deriver A and Deriver B for Ed25519 lifecycle ceremonies. Garbled tables stream directly from A to B. |
| Threshold session     | Curve/session-specific signing authority.                                                                                                             |
| Typed intent digest   | Canonical digest of the exact action being approved or executed.                                                                                      |
| Wallet Session        | A wallet-user operation authority used by signing and budget routes.                                                                                  |

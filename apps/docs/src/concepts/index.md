---
title: Concepts
---

# Concepts

Seams is key, credential, and policy infrastructure for digital authority. It
helps applications prove who is acting, bind what they approved to a typed
intent, enforce policy before execution, and preserve an audit trail afterward.

```text
Prove who is acting.
Prove what they approved.
Enforce what they can do.
```

Wallet signing is the first execution surface. The same model extends to payment
rails, merchant APIs, marketplace APIs, agent tools, and delegated device
actions.

## System Layers

| Layer | Role |
| --- | --- |
| Proof layer | Passkeys, Email OTP, VoiceID, device proof, org proof, wallet proof, and configured external credentials. |
| Policy and mandate layer | Signed mandates, typed intent digests, policy epochs, budgets, expiry, revocation, and audit state. |
| Key infrastructure | Holder shares, server shares, Router A/B, SigningWorker, export, recovery, delegation, and rotation. |
| Enforcement gateway | Allows, denies, escalates, or requires human approval before money, authority, inventory, or API state moves. |
| Execution adapters | Wallet signatures, payments, merchant APIs, marketplaces, agent tools, and future device actions. |

## Reading Order

1. [Architecture](/concepts/architecture) for the source-of-truth component map.
2. [Policy](/concepts/policy/) for mandates, proofs, and authorization.
3. [Custody](/concepts/custody/) for who can hold or open key material.
4. [Threshold Signing](/concepts/threshold-signing/) for Router A/B and HSS.
5. [Sessions](/concepts/sessions/) for signing lanes and bounded runtime authority.
6. [Auth Methods](/concepts/auth-methods/) for passkeys, Email OTP, and VoiceID.
7. [Delegation](/concepts/delegation/) for linked devices, agents, and rotation.
8. [Advanced](/concepts/advanced/) for protocol, ceremony, and deployment details.

## Short Version

Give agents permission to act without giving them unlimited authority.

Define what an agent may do. Bind it to signed intent. Enforce it before money,
inventory, or authority moves.

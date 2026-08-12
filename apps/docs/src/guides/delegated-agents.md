---
title: Delegated agents
description: Issue revocable, policy-bound authority to agents without sharing a user's wallet credential or broad signing power.
---

# Delegated agents

Give an agent its own subject and signing lane. Bind the grant to allowed
operations, targets, budget, expiry, revocation state, and human-approval rules.

## Recommended sequence

1. Authenticate the owner with fresh user presence.
2. Describe the mandate in plain language and typed policy data.
3. Create the delegated signer or lane.
4. Verify public-key and wallet-identity parity where the protocol requires it.
5. Store the grant receipt and expose revocation.
6. Route each agent operation through the same admission and audit boundary as
   normal signing.

Never copy a user's passkey, session token, or unrestricted API credential into
an agent. Revoke a compromised agent lane independently from the owner wallet.

Read [delegated agents](/concepts/delegation/delegated-agents) and [ecommerce
agents](/use-cases/ecommerce-agents).

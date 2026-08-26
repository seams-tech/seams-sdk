---
title: Delegated agents
description: Issue revocable, policy-bound authority to agents without sharing a user's wallet credential or broad signing power.
---

# Delegated agents

Use the [policies and mandates guide](/guides/policies-and-mandates) for the
operation shape, then review [shopping agents](/use-cases/ecommerce-agents) for
a product example. Give each agent an independent subject and signing lane.

## Grant narrow authority

1. Authenticate the owner with fresh user presence.
2. Describe allowed operations, targets, budgets, expiry, revocation, and
   human-approval rules in plain language and typed policy data.
3. Use an independent agent identity and verify the grant receipt.
4. Route each agent operation through the same admission and audit boundary as
   normal signing.

Never copy a user's passkey, session token, private key, or unrestricted API
credential into an agent. The owner wallet remains the payer; the agent's
identity proves who requested the operation. Revoke a compromised agent lane
independently from the owner wallet.

Read [delegated agents](/concepts/delegation/delegated-agents) for the security
model.

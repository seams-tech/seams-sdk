---
title: Delegated Agents
---

# Delegated Agents

Delegated agents receive bounded signing lanes. The lane is tied to mandate
policy, typed intent checks, budget, expiry, revocation state, and audit
requirements.

## Flow

```mermaid
flowchart TD
  Owner["Owner lane<br/>fresh user authorization"] --> Mandate["Mandate policy<br/>approved digest"]
  Owner --> Reshare["Address-preserving lane creation"]
  Reshare --> AgentShare["Agent holder share<br/>encrypted to agent custody"]
  Reshare --> ServerShare["Server share<br/>lane-scoped admission"]
  Mandate --> Admission["Delegated signing admission"]
  AgentShare --> Admission
  ServerShare --> Admission
  Admission --> Sign["Router A/B normal signing"]
```

Every agent signing request must pass lane status, mandate, intent digest,
budget, expiry, idempotency, and replay checks.

## Invariants

1. Agents do not receive wallet private keys.
2. Agents cannot change recovery factors.
3. Agents cannot export wallet keys.
4. Agents cannot sign outside their mandate.
5. Agent revocation does not change the wallet address.

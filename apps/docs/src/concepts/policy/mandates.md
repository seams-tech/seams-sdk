---
title: Mandates
---

# Mandates

A mandate is the authority object for delegated action.

```text
This subject may perform this class of action, under this policy, until this
expiry, within this budget, against this exact intent shape.
```

Mandates are the bridge between user approval and agent execution. They should
be scoped, typed, revocable, and auditable.

## Core Fields

| Field | Role |
| --- | --- |
| Subject | User, org role, wallet, device, agent, or service. |
| Intent shape | The typed action family the mandate may authorize. |
| Constraints | Budget, merchant, recipient, chain, marketplace, geography, time, and risk rules. |
| Policy epoch | Versioned policy state for revocation-sensitive decisions. |
| Expiry | Hard lifetime for the delegated authority. |
| Audit facts | Evidence needed to explain what was allowed or denied. |

## Examples

- A shopping agent may buy one jacket under USD 500 from approved merchants.
- A bidding agent may bid up to a fixed ceiling on one listing.
- A merchant support agent may issue refunds up to a configured amount.
- A backend service may execute one wallet intent under a delegated lane.

Mandates do not replace signing controls. They constrain when signing or another
execution adapter may proceed.

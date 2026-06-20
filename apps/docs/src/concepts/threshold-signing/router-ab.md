---
title: Router A/B
---

# Router A/B

Router A/B is the split-server architecture for derivation-time custody,
SigningWorker activation, and normal signing admission.

## Roles

| Role | Responsibility |
| --- | --- |
| Router | Public API, auth, policy, quota, replay, Wallet Session verification, signing budget, and response binding. |
| Deriver A | A-side server derivation material and A-side proof/output packages. |
| Deriver B | B-side server derivation material and B-side proof/output packages. |
| SigningWorker | Activated server signing material for the normal signing path. |

## Flow Shape

Registration, recovery, export, refresh, rotation, delegation, and activation:

```text
Client -> Router -> Deriver A + Deriver B -> Client or SigningWorker
```

Day-to-day signing:

```text
Client -> Router -> SigningWorker -> Router -> Client
```

Deriver A and Deriver B stay out of the hot path for ordinary signatures.

## Security Claims

Router sees public metadata, route auth, policy state, replay state, signing
budget state, and encrypted role envelopes. Deriver A sees A-side material.
Deriver B sees B-side material. SigningWorker sees activated server signing
material for the selected signing root, key version, lane, and session.

Public clients use Router A/B normal signing surfaces.

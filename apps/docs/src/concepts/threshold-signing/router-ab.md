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

Ed25519 registration, recovery, export, refresh, share provisioning, and
activation:

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

Ed25519 lifecycle ceremonies use Streaming Yao between A and B. ECDSA uses its
strict threshold-PRF and additive-share path. Both curves leave the Derivers
after activation and use Router plus SigningWorker for normal signing.

## Sign-Ready Boundary

Router A/B separates signing authority from signing material readiness.

```text
Wallet Session auth + signingGrantId -> may spend budget
thresholdSessionId + worker material -> may participate in threshold signing
both validated together -> sign-ready
```

The Router owns Wallet Session verification, signing grant budget, quota, replay,
and request admission. The browser worker owns holder-side signing material. The
SigningWorker owns server-side signing material. A public signing route should
only be called after the SDK has selected a lane whose current browser worker
material is runtime-validated for the same Router A/B scope and signing grant.

State names used by the SDK:

| State | Router A/B meaning |
| --- | --- |
| `runtime_validated` | Sign-ready. Auth/grant, threshold identity, budget, Router A/B scope, and worker material are bound together. |
| `restore_available` | Durable worker material exists. The SDK can run restore before signing. |
| `material_hint_unvalidated` | A persisted worker-material handle exists, but the current worker has not validated it. |
| `auth_ready_material_pending` | Wallet Session auth is available, but required holder-side material is missing. |
| `non_signing` | The record is valid for another lifecycle surface and cannot authorize Router A/B signing. |
| `invalid` | Required auth, scope, budget, identity, or material fields are missing or inconsistent. |

Final signing accepts only `runtime_validated`. Any other state must route to
restore, step-up, diagnostics, or failure before a signing request is sent.

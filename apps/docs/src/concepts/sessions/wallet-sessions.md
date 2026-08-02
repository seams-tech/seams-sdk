---
title: Wallet Sessions
---

# Wallet Sessions

Wallet Sessions admit wallet-user operations and signing-budget routes. They are
separate from app sessions.

## Authorization Identities

A Wallet Session quota is a bounded reusable allowance. A capability grant and
grant use identify one authorized operation.

```text
signing lane + walletSessionId + quotaId + thresholdSessionId
```

The wallet id alone is insufficient. The threshold session id alone is
insufficient. Transaction signing needs the exact lane plus the admitted budget.

The identities have distinct roles:

| Field | Meaning |
| --- | --- |
| `thresholdSessionId` | The curve/session material identity for the threshold protocol. It ties protocol state, restored material, and persisted lane records to the same protocol session. |
| `walletSessionId` + `quotaId` | Reusable authorization and server-owned expiry/remaining uses. |
| `CapabilityGrantId` + `CapabilityGrantUseId` | One-operation authority and its atomic use. |

The same threshold session can sign only with an accepted claim bound to the
exact reusable Wallet Session/quota or one-operation capability grant.

## Readiness States

Wallet unlock can create auth-ready state without making a lane immediately
sign-ready.

| State | Meaning | Can sign now? |
| --- | --- | --- |
| Auth-ready | Wallet Session auth, quota, Router A/B scope, and budget metadata exist. | No |
| Restore-ready | Auth-ready state plus durable sealed worker material exists, so an explicit restore phase can run. | No |
| Material pending | A persisted worker-material handle or hint exists, but the current worker has not validated it. | No |
| Sign-ready | Auth/grant, threshold session identity, budget, Router A/B scope, and current worker-owned material have all been validated together. | Yes |

Persisted records are durable hints. They are not durable proof that a browser
worker currently has usable signing material. After reload, reconnect, restore,
bootstrap, or worker restart, the worker must validate the material against the
current session binding before the lane becomes sign-ready.

## Budget Admission

Budget admission happens before signing. It must bind wallet id, lane identity,
threshold session id, Wallet Session/quota identity, expiry, remaining uses, and operation
fingerprint.

Rejected requests should fail before any private Deriver or SigningWorker work
happens.

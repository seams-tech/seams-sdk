---
title: Wallet sessions
description: Admit wallet operations through authenticated sessions with explicit capability readiness, quota, expiry, and refresh.
---

# Wallet sessions

Wallet Sessions admit wallet-user operations and own reusable signing quota. They are
separate from app sessions.

## Authorization identities

A Wallet Session quota is a bounded reusable allowance. An
`AuthorizedOperationId` identifies one exact admitted operation.

```text
authorizationGrantRef + walletSessionId + quotaId + authorizedOperationId + thresholdSessionId
```

The wallet id alone is insufficient. The threshold session id alone is
insufficient. Transaction signing needs the exact lane and authorized operation.

The identities have distinct roles:

| Field                         | Meaning                                                                                                                                                             |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `thresholdSessionId`          | The curve/session material identity for the threshold protocol. It ties protocol state, restored material, and persisted lane records to the same protocol session. |
| `AuthorizationGrantRef`       | Reusable Wallet Session authorization identity.                                                                                                                     |
| `walletSessionId` + `quotaId` | Wallet Session identity and server-owned expiry/remaining uses.                                                                                                     |
| `AuthorizedOperationId`       | Exact reusable or verified-step-up operation admission.                                                                                                             |

The same threshold session can sign only with an authorized operation bound to the
exact reusable authorization/Wallet Session/quota or verified step-up evidence.

## Readiness states

Wallet unlock can create auth-ready state without making a lane immediately
sign-ready.

| State            | Meaning                                                                                                                                                                     | Can sign now? |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------- |
| Auth-ready       | Wallet Session authorization, quota, and Router A/B scope exist.                                                                                                            | No            |
| Restore-ready    | Auth-ready state plus durable sealed worker material exists, so an explicit restore phase can run.                                                                          | No            |
| Material pending | A persisted worker-material handle or hint exists, but the current worker has not validated it.                                                                             | No            |
| Sign-ready       | The exact authorization source, authorized operation, threshold session, quota state, Router A/B scope, and current worker-owned material have all been validated together. | Yes           |

Persisted records are durable hints. They are not durable proof that a browser
worker currently has usable signing material. After reload, reconnect, restore,
bootstrap, or worker restart, the worker must validate the material against the
current session binding before the lane becomes sign-ready.

## Operation admission

Operation admission happens before signing. It validates the wallet, lane,
authorization source, threshold session, and applicable Wallet Session quota,
then records the exact operation fingerprint. The stable fingerprint covers the
capability and operation digests; it excludes rotating authorization, quota,
session, and runtime identities. Existing fingerprints replay without consuming
quota again.

Rejected requests should fail before any private Deriver or SigningWorker work
happens.

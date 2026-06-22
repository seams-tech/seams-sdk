---
title: Wallet Sessions
---

# Wallet Sessions

Wallet Sessions admit wallet-user operations and signing-budget routes. They are
separate from app sessions.

## Signing Grants

A signing grant is a bounded allowance for a selected signing lane. It carries
server-authoritative TTL and remaining-use state.

```text
signing lane + signingGrantId + thresholdSessionId + budget policy
```

The wallet id alone is insufficient. The threshold session id alone is
insufficient. Transaction signing needs the exact lane plus the admitted budget.

`thresholdSessionId` and `signingGrantId` name different things:

| Field | Meaning |
| --- | --- |
| `thresholdSessionId` | The curve/session material identity for the threshold protocol. It ties MPC/HSS round trips, restored material, and persisted lane records to the same protocol session. |
| `signingGrantId` | The Wallet Session signing authorization grant. It owns the budget state, such as expiry and remaining uses. |

The same threshold session can only be used for signing when it is paired with
an active signing grant. The same signing grant can only be spent by the exact
lane and threshold session it was issued for.

## Readiness States

Wallet unlock can create auth-ready state without making a lane immediately
sign-ready.

| State | Meaning | Can sign now? |
| --- | --- | --- |
| Auth-ready | Wallet Session auth, `signingGrantId`, Router A/B scope, and budget metadata exist. | No |
| Restore-ready | Auth-ready state plus durable sealed worker material exists, so an explicit restore phase can run. | No |
| Material pending | A persisted worker-material handle or hint exists, but the current worker has not validated it. | No |
| Sign-ready | Auth/grant, threshold session identity, budget, Router A/B scope, and current worker-owned material have all been validated together. | Yes |

Persisted records are durable hints. They are not durable proof that a browser
worker currently has usable signing material. After reload, reconnect, restore,
bootstrap, or worker restart, the worker must validate the material against the
current session binding before the lane becomes sign-ready.

## Budget Admission

Budget admission happens before signing. It must bind wallet id, lane identity,
threshold session id, signing grant id, expiry, remaining uses, and operation
fingerprint.

Rejected requests should fail before any private Deriver or SigningWorker work
happens.

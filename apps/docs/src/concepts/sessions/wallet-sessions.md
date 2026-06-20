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

## Budget Admission

Budget admission happens before signing. It must bind wallet id, lane identity,
threshold session id, signing grant id, expiry, remaining uses, and operation
fingerprint.

Rejected requests should fail before any private Deriver or SigningWorker work
happens.

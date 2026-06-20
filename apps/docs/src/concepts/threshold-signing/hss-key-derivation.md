---
title: HSS Key Derivation
---

# HSS Key Derivation

HSS means homomorphic secret sharing. Seams uses it to split and derive wallet
key material homomorphically, so the client side and server side can transform
their own secret contributions into compatible signing shares. The wallet
private key is not reconstructed in one place during ordinary signing.

## Where HSS Is Used

HSS is used for key-derivation operations:

- registration;
- key export;
- key delegation;
- key rotation;
- recovery;
- refresh;
- SigningWorker activation.

Day-to-day transaction signing uses the resulting signing shares from the prior
derivation or activation step.

## Practical Model

```text
wallet key material = holder contribution + server contribution
```

The holder contribution and server contribution are transformed together by
protocol. They are not joined in app code or Router code. The client receives
only holder-side signing output or handles. Server-side roles receive only their
allowed server-side outputs.

Export is a separate, freshly authorized flow because ordinary signing uses
shares rather than a full private key.

Protocol internals live in [HSS Internals](/concepts/advanced/hss-internals).

---
title: EVM ECDSA-HSS
---

# EVM ECDSA-HSS

EVM-family signing uses threshold ECDSA over secp256k1.

```text
x = x_client + x_server mod n
X = X_client + X_server
ethereum_address = address(X)
```

## Address Invariant

Tempo, Arc, Ethereum, and future EVM-family targets share one threshold owner
address for the same wallet, RP, signing root, and key version.

Concrete chain targets may partition sessions, budgets, nonce lanes, and
transaction serialization. They must not partition the persistent ECDSA key or
the displayed owner address.

## Normal Signing

Normal ECDSA signing uses Router A/B admission plus SigningWorker participation.
Pool-hit signing consumes one prepared presignature. Pool-miss signing refills
through the Router A/B ECDSA-HSS pool path, then signs through the same normal
signing boundary.

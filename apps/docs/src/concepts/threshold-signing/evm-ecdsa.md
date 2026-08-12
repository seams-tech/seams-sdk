---
title: EVM ECDSA
description: Use threshold secp256k1 signing for EVM-family networks with strict Router A/B role separation.
---

# EVM ECDSA

EVM-family signing uses threshold ECDSA over secp256k1. Strict Router A/B
threshold-PRF derivation produces additive client and server scalar shares:

```text
x = x_client + x_server mod n
X = X_client + X_server
ethereum_address = address(X)
```

ECDSA does not use the Ed25519 Streaming Yao circuit. Deriver A and Deriver B
own role-local threshold-PRF material during lifecycle operations. The browser
worker receives the client share, and SigningWorker receives the activated
server share and one-use presignature state.

## Address invariant

Tempo, Arc, Ethereum, and future EVM-family targets share one threshold owner
address for the same wallet, RP, signing root, and key version.

Concrete chain targets may partition sessions, budgets, nonce lanes, and
transaction serialization. They cannot partition the persistent ECDSA key or
the displayed owner address.

## Normal signing

Normal ECDSA signing uses Router admission plus SigningWorker participation.
Deriver A and Deriver B remain outside the signing hot path. Pool refill and
normal signing use strict Router A/B routes and one-use presignature state.

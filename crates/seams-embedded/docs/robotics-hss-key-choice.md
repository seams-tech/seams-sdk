# Embedded Robotics HSS Key Choice

This note records the current recommendation for embedded robotics signers that
need a split client/server signing key.

## Recommendation

Prefer ECDSA-HSS for embedded robotics signers when the product can use a
secp256k1/EVM-family key.

Use Ed25519-HSS only when the product specifically requires standard Ed25519
seed compatibility, NEAR-native Ed25519 account compatibility, or another
Ed25519-only integration.

## Why ECDSA-HSS Fits Embedded Signers

ECDSA-HSS uses a role-local additive key shape:

```text
x_client = H_scalar("client-share", context, y_client)
x_relayer = H_scalar("relayer-share", context, y_relayer)
x = x_client + x_relayer mod n
X = x_clientG + x_relayerG
```

The device derives and retains only its client share. The relayer derives and
retains only its relayer share. The shared public key is computed with ordinary
public elliptic-curve addition.

This is a good fit for embedded robotics because the client-side work is small:

- hash-to-scalar for the device role
- secp256k1 scalar multiplication for the device public share
- public-key verification and transcript checks
- threshold ECDSA signing using the retained client share

The server-blind boundary is also direct:

- the server sees `X_client`, public transcript data, and its own relayer share
- the server does not need `y_client`, `x_client`, or canonical `x`
- the device does not receive `x_relayer` during non-export signing flows
- explicit export is a separate policy-gated path

This shape avoids a hidden computation over joined client/server secret state.

## Why Ed25519-HSS Is Heavier

Standard Ed25519 keys derive the signing scalar and deterministic nonce prefix
from a seed:

```text
h = SHA512(seed)
a = clamp(h[0..32])
prefix = h[32..64]
A = aB
```

If the seed is split across a device and server, preserving standard Ed25519
seed compatibility requires evaluating `SHA512(joined_seed)` without revealing
the joined seed. That hidden SHA-512 and clamp step is the expensive part.

Group operations after the scalar exists are linear and cheap. The difficult
piece is the nonlinear hash circuit over joined secret state:

- SHA-512 message schedule and compression rounds
- boolean operations
- additions with carries
- bit rotations
- conversion back into scalar material

That cost is a poor fit for small embedded clients, especially devices with
tight memory, CPU, power, and latency budgets.

## Security Implication

ECDSA-HSS is easier to keep server-blind because the server never needs to run a
joint hidden evaluation. A tampered relayer can still exfiltrate server-owned
material such as `x_relayer`, relayer signing state, and presign state. It
should not be able to reconstruct the full canonical private key from the normal
non-export server view alone.

Ed25519-HSS has a larger implementation risk because standard seed-compatible
derivation forces a hidden nonlinear computation. If the implementation lets a
server process materialize joined hidden state during that computation, a
tampered server can log sensitive joined material.

## Embedded Design Posture

For robotics, use the smallest protocol that satisfies the product key
requirements:

```text
device:
  derive or unseal y_client
  derive x_client
  retain x_client in the device secret store
  verify public identity and transcript bindings

relayer:
  derive y_relayer from server-side signing-root share material
  derive x_relayer
  retain only relayer share state and public identity

public identity:
  X_client = x_clientG
  X_relayer = x_relayerG
  X = X_client + X_relayer

signing:
  use threshold ECDSA over the retained additive shares

export:
  disabled by default
  enabled only through an explicit, policy-bound flow
```

Use Ed25519-HSS for embedded devices only after measuring the hidden-evaluation
cost on target hardware and confirming that standard Ed25519 compatibility is a
hard requirement.

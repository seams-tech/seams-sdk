---
title: Nonce Lanes
---

# Nonce Lanes

Nonce lanes prevent EVM-family transaction conflicts. They track which nonces
are available, in flight, finalized, dropped, or replaced for a concrete chain
target and signing lane.

## Default Rule

Application code should not fetch or assign nonces for default Tempo/EVM
signing flows. The signing engine owns nonce preparation, broadcast reporting,
finalization reporting, and reconciliation.

## Lifecycle

1. Read chain nonce and local unresolved state.
2. Reserve a nonce for an admitted signing request.
3. Report broadcast accepted or rejected.
4. Report finalized, dropped, or replaced.
5. Reconcile when chain state and local state disagree.

Nonce state belongs to the concrete chain target and lane. It must not select a
different persistent ECDSA key or displayed signer address.

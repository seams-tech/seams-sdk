# threshold

## Owns

Threshold protocol policy, relayer workflows, curve-specific threshold signing
material, and protocol crypto helper material.

## May Import

`workers/*`, `threshold/crypto/*`, and type-only imports from
`session/identity/laneIdentity.ts`.

## Must Not Import

`SigningEngine.ts`, `assembly/*`, `flows/*`, `stepUpConfirmation/*`, `chains/*`,
`nonce/*`, or session lifecycle modules.

## Entrypoints

Current policy entrypoint: `sessionPolicy.ts`. Curve-specific protocol flows
live under `ed25519/*` and `ecdsa/*`. PRF salts, WebAuthn PRF helpers, and
wrap-key salts live under `crypto/*`. The ECDSA derivation worker facade lives under
`crypto/ecdsaDerivationClientWasm.ts`. `ed25519/public.ts` owns the Ed25519 Yao and
online FROST facade used by the signing engine.

## Ed25519 Yao Boundary

Router A and B run the selected Yao profile and return additive Ed25519 scalar
shares. The browser keeps its scalar inside the active WASM client and exposes
only public identity plus online FROST operations. Durable browser records hold
public metadata and session authority; they never hold the scalar share.

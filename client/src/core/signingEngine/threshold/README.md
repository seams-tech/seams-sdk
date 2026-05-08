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
wrap-key salts live under `crypto/*`. HSS worker facade code lives under
`crypto/hssClientSignerWasm.ts`. `ed25519/public.ts` owns the facade-facing HSS
helper entrypoint used by `SigningEngine.ts`.

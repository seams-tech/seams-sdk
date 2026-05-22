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

## Ed25519 HSS Boundary

Ed25519 HSS client-owned finalization uses client-masked projection. The
threshold layer derives `clientOutputMaskB64u` locally from recoverable
client-side material and canonical HSS context, sends only the masked artifact
through the worker/server boundary, and opens `x_client_base` on the client.

Under the trusted-server/code-as-deployed assumption, this lets the product
claim that the server does not receive or materialize the client's sensitive
key-derivation secret during Ed25519 HSS key derivation. It is a Level A
server-blind boundary, not a full malicious-server security claim.

# webauthnAuth

## Owns

Low-level WebAuthn/passkey browser primitives: credential collection,
credential normalization/redaction, signer-slot device helpers, and Safari
fallback behavior.

## May Import

Shared SDK types, IndexedDB account/profile projection helpers, and primitive
shared validation helpers.

## Must Not Import

`SigningEngine.ts`, `assembly/*`, `flows/*`, `session/*`, `threshold/*`,
`chains/*`, `nonce/*`, `stepUpConfirmation/*` orchestration logic, or
confirmation/runtime flow modules.

## Entrypoints

- `credentials/*`
- `device/*`
- `fallbacks/*`

## ECDSA Boundary

`webauthnAuth/*` provides credential primitives only. It does not own ECDSA
session reconnect planning, warm-session bootstrap resolution, or threshold
activation.

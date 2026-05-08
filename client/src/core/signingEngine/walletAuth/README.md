# walletAuth

## Owns

Wallet auth policy helpers and the legacy auth-plan resolver still used by
NEAR, recovery, and threshold-ed25519 paths.

## May Import

Shared SDK types, IndexedDB account/profile projection helpers, and primitive
crypto constants from shared packages.

## Must Not Import

`SigningEngine.ts`, `assembly/*`, `flows/*`, `session/*`, `threshold/*`,
`chains/*`, `nonce/*`, or confirmation runtime flow modules.

## Entrypoints

Current entrypoints: `index.ts` for the public wallet auth export surface and
`walletAuthModeResolver.ts`.

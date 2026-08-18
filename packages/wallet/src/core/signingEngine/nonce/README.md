# nonce

## Owns

Nonce lease state, durable nonce coordination, and nonce lifecycle persistence.

## May Import

Nonce persistence/RPC dependencies and primitive types.

## Must Not Import

`SigningEngine.ts`, `assembly/*`, `flows/*`, `session/*`, `stepUpConfirmation/*`,
`threshold/*`, or `chains/*`.

## Entrypoints

Current entrypoint: `NonceCoordinator.ts`. Future entrypoint:
`coordinator.ts`.

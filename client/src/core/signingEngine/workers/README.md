# workers

## Owns

Worker transport, worker RPC message contracts, and signer worker runtime
dispatch.

## May Import

Worker runtime code and primitive message types.

## Must Not Import

`SigningEngine.ts`, `assembly/*`, `flows/*`, `session/*`, `stepUpConfirmation/*`,
`threshold/*`, `chains/*`, or `nonce/*`.

## Entrypoints

Future entrypoints: `manager.ts`, `transport.ts`, `flows.ts`, and
`runtimes/*`.

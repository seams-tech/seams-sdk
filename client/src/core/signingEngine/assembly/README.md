# assembly/

## Owns

Construction-time assembly for `SigningEngine`: manager creation, operation
ports, runtime startup, and resource warmup.

## May Import

`flows/*` public entrypoints, `session/*`, `sessionEmailOtp/*`,
`stepUpConfirmation/*`, `threshold/*`, `chains/*`, `workers/*`,
`workerManager/*`, `uiConfirm/*`, `walletAuth/*`, `webauthnAuth/*`,
`interfaces/*`, and `nonce/*`.

## Must Not Import

`SigningEngine.ts`, retired `api/*`, retired `orchestration/*`, and broad
internal barrels. `assembly/*` may depend on flow-facing public entrypoints and
typed operation binders; it should not reach into unrelated deep flow internals
as a convenience layer.

## Entrypoints

- `createManagers.ts`
- `createPorts.ts`
- `ports/*`
- `ports/stepUpRuntime.ts`
- `ports/session.ts`
- `createSigningEngineRuntime.ts`
- `warmup.ts`

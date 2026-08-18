# chains

## Owns

Chain-specific normalization, display shaping, serialization, and worker payload
assembly.

## May Import

`workers/*`, `workerManager/*`, chain libraries, signing interfaces, and
type-only identity imports from `session/identity/laneIdentity.ts` where
needed.

## Must Not Import

`SigningEngine.ts`, `assembly/*`, `flows/*`, `stepUpConfirmation/*`, `threshold/*`,
or session lifecycle modules.

## Entrypoints

Current entrypoints live under `chains/near/*`, `chains/evm/*`, and
`chains/tempo/*`, including chain-owned WASM facades.

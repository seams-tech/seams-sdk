# interfaces

## Owns

Public signing-engine type contracts used by SDK consumers and runtime
composition, plus primitive cross-domain signing identifiers such as ECDSA chain
targets.

## May Import

Shared SDK types and primitive runtime contracts.

## Must Not Import

`SigningEngine.ts`, `assembly/*`, `flows/*`, concrete session lifecycle
modules, confirmation runtimes, type-only protocol result contracts, chain
serializers, nonce managers, or worker implementations.

## Entrypoints

Current entrypoints: `index.ts` for the public interface export surface,
`runtime.ts`, `signing.ts`, `near.ts`, `nearKeyOps.ts`, and
`ecdsaChainTarget.ts`.

## Owns

Application use-case contracts for wallet registration, unlock, restore, signing, export, activation, and ECDSA provisioning.

## May Import

Domain interfaces, chain request/result types, session read models, threshold protocol facts, and sibling use-case lifecycle helpers.

## Must Not Import

SigningEngine facade construction, UI runtime internals, worker manager construction, persistence compatibility shapes outside boundary inputs, or product UI code.

## Entrypoints

Import concrete use cases directly from their module files, for example `useCases/signNear` or `useCases/provisionEcdsa`.

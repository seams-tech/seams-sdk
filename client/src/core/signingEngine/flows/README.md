# flows

## Owns

- SDK signing operation entrypoints and operation-time sequencing.
- Shared operation state machine and operation state types.

## May Import

- `flows/shared/*`
- `session/*`
- `stepUpConfirmation/*`
- `threshold/*`
- `chains/*`
- `workers/*`
- `nonce/*`

## Must Not Import

- `SigningEngine.ts`
- `assembly/*`
- old `api/*`
- old `orchestration/*`
- sibling operation modules unless the dependency is in `flows/shared/*`

## Entrypoints

- `signEvmFamily/*`: EVM and Tempo signing flows.
- `signNear/*`: NEAR signing flows.
- `registration/*`: registration-facing credential confirmation and account lifecycle.
- `shared/signingStateMachine.ts`: shared operation runner.
- `shared/operationState.ts`: shared operation lifecycle state types.

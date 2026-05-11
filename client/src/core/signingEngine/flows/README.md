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

## ECDSA Call Graph

The final ECDSA operation path is:

- `SigningEngine.ts` exposes the public/bootstrap entrypoint.
- `flows/signEvmFamily/*` resolves lane identity, step-up authorization, and
  ECDSA provision plans.
- `stepUpConfirmation/*` owns confirmation payload collection only.
- `session/passkey/ecdsaWarmCapabilityBootstrap.ts` owns the public
  `EcdsaBootstrapRequest` boundary.
- `session/passkey/ecdsaProvisioner.ts` consumes ECDSA provision plans and
  decides reuse, reconnect, or fresh activation through strict branches.
- `session/passkey/ecdsaSessionProvision.ts` and `threshold/ecdsa/activation.ts`
  own threshold-session activation and warm-material persistence.

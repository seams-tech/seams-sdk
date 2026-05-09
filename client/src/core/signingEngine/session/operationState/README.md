# session/operationState

## Owns

Shared signing-operation state, lane specializations, prepared operation
shapes, post-sign policy state, transaction state, and trace events.

## May Import

Primitive identity and record types from `session/*`, plus neutral interface
types.

## Must Not Import

`SigningEngine.ts`, `assembly/*`, `flows/*`, chain operation modules,
`threshold/*`, concrete confirmation runtime modules, or worker managers.

## Entrypoints

- `types.ts`
- `lanes.ts`
- `preparedOperation.ts`
- `postSignPolicy.ts`
- `warmSessionPolicyAdapter.ts`
- `transactionState.ts`
- `trace.ts`

# session/signingSession

## Owns

Signing-session operation planning, budget state, prepared operation state,
post-sign policy, transaction state, operation fingerprints, and trace events.

## May Import

Primitive identity and record types from `session/*`, plus neutral interface
types.

## Must Not Import

`SigningEngine.ts`, `assembly/*`, `flows/*`, chain operation modules,
`threshold/*`, concrete confirmation runtime modules, or worker managers.

## Entrypoints

- `planner.ts`
- `budget.ts`
- `budgetStatusReader.ts`
- `preparedOperation.ts`
- `postSignPolicy.ts`
- `transactionState.ts`
- `types.ts`

# session/budget

## Owns

Signing grant budget status reads, admission classification, and trusted
status normalization during the remaining server-status cutover.

## May Import

Shared operation-state and lane types from `session/operationState/*`,
primitive persistence reads, and neutral relayer/session token helpers.

## Must Not Import

Operation flows, `SigningEngine.ts`, assembly construction, threshold protocol
entrypoints, or concrete confirmation/runtime modules.

## Entrypoints

- `BudgetCoordinator.ts`
- `budget.ts`
- `budgetProjection.ts`
- `budgetStatusReader.ts`

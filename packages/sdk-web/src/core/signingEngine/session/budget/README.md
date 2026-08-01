# session/budget

## Owns

Signing grant status reads and admission classification for server-owned
operation claims.

## May Import

Shared operation-state and lane types from `session/operationState/*`,
primitive persistence reads, and neutral relayer/session token helpers.

## Must Not Import

Operation flows, `SigningEngine.ts`, assembly construction, threshold protocol
entrypoints, or concrete confirmation/runtime modules.

## Entrypoints

- `budget.ts` — status-check identities and owner builders
- `budgetStatusReader.ts` — trusted status reads and normalization
- `admission.ts` — server admission error classification and retry keys
- `policy.ts` — session policy defaults

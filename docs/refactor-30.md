# Refactor 30 Plan: Sponsored Call Idempotency Must Be Intent-Scoped

Status: Ready for implementation  
Severity: High (user-facing replay bugs + confusing API semantics)  
Last updated: 2026-03-15

## 1. Direct Answer

Yes, we should keep sponsored-call idempotency.

No, we should not derive sponsored-call idempotency from the raw payload by default.

The bug is not that idempotency exists. The bug is that the current dedupe key does not model user intent.

For user-triggered sponsored actions:

1. Each explicit click must get a fresh idempotency key.
2. Automatic retries of that same click must reuse the same key.
3. A second intentional click with identical calldata must still be allowed.

The current `sourceEventId` behavior violates rule 3 when the client omits the field and the server hashes the payload.

## 2. Current Failure Mode

Today the sponsored EVM route does this:

1. If the request includes `sourceEventId`, use it.
2. Otherwise derive one from:
   `nearAccountId`, `walletAddress`, `chainId`, `call.to`, `call.data`, `call.gasLimit`, `call.value`.
3. Look up an existing ledger record by that key.
4. Replay the stored terminal result instead of broadcasting again.

Relevant code:

- [server/src/router/relaySponsoredEvmCall.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/relaySponsoredEvmCall.ts)
- [server/src/sponsorship/evm.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/sponsorship/evm.ts)
- [server/src/console/sponsoredCalls/postgres.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/sponsoredCalls/postgres.ts)

This creates bad behavior for interactive flows like `Drip Fee Tokens`:

1. A real on-chain revert is recorded once.
2. The user fixes chain state later.
3. The user clicks again with the same calldata.
4. The server replays the old failed record instead of making a new attempt.

That is correct for transport retries, but wrong for a new user action.

## 3. Why `console_sponsored_call_records` Should Stay

The table is still the right abstraction.

It gives us:

1. Finalized spend accounting.
2. Billing attribution.
3. Auditability.
4. Replay safety across process restarts and multiple instances.
5. Deterministic reconciliation when the caller intentionally reuses an idempotency key.

The table is not the problem.

The problem is that we overloaded one field to mean all of these at once:

1. request identity
2. retry identity
3. business-event identity
4. payload hash fallback

Those are not the same thing.

## 4. Refactor Decision

We should make a breaking change:

1. Remove implicit payload-derived fallback for sponsored calls.
2. Replace the public sponsored-call request field `sourceEventId` with `idempotencyKey`.
3. Require callers to send an explicit key.
4. Treat that key as one user intent / attempt identity.
5. Keep ledger-backed replay keyed by that explicit idempotency key.

This aligns sponsored-call behavior with how the billing subsystem already thinks about idempotency.

## 5. Target Semantics

### 5.1 Request semantics

`idempotencyKey` means:

1. "This is the same logical attempt as before."

It does **not** mean:

1. "This payload is identical to a previous payload."

### 5.2 Caller rules

1. New click: new `idempotencyKey`
2. Retry caused by timeout/network ambiguity for that same click: reuse the same `idempotencyKey`
3. Identical calldata on purpose later: new `idempotencyKey`

### 5.3 Server rules

1. If the same `idempotencyKey` is seen again, replay the stored terminal result.
2. If a different `idempotencyKey` is seen, process as a fresh attempt even if the payload is identical.
3. Never silently hash the payload to invent idempotency for the caller.

## 6. Current Stopgap

The current demo client already moved in this direction:

- [examples/tatchi-site/src/flows/demo/hooks/useDemoTempoSigningActions.tsx](/Users/pta/Dev/rust/simple-threshold-signer/examples/tatchi-site/src/flows/demo/hooks/useDemoTempoSigningActions.tsx)

It now sends a fresh explicit `sourceEventId` per click for `Drip Fee Tokens`.

That is the correct immediate behavior for the demo, but it is only a stopgap because:

1. the field name is still misleading
2. the route still supports implicit payload hashing
3. the replay response model is still awkward for failures

## 7. Breaking API Changes

### 7.1 Remove

1. `SponsoredEvmCallRequest.sourceEventId`
2. Route fallback that calls `createSponsoredEvmSourceEventId(...)`
3. `getRecordBySourceEventId(...)` naming in the sponsored-call ledger service

### 7.2 Add

1. `SponsoredEvmCallRequest.idempotencyKey`
2. `getRecordByIdempotencyKey(...)`
3. `console_sponsored_call_records.idempotency_key`

### 7.3 Keep

1. replay behavior backed by the sponsored-call ledger
2. unique constraint per org + request identity
3. spend recording and billing

## 8. Response Semantics Refactor

Current replay behavior is inconsistent:

1. success replay returns `200`
2. failed replay returns `409`

That is not a good fit for idempotent terminal replay.

Refactor target:

1. Same key + prior success:
   return `200`, `replayed: true`, same success payload shape.
2. Same key + prior revert / failure:
   return the same failure classification as the original terminal result, plus `replayed: true`.
3. Reserve `409` for true mutable-state conflicts, not "you retried a finished request."

For sponsored tx revert replay specifically:

1. first result: `502` with `code = tx_reverted`
2. replay result with same idempotency key: `502` with `replayed: true` and the same tx hash / record id

## 9. Data Model Refactor

### Phase 1: sponsored-call ledger rename

Rename these concepts in the sponsored-call domain:

1. `sourceEventId` -> `idempotencyKey`
2. `source_event_id` -> `idempotency_key`
3. `console_sponsored_call_source_event_idx` -> `console_sponsored_call_idempotency_key_idx`

Files:

- [server/src/console/sponsoredCalls/types.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/sponsoredCalls/types.ts)
- [server/src/console/sponsoredCalls/service.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/sponsoredCalls/service.ts)
- [server/src/console/sponsoredCalls/postgres.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/sponsoredCalls/postgres.ts)

### Phase 2: route types rename

Files:

- [server/src/sponsorship/evm.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/sponsorship/evm.ts)
- [server/src/router/relay.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/relay.ts)
- [server/src/router/relaySponsoredEvmCall.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/relaySponsoredEvmCall.ts)

### Phase 3: docs/examples rename

Files:

- [examples/relay-server/README.md](/Users/pta/Dev/rust/simple-threshold-signer/examples/relay-server/README.md)
- [docs/sponsored-tempo-tx.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/sponsored-tempo-tx.md)
- [docs/sponsorship-policy.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/sponsorship-policy.md)

## 10. Client Refactor

### 10.1 Introduce a shared helper

Add one client helper that generates intent-scoped idempotency keys:

Suggested file:

- `client/src/core/idempotency/createIntentId.ts`

Suggested shape:

```ts
export function createIntentId(prefix: string): string
```

Behavior:

1. prefer `crypto.randomUUID()`
2. fallback to `Date.now()` + random suffix
3. never derive from calldata

### 10.2 Sponsored-call callers must own the key

User-triggered callers must generate the key before dispatch and pass it through.

Initial callers:

1. [examples/tatchi-site/src/flows/demo/hooks/useDemoTempoSigningActions.tsx](/Users/pta/Dev/rust/simple-threshold-signer/examples/tatchi-site/src/flows/demo/hooks/useDemoTempoSigningActions.tsx)

Longer term:

1. any future generic sponsorship client helper
2. any server-to-server sponsorship caller

### 10.3 Retry wrappers

If we add retry helpers around sponsored-call fetches, they must take the already-created `idempotencyKey` as input and reuse it, not regenerate it.

## 11. Server Refactor

### Phase 0: stop inventing ids

Change the route contract to require `idempotencyKey`.

If missing:

1. return `400 invalid_body`
2. message: `Field idempotencyKey is required`

Do not silently fall back to a payload hash.

### Phase 1: replay terminal results cleanly

Refactor replay code in:

- [server/src/router/relaySponsoredEvmCall.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/relaySponsoredEvmCall.ts)

Rules:

1. success replay returns stored success result
2. failure replay returns stored failure result
3. `replayed: true` is included on both paths
4. `409` is removed from the replay path

### Phase 2: unify naming

Rename internal variables and helpers:

1. `createSponsoredEvmSourceEventId` must be deleted
2. `sourceEventId` route variables must become `idempotencyKey`
3. route docs and tests must be updated in one sweep

## 12. Suggested Implementation Phases

### Phase A: API + storage rename

- [ ] Rename sponsored-call request field to `idempotencyKey`
- [ ] Rename ledger service/storage fields
- [ ] Add Postgres migration/backfill for `idempotency_key`
- [ ] Drop old `source_event_id` usage in sponsored-calls code

### Phase B: route behavior cleanup

- [ ] Remove payload-derived fallback
- [ ] Require explicit `idempotencyKey`
- [ ] Replay prior failures with stored failure semantics instead of `409`

### Phase C: client intent helper

- [ ] Add shared `createIntentId(...)`
- [ ] Replace ad hoc demo-only generation with the shared helper
- [ ] Audit other user-triggered mutating routes for the same problem

### Phase D: docs + tests

- [ ] Update route docs to explain click-scope vs retry-scope idempotency
- [ ] Update sponsored-call relayer tests
- [ ] Add UI test proving two identical sequential clicks with different keys create two attempts
- [ ] Add route test proving same key replays exact stored result
- [ ] Add route test proving missing key is rejected

## 13. Test Matrix

### Required route tests

1. same payload, same `idempotencyKey`:
   one execution, one ledger row, replayed second response
2. same payload, different `idempotencyKey`:
   two executions, two ledger rows
3. same key after revert:
   replay stored revert with same status/code/body shape
4. missing key:
   `400 invalid_body`

### Required client tests

1. one click generates one key
2. two clicks generate different keys
3. retry helper preserves the original key

## 14. Risks

1. Removing payload-derived fallback is a breaking API change for any caller that does not currently send an explicit key.
2. If the client generates a fresh key on automatic retry instead of per click, we will lose retry idempotency.
3. If we keep `sourceEventId` in some layers and `idempotencyKey` in others, the codebase will get more confusing, not less.

## 15. Recommendation

Do the full breaking refactor.

Do not stop at the current demo-only workaround.

The correct end state is:

1. keep `console_sponsored_call_records`
2. keep replay-backed idempotency
3. remove payload-derived implicit dedupe
4. require explicit intent-scoped `idempotencyKey`
5. replay prior terminal failures as failures, not `409 conflicts`

That preserves the good part of idempotency and removes the part that breaks sequential identical user actions.

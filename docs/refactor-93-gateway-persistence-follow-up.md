# Gateway Ceremony Persistence Follow-up

Status: planned follow-up to Refactor 93

Refactor 93 moves Ed25519 Yao execution coordination into the MPC Router. It
does not rearchitect the Gateway's product-state persistence. The current
Gateway still uses `ROUTER_API_RUNTIME`, a tenant-environment Durable Object
that owns admission, authorization, recovery, export, and snapshot writes.

That object is outside the Yao stream, yet it is a single-threaded tenant
throughput ceiling and a persistence hop on the Gateway's `pre_yao` path. Its
request-overlap behavior also permits stale full-snapshot writes unless the
caller supplies an equivalent compare-and-swap boundary.

## Objective

Replace the tenant-wide mutable snapshot with request-safe, per-ceremony
records. Preserve all admission, replay, recovery, export, and authorization
invariants while allowing independent ceremonies in one tenant environment to
progress concurrently.

## Scope

This follow-up owns:

- the Gateway product-state composition wrappers;
- per-ceremony record keys and lifecycle ownership;
- versioned JSON encoding for the four interdependent product maps;
- compare-and-swap persistence and conflict handling;
- recovery, export, and authorization records that outlive one request;
- migration, drain, and deletion of `ROUTER_API_RUNTIME`.

Refactor 93 owns the MPC Router ceremony protocol and role-local Durable
Objects. This follow-up must not add a ceremony-wide Router ledger or move
Yao coordination back into the Gateway.

## Existing foundation

Refactor 93 already provides the safe boundary pieces in
`packages/sdk-server-ts/src/router/routerAbEd25519YaoProductRegistrationPersistence.ts`
and `packages/sdk-server-ts/src/router/cloudflare/versionedJsonRecordStore.ts`:

- strict opaque ceremony-key parsing;
- lossless Map/Set/Uint8Array encoding;
- versioned per-record storage and compare-and-swap contracts;
- adapter tests covering key binding and byte-preserving round trips.

The first bounded production route integration is now in place. Registration
admission and execution use a request-scoped adapter in
`d1RouterApiStagingWorker`; it loads shared and ceremony records from D1,
authorizes the request, persists an admission or execution claim before the
backend call, and commits terminal state from a fresh snapshot. Backend
uncertainty leaves the claim durable and terminal CAS conflicts fail closed
without retrying the backend.

The request-boundary ceremony-key parser, partitioned state composition, and
transaction-capable D1 CAS primitive are implemented. The current legacy
handler still materializes a four-map product state, so sending each lifecycle
to an independent object would isolate capabilities and replay state. The
partitioning boundary projects registration, authorization, recovery, and
export lifecycle entries
separately while retaining recovery capability ownership, stable identity
indexes, and export authorization nonces in a shared record. Its load/merge
store reads the shared and ceremony records in one D1 batch snapshot and
commits both with one typed CAS batch. Registration admission and execution
now use this composition. The tenant runtime remains active for wallet
registration start/bind/finalize, recovery, export, activation/session side
effects, and the non-Yao API until those routes receive equivalent typed
side-effect boundaries and lifecycle contract coverage.

## Request-scoped runner boundary

The SDK now exposes
`runRouterAbEd25519YaoProductRegistrationRequestScopedV1`. It loads one
ceremony's shared and lifecycle records in one snapshot, passes the composed
state to a request-local executor, and commits the returned state through one
typed CAS batch. A stale shared or ceremony version is returned as a typed
`version_mismatch`; the runner does not retry it. Focused tests cover the
committed response, elision of an unchanged shared record, and a concurrent
shared-state conflict.

This runner remains a composition seam for routes that have not been split. The
existing `createRouterApiHandler` combines Yao state transitions with D1
wallet/auth writes, console responses, and other non-Yao side effects. Wrapping
that handler would leave the CAS commit boundary ambiguous: a response can
escape after a one-use side effect and before persistence, while a concurrent
request can observe a shared in-memory handler. The production cutover remains
blocked until the Gateway supplies a Yao-only route adapter with an explicit
request side-effect boundary and proves their recovery, export, replay, and
authorization contracts. Registration admission and execution now use the
dedicated request-scoped adapter; `ROUTER_API_RUNTIME` remains for the other
routes while that handler-integrity work is completed.

### Registration execute two-phase seam

The SDK now exposes a bounded two-phase registration-execute seam in
`routerAbEd25519YaoRegistrationTwoPhaseRunner.ts`. Its preparation callback
must write a typed execution claim (the existing registration service uses the
`executing` lifecycle state), and the runner CASes that state before it calls
the backend. The backend callback receives the claim only after the preclaim
is durable. A fresh snapshot is loaded for terminal completion, and the
terminal state is committed with one CAS. The runner never retries a backend
call; an uncertain backend response leaves the claim durable for reconciliation,
and a terminal CAS conflict is returned as `terminal_version_mismatch` with
the claim attached.

Focused tests prove the ordering, the durable claim on backend uncertainty,
and the no-retry terminal conflict behavior. Registration admission and
execution now use this production boundary. The current Gateway
wallet-registration finalize handler still combines Yao consumption with
sponsored account creation, signing-session provisioning, wallet D1 commits,
capability installation, replay writes, and ceremony deletion. Until those
side effects are split behind explicit typed hooks, that handler and the
remaining `ROUTER_API_RUNTIME` routes stay unchanged.

## Implementation phases

### 1. Composition boundary

- Define branch-specific request compositions for admission, authorization,
  recovery, and export.
- Load one ceremony record at the request boundary and normalize it into the
  existing product-state types.
- Keep raw persistence records and compatibility parsing outside core logic.

Status: the explicit shared/ceremony partition and lossless merge boundary are
implemented in
`packages/sdk-server-ts/src/router/routerAbEd25519YaoProductRegistrationPartitioning.ts`.
The request-safe load/commit composition is implemented in
`packages/sdk-server-ts/src/router/routerAbEd25519YaoProductRegistrationPartitionedStateStore.ts`.
Registration admission and execution now compose requests through this store.
Recovery, export, replay, authorization, and wallet-finalize composition
remains gated on typed side-effect boundaries and lifecycle contract runs.

### 2. Atomic mutation protocol

- Stage all state changes in memory. **Implemented** by the partitioned state
  store.
- Commit the shared and complete ceremony records with one expected-version
  CAS batch. **Implemented** by the D1 versioned JSON store and its seeded
  constraint guard.
- Return a typed conflict when another request wins either version.
  **Implemented** without applying either record.
- Never retry a failed CAS after a one-use side effect; callers must reconcile
  from the terminal record or allocate a new ceremony identity.

### 3. Lifetime and cross-ceremony state

- Split durable state that is genuinely tenant-wide from ceremony state.
- Give replay, capability ownership, and stable identity records explicit
  record keys and typed CAS contracts.
- Add concurrency tests for independent ceremonies and same-ceremony conflicts.
- Prove recovery and export redelivery remain byte-exact and one-use.

### 4. Migration and drain

- Deploy the new record path behind an internal migration boundary.
- Dual-read only at the persistence boundary while the maximum in-flight
  ceremony lifetime drains.
- Compare old and new records without allowing two writers to commit the same
  lifecycle mutation.
- Remove `ROUTER_API_RUNTIME`, its binding, migration, readiness checks, and
  tenant snapshot serializer after the drain evidence is complete.

## Acceptance gates

- No production Yao request uses `ROUTER_API_RUNTIME`.
- Concurrent ceremonies in one tenant do not serialize on one Durable Object.
- Same-ceremony CAS conflicts fail closed without duplicate side effects.
- Registration, recovery, export, replay, and authorization contract suites
  pass with the new record path.
- Staging evidence shows no D1 overload and no tenant-runtime Durable Object
  in the Yao execution span.

This follow-up is a prerequisite for closing Refactor 93 acceptance criterion
3 and the related Phase 5 deletion checkbox. It is not a reason to expand the
Router coordinator or to claim that the Refactor 93 cutover is complete today.

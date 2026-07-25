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

Those adapters are intentionally not wired to production traffic yet. A
partial route integration would allow side effects to escape before its CAS
commit and could lose replay or authorization state.

## Implementation phases

### 1. Composition boundary

- Define branch-specific request compositions for admission, authorization,
  recovery, and export.
- Load one ceremony record at the request boundary and normalize it into the
  existing product-state types.
- Keep raw persistence records and compatibility parsing outside core logic.

### 2. Atomic mutation protocol

- Stage all state changes in memory.
- Commit the complete ceremony record with one expected-version CAS.
- Return a typed conflict when another request wins the version.
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

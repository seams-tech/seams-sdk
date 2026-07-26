# Gateway Ceremony Persistence Follow-up

Status: implemented by Refactor 93

The Gateway now stores Ed25519 Yao product lifecycle state in request-safe,
partitioned D1 records. The tenant-environment `ROUTER_API_RUNTIME` Durable
Object, mutable full-snapshot persistence, and staged selector have been
deleted.

## Result

The request-scoped composition provides:

- strict opaque ceremony-key parsing at the request boundary;
- lossless Map, Set, and byte-array encoding;
- versioned shared and per-ceremony records;
- transaction-backed compare-and-swap writes;
- durable admission and execution claims before backend calls;
- exact terminal replay without repeating cryptographic or wallet side
  effects;
- request-scoped registration, recovery, export, capability, session, and
  wallet-finalization handling;
- operation receipts that reconcile uncertain D1 responses and concurrent
  terminal attempts.

Mutable lifecycle authority remains in D1. Gateway handlers are composed per
request and do not share an in-memory tenant snapshot across requests.

## Ownership boundaries

The Gateway owns product admission, authorization, recovery, export, and
wallet-side effects. The MPC Router owns one admitted Ed25519 Yao execution and
coordinates the role-local Durable Objects. No ceremony-wide Router ledger was
introduced, and Yao coordination does not return to the Gateway.

`SIGNING_WORKER` remains a valid Gateway binding for Router A/B ECDSA
threshold-store transport. `MPC_ROUTER` remains the Gateway's Ed25519 Yao
origin. The direct Gateway Deriver bindings and the tenant runtime have no
current owner.

## Completion evidence

- [x] Partition registration, recovery, export, capability, and session state.
- [x] Persist claims before non-idempotent backend work.
- [x] Make registration finalize and recovery activation converge through
      typed claims and receipts.
- [x] Remove tenant snapshot hydration, serialization, and broad write-back.
- [x] Remove `ROUTER_API_RUNTIME`, its class binding, and readiness probe.
- [x] Remove selector windows, admission-drain responses, and deployment
      configuration.
- [x] Route all Gateway traffic through the request-scoped composition.
- [ ] Complete hosted staging recovery and broader manual acceptance recorded
      in [Refactor 93](./refactor-93.md).

## Historical note

Earlier revisions of this document described a two-boundary migration with the
tenant runtime kept active during a drain. That plan was superseded by the
immediate hard cutover. It has no current operational steps.

# Fixed 2-of-2 ECDSA Persistent Pool Lifecycle v1

Status: checkpoint 10 isolated state and atomic-mutation contract. Concrete
IndexedDB and SigningWorker persistence adapters remain Phase 7 integration.

## Scope

This crate owns the persisted lifecycle of one role-local half of an ECDSA
presignature pair. It owns no cryptographic arithmetic, secret serialization,
database driver, browser API, Worker API, network transport, or compatibility
decoder.

Each record binds exactly:

- wallet, account, signing scope, and presignature pair;
- Client or SigningWorker role;
- key epoch and activation epoch;
- production protocol identifier; and
- one sealed-material locator.

All digest bindings and epochs are non-zero. Untrusted database/request values
must be parsed into these types once at their persistence or request boundary.

## State machine

```text
available@revision_0
    -> reserved@revision_1
    -> committed-use@revision_2
    -> tombstone@revision_3
```

Available material may also transition directly to a tombstone after expiry or
epoch retirement. Reserved and committed records transition only forward.
Tombstones are absorbing and expose no transition method.

Every transition emits a compare-and-swap mutation containing the exact record
key, expected revision, and replacement record. The persistence adapter must
atomically:

1. compare the complete key and expected revision;
2. store exactly the replacement record;
3. delete the sealed material in the same transaction when the replacement is
   a tombstone; and
4. report conflicts without retrying against a different pair or revision.

The crate's reference tests demonstrate the transition contract and stale-CAS
rejection. They do not establish IndexedDB, Durable Object, or database
atomicity. Each Phase 7 adapter requires its own crash/fault evidence.

## Terminal policy

Success, validation rejection, binding substitution, timeout, cancellation,
crash recovery, peer abort, ambiguous delivery, persistence failure, material
expiry, and epoch retirement all end in a permanent tombstone. A reserved
record cannot claim success. A committed record must be tombstoned before an
online output crosses the process boundary.

Recovery is deliberately destructive:

- an interrupted reservation becomes `CrashRecovery`;
- an interrupted committed use becomes `AmbiguousDelivery`; and
- neither record returns to the available pool.

## Requirement alignment

| ID | Requirement | Code evidence | Classification | Confidence |
| --- | --- | --- | --- | --- |
| POOL-ID-01 | Bind wallet, account, scope, pair, role, epochs, protocol, request, and reservation. | `src/lib.rs:11-181`, `src/lib.rs:331-346` | Full in isolated domain | 1.00 |
| POOL-STATE-01 | Represent only available, reserved, committed-use, and tombstone states. | `src/lib.rs:213-630` | Full in isolated domain | 1.00 |
| POOL-CAS-01 | Every transition names the expected revision and exact replacement. | `src/lib.rs:183-202`, `src/lib.rs:656-698` | Full contract; adapter pending | 1.00 |
| POOL-BURN-01 | Success and every uncertain/failure outcome permanently burn material. | `src/lib.rs:274-327`, `src/lib.rs:373-595` | Full in isolated domain | 1.00 |
| POOL-REPLAY-01 | Concurrent/stale attempts cannot both reserve one record. | `src/lib.rs:183-202`, `src/lib.rs:656-698`, `src/lib.rs:836-847` | Full contract; adapter pending | 0.99 |
| POOL-DEPS-01 | The lifecycle contract remains outside the generic threshold-signing graph. | `../router-ab-ecdsa-near-oracle-tests/tests/production_boundaries.rs:40-63`, `../router-ab-ecdsa-near-oracle-tests/tests/production_boundaries.rs:120-152` | Full for the isolated graph | 1.00 |
| POOL-STORE-01 | Browser and SigningWorker persistence apply record replacement and material deletion atomically. | No concrete adapter in the isolated crate | Missing integration; Phase 7 blocker | 1.00 |
| POOL-OUTPUT-01 | Terminal persistence completes before online output release. | Required by this specification; output adapter is absent | Missing integration; Phase 7 blocker | 1.00 |

## Adapter promotion gate

Each concrete adapter must prove:

- exact key and revision comparison;
- record replacement and material deletion in one transaction;
- stale-write conflict without automatic state revival;
- destructive recovery after process termination at every transition edge;
- idempotent observation of an existing tombstone; and
- output release only after successful terminal persistence.

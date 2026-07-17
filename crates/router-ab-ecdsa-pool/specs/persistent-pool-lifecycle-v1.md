# Fixed 2-of-2 ECDSA Persistent Pool Lifecycle v1

Status: complete local state and atomic-mutation contract. The concrete
encrypted IndexedDB Client adapter and SigningWorker lifecycle reducer are
integrated and fault-tested.

## Scope

This crate owns the persisted lifecycle of one role-local half of an ECDSA
presignature pair. It owns no cryptographic arithmetic, secret serialization,
database driver, browser API, Worker API, network transport, or compatibility
decoder.

Each active record binds exactly:

- wallet, account, signing scope, and presignature pair;
- Client or SigningWorker role;
- key epoch and activation epoch;
- production protocol identifier; and
- one sealed-material locator.

Consumed records and tombstones retain identity and audit metadata without a
material locator.

All digest bindings and epochs are non-zero. Untrusted database/request values
must be parsed into these types once at their persistence or request boundary.

## State machine

```text
available@revision_0
    -> reserved@revision_1
    -> consumed@revision_2
```

Available material may also transition directly to a tombstone after expiry or
epoch retirement. Reserved material transitions to a tombstone after rejection,
binding substitution, lease or material expiry, cancellation, crash recovery,
peer abort, persistence failure, or epoch retirement. Consumed records and
tombstones are absorbing and expose no transition method.

Every transition emits a compare-and-swap mutation containing the exact record
key, expected revision, replacement record, and one exact material disposition:
`Retain`, `Take(locator)`, or `Destroy(locator)`. The persistence adapter must
atomically:

1. compare the complete key and expected revision;
2. store exactly the replacement record;
3. apply the specified material disposition in the same transaction;
4. report conflicts without retrying against a different pair or revision.

`Take` reads and deletes the sealed material exactly once. It returns that
material to the caller only after the consumed replacement has been durably
stored. `Destroy` deletes without returning material. Terminal persisted states
contain no material or material locator.

The crate's reference tests demonstrate the transition contract and stale-CAS
rejection. The IndexedDB and Durable Object adapters have separate transaction,
concurrency, persistence-failure, crash-recovery, retirement, and
terminal-cleanup evidence.

## Terminal policy

An authorized online use atomically takes and deletes material while persisting
a consumed record. Validation rejection, binding substitution, timeout,
cancellation, crash recovery, peer abort, persistence failure, material expiry,
and epoch retirement atomically destroy material while persisting a tombstone.

Recovery is deliberately destructive:

- an interrupted reservation becomes `CrashRecovery`;
- an already-consumed record remains consumed even if the caller did not receive
  an output; and
- neither terminal state returns to the available pool.

An alarm may schedule reserved cleanup at
`min(lease_expires_at_ms, material_expires_at_ms)`. Cleanup records
`MaterialExpired` once the material lifetime has elapsed and `Timeout` when
only the lease has elapsed.

## Requirement alignment

| ID | Requirement | Code evidence | Classification | Confidence |
| --- | --- | --- | --- | --- |
| POOL-ID-01 | Bind wallet, account, scope, pair, role, epochs, protocol, request, and reservation. | `PoolRecordKey`, `ReservationBinding`, and active record headers in `src/lib.rs` | Full in isolated domain | 1.00 |
| POOL-STATE-01 | Represent only available, reserved, consumed, and tombstone states. | `PoolRecord`, `ConsumedRecord`, and `TombstoneRecord` in `src/lib.rs` | Full in isolated domain | 1.00 |
| POOL-CAS-01 | Every transition names the expected revision, exact replacement, and exact material disposition. | `PoolMutation` and `MaterialDisposition` in `src/lib.rs`; concrete adapters compare and persist the same revision-bound mutation | Full local integration | 1.00 |
| POOL-BURN-01 | Authorized consumption and every uncertain/failure outcome permanently delete material. | `ReservedRecord::{consume,destroy,expire,retire,recover_after_crash}` in `src/lib.rs` | Full in isolated domain | 1.00 |
| POOL-REPLAY-01 | Concurrent/stale attempts cannot reserve or take one record twice. | CAS reference tests in `src/lib.rs`; Client concurrency and SigningWorker stale-CAS tests | Full local integration | 0.99 |
| POOL-DEPS-01 | The lifecycle contract remains outside the generic threshold-signing graph. | `../router-ab-ecdsa-near-oracle-tests/tests/production_boundaries.rs:40-63`, `../router-ab-ecdsa-near-oracle-tests/tests/production_boundaries.rs:120-152` | Full for the isolated graph | 1.00 |
| POOL-STORE-01 | Browser and SigningWorker persistence apply record replacement and material deletion atomically. | `packages/sdk-web/.../ecdsaPresignMaterialStore.ts`; `crates/router-ab-cloudflare/src/ecdsa_pool_lifecycle.rs` and its Durable Object mutation surface | Full local integration | 0.99 |
| POOL-OUTPUT-01 | Consumed persistence and material deletion complete before online material release. | `MaterialDisposition::Take`; concrete adapters must return material only after the CAS transaction commits. | Full contract; adapter evidence required | 1.00 |

## Adapter invariants

Each concrete adapter must prove:

- exact key and revision comparison;
- record replacement and exact material disposition in one transaction;
- stale-write conflict without automatic state revival;
- destructive recovery of every interrupted reservation;
- idempotent observation of an existing consumed record or tombstone; and
- material release only after successful consumed persistence.

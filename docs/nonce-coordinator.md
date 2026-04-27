# Nonce Coordinator Plan

Date created: 2026-04-26

## Objective

Move nonce ownership out of chain-specific helper code and into one
`NonceCoordinator` state machine.

The coordinator should make nonce behavior explicit, auditable, and consistent
across NEAR, Tempo, Arc EVM, and generic EVM signing. It should also compose
cleanly with the signing-session budget model so session exhaustion, concurrent
signing, cancellation, and broadcast failures do not create split-brain state.

## Current Problem

Nonce state is currently distributed across several places:

1. EVM-family signing used to reserve managed nonces in a chain-specific helper.
2. EVM-family broadcast/finalization code reports lifecycle events later through
   nonce lifecycle helpers.
3. NEAR has its own reservation model and separate release/fetch behavior.
4. Signing-session budget reservations live in `WalletSigningBudgetLedger`.
5. Tx confirmation, OTP/passkey reauth, threshold signing, broadcast, and status
   polling are driven by flow-specific orchestration.

That split means every flow has to remember the same cleanup rules. When any path
misses a release, reconciliation, or budget update, the UI can show a valid
signing session while the nonce lane is stuck, or the nonce lane can skip ahead
while the chain still expects an earlier nonce.

```mermaid
flowchart TD
  A["EVM / Tempo / Arc flow"] --> B["Reserve nonce in EVM manager"]
  A --> C["Reserve wallet-session budget"]
  A --> D["Show tx confirmer"]
  D --> E["OTP or passkey reauth"]
  E --> F["Threshold signer"]
  F --> G["Broadcast and poll status"]
  G --> H["Nonce lifecycle helper"]
  F --> I["Budget finalizer"]
  H --> B
  I --> C
  J["NEAR flow"] --> K["Separate NEAR nonce helper"]
  J --> C
  K -. "different release/recompute rules" .-> J
```

The failure mode is not that any one helper is inherently wrong. The failure
mode is that nonce state, auth state, signing-session budget state, and broadcast
state are coupled by convention instead of by a single operation state machine.

## Target Design

Introduce a `NonceCoordinator` that owns nonce lanes and nonce leases.

The coordinator is not an auth system and does not consume signing-session
budget. It owns only nonce allocation and nonce lifecycle. Signing-session budget
remains owned by the wallet signing-session coordinator and the server
authoritative budget consume path.

```mermaid
flowchart TD
  A["SigningSessionCoordinator"] --> B["Signing operation context"]
  B --> C["WalletSigningBudgetLedger"]
  B --> D["NonceCoordinator"]
  C --> E["Budget reservation"]
  D --> F["Nonce lease"]
  E --> G["Tx confirmer"]
  F --> G
  G --> H["OTP or passkey if required"]
  H --> I["Threshold signer"]
  I --> J["Broadcast executor"]
  J --> K["NonceCoordinator lifecycle"]
  I --> L["Wallet budget consume"]
  K --> M["Reserved / InFlight / Finalized / Dropped"]
  L --> N["Server-authoritative remainingUses"]
```

The key change is that a transaction signing operation gets two explicit local
resources:

1. a wallet signing-session budget reservation;
2. a nonce lease.

Those resources are siblings under the same `operationId`. Neither resource is
allowed to infer or synthesize the other.

## Core Invariants

1. Every signed transaction has exactly one nonce lease.
2. A nonce lease is bound to one `operationId`, one operation fingerprint, one
   account, one chain lane, and one nonce value.
3. A nonce lease must expire or be explicitly released before signature
   creation if the operation is cancelled or auth fails.
4. After a threshold signature is produced, wallet signing-session budget is
   spent even if broadcast or finality later fails. The signature exists.
5. Broadcast rejection, dropped transactions, and replacement affect nonce state,
   not whether a signature consumed wallet-session budget.
6. Missing or malformed managed nonce metadata is an invariant violation for
   managed EVM-family signing. It must fail closed.
7. All mutations for one nonce lane run through one serialized state-machine
   transition path.
8. Chain/RPC state remains authoritative for confirmed nonce progress. Local
   coordinator state is only a lease and reconciliation layer.
9. Cross-tab and cross-device wallet budget atomicity belongs server-side.
   Cross-tab nonce coordination should use same-origin browser coordination, but
   it is still subordinate to chain/RPC reconciliation.

## Lane Identity

Nonce lanes should be explicit and chain-specific without duplicating lifecycle
logic.

```ts
type NonceLane =
  | {
      family: 'evm';
      chain: 'evm' | 'tempo';
      networkKey: string;
      chainId: number;
      sender: `0x${string}`;
      nonceKey?: bigint;
      accountId?: string;
    }
  | {
      family: 'near';
      networkKey: string;
      accountId: string;
      publicKey: string;
    };
```

For EVM-family lanes, `nonceKey` remains available for account-abstraction or
chain-specific nonce domains. For NEAR lanes, the lane is the account/public-key
pair because NEAR nonces are access-key scoped.

## Operation Identity

The coordinator should share operation identity with signing-session budget
accounting.

```ts
type NonceOperationContext = SigningOperationContext & {
  operationFingerprint: SigningOperationFingerprint;
  accountId: string;
  walletSigningSessionId?: string;
  chainFamily: 'near' | 'evm' | 'tempo';
};
```

`operationFingerprint` must bind enough transaction identity to reject accidental
reuse of the same caller operation id for a different transaction. It should not
include plaintext secrets.

Budget reservation and nonce leasing must receive the same
`SigningOperationContext` for a transaction. The nonce context only extends that
operation with account, wallet-session, and chain-lane metadata; it must not
mint a separate operation id or infer a different fingerprint.

## State Machine

```mermaid
stateDiagram-v2
  [*] --> Idle
  Idle --> Reserved: reserve
  Reserved --> Released: cancel / auth_failed / nonce_failed
  Reserved --> Expired: lease_ttl_elapsed
  Reserved --> Signed: threshold_signature_created
  Signed --> BroadcastAccepted: rpc_accepts_tx
  Signed --> BroadcastRejected: rpc_rejects_tx
  Signed --> SignedLeaseExpired: signed_not_broadcast_ttl_elapsed
  BroadcastAccepted --> Finalized: receipt_or_chain_nonce_advances
  BroadcastAccepted --> Dropped: tx_hash_disappears
  BroadcastAccepted --> Replaced: replacement_detected
  Dropped --> Reconciled: rpc_reconcile
  Replaced --> Reconciled: rpc_reconcile
  BroadcastRejected --> Reconciled: rpc_reconcile
  Expired --> Reconciled: rpc_reconcile
  Released --> Reconciled: optional_rpc_reconcile
  SignedLeaseExpired --> Reconciled: rpc_reconcile
  Finalized --> [*]
  Reconciled --> Idle
```

Required semantics:

1. `Reserved` means the transaction has not produced a signature yet. It is safe
   to release this lease without spending wallet-session budget.
2. `Signed` means a threshold signature exists. Budget must be consumed exactly
   once for the operation. The nonce should remain protected briefly for
   broadcast retry, then reconcile if no broadcast succeeds.
3. `BroadcastAccepted` means the RPC accepted or returned a tx hash. The
   coordinator treats the nonce as in flight until finalized, dropped, replaced,
   or reconciled.
4. `Dropped` means the local tx hash is no longer a reliable pending/finalized
   candidate. The coordinator must reconcile before issuing another nonce for the
   lane when the dropped nonce could create a gap.
5. `Replaced` means the nonce was used by another tx. The lane must reconcile
   before choosing the next nonce.

## Public API Sketch

```ts
type NonceLease = {
  leaseId: string;
  batchId?: string;
  lane: NonceLane;
  operationId: SigningOperationId;
  operationFingerprint: string;
  nonce: bigint | string;
  txIndex?: number;
  reservedAtMs: number;
  expiresAtMs: number;
};

type NonceCoordinator = {
  reserve(input: {
    lane: NonceLane;
    operation: NonceOperationContext;
  }): Promise<NonceLease>;

  reserveBatch(input: {
    lane: NearNonceLane;
    operation: NonceOperationContext;
    count: number;
  }): Promise<NonceLease[]>;

  reserveNearContext<TContext extends { nextNonce?: string }>(input: {
    lane: NearNonceLane;
    operation: NonceOperationContext;
    count: number;
    fetchContext: () => Promise<TContext>;
  }): Promise<{ context: TContext; leases: NonceLease[] }>;

  markSigned(input: {
    leaseId: string;
    operationId: SigningOperationId;
    signedTxHash?: string;
  }): Promise<void>;

  markBroadcastAccepted(input: {
    leaseId: string;
    operationId: SigningOperationId;
    txHash?: string;
  }): Promise<void>;

  markBroadcastRejected(input: {
    leaseId: string;
    operationId: SigningOperationId;
    error: unknown;
  }): Promise<void>;

  markFinalized(input: {
    leaseId: string;
    operationId: SigningOperationId;
    txHash?: string;
  }): Promise<void>;

  markDroppedOrReplaced(input: {
    leaseId: string;
    operationId: SigningOperationId;
    reason: 'dropped' | 'replaced';
    txHash?: string;
  }): Promise<void>;

  release(input: {
    leaseId: string;
    operationId: SigningOperationId;
    reason: 'cancelled' | 'auth_failed' | 'signing_failed' | 'nonce_failed';
  }): Promise<void>;

  reconcile(input: { lane: NonceLane }): Promise<NonceLaneStatus>;
};
```

The implementation can initially be in-runtime memory plus browser coordination.
The API should still be written as if the coordinator is the only writer for a
nonce lane.

## Current Backend Role

During migration, `NonceCoordinator` is the transaction-facing nonce owner.
Chain-specific nonce classes are backend ports, not independent policy owners.

Current split:

1. `NonceCoordinator` owns lease identity, operation binding, state transitions,
   TTL expiry, cancellation release, signed/broadcast/finalized transitions, and
   fail-closed metadata validation. It also owns EVM-family lane arithmetic,
   in-flight nonce tracking, dropped/replaced reconciliation state, and
   same-origin lease coordination.
2. The EVM nonce backend is a fetch-only RPC port. It resolves the configured
   chain RPC and returns the chain-visible pending nonce. It does not reserve,
   release, reconcile, cache, or mutate lane state.
3. NEAR access-key nonce/block context, batch nonce arithmetic,
   release/recompute mechanics, prewarm, and account reset are now owned by
   `NonceCoordinator`.

The desired end state is not two parallel manager layers. The EVM side now uses
explicit backend terminology (`EvmNonceBackend`), and the NEAR side no longer
has a standalone nonce backend object.

Do not add new transaction signing paths that call nonce helpers directly. New
transaction paths must request coordinator leases and report coordinator
lifecycle transitions.

## Signing Session Integration

`NonceCoordinator` and signing-session budget accounting should meet at the
transaction operation boundary.

Recommended operation order for a warm session:

```mermaid
sequenceDiagram
  participant Flow as "Signing flow"
  participant Session as "SigningSessionCoordinator"
  participant Budget as "WalletSigningBudgetLedger"
  participant Nonce as "NonceCoordinator"
  participant Confirm as "Tx confirmer"
  participant Signer as "Threshold signer"
  participant Chain as "RPC / chain"

  Flow->>Session: "Resolve lane and plan"
  Flow->>Budget: "Reserve remainingUses for operation"
  Flow->>Nonce: "Reserve nonce lease"
  Flow->>Confirm: "Display exact transaction"
  Confirm-->>Flow: "User confirms"
  Flow->>Signer: "Create threshold signature"
  Flow->>Nonce: "markSigned"
  Flow->>Budget: "Consume server-authoritative use"
  Flow->>Chain: "Broadcast"
  Chain-->>Flow: "Accepted / rejected"
  Flow->>Nonce: "Broadcast lifecycle transition"
```

Recommended operation order for an exhausted session:

1. Planner sees no available local budget after subtracting in-flight
   reservations.
2. Tx confirmer owns the flow and shows the registered reauth method.
3. Email OTP or passkey reauth mints or refreshes exactly the requested
   `remainingUses` for this operation.
4. The flow reserves the new wallet-session budget and nonce lease under the
   same `operationId`.
5. The signer produces one signature.
6. Budget is consumed once and nonce lifecycle proceeds independently.

For EVM-family transactions, the nonce may need to be known before the exact
transaction digest is confirmed. That is allowed only as a short-lived nonce
lease. If the user cancels, OTP fails, passkey fails, or threshold reconnect
fails before signature creation, the nonce lease is released and the budget
reservation is released or recorded as zero-spend.

### Concurrent Remaining Uses

If `remainingUses = 2` and two transactions are already in flight, the third
transaction must plan as exhausted even before the first two finalize.

That behavior comes from budget reservations, not from nonce state:

1. Operation A reserves one wallet-session use.
2. Operation B reserves one wallet-session use.
3. `WalletSigningBudgetLedger.getAvailableStatus` returns zero local available
   uses for the shared `walletSigningSessionId`.
4. Operation C routes through OTP/passkey reauth.
5. If A or B is cancelled before signature creation, its reservation is released
   and future operations can use that budget again.

The `NonceCoordinator` should expose enough trace context to correlate nonce
leases with those budget reservations, but it must not decrement or refill
`remainingUses` itself.

### Budget And Nonce Failure Matrix

| Phase | Signature exists? | Budget action | Nonce action |
| --- | --- | --- | --- |
| User cancels confirmation | No | Release or zero-spend | Release lease |
| OTP/passkey fails | No | Release or zero-spend | Release lease |
| Nonce reservation fails | No | Release or zero-spend | No lease |
| Threshold reconnect fails | No | Release or zero-spend | Release lease |
| Threshold signing fails before signature | No | Release or zero-spend | Release lease |
| Signature succeeds, broadcast not attempted | Yes | Consume once | Mark signed, retry or expire and reconcile |
| Broadcast rejected | Yes | Consume once | Mark rejected and reconcile |
| Broadcast accepted | Yes | Consume once | Mark in flight |
| Tx finalized | Yes | Already consumed | Mark finalized |
| Tx dropped or replaced | Yes | Already consumed | Mark dropped/replaced and reconcile |

## Phased TODO

### Phase 0. Freeze Invariants And Regression Tests

1. [x] Add tests for the five known nonce review findings:
   reserved EVM nonce expiry, locked rejection cleanup, fail-closed chain
   parsing, mandatory managed nonce metadata, and NEAR reservation recompute.
   - [x] EVM reserved nonce expiry is covered in
     `tests/unit/nonceCoordinator.unit.test.ts`.
   - [x] EVM rejection cleanup is async and runs through the lane lock.
   - [x] Managed nonce chain parsing fails closed for non-`evm`/`tempo`
     snapshots.
   - [x] Missing managed nonce metadata fails closed in EVM-family lifecycle
     tests.
   - [x] NEAR release recomputes highest reserved nonce in
     `tests/unit/nonceCoordinator.nearContext.test.ts`.
2. [x] Add tests that signing-session budget reservations and nonce leases are
   both released on cancellation before signature creation.
   - [x] TouchConfirm signing and registration cancellation tests assert nonce
     lease release through the coordinator.
   - [x] Add the paired wallet-session budget reservation assertions for
     signing-session-backed transaction paths.
3. [x] Add tests that a signature-created-but-broadcast-failed operation consumes
   budget exactly once and reconciles nonce state.
   - [x] `tests/unit/transactionSigningBudgetFinalizer.unit.test.ts` covers a
     signed EVM operation whose broadcast is rejected, records one successful
     budget spend, and reconciles the nonce lane.
4. [x] Add tests that two in-flight wallet-session reservations exhaust local
   availability for the third transaction.
   - [x] `tests/unit/walletSigningBudgetLedger.unit.test.ts` covers concurrent
     reservations up to `remainingUses`, rejection of the next operation, and
     available-status reporting net of in-flight reservations.
5. [x] Add trace assertions that every transaction operation emits one
   `operationId`, one budget reservation, and one nonce lease id.
   - [x] `tests/unit/transactionSigningBudgetFinalizer.unit.test.ts` asserts a
     transaction operation emits a wallet budget reservation trace and a nonce
     lease trace sharing the same `operationId` and operation fingerprint.

### Phase 1. Define Coordinator Types And State Machine

1. [x] Add `NonceLane`, `NonceOperationContext`, `NonceLease`, and
   `NonceCoordinator` types.
2. [x] Implement a pure transition reducer for nonce lease states.
3. [x] Make illegal transitions fail closed with typed errors.
4. [x] Bind every transition to `operationId` and operation fingerprint.
5. [x] Add redacted trace events for reserve, release, signed, accepted,
   rejected, finalized, dropped, replaced, expired, and reconciled.
   - [x] Added trace events for reserve, release, signed, accepted, rejected,
     finalized, dropped, replaced, and lane reconciliation.
   - [x] Add explicit lease expiry transitions and trace events.
   - [x] Add lane-clear trace events for account-scoped and full coordinator
     reset paths.

### Phase 2. Implement EVM-Family Coordinator Backend

Progress:

1. [x] Route EVM-family nonce reservation and lifecycle calls through
   `NonceCoordinator`.
2. [x] Keep the current EVM nonce backend as the coordinator backend while the
   transaction-facing boundary migrates.
3. [x] Carry nonce lease metadata through managed nonce snapshots.
4. [x] Fail closed when managed signing results are missing nonce lease metadata.

Remaining TODO:

1. [x] Move current EVM nonce lane state fully into the coordinator backend.
   - [x] `NonceCoordinator` owns EVM-family `chainNonce`, `nextCandidate`,
     in-flight nonces, TTL refresh, stale in-flight blocking, and
     dropped/replaced alert windows.
   - [x] `EvmNonceBackend` is now a fetch-only RPC port with static guard
     coverage preventing stateful reserve/release/reconcile methods from
     returning.
2. [x] Keep one serialized lock per EVM-family nonce lane.
3. [x] Store reserved nonces with `reservedAtMs` and `expiresAtMs`.
4. [x] Validate managed nonce snapshots strictly; accept only `evm` and
   `tempo`.
5. [x] Treat missing managed nonce metadata as an invariant failure in managed
   signing results.
6. [x] Reconcile on dropped, replaced, stale in-flight, and rejected nonce
   errors.
7. [x] Remove direct lifecycle mutation calls from EVM/Tempo/Arc flows once they
   route through the coordinator.

### Phase 3. Integrate NEAR Access-Key Nonces

Progress:

1. [x] Model NEAR account/public-key as a nonce lane.
2. [x] Support atomic NEAR batch reservation that returns one lease per signed
   transaction.
3. [x] Wire TouchConfirm NEAR reservation/cancel cleanup through
   `NonceCoordinator`.
4. [x] Recompute the highest reserved NEAR nonce after every release in
   coordinator-owned NEAR nonce state.
5. [x] Carry TouchConfirm NEAR nonce lease handles into the signing worker and
   mark the lease signed after threshold signature creation.
6. [x] Attach per-transaction NEAR lease metadata to each
   `SignTransactionResult` and `SignedTransaction`.

Remaining TODO:

1. [x] Refresh block hash, block height, and access-key nonce through the same
   lane lock.
2. [x] Route NEAR signing cleanup through coordinator release/signed/finalized
   transitions for signed transactions carrying coordinator lease metadata.
3. [ ] Add NEAR dropped/replaced reconciliation once a chain-specific detector is
   available.
   - Status: blocked on a NEAR-specific detector. The coordinator already owns
     NEAR release, signed, finalized, expiry, and startup-recovery paths; there
     is not yet an equivalent to EVM pending-pool dropped/replaced detection for
     NEAR transaction hashes.

### Phase 4. Wire Transaction Signing Through One Boundary

1. [x] Make EVM-family and TouchConfirm NEAR transaction flows request nonce
   leases through the `NonceCoordinator` instead of chain-specific helpers.
2. [x] Keep signing-session coordinator and wallet-budget paths nonce-agnostic;
   nonce lease creation belongs only at transaction signing boundaries and in
   `NonceCoordinator`.
   - [x] NEAR transaction/delegate/NEP-413 orchestration no longer
     pre-initializes NEAR nonce state outside the coordinator before
     TouchConfirm.
   - [x] Delegate and NEP-413 confirmation contexts do not reserve NEAR
     access-key nonce leases, because those flows do not spend transaction
     nonces at confirmation time.
   - [x] Added a static guard that prevents session, threshold, and
     signing-session coordinator modules from importing or mutating nonce
     coordinator state directly.
3. [x] Use the same `SigningOperationContext` for budget reservation and nonce
   lease creation.
   - [x] `NonceOperationContext` now extends `SigningOperationContext` and
     requires the same canonical operation fingerprint used for budget
     accounting.
   - [x] EVM-family budget helpers accept a transaction operation context
     directly instead of separate `confirmationOperationId` and fingerprint
     arguments.
   - [x] Added a static guard that prevents the EVM-family budget helper from
     reintroducing separate operation-id arguments.
4. [x] Reserve wallet-session budget before threshold signing and release it on
   every no-signature outcome.
   - [x] NEAR transaction signing releases coordinator nonce leases and records
     zero spend when no threshold signature was created.
   - [x] NEAR transaction signing records successful wallet-session spend when a
     threshold signature exists, even if later cleanup fails.
   - [x] EVM-family touch-confirm flows reserve wallet-session budget before
     `executeSigningIntent` and release the reservation if no threshold
     signature was created.
   - [x] EVM-family cancellation tests cover the no-signature path for both
     Tempo and EVM Email OTP reauth without spending wallet budget.
5. [x] Mark nonce leases signed immediately after threshold signature creation.
   - [x] NEAR transaction signing marks the TouchConfirm lease signed after the
     threshold signer returns.
   - [x] EVM-family signing records the same explicit signed transition instead
     of jumping directly from reserved to broadcast lifecycle events.
6. [x] Update TouchConfirm success/defensive tests to attach `NonceCoordinator`
   explicitly and require `SigningAuthPlan` on signing confirmation requests.
7. [x] Ensure post-sign finalization consumes wallet-session budget before
   broadcast status polling can hide errors.
   - [x] EVM-family touch-confirm flows return signed raw transactions only;
     `transactionExecutor` consumes wallet-session budget before returning the
     signed result to dispatch/finality polling callers.
   - [x] Existing budget/nonce tests cover the post-sign broadcast-rejection
     case: once a signature exists, budget is consumed exactly once and nonce
     cleanup reconciles independently.
8. [x] Make retry paths reuse the same operation id only when the operation
   fingerprint matches.
   - [x] Caller-provided operation ids are bound to canonical operation
     fingerprints for NEAR and EVM-family signing requests.
   - [x] Added regression coverage for reusing the same operation id with the
     same fingerprint and rejecting reuse with a different transaction payload.

### Phase 5. Browser Runtime Coordination

1. [x] Use a same-origin coordination primitive for multi-tab nonce lanes
   (`navigator.locks`, SharedWorker, or IndexedDB lease records).
   - [x] `NonceCoordinator` uses `navigator.locks` when available and falls
     back to the in-runtime lane lock when same-origin locks are unavailable.
2. [x] Persist only redacted lease metadata required for recovery and
   reconciliation. Do not persist signed transaction bytes unless a deliberate
   retry queue is added.
   - [x] EVM-family lanes persist only lane key, lease id, nonce, active lease
     state, timestamps, and account id in same-origin storage. This lets a
     second tab skip active reserved/signed/broadcast nonces without persisting
     transaction bytes or secrets.
3. [x] Expire abandoned reserved leases after a short TTL.
4. [x] Expire signed-but-not-broadcast leases after a separate short TTL and
   force lane reconciliation.
   - [x] `markSigned` now switches a lease to the shorter post-sign TTL.
   - [x] Signed EVM-family leases release their backend reservation and force
     lane reconciliation when they expire before broadcast acceptance.
   - [x] Signed NEAR leases release local reservation state when they expire;
     NEAR dropped/replaced detection remains chain-detector dependent.
5. [x] Clear all lane leases for an account on wallet lock, account switch, or
   signer reset.
   - [x] Account-scoped reset clears EVM backend lanes, active NEAR access-key
     context, and coordinator leases for that account.
   - [x] Wallet lock and `SigningEngine.destroy()` now call coordinator
     `clearAll()` so EVM and NEAR lane state are reset together.

### Phase 6. Remove Old Nonce Paths

1. [x] Delete direct calls to EVM and NEAR nonce helpers from transaction
   signing flows.
   - [x] Removed direct NEAR nonce pre-initialization from transaction,
     delegate, and NEP-413 orchestration paths.
   - [x] Removed direct no-lease NEAR transaction lifecycle cleanup fallbacks
     from `sendTransaction`; coordinator-backed results now report coordinator
     lifecycle, and externally managed results do not mutate local reservations.
   - [x] TouchConfirm NEAR context fetch now goes through coordinator
     `fetchNearContext` / `reserveNearContext` methods.
   - [x] Resource prewarm, wallet lock/reset, and registration lifecycle now
     call coordinator NEAR access-key methods instead of the backend directly.
2. [x] Keep chain-specific RPC fetchers as coordinator ports, not independent
   nonce owners.
   - [x] Coordinator deps now treat EVM nonce code as a fetch-only backend
     port for chain-visible pending nonce reads.
   - [x] Rename the EVM coordinator port and implementation from manager
     terminology to `EvmNonceBackend`.
   - [x] Collapse the NEAR backend implementation into coordinator-local
     context fetch, prewarm, reservation, release, and finalized-refresh
     functions.
   - [x] Replace dedicated NEAR backend tests with coordinator behavior tests.
3. [x] Remove duplicate lifecycle helpers once coordinator transitions cover
   accepted, rejected, finalized, dropped, and replaced outcomes.
   - [x] EVM-family helper code now remains only as the event/metric adapter
     around coordinator transitions; transaction-facing nonce mutation is owned
     by `NonceCoordinator`.
   - [x] Renamed the EVM-family lifecycle boundary to
     `nonceLifecycleAdapter` and added a static guard that prevents EVM-family
     signing code from calling lifecycle transitions outside the adapter or
     coordinator.
4. [x] Add static guards that transaction signing code cannot bypass
   `NonceCoordinator` for managed nonce lanes.
5. [x] Update tests and docs to use "nonce coordinator" terminology.

### Phase 7. Observability And Runbooks

1. [x] Add redacted metrics for lease age, stale in-flight lanes, dropped txs,
   replacement detection, reconcile results, and release reasons.
   - [x] Coordinator traces now include signed-lease expiry, lane
     reconciliation, and lane-clear events.
   - [x] Add aggregate metric emission for lease age and stale in-flight lanes
     through `getDiagnostics({ emitMetrics: true })`.
   - [x] Add redacted outcome counters for dropped/replaced detections,
     reconcile reasons, release reasons, expiry reasons, and broadcast
     rejections.
2. [x] Add a developer diagnostic view that shows nonce lane state beside wallet
   signing-session budget state.
   - [x] `NonceCoordinator.getDiagnostics()` exposes redacted lease counts,
     lane counts, per-state counts, and active NEAR context state for a future
     UI/debug panel.
   - [x] Wire diagnostics into the developer panel beside wallet-session budget
     through `getWalletSession().nonceDiagnostics`.
3. [x] Document recovery steps for a stuck nonce lane:
   reconcile lane, clear expired reserved leases, and retry signing.
   - [x] Added the recovery runbook below.
4. [x] Add alerts for repeated dropped/replaced outcomes by chain and sender.
   - [x] `NonceCoordinator` emits a redacted `nonce_lane_alert` trace and a
     `console.warn` when repeated dropped/replaced outcomes cross the configured
     threshold for one EVM-family lane.

### Phase 8. Durable Same-Origin Coordination Hardening

Phase 5 introduced same-origin coordination, but the current EVM-family durable
lease mirror is still a `localStorage` implementation detail. Replace it with a
wallet-iframe IndexedDB-backed coordination layer and extend the same layer to
NEAR.

The storage invariant for this phase is strict:

1. Do not create a new IndexedDB database for nonce coordination.
2. Store nonce lane coordination records in the existing wallet iframe
   IndexedDB surface, behind `IndexedDBManager` / `UnifiedIndexedDBManager`.
3. In wallet-iframe mode, app-origin IndexedDB remains disabled; nonce leases
   are stored only in the wallet iframe origin.
4. Do not use `localStorage` as the durable nonce lease store after the
   migration.
5. Do not persist signed transaction bytes, raw transaction payloads, OTP
   material, PRF output, recovery keys, or threshold secret material.

#### Phase 8.1. IndexedDB Same-Origin Lock/Store Abstraction

1. [x] Add a coordinator storage port for same-origin nonce coordination:
   `NonceLaneCoordinationStore`.
   - Required operations:
     - read active leases by `laneKey`;
     - upsert a redacted lease record;
     - remove one lease;
     - clear leases by account;
     - clear all leases;
     - prune expired leases;
     - acquire/release a lane-scoped durable lock with a fencing token.
2. [x] Implement the port in the wallet iframe IndexedDB layer.
   - Add a store to `PasskeyClientDB` rather than creating another database.
   - Store names: `nonceLaneLeasesV1` and `nonceLaneLocksV1`.
   - Suggested key: `leaseId`.
   - Suggested indexes:
     - `laneKey`;
     - `accountId`;
     - `state`;
     - `expiresAtMs`;
     - `lane_state`, e.g. `[laneKey, state]`;
     - `account_expiresAt`, e.g. `[accountId, expiresAtMs]`.
3. [x] Store only redacted lease metadata:
   - `v`;
   - `leaseId`;
   - `laneKey`;
   - `family`;
   - `chain` for EVM-family lanes;
   - `networkKey`;
   - `chainId` for EVM-family lanes;
   - sender address for EVM-family lanes;
   - `nonceKey` when present;
   - `accountId`;
   - NEAR `publicKey` for NEAR lanes;
   - `nonce`;
   - `state`;
   - `operationId`;
   - `operationFingerprint`;
   - `reservedAtMs`;
   - `expiresAtMs`;
   - `updatedAtMs`;
   - `runtimeId`;
   - `fencingToken`.
4. [x] Keep `navigator.locks` as the preferred lock when available, but make
   IndexedDB the durable fallback. If both are unavailable, the coordinator may
   use the existing in-runtime lock, but it must emit a degradation warning.
5. [x] Replace `NonceCoordinatorSameOriginLeaseStorePort`'s `localStorage`
   implementation with the IndexedDB-backed store.
6. [x] Remove the old `localStorage` durable lease path entirely.
   - Development invariant: no legacy fallback, migration shim, or cleanup path
     remains in the coordinator or nonce coordination storage code.
7. [x] Add tests for:
   - IndexedDB unavailable -> in-runtime lock only + degradation warning;
   - Web Locks unavailable but IndexedDB available -> durable lock/store works;
   - two coordinator instances in the same origin reserve distinct EVM nonces;
   - expired IndexedDB records are pruned before reservation;
   - account clear removes durable lease records.
8. [x] Add static guard tests for the refactor:
   - no `localStorage` usage in `NonceCoordinator` or nonce coordination
     storage code;
   - no new IndexedDB database name for nonce coordination;
   - nonce durable store implementation must route through
     `IndexedDBManager` / `UnifiedIndexedDBManager` / `PasskeyClientDB`;
   - no transaction signing flow imports a durable nonce store directly;
   - no chain adapter mutates nonce lease state directly.
9. [x] Tighten those temporary static guards into stable ownership guards.
   - The guard now asserts the stable invariant: transaction code talks to
     `NonceCoordinator`; durable nonce persistence is hidden behind the
     coordinator storage port; no `localStorage` durable lease store remains.

#### Phase 8.2. Startup Recovery For EVM Signed/Broadcast Leases

1. [x] Add a startup recovery method:
   `NonceCoordinator.recoverDurableLeases({ accountId? })`.
2. [x] Run recovery during wallet iframe startup/unlock after IndexedDB is
   initialized and before the first transaction signing attempt.
3. [x] Recovery rules for EVM-family durable leases:
   - expired `reserved`: remove the lease and free the local lane;
   - expired `signed`: remove the lease, force lane reconciliation, and log a
     redacted recovery event;
   - active `signed`: keep it protected until its signed-lease TTL expires;
   - `broadcast_accepted`: reconcile the lane against pending nonce state;
   - finalized or chain-advanced nonces: mark recovered/finalized and remove
     active durable lease protection;
   - disappeared pending tx hash, when known: mark dropped/replaced and
     reconcile.
4. [x] Keep recovery idempotent. Running it repeatedly must not issue new
   nonces, spend wallet-session budget, or rebroadcast transactions.
5. [x] Do not persist raw signed tx bytes in this phase. Recovery is nonce-lane
   cleanup and reconciliation, not a rebroadcast queue.
6. [x] Add tests for startup recovery:
   - signed-but-not-broadcast lease expires and reconciles;
   - broadcast-accepted lease survives restart and blocks duplicate nonce
     reservation until reconcile;
   - chain nonce advancement clears stale in-flight leases;
   - recovery never mutates wallet-session budget.
7. [x] Add static guard tests for the refactor:
   - startup recovery is invoked only from wallet startup/unlock boundaries, not
     from transaction signing hot paths;
   - recovery code must not import wallet budget mutation APIs;
   - recovery code must not persist, read, or rebroadcast raw signed
     transactions.
8. [x] Tighten those temporary guards after EVM startup recovery has settled.
   - The stable guard now asserts the important invariant: recovery never spends
     wallet-session budget and never rebroadcasts transactions.

#### Phase 8.3. NEAR Same-Origin Durable Leases

1. [x] Extend the IndexedDB same-origin lease store to support NEAR lanes using
   the same record shape and lock abstraction.
2. [x] Use lane keys of the form:
   `near:<networkKey>:<accountId>:<publicKey>`.
3. [x] Persist NEAR per-transaction child leases for batch reservations.
   - One NEAR confirmation flow may reserve a batch.
   - Each transaction nonce in that batch has its own lease id, state, nonce,
     `batchId`, and `txIndex`.
4. [x] On `reserveNearContext`, read active durable NEAR leases and skip those
   nonces when computing the next batch.
5. [x] On release/finalize/expiry, update both the in-runtime NEAR reservation
   set and the durable IndexedDB lease record in one serialized lane operation.
6. [x] On startup recovery, refresh the NEAR access-key nonce and prune durable
   NEAR leases below or equal to the chain-visible access-key nonce.
7. [x] Add tests for:
   - two same-origin coordinators reserve non-overlapping NEAR batch nonces;
   - release recomputes highest reserved nonce across in-runtime and durable
     records;
   - startup recovery prunes finalized NEAR durable leases;
   - wallet/account clear removes NEAR durable records;
   - delegate and NEP-413 confirmation contexts still do not reserve
     transaction nonce leases.
8. [x] Add static guard tests for the refactor:
   - no NEAR transaction path writes durable lease records except through
     `NonceCoordinator`;
   - no separate NEAR nonce manager/helper owns reserved nonce sets outside the
     coordinator;
   - delegate and NEP-413 confirmation paths cannot call transaction nonce
     reservation APIs.
9. [x] Tighten those temporary guards after NEAR durable leases are fully
   integrated.
   - Keep only the stable ownership guard: NEAR transaction nonce allocation is
     coordinator-owned, and non-transaction confirmation flows do not reserve
     access-key transaction nonces.

#### Phase 8.4. Degraded Coordination Warnings

Do not add a vague diagnostics enum just to name implementation details. The
runtime only needs to surface degradation when it changes the safety properties
of nonce allocation.

1. [x] Add a redacted `nonce_coordination_degraded` trace/warning when the
   coordinator cannot acquire a same-origin lock or cannot access the durable
   IndexedDB lease store.
2. [x] Include only actionable fields:
   - `reason`: `web_locks_unavailable`, `indexeddb_unavailable`,
     `durable_lock_timeout`, or `durable_store_error`;
   - `laneFamily`;
   - `networkKey`;
   - `accountId`, when known;
   - whether the coordinator is falling back to in-runtime locking.
3. [x] Show the warning in developer diagnostics only when degraded mode is
   active or was observed during the current runtime.
4. [x] Do not show normal implementation mode names such as `"web_locks"` or
   `"indexeddb"` in user-facing status. Normal mode is not user-actionable.
5. [x] Add tests that degraded warnings are emitted once per runtime/lane reason
   and do not spam every reservation.

## Stuck Nonce Lane Recovery Runbook

Use this runbook when a signer appears stuck at transaction-status polling, when
the EVM-family lifecycle reports `tx_dropped_or_replaced`, or when a developer
diagnostic snapshot shows reserved/signed leases that are older than their
expected TTL.

1. Capture a redacted coordinator diagnostic snapshot:
   call `signingEngine.getNonceCoordinator().getDiagnostics({ accountId })` and
   record `leaseCount`, `leasesByState`, lane `family`, `networkKey`, `chain`,
   `chainId`, and per-lane state counts. Do not log signed transaction bytes,
   private keys, PRF output, recovery keys, or OTP material.
2. Expire local abandoned leases:
   call `signingEngine.getNonceCoordinator().expireLeases({ accountId })`.
   Reserved leases release the local nonce reservation. Signed-but-not-broadcast
   EVM-family leases release the reservation and force lane reconciliation.
3. Reconcile the affected EVM-family lane:
   call `signingEngine.getNonceCoordinator().reconcile({ lane })` with the same
   `networkKey`, `chainId`, sender, optional `nonceKey`, and account id used by
   the failed signing operation. If the lane reports `blocked: true`, avoid
   issuing another transaction for that lane until the blocked nonce finalizes,
   drops, or is replaced.
4. Retry signing with a fresh operation id:
   reuse an operation id only when the operation fingerprint is identical. A
   changed transaction payload must allocate a new operation id so wallet budget
   idempotency cannot hide a real spend or nonce transition.
5. If account state was switched or the runtime is clearly stale, clear local
   lane state:
   call `signingEngine.getNonceCoordinator().clearForAccount(accountId)` for an
   account-scoped reset, or `clearAll()` during wallet lock/signer teardown. The
   next signing attempt must fetch fresh chain-visible nonce state.
6. Escalate repeated dropped/replaced outcomes:
   collect chain, network key, sender, nonce key, transaction hash, finalization
   branch, and coordinator trace ids. Repeated drops for the same sender/lane
   should be treated as chain/RPC or transaction-fee policy issues, not as wallet
   budget failures.

## NEAR Dropped/Replaced Detector Design

NEAR does not have an EVM-style pending pool replacement model. There is no
account-local transaction nonce replacement rule where a later transaction with
the same nonce and higher fee clearly supersedes the earlier transaction. A
NEAR access-key nonce is consumed only when a transaction is accepted into a
block. Before that point, a missing transaction hash can mean RPC propagation
lag, block-finality lag, mempool eviction, invalid transaction rejection, or an
RPC node that never observed the transaction.

The coordinator should therefore avoid naming NEAR outcomes `dropped` or
`replaced` until a detector can prove the distinction. The stable NEAR detector
should classify outcomes as:

1. `finalized`: the transaction hash is found in a final block, and the access
   key nonce has advanced to at least the transaction nonce.
2. `accepted_nonfinal`: the transaction hash is visible but not final yet. Keep
   the durable lease protected and continue status polling.
3. `nonce_advanced_hash_missing`: the access-key nonce has advanced past the
   leased nonce, but the transaction hash is not found through the configured
   RPC. Treat the lease as resolved and reconcile the lane. Do not call it
   replaced; another transaction may have consumed the nonce, but NEAR does not
   expose the EVM replacement semantics needed to prove that.
4. `expired_hash_missing_nonce_not_advanced`: the lease TTL elapsed, the hash is
   not found, and the access-key nonce is still below or equal to the leased
   nonce. Treat this as a local lease expiry/release. The same nonce can be
   retried after fresh chain context is fetched.
5. `invalid_or_rejected`: RPC returns a deterministic transaction execution or
   validation error for this hash. Release or finalize the lease according to
   whether the access-key nonce advanced.
6. `unknown`: RPC is unavailable or contradictory. Keep the durable lease until
   TTL/recovery and surface a degraded diagnostic rather than allocating over
   the possibly active nonce.

Detector inputs:

1. `accountId`, `publicKey`, `networkKey`, leased `nonce`, `txHash`, `batchId`,
   `txIndex`, `reservedAtMs`, `signedAtMs`, and `broadcastAcceptedAtMs`.
2. Current access-key nonce from `viewAccessKey(accountId, publicKey)`.
3. Transaction status by hash and signer account from the configured NEAR RPC.
4. The coordinator's durable lease state and signed/broadcast TTL policy.

Coordinator transitions:

1. `finalized` -> `markFinalized`, refresh the access-key nonce, remove the
   durable lease.
2. `accepted_nonfinal` -> keep `broadcast_accepted`, extend only within a
   bounded polling window.
3. `nonce_advanced_hash_missing` -> new NEAR-specific resolved transition, or
   `markFinalized` with reason `near_nonce_advanced_hash_missing`; remove the
   durable lease and emit a warning metric.
4. `expired_hash_missing_nonce_not_advanced` -> release the lease with reason
   `near_hash_missing_nonce_not_advanced`; force fresh context before retry.
5. `invalid_or_rejected` -> release or finalize based on access-key nonce
   advancement, and emit the RPC error class as a redacted reason.
6. `unknown` -> no nonce allocation over the lease; emit
   `nonce_coordination_degraded` or a NEAR lane warning.

Implementation phases:

1. Add a NEAR transaction-status port to `NonceCoordinator` rather than letting
   signing flows query status and mutate leases directly.
2. Persist `txHash` and `broadcastAcceptedAtMs` in the durable NEAR lease
   record. Continue to avoid persisting signed transaction bytes.
3. Add `reconcileNearLane({ lane })` that examines every active durable NEAR
   lease for the lane under the lane lock.
4. Add status tests for the six detector outcomes above using a fake NEAR RPC.
5. Only after those semantics are covered, mark Phase 3 item 3 complete.

## Acceptance Checks

1. A cancelled transaction cannot leak a nonce reservation indefinitely.
2. A malformed managed nonce snapshot cannot clean up the wrong chain lane.
3. NEAR, Tempo, Arc EVM, and generic EVM all use one nonce lifecycle model.
4. Two concurrent transactions with two remaining wallet-session uses make the
   third transaction require fresh auth.
5. A transaction that produced a threshold signature consumes budget exactly once
   regardless of broadcast/finality result.
6. A transaction that did not produce a threshold signature never consumes
   wallet-session budget.
7. Stuck "Checking transaction status" states have a traceable nonce-lane reason
   and an explicit reconcile path.
8. Old nonce-manager ownership paths are removed instead of kept as parallel
   legacy systems.

## Related Docs

1. [Signing Session Architecture](./signing-session-architecture.md)
2. [Signing Session Coordinator Tests](./signing-session-coordinator-tests.md)
3. [Email OTP Signing Sessions](./email-otp-sessions.md)

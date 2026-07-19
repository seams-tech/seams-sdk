# Regression Checkpoint 1: Restore ECDSA Wallet Lifecycle Correctness

Date created: July 19, 2026

Status: planned; blocks the start of Refactor 90 implementation.

## Purpose

Create a clean, working checkpoint on top of the current branch before beginning
[Refactor 90](./refactor-90-modular-auth-capabilities-plan.md).

Commit `06c923053` combined registration, persistence, unlock, recovery, signing,
export, and server-selector changes. The resulting system no longer preserves one
ECDSA role-local material identity across those entry points. The production-like
local Router A/B topology then exposed the broken transitions.

This plan restores correctness within the current architecture. Refactor 90 owns
the final capability model, canonical activation journal, modular auth boundaries,
and broader persistence redesign.

## Decision

Repair the current branch through a short series of concern-specific commits.
Do not revert `06c923053`, restore its deleted legacy runtimes, or begin the
Refactor 90 module split during this checkpoint.

The checkpoint will:

1. preserve and consolidate existing browser ECDSA material;
2. establish one durable representation and one volatile representation of
   role-local material;
3. make registration commit the exact client material and SigningWorker
   activation later used by unlock, signing, and export;
4. make unlock rehydrate the exact registered material;
5. remove fresh threshold-PRF recovery from existing-key activation;
6. make every EVM-family operation use one hydration path while preserving one
   shared EVM-family key identity;
7. repair explicit export so SigningWorker releases the exact registered server
   additive share through one authorized, recipient-bound operation;
8. keep the Cloudflare Durable Object activation repair required by the current
   local topology; and
9. prove the lifecycle through a focused end-to-end checkpoint matrix.

## Relationship To Other Plans

- [Refactor 90](./refactor-90-modular-auth-capabilities-plan.md) remains the main
  architectural correction. It owns canonical MPC capability hydration,
  `ActiveEcdsaCapabilityManifest`, `DurableEcdsaMaterialBinding`,
  `ActiveEcdsaMaterialSession`, activation journaling, and auth capability
  modularization.
- [Refactor 90A](./refactor-90A-patches.md) owns the permanent protocol deletion
  of threshold-PRF client-share rederivation and exact-material possession proof.
  This checkpoint removes the incorrect recovery call from active SDK flows and
  keeps missing-device behavior fail closed.
- Refactor 95 owns exact wrapped-custody restoration.
- Refactors 97 and 98 own independently revocable linked-device lanes.

This checkpoint does not create temporary substitutes for those planned
domains. It uses the existing hydration union and current role-local persistence
contracts to restore correct behavior.

## Scope

### In Scope

- Passkey ECDSA registration and immediate activation.
- Existing-device wallet unlock.
- Browser reload and worker restart.
- NEAR signing through the production-equivalent Cloudflare worker topology.
- Tempo and EVM transaction signing.
- Ed25519 and ECDSA key export.
- Consolidation of ECDSA role-local and presign IndexedDB state into
  `seams_wallet`.
- Exact chain-qualified operation projection over one shared EVM-family key.
- Registration and inventory response boundary parsing.
- Durable Object activation persistence required by the checkpoint.
- Removal of obsolete tests that encode the broken recovery or persistence
  behavior.

### Out Of Scope

- Refactor 90 capability-module extraction.
- New auth providers.
- Cross-device ECDSA material provisioning.
- Additive ECDSA lane resharing.
- Exact wrapped-custody restoration.
- General wallet persistence redesign.
- Unrelated iframe, UI, Gateway, and deployment refactors.
- Migration support outside the two IndexedDB databases introduced by
  `06c923053`.

## Regression Ledger

### Regressions Introduced By `06c923053`

| ID | Regression | User-visible result | Required correction |
| --- | --- | --- | --- |
| R1 | Existing-key activation ran a fresh threshold-PRF recovery ceremony | Recovery produced a different client public share for a fresh transcript | Activate the exact material produced at registration or restored from durable local storage |
| R2 | Durable session state and volatile WASM handles were mixed | `volatile worker handle is not durable state` and invalid persisted-session errors | Persist only sealed material identity; keep the live handle only in worker/runtime memory |
| R3 | `rehydrate_active_session` was accepted without opening the sealed material | Tempo, EVM, and export reached execution with `session record is missing role-local state` | Execute rehydration, register the live handle, and verify its exact durable binding |
| R4 | Role-local and presign material moved into standalone IndexedDB databases | Extra `seams_router_ab_ecdsa_*` databases fragmented wallet state | Copy the sealing keys and encrypted records into `seams_wallet`, verify them, and retire the source databases |
| R5 | The registration bootstrap runtime containing the in-process server-share writer was deleted while presign still retained that fallback | Presign returned `ECDSA key selector is not active on this server` | Require the private SigningWorker transport in strict topology and delete the unsupported Gateway-local fallback |
| R6 | ECDSA profile and lane lookup conflated shared key identity with concrete-chain projections | Valid Tempo and EVM projections appeared as duplicate key handles | Keep one wallet-level EVM-family key identity and qualify only profile, inventory, lane, session, and authorization projections by chain target |
| R7 | Unlock required one exact capability while profile repair remained incomplete | Unlock returned `requires one exact persisted public capability` | Resolve from authenticated chain-qualified inventory and durably repair stale profile metadata |
| R8 | Registration, unlock, signing, and export used different material lookup paths | One operation worked while another reported missing material | Route all entry points through one exact role-local material resolver |
| R9 | Registration finalization trusted broad generic response typing | Malformed or partial capability state reached core lifecycle logic | Parse the complete response once at the RPC boundary |
| R10 | Registration bootstrap and recovery retained competing Rust/WASM ownership | Duplicate commands and types obscured which flow owned client material | Keep one registration bootstrap owner and remove recovery-only ownership after its callers move |
| R11 | Explicit export passed a fresh threshold-PRF output as the registered server additive share | Export failed the public-key equality check or could reconstruct the wrong key if validation weakened | Add a one-time SigningWorker export operation that derives and wraps the exact registered server additive share for the authorized client recipient |

### Related Defects Required For The Checkpoint

These defects were not introduced by `06c923053`, but the checkpoint cannot pass
while they remain.

| ID | Source | Defect | Required correction |
| --- | --- | --- | --- |
| C1 | Current uncommitted IndexedDB consolidation | Opening `seams_wallet` deletes old ECDSA databases without migrating their records | Replace deletion-on-open with an idempotent copy, verification, and delayed cleanup protocol |
| C2 | `71ef1d62f`, exposed by `23bd983e3` | Cloudflare Durable Object activation multi-write did not produce reliably readable material and active-state records | Use the correct raw multi-write representation and verify both records before reporting success |
| C3 | `23bd983e3` topology cutover | Old native-worker local state is outside the new Wrangler Durable Object namespaces | Treat old server-side local state as a development reset boundary; do not weaken active-state validation |

Transient errors created and fixed only in the uncommitted worktree cannot be
assigned to a historical commit. They must still be covered by the checkpoint
matrix.

## Current Worktree Disposition

The uncommitted worktree contains valid forward fixes alongside incomplete or
incorrect corrections. Preserve, revise, or remove them as follows.

### Preserve

- Actual sealed-material rehydration in
  `flows/signEvmFamily/readySecp256k1Material.ts`.
- Existing-material post-registration activation in
  `threshold/ecdsa/postRegistrationSessionActivation.ts`.
- Authenticated inventory repair persistence in `operations/auth/login.ts`.
- Full registration-finalize boundary parsing in
  `rpcClients/relayer/walletRegistration.ts`.
- Strict private SigningWorker presign transport.
- Durable Object raw multi-write and exact read-back validation.
- Canonical live-handle and durable-reference branding that prevents epoch,
  session, and material-reference substitution.

### Revise

- Make strict private SigningWorker transport required and delete its
  in-process fallback.
- Keep chain qualification on operation projections while removing it from
  wallet-level EVM-family material identity.
- Replace database deletion with authenticated migration and delayed cleanup.
- Replace fresh-PRF explicit export with a one-time SigningWorker exact-share
  release.
- Ensure every preserved fix uses narrow branch-specific inputs and no optional
  lifecycle bags or broad object spreads.

### Remove

- Gateway-local ECDSA server-share lookup used by presign fallback.
- Destructive obsolete-database cleanup.
- Fresh threshold-PRF calls for existing-key activation or explicit export.
- Tests and fixtures that require any of those paths.

## Required Invariants

1. Registration creates the owner-lane ECDSA client share exactly once.
2. The registered client public share, threshold public key, EVM address,
   participant tuple, signing-root scope, and key slot remain stable across
   registration, unlock, signing, and export. Each operation retains its exact
   chain-target projection and authorization.
3. A durable record contains a sealed material reference and public binding
   facts. It cannot contain a live worker handle.
4. A live worker handle exists only in volatile worker/runtime state and is
   bound to one exact durable material reference.
5. `use_live_runtime` verifies the live handle and exact session identity.
6. `rehydrate_active_session` opens the exact sealed material before publishing
   a live runtime.
7. Missing, corrupt, conflicting, unavailable, and binding-mismatched
   persistence remain distinct outcomes.
8. `device_link_required` is returned only after exact local lookup establishes
   that material is genuinely absent for this device.
9. Existing-key activation makes no ECDSA derivation recovery request.
10. Registration cannot report success until the exact SigningWorker activation
    required by presign is durably readable.
11. EVM-family key material is identified by wallet, signing-root-derived slot,
    handle, and registered capability. It is shared across concrete EVM chains.
12. Boundary parsers produce precise internal types before core lifecycle code
    receives a value.
13. Diagnostics, timestamps, source priority, and optional profile fields cannot
    select a capability or authorize an operation.
14. IndexedDB source databases remain untouched until their destination records
    and sealing keys have passed authenticated read-back.
15. A failed or blocked migration never creates a new sealing key that hides
    recoverable old material.
16. Cloudflare activation success means both the material record and its
    active-state index are durably readable.
17. Explicit export obtains the server additive share only from the selected
    SigningWorker, after one-time authorization, and delivers it only in a
    recipient-bound encrypted envelope.
18. Gateway never persists or receives the plaintext server additive share.

## Checkpoint State Model

### Durable Role-Local State

The checkpoint keeps one durable role-local record shape with required:

- durable material reference;
- exact binding digest;
- lifecycle ID;
- transcript and activation digests;
- activation timestamp;
- encrypted worker state;
- non-exportable AES-GCM sealing key stored in `seams_wallet`; and
- exact public facts carried by the owning session/capability record.

No durable shape may admit a worker handle, runtime validation marker, current
operation grant, quota state, or request nonce.

### Live Role-Local State

One canonical live handle type represents material opened inside the WASM
worker. The runtime registry binds it to:

- the durable material reference;
- the threshold session;
- the exact public facts;
- the authentication method; and
- the worker instance that owns the plaintext state.

Destroying the worker removes the live state without changing the durable
record.

### Exact Key Identity

The underlying EVM-family material uses one wallet-level identity:

```text
wallet ID
+ EVM-family signing key slot
+ signing root and version
+ key handle
+ registered public-capability identity
```

Concrete chain target is added by profile, inventory, lane, session,
authorization, and operation-projection records. Tempo, Arc, and other EVM
targets may project the same key and address. They do not create independent
role-local material.

## Target Flows

### Registration

```text
WebAuthn authorization
  -> Router A/B registration ceremony
  -> client worker creates one role-local share
  -> client worker returns opaque handle plus public facts
  -> SDK seals role-local state into seams_wallet
  -> Gateway commits the public signer projection
  -> SigningWorker commits exact server activation material
  -> SDK activates the exact live registration handle
  -> exact persisted record is readable
  -> registration reports success
```

No recovery ceremony occurs after registration.

### Existing-Device Unlock

```text
authenticated exact key inventory
  -> resolve chain-qualified capability
  -> inspect exact local material
     -> live: verify and use
     -> sealed: decrypt in worker, verify, bind, and use
     -> absent: device_link_required
     -> corrupt/conflicting/unavailable: return exact failure
  -> activate or refresh server material without changing client identity
  -> publish ready capability
```

### Signing And Export

```text
exact operation target
  -> exact chain-qualified signer
  -> shared hydration resolver
  -> verified live role-local handle
  -> operation-specific authorization
  -> presign/sign or export
```

Tempo, EVM signing, and ECDSA export cannot implement separate fallback
selection.

### Explicit ECDSA Export

```text
fresh export authorization and grant
  -> exact wallet-level EVM-family key identity
  -> exact active SigningWorker material
  -> SigningWorker derives the registered server additive share
  -> verify server verifying share and registered threshold public key
  -> wrap share to the authorized client export recipient
  -> consume export grant and replay reservation once
  -> client worker combines exact client and server shares
  -> verify reconstructed public key and address
  -> return export artifact
```

Deriver A/B do not create a fresh threshold-PRF output for explicit export.
Gateway carries authorization and opaque ciphertext only.

## Implementation Phases

Required order:

1. Phase 0 prevents further local material loss.
2. Phase 1 consolidates durable browser material.
3. Phase 2 freezes the durable/live state boundary.
4. Phases 3 and 4 restore registration and unlock continuity.
5. Phase 5 cuts every operation over to the same material path.
6. Phase 6 repairs explicit export without changing server-share custody.
7. Phase 7 closes the production-equivalent Worker persistence defect.
8. Phases 8 and 9 remove obsolete paths and establish the checkpoint.

### Phase 0: Freeze And Protect Existing State

- [ ] Remove `deleteObsoleteStandaloneWalletDatabases()` from the general
      `SeamsWalletDBManager.getDB()` path.
- [ ] Prevent any startup path from deleting
      `seams_router_ab_ecdsa_role_local_session_v1`.
- [ ] Prevent any startup path from deleting
      `seams_router_ab_ecdsa_presign_material_v2`.
- [ ] Keep all current repair work isolated from Refactor 90 module changes.
- [ ] Record a compact failure matrix for fresh registration, immediate signing,
      reload, unlock, export, worker restart, and migration.
- [ ] Confirm which current tests encode obsolete recovery or destructive
      deletion behavior and mark them for removal in Phase 8.

Exit criteria:

- opening the current SDK cannot delete either source database;
- no checkpoint task depends on a Refactor 90 type that has not landed; and
- the known failure matrix distinguishes `06c923053`, current-worktree, and
  topology-exposed defects.

### Phase 1: Consolidate ECDSA IndexedDB State

#### Destination

Use the existing `seams_wallet` stores:

- `ecdsa_role_local_sealing_keys`;
- `ecdsa_role_local_active_material`;
- `ecdsa_presign_sealing_keys`; and
- `ecdsa_presign_records`.

Do not add another database.

#### Migration Contract

- [ ] Implement migration in a persistence-boundary module owned by
      `seamsWalletDB`.
- [ ] Represent migration lifecycle as an exhaustive persisted state:
      `copy_pending`, `copy_verified`, `cleanup_pending`, `complete`, or
      `failed`.
- [ ] Give every branch required source version, destination schema version,
      record counts, and completion timestamp fields appropriate to that branch.
- [ ] Keep failure details diagnostic. They cannot authorize deletion or
      replacement.
- [ ] Detect source database absence without leaving a newly created empty
      database. Use `indexedDB.databases()` when supported and an
      upgrade-aborting probe for the fallback.
- [ ] Open the version-1 role-local source database read-only.
- [ ] Copy its non-exportable `CryptoKey` through IndexedDB structured cloning.
- [ ] Copy encrypted role-local rows without changing their version-1 header,
      IV, ciphertext, or AES-GCM additional authenticated data.
- [ ] Open each copied version-1 row with the migrated key, verify its exact
      binding, reseal it as the destination version with a fresh IV and current
      authenticated header, and read it back again.
- [ ] Open the version-2 presign source database read-only.
- [ ] Copy its sealing key and non-terminal, unexpired records.
- [ ] Preserve reservation and revision state exactly for copied presign rows.
- [ ] Skip expired or terminal presign rows through an explicit counted
      retirement result.
- [ ] Perform destination writes in transactions scoped to the corresponding
      destination stores.
- [ ] Treat an exact destination match as idempotent success.
- [ ] Treat a destination key or record mismatch as `failed`; never overwrite
      either side.
- [ ] Read back the destination records and keys.
- [ ] Decrypt at least every active role-local record with its migrated key and
      verify its binding digest before marking `copy_verified`.
- [ ] Exercise one copied presign record through its normal parser and
      cryptographic opening path when a valid record exists.
- [ ] Close all source database connections before cleanup.
- [ ] Move to `cleanup_pending` after verified copy.
- [ ] Attempt source deletion only on a later startup after `cleanup_pending`
      is durably readable.
- [ ] Keep `cleanup_pending` when deletion is blocked. Do not report completion.
- [ ] Mark `complete` only after both obsolete database names are absent.

Compatibility code is limited to this migration adapter. Core signing,
hydration, and registration code cannot import the version-1 source shapes.

Exit criteria:

- a pre-consolidation same-device account unlocks and signs after migration;
- a fresh account creates only `seams_wallet`;
- interrupted migration resumes idempotently at every phase;
- source material survives copy, verification, blocked deletion, and reload;
- no destructive deletion test remains; and
- successful cleanup leaves no `seams_router_ab_ecdsa_*` database.

#### Irrecoverable Profiles

If the destructive cleanup has already deleted a source database, its
non-exportable sealing key cannot be reconstructed. The migration must report
the source as absent and must not claim that the old account was migrated.
Such a profile can proceed only through an exact custody or device-link flow
owned by later refactors.

### Phase 2: Canonicalize Durable And Live Material

- [ ] Keep one canonical `EcdsaRoleLocalWorkerHandle` type.
- [ ] Keep one canonical durable material reference type.
- [ ] Remove competing handle aliases from SDK interfaces, worker channels, and
      persistence records.
- [ ] Make persisted session records reject every volatile handle field at the
      boundary parser.
- [ ] Keep the volatile registry separate from serializable session records.
- [ ] Key the registry by exact threshold session and durable material identity.
- [ ] Require public facts and auth method when binding a live handle.
- [ ] Provide branch-specific builders for live, rehydrated, and blocked
      material states.
- [ ] Make every switch over hydration and material state exhaustive.
- [ ] Add static fixtures rejecting:
      - a persisted live handle;
      - a live branch without exact public facts;
      - a rehydrate branch without a durable reference;
      - a blocked branch with a usable handle; and
      - a broad object spread that combines live and durable-only fields.
- [ ] Remove tests and fixtures that construct the obsolete mixed record.

Exit criteria:

- one live handle type remains;
- no serializable type can contain a volatile handle;
- destroying the worker changes only the volatile observation; and
- the same durable record can be rehydrated into a new worker instance.

### Phase 3: Repair Registration Commit And Activation

- [ ] Parse the complete registration-finalize response at
      `walletRegistration.ts`.
- [ ] Normalize wallet ID, chain target, signing key slot, key handle, threshold
      session ID, signing grant ID, public capability, participant tuple, and
      activation facts once.
- [ ] Reject missing, duplicate, mismatched, or malformed identity fields before
      registration core receives the response.
- [ ] Persist the encrypted client role-local material into `seams_wallet`.
- [ ] Read it back and verify its exact public binding before continuing.
- [ ] Persist server role-local material only through the selected
      SigningWorker activation boundary.
- [ ] Bind that activation to the exact wallet, EVM-family key slot, key handle,
      public capability, threshold session, SigningWorker identity, and server
      generation.
- [ ] Make activation idempotent for an exact record and conflicting for any
      mismatched record.
- [ ] Read the activation back through the same private SigningWorker boundary
      used by presign and normal signing.
- [ ] Ensure registration cannot report success before that exact activation is
      readable.
- [ ] Keep Gateway limited to public capability, activation receipt, and
      routing/admission state. Gateway cannot persist the server share.
- [ ] Activate the exact live role-local handle returned by registration.
- [ ] Compare its public facts with the finalized registered capability.
- [ ] Remove fresh threshold-PRF recovery from post-registration activation.
- [ ] Preserve registration rollback and terminal ceremony cancellation if any
      required commit fails.
- [ ] Release wallet-ID reservation through the existing terminal cancellation
      path after failed finalization.

Exit criteria:

- registration performs one client-share derivation;
- post-registration activation performs zero recovery calls;
- the role-local material opened after registration has the registered public
  facts;
- the SigningWorker activation is readable before success; and
- immediate NEAR, Tempo, and EVM signing use the registered key.

### Phase 4: Repair Existing-Device Unlock

- [ ] Resolve configured ECDSA targets through authenticated server inventory.
- [ ] Require exactly one capability for each exact chain target.
- [ ] Distinguish missing, duplicate, malformed, and stale-profile inventory.
- [ ] Persist an authenticated inventory repair into profile metadata instead of
      using a transient replacement.
- [ ] Resolve local role-local material through an exhaustive result:
      `live`, `sealed`, `missing`, `binding_mismatch`, `conflict`, `corrupt`, or
      `persistence_unavailable`.
- [ ] Reuse a validated live handle only when its threshold session, durable
      reference, and public facts match.
- [ ] Rehydrate sealed material inside the derivation worker.
- [ ] Bind the rehydrated handle to the volatile registry.
- [ ] Re-resolve readiness after binding.
- [ ] Return `device_link_required` only for the exact `missing` result.
- [ ] Return stable distinct errors for every other blocked result.
- [ ] Make no ECDSA recovery request from wallet unlock.
- [ ] Avoid broad spreads and optional runtime bootstrap bags in the unlock
      input. Construct the exact branch through a typed builder.

Exit criteria:

- a same-device reload rehydrates and signs;
- a migrated account rehydrates and signs;
- a genuinely material-free device receives `device_link_required`;
- corruption or unavailable IndexedDB is never mislabeled as a new device; and
- unlock makes zero strict ECDSA derivation recovery calls.

### Phase 5: Unify Signing And Export Material Resolution

- [ ] Make `buildReadySecp256k1SigningMaterialFromRecord` execute every
      hydration branch rather than merely classify it.
- [ ] In `use_live_runtime`, verify the exact registered handle.
- [ ] In `rehydrate_active_session`, open the sealed material, register the
      resulting handle, and verify its binding.
- [ ] Reject `reauthorize_public_anchor` and blocked branches with their exact
      domain result during this checkpoint.
- [ ] Require the ready signer key reference to contain the handle produced or
      verified by hydration.
- [ ] Route Tempo signing through this resolver.
- [ ] Route generic EVM signing through this resolver.
- [ ] Route ECDSA key export through this resolver.
- [ ] Keep Ed25519 signing and export behavior unchanged except where shared
      end-to-end verification exposes a real boundary defect.
- [ ] Remove target-specific source-priority or material-presence fallbacks.
- [ ] Require configured private SigningWorker transport when constructing the
      ECDSA presign runtime.
- [ ] Fail startup when strict ECDSA signing is enabled without that transport.
- [ ] Remove `ecdsaKeyStore` and `resolveRoleLocalKeyRecord` from the presign
      runtime after the private transport owns all key-material resolution.
- [ ] Delete the in-process presign branch that reads a Gateway-local server
      share.
- [ ] Make every presign init and step use the private SigningWorker transport.
- [ ] Carry chain target through profile, inventory, lane, session,
      authorization, and operation-projection lookups.
- [ ] Resolve underlying material by the wallet-level EVM-family key identity.
- [ ] Reject projections whose chain-qualified record points at a different
      wallet-level key identity.
- [ ] Remove chain target from material-store uniqueness where it would create
      separate Tempo, Arc, or EVM key material.
- [ ] Preserve exact chain qualification for operation policy and transaction
      authorization.

Exit criteria:

- Tempo, EVM signing, and ECDSA export use one hydration executor;
- reload before any operation still succeeds;
- strict ECDSA startup rejects an unconfigured SigningWorker transport;
- Gateway contains no ECDSA server-share lookup used by presign;
- a key for one chain target cannot satisfy another target accidentally; and
- all valid EVM-family projections resolve the same wallet-level key and
  address.

### Phase 6: Repair Explicit ECDSA Export

- [ ] Delete the path that passes a fresh threshold-PRF result to
      `serverExportShare32B64u`.
- [ ] Add a private SigningWorker export operation over the exact active ECDSA
      material.
- [ ] Require a fresh one-time export grant and replay reservation.
- [ ] Bind the request to wallet ID, EVM-family key slot, key handle, registered
      public capability, active server generation, export authorization digest,
      export transcript, and client recipient key.
- [ ] Derive the exact additive server share inside SigningWorker from the
      active server-output material and registered client public identity.
- [ ] Verify its public share and composed threshold public key equal the
      registered capability before release.
- [ ] Encrypt the additive share directly to the client export recipient.
- [ ] Keep plaintext share bytes inside the SigningWorker until encryption.
- [ ] Zeroize the derived share immediately after encryption.
- [ ] Keep Gateway and MPCRouter limited to authorization, routing, replay
      reservation, opaque ciphertext, and audit facts.
- [ ] Consume the one-time grant exactly once across success, replay,
      cancellation, timeout, and recipient mismatch.
- [ ] Make the client worker open the recipient envelope and combine the exact
      server share with its hydrated client share.
- [ ] Preserve the final public-key and EVM-address equality checks.
- [ ] Remove the Deriver A/B explicit-export PRF path after its only caller
      moves.

Exit criteria:

- explicit export performs zero threshold-PRF derivation calls;
- Gateway never receives or persists plaintext server share material;
- recipient, grant, transcript, capability, or server-generation substitution
  fails closed;
- replay cannot release the share twice; and
- exported private key reproduces the registered public key and EVM address.

### Phase 7: Close Cloudflare Durable Object Activation Persistence

- [ ] Encode multi-key Durable Object writes using the `workers-rs` raw object
      representation expected by the runtime.
- [ ] Commit the material record and active-state index in one storage
      operation.
- [ ] Read back both records before returning activation success.
- [ ] Validate that the read-back material and active-state index refer to the
      same account, session, worker, lifecycle, and material handle.
- [ ] Return a stable storage error when either read-back is absent or
      mismatched.
- [ ] Verify behavior after restarting the local Wrangler workers.
- [ ] Keep the production and local Worker implementation on the same code
      path.

Exit criteria:

- NEAR signing no longer receives a Durable Object 404 after successful
  registration;
- restart preserves the active state;
- memory-only tests cannot substitute for the real Workers storage check; and
- local and production use the same activation persistence implementation.

### Phase 8: Remove Obsolete Paths And Fixtures

- [ ] Delete the standalone store implementations after the migration adapter
      owns their raw source schemas.
- [ ] Keep source schema constants private to the migration adapter.
- [ ] Delete the destructive database cleanup helper and its test.
- [ ] Delete active SDK fallbacks that start strict ECDSA derivation recovery.
- [ ] Delete recovery worker commands and WASM exports whose only caller was
      the removed existing-key activation path.
- [ ] Update Refactor 90A's deletion ledger for any server routes or protocol
      types intentionally retained until its possession-proof cutover.
- [ ] Delete fixtures that manufacture volatile handles inside persisted
      records.
- [ ] Delete tests that expect chain-unqualified duplicate handling.
- [ ] Delete tests that treat missing local material as recoverable through a
      fresh derivation ceremony.
- [ ] Delete tests and fixtures that permit Gateway-local ECDSA server-share
      lookup in strict topology.
- [ ] Delete explicit-export fixtures that treat a fresh PRF output as the
      registered server additive share.
- [ ] Keep compatibility logic only in the IndexedDB migration and request
      boundary parsers.

Exit criteria:

- product code contains no duplicate role-local store or handle implementation;
- current behavior has one registration owner, one hydration executor, and one
  wallet-level material lookup plus one chain-qualified projection lookup;
- obsolete behavior has no supporting fixtures; and
- retained Refactor 90A work is explicit and unreachable from checkpoint
  existing-key flows.

### Phase 9: Verification And Checkpoint

#### Static And Focused Checks

- [ ] Run `pnpm type-check:sdk`.
- [ ] Run the ECDSA identity, persistence, registration boundary, hydration,
      inventory, and Cloudflare Durable Object focused tests.
- [ ] Run the Rust/WASM boundary checks affected by recovery ownership changes.
- [ ] Run source guards for duplicate handle types, persisted live handles,
      Gateway server-share ownership, chain-projection/material conflation,
      fresh-PRF export, and recovery calls from existing-key flows.

#### Build And Intended Behavior

- [ ] Run `pnpm build:sdk`.
- [ ] Run `pnpm test:intended`.
- [ ] Start the production-equivalent local workers with `pnpm router`.
- [ ] Verify the real browser flow against Caddy, Gateway, MPCRouter, Deriver A,
      Deriver B, and SigningWorker.

#### Required Lifecycle Matrix

| Scenario | Required result |
| --- | --- |
| Fresh registration | One ECDSA client share, one durable record, one readable SigningWorker activation |
| Registration then NEAR signing | Signature succeeds through real Cloudflare Durable Objects |
| Registration then Tempo signing | Signature succeeds through the exact SigningWorker activation |
| Registration then generic EVM signing | Signature succeeds with exact chain target |
| Registration then Ed25519 export | Export succeeds with unchanged Ed25519 behavior |
| Registration then ECDSA export | Export combines the hydrated client share with a one-time recipient-wrapped exact SigningWorker share and reproduces the registered key |
| Reload then unlock | Durable material rehydrates and requested capabilities warm |
| Reload then Tempo/EVM signing | Shared hydration executor succeeds |
| Worker restart then NEAR signing | Durable Object active state remains readable |
| Pre-consolidation browser profile | Material migrates, unlocks, and signs |
| Interrupted migration | Next startup resumes without deleting source state |
| Fresh browser without local ECDSA material | Stable `device_link_required` result |
| Corrupt or unavailable IndexedDB | Exact blocked result, never `device_link_required` |
| Two chain-qualified ECDSA projections | Exact target selection without false duplicate |
| Tempo and Arc projections for one wallet | Both projections resolve one EVM-family key slot, handle, public key, and address |
| Replayed or substituted ECDSA export | SigningWorker releases no share and the registered key remains unchanged |

Exit criteria:

- every matrix row passes;
- only `seams_wallet` remains after verified migration;
- no known regression from the ledger remains reproducible;
- no unrelated Refactor 90 implementation is included; and
- the work is committed as reviewable checkpoints.

## Commit Sequence

Use separate commits in this order:

1. `fix(indexeddb): preserve and migrate ECDSA wallet material`
2. `fix(ecdsa): separate durable material from live worker handles`
3. `fix(registration): commit exact client and SigningWorker activation state`
4. `fix(unlock): rehydrate exact local ECDSA material`
5. `fix(signing): require SigningWorker transport and unify ECDSA hydration`
6. `fix(export): release the exact ECDSA server share from SigningWorker`
7. `fix(router-ab): verify durable activation writes`
8. `test(ecdsa): lock the working lifecycle checkpoint`

Each commit must pass its focused checks before the next commit begins. Run the
full intended matrix after the final code commit.

## Files Expected To Change

### Browser Persistence

- `packages/sdk-web/src/core/indexedDB/schemaNames.ts`
- `packages/sdk-web/src/core/indexedDB/seamsWalletDB/manager.ts`
- `packages/sdk-web/src/core/indexedDB/seamsWalletDB/repositories.ts`
- `packages/sdk-web/src/core/indexedDB/seamsWalletDB/ecdsaRoleLocalSessionMaterialStore.ts`
- `packages/sdk-web/src/core/indexedDB/seamsWalletDB/ecdsaPresignMaterialStore.ts`
- a narrow migration module under
  `packages/sdk-web/src/core/indexedDB/seamsWalletDB/`

### SDK Lifecycle

- `packages/sdk-web/src/SeamsWeb/operations/auth/login.ts`
- `packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts`
- `packages/sdk-web/src/core/rpcClients/relayer/walletRegistration.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/readySecp256k1Material.ts`
- `packages/sdk-web/src/core/signingEngine/threshold/ecdsa/postRegistrationSessionActivation.ts`
- `packages/sdk-web/src/core/signingEngine/session/persistence/records.ts`
- `packages/sdk-web/src/core/signingEngine/session/persistence/ecdsaRoleLocalRecords.ts`
- `packages/sdk-web/src/core/signingEngine/session/identity/ecdsaCapabilityHydration.ts`
- `packages/sdk-web/src/core/signingEngine/session/passkey/ecdsaKeyFactsInventory.ts`
- ECDSA worker channels and derivation worker implementation

### Gateway And Server

- `packages/sdk-server-ts/src/core/WalletStore.ts`
- `packages/sdk-server-ts/src/core/d1WalletStore.ts`
- `packages/sdk-server-ts/src/core/authService/thresholdEcdsaKeyInventory.ts`
- `packages/sdk-server-ts/src/core/ThresholdService/routerAb/ecdsaDerivationPoolFillHandlers.ts`
- `packages/sdk-server-ts/src/core/routerAbSigning/RouterAbEcdsaPresignRuntime.ts`
- `packages/sdk-server-ts/src/core/routerAbSigning/RouterAbNormalSigningRuntime.ts`
- `packages/sdk-server-ts/src/router/cloudflare/d1EvmFamilyEcdsaRegistrationBranch.ts`
- `packages/sdk-server-ts/src/router/cloudflare/d1WalletRegistrationService.ts`
- registration and threshold-ECDSA route boundary parsers

### Cloudflare Worker

- `crates/router-ab-cloudflare/src/durable_object/worker_storage.rs`
- `crates/router-ab-cloudflare/src/signing_worker/mod.rs`
- `crates/router-ab-cloudflare/src/strict_worker/signing_worker.rs`
- explicit-export private route and recipient-envelope contracts
- focused Durable Object boundary tests

### Deletion Candidates

- `packages/sdk-web/src/core/signingEngine/workerManager/workers/ecdsaRoleLocalSessionMaterialStore.ts`
- `packages/sdk-web/src/core/signingEngine/workerManager/workers/ecdsaPresignMaterialStore.ts`
- obsolete strict ECDSA derivation recovery SDK/WASM paths identified in
  Refactor 90A
- the Gateway-local ECDSA presign key-material fallback
- Deriver A/B explicit-export PRF routes after SigningWorker export cutover
- obsolete tests and fixtures listed in Phase 8

## Completion Criteria

This plan is complete when:

1. fresh registration, reload, unlock, NEAR signing, Tempo signing, EVM signing,
   and both key-export families pass in the production-equivalent local setup;
2. existing same-device ECDSA material survives consolidation into
   `seams_wallet`;
3. a genuinely missing device receives `device_link_required` without invoking
   strict ECDSA derivation recovery;
4. one canonical durable material representation and one canonical live handle
   representation remain;
5. registration commits exact SigningWorker activation state and Gateway owns no
   server share;
6. every ECDSA operation uses the shared hydration executor, chain-qualified
   projections preserve one wallet-level EVM-family key, and presign requires
   private SigningWorker transport;
7. explicit export obtains the exact server additive share through a one-time,
   recipient-bound SigningWorker operation and reproduces the registered key;
8. Cloudflare Durable Object activation survives worker restart;
9. the intended suite passes;
10. the regression fixes are committed in the sequence above; and
11. Refactor 90 can start from a known working checkpoint.

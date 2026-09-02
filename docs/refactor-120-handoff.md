# Refactor 120 — implementation handoff

Branch `codex/refactor-120-phase0`, worktree
`/Users/pta/Dev/rust/seams-sdk-r120`.

Read `AGENTS.md` and `docs/refactor-120-rotate-tenant-secrets.md` first. The
plan is authoritative; this file is the shortest route back into the current
implementation state.

## Goal

Replace the deployment-wide Deriver A/B root pair with one independently
generated, refreshable A/B root pair per authenticated tenant. Refresh must
preserve every existing public wallet key. Clients remain unchanged. Each role
keeps its scalar inside its own trust boundary, and only authenticated public
commitments, evidence, receipts, and encrypted role-local artifacts cross
service boundaries.

## Current state

The plan checklist was 60/99 complete before this checkpoint. The cryptographic
and dormant persistence foundation is substantially built:

- stable ECDSA tenant derivation context and threshold-PRF refresh invariance;
- Ed25519 role-target threshold-PRF primitives, proofs, vectors, and WASM
  evidence;
- per-tenant creation, refresh, restore, retirement, activation-evidence, and
  deletion lifecycle types;
- one-use D1 command reservations, executed checkpoints, exact terminal
  receipts, and atomic role-share mutation;
- authenticated public-evidence-only creation and refresh Durable Object
  checkpoints;
- role-private encrypted pending/active/retired stores;
- provider-neutral online sealing and managed backup;
- the Cloudflare `operational_rotation_v1` HPKE provider with distinct A/B and
  online/backup keys, strict Secret loading, deployment-key generation, and
  deployment preflight validation;
- B4/B5 ECDSA and Ed25519 identity composition that rejects caller-selected
  tenant, root, role, and epoch fields;
- exact R103F integration through the final `dev` cutover.

The last completed slice reconstructs an online provider artifact from a
validated active D1 row:

- `TenantRootOnlineRoleShareBindingV1::from_persisted`
- `TenantRootSealedOnlineRoleShareV1::from_persisted`
- `CloudflareStoredTenantRootRoleShareV1::into_online_role_share_artifact`

It validates active lifecycle, role, epoch, revision, activation binding,
commitment, wrapping-key reference, installation-evidence digest, and
ciphertext digest before the provider opens the share.

Focused evidence at the checkpoint:

```text
router-ab-core tenant_root_online_sealing: 4/4
Cloudflare persisted active-row reconstruction: 1/1
Cloudflare operational-provider open round-trip: 1/1
deployment script tests: 32/32
git diff --check: clean
```

No shared Workers or fixed-port services are running for R120. No subagent is
still editing the worktree.

## Next implementation path

Do these in order. Keep each slice compiling before moving on.

### 1. Refresh activation admission

Finish the smallest authenticated refresh-only activation boundary in:

- `crates/router-ab-cloudflare/src/durable_object/tenant_root_creation.rs`
- `crates/router-ab-cloudflare/src/durable_object/mod.rs`
- `crates/router-ab-cloudflare/src/strict_worker/router.rs`

The private POST route must decode and verify the bounded canonical signed
activation receipt, require `RefreshSwap`, exact identity/lineage/authority,
`BothRolesReady`, `current_revision == expected_revision`, and
`result_revision == expected_revision + 1`. Persist a pending admission
atomically. Exact replay returns the same admission; changed receipt or
revision fails closed. Do not update the active epoch until both role-private
D1 mutations have committed.

### 2. Self-contained Router-attested role command

`TenantRootRoleCreationCommandV1` already signs the operation, identity,
lineage, Started-journal digest, context digest, role, session, nonce,
authority, time window, and issuer key ID. A Deriver currently also needs the
Router's in-memory Started journal and ceremony context to obtain
`VerifiedTenantRootRoleCreationCommandV1`.

Add the smallest strict public package that carries the exact canonical command
plus the public journal/context material needed by the existing verifier. Do
not add a second verifier or a compatibility route. Signature, digest,
identity, role, authority, freshness, and every substitution must fail closed.

Primary files:

- `crates/router-ab-core/src/derivation/tenant_root_creation_role_command.rs`
- `crates/router-ab-core/tests/tenant_root_creation_role_command.rs`

### 3. Live role-separated creation

Wire a private bounded call graph:

```text
Router -> Deriver A -> Deriver B -> Router creation DO
```

Deriver A keeps `PendingTenantRootInitialRoleAttemptV1` alive while awaiting B.
Deriver B owns its own pending token, submits the A and B signed public
commitments to the Router-owned DO, finalizes and persists B, then returns only
canonical public pair/evidence bytes. A verifies those bytes, finalizes, and
persists A. No worker, request, message, DO record, or log may ever contain both
scalars.

Expected small source boundary:

- `crates/router-ab-cloudflare/src/paths.rs`
- `crates/router-ab-cloudflare/src/strict_worker/router.rs`
- `crates/router-ab-cloudflare/src/strict_worker/deriver.rs`
- `crates/router-ab-cloudflare/src/durable_object/tenant_root_creation.rs`
- the Deriver-to-Router service binding in the relevant Wrangler manifest

Use service bindings and existing internal-service authentication. Carry only
plain structured-clone/JSON public wires. The first role attempt that returns
before the commitment pair is complete is burned; never persist a scalar to
make it resumable.

### 4. ECDSA V2 production boundary

Add and then cut over the ECDSA request boundary so
`StableTenantDerivationContextV2` is the only threshold-PRF input and
`TenantRootCustodyBindingV1` carries epoch-bound custody metadata outside the
PRF bytes. Prove:

- changing `TenantRootShareEpoch` leaves the stable PRF bytes and output
  unchanged;
- the same change alters the custody/replay binding;
- `RootShareEpoch` is absent from the V2 PRF input;
- callers cannot select identity, lineage, role, or epoch;
- each Deriver loads its own authenticated active D1 row, reconstructs the
  provider artifact, opens it locally, and verifies the share commitment before
  evaluation.

Keep existing durable `RootShareEpoch` fields for already-created ECDSA wallet
material. Do not translate them into `TenantRootShareEpoch`.

### 5. Deletion and broader cutover

Remove deployment-wide root-share Secret bindings only after the live ECDSA
path and the Phase 0-approved Ed25519 V2 path both use tenant roots. The
Ed25519 production cutover remains gated on the signed Phase 0 benchmark
selection. Do not activate an Ed25519 architecture candidate before that gate.

Then add crash/restart tests at every persisted transition, live per-tenant
locks/fences, role loss and backup restore drills, provider-key retirement, and
the Phase 5 release matrix.

## Important constraints

- Keep A/B scalars role-local and zeroizing. Public commitments may meet;
  secrets may not.
- Use exact canonical bytes for signatures, replay digests, D1 receipts, and DO
  checkpoints. Never reconstruct a signed payload from a looser record.
- D1 mutation and the command `executed` checkpoint are one atomic batch.
- Activation requires verified current-backup evidence or the explicit signed
  accepted-loss branch.
- Keep R103F B4/B5 schemas and signer D1 unchanged.
- Remove old paths when the replacement is live; do not add legacy flags.
- Classify a failing test before changing production code.
- Do not commit generated root `target/`, `rust_out`, `librust_out.rlib`, or
  toolchain fingerprint artifacts.

## Fast verification commands

```sh
cargo test --manifest-path crates/router-ab-core/Cargo.toml --test tenant_root_online_sealing
cargo test --manifest-path crates/router-ab-core/Cargo.toml --test tenant_root_creation_role_command
cargo test --manifest-path crates/router-ab-core/Cargo.toml --test tenant_root_refresh_checkpoint
cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --features workers-rs --lib tenant_root_role_d1
cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features workers-rs --all-targets
pnpm -C tests exec playwright test -c playwright.scripts.config.ts unit/deployCommands.script.unit.test.ts unit/deploymentTargets.script.unit.test.ts --reporter=line
pnpm exec tsc -p tests/tsconfig.unit.json --pretty false
git diff --check
```

Run broad suites after the live request and persistence boundaries are wired.
The two existing `clippy -D warnings` failures in
`router_ab_ecdsa_derivation.rs` are pre-existing `too_many_arguments` findings;
do not disguise them with unrelated R120 changes.

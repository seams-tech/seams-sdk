# True Server-Blindness Plan

This plan updates
[crates/ecdsa-hss](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss)
so ECDSA HSS enforces true server blindness for non-export flows and explicit
export.

The current security issue is in the ECDSA HSS derivation boundary: the
crate-local reference path can combine client root input with relayer root input,
derive canonical `x`, derive both additive shares, and return/retain role
outputs. That shape is useful for fixtures and review, but it is too powerful
for the production server boundary.

The target property is:

- the server never receives client root material in plaintext
- the server never learns canonical secp256k1 scalar `x`
- the server never learns `x_client`
- the server learns only `x_relayer` plus public verification data
- the client never receives server root material in plaintext
- the client never learns `x_relayer` during non-export flows
- explicit export delivers export-capable material to the authorized client
  without the server computing canonical `x`
- threshold signing and export still refer to the same EVM address

Existing ECDSA HSS accounts and IndexedDB state can be wiped. The implementation
should replace the active protocol shape directly, delete superseded v1 paths,
and avoid compatibility branches.

## Current Starting Point

Relevant existing material:

- active protocol spec:
  [specs/protocol.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/specs/protocol.md)
- security model:
  [security.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/security.md)
- export semantics:
  [specs/export.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/specs/export.md)
- threshold backend integration:
  [specs/integration-near-threshold.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/specs/integration-near-threshold.md)
- formal verification area:
  [formal-verification](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification)
- current native benchmark:
  [benches/performance_baseline.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/benches/performance_baseline.rs)

## Replacement Design

Use role-local additive derivation as the production design:

```text
x_client = H_scalar("ecdsa-hss:v2:client-share", context, y_client)
x_relayer = H_scalar("ecdsa-hss:v2:relayer-share", context, y_relayer)
x = x_client + x_relayer mod n
X = xG = x_clientG + x_relayerG
address = ethereum_address(X)
```

The client derives `x_client` locally. The server derives `x_relayer` locally.
Neither side derives canonical `x` during non-export ceremonies.

For explicit export:

```text
server_export_share = x_relayer
client_export_key = x_client + server_export_share mod n
```

The server export share must be policy-gated, transcript-bound, auditable, and
encrypted or otherwise delivered only to the authorized client export runtime.
The client verifies:

```text
client_export_key * G == X
ethereum_address(X) == expected_address
```

The Cait-Sith signing input remains:

```text
x = x_client + x_relayer mod n
```

Each party maps only its own additive share into the
`threshold-signatures`/Cait-Sith participant-share format.

## Performance Scope

True server blindness should affect ECDSA HSS setup, session bootstrap, recovery,
and explicit export. It should leave the Cait-Sith presign/sign protocol in the
same cost class because the final threshold key is still a two-party additive
secp256k1 key.

Measure overhead in:

- registration bootstrap
- session bootstrap
- Email OTP recovery/bootstrap
- explicit export
- first presign after bootstrap
- normal presign/sign with persisted shares

The main performance budget is:

- keep HSS derivation sub-millisecond in native Rust
- avoid adding network round trips to normal signing
- avoid adding browser WASM role code for server-only derivation
- avoid changing Cait-Sith triple/presign/sign cost
- keep export overhead isolated to explicit export

## Phase 1: Lean Model First

Do proof work before changing production Rust.

- [x] Add the initial v2 Lean scaffold:
  [TrueBlindV2.lean](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/lean-privacy/EcdsaHssPrivacy/TrueBlindV2.lean).
- [ ] Freeze the new ideal functionality in Lean:
  `F_ecdsa_hss_true_blind_v2`.
- [ ] Model private inputs:
  `y_client`, `y_relayer`.
- [ ] Model role-local derived shares:
  `x_client`, `x_relayer`.
- [ ] Model public outputs:
  `X_client = x_clientG`, `X_relayer = x_relayerG`, `X = X_client + X_relayer`,
  and Ethereum address.
- [ ] Model explicit export as a separate operation that releases
  `x_relayer` only to the authorized client export view.
- [ ] Prove the additive identity:

  ```text
  X = (x_client + x_relayer)G
  X = x_clientG + x_relayerG
  ```

- [ ] Prove the non-export server view excludes `y_client`, `x_client`, and
  canonical `x`.
- [ ] Prove the non-export client view excludes `y_relayer` and `x_relayer`.
- [ ] Prove explicit export gives the client enough material to reconstruct `x`
  and verify `xG == X`.
- [ ] Prove export and threshold signing share the same public key `X`.
- [ ] Define allowed public transcript fields:
  context binding, public share commitments, public key `X`, address, operation,
  and transcript digests.
- [ ] Define forbidden production fields in the server view:
  `y_client`, `x_client`, and canonical `x`.
- [ ] Define forbidden production fields in the client non-export view:
  `y_relayer` and `x_relayer`.
- [ ] Run the Lean privacy build:

  ```sh
  cd crates/ecdsa-hss/formal-verification
  make lean-check
  ```

## Phase 2: Boundary Contract

Turn the Lean model into a concrete implementation contract.

- [ ] Update
  [formal-verification/docs/proof-inventory.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/docs/proof-inventory.md)
  with the v2 true-blind proof targets.
- [ ] Update
  [formal-verification/docs/implementation-plan.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/docs/implementation-plan.md)
  with the Lean-first order.
- [ ] Update
  [specs/protocol.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/specs/protocol.md)
  so the production protocol is defined by role-local additive derivation.
- [ ] Update
  [specs/export.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/specs/export.md)
  so export is client-side reconstruction from `x_client` and an export-authorized
  relayer share.
- [ ] Update
  [security.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/security.md)
  with the hard invariant that the live server process cannot reconstruct
  canonical `x`.
- [ ] Define one active v2 wire shape.
- [ ] Delete v1 request/response compatibility from production boundaries.
- [ ] Define reference-only code paths for fixture generation and algebraic tests.

## Phase 3: Rust Implementation

After Lean proof obligations and the boundary contract are in place, update Rust.

- [ ] Replace canonical derivation from joined roots in
  [src/shared/derive.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/src/shared/derive.rs)
  with role-local additive share derivation.
- [ ] Remove production APIs that accept both `y_client` and `y_relayer` in one
  process.
- [ ] Replace
  [src/wire/mod.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/src/wire/mod.rs)
  request types so the server never receives plaintext client root material.
- [ ] Replace
  [src/client/mod.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/src/client/mod.rs)
  outputs so non-export returns only `x_client`, `X_client`, shared public key
  `X`, address, and verification data.
- [ ] Replace
  [src/server/mod.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/src/server/mod.rs)
  retained state so it stores only `x_relayer`, `X_relayer`, shared public key
  `X`, address, and verification data.
- [ ] Update
  [src/integration/mod.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/src/integration/mod.rs)
  so Cait-Sith receives mapped shares derived from role-local additive shares.
- [ ] Update explicit export so the server returns only an export-authorized
  relayer share payload.
- [ ] Move full-key reconstruction to the client export runtime.
- [ ] Delete old fixtures tied to joined-root v1 derivation.
- [ ] Regenerate fixtures for v2 additive derivation.
- [ ] Update WASM bindings so browser code exposes only client-role derivation
  and export reconstruction.
- [ ] Update server bindings so server code exposes only relayer-role derivation
  and export-share authorization.

## Runtime Stage Details

Use these stage contracts during implementation and benchmarking.

### Stage 0: Context Binding

Purpose:

- normalize account, subject, chain target, key id, signing root, and key version
- derive a stable HSS context binding

Performance risks:

- repeated hashing and serialization on hot paths
- larger typed context payloads crossing client/server boundaries

Todo:

- [ ] Measure context encoding time.
- [ ] Measure context payload size.
- [ ] Cache context binding within a ceremony.

### Stage 1: Client Share Derivation

Purpose:

- client derives `x_client`
- client derives public share `X_client`
- client prepares public verification payload

Performance risks:

- extra scalar validation and public-key derivation in browser WASM
- larger client bootstrap payload if proof metadata grows

Todo:

- [ ] Measure browser client-share derivation time.
- [ ] Measure `X_client` verification payload size.
- [ ] Assert no server-owned fields enter the client derivation API.

### Stage 2: Server Share Derivation

Purpose:

- server derives `x_relayer`
- server derives public share `X_relayer`
- server computes shared public key `X = X_client + X_relayer`

Performance risks:

- public-key addition repeated across bootstrap and resume flows
- server retained-state growth from transcript metadata

Todo:

- [ ] Measure server share derivation time.
- [ ] Measure public-key addition time.
- [ ] Measure retained server state size.
- [ ] Assert no client root/share fields enter the server derivation API.

### Stage 3: Public Key And Address Verification

Purpose:

- verify `X = X_client + X_relayer`
- verify `address = ethereum_address(X)`
- bind `X` and address to the key id/session

Performance risks:

- repeated compressed public-key parsing
- repeated Ethereum address derivation

Todo:

- [ ] Measure public-key parse/add/address derivation time.
- [ ] Cache verified public identity per key id.
- [ ] Assert every persisted key record includes `X_client`, `X_relayer`, `X`,
  and address.

### Stage 4: Cait-Sith Share Mapping

Purpose:

- map `x_client` and `x_relayer` into the participant-share representation used
  by the threshold ECDSA backend
- preserve the same public key `X`

Performance risks:

- extra scalar conversions in browser/server WASM
- mapping checks repeated for every presign

Todo:

- [ ] Measure additive-share mapping time per role.
- [ ] Cache mapped participant share for persisted signing sessions.
- [ ] Assert mapped shares reconstruct the same public key `X`.

### Stage 5: Non-Export Presign/Sign

Purpose:

- use the existing Cait-Sith/triples/presign/sign flow with role-local shares

Performance risks:

- accidental extra bootstrap before presign
- additional round trips before normal signing
- invalidating existing triple/presign caches after harmless metadata changes

Todo:

- [ ] Measure first presign after bootstrap.
- [ ] Measure normal presign/sign with persisted shares.
- [ ] Confirm round-trip count matches the current signing path.
- [ ] Confirm triple/presign behavior is unchanged by HSS v2.

### Stage 6: Explicit Export

Purpose:

- authorize export
- release encrypted/export-bound relayer share to the client
- reconstruct canonical `x` client-side
- verify `xG == X`

Performance risks:

- adding export checks to non-export paths
- expensive client-side reconstruction or verification in browser WASM
- oversized export envelope

Todo:

- [ ] Benchmark export separately from non-export flows.
- [ ] Measure export envelope size.
- [ ] Measure client-side scalar addition and public-key verification time.
- [ ] Assert server never returns `privateKeyHex` or canonical `x`.

## Phase 4: Rust Verification Bridge

After the Rust rewrite, link implementation back to the proof artifacts.

- [ ] Run Aeneas extraction for the new visible boundary slice.
- [ ] Update generated Lean boundary artifacts under
  [formal-verification/lean-boundary/generated](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/lean-boundary/generated).
- [ ] Prove bridge lemmas from generated boundary types to the Lean privacy
  model.
- [ ] Update Verus specifications for role-local derivation, public-key addition,
  output type separation, forbidden-field absence, and export isolation.
- [ ] Add Verus anti-drift checks that fail if server production types gain
  client-owned secrets.
- [ ] Add Verus anti-drift checks that fail if client non-export types gain
  server-owned secrets.
- [ ] Run the formal verification gate:

  ```sh
  cd crates/ecdsa-hss/formal-verification
  make check
  ```

## Phase 5: Tests

- [ ] Add algebraic tests for:

  ```text
  X = x_clientG + x_relayerG
  X = (x_client + x_relayer)G
  ```

- [ ] Add export tests proving client-side reconstruction produces the persisted
  address.
- [ ] Add boundary tests that fail if a server request accepts `y_client`,
  `x_client`, or canonical `x`.
- [ ] Add boundary tests that fail if a non-export client response includes
  `x_relayer`.
- [ ] Add integration tests for bootstrap, session resume, presign, sign, and
  export.
- [ ] Add regression tests that no server API returns `privateKeyHex` or
  canonical `x`.
- [ ] Delete tests whose only purpose is preserving v1 joined-root behavior.
- [ ] Run the crate test suite:

  ```sh
  cargo test --manifest-path crates/ecdsa-hss/Cargo.toml
  ```

## Phase 6: Product Integration

- [ ] Update server ECDSA HSS routes to accept only v2 role-local protocol
  messages.
- [ ] Update client signing-engine ECDSA bootstrap to derive and retain
  `x_client` locally.
- [ ] Update relayer persistence to store only `x_relayer`, public identity, and
  audit metadata.
- [ ] Update passkey and Email OTP ECDSA bootstrap flows.
- [ ] Update explicit export flow so the client reconstructs `x`.
- [ ] Delete IndexedDB v1 ECDSA account records and compatibility readers.
- [ ] Delete server-side v1 migration and compatibility logic.
- [ ] Update docs to state that existing ECDSA HSS accounts must be recreated.

## Phase 7: Performance Benchmarks

Run benchmarks after Lean proof work, Rust implementation, verification bridge,
and tests pass.

- [ ] Capture a pre-change baseline:

  ```sh
  cargo bench --manifest-path crates/ecdsa-hss/Cargo.toml
  ```

- [ ] Capture post-change native derivation benchmarks:

  ```sh
  cargo bench --manifest-path crates/ecdsa-hss/Cargo.toml
  ```

- [ ] Measure:
  context binding time,
  client share derivation time,
  server share derivation time,
  public-key addition time,
  address derivation time,
  additive-share mapping time,
  first presign after bootstrap,
  normal presign/sign with persisted shares,
  explicit export time,
  WASM artifact size,
  request/response byte sizes,
  retained server state size,
  and retained client state size.
- [ ] Emit a per-stage benchmark table covering:
  context binding,
  client share derivation,
  server share derivation,
  public key and address verification,
  Cait-Sith share mapping,
  non-export presign/sign,
  and explicit export.
- [ ] Compare against current notes:
  native derivation/bootstrap/export sub-millisecond,
  native sign about `~40 ms`,
  and Node-hosted wasm non-export sign about `~120 ms`.
- [ ] Treat any Cait-Sith presign/sign regression as a release blocker unless it
  is explained by intentional backend changes.
- [ ] Keep export overhead isolated from non-export signing.

## Completion Criteria

- [ ] Lean privacy theorems for true ECDSA HSS server blindness pass.
- [ ] Rust implementation exposes one active v2 production protocol shape.
- [ ] Production server cannot reconstruct canonical `x`.
- [ ] Production client cannot reconstruct `x_relayer` in non-export flows.
- [ ] Explicit export reconstructs canonical `x` client-side.
- [ ] Threshold signing and export verify against the same public key `X` and
  Ethereum address.
- [ ] Old v1 account, wire, fixture, migration, and IndexedDB compatibility paths
  are deleted.
- [ ] Aeneas/Lean boundary bridge passes.
- [ ] Verus checks pass.
- [ ] Rust tests pass.
- [ ] Native and browser benchmark results are committed.

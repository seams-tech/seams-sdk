# Malicious-Security Hardening Plan

This note is the hardening roadmap for
[crates/ed25519-hss](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss).

Runtime shape, protocol behavior, and the current security boundary are
described in:

- [README.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/README.md)
- [security.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/security.md)
- [specs/protocol.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/specs/protocol.md)

## Current Boundary

The current production boundary is stronger than the old joined-input seam:

- non-export production flows no longer expose reconstructable `y_relayer` or
  `tau_relayer` to the client
- the staged server-assisted flow advances through server-owned continuation
  state from add-stage onward
- normal server outputs are role-gated so the intended server output is
  `x_relayer_base`
- the intended client output is delivered to the client as `x_client_base`

That boundary assumes the server process follows the protocol.

The current implementation does not claim that a malicious server process with
arbitrary memory inspection cannot recover client-owned output. The output
projector currently materializes split-local internal values including:

- `reduced_a_bits`
- `tau_bits`
- `x_client_base_bits`
- `x_relayer_base_bits`

A process that can inspect executor memory can read both local sides of those
split-local values and reconstruct intermediate or final scalars.

## Hardening Approaches

The main options for raising the server-side trust boundary are:

- **Client-masked output projection.** The server materializes and stores only a
  client-blinded output such as `x_client_base + r_client mod l`; the client
  subtracts `r_client` after opening. Expected cost is low to moderate if the
  mask is integrated at the output-projection layer.
- **Client-side output finalization.** The server returns a continuation or
  non-openable output material, and the client completes the final projection.
  Expected cost is moderate to high on the browser/wasm path.
- **Malicious-secure MPC or garbled-output delivery.** The protocol proves or
  enforces correct output delivery under active attacks. Expected cost is high
  in latency, bytes, implementation complexity, and proof work.
- **Split server roles.** Independent services hold disjoint execution shares so
  no single server process can reconstruct protected values. Expected runtime
  cost depends on network placement; operational complexity is high.
- **TEE or enclave execution.** The current executor runs in attested protected
  memory. Runtime cost can be low to moderate, while deployment, attestation,
  debugging, and hardware trust become the main cost.

## Selected Near-Term Slice

Implement **ClientMaskedProjection** first.

This is an incremental hardening step. Its target is:

- remove unmasked `x_client_base` from server-owned output bundles and retained
  server finalization state
- keep `r_client` reconstructable only by the client
- deliver `x_client_base_blinded = x_client_base + r_client mod l`
- have the client open the blinded output and compute
  `x_client_base = x_client_base_blinded - r_client mod l`
- preserve the server's intended output, `x_relayer_base`

This slice does not establish a full arbitrary-server-memory compromise claim
by itself. Full protection against a server process reading every internal
executor value also requires preventing the server from holding reconstructable
`a`, `tau`, or both local sides of the output-projection intermediates.

## Security Claim Levels

There are two distinct guarantees to keep separate while implementing this
feature.

**Level A: masked output-state delivery.**

Required for the first `ClientMaskedProjection` slice:

- server-owned finalization state contains only `x_client_base_blinded`
- wire output carries only `x_client_base_blinded`
- reports, logs, debug output, and persisted server state contain no unmasked
  `x_client_base`
- client policy can require this mode and reject downgrade

This level allows the output projector to compute transient internal values
during execution. It hardens the retained and delivered boundary, while still
assuming the server process is not arbitrarily inspecting every executor
allocation at runtime.

Level A claim language:

- product phrasing:
  "The relay only handles a client-masked signing share; the client unblinds it
  locally."
- technical phrasing:
  "Under trusted-server execution, the server never receives, stores, logs, or
  returns the unmasked client signing share. It handles
  `x_client_base_blinded = x_client_base + r_client mod l`, and the client
  derives `r_client` and unblinds locally."

Avoid saying only "the server never sees client secrets" for Level A, because
that phrase can imply arbitrary memory-inspection resistance. Use the Level B
claim when the intended meaning is that a malicious server process cannot read
executor memory and reconstruct the client share.

**Level B: executor-memory-safe client output.**

Required before claiming that a malicious server process with arbitrary memory
inspection cannot recover `x_client_base`:

- the server process must never hold `r_client`
- the server process must never hold an unmasked `x_client_base`
- the server process must never hold both local sides of `a` and `tau` in a form
  that lets it reconstruct `x_client_base = a + tau mod l`
- the server process must never hold both local sides of an unmasked
  output-projection intermediate from which `x_client_base` is recoverable

The current single-process output projector does not satisfy Level B. Achieving
that level likely requires client-side finalization, split execution, an
enclave/TEE boundary, or a new output-delivery primitive that keeps the
unmasked projection outside server-readable memory.

## Protocol Modes

The projection behavior must be an explicit transcript-bound mode:

```text
OutputProjectionMode =
  TrustedServerProjection
  ClientMaskedProjection {
    mask_commitment,
    mask_context,
  }
```

`TrustedServerProjection` is the current semi-honest/trusted-server behavior.
It may remain available for development, compatibility testing, or explicitly
approved deployments.

`ClientMaskedProjection` is the hardened feature. It requires client policy to
provide a recoverable client-only mask root and requires the server response to
deliver `x_client_base_blinded`.

Mode selection rules:

- mode is chosen by client policy before the run starts
- mode is included in prepared-session metadata
- mode is included in all relevant transcript digests
- mode is included in final report validation
- a client that requires `ClientMaskedProjection` must reject
  `TrustedServerProjection`
- the protocol must not silently fall back from `ClientMaskedProjection` to
  `TrustedServerProjection`

## Mask Requirements

`r_client` must satisfy all of the following:

- derived deterministically from recoverable client-only secret material and
  stable session context
- sampled as a canonical scalar modulo Ed25519 `l`
- recomputable after IndexedDB loss, as long as the user can recover the normal
  client secret material
- kept only in memory during finalize/open
- bound to the transcript by a commitment such as
  `H("client-output-mask", context_binding, server_eval_handle, r_client)`
- absent from server-visible request payloads, persisted server state, logs,
  benchmark reports, and debug output
- never represented as a normal joined `DdhHssInputShareBundle` sent to the
  server, because that shape contains enough material for the server process to
  reconstruct the encoded value

The client-only mask root is derived from the normal account recovery path:

```text
client_recoverable_secret =
  passkey path: WebAuthn PRF output
  recovery-code path: recovered high-entropy client_secret

r_client = scalar_from_hkdf(
  ikm = client_recoverable_secret,
  info = "ed25519-hss/client-output-mask/v1" ||
         context_binding ||
         server_eval_handle ||
         org_id ||
         account_id ||
         key_purpose ||
         key_version ||
         credential_id ||
         output_projection_mode
)
```

For the recovery-code path, the server may store only encrypted backup material:

- the client generates a high-entropy `client_secret`
- the client stores it locally for normal operation
- the server stores an encrypted backup of it
- recovery codes and `shamir3pass` recover/decrypt the high-entropy secret
- `r_client` is derived from the recovered secret after recovery

Recovery codes authenticate or unlock the backup path. They are not the IKM for
`r_client`.

## Implementation Plan

### Completed

- Reviewed the Rust HSS executor, output opener, transcript digest, server
  finalize state, WASM bindings, client SDK, server SDK, and route surfaces.
- Confirmed that `ClientMaskedProjection` is a cross-layer API change, with the
  final public client result able to remain `xClientBaseB64u`.
- Reached the required mask-injection design checkpoint.
- Added a future-facing TypeScript boundary type and type fixture for
  role-separated HSS server-visible client requests. The fixture rejects
  `evaluatorOtStateB64u`, client input shares, client mask material, PRF output,
  and recovered client secret material.
- Added a future-facing TypeScript server response type and type fixture for
  role-separated HSS responses. The fixture rejects evaluator state, staged
  evaluator artifacts, raw client/server output scalars, client mask material,
  PRF output, and recovered client secret material.
- Added a Rust role-separated add-stage request packet and boundary test proving
  the target server-visible request omits joined client bundle payload fields
  and clear client/relayer root bytes.
- Refactored the role-separated add-stage builder so it computes the shared
  commitments without first constructing the legacy server-visible add-stage
  payload.
- Added a Rust role-separated client output-delivery packet and boundary test
  proving the target client-facing delivery omits server-output payload fields,
  seed output for registration, and clear client/relayer root bytes.
- Added a Rust role-separated server-input delivery packet and client-owned
  materialization prototype. The boundary test proves the server packet omits
  joined client bundle fields and clear client/relayer roots, while the client
  can materialize a staged evaluator artifact and open the expected client
  output.
- Added Rust message-level helpers and WASM exports for the role-separated
  boundary: server prepares a sealed server-input delivery without accepting
  evaluator OT state, and the client builds the staged evaluator artifact
  locally from that delivery plus its retained evaluator state.
- Verified the role-separated boundary with the focused Rust boundary test, the
  combined client/server HSS WASM cargo check, the TypeScript type check, and
  the formal-verification gate.
- Added the first client-owned masked-output projection slice: the client can
  replace the staged artifact's client output packet with
  `x_client_base_blinded = x_client_base + r_client mod l`, the normal opener
  rejects that packet, and the client masked opener subtracts `r_client`
  locally.
- Wired the optional `clientOutputMaskB64u` parameter through the client WASM
  boundary, near-signer HSS client export, and TypeScript worker request
  surface.

### Active Design Checkpoint

The current single-process output projector has no existing primitive that can
apply `r_client` while keeping `r_client` unreconstructable by that server
process.

The existing client-input path is OT-backed and reconstructs a joined
`DdhHssInputShareBundle` before execution. Reusing that path for `r_client`
would put both local sides of the mask inside server executor memory. That would
violate the `r_client` requirement for `ClientMaskedProjection`.

The SDK/server route review found a second prerequisite: the current
`/threshold-ed25519/hss/respond` request sends `evaluatorOtStateB64u` to the
server, and the server ceremony reconstructs client OT bundles while preparing
the staged evaluator artifact. Level A cannot be reached while client-owned
evaluator state is accepted by a server route.

The Rust staged-flow review found the matching lower-level issue: the legacy
`AddStageRequestPayload` carries unsealed joined `y_client_bundle_payload` and
`tau_client_bundle_payload`. A role-separated add-stage target packet now omits
those fields, but the server execution path still needs to move to the
role-separated packet family.

Proceed with a role-separated output-delivery design unless a new
mask-injection primitive is developed first. A direct "send the projector
continuation to the browser" design is insufficient, because the current
continuation contains both transport sides of server-owned `tau_relayer`
material. The role-separated design must specify:

- which continuation material the server returns
- which pieces remain opaque or one-sided from the server's and client's
  perspectives
- how the client combines its retained evaluator state with `r_client`
- how `x_relayer_base` remains available to the server
- how server-owned `y_relayer` and `tau_relayer` remain unavailable to the
  client
- how client-owned evaluator state stays off server routes
- which transcript digests bind the projection mode, mask commitment, and
  final output commitment
- how benchmarks separate server latency, client finalization latency, and total
  ceremony latency

Immediate next implementation sequence:

- [x] Define a server-visible client request shape where the client retains
  `evaluatorOtStateB64u` and server routes accept only the public
  `clientRequestMessageB64u`.
- [x] Define a server response shape that provides only authenticated stage
  responses and output-delivery material safe for the client to receive.
- [x] Add type-level tests that reject server route payloads containing
  `evaluatorOtStateB64u`, `yClientB64u`, `tauClientB64u`, `rClientB64u`, or raw
  PRF/client-secret material.
- [x] Add the Rust role-separated add-stage target packet that omits joined
  client bundle payload fields.
- [x] Prototype the one-sided output-delivery primitive in Rust tests before
  touching SDK routes.
- [x] Design the split-execution or evaluator-owned materialization path that
  removes the server executor's dependency on joined client bundles.
- [x] Add the Rust/WASM boundary APIs for role-separated server-input delivery
  and client-owned staged-artifact materialization.
- [x] Move the server execution path and SDK route surface to the
  role-separated packet family.
- [x] Regenerate the checked-in browser WASM package artifacts for
  `wasm/hss_client_signer` in an environment whose clang supports
  `wasm32-unknown-unknown`.
- [x] Regenerate the checked-in near-signer WASM package artifacts for the
  browser and server package surfaces so the role-separated exports are
  available to SDK tests and server routes.
- [x] Add route/service and worker tests for the role-separated ceremony
  exchange.
- [x] Resume the first `ClientMaskedProjection` implementation slice after the
  role-separated Rust prototype proved that neither party receives the other's
  private root material and the server route no longer receives evaluator OT
  state.

The server execution path migration now has a Rust target:

1. Server prepare/respond returns a role-separated server-input delivery packet
   instead of accepting `evaluatorOtStateB64u`.
2. Client opens the sealed server-input transport, reconstructs its retained
   client input bundles locally, and materializes the staged evaluator artifact.
3. Client submits the staged evaluator artifact, or an equivalent server-safe
   finalization artifact, back to the server for relayer output finalization.
4. Server finalizes only from the artifact and its server eval state; it never
   receives joined client input bundles or evaluator OT state.

The SDK/WASM route integration source path now targets that packet family.

Route migration sequence:

1. [x] Add server SDK wrappers around
   `threshold_ed25519_hss_prepare_role_separated_server_input_delivery`.
   The wrapper input must accept only `clientRequestMessageB64u` from the
   client-visible request, plus server-retained relayer inputs.
2. [x] Add client WASM/runtime support in `wasm/hss_client_signer` for
   client-owned staged-artifact materialization. The browser-facing HSS client
   worker currently uses this package, so the near-signer export is a compiled
   proof point rather than the final browser SDK surface.
3. [x] Change `/threshold-ed25519/hss/respond` and the registration respond route
   to return the role-separated server-input delivery instead of storing a
   server-built staged evaluator artifact.
4. [x] Change the client lifecycle so it retains `evaluatorOtStateB64u`, receives
   the server-input delivery, materializes the staged evaluator artifact locally,
   and sends that artifact or a server-safe finalization artifact during
   finalize.
5. [x] Change server finalize to accept the client-owned staged artifact, validate
   context binding and ceremony scope, and continue opening only the relayer
   output on the server.
6. [x] Remove legacy server route acceptance of `evaluatorOtStateB64u` after the
   role-separated request/response path is wired through both session and
   registration flows.
7. [x] Add route/service and worker tests proving the server route payload never
   accepts evaluator OT state and the client can still complete registration
   and session HSS ceremonies.

Test checkpoint:

- Added an Express relayer route test proving `/threshold-ed25519/hss/respond`
  rejects legacy `evaluatorOtStateB64u` before server-side ceremony execution.
- Added a signing-engine public facade guard for the new client-owned staged
  artifact worker entrypoint.
- Updated relayer and active-path SDK tests so session repair, session
  completion, export, and managed registration use the role-separated server
  input delivery plus client-owned staged artifact exchange.

Artifact checkpoint:

- `cargo check` passes for `wasm/hss_client_signer` and the combined
  near-signer HSS client/server feature set.
- `wasm-pack build wasm/hss_client_signer --target web --out-dir pkg` succeeds
  locally with `CC_wasm32_unknown_unknown=/opt/homebrew/opt/llvm/bin/clang`.
  The default Apple clang path still cannot compile the `blst` wasm target.
- `wasm-pack build wasm/near_signer --target web --out-dir pkg --features
  hss-client-exports` and `wasm-pack build wasm/near_signer --target web
  --out-dir pkg-server --features hss-server-exports` succeed with the same
  Homebrew LLVM clang setting.
- Formal verification passes after the role-separated route migration:
  `pnpm check:formal-verification`.

Client-masked projection checkpoint:

- The implemented first slice keeps `r_client` as a client-side optional
  parameter on staged-artifact build/open calls.
- The client-owned staged artifact can reseal only the client output packet as
  `x_client_base_blinded`; server output material remains unchanged.
- The existing evaluation digest is preserved so current server finalization
  validation continues to bind the same hidden-eval run.
- This is a Level A packet-delivery checkpoint. Full `OutputProjectionMode`
  metadata, mask commitment binding, derivation lifecycle, downgrade policy,
  and a core output model that names the blinded client output remain open.

Validation checkpoint for the first masked-output slice:

- `cargo check` passes for `crates/ed25519-hss`, `wasm/hss_client_signer`, and
  `wasm/near_signer` with combined HSS client/server exports.
- The focused Rust boundary test proves masked client output rejects the normal
  opener, opens with `r_client`, and still preserves server output finalization.
- `pnpm check:formal-verification` passes across vectors, parity, Aeneas, Lean,
  Verus, and anti-drift checks.
- The focused SDK TypeScript build, active-path Playwright suite, and relayer
  HSS route suite pass after regenerating the WASM surfaces.
- A focused SDK unit guard proves present `clientOutputMaskB64u` values are
  forwarded to the client worker for staged-artifact build and client-output
  open calls.
- Added explicit `OutputProjectionMode` metadata to client output packets,
  staged evaluator artifacts, server finalize packets, role-separated output
  delivery, and evaluation reports.
- Added a transcript-derived mask commitment for `ClientMaskedProjection` and
  bound the projection mode into the client-output packet AAD.
- Added downgrade validation so a masked client-output packet cannot be
  finalized under trusted-server projection metadata.
- Re-ran formal verification and regenerated the browser/server WASM surfaces
  after adding the projection-mode metadata.
- Carried `clientOutputMaskB64u` through the high-level client HSS session
  ceremony helper so callers can run the full session ceremony in masked mode
  once they supply a recoverable client-only mask.
- Added a client-side `ClientMaskedProjection` policy that derives `r_client`
  with HKDF-SHA-256 from recoverable 32-byte client material and stable HSS
  transcript context. The derivation context includes the context binding,
  signing root, NEAR account, key purpose/version, participant set, derivation
  version, operation, relayer key id, and projection mode.
- Wired passkey warm-session reconstruction and Email OTP Ed25519
  reconstruction/provisioning to use the derived mask from the same
  recoverable client material used to re-derive client inputs.
- Added a deterministic derivation test against Node HKDF and exercised the
  derived-mask path through the full single-key HSS active-path Playwright
  suite.
- Added Rust boundary negative coverage proving masked client-output packets
  reject missing unmasked opening and wrong-mask opening both before and after
  final report delivery.
- Added client-side projection-policy preflight validation so malformed
  `ClientMaskedProjection` policy is rejected before opening a server ceremony.
- Renamed the internal hidden-eval client output bundle from
  `DdhHiddenEvalOutputBundles.x_client_base` to `client_base_output` and added a
  boundary regression that server finalize output state no longer exposes an
  unmasked `x_client_base` field name.
- Added a downgrade boundary test proving a client-masked opener rejects a
  trusted-server projection client-output packet.
- Clarified the mask-reuse test target: same-context deterministic
  re-derivation is required for IndexedDB loss recovery, while cross-context
  reuse must separate by derivation context and commitment checks.
- The refreshed small native hidden-eval benchmark remains in the same envelope
  as the previous optimized path: `output_projector` mean `46.74ms`,
  `total_hidden_eval` mean `232.59ms`, and delivery total mean `267.84ms`
  across three release samples. This benchmark measures the default unmasked
  path; the optional mask slice adds packet resealing/opening work outside the
  core hidden-eval projector.
- Added projection-mode metadata to the output-projection stage request and
  response payloads, bound it into the request/response transcript digests, and
  added a regression that tampering the stage projection mode is rejected before
  the server produces an output-projection response.
- Added prepared-session projection metadata to `PreparedSession`,
  `SharedRuntimeState`, and `DeliveryMaterial`, with the current default set to
  `TrustedServerProjection`. The prepared-session output-projection request
  helper now builds from that session mode.
- Added an explicit `ClientOutputValueKind` packet domain type distinguishing
  unmasked client base output from client-blinded base output, bound it into
  client-output packet AAD, and validate it against projection mode at opening,
  report finalization, and server-finalize validation.
- Wrapped the hidden-eval core client output as a typed
  `DdhHiddenEvalClientOutputBundle`, renamed the core field to
  `client_output`, and included the client-output value kind in core output
  digests.
- Split retained server finalize output state so it stores only seed commitment
  metadata plus server output transport material, rather than retaining
  `DdhHiddenEvalClientOutputBundle` or client-output commitment metadata.
- Added staged-artifact client-output metadata for the public value kind and
  commitment, so server finalization can bind the client-owned output packet
  without retaining or recomputing an unmasked client output.
- Added a server-only output projector path for output-projection response
  preparation. The server path computes `x_relayer_base` as `a + 2*tau mod l`
  and does not construct or package an `x_client_base` output bundle.
- Migrated the native test helper and driver process to client-owned staged
  artifact materialization; server-owned staged artifact rebuild from finalize
  state is now rejected.
- Re-ran formal verification and the small native hidden-eval benchmark after
  the server-only projector change. The release benchmark reported
  `output_projector` mean `44.54ms`, `total_hidden_eval` mean `239.43ms`, and
  delivery total mean `271.64ms` across three samples.
- Completed the formal-first checkpoint for projection-mode/value-kind mapping,
  staged-artifact metadata, server-finalize retained-state shape, server-only
  projector algebra, and anti-drift coverage.
- Added a runtime regression proving masked projection finalization rejects a
  client output packet marked as `UnmaskedClientBase`.
- Switched the client-owned masked materialization path so the DDH output
  projector emits `ClientBlindedBase` directly. The masked path no longer opens
  an unmasked staged client output and reseals it after artifact construction.
- Re-ran the small native hidden-eval benchmark after direct masked projection.
  The default unmasked release path reported `output_projector` mean `40.49ms`,
  `total_hidden_eval` mean `217.82ms`, and delivery total mean `249.31ms` across
  three samples.
- Regenerated the checked-in `hss_client_signer` and `near_signer`
  browser/server WASM packages after the direct masked projection change.
- Re-ran the WASM Rust consumer checks, SDK type check, focused HSS relayer
  route tests, and focused single-key/separated-role HSS script-unit suites.
  The HSS-focused route and script tests pass with client-masked output
  projection enabled.
- Re-ran the broader `test:threshold-ed25519:active-path` suite after tightening
  exact threshold-session replay budget handling and updating the
  threshold-ECDSA session auth fixture to the current claim shape. The relayer
  route suite and HSS script suite pass.
- Made client-owned HSS finalization masked-only at the Rust/WASM/SDK boundary:
  client-owned staged artifact construction and client-output opening now
  require `clientOutputMaskB64u`, registration derives a ceremony-local client
  output mask, and export/session flows derive the mask from recoverable client
  material.
- Updated the Verus mirror with a client-owned finalization projection proof,
  re-ran anti-drift, regenerated checked-in WASM artifacts, and re-ran the
  broad threshold-Ed25519 active-path suite.

### Current Boundary

Implementation boundary:

- The model, packet metadata, transcript/AAD binding, and client-side mask
  lifecycle are now in place.
- The server-owned output model no longer needs a mask-injection primitive:
  server output projection is server-only, and client output is produced by
  client-owned materialization.
- The server executor must still never receive `r_client`, or a joined encoded
  `r_client` bundle. That would make the mask reconstructable by the server
  process and fail the intended Level A boundary.
- The implemented Level A route is client-owned finalization: the server stops
  materializing or storing a client-output bundle, while the client materializes
  the client side locally, applies `r_client` inside client-owned projection,
  and submits only a blinded client-output packet plus server-safe finalization
  material.

### Formal-First Checkpoint

The formal-verification surface now names the `ClientMaskedProjection` boundary
that the implementation enforces. The formal gate models the client-output
value kind, staged-artifact metadata, server-finalize retained-state invariant,
and server-only projector algebra.

Formal-first implementation plan:

1. Model projection mode and client-output value kind.
   - Add Verus mirror enums for `OutputProjectionMode` and
     `ClientOutputValueKind`.
   - Specify that `TrustedServerProjection` maps to `UnmaskedClientBase`.
   - Specify that `ClientMaskedProjection` maps to `ClientBlindedBase`.
   - Prove the mapping is total and deterministic.

2. Model staged-artifact output metadata.
   - Add a mirror `StagedEvaluatorArtifactShape` that carries projection mode,
     client-output value kind, and a boolean for client-output commitment
     presence.
   - Specify that every staged artifact used for finalize must carry
     client-output commitment metadata.
   - Specify that the artifact value kind must match the projection mode.

3. Model server-finalize retained state.
   - Add a mirror `ServerEvalFinalizeRetainedShape` for retained server state.
   - Specify that retained server state carries seed commitment metadata and
     server-output transport material.
   - Specify that retained server state does not carry a client-output bundle,
     client-output value kind, or client-output commitment.

4. Model server finalization validation.
   - Specify that finalization combines server-retained seed/server-output
     metadata with staged-artifact client-output metadata.
   - Prove that `ClientMaskedProjection` finalization accepts only
     `ClientBlindedBase`.
   - Prove that `TrustedServerProjection` finalization accepts only
     `UnmaskedClientBase`.

5. Model the server-only projector algebra.
   - Add a spec lemma for `x_relayer_base = a + 2*tau mod l`.
   - Prove it is equivalent to the legacy expression
     `x_relayer_base = (a + tau) + tau mod l`.
   - Document that the server-only output path needs only the relayer output and
     seed commitment metadata for finalization binding.

6. Add anti-drift coverage.
   - Extend [anti_drift.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/formal-verification/verus/tests/anti_drift.rs)
     so production `StagedEvaluatorArtifact` exposes `client_output_value_kind`
     and `client_output_commitment`.
   - Add a production-shape check proving serialized
     `ServerFinalizePacket` still does not expose server output material.
   - Add a production-state debug/shape check for the server finalize retained
     output: no `DdhHiddenEvalClientOutputBundle`, no `x_client_base`, and no
     client-output commitment metadata.

Formal-first TODO:

- [x] Update [server/api.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/formal-verification/verus/src/server/api.rs)
  with projection mode, client-output value kind, staged-artifact shape, and
  server-retained finalize shape.
- [x] Add Verus proofs for projection-mode to client-output value-kind mapping.
- [x] Add Verus proofs that server-retained finalize state excludes client
  output bundle/value-kind/commitment metadata.
- [x] Add Verus proofs that server finalization binds staged-artifact
  client-output metadata to the projection mode.
- [x] Add the `a + 2*tau mod l` equivalence lemma for server-only projection.
- [x] Extend anti-drift tests for the new staged-artifact fields and retained
  server finalize state boundary.
- [x] Run `pnpm check:formal-verification`.
- [x] Only after the formal gate passes, implement the remaining mandatory
  `ClientMaskedProjection` finalization rejection paths.

Next implementation sequence:

- [x] Split retained server-finalization output state from full hidden-eval
  output:
  - server output state keeps `x_relayer_base` transport material and
    commitment/checkpoint data needed for finalization
  - staged artifacts carry the public client-output value kind and commitment
    used for finalization binding
  - server output state does not store client-output value kind or commitment
    metadata
  - retained server finalize state no longer contains the client output bundle
- [x] Split the hidden-eval output model into server-finalization output and
   client-delivery output:
   - server finalization output carries seed commitment metadata and server
     transport bundles
   - client delivery output remains staged-artifact owned and carries explicit
     client-output value kind and commitment metadata
- [x] Change server output-projection response preparation so the server no longer
   calls the full output materializer to store client output in
   `ServerEvalFinalizeState`.
- [x] Add a server-only output projector path that computes the relayer output
   without constructing an `x_client_base` output bundle. Algebraically, this
   should compute the server share as `a + 2*tau mod l` or an equivalent
   expression, so `x_client_base = a + tau mod l` is not named or packaged as a
   server-side output.
- [x] Complete the formal-first checkpoint before changing the remaining
   `ClientMaskedProjection` finalization behavior.
- [x] Make client-owned finalization mandatory for `ClientMaskedProjection`:
   - [x] the client materializes its local staged artifact from role-separated
     delivery
   - [x] the client applies `r_client` locally
   - [x] the staged artifact sent to the server carries `ClientBlindedBase`
   - [x] server finalize rejects `UnmaskedClientBase` for masked projection
- [x] Update transcript validation so server finalization validates the server
   output payload, run binding, projection mode, value kind, and client-output
   packet binding without requiring the server to recompute or store the
   unmasked client output.
- [x] Add boundary tests proving:
  - [x] server finalize state has no `DdhHiddenEvalClientOutputBundle`
  - [x] server finalize state debug output contains no `x_client_base`
  - [x] server finalize state debug output contains no client-output commitment
    metadata
  - [x] masked projection finalize rejects `UnmaskedClientBase`
  - [x] client opening still returns the reference `x_client_base` after
    unmasking
  - [x] server opening still returns the reference `x_relayer_base`

1. **Define the new output model.**
   - [x] Add an `OutputProjectionMode` domain enum with
     `TrustedServerProjection` and `ClientMaskedProjection`.
   - [x] Add explicit projection-mode metadata to client output packets, staged
     artifacts, server finalize packets, role-separated output delivery, and
     reports.
   - [x] Bind masked client output packets to a mask commitment in packet AAD.
   - [x] Reject projection-mode downgrade metadata during report finalization.
   - [x] Replace the core `DdhHiddenEvalOutputBundles.x_client_base` field with
     a neutral client output bundle field.
   - [x] Move the core output value itself to a first-class typed client output
     model.
   - [x] Switch the client-owned masked core projector from unmasked client
     output to blinded client output. The selected primitive is client-owned
     materialization, so `r_client` stays out of the server executor.
   - [x] Add explicit domain types for client mask state.
   - [x] Add explicit domain types for blinded client output beyond the current
     projection-mode enum.
   - [x] Keep the unmasked `x_client_base` type restricted to trusted-server
     projection and client-opened output. `ClientMaskedProjection` artifacts now
     carry only `ClientBlindedBase`.
   - [x] Update all remaining names in reports and packet validation so the
     boundary is visible in types instead of comments.

2. **Add client mask lifecycle.**
   - [x] Carry optional `clientOutputMaskB64u` through the high-level client HSS
     session ceremony helper.
   - [x] Derive `r_client` from `client_recoverable_secret` and stable transcript
     context when the client creates or resumes staged request state.
   - [x] Keep only the minimum derivation context in client driver/output opener
     state.
   - [x] Keep client-owned evaluator state in the client runtime; do not send
     `evaluatorOtStateB64u` to server routes.
   - [x] Include only a mask commitment in transcript-bound client output state.
   - [x] Re-derive after IndexedDB loss using the same account recovery path.
   - [x] Clear transient mask material after successful finalize/open, where
     practical.

3. **Change output projection.**
   - Compute the client-facing output as
     `x_client_base_blinded = x_client_base + r_client mod l`.
   - Preserve `x_relayer_base = x_client_base + tau mod l` or its algebraic
     equivalent for the server-facing output.
   - Keep labels domain-separated, for example:
     `output_projector/x_client_base_blinded`.
   - Avoid producing or storing an unmasked client output bundle in
     `DdhHiddenEvalOutputBundles`.

4. **Choose a mask-injection primitive before coding the projection change.**
   - The target primitive must let the server apply the client mask without
     learning `r_client`.
   - Sending `r_client`, or a joined encoded bundle for `r_client`, to the
     server is disallowed.
   - Document whether the primitive reaches Level A or Level B before
     implementation starts.
   - Level A is acceptable for the first slice if the code and product copy
     claim only masked output-state delivery.
   - Level B requires a design where the same server process cannot reconstruct
     `a + tau` from internal executor state.
   - Current checkpoint result: the current DDH/HSS representation cannot apply
     a client-only scalar mask without revealing reconstructable mask material
     to the single server executor process.
   - Move the slice to a role-separated output-delivery design, or develop a
     new mask-injection primitive before changing projection code.

5. **Update client opening.**
   - [x] Open `x_client_base_blinded` through the existing client output opener.
   - [x] Subtract `r_client` modulo `l` inside the client runtime.
   - [x] Return only the unmasked `x_client_base` from the client API.
   - [x] Ensure debug helpers that materialize hidden outputs are clearly test-only
     and cannot silently bypass the mask lifecycle.

6. **Update wire and transcript binding.**
   - [x] Add the mask commitment to the client output transcript surface.
   - [x] Bind projection mode and mask commitment to client-output packet AAD.
   - [x] Bind the blinded client output commitment to the final report through
     the existing client-output binding.
   - [x] Reject finalize/open attempts when the packet projection mode does not
     match the provided mask or staged artifact metadata.
   - [x] Reject downgrade from `ClientMaskedProjection` to
     `TrustedServerProjection` at report finalization.
   - [x] Add projection mode to output-projection stage request/response
     transcript surfaces.
   - [x] Add projection mode to prepared-session metadata surfaces.
   - [x] Reject downgrade from `ClientMaskedProjection` to
     `TrustedServerProjection` through client policy before ceremony start.

7. **Update tests.**
   - [x] Add unit tests for scalar mask/unmask round trips.
   - [x] Add derivation tests for passkey PRF and recovered-client-secret roots.
   - [x] Add protocol-flow tests proving the client opens the same
     `x_client_base` as the reference after unmasking.
   - [x] Add negative tests for missing and mismatched mask state.
   - [x] Add negative tests for cross-context mask state.
   - [x] Document same-context deterministic mask re-derivation as required
     recovery behavior rather than a negative reuse case.
   - [x] Add downgrade tests where client policy requires `ClientMaskedProjection`.
   - [x] Add a boundary regression test that server finalization state contains no
     field named or typed as unmasked `x_client_base`.
   - [x] Add a stage-transcript regression proving projection-mode tampering is
     rejected at output-projection response preparation.
   - [x] Add a prepared-session delivery-material regression proving projection
     mode is visible before stage execution.
   - [x] Add a packet-value-kind regression proving trusted projection cannot
     carry client-blinded output metadata.
   - [x] Add a core-output regression proving server finalization state uses the
     typed client-output field and no unmasked `x_client_base` field name.

8. **Run verification and benchmarks.**
   - [x] Run focused Rust tests for output projection and protocol flow.
   - [x] Run `pnpm check:formal-verification`.
   - [x] Regenerate the native phase3 hidden-eval benchmark.
   - [x] Compare `output_projector`, `total_hidden_eval`, and delivery total against
     the current native baseline.

## SDK/API Integration Surface

The Level A implementation changes the crate API and the SDKs that drive the
HSS ceremony. The intended public client result can remain `xClientBaseB64u`,
but the server-owned protocol state, final reports, and route payloads need to
represent the blinded output and transcript-bound projection mode explicitly.

### Rust crate surfaces

Update the core output and transcript types first:

- [src/ddh/hidden_eval_executor.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/ddh/hidden_eval_executor.rs)
  - replace `DdhHiddenEvalOutputBundles.x_client_base` with a blinded client
    output field
  - update `execute_output_projector_stage` so the stored client-facing bundle
    is labeled and committed as `x_client_base_blinded`
  - update output digest hashing to commit to the blinded output
- [src/protocol/transcript.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/protocol/transcript.rs)
  - bind `OutputProjectionMode`, mask commitment, and blinded output commitment
    into evaluation and final-report digests
- [src/client/outputs.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/client/outputs.rs)
  - open `x_client_base_blinded`, re-derive the mask, subtract it locally, and
    return unmasked client output
- [src/client/api.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/client/api.rs)
  - seal the blinded client output in staged artifacts and reports
- [src/server/api.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/server/api.rs)
  and [src/server/state.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/server/state.rs)
  - persist only blinded client output and projection-mode metadata in server
    finalize state

### WASM bindings

The generated JS/TS package files should be regenerated from Rust changes, not
hand-edited.

- [wasm/hss_client_signer/src/threshold_hss.rs](/Users/pta/Dev/rust/simple-threshold-signer/wasm/hss_client_signer/src/threshold_hss.rs)
  - add mask-derivation inputs or opaque client mask state to prepare/open
    requests
  - update `threshold_ed25519_hss_open_client_output` to unmask locally before
    returning `xClientBaseB64u`
- [wasm/hss_client_signer/src/lib.rs](/Users/pta/Dev/rust/simple-threshold-signer/wasm/hss_client_signer/src/lib.rs)
  - export the revised opening API
- [wasm/near_signer/src/threshold/threshold_hss.rs](/Users/pta/Dev/rust/simple-threshold-signer/wasm/near_signer/src/threshold/threshold_hss.rs)
  - carry projection mode and mask commitment through server-side prepare,
    respond, and finalize wrappers
- [wasm/threshold_prf/src/lib.rs](/Users/pta/Dev/rust/simple-threshold-signer/wasm/threshold_prf/src/lib.rs)
  - update context-binding helpers if projection mode becomes part of the HSS
    context binding

### Client SDK

The client SDK must carry mask policy and derivation context through the HSS
lifecycle, while preserving the post-open result shape consumed by signing
flows.

- [client/src/core/types/signer-worker.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/types/signer-worker.ts)
  - add worker request/result fields for projection mode, mask commitment, and
    client-only mask derivation context
  - keep lifecycle/auth/session fields required, following the TypeScript domain
    state rules
  - split client-retained evaluator state from server-visible request payloads
- [client/src/core/signingEngine/workerManager/workers/hss-client.worker.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/workerManager/workers/hss-client.worker.ts)
  - pass the new mask state to WASM opening
  - review the PRF-secret payload guard so it still blocks accidental leakage
    while allowing the approved mask derivation path
- [client/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.ts)
  - add typed wrappers for masked projection prepare/open inputs
  - continue returning unmasked `xClientBaseB64u` only after local unmasking
- [client/src/core/signingEngine/threshold/ed25519/hssLifecycle.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/threshold/ed25519/hssLifecycle.ts)
  - thread projection policy through prepare, respond, finalize, and client
    open
  - reject downgrade when the client requires `ClientMaskedProjection`
- [client/src/core/signingEngine/threshold/ed25519/hssClientBase.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/threshold/ed25519/hssClientBase.ts)
  - derive or re-derive mask state from the same recoverable client secret path
    used to recover the HSS client base

Downstream consumers that only need the final opened `xClientBaseB64u` should
require little or no shape change after the opening layer is updated. Audit the
signing flows, warm-session bootstrap, email-recovery provisioning, passkey
session code, and sealed-session persistence to confirm they only see the
post-open result.

### Server SDK and routes

The server SDK and route layer must accept the client-selected projection mode
and commitment, then persist them with ceremony state.

- [server/src/core/ThresholdService/ed25519HssWasm.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/ThresholdService/ed25519HssWasm.ts)
  - add projection mode and mask commitment to server prepare, ceremony, and
    report-finalization wrappers
  - keep server output opening centered on `xRelayerBaseB64u`
- [server/src/core/ThresholdService/ThresholdSigningService.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/ThresholdService/ThresholdSigningService.ts)
  - persist projection mode and mask commitment in HSS ceremony records for
    registration and warm-session flows
- [server/src/core/types.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/types.ts)
  - update HSS request/response domain types so blinded client output is
    distinct from opened client output
  - reject server-route HSS client request envelopes that contain
    `evaluatorOtStateB64u`
- [server/src/router/express/routes/thresholdEd25519.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/express/routes/thresholdEd25519.ts)
  and [server/src/router/cloudflare/routes/thresholdEd25519.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/cloudflare/routes/thresholdEd25519.ts)
  - validate and pass projection metadata through prepare, respond, and finalize
- [server/src/router/relayRegistrationThresholdEd25519Hss.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/relayRegistrationThresholdEd25519Hss.ts)
  plus the Express and Cloudflare registration route wrappers
  - mirror the same projection metadata for registration ceremonies
- [server/src/router/relay.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/relay.ts)
  - update the relay interface shape for the revised HSS API

### Tests and generated artifacts

Add targeted coverage before broad builds:

- [x] Rust protocol-flow tests for masked projection and downgrade rejection
- [x] TypeScript type fixtures and targeted unit tests for projection policy,
  missing mask state, and raw route payloads crossing into core lifecycle code
- [x] TypeScript fixtures and route tests proving server HSS route payloads
  reject `evaluatorOtStateB64u` and raw client secret material
- [x] route/service tests for registration and warm-session HSS ceremonies
- [x] worker tests showing raw mask material is absent from server payloads and logs
- [x] regenerated WASM JS/TS artifacts after the Rust APIs are finalized

## Expected Cost

The intended near-term path should be cheaper than full malicious-secure MPC:

- one extra scalar mask/unmask path
- additional transcript fields
- extra validation around client mask state
- possible output-projector overhead if the mask is applied inside the hidden
  arithmetic layer

If the design needs client-side finalization or split execution to keep
`r_client` hidden from server memory, the cost estimate moves from low/moderate
to moderate/high, especially on the wasm path.

## Difference From True Malicious Security

`ClientMaskedProjection` is a confidentiality hardening feature for the client
output share. It narrows what the server can retain or deliver for
`x_client_base`, and it gives the client a downgrade-resistant way to require
masked delivery.

True malicious security is broader. It would cover active cheating and
correctness across the whole protocol, including:

- malicious-secure OT
- authenticated Beaver material or equivalent active checks
- proof that the server used the committed inputs and correct hidden-eval
  circuit
- proof that output labels, commitments, and openings are consistent
- abort behavior that does not leak useful information across retries
- replay and cross-session mixing resistance under active adversaries
- formal or proof-oriented treatment of what each party can learn under
  malicious behavior

`ClientMaskedProjection` does not prove all of those properties. It also does
not automatically prevent a malicious server process from reading every
transient internal executor value if the selected mask-injection primitive still
materializes reconstructable `a`, `tau`, or unmasked `x_client_base` inside that
same process. The implementation checkpoint for the mask-injection primitive is
therefore a security requirement and a performance design point.

## Non-Goals For This Slice

This slice does not attempt to deliver:

- a full malicious-client security proof
- malicious-secure OT
- authenticated Beaver protections
- a complete arbitrary-server-memory compromise proof
- changes to the `ExplicitKeyExport` product exception

Those remain separate hardening workstreams.

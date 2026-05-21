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

1. **Define the new output model.**
   - Replace the server-side `x_client_base` output field with
     `x_client_base_blinded`.
   - Add explicit domain types for client mask state and blinded client output.
   - Add an `OutputProjectionMode` domain enum with `TrustedServerProjection`
     and `ClientMaskedProjection`.
   - Keep the unmasked `x_client_base` type restricted to client-opened output.
   - Update names in reports and packet validation so the boundary is visible in
     types instead of comments.

2. **Add client mask lifecycle.**
   - Derive `r_client` from `client_recoverable_secret` and stable transcript
     context when the client creates or resumes staged request state.
   - Keep only the minimum derivation context in client driver/output opener
     state.
   - Include only a mask commitment in transcript-bound client state.
   - Re-derive after IndexedDB loss using the same account recovery path.
   - Clear transient mask material after successful finalize/open, where
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
   - If the current DDH/HSS representation cannot apply a client-only mask
     without revealing it, stop at a design checkpoint and move this slice to a
     client-side finalization or split-executor design.

5. **Update client opening.**
   - Open `x_client_base_blinded` through the existing client output opener.
   - Subtract `r_client` modulo `l` inside the client runtime.
   - Return only the unmasked `x_client_base` from the client API.
   - Ensure debug helpers that materialize hidden outputs are clearly test-only
     and cannot silently bypass the mask lifecycle.

6. **Update wire and transcript binding.**
   - Add the mask commitment to the client transcript surface.
   - Add the projection mode to prepared-session and stage transcript surfaces.
   - Bind the blinded client output commitment to the final report.
   - Reject finalize/open attempts when the mask commitment or context binding
     does not match the stored client mask state.
   - Reject downgrade from `ClientMaskedProjection` to
     `TrustedServerProjection`.

7. **Update tests.**
   - Add unit tests for scalar mask/unmask round trips.
   - Add derivation tests for passkey PRF and recovered-client-secret roots.
   - Add protocol-flow tests proving the client opens the same
     `x_client_base` as the reference after unmasking.
   - Add negative tests for missing, mismatched, reused, or cross-context mask
     state.
   - Add downgrade tests where client policy requires `ClientMaskedProjection`.
   - Add a boundary regression test that server finalization state contains no
     field named or typed as unmasked `x_client_base`.

8. **Run verification and benchmarks.**
   - Run focused Rust tests for output projection and protocol flow.
   - Run `pnpm check:formal-verification`.
   - Regenerate the native phase3 hidden-eval benchmark.
   - Compare `output_projector`, `total_hidden_eval`, and delivery total against
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

- Rust protocol-flow tests for masked projection and downgrade rejection
- TypeScript type fixtures for invalid projection-mode state, missing mask
  commitment, and raw route payloads crossing into core lifecycle code
- route/service tests for registration and warm-session HSS ceremonies
- worker tests showing raw mask material is absent from server payloads and logs
- regenerated WASM JS/TS artifacts after the Rust APIs are finalized

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

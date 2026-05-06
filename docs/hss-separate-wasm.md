# Separate HSS Client WASM Plan

Date: April 5, 2026

## Summary

The current browser HSS path still ships a wasm artifact that is roughly
`1,163,940` bytes. That is too large for a latency-sensitive browser hot path.

The main problem is structural:

- the current browser build still compiles the broader
  [wasm/near_signer](/Users/pta/Dev/rust/simple-threshold-signer/wasm/near_signer)
  worker surface
- the recent `hss-client-exports` / `hss-server-exports` split helped, but it
  only trimmed the export surface
- the client is still paying for unrelated signer-worker code that the HSS
  registration / rebuild / export path does not need

This plan defines a phased path to introduce a separate HSS client wasm package
and keep it only if it materially reduces shipped browser size without
regressing behavior.


## Current Baseline

Old broad browser HSS artifact benchmarked from a release build of
`wasm/near_signer` with `hss-client-exports` enabled:

- wasm: `1,163,476` bytes
- JS glue: `173,004` bytes

Current relay/server HSS wasm artifact:

- `1,148,011` bytes

The current export split is already worth keeping, but it is not enough.

Phase 0 findings completed so far:

- browser wasm baseline confirmed from
  [wasm/near_signer/pkg/wasm_signer_worker_bg.wasm](/Users/pta/Dev/rust/simple-threshold-signer/wasm/near_signer/pkg/wasm_signer_worker_bg.wasm)
- browser JS glue baseline confirmed from
  [wasm/near_signer/pkg/wasm_signer_worker.js](/Users/pta/Dev/rust/simple-threshold-signer/wasm/near_signer/pkg/wasm_signer_worker.js)
- relay/server wasm baseline confirmed from
  [wasm/near_signer/pkg-server/wasm_signer_worker_bg.wasm](/Users/pta/Dev/rust/simple-threshold-signer/wasm/near_signer/pkg-server/wasm_signer_worker_bg.wasm)
- active browser-path timing baseline captured from the real worker-driven HSS
  harness in
  [tests/unit/thresholdEd25519.singleKeyHssActivePath.script.unit.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/unit/thresholdEd25519.singleKeyHssActivePath.script.unit.test.ts):
  - rebuild / lazy reconstruction:
    - `prepareSessionMs`: about `364-390ms`
    - `prepareClientRequestMs`: about `229-243ms`
    - `relayCeremonyMs`: about `3034-3219ms`
    - `totalMs`: about `3653-3851ms`
  - ceremony substeps:
    - HSS prepare total: about `322-367ms`
    - HSS finalize total: about `514-545ms`
    - HSS ceremony total: about `3034-3218ms`
  - sessionless registration finalize route:
    - `[Registration] threshold-ed25519 HSS finalize response received`: about `520ms`

## Proposed Architecture

Introduce a dedicated browser HSS client wasm target, separate from the broader
`near_signer` worker wasm.

Preferred shape:

- keep the main protocol code in
  [crates/ed25519-hss](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss)
- create a new wasm package focused only on browser HSS client behavior
- make the SDK build emit:
  - the minimal HSS client wasm package for browser HSS flows
  - the existing full signer worker for transaction signing flows
  - the server/relay HSS package for garbler-side relay use

That means the browser HSS flow should stop depending on the monolithic
`near_signer` worker artifact.

## Recommended Package Shape

Preferred new package:

- `wasm/hss_client_signer/`

Responsibilities:

- expose only browser HSS client entrypoints:
  - prepare session
  - prepare client request
  - evaluate result
  - open client output
  - open seed output
  - public key from base shares
- depend on:
  - `ed25519-hss`
  - minimal encoding helpers
  - minimal wasm-bindgen / serde glue

Must not depend on:

- transaction action handlers
- COSE parsing unless truly needed on the HSS path
- generic worker envelope routing
- unrelated threshold ECDSA / NEAR transaction modules

## Phased Plan

### Phase 0: Baseline And Measurement

Before changing architecture:

- record current browser wasm size
- record current JS glue size
- record current registration/rebuild/export timings
- record which browser entrypoints are actually used by the HSS path

Keep this as the before/after comparison baseline.

### Phase 1: Isolate The HSS Browser Surface

Audit the active browser HSS path and list the exact wasm exports it requires.

The actual currently used browser HSS surface is:

- `threshold_ed25519_hss_prepare_session`
- `threshold_ed25519_hss_prepare_client_request`
- `threshold_ed25519_hss_evaluate_result`
- `threshold_ed25519_hss_open_client_output`
- `threshold_ed25519_hss_open_seed_output`
- `threshold_ed25519_hss_public_key_from_base_shares`
- `threshold_ed25519_seed_export_artifact_from_seed`

Also identify all imports in the client code that currently pull in the broader
`near_signer` worker for HSS-only use.

Phase 1 findings completed so far:

- the HSS worker wrapper surface is concentrated in
  [client/src/core/signingEngine/signers/wasm/hssClientSignerWasm.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/signers/wasm/hssClientSignerWasm.ts)
  and currently wraps:
  - prepare session
  - prepare client request
  - evaluate result
  - open client output
  - open seed output
  - derive public key from base shares
  - build seed export artifact
- active browser HSS lifecycle consumers are:
  - [client/src/core/signingEngine/api/thresholdLifecycle/thresholdEd25519Lifecycle.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/api/thresholdLifecycle/thresholdEd25519Lifecycle.ts)
    for registration, ceremony completion, session ceremony, and export
  - [client/src/core/signingEngine/orchestration/near/shared/ensureThresholdEd25519HssClientBase.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/orchestration/near/shared/ensureThresholdEd25519HssClientBase.ts)
    for lazy client-base reconstruction
  - [client/src/core/signingEngine/SigningEngine.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/SigningEngine.ts)
    for export
- the export UI path in
  [client/src/core/signingEngine/workerManager/workers/passkey-confirm.worker.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/workerManager/workers/passkey-confirm.worker.ts)
  now uses the dedicated `hss_client_signer` package for
  `threshold_ed25519_seed_export_artifact_from_seed`
- the browser HSS path still depends on one non-`threshold_hss.rs` helper from
  the monolithic worker:
  `DeriveThresholdEd25519HssClientInputs`, surfaced through
  [client/src/core/signingEngine/signers/wasm/hssClientSignerWasm.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/signers/wasm/hssClientSignerWasm.ts)
  and implemented in
  [wasm/near_signer/src/handlers/handle_threshold_ed25519_derive_hss_client_inputs.rs](/Users/pta/Dev/rust/simple-threshold-signer/wasm/near_signer/src/handlers/handle_threshold_ed25519_derive_hss_client_inputs.rs)
- the type surface is still coupled to the broad worker artifact through
  [client/src/core/types/signer-worker.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/types/signer-worker.ts)
  which imports types from
  [wasm/near_signer/pkg/wasm_signer_worker.js](/Users/pta/Dev/rust/simple-threshold-signer/wasm/near_signer/pkg/wasm_signer_worker.js)

Minimum code surface for a standalone browser HSS client package:

- from `threshold_hss.rs`:
  - prepare session
  - prepare client request
  - evaluate result
  - open client output
  - open seed output
  - public key from base shares
- from the current worker handler surface:
  - derive HSS client inputs from `PRF.first`
- from `threshold_frost.rs`:
  - seed export artifact builder, if export stays on the same browser package
- minimal glue only:
  - base64 helpers
  - serde / wasm-bindgen bindings
  - any small validation helpers needed by those exact paths

The separate package should avoid carrying:

- generic signer worker request routing
- transaction signing handlers
- action/delegate flows
- unrelated COSE / transaction / NEAR action code
- server/garbler HSS exports

### Phase 2: Create A Dedicated HSS Client WASM Package

Create a new wasm package dedicated to the browser HSS client path.

Initial implementation rules:

- reuse existing HSS logic from `ed25519-hss`
- copy only the minimum helper code needed from `near_signer`
- do not carry over generic multi-purpose worker routing
- do not keep dead duplicate helper modules if they become unused in
  `near_signer`

The package should expose a narrow API and compile independently.

Phase 2 findings completed so far:

- dedicated browser package created at
  [wasm/hss_client_signer](/Users/pta/Dev/rust/simple-threshold-signer/wasm/hss_client_signer)
- current exported browser-only surface there is:
  - `threshold_ed25519_hss_prepare_session`
  - `threshold_ed25519_hss_prepare_client_request`
  - `threshold_ed25519_hss_evaluate_result`
  - `threshold_ed25519_hss_open_client_output`
  - `threshold_ed25519_hss_open_seed_output`
  - `threshold_ed25519_hss_public_key_from_base_shares`
  - `derive_threshold_ed25519_hss_client_inputs`
  - `threshold_ed25519_seed_export_artifact_from_seed`
- the package compiles independently with no relay/server HSS exports and no
  transaction-signing handler surface

### Phase 3: Wire The SDK Build

Update the SDK build so it emits the new HSS client artifact.

Required updates:

- build script support
- type generation support
- worker bundling or loader support
- artifact copy / output placement in `dist`

At this stage, the old browser HSS path may exist only as a short migration
bridge during implementation. The landed browser path now uses the dedicated
package.

Phase 3 findings completed so far:

- SDK build path registry updated for
  [wasm/hss_client_signer](/Users/pta/Dev/rust/simple-threshold-signer/wasm/hss_client_signer)
- dev/prod build scripts now build the new browser HSS client package
- code generation now emits
  [wasm/hss_client_signer/pkg/hss_client_signer.d.ts](/Users/pta/Dev/rust/simple-threshold-signer/wasm/hss_client_signer/pkg/hss_client_signer.d.ts)
- `dist/esm` emission now includes:
  - [dist/esm/wasm/hss_client_signer/pkg/hss_client_signer.js](/Users/pta/Dev/rust/simple-threshold-signer/sdk/dist/esm/wasm/hss_client_signer/pkg/hss_client_signer.js)
  - [dist/esm/wasm/hss_client_signer/pkg/hss_client_signer_bg.wasm](/Users/pta/Dev/rust/simple-threshold-signer/sdk/dist/esm/wasm/hss_client_signer/pkg/hss_client_signer_bg.wasm)
- build plumbing is now present for the new package and is the active browser HSS path

### Phase 4: Switch The Browser HSS Flow To The New Package

Move the active browser HSS flow to the new client package.

This includes:

- registration HSS flow
- Ed25519 single-key HSS rebuild flow
- export flow if it uses the same browser HSS evaluator path

After the new path is working:

- remove the old browser HSS dependency on the broad `near_signer` worker
- delete dead loader code and duplicate wrapper code immediately

Phase 4 findings completed so far:

- browser HSS request types in
  [client/src/core/signingEngine/workerManager/workers/near-signer.worker.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/workerManager/workers/near-signer.worker.ts)
  now execute against
  [wasm/hss_client_signer/pkg/hss_client_signer.js](/Users/pta/Dev/rust/simple-threshold-signer/wasm/hss_client_signer/pkg/hss_client_signer.js)
  instead of the monolithic `near_signer` wasm
- this covers the active browser HSS registration and lazy rebuild flows through
  [client/src/core/signingEngine/signers/wasm/hssClientSignerWasm.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/signers/wasm/hssClientSignerWasm.ts)
  and `near-signer.worker.ts`
- the browser export artifact path in
  [client/src/core/signingEngine/workerManager/workers/passkey-confirm.worker.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/workerManager/workers/passkey-confirm.worker.ts)
  now imports
  `threshold_ed25519_seed_export_artifact_from_seed` from the separate HSS client package
- the broader browser `near_signer` package still remains in the browser for
  NEAR transaction signing, but the HSS browser path no longer depends on it

### Phase 5: Remove Dead Mixed Surface

Once the browser no longer uses the broad `near_signer` worker for HSS:

- remove old HSS browser exports from the broad worker if no longer needed
- remove stale TypeScript wrappers
- remove stale build-script branches
- update docs so they describe the dedicated browser HSS package as the active
  packaging model

This phase should leave one clear browser HSS wasm path, not two.

Phase 5 findings completed so far:

- the plain browser `near_signer` build no longer compiles the browser HSS implementation:
  - browser HSS exports were gated out of
    [wasm/near_signer/src/threshold/threshold_hss.rs](/Users/pta/Dev/rust/simple-threshold-signer/wasm/near_signer/src/threshold/threshold_hss.rs)
    and
    [wasm/near_signer/src/threshold/threshold_frost.rs](/Users/pta/Dev/rust/simple-threshold-signer/wasm/near_signer/src/threshold/threshold_frost.rs)
  - browser build scripts now build
    [wasm/near_signer](/Users/pta/Dev/rust/simple-threshold-signer/wasm/near_signer)
    without `hss-client-exports`
- HSS browser result typing no longer depends on generated HSS result classes from the monolithic signer package in
  [client/src/core/types/signer-worker.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/types/signer-worker.ts)
- the old browser-only wrapper module was removed and replaced by
  [client/src/core/signingEngine/signers/wasm/hssClientSignerWasm.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/signers/wasm/hssClientSignerWasm.ts)
  so the active browser HSS wrapper surface no longer uses `nearSigner*` naming
- server-only HSS helpers that are still genuinely used by the relay remain on the `pkg-server` artifact
- the active docs and browser loader names now describe the dedicated HSS client
  package rather than a mixed `near_signer` browser HSS path

### Phase 6: Benchmark And Decide

Measure:

- browser HSS wasm size
- browser HSS JS glue size
- registration timing
- first-load timing for the HSS path

Keep the split only if the size win is meaningful and behavior remains clean.

If the split saves little, revert it instead of carrying extra package/build
complexity.

Phase 6 findings completed so far:

- production SDK build completed successfully via
  [sdk/scripts/build/build-prod.sh](/Users/pta/Dev/rust/simple-threshold-signer/sdk/scripts/build/build-prod.sh)
- shipped browser HSS client artifact in `dist/esm` was initially:
  - wasm:
    [sdk/dist/esm/wasm/hss_client_signer/pkg/hss_client_signer_bg.wasm](/Users/pta/Dev/rust/simple-threshold-signer/sdk/dist/esm/wasm/hss_client_signer/pkg/hss_client_signer_bg.wasm)
    = `562,737` bytes
  - JS glue:
    [sdk/dist/esm/wasm/hss_client_signer/pkg/hss_client_signer.js](/Users/pta/Dev/rust/simple-threshold-signer/sdk/dist/esm/wasm/hss_client_signer/pkg/hss_client_signer.js)
    = `22,209` bytes
- shipped browser `near_signer` artifact is now separate and HSS-free:
  - wasm:
    [sdk/dist/esm/wasm/near_signer/pkg/wasm_signer_worker_bg.wasm](/Users/pta/Dev/rust/simple-threshold-signer/sdk/dist/esm/wasm/near_signer/pkg/wasm_signer_worker_bg.wasm)
    = `657,699` bytes
  - JS glue:
    [sdk/dist/esm/wasm/near_signer/pkg/wasm_signer_worker.js](/Users/pta/Dev/rust/simple-threshold-signer/sdk/dist/esm/wasm/near_signer/pkg/wasm_signer_worker.js)
    = `146,416` bytes
- compared to the old broad browser HSS artifact, the dedicated browser HSS
  package reduces:
  - wasm by `600,739` bytes, about `51.6%`
  - JS glue by `150,795` bytes, about `87.2%`
- release init/load proxy benchmark using the same web-target wasm modules in
  Node showed first-load improvement for the dedicated package:
  - old broad browser HSS artifact: `11.542ms` mean across 5 samples
  - dedicated `hss_client_signer`: `9.344ms` mean across 5 samples
  - improvement: about `19.0%`
- these results clear the keep threshold, so the split should be kept

## Post-Plan Follow-Up

After the main split plan landed, we completed one more browser/relay seam
cleanup and another wasm-size pass.

### Relay-Authored Prepare Seam

The browser HSS path no longer prepares relay-only / garbler-side session state
on the client hot path.

What changed:

- the relay `prepare` route now creates the authoritative HSS prepared session
  and returns:
  - `preparedSession`
  - `clientOtOfferMessageB64u`
  - `ceremonyHandle`
- the browser now sends only:
  - `context` to `prepare`
  - `clientRequest` plus `ceremonyHandle` to `respond`
  - `evaluationResult` plus `ceremonyHandle` to `finalize`
- the browser HSS path no longer needs to post or depend on browser-created
  garbler-side session material

Measured route-payload result:

- session HSS finalize request:
  - before: `315,263` bytes
  - after ceremony-handle seam: `154,622` bytes
  - reduction: `160,641` bytes, about `50.9%`
- registration HSS finalize request:
  - now `154,693` bytes

Measured active-path timings after the seam cleanup:

- HSS prepare: about `340-367ms`
- HSS respond: about `302-310ms`
- HSS finalize: about `479-489ms`
- full HSS ceremony: about `3.57-3.64s`

### Additional WASM Reduction

We then continued the browser HSS wasm minimization pass:

- removed `serde_wasm_bindgen` from the browser HSS path
- made `serde_json` host-only in `ed25519-hss`
- compacted serialized runtime state so the browser carries compact context
  instead of full candidate metadata
- stopped duplicating evaluator state inside shared runtime state

Current shipped browser HSS baseline from the production SDK build:

- wasm:
  [sdk/dist/esm/wasm/hss_client_signer/pkg/hss_client_signer_bg.wasm](/Users/pta/Dev/rust/simple-threshold-signer/sdk/dist/esm/wasm/hss_client_signer/pkg/hss_client_signer_bg.wasm)
  = `413,159` bytes
- JS glue:
  [sdk/dist/esm/wasm/hss_client_signer/pkg/hss_client_signer.js](/Users/pta/Dev/rust/simple-threshold-signer/sdk/dist/esm/wasm/hss_client_signer/pkg/hss_client_signer.js)
  = `14,897` bytes
- dedicated browser HSS worker:
  [sdk/dist/workers/hss-client.worker.js](/Users/pta/Dev/rust/simple-threshold-signer/sdk/dist/workers/hss-client.worker.js)
  = `22,550` bytes raw

Current shipped relay/server HSS baseline from the production SDK build:

- wasm:
  [sdk/dist/esm/server/wasm/near_signer/pkg-server/wasm_signer_worker_bg.wasm](/Users/pta/Dev/rust/simple-threshold-signer/sdk/dist/esm/server/wasm/near_signer/pkg-server/wasm_signer_worker_bg.wasm)
  = `874,850` bytes
- JS glue:
  [sdk/dist/esm/server/wasm/near_signer/pkg-server/wasm_signer_worker.js](/Users/pta/Dev/rust/simple-threshold-signer/sdk/dist/esm/server/wasm/near_signer/pkg-server/wasm_signer_worker.js)
  = `47,598` bytes

Net browser HSS reduction versus the original broad browser artifact:

- wasm:
  `1,163,476` -> `413,159`
  reduction: `750,317` bytes, about `64.5%`
- JS glue:
  `173,004` -> `14,897`
  reduction: `158,107` bytes, about `91.4%`

### Follow-Up Checklist

- [x] Move relay-only / garbler-side session preparation fully off the browser hot path
- [x] Make relay `prepare` authoritative for returned evaluator session state
- [x] Keep the active rebuild / export / registration HSS flows green with the new seam
- [x] Rebuild production browser/server artifacts and record the new shipped sizes

## Verification Requirements

At minimum, each meaningful phase should re-run:

- `cargo test` for `crates/ed25519-hss`
- `cargo test` for the new HSS client wasm package
- `cargo test` for `wasm/near_signer`
- `npx tsc --noEmit -p sdk/tsconfig.build.json`

And after the switch:

- registration flow smoke test
- single-key HSS rebuild flow smoke test
- export flow smoke test

## Risks

1. Duplicate packaging complexity.
   If the new HSS client package and the existing `near_signer` package share too
   much glue code, the build can become harder to reason about.

2. Partial migration drift.
   If the browser still quietly imports the broad worker somewhere, the size win
   will be smaller than expected.

3. Hidden helper coupling.
   The current HSS browser path may rely on more `near_signer` internals than the
   public exports make obvious.

4. Regressions from temporary dual paths.
   If both old and new paths stay alive too long, the codebase will get noisier.
   Avoid that.

## Next Optimization Pass

The browser HSS split is worth keeping, but the shipped browser HSS wasm is
still large enough that another optimization pass is justified.

The next pass should stay disciplined:

1. test one optimization at a time
2. benchmark size and hot-path timing before and after
3. keep a change only if it materially helps
4. remove dead code immediately if a change lands

The highest-value follow-up tasks are below.

### Optimization 1: Run A Stronger `wasm-opt` Pass

Current state:

- both
  [wasm/hss_client_signer/Cargo.toml](/Users/pta/Dev/rust/simple-threshold-signer/wasm/hss_client_signer/Cargo.toml)
  and
  [wasm/near_signer/Cargo.toml](/Users/pta/Dev/rust/simple-threshold-signer/wasm/near_signer/Cargo.toml)
  already use:
  - `opt-level = "z"`
  - `lto = true`
  - `codegen-units = 1`
  - `panic = "abort"`
  - `wasm-opt = true`

Potential improvement:

- run an explicit post-build `wasm-opt -Oz --strip-debug --strip-dwarf`
  against the browser HSS client artifact
- keep it only if it beats the current default `wasm-pack` result

Landed benchmark:

- baseline production browser HSS wasm:
  `562,772` bytes
- explicit post-pass output:
  `557,527` bytes
- reduction:
  `5,245` bytes, about `0.93%`

Decision:

- do not keep this as a new build step
- the extra complexity is not justified by a sub-1% size win

### Optimization 2: Split Export-Only Code Out Of `hss_client_signer`

Current state:

- the browser HSS package still includes both:
  - hot-path HSS ceremony/rebuild logic
  - seed export artifact construction

Current export-only code now isolated:

- [wasm/hss_client_signer/src/threshold_export.rs](/Users/pta/Dev/rust/simple-threshold-signer/wasm/hss_client_signer/src/threshold_export.rs)
  exists only to expose:
  - `threshold_ed25519_seed_export_artifact_from_seed`
- that path depends on
  [crates/signer-platform-web](/Users/pta/Dev/rust/simple-threshold-signer/crates/signer-platform-web)
  `near_ed25519_recovery`, which is not part of the registration/rebuild hot
  path
- the rest of the package is the actual browser HSS evaluator surface:
  - [wasm/hss_client_signer/src/client_inputs.rs](/Users/pta/Dev/rust/simple-threshold-signer/wasm/hss_client_signer/src/client_inputs.rs)
  - [wasm/hss_client_signer/src/threshold_hss.rs](/Users/pta/Dev/rust/simple-threshold-signer/wasm/hss_client_signer/src/threshold_hss.rs)

Potential improvement:

- separate `threshold_ed25519_seed_export_artifact_from_seed` into:
  - a second tiny wasm package, or
  - a clearly separate lazy-loaded export package
- keep the HSS hot path focused on registration and rebuild only

Landed benchmark:

- hot-path browser HSS package before the split:
  - wasm: `562,772` bytes
  - JS glue: `22,209` bytes
- hot-path browser HSS package after moving export out:
  - wasm: `553,537` bytes
  - JS glue: `21,880` bytes
- hot-path reduction:
  - wasm: `9,235` bytes, about `1.64%`
  - JS glue: `329` bytes, about `1.48%`
- separate export package added:
  - wasm: `119,738` bytes
  - JS glue: `10,722` bytes

Decision:

- do not keep the separate export package
- the hot-path win is too small to justify the extra build/package complexity
- export stays in
  [wasm/hss_client_signer/src/threshold_export.rs](/Users/pta/Dev/rust/simple-threshold-signer/wasm/hss_client_signer/src/threshold_export.rs)
  and the temporary export-only wasm package was removed

### Optimization 3: Replace `serde_json` For Internal WASM State Blobs

This is the highest-priority code-level optimization candidate after the wasm
split.

Current state:

- [wasm/hss_client_signer/Cargo.toml](/Users/pta/Dev/rust/simple-threshold-signer/wasm/hss_client_signer/Cargo.toml)
  no longer depends on `serde_json` directly for internal HSS state blobs
- the HSS browser path now serializes internal state blobs as compact bincode
  payloads wrapped in base64url, using:
  - `garblerDriverStateB64u`
  - `evaluatorDriverStateB64u`
  - `evaluatorOtStateB64u`
- these are large internal protocol/runtime state carriers, not human-facing
  payloads

Landed result:

- removed direct `serde_json` usage from
  [wasm/hss_client_signer/src/threshold_hss.rs](/Users/pta/Dev/rust/simple-threshold-signer/wasm/hss_client_signer/src/threshold_hss.rs)
  for internal driver/OT state transport
- replaced it with `bincode` plus existing base64url transport
- regenerated the browser HSS wasm package and reran the active-path keep-gate
- production browser HSS artifact changed from:
  - `662,319` bytes wasm
  - `22,209` bytes JS glue
- to:
  - `562,772` bytes wasm
  - `22,209` bytes JS glue
- wasm reduction: `99,547` bytes, about `15.0%`

Why this matters:

- `serde_json` often brings a non-trivial code-size cost into wasm
- JSON is also inefficient for large internal state blobs that never need to be
  user-readable
- if these are internal-only transport/state blobs, a smaller binary encoding
  or more compact string-safe format could cut both wasm size and payload size

Recommended evaluation order:

1. confirm exactly where `serde_json` is used in:
   - [wasm/hss_client_signer](/Users/pta/Dev/rust/simple-threshold-signer/wasm/hss_client_signer)
   - [crates/ed25519-hss](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss)
   - [crates/signer-platform-web](/Users/pta/Dev/rust/simple-threshold-signer/crates/signer-platform-web)
2. separate usages into:
   - public/user-facing JSON that must stay JSON
   - internal state blobs that can change format
3. prototype replacing internal state JSON blobs with one of:
   - `postcard`
   - `bincode`
   - a custom byte encoding wrapped in base64url for JS transport
4. benchmark:
   - browser wasm size
   - request payload sizes for HSS prepare/finalize
   - hot-path timing
5. keep the replacement only if it improves size materially without making the
   browser/relay seam harder to reason about

Important rule:

- do not introduce dual legacy support for both JSON and binary state blobs in
  the same path unless migration is required
- if the new encoding lands, remove the old JSON-only internal blob surface as
  part of the same refactor

### Optimization 4: Feature-Prune `ed25519-hss` And `signer-platform-web`

Current state:

- the browser HSS package now has a dedicated top-level package, but its
  dependencies may still compile more than the browser path actually needs

Potential improvement:

- add narrower feature gates in:
  - [crates/ed25519-hss](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss)
  - [crates/signer-platform-web](/Users/pta/Dev/rust/simple-threshold-signer/crates/signer-platform-web)
- compile only the browser evaluator/runtime/wire surface required by
  `hss_client_signer`

Landed partial result:

- split `signer-core` and `signer-platform-web` so browser HSS recovery uses a
  dedicated `near-ed25519-recovery` feature instead of the broader
  `near-threshold-ed25519` feature
- `hss_client_signer` now depends on:
  - `signer-platform-web/near-ed25519-recovery`
- confirmed via `cargo tree -e features` that the browser HSS package no longer
  pulls:
  - `frost-ed25519`
  - `borsh`
  through `signer-platform-web`
- production browser HSS artifact changed from:
  - wasm: `562,737` bytes
  - JS glue: `22,209` bytes
- to:
  - wasm: `561,164` bytes
  - JS glue: `22,209` bytes
- reduction:
  - wasm: `1,573` bytes, about `0.28%`

Interim decision:

- keep the feature split because it makes the browser dependency surface
  correct and narrower
- do not count this as a meaningful size optimization by itself
- the remaining worthwhile pruning work is now clearly in
  [crates/ed25519-hss](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss),
  not `signer-platform-web`

Landed `ed25519-hss` pruning result:

- gated browser-unused host surfaces out of wasm builds:
  - [crates/ed25519-hss/src/lib.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/lib.rs)
    now excludes `artifact_stub` and `fixtures` on `wasm32`
  - [crates/ed25519-hss/src/runtime/mod.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/runtime/mod.rs)
    now excludes `debug` on `wasm32`
  - deleted
    [crates/ed25519-hss/src/runtime/wasm.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/runtime/wasm.rs),
    which was an internal demo/runtime surface not used by the browser HSS
    package
  - gated fixture-driven CPU-executor benchmark helpers in
    [crates/ed25519-hss/src/runtime/prime_order_cpu_executor.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/runtime/prime_order_cpu_executor.rs)
    to host builds only
- production browser HSS package changed from:
  - wasm: `561,164` bytes
  - JS glue: `22,209` bytes
- to:
  - wasm: `472,527` bytes
  - JS glue: `21,060` bytes
- reduction:
  - wasm: `88,637` bytes, about `15.8%`
  - JS glue: `1,149` bytes, about `5.2%`

Decision:

- keep this pruning pass
- the size win is large enough to justify the cleanup
- this is now the most effective post-split bundle reduction after replacing
  internal JSON blobs

### Optimization 5: Introduce A Dedicated `hss-client.worker.ts`

Current state:

- browser HSS requests still run through
  [near-signer.worker.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/workerManager/workers/near-signer.worker.ts)
  even though the wasm package is now separate

Potential improvement:

- create a dedicated `hss-client.worker.ts`
- route HSS browser operations through it directly
- keep `near-signer.worker.ts` focused on NEAR transaction signing

This is mainly a JS-side bundle and clarity optimization.

Result:

- old HSS browser worker path used a single mixed
  `near-signer.worker.js` entry:
  - raw: `42,125` bytes
  - gzip: `8,869` bytes
  - brotli: `7,550` bytes
- new dedicated HSS worker path uses
  [hss-client.worker.js](/Users/pta/Dev/rust/simple-threshold-signer/sdk/dist/workers/hss-client.worker.js):
  - raw: `24,543` bytes
  - gzip: `6,160` bytes
  - brotli: `5,335` bytes
- reduction on the HSS hot path:
  - raw: `17,582` bytes, about `41.7%`
  - gzip: `2,709` bytes, about `30.5%`
  - brotli: `2,215` bytes, about `29.3%`
- the NEAR-only worker also became smaller after removing the HSS path:
  - [near-signer.worker.js](/Users/pta/Dev/rust/simple-threshold-signer/sdk/dist/workers/near-signer.worker.js)
    is now `30,499` bytes raw

Decision:

- keep the dedicated HSS worker split
- the HSS browser hot path now loads materially less JS
- the worker boundary is cleaner and better matches the separate HSS wasm split

### Optimization 6: Audit Dependency Defaults Aggressively

Current state:

- some dependencies in the browser wasm crates may still be pulling default
  features we do not need

Potential improvement:

- review each dependency in:
  - [wasm/hss_client_signer/Cargo.toml](/Users/pta/Dev/rust/simple-threshold-signer/wasm/hss_client_signer/Cargo.toml)
  - [wasm/near_signer/Cargo.toml](/Users/pta/Dev/rust/simple-threshold-signer/wasm/near_signer/Cargo.toml)
- prefer `default-features = false` wherever safe
- keep only the minimum browser-required features enabled

Result:

- audited the browser HSS dependency tree and tested the lowest-risk toggles:
  - `base64ct`
  - `bs58`
  - explicit `default-features = false` on the browser-side
    `signer-platform-web` dependency
- production browser HSS package did not move in a meaningful way:
  - wasm stayed effectively flat at `472,527` bytes
  - JS glue stayed flat at `18,414` bytes
- the toggles therefore did not meet the keep threshold

Decision:

- do not keep the no-op default-feature toggles
- the browser HSS crates are already fairly lean on defaults
- further size wins need deeper structural changes, not Cargo feature hygiene

## Todo List

### Phase 0

- [x] Record current browser HSS wasm and JS glue baseline
- [x] Record current registration/rebuild/export timing baseline
- [x] List the exact browser HSS exports actually used by the app

### Phase 1

- [x] Trace all current browser HSS call sites that depend on `near_signer`
- [x] Identify the minimum helper/code surface needed for a standalone HSS client package

### Phase 2

- [x] Create a dedicated browser HSS client wasm package
- [x] Expose only the minimal evaluator/browser HSS API
- [x] Keep server/garbler logic out of the new browser package

### Phase 3

- [x] Add build-script support for the new HSS client package
- [x] Add type generation support
- [x] Add dist/output placement in the SDK build

### Phase 4

- [x] Switch registration HSS flow to the new browser package
- [x] Switch rebuild/recovery HSS flow to the new browser package
- [x] Switch export flow if it uses the browser HSS evaluator package

### Phase 5

- [x] Remove obsolete browser HSS exports from the broad `near_signer` worker
- [x] Remove dead TS wrappers and loaders
- [x] Remove stale build branches and docs

### Phase 6

- [x] Benchmark browser wasm size before/after
- [x] Benchmark browser HSS first-load behavior before/after
- [x] Keep the split only if the size reduction is meaningfully large

### Optimization Backlog

- [x] Optimization 1: test explicit `wasm-opt -Oz --strip-debug --strip-dwarf`
- [x] Optimization 1: record before/after browser wasm size
- [x] Optimization 1: keep only if it materially improves size

- [x] Optimization 2: isolate export-only code currently shipped in `hss_client_signer`
- [x] Optimization 2: prototype a separate lazy export package
- [x] Optimization 2: record before/after HSS hot-path bundle size
- [x] Optimization 2: keep only if it materially improves shipped browser size

- [x] Optimization 3: inventory every `serde_json` use on the browser HSS path
- [x] Optimization 3: classify each use as public JSON vs internal state blob
- [x] Optimization 3: prototype a smaller encoding for internal-only state blobs
- [x] Optimization 3: benchmark wasm size and HSS payload-size impact
- [x] Optimization 3: remove the old JSON-only internal blob surface if the replacement lands

- [x] Optimization 4: identify feature-pruning opportunities in `ed25519-hss`
- [x] Optimization 4: identify feature-pruning opportunities in `signer-platform-web`
- [x] Optimization 4: benchmark browser wasm size after pruning
- [x] Optimization 4: keep only if the reduction is meaningful

- [x] Optimization 5: scaffold a dedicated `hss-client.worker.ts`
- [x] Optimization 5: switch browser HSS calls to that worker
- [x] Optimization 5: measure JS bundle-size impact
- [x] Optimization 5: remove dead mixed worker code if the split lands

- [x] Optimization 6: audit browser wasm dependencies for removable default features
- [x] Optimization 6: disable defaults where safe
- [x] Optimization 6: benchmark resulting wasm size
- [x] Optimization 6: keep only the flags that produce a meaningful win

# Separate HSS Client WASM Plan

Date: April 4, 2026

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

## Goal

Create a separate browser-targeted HSS client wasm package that contains only
the evaluator-side HSS functionality required by the browser.

The target package should include only:

- HSS client/evaluator entrypoints
- minimal shared encoding / error helpers
- the `ed25519-hss` client, runtime, shared, and wire surfaces needed by the
  browser

The target package must exclude:

- transaction signing handlers
- general action / delegate / NEAR transaction surfaces
- server/garbler-only HSS logic
- unrelated worker request routing and message handlers
- any legacy duplicate export surface

## Non-Goals

- do not keep parallel legacy browser HSS paths long-term
- do not fork the `ed25519-hss` protocol into separate client and server crates
- do not preserve compatibility aliases once the new package is working

## Success Criteria

We keep the separate HSS client wasm package only if all of the following hold:

1. Browser HSS client artifact size drops meaningfully.
   Initial keep threshold:
   - at least `20%` smaller than the current browser HSS artifact
   - or at least `200 KB` smaller

2. The active registration / rebuild / export flows remain correct.

3. The server HSS package remains unaffected or cleaner.

4. The SDK build and load path do not become materially more confusing.

If the artifact split adds complexity but only saves a trivial amount, revert
it and keep the current single-package approach.

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
  [tests/unit/thresholdEd25519.optionAActivePath.script.unit.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/unit/thresholdEd25519.optionAActivePath.script.unit.test.ts):
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
- Ed25519 Option A rebuild flow
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
- shipped browser HSS client artifact in `dist/esm` is now:
  - wasm:
    [sdk/dist/esm/wasm/hss_client_signer/pkg/hss_client_signer_bg.wasm](/Users/pta/Dev/rust/simple-threshold-signer/sdk/dist/esm/wasm/hss_client_signer/pkg/hss_client_signer_bg.wasm)
    = `662,319` bytes
  - JS glue:
    [sdk/dist/esm/wasm/hss_client_signer/pkg/hss_client_signer.js](/Users/pta/Dev/rust/simple-threshold-signer/sdk/dist/esm/wasm/hss_client_signer/pkg/hss_client_signer.js)
    = `22,209` bytes
- shipped browser `near_signer` artifact is now separate and HSS-free:
  - wasm:
    [sdk/dist/esm/wasm/near_signer/pkg/wasm_signer_worker_bg.wasm](/Users/pta/Dev/rust/simple-threshold-signer/sdk/dist/esm/wasm/near_signer/pkg/wasm_signer_worker_bg.wasm)
    = `657,714` bytes
  - JS glue:
    [sdk/dist/esm/wasm/near_signer/pkg/wasm_signer_worker.js](/Users/pta/Dev/rust/simple-threshold-signer/sdk/dist/esm/wasm/near_signer/pkg/wasm_signer_worker.js)
    = `146,416` bytes
- compared to the old broad browser HSS artifact, the dedicated browser HSS
  package reduces:
  - wasm by `501,157` bytes, about `43.1%`
  - JS glue by `150,795` bytes, about `87.2%`
- release init/load proxy benchmark using the same web-target wasm modules in
  Node showed first-load improvement for the dedicated package:
  - old broad browser HSS artifact: `11.542ms` mean across 5 samples
  - dedicated `hss_client_signer`: `9.344ms` mean across 5 samples
  - improvement: about `19.0%`
- these results clear the keep threshold, so the split should be kept

## Verification Requirements

At minimum, each meaningful phase should re-run:

- `cargo test` for `crates/ed25519-hss`
- `cargo test` for the new HSS client wasm package
- `cargo test` for `wasm/near_signer`
- `npx tsc --noEmit -p sdk/tsconfig.build.json`

And after the switch:

- registration flow smoke test
- Option A rebuild flow smoke test
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

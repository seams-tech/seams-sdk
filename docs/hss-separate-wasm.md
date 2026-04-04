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

Current browser client-only HSS wasm artifact:

- `1,163,940` bytes

Current relay/server HSS wasm artifact:

- `1,152,055` bytes

The current export split is already worth keeping, but it is not enough.

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

Expected active browser HSS surface:

- `threshold_ed25519_hss_prepare_session`
- `threshold_ed25519_hss_prepare_client_request`
- `threshold_ed25519_hss_evaluate_result`
- `threshold_ed25519_hss_open_client_output`
- `threshold_ed25519_hss_open_seed_output`
- `threshold_ed25519_hss_public_key_from_base_shares`

Also identify all imports in the client code that currently pull in the broader
`near_signer` worker for HSS-only use.

### Phase 2: Create A Dedicated HSS Client WASM Package

Create a new wasm package dedicated to the browser HSS client path.

Initial implementation rules:

- reuse existing HSS logic from `ed25519-hss`
- copy only the minimum helper code needed from `near_signer`
- do not carry over generic multi-purpose worker routing
- do not keep dead duplicate helper modules if they become unused in
  `near_signer`

The package should expose a narrow API and compile independently.

### Phase 3: Wire The SDK Build

Update the SDK build so it emits the new HSS client artifact.

Required updates:

- build script support
- type generation support
- worker bundling or loader support
- artifact copy / output placement in `dist`

At this stage, the old browser HSS path can still exist temporarily, but only
as a short migration bridge.

### Phase 4: Switch The Browser HSS Flow To The New Package

Move the active browser HSS flow to the new client package.

This includes:

- registration HSS flow
- Ed25519 Option A rebuild flow
- export flow if it uses the same browser HSS evaluator path

After the new path is working:

- remove the old browser HSS dependency on the broad `near_signer` worker
- delete dead loader code and duplicate wrapper code immediately

### Phase 5: Remove Dead Mixed Surface

Once the browser no longer uses the broad `near_signer` worker for HSS:

- remove old HSS browser exports from the broad worker if no longer needed
- remove stale TypeScript wrappers
- remove stale build-script branches
- remove obsolete docs describing the old browser HSS packaging model

This phase should leave one clear browser HSS wasm path, not two.

### Phase 6: Benchmark And Decide

Measure:

- browser HSS wasm size
- browser HSS JS glue size
- registration timing
- first-load timing for the HSS path

Keep the split only if the size win is meaningful and behavior remains clean.

If the split saves little, revert it instead of carrying extra package/build
complexity.

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

- [ ] Record current browser HSS wasm and JS glue baseline
- [ ] Record current registration/rebuild/export timing baseline
- [ ] List the exact browser HSS exports actually used by the app

### Phase 1

- [ ] Trace all current browser HSS call sites that depend on `near_signer`
- [ ] Identify the minimum helper/code surface needed for a standalone HSS client package

### Phase 2

- [ ] Create a dedicated browser HSS client wasm package
- [ ] Expose only the minimal evaluator/browser HSS API
- [ ] Keep server/garbler logic out of the new browser package

### Phase 3

- [ ] Add build-script support for the new HSS client package
- [ ] Add type generation support
- [ ] Add dist/output placement in the SDK build

### Phase 4

- [ ] Switch registration HSS flow to the new browser package
- [ ] Switch rebuild/recovery HSS flow to the new browser package
- [ ] Switch export flow if it uses the browser HSS evaluator package

### Phase 5

- [ ] Remove obsolete browser HSS exports from the broad `near_signer` worker
- [ ] Remove dead TS wrappers and loaders
- [ ] Remove stale build branches and docs

### Phase 6

- [ ] Benchmark browser wasm size before/after
- [ ] Benchmark browser HSS first-load behavior before/after
- [ ] Keep the split only if the size reduction is meaningfully large

# Optimization v4 Audit Log

Date created: April 7, 2026

This note is a backward-looking audit log for the accepted optimization work
that survived the current `ed25519-hss` refactors.

It is intentionally narrower than
[optimization.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/optimization.md):

- `optimization.md` is the current optimization entrypoint
- this file is the historical record of what we kept, why we kept it, and what
  correctness/security questions each change should keep raising in review

## Scope

This log covers the accepted optimizations from:

- the kept v3 kernel/package work
- the Cloudflare-first Worker-path optimization work in Refactor 5

It does not try to preserve every attempted idea. Rejected or reverted ideas
belong in
[optimization-v3.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/docs/plans/optimization-v3.md)
or in the Refactor 5 notes.

## Keep Criteria

An optimization is only listed here if it met all of the following:

- improved the real production path, not only a benchmark-only helper path
- did not reopen the joined-input boundary
- did not add a duplicate legacy implementation path
- did not widen evaluator-visible or client-visible secret material
- stayed compatible with the current staged server-owned execution model

## Baseline And Current Outcome

Useful reference points:

- raw crate hidden-eval benchmark:
  about `305.66ms` mean
- early local Worker-compatible registration `/respond` baseline:
  about `2853ms`
- earlier forced-wasm-only registration `/respond` baseline:
  about `5715ms`
- current forced-wasm-only registration `/respond`:
  about `886ms`
- current native-enabled optional registration `/respond`:
  about `720ms`

So the accepted Worker-path work recovered roughly:

- `5715ms -> 886ms` on forced-wasm `/respond`
- `2853ms -> 720ms` on the optional native path

Fresh local reruns of the same focused registration route:

- Cloudflare-compatible wasm-only:
  - `/prepare`: `400ms`
  - `/respond`: `954ms`
  - `/finalize`: `39ms`
- native-enabled optional path:
  - `/prepare`: `409ms`
  - `/respond`: `438ms`
  - `/finalize`: `303ms`

Before/after route-shape reductions that survived review:

- `/finalize` request:
  `154587` bytes -> `102` bytes
- `/respond` response:
  `268793` bytes -> `11` bytes
- registration `/finalize` response:
  `570041` bytes -> `92` bytes
- `/prepare` response:
  `24279` bytes -> `22919` bytes
- `/respond` request:
  `47909` bytes -> `45189` bytes

That leaves the remaining Cloudflare-compatible wasm overhead concentrated in
real ceremony execution, especially `round_core`, rather than in obvious route
transport waste.

One remaining measurement caveat:

- the coarse wasm route breakdown is trustworthy and shows the remaining
  forced-wasm `/respond` time sits in `ceremonyCoreMs`
- the executor's inner stage profiler now uses a Worker-compatible wasm timer
  source, so the live forced-wasm `/respond` breakdown is measurable:
  - registration:
    - `add_stage` about `7.40ms`
    - `message_schedule` about `113.97ms`
    - `round_core` about `433.15ms`
    - `output_projector` about `203.62ms`
  - sign/self-heal:
    - `add_stage` about `7.03ms`
    - `message_schedule` about `111.71ms`
    - `round_core` about `445.32ms`
    - `output_projector` about `205.37ms`
- that confirms `round_core` is the dominant inner ceremony stage on the live
  wasm path too

## Accepted Optimizations

### 1. Dedicated Browser HSS Wasm Package

What changed:

- the browser HSS path uses a dedicated HSS signer wasm package instead of a
  broader mixed runtime bundle

Why it stayed:

- it reduced browser bundle weight and improved isolation of the HSS-specific
  path

Observed benefit:

- stable browser HSS artifacts without regressions in the hardened staged path

Audit watchpoints:

- make sure browser-specific packaging does not drift from the server wasm path
- keep generated worker types aligned across the dedicated package boundary

### 2. Split/Local Arithmetic Hot Path

What changed:

- the kept kernel path uses split/local arithmetic execution through the
  production hidden-eval path

Why it stayed:

- this was one of the durable sources of the v3 kernel wins

Observed benefit:

- native total hidden eval recovered into the old fast band without reopening
  the unsafe joined-value shortcut

Audit watchpoints:

- any future shortcut that reconstructs joined arithmetic words should be
  treated as suspect by default
- constant-time review still matters for low-level arithmetic helpers

### 3. Kernel-Local SHA-512 Boolean-Lane Rewrites

What changed:

- the boolean-heavy `round_core` work moved below generic helper composition
- kernel-local storage and fused transforms were introduced for the SHA-512
  lane

Why it stayed:

- helper-level cleanup alone was not enough; this was part of the real durable
  kernel win

Observed benefit:

- v3 recovered from the early hardened regression while preserving the secure
  staged boundary

Audit watchpoints:

- keep the optimized boolean-lane path the only production path
- do not reintroduce duplicate helper-era kernels “for fallback”

### 4. OT/Open/Join Cleanup Without Boundary Widening

What changed:

- garbler-side OT/open/join overhead was reduced without widening
  evaluator-visible state

Why it stayed:

- it improved the real hot path after the kernel shape was already under
  control

Observed benefit:

- part of the stable browser/native latency recovery in the kept path

Audit watchpoints:

- verify no cleanup here causes hidden server material to leak into evaluator
  state or wire messages

### 5. Route-Level HSS Instrumentation

What changed:

- `/prepare`, `/respond`, and `/finalize` now log:
  - request/response bytes
  - payload contributors
  - parse time
  - wasm ceremony timing breakdown

Why it stayed:

- this is what made the Worker-path overhead measurable instead of guessed

Observed benefit:

- let us separate transport waste from true wasm/runtime cost
- made the later `/respond` wins explainable and auditable

Audit watchpoints:

- keep logs scoped to sizes/timings only
- do not log raw secret material or full opaque state blobs

### 6. Remove Client-Visible Server-Owned Artifact Round-Trips

What changed:

- `/respond` no longer returns the staged evaluator artifact to the client
- `/finalize` no longer expects the client to post that artifact back
- the artifact stays server-side on the ceremony handle

Why it stayed:

- it removed large pure transport waste without changing the staged boundary

Observed benefit:

- `/finalize` request:
  about `154587 -> 102` bytes
- `/respond` response:
  about `268793 -> 11` bytes

Audit watchpoints:

- ceremony handles become the authority for retained artifact state
- state lifetime, cleanup, and scope validation must remain correct

### 7. Remove Client-Visible `serverAssistInit` Echo

What changed:

- `/respond` no longer returns `serverAssistInit` to the client

Why it stayed:

- the client did not need it after the server-owned staged artifact path became
  canonical

Observed benefit:

- part of the `268793 -> 11` byte `/respond` response collapse

Audit watchpoints:

- make sure any remaining validator path does not still assume that echo exists

### 8. Minimal Registration Finalize Response

What changed:

- registration `/finalize` no longer returns the full finalized report
- it returns only the registration material the client actually consumes

Why it stayed:

- registration was paying for server-owned data it did not use

Observed benefit:

- registration `/finalize` response:
  about `570041 -> 92` bytes

Audit watchpoints:

- keep registration output semantics minimal and explicit
- do not accidentally couple registration finalize to export-capable output

### 9. Export-Only Seed Output On Session Finalize

What changed:

- normal session `/finalize` no longer includes `seedOutputMessageB64u`
- explicit export is the only flow that requests seed-capable output

Why it stayed:

- it reduced unnecessary response weight and made the export exception explicit

Observed benefit:

- session finalize now defaults to client output only

Audit watchpoints:

- preserve the explicit `ExplicitKeyExport` exception as the only seed-capable
  client-visible flow

### 10. Remove Redundant Envelope Binding Fields

What changed:

- `/respond` stopped carrying redundant `clientRequest.contextBindingB64u`
- `/prepare` stopped echoing duplicate public context inside `preparedSession`
- the wasm client-request result also stopped carrying its unused
  `contextBindingB64u`

Why it stayed:

- these were low-risk, real duplications in the live route and worker seam

Observed benefit:

- small but honest payload reductions
- simpler route/state shapes

Audit watchpoints:

- binding validation must continue to use the canonical prepared-session
  binding
- do not remove binding material that is still actually checked

### 11. Compact Retained Ceremony State

What changed:

- stored ceremony state dropped duplicate:
  - `contextBindingB64u` in retained server inputs
  - `contextBindingB64u` in stored prepared-server session
  - `clientOtOfferMessageB64u` in stored prepared-server session
  - `contextBindingB64u` in stored staged evaluator artifact

Why it stayed:

- these were true same-process retained-state duplicates

Observed benefit:

- smaller ceremony records
- less in-memory retained-state noise

Audit watchpoints:

- keep the retained-state story explicit:
  - no raw relayer roots after add-stage
  - `projector_inputs` remains the accepted retained-state exception

### 12. OT Bundle/State Compaction

What changed:

- OT selection bundles now serialize `width_bits` once per bundle instead of
  once per OT word
- OT receiver-state bundles now serialize `width_bits` once per bundle instead
  of once per OT word
- `ClientOtOffer` serializes fixed owner/purpose metadata once at the outer
  level instead of repeating it per nested OT offer word

Why it stayed:

- crate-side measurement showed OT vectors were the real dominant payloads

Observed benefit:

- `/prepare` response:
  about `24279 -> 22919` bytes
- `/respond` request:
  about `47909 -> 45189` bytes

Audit watchpoints:

- keep serde/bincode compatibility aligned across:
  - crate
  - browser wasm
  - server wasm
  - optional native driver
- any shared encoding change must keep the native-driver freshness guard honest

### 13. Direct Artifact Build From Retained Add-Stage State

What changed:

- server ceremony artifact construction no longer simulates all later staged
  `message_schedule`, `round_core`, and `output_projection` request/response
  steps just to produce the server-owned staged evaluator artifact
- instead, it builds final output bundles directly from retained staged
  material derived after add-stage

Why it stayed:

- this removed the largest remaining pure integration overhead in the wasm
  `/respond` path

Observed benefit:

- forced-wasm registration `/respond`:
  about `5715 -> 1304` ms before the next follow-up cut

Audit watchpoints:

- the direct helper must stay semantically equivalent to the staged path
- any future change here should be reviewed as a correctness-sensitive
  optimization, not a harmless refactor

### 14. Raw-Bytes Internal Staged Artifact Handoff

What changed:

- inside the same-process server/wasm path, the staged evaluator artifact now
  stays as raw bytes in memory
- the hot path no longer base64-encodes that artifact on `/respond` and
  base64-decodes it again on `/finalize`

Why it stayed:

- the artifact no longer crosses the client HTTP seam, so keeping it base64 in
  memory was pure overhead

Observed benefit:

- forced-wasm registration `/respond`:
  about `1304 -> 1240` ms

Audit watchpoints:

- this is an internal same-process optimization only
- do not accidentally let the raw byte shape leak into public client HTTP APIs

### 15. Native Driver Freshness Guard

What changed:

- the optional native driver now rebuilds when the crate sources or shared
  wasm-side state producers are newer than the cached binary

Why it stayed:

- shared encoding changes made stale native binaries a correctness risk

Observed benefit:

- prevents false decode failures when the optional native path is enabled

Audit watchpoints:

- treat this as a correctness guard first, not a performance feature
- make sure stale-driver rebuild checks cover every shared state producer

### 16. Wasm `/respond` Hotspot Summary Logging

What changed:

- the service now summarizes wasm `/respond` timing into:
  - `totalMeasuredMs`
  - `materializationMs`
  - `dominantBucket`
  - `dominantBucketMs`
- both the registration-path and sign-path relayer keep-gates now assert that
  summary exists

Why it stayed:

- the remaining optimization problem is now "which measured wasm bucket is
  still dominating?" more than "is the route envelope still bloated?"

Observed benefit:

- the next pass can target the dominant measured wasm bucket directly instead
  of guessing between:
  - decode work
  - runtime/session materialization
  - ceremony core
  - artifact encode

Audit watchpoints:

- keep the summary derived only from existing timing buckets
- do not log secret-bearing payload contents while adding hotspot visibility

### 17. Same-Isolate Prepared-Session Reuse

What changed:

- the server wasm path now caches the fully prepared `PreparedSession` across
  `/prepare -> /respond -> /finalize`
- wasm `/respond` reuses the cached runtime/evaluator/garbler sessions instead
  of re-materializing them from driver-state bytes
- wasm `/finalize` and server-output opening reuse the same cached prepared
  session when available
- a missing cache entry falls back to the retained byte-state path instead of
  failing the ceremony

Why it stayed:

- it attacks a real wasm-only hotspot without changing the staged boundary or
  making the native path mandatory

Observed benefit:

- forced-wasm registration `/respond`:
  about `1240ms -> 1024ms`
- forced-wasm registration `/finalize`:
  about `512ms -> 46ms`

Audit watchpoints:

- the cache must stay scoped to the same-process wasm isolate only
- ceremony cleanup must release cached prepared sessions on expiry and finalize
- correctness must not depend on cache hits; retained-byte fallback must remain
  valid

### 18. Cache-Hit Hidden-Eval Constant-Pool Reuse

What changed:

- the cache-hit wasm `/respond` path now reuses the prepared session's cached
  hidden-eval constant pool instead of rebuilding it during ceremony assembly
- the cache-hit path uses the existing prepared-session cache and the
  pool-aware artifact builder directly

Why it stayed:

- it removes repeated ceremony-core setup without changing the staged boundary
- it does not introduce a new cache class; it only uses data already retained
  inside `PreparedSession`

Observed benefit:

- forced-wasm registration `/respond`:
  about `1024ms -> 935ms`

Audit watchpoints:

- keep the pool reuse scoped to cache-hit same-isolate execution only
- fallback byte-state execution must remain correct when the prepared-session
  cache is unavailable
- the optimization must not change any staged digest, output, or finalize
  semantics

### 19. Same-Isolate Staged-Artifact Handle Reuse

What changed:

- the same-process wasm path now retains the staged evaluator artifact by
  handle instead of serializing it into bytes between `/respond` and
  `/finalize`
- `/finalize` consumes that cached staged artifact directly when available
- ceremony cleanup now releases staged-artifact cache entries alongside the
  prepared-session cache

Why it stayed:

- it removes same-isolate artifact encode/decode work without changing the
  staged boundary or making the native path mandatory

Observed benefit:

- forced-wasm registration `/respond`:
  about `935ms -> 923ms`
- forced-wasm registration `/finalize`:
  about `45ms -> 34ms`

Audit watchpoints:

- the stored ceremony record must keep only the artifact handle or artifact
  bytes, never reintroduce duplicate `contextBindingB64u`
- finalize must not release the prepared-session or artifact caches before the
  finalization step actually runs
- cleanup on expiry and explicit ceremony deletion must release both caches

### 20. Direct Same-Process Ceremony-Core Run

What changed:

- the modern artifact-only `/respond` path no longer routes through add-stage
  materialization plus projector replay just to recover final output bundles
- instead, it reconstructs the client bundles from the trusted OT material and
  executes the same-process hidden eval directly from the full client/server
  input bundles, then builds the staged evaluator artifact from that run

Why it stayed:

- measured forced-wasm `/respond` breakdown showed `ceremonyCoreMs` dominating
  both registration and sign flows, while decode and materialization had
  already dropped to effectively zero
- this directly attacks that dominant bucket without changing the staged
  boundary or the external HTTP shape

Observed benefit:

- forced-wasm registration `/respond`:
  about `923ms -> 886ms`
- forced-wasm registration `/finalize`:
  about `34ms -> 32ms`

Audit watchpoints:

- the direct run must produce the same client/server input commitments as the
  staged path
- artifact generation must still bind to the same output bundles and finalize
  semantics as before
- the optimization must not reintroduce client-visible server secret material
  or duplicate retained state

### 21. Pair-Wise Round-Core Boolean XOR Construction

What changed:

- the `round_core` sigma helpers and the `y ^ z` precompute used by `ch`
  now build left/right local words as one pair instead of constructing the two
  sides independently
- this keeps the same Boolean function, but avoids duplicating provenance and
  commitment derivation work across the two shares

Why it stayed:

- live forced-wasm measurements already showed `round_core` as the dominant
  inner ceremony stage
- the previous route-level cuts had already removed transport and
  materialization waste, so this was the next honest kernel target

Observed benefit:

- registration breakdown:
  - `ceremonyCoreMs`: about `850ms -> 841ms`
  - `ceremonyRoundCoreMs`: about `433.15ms -> 416.22ms`
- sign/self-heal breakdown:
  - `ceremonyCoreMs`: about `859ms -> 846ms`
  - `ceremonyRoundCoreMs`: about `445.32ms -> 430.90ms`
- forced-wasm registration `/respond` stayed roughly flat at about `886-907ms`
  in local route totals, so the benefit is best treated as an inner-kernel win
  rather than a new top-line latency jump

Audit watchpoints:

- the pair-wise helper must keep left/right provenance aligned; mismatched
  split-local provenance should still fail instead of being silently merged
- this must remain a same-math refactor only; it must not change staged
  digests, output bundles, or finalize semantics
- future boolean-kernel fusion should reuse this pair-wise shape instead of
  reviving duplicated side-by-side XOR construction

## Accepted But Explicitly Optional

These changes are accepted, but only as optional deployment-mode support:

- native Rust driver retained for VM/container deployments

This is acceptable because:

- the Cloudflare-compatible wasm path remains the primary deployment target
- the native path is optional, not required for correctness

Audit watchpoints:

- the native path must never become the only practical path
- encoding/state changes must continue to keep wasm and native behavior aligned

## Security And Correctness Review Checklist

When auditing an accepted optimization from this file, check:

1. Did it remove only duplication, or did it also remove a real validation
   input?
2. Did it keep secret-bearing material server-owned in non-export flows?
3. Did it preserve the staged execution semantics, or replace them with a
   shortcut that only “looks equivalent”?
4. Did it change a shared encoded state shape across crate/browser/server/native
   boundaries?
5. Did it introduce a new same-process retained-state blob that now needs scope,
   TTL, or cleanup review?
6. Did it improve the real route path, not just a synthetic benchmark?

## Current Conclusion

The accepted optimization story so far is:

- v3 recovered the kernel path without reviving unsafe joined execution
- Refactor 5 removed large amounts of Worker-path integration waste
- the largest Worker-path win came from eliminating internal staged replay
  during artifact construction
- the remaining local wasm-vs-native gap is now roughly `300ms`, which looks
  like real wasm/runtime overhead rather than obvious transport waste

That means future optimization work should be judged against this standard:

- keep only changes that improve the real Cloudflare-compatible wasm path
- keep the staged boundary intact
- treat every “fast” shortcut as suspicious until its security and semantic
  equivalence are clear

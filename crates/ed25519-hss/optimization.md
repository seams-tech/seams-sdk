# Optimization Notes

This file is the optimization-focused entrypoint for
[crates/ed25519-hss](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss).
Historical optimization plans live in
[docs/plans/optimization-v3.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/docs/plans/optimization-v3.md)
and
[docs/plans/optimization-v4.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/docs/plans/optimization-v4.md).

## Current Hot Path

The dominant runtime cost is still the hidden-eval executor, especially:

- `message_schedule`
- `round_core`
- `output_projection`

The most expensive stage remains `round_core`.

Latest local benchmark snapshot, generated on 2026-05-20 15:44:37 JST on
macOS/aarch64:

- hidden eval prepare:
  `112.91ms`
- hidden eval direct executor:
  `224.24ms` mean, `224.71ms` median, `225.83ms` p95
- hidden eval same-process delivery path:
  `264.20ms` mean, `264.24ms` median, `267.41ms` p95
- stage means:
  - input sharing:
    `2.00ms`
  - add stage:
    `2.87ms`
  - message schedule:
    `40.35ms`
  - round core:
    `134.89ms`
  - output projector:
    `42.95ms`
  - direct executor unbucketed:
    `1.19ms`
- delivery-path means:
  - OT open/join:
    `21.98ms`
  - server input open:
    `3.26ms`
  - output sealing finalization:
    `0.40ms`
  - delivery unbucketed:
    `14.31ms`
- CPU executor:
  `2.042ms` mean, `2.021ms` median, `2.145ms` p95

The native DDH report now separates direct hidden-eval executor timings from
same-process delivery timings. Use `stage_timings.total_hidden_eval` for
low-level executor optimization and `delivery_timings.delivery_total` for the
debug delivery-path envelope.

Latest native hidden-eval optimization slice:

- majority/choose batch helpers now stream generated local bit pairs directly
  into the reusable round scratch buffers instead of allocating intermediate
  left/right vectors
- hot label construction now reuses `String` buffers in the round-core boolean
  operations and raw batch gates while preserving the existing label domains
- compared with the previous output-projector baseline, direct hidden eval
  improved from `232.62ms` to `224.24ms` (`-8.37ms`, `-3.60%`)
- same-process delivery improved from `272.22ms` to `264.20ms` (`-8.02ms`,
  `-2.95%`)
- `message_schedule` improved from `43.46ms` to `40.35ms` (`-7.14%`), and
  `round_core` improved from `139.32ms` to `134.89ms` (`-3.18%`)

## Current Worker-Path Baseline

The crate benchmark is not the live route cost model.

Latest local Node Worker-compatible HSS route snapshot from the focused
registration flow:

- `/prepare`:
  about `372ms`
- `/respond`:
  about `886ms`
- `/finalize`:
  about `32ms`

Observed request sizes in that same flow:

- `/prepare` request:
  about `253` bytes
- `/respond` request:
  about `45189` bytes
- `/finalize` request:
  about `102` bytes

Largest currently observed request payload contributor:

- `/respond` `clientRequest` envelope:
  about `45070` bytes

## Before / After Summary

Focused local registration HSS route, same machine:

- early local Worker-compatible baseline:
  - `/prepare`: about `387ms`
  - `/respond`: about `2853ms`
  - `/finalize`: about `515ms`
- earlier forced-wasm-only baseline:
  - `/prepare`: about `385ms`
  - `/respond`: about `5715ms`
  - `/finalize`: about `494ms`
- current Cloudflare-compatible wasm-only rerun:
  - `/prepare`: `400ms`
  - `/respond`: `954ms`
  - `/finalize`: `39ms`
- current native-enabled optional rerun:
  - `/prepare`: `409ms`
  - `/respond`: `438ms`
  - `/finalize`: `303ms`

Largest route-shape gains:

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

Current interpretation:

- the major gains came from removing ceremony transport waste, duplicate
  materialization, and repeated same-process base64/state churn
- the remaining Cloudflare-compatible wasm gap is mostly real ceremony compute,
  not route-envelope waste
- the native optional path is still faster on `/respond`, but the wasm path is
  now in the same sub-second band locally instead of the earlier multi-second
  band

Current interpretation:

- `/respond` is still the main latency hotspot
- `/finalize` is no longer a meaningful transport hotspot in the normal
  registration path
- the current remaining work is primarily same-process wasm decode and ceremony
  core cost, not outer-route payload churn
- the wasm-only `/respond` path now logs executor stage buckets too, but the
  current nanosecond-stage profiler is effectively zeroed under wasm, so those
  inner stage values are not yet usable for hotspot ranking
- the coarse wasm route breakdown is still useful and currently shows the
  remaining `/respond` cost is concentrated in `ceremonyCoreMs`, not decode or
  materialization
- the inner ceremony-stage breakdown is now trustworthy on the wasm Worker
  path too:
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
- so the next real optimization target is no longer guessed from native-only
  benchmarks; on the live wasm path it is clearly `round_core`

Latest Phase 2 transport reduction:

- `/finalize` request no longer round-trips the staged evaluator artifact
- `/respond` no longer returns the staged evaluator artifact to the client
- `/respond` no longer returns `serverAssistInit`
- registration `/finalize` no longer returns a full `finalizedReport`
- session `/finalize` now includes `seedOutputMessageB64u` only when the caller
  explicitly requests export-capable output
- `/respond` requests no longer carry a redundant
  `clientRequest.contextBindingB64u` field
- `/prepare` responses no longer echo duplicate public context inside
  `preparedSession`
- the server now keeps that artifact inside ceremony state until `/finalize`

Observed local Node Worker-compatible after that slice:

- registration `/prepare`:
  `362ms`
- registration `/respond`:
  `2735ms`
- registration `/finalize`:
  `497ms`
- session `/prepare`:
  `373ms`
- session `/respond`:
  `2740ms`
- session `/finalize`:
  `500ms`
- `/finalize` request:
  `154587` bytes -> `102` bytes
- `/respond` response:
  `268793` bytes -> `11` bytes
- registration `/finalize` response:
  `570041` bytes -> `92` bytes
- session `/respond` request:
  `47905` bytes -> `47838` bytes
- registration `/respond` request:
  `47976` bytes -> `47909` bytes
- session `/prepare` response:
  `24448` bytes -> `24279` bytes
- registration `/prepare` response:
  `24448` bytes -> `24279` bytes
- session `/finalize` response:
  `39397` bytes
- session `/finalize` `seedOutputMessageB64u`:
  `0` bytes by default

Largest remaining payloads after that slice:

- session `/finalize` response:
  `clientOutputMessageB64u` at about `39280` bytes
- `/prepare` response:
  `clientOtOfferMessageB64u` at about `23535` bytes and
  `preparedSession.evaluatorDriverStateB64u` at about `664` bytes
  - decoded payload sizes:
    - `clientOtOfferMessage`: about `17651` bytes
    - `evaluatorDriverState`: about `498` bytes
  - base64url transport overhead:
    - `clientOtOfferMessage`: about `5884` bytes
    - `evaluatorDriverState`: about `166` bytes
- `/respond` request:
  `clientRequest` at about `47790` bytes
  - `clientRequestMessageB64u` at about `23535` bytes
  - `evaluatorOtStateB64u` at about `24198` bytes
  - decoded payload sizes:
    - `clientRequestMessage`: about `17651` bytes
    - `evaluatorOtState`: about `18148` bytes
  - base64url transport overhead:
    - `clientRequestMessage`: about `5884` bytes
    - `evaluatorOtState`: about `6050` bytes

Updated interpretation:

- the staged evaluator artifact echo and `serverAssistInit` echo were real
  waste and are now gone
- registration no longer pays for a `finalizedReport` it does not consume
- normal session finalize no longer has to carry seed-capable material by
  default
- the remaining `/respond` request size is now dominated by the real OT/client
  request payload, not extra envelope binding fields
- `/prepare` still carries a large OT offer plus evaluator driver state, but it
  no longer echoes duplicate public scope fields
- on the server side, stored ceremony state was also tightened by dropping the
  duplicate `contextBindingB64u` from retained server inputs
- the real service path now logs the main remaining contributors explicitly:
  - `/prepare`: `evaluatorDriverStateBytes`, `clientOtOfferMessageBytes`
  - `/respond`: `clientRequestMessageBytes`, `evaluatorOtStateBytes`
- retained ceremony state is also smaller than before:
  - stored server inputs no longer keep duplicate `contextBindingB64u`
  - stored prepared-server session no longer keeps duplicate `contextBindingB64u`
  - stored prepared-server session no longer keeps a second copy of
    `clientOtOfferMessageB64u`
  - stored staged evaluator artifact no longer keeps duplicate
    `contextBindingB64u`
- the remaining major cost is now in the live transport payloads themselves,
  not redundant retained-state copies
- the service path now also logs decoded payload-byte counts for the dominant
  base64url fields, so the next decision can be based on actual base64 overhead
  rather than guesswork
- that overhead is meaningful in bytes but still secondary to route compute
  cost, so the next optimization pass should target deeper wasm/state
  compaction before redesigning the HTTP seam
- the first wasm-side cleanup in that direction is landed:
  - the client-request wasm result no longer carries an unused
    `contextBindingB64u` field
- a crate-side size regression now confirms the bigger structural point:
  - `ClientPacket` is dominated by the serialized OT selection-word vectors
  - `ClientOtState` is dominated by the serialized OT receiver-state word
    vectors
- so the next real size win has to come from compacting those OT bundle/state
  encodings, not from shaving a few more wrapper fields
- the first OT bundle compaction slice is now landed:
  - OT selection bundles serialize `width_bits` once per bundle instead of
    once per OT word
  - OT receiver-state bundles serialize `width_bits` once per bundle instead
    of once per OT word
  - `ClientOtOffer` now serializes its fixed owner and purpose metadata once
    at the outer bundle level instead of repeating them inside each nested OT
    offer word
  - in the focused registration Worker path, `/prepare` response size dropped
    from about `24279` bytes to about `22919` bytes
  - in the focused registration Worker path, `/respond` request size dropped
    from about `47909` bytes to about `45189` bytes
  - that is a reduction of about `1360` bytes on `/prepare` and about
    `2720` bytes on `/respond` without changing the staged security boundary
- a follow-up wrapper-level compaction pass for `ClientPacket` and
  `ClientOtState` was tried and rejected:
  - it saved only about `69` bytes on `/prepare` and about `139` bytes on
    `/respond`
  - the code was reverted so the crate keeps the simpler derived
    packet/state encoding
- this also exposed an optional native-driver maintenance issue:
  - the native Rust driver binary can go stale relative to the wasm path when
    the shared bincode state encoding changes
  - the native-driver loader now rebuilds the driver when either the crate
    sources or the shared wasm-side state producers are newer than the cached
    binary
- the next meaningful Worker-path wins will come from reducing the remaining
  `/prepare` and `/respond` message sizes and shrinking the state behind them
- a Cloudflare coordination review was also completed:
  - the current HSS ceremony owner is already a simple in-memory handle map in
    [server/src/core/ThresholdService/ThresholdSigningService.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/ThresholdService/ThresholdSigningService.ts)
  - Durable Object affinity was rejected for now because it would add routing
    complexity without attacking the dominant wasm `/respond` compute cost
  - KV remains inappropriate for hot ceremony state and should stay limited to
    low-frequency metadata if used at all
- a direct local native-vs-wasm comparison is now also recorded:
  - optional native-driver path:
    - `/prepare`: about `373ms`
    - `/respond`: about `720ms`
    - `/finalize`: about `509ms`
  - wasm-only Worker-compatible path with
    `THRESHOLD_ED25519_HSS_DISABLE_NATIVE_DRIVER=1`:
    - `/prepare`: about `394ms`
    - `/respond`: about `1024ms`
    - `/finalize`: about `46ms`
  - the first major wasm-path win was removing internal replay of all later
    staged request/response hops when building the server-owned staged
    evaluator artifact
  - the follow-up win was keeping that staged evaluator artifact as raw bytes
    inside the same-process server/wasm path instead of base64-wrapping it
  - a later retained-state cut also keeps prepared server state and relayer
    inputs as raw bytes in memory across the same-process server/wasm bridge
    instead of re-decoding server-owned base64 at ceremony time
  - the latest kept wasm-only win is same-isolate prepared-session reuse:
    - `/prepare` caches the fully prepared `PreparedSession` inside the server
      wasm isolate
    - `/respond` reuses the cached runtime, evaluator session, and garbler
      session instead of re-materializing them from driver-state bytes
    - `/finalize` and server-output opening reuse the same cached prepared
      session when it is still present
    - cache misses fall back to the retained byte-state path instead of
      failing the ceremony
  - the follow-up same-process bridge cleanup now passes the live
    `clientRequestMessage` and `evaluatorOtState` into wasm as raw bytes
    instead of base64 strings
  - the latest cache-hit wasm `/respond` win reuses the prepared session's
    hidden-eval constant pool instead of rebuilding it per request:
    - forced-wasm registration `/respond` improved further from about
      `1024ms -> 935ms`
    - the remaining local wasm-only gap vs the optional native path is now
      only a few hundred milliseconds, not the earlier multi-second spread
  - the latest same-isolate artifact win keeps the staged evaluator artifact in
    the wasm isolate by handle instead of serializing it back into bytes for
    `/finalize`:
    - forced-wasm registration `/respond` improved modestly again from about
      `935ms -> 923ms`
    - forced-wasm registration `/finalize` improved from about `45ms -> 34ms`
    - ceremony cleanup now releases both prepared-session and staged-artifact
      cache entries after finalize or expiry
  - the next kept ceremony-core win replaces the staged-projector replay inside
    the modern artifact-only `/respond` path with a direct same-process hidden
    eval run from reconstructed client/server input bundles:
    - forced-wasm registration `/respond` improved again from about
      `923ms -> 886ms`
    - forced-wasm registration `/finalize` improved slightly from about
      `34ms -> 32ms`
    - measured forced-wasm `/respond` breakdown before that cut showed
      `ceremonyCoreMs` dominating both registration and sign flows at about
      `963-978ms`, with decode and materialization effectively at zero
    - this keeps the same-process seam cleaner
    - the measured top-line effect was small, so it should be treated as a
      supporting cleanup, not the main latency win
  - the next kept kernel cut switched the `round_core` sigma and `y ^ z`
    boolean-XOR paths to pair-wise left/right word construction instead of
    building both sides independently:
    - registration breakdown improved from about:
      - `ceremonyCoreMs`: `850ms -> 841ms`
      - `ceremonyRoundCoreMs`: `433.15ms -> 416.22ms`
    - sign/self-heal breakdown improved from about:
      - `ceremonyCoreMs`: `859ms -> 846ms`
      - `ceremonyRoundCoreMs`: `445.32ms -> 430.90ms`
    - forced-wasm registration `/respond` stayed roughly flat at about
      `886-907ms`, so this should be treated as a real inner-kernel win with a
      small noisy route-level effect, not a new top-line jump
  - the service logs now also summarize the wasm `/respond` timing breakdown as:
    - `totalMeasuredMs`
    - `materializationMs`
    - `dominantBucket`
    - `dominantBucketMs`
    on both registration and sign-path keep-gates
  - the relayer keep-gates now also assert that cache-hit wasm `/respond`
    materialization is effectively gone:
    - `materializationMs <= 1`
    - dominant bucket is not `materializeRuntimeMs` or
      `materializeSessionsMs`
  - the meaningful deployment gap is now still in `/respond`, but it is down to
    about `300ms` locally instead of multiple seconds
  - that means the remaining work should target real wasm/runtime overhead
    first, not more low-value transport-envelope shaving

## Current Bundle Sizes

Latest browser HSS artifacts:

- wasm:
  `262,555` bytes
- JS glue:
  `14,028` bytes
- worker JS:
  `21,744` bytes

These sizes are now stable enough that future protocol or runtime changes
should be judged partly on bundle-size impact, not just runtime speed.

## Durable Optimization Wins

The main durable gains that survived the refactor are:

- dedicated browser HSS wasm package instead of a broad mixed runtime bundle
- staged production seam without duplicate legacy runtime paths
- split/local arithmetic execution through the production hot path
- dedicated kernel-local paths for the SHA-512 boolean-heavy work
- removing repeated conversions and joined-value materialization from the hot
  execution path

The key result is that the hardened staged boundary landed without meaningful
bundle-size growth and without a material hidden-eval regression.

## Constant-Time Constraints

Performance changes are constrained by the crypto boundary.

Optimization work must not:

- add secret-dependent branches
- add secret-dependent division or modulo
- reconstruct joined hidden values in production hot paths
- reopen evaluator-visible clear-input shortcuts
- introduce target-specific production algorithms that diverge in behavior

Recent constant-time cleanup:

- the round-core local bit-pair arithmetic split no longer branches on a
  secret `cross` bit
- the same path no longer reduces with `%`; it now uses masking and wrapping
  arithmetic

## Accepted Retained State

The staged server-owned executor now keeps one explicit minimal retained-state
exception after add-stage:

- `projector_inputs`

That retained state is accepted because:

- raw relayer roots are dropped after add-stage
- `output_projection` still needs server-owned projector prerequisites later
- recomputing those prerequisites from scratch would violate the intended
  boundary model

This is an optimization and architecture tradeoff, not a client-visible
shortcut.

## What To Avoid

These classes of work have repeatedly been bad trades and should stay dead:

- helper-level rewrites that do not change the real hot-kernel shape
- native-only fast paths
- browser-only serialization detours that leave the kernel untouched
- evaluator-visible shortcuts that reconstruct hidden intermediate values
- duplicate legacy runtime paths kept “just in case”

## Next Optimization Directions

If performance work resumes, the highest-value directions are:

- denser executor-local storage for the split/local staged continuations
- fused local kernels around `round_core`
- more pair-wise boolean kernels inside `round_core` so left/right shares stop
  doing duplicate digest and commitment work
- better amortization of local Beaver/triple-adjacent material
- constant-time review of any new low-level arithmetic helper before it lands

The detailed phased history remains in
[docs/plans/optimization-v3.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/docs/plans/optimization-v3.md).

# Refactor 5: Cloudflare-First HSS Worker Optimization

Date created: April 7, 2026

## Summary

Refactor 5 is the next optimization pass for the `ed25519-hss` server path.

The goal is not to change the staged security boundary that landed in the
earlier boundary refactors. The goal is to reduce the real end-to-end
`/threshold-ed25519/hss/respond` cost in the Cloudflare-compatible wasm path.

This plan assumes:

- the Cloudflare Worker-compatible wasm path is the primary deployment target
- the native Rust driver path remains available as an optional VM/container
  deployment mode
- we optimize the Worker path without introducing a duplicate legacy protocol
  or a weaker boundary

## Why This Refactor Exists

The current crate benchmarks are healthy, but the live `/respond` route still
costs much more than the raw hidden-eval kernel:

- raw hidden-eval benchmark is roughly `0.3s`
- live Worker-compatible `/respond` is materially slower because it includes:
  - JSON request and response shaping
  - base64 encode and decode churn
  - large state blob parsing and re-serialization
  - staged artifact assembly around the kernel

So the remaining latency is now largely integration overhead, not just crypto
compute.

## Non-Goals

Refactor 5 should not do any of the following:

- reopen the old joined-input seam
- add a second production protocol shape
- make the native driver the only or preferred deployment path
- introduce legacy flags or compatibility branches
- claim a cryptographic redesign when the work is really serialization and
  runtime optimization

## Primary Goal

Make the Cloudflare-compatible wasm path materially cheaper without changing
the current staged boundary model.

That means improving:

- route latency
- CPU cost
- request and response size
- state materialization cost

while keeping:

- the staged server-owned execution model
- the same logical wire protocol
- the same non-export secrecy guarantees

## Architecture Stance

The deployment stance for Refactor 5 is:

- wasm Worker path is the primary target
- native Rust driver is optional and retained for VM/container deployments
- performance decisions must be judged against the Worker path first

The native path may remain faster, but it must not become the only path that
is practical to run.

## Main Optimization Themes

### 1. Reduce Serialization Overhead

The first target is non-kernel overhead in the live `/respond` path.

Focus areas:

- shrink JSON payload size
- reduce base64 churn
- remove repeated encode and decode of large state blobs
- stop re-wrapping the same state multiple times across layers

Specific questions:

- can large state blobs stay binary for longer before crossing the final HTTP
  seam?
- can internal relay-to-wasm boundaries use a more compact representation than
  JSON-plus-base64 for state-heavy fields?
- can we collapse repeated serialization of the prepared session, server
  assist state, and staged evaluator artifact inputs?

Success criteria:

- lower route-level parse and serialize time
- smaller request and response byte counts
- fewer encode and decode passes in the hot path

### 2. Avoid Duplicated Materialization In The Worker Path

Earlier work already removed one duplicate pass, but this should be treated as
an ongoing rule:

- compute once
- bind once
- reuse structured state instead of rebuilding it from wire form

Specific targets:

- avoid reconstructing staged ceremony state after it has already been
  materialized once in the same request
- avoid rebuilding artifact inputs from forms that were only created for
  transport
- ensure the wasm Worker path does not do extra staging work that the crate
  path no longer does

Success criteria:

- no duplicated staged-flow materialization in `/respond`
- fewer large intermediate objects
- lower total wasm execution time around artifact construction

### 3. Keep Ceremony State Compact

The next target is state size, because larger state means:

- more CPU to parse and serialize
- more transfer cost
- more memory pressure in the Worker runtime

Focus areas:

- shrink prepared evaluator state
- shrink server ceremony state
- shrink staged evaluator artifact representation where possible
- keep only the minimum retained state required by the staged executor

This must preserve the accepted staged model:

- server owns continuation state
- raw server roots are still not retained past the accepted boundary
- `projector_inputs` remains the explicit retained-state exception unless a
  better design lands

Success criteria:

- smaller state blobs across the `/prepare`, `/respond`, and `/finalize` path
- fewer large transient allocations in the Worker runtime

### 4. Use Cloudflare-Native Coordination Only Where It Helps

Cloudflare-native coordination primitives may help state handling, but they are
not a substitute for compute.

Appropriate use:

- Durable Objects for ceremony/session coordination when stable request routing
  or handle ownership helps
- KV for low-frequency metadata, not hot compute state

Not appropriate:

- treating Durable Objects or KV as a solution to raw hidden-eval compute cost
- moving hot cryptographic computation into a coordination layer

Questions to answer:

- does Durable Object affinity reduce ceremony state transfer enough to matter?
- can handle ownership be simplified if a single Worker-affine object owns a
  ceremony?
- does the operational complexity pay for itself in reduced serialization?

Success criteria:

- use Cloudflare-native primitives only where they reduce coordination or state
  transfer overhead
- do not move compute into the wrong runtime layer

### 5. Benchmark The Pure Worker Path Directly

The crate benchmark is useful, but it is not the live route cost model.

Refactor 5 must add or improve route-level benchmarking for the Worker path.

We should measure at least:

- wasm compute time
- request parse and serialize time
- artifact assembly time
- total `/respond` time

Recommended breakdown:

- `/prepare`
  - request parse
  - wasm prepare
  - response serialize
- `/respond`
  - request parse
  - wasm staged ceremony / artifact build
  - response serialize
- `/finalize`
  - request parse
  - wasm finalize
  - response serialize

Recommended outputs:

- local Node Worker-compatible benchmark harness
- deployed Cloudflare timing snapshots
- byte-size accounting for the largest request and response payloads

Success criteria:

- route-level timing exists and is easy to rerun
- coarse wasm `/respond` timing can distinguish decode, materialization, and
  ceremony core cost
- executor-internal stage timings now use a Worker-compatible wasm timer
  source, so live wasm decisions can be grounded in measured inner-stage data
- optimization decisions are made from live-path numbers, not just crate
  kernel benchmarks

## Phase Plan

### Phase 1: Baseline The Real Worker Cost

Record the current Cloudflare-compatible route breakdown.

Tasks:

- add timing spans for request parse, wasm compute, artifact assembly, and
  response serialize
- record payload byte counts for `/prepare`, `/respond`, and `/finalize`
- document current baselines in this file and in
  [optimization.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/optimization.md)

Exit criteria:

- we can answer where `/respond` time is actually going

Todo:

- [x] add route-level timing spans for `/prepare`, `/respond`, and `/finalize`
- [x] separate wasm compute time from parse and serialize time in logs
- [x] record request and response byte counts for each route
- [x] capture a local Node Worker-compatible baseline
- [ ] capture at least one deployed Cloudflare baseline
- [x] write the baseline numbers into this file and
      [optimization.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/optimization.md)

Current local Node Worker-compatible baseline:

- focused route:
  `sessionless registration HSS routes with managed registration flow grants`
- `/prepare`:
  about `387ms`
- `/respond`:
  about `2853ms`
- `/finalize`:
  about `515ms`
- request sizes observed in that flow:
  - `/prepare` request:
    about `253` bytes
  - `/respond` request:
    about `47976` bytes
  - `/finalize` request:
    about `154587` bytes
- largest currently observed request payload contributor:
  - finalize `stagedEvaluatorArtifactB64u`:
    about `154364` bytes

What this baseline tells us:

- `/respond` is still the dominant latency hotspot
- `/finalize` currently carries the single largest route payload
- the next optimization slice should target transport shaping and artifact/state
  size before touching the staged boundary

### Phase 2: Remove Serialization Waste

Target the largest obvious overhead first.

Tasks:

- identify the biggest JSON-heavy payloads in the HSS route
- reduce repeated base64 wrapping and unwrapping
- reduce repeated state blob encode and decode across the route stack
- replace oversized transport envelopes where internal-only structure can stay
  compact longer

Exit criteria:

- request and response byte counts drop
- route parse and serialize time drops

Todo:

- [x] identify the largest JSON payload contributors in `/respond`
- [x] identify the largest base64-heavy fields in the route path
- [x] remove repeated encode/decode passes for prepared session state
- [x] remove repeated encode/decode passes for staged evaluator artifact inputs
- [x] remove redundant envelope-only binding fields from `/respond` requests
- [x] remove duplicate public context from `/prepare` `preparedSession`
- [x] evaluate whether internal-only state can stay binary longer before HTTP
- [x] simplify or remove oversized internal transport envelopes that only exist
      for intermediate shaping
- [x] rerun route timing after each serialization reduction slice
- [x] record before/after byte-size changes in this file

Current Phase 2 slice:

- `/finalize` no longer requires the client to send back the staged evaluator
  artifact
- `/respond` no longer returns the staged evaluator artifact to the client
- `/respond` no longer returns `serverAssistInit`
- registration `/finalize` no longer returns the full `finalizedReport`
- session `/finalize` now includes `seedOutputMessageB64u` only when explicitly
  requested for export
- `/respond` requests no longer carry a redundant
  `clientRequest.contextBindingB64u` field
- `/prepare` responses no longer echo duplicate public context inside
  `preparedSession`
- the server stores the staged evaluator artifact inside the ceremony handle and
  consumes it during `/finalize`

Observed local Node Worker-compatible before/after for that slice:

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
- bytes removed:
  `154485` on `/finalize` request
  `268782` on `/respond` response
  `569949` on registration `/finalize` response
  `67` on session `/respond` request
  `67` on registration `/respond` request
  `169` on session `/prepare` response
  `169` on registration `/prepare` response
- reduction:
  about `99.93%` on `/finalize` request
  about `99.996%` on `/respond` response
  about `99.98%` on registration `/finalize` response
  about `0.14%` on session `/respond` request
  about `0.14%` on registration `/respond` request
  about `0.69%` on session `/prepare` response
  about `0.69%` on registration `/prepare` response
- local registration wrapper timings after the slice:
  - `/prepare`:
    `362ms`
  - `/respond`:
    `2735ms`
  - `/finalize`:
    `497ms`
- local session wrapper timings after the slice:
  - `/prepare`:
    `373ms`
  - `/respond`:
    `2740ms`
  - `/finalize`:
    `500ms`

Largest remaining payload contributors after this slice:

- session `/finalize` response:
  about `39397` bytes total, almost all `clientOutputMessageB64u`
- `/prepare` response:
  `clientOtOfferMessageB64u` at about `23535` bytes and
  `preparedSession.evaluatorDriverStateB64u` at about `664` bytes
- `/respond` request:
  `clientRequest` at about `47790` bytes

What this means:

- the staged evaluator artifact and `serverAssistInit` echo are gone from the
  client-visible path
- registration no longer pays to receive a full `finalizedReport` it does not
  use
- normal session finalize no longer has to carry seed-capable material by
  default
- the remaining `/respond` request size is now mostly the actual OT/client
  request payload, not envelope-only binding fields
- `/prepare` still has a large OT offer plus evaluator driver state, but the
  duplicate public scope echo is gone
- the later Worker-only ceremony cuts stayed inside the same staged boundary:
  - `/respond` no longer simulates all later staged request/response hops just
    to build the staged evaluator artifact
  - the staged evaluator artifact now stays as raw bytes inside the same-process
    server/wasm path instead of being base64-wrapped and unwrapped again
- the next real transport targets are:
  - remaining large `/prepare` and `/respond` message bodies
  - deeper state compaction behind those remaining message bodies

### Phase 3: Compact Ceremony State

Make the staged ceremony state smaller and cheaper to move around.

Tasks:

- audit prepared-session state size
- audit server ceremony state size
- audit staged evaluator artifact size
- trim unneeded fields and transitional wrappers
- keep only the minimum retained staged state needed by the execution model

Exit criteria:

- state blobs are smaller
- wasm Worker allocations and transfers drop

Todo:

- [x] measure prepared-session blob size and major field contributors
- [x] measure server ceremony state blob size and major field contributors
- [x] measure staged evaluator artifact size and major field contributors
- [x] remove stale or transitional state fields that are no longer required
- [x] keep only the minimum retained staged state needed by the current
      execution model
- [x] confirm `projector_inputs` remains the only accepted retained-state
      exception
- [x] rerun route timing and payload-size measurement after state compaction
- [x] update docs if the retained-state story becomes simpler or more explicit

### Phase 4: Worker Coordination Review

Check whether Cloudflare-native coordination helps enough to justify it.

Tasks:

- evaluate whether Durable Object ceremony affinity reduces state transfer
- keep coordination optional and deployment-driven
- reject coordination changes that add complexity without measurable route
  wins

Exit criteria:

- explicit decision on whether Durable Object affinity is worth adopting

Todo:

- [x] document the current ceremony-handle ownership model in the Worker path
- [x] evaluate whether Durable Object affinity would reduce state transfer
- [x] evaluate whether Durable Object affinity would simplify ceremony routing
- [x] estimate the operational and implementation complexity of that change
- [x] reject the idea if it does not produce measurable route wins
- [x] document the keep/reject decision in this file
- [x] keep KV use limited to low-frequency metadata if any KV change is
      proposed

### Phase 5: Re-Measure And Decide

After the route and state optimizations land:

- rerun the Worker-path benchmarks
- compare against current `/respond` baseline
- compare against the optional native-driver path
- document the accepted Cloudflare-first tradeoff clearly

Exit criteria:

- we have an updated production baseline
- we know whether additional wasm-path optimization is worth more time

Todo:

- [ ] rerun the full Worker-path benchmark suite
- [x] compare updated `/respond` timing against the original Refactor 5
      baseline
- [x] compare the optimized Worker path against the optional native-driver path
- [x] summarize where the remaining overhead still lives
- [x] decide whether another wasm optimization pass is justified
- [x] update [optimization.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/optimization.md)
      with the kept final numbers
- [x] update this file with a short backward-looking implementation summary

Current steady-state local comparison after the direct-artifact and raw-bytes
cuts:

- focused route:
  `sessionless registration HSS routes with managed registration flow grants`
- wasm-only Worker-compatible path with
  `THRESHOLD_ED25519_HSS_DISABLE_NATIVE_DRIVER=1`:
  - `/prepare`:
    about `372ms`
  - `/respond`:
    about `886ms`
  - `/finalize`:
    about `32ms`
- native-enabled optional path:
  - `/prepare`:
    about `373ms`
  - `/respond`:
    about `720ms`
  - `/finalize`:
    about `509ms`

What changed relative to the earlier Refactor 5 baseline:

- wasm-only `/respond` moved from about `5715ms` to about `1240ms`
- native-enabled `/respond` moved from about `2857ms` to about `720ms`
- the dominant win was eliminating internal staged response replay during
  artifact construction
- the follow-up raw-bytes bridge cut removed another same-process artifact
  encode/decode pass
- the later retained-state raw-bytes cut now also keeps prepared server state
  and server inputs as raw bytes inside the same-process server/wasm bridge
  instead of decoding server-owned base64 again at ceremony time
- the latest kept wasm-only win is same-isolate prepared-session reuse:
  - `/prepare` caches the fully prepared `PreparedSession` inside the server
    wasm isolate
  - `/respond` reuses the cached runtime, evaluator session, and garbler
    session instead of re-materializing them from driver-state bytes
  - `/finalize` and server-output opening reuse the same cached prepared
    session when it is still present
  - cache misses fall back to the retained byte-state path instead of failing
    the ceremony
  - the server keep-gates now assert that cache-hit wasm `/respond`
    materialization is effectively gone:
    - `materializationMs <= 1`
    - dominant bucket is not `materializeRuntimeMs` or
      `materializeSessionsMs`
  - a follow-up same-process bridge cleanup now passes
    `clientRequestMessage` and `evaluatorOtState` into wasm as raw bytes
    instead of base64 strings
    - this kept the seam cleaner
    - the top-line latency effect was modest, so it is not the main remaining
      optimization lever

Current interpretation:

- the Cloudflare-compatible wasm path now lands within the requested
  "around 2s" target for registration `/respond`
- the remaining wasm-vs-native gap is about `300ms` locally
- that remaining gap now looks more like true wasm/runtime overhead than easy
  transport waste
- the widened keep-gates now cover:
  - registration HSS ceremony measurement
  - session sign/self-heal HSS ceremony measurement
  - the separated-roles example aligned to the current direct ceremony helper

## Phased Todo List

This section is the concise execution checklist for Refactor 5.

### Phase 1

- [x] instrument `/prepare`, `/respond`, and `/finalize`
- [x] capture Worker-path timing baselines
- [x] capture payload byte-size baselines
- [x] publish baseline numbers in docs

### Phase 2

- [x] remove repeated JSON/base64 churn
- [x] reduce repeated state encode/decode work
- [x] remove client-visible transport of server-owned staged artifact state
- [x] remove client-visible transport of unused `serverAssistInit`
- [x] remove client-visible registration return of unused `finalizedReport`
- [x] make seed-capable session finalize output explicit instead of default
- [x] simplify internal transport envelopes
- [x] record byte and timing wins

### Phase 3

- [x] compact prepared-session state
- [x] compact server ceremony state
- [x] compact staged evaluator artifact state
- [x] confirm retained staged state is still minimal

### Phase 4

- [x] evaluate Durable Object ceremony affinity
- [x] reject or accept Cloudflare-native coordination changes explicitly
- [x] keep coordination changes out unless they measurably help

### Phase 5

- [x] rerun focused Worker-path benchmarks after the prepared-session cache cut
- [x] compare against the native-driver optional path
- [x] record the direct-artifact wasm-path win
- [x] record the raw-bytes internal artifact win
- [x] record the prepared-session reuse wasm-path win
- [ ] update docs with the final Cloudflare-first tradeoff
- [ ] close the refactor with a short historical summary

## Likely Write Scope

Primary files likely to change:

- [server/src/core/ThresholdService/ed25519HssWasm.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/ThresholdService/ed25519HssWasm.ts)
- [wasm/near_signer/src/threshold/threshold_hss.rs](/Users/pta/Dev/rust/simple-threshold-signer/wasm/near_signer/src/threshold/threshold_hss.rs)
- [crates/ed25519-hss/src/server/api.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/server/api.rs)
- [crates/ed25519-hss/src/wire/mod.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/wire/mod.rs)
- [client/src/core/signingEngine/api/thresholdLifecycle/thresholdEd25519Lifecycle.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/api/thresholdLifecycle/thresholdEd25519Lifecycle.ts)
- [crates/ed25519-hss/optimization.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/optimization.md)

Potential Cloudflare coordination review scope:

- Worker entrypoints that own HSS ceremony handles
- Durable Object ceremony affinity layer, if explored

## Risks

The main risks are:

- optimizing byte layout in ways that make the code harder to reason about
- accidentally reintroducing duplicate route logic while trying to optimize it
- confusing internal compact-state changes with public protocol changes
- overfitting to local Node tests instead of real Worker behavior

The biggest discipline rule is:

- no duplicate legacy path
- no weaker staged boundary
- no native-only optimization treated as the main solution

Current Phase 3 slice:

- stored server inputs no longer retain a duplicate `contextBindingB64u`
- stored prepared-server session no longer retains a duplicate
  `contextBindingB64u`
- stored staged evaluator artifact no longer retains a duplicate
  `contextBindingB64u`
- stored prepared-server session no longer retains the OT offer, because the
  client receives it at `/prepare` and the server does not need to keep a
  second retained copy afterward
- the canonical binding now lives on the prepared-session path and is passed
  explicitly into server-side ceremony validation where needed
- this is ceremony-state compaction, not an HTTP payload change
- prepare timings now log the dominant prepared-session contributors directly:
  - `preparedSessionBytes`
  - `evaluatorDriverStateBytes`
  - `clientOtOfferMessageBytes`
- respond timings now log the dominant request contributors directly:
  - `clientRequestBytes`
  - `clientRequestMessageBytes`
  - `evaluatorOtStateBytes`
- current focused Worker-path breakdown is now explicit:
  - `/prepare` response before OT offer compaction: `24279` bytes
  - `/prepare` response after OT offer compaction: `22919` bytes
  - `/prepare` major fields:
    - `clientOtOfferMessageB64u`: about `22175` bytes
    - `preparedSession.evaluatorDriverStateB64u`: about `664` bytes
  - net `/prepare` response reduction from OT bundle compaction:
    about `1360` bytes
  - `/respond` request after OT bundle compaction: `45189` bytes
  - `/respond` request before OT bundle compaction: `47909` bytes
  - net `/respond` request reduction from bundle-level OT compaction:
    about `2720` bytes
- the latest deeper wasm/state compaction behind those bytes is:
  - OT selection bundles now serialize `width_bits` once per bundle instead of
    once per OT word
  - OT receiver-state bundles now serialize `width_bits` once per bundle
    instead of once per OT word
  - `ClientOtOffer` now serializes its fixed owner and purpose metadata once
    at the outer bundle level instead of repeating them inside each nested OT
    offer word
  - this keeps the same in-memory staged model while shrinking the
    Worker-compatible `/respond` request body
  - a follow-up wrapper-level compaction pass for `ClientPacket` and
    `ClientOtState` was tried and rejected:
    - it saved only about `69` bytes on `/prepare` and about `139` bytes on
      `/respond`
    - that was not enough to justify the added manual serialization
      complexity
    - the code was reverted so the crate keeps the simpler derived
      packet/state encoding
- the compaction also required keeping the optional native-driver path fresh:
  - the native Rust driver now rebuilds itself when either the crate sources
    or the shared wasm-side state producers are newer than the cached release
    binary
  - this avoids stale-driver decode failures when the wasm and native paths
    share evolving bincode state encodings
    - decoded payloads:
      - `clientOtOfferMessage`: about `16630` bytes
      - `evaluatorDriverState`: about `498` bytes
    - base64url transport overhead:
      - `clientOtOfferMessage`: about `5884` bytes
      - `evaluatorDriverState`: about `166` bytes
  - `/respond` request: `47838` bytes
  - `/respond` major fields:
    - `clientRequestMessageB64u`: about `23535` bytes
    - `evaluatorOtStateB64u`: about `24198` bytes
    - decoded payloads:
      - `clientRequestMessage`: about `17651` bytes
      - `evaluatorOtState`: about `18148` bytes
    - base64url transport overhead:
      - `clientRequestMessage`: about `5884` bytes
      - `evaluatorOtState`: about `6050` bytes
- added a real `ThresholdSigningService` regression covering:
  - `ceremonyStateBytes` logging on HSS prepare/respond
  - prepared-session and client-request contributor byte logging
  - staged evaluator artifact size logging
  - compact stored ceremony state after `/prepare`
  - compact stored evaluator artifact and stored prepared-server session after
    `/respond`
- the remaining large fields are now the live transport payloads themselves,
  not obvious duplicate retained-state copies

Current decision:

- base64url transport overhead is real and measurable:
  - about `6050` bytes on `evaluatorOtState`
  - about `5884` bytes on each `23535`-byte HSS message
- but the route is still compute-dominated at about `2.7s-3.1s` on `/respond`
- and the current client/server wasm seam still consumes base64 strings
  internally
- so a pure HTTP transport redesign would shrink network bytes, but it would
  not attack the main latency cost yet
- Refactor 5 should therefore prioritize deeper wasm/state compaction behind
  those fields before redesigning the HTTP seam
- the current Worker-compatible ceremony ownership model is already simple:
  - [server/src/core/ThresholdService/ThresholdSigningService.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/ThresholdService/ThresholdSigningService.ts)
    stores HSS ceremony state in an in-memory `Map<string, ThresholdEd25519HssCeremonyRecord>`
  - `storeThresholdEd25519HssCeremony(...)` creates a random handle and sets a
    short TTL
  - `getThresholdEd25519HssCeremony(...)` does the scope/expiry lookup
  - `deleteThresholdEd25519HssCeremony(...)` removes the record on finalize
  - `/prepare` writes the record once, `/respond` mutates it by attaching the
    staged evaluator artifact, and `/finalize` consumes and deletes it
- Durable Object affinity was reviewed and rejected for now:
  - it would replace one handle-routed state lookup with another, but the
    dominant `/respond` cost is still the wasm ceremony compute
  - it would not remove the large OT/client payload parsing cost on its own
  - it would add routing/affinity complexity and a second ceremony ownership
    model without a measured latency win
  - KV is also not a fit for hot HSS ceremony state; if used at all it should
    stay limited to low-frequency metadata outside the hot path

Latest focused rerun after the kept OT compaction:

- local Node Worker-compatible registration route:
  - `/prepare`: about `372ms`
  - `/respond`: about `886ms`
  - `/finalize`: about `32ms`
  - `/prepare` response: `22919` bytes
  - `/respond` request: `45189` bytes
  - `/finalize` request/response: `102` / `92` bytes
- comparison against the original local Refactor 5 registration baseline:
  - `/respond` request bytes improved materially: `47976` -> `45189`
  - `/respond` latency improved materially: `2853ms` -> `886ms`
- current interpretation:
  - the kept optimization stack now pulls the Worker-compatible `/respond`
    route into the requested "around 2s" target band with room to spare
  - local measurements are a lower bound on end-user time because deployed
    environments will add real request/response RTT on top
  - that means `/respond` latency remains the main optimization target for the
    next pass, but it is now true wasm/runtime overhead more than obvious
    route-envelope waste

Focused local native-vs-wasm comparison:

- optional native-driver path enabled:
  - `/prepare`: about `373ms`
  - `/respond`: about `720ms`
  - `/finalize`: about `509ms`
- wasm-only Worker-compatible path forced with
  `THRESHOLD_ED25519_HSS_DISABLE_NATIVE_DRIVER=1`:
  - `/prepare`: about `372ms`
  - `/respond`: about `886ms`
  - `/finalize`: about `32ms`
- interpretation:
  - the dominant gap is specifically in `/respond`
  - local wasm-only `/respond` is now about `1.4x` slower than the optional
    native path on the same machine
  - that confirms the next worthwhile work is still wasm-path optimization,
    not more envelope cleanup
  - because Cloudflare-style deployment remains the primary target, another
    wasm optimization pass is justified

Latest deeper-compaction slice:

- removed the unused `contextBindingB64u` field from the wasm client-request
  result path
- this was an internal worker/result cleanup, not a public HTTP shape change
- it confirms the next meaningful pass should keep attacking blob producers and
  retained state before changing the outer HTTP seam
- added a crate-side size regression showing the deeper issue:
  - `ClientPacket` size is dominated by the serialized OT word vectors
  - `ClientOtState` size is dominated by the serialized OT local-state word
    vectors
- that means the next meaningful `/respond` compaction work belongs in the OT
  bundle/state encoding itself, not in a few remaining wrapper fields

Latest cache-hit wasm ceremony-core slice:

- the cache-hit wasm `/respond` path now reuses the prepared session's
  hidden-eval constant pool instead of rebuilding it per request
- this keeps the same staged boundary and same prepared-session cache model;
  it only removes repeated per-request setup inside the ceremony core path
- observed local forced-wasm registration benefit:
  - `/respond`: about `1024ms -> 935ms`
- interpretation:
  - the remaining wasm-only `/respond` cost is now more clearly ceremony core
    and message/state decode work, not runtime/session materialization and not
    constant-pool setup

Latest same-isolate staged-artifact slice:

- the wasm path now retains the staged evaluator artifact by handle inside the
  same isolate instead of serializing it back into bytes for local `/finalize`
- `/finalize` now consumes the cached staged artifact directly when it is still
  present, with retained-byte fallback still available for the native path
- ceremony cleanup now releases both prepared-session and staged-artifact cache
  entries after finalize or expiry
- observed local forced-wasm registration benefit:
  - `/respond`: about `935ms -> 923ms`
  - `/finalize`: about `45ms -> 34ms`

Latest direct ceremony-core run slice:

- the modern artifact-only `/respond` path no longer routes through add-stage
  materialization plus projector replay just to reach final output bundles
- instead, it reconstructs the client bundles and runs the same-process hidden
  eval directly from the full client/server input bundles, then builds the
  staged evaluator artifact from that run output
- observed local forced-wasm registration benefit:
  - `/respond`: about `923ms -> 886ms`
  - `/finalize`: about `34ms -> 32ms`
- measured forced-wasm `/respond` breakdown immediately before this cut showed:
  - `ceremonyCoreMs` dominating both registration and sign flows at about
    `963-978ms`
  - `decodeStatesMs`, `decodeMessagesMs`, and materialization effectively at
    zero on cache-hit wasm runs

Latest round-core kernel slice:

- the `round_core` sigma helpers and the `ch` precompute path now construct
  left/right XOR outputs as one pair instead of duplicating the work for each
  side separately
- observed forced-wasm server breakdown improvement:
  - registration:
    - `ceremonyCoreMs`: about `850ms -> 841ms`
    - `ceremonyRoundCoreMs`: about `433.15ms -> 416.22ms`
  - sign/self-heal:
    - `ceremonyCoreMs`: about `859ms -> 846ms`
    - `ceremonyRoundCoreMs`: about `445.32ms -> 430.90ms`
- focused forced-wasm registration `/respond` stayed roughly flat at about
  `886-907ms`, so this is best treated as an inner-kernel win with a noisy
  route-level effect
- current interpretation:
  - `round_core` remains the dominant live wasm ceremony stage
  - future wasm optimization work should keep targeting executor-internal
    `round_core` kernels before revisiting the outer HTTP seam

## Exit Criteria

Refactor 5 is successful if all of the following are true:

- the Cloudflare-compatible wasm `/respond` path is measurably faster
- request and response sizes are smaller or at least better understood
- the route-level benchmark story is good enough to guide future work
- the staged boundary remains unchanged
- the native driver remains optional rather than required

## Deliverable

The final output of Refactor 5 should be:

- a faster Cloudflare-first wasm path
- a cleaner measurement story for the real route
- a documented deployment tradeoff:
  - Cloudflare-first path is the primary target
  - native driver remains an optional faster server deployment mode

# Optimization 8: Closed HSS Latency Experiment Record

Status: **closed and superseded on July 10, 2026**. No further current-backend
or succinct-HSS implementation, optimization, feasibility, amplification, or
benchmark work is authorized. Existing measurements are retained only as dated
historical evidence.

Date created: July 10, 2026

This document superseded [optimization-7.md](optimization-7.md) during the
investigation. The active replacement plan is now
[Streaming Yao for Deriver A and Deriver B](../../../docs/yaos-ab.md).

## Purpose

Preserve the measured history and security finding for the Ed25519 hidden
seed-to-scalar path:

```text
d = LE32(y_client + y_server mod 2^256)
h = SHA-512(d)
a = clamp(h[0..32]) mod l
```

Track A current-backend experiments are canceled. Track B is superseded by the
actively secure Streaming Yao plan. The O8-S0 peer-confidentiality finding
remains production-blocking for every old HSS path and is resolved through
replacement and deletion.

The objective remains the user-visible critical path:

```text
max(server advance, client artifact) + finalize
```

The server advance and client artifact legs run in parallel. A bucket-only win
does not count as a product win unless it moves the maximum leg or is a named
prerequisite for the next experiment.

## Executive Decisions

- [x] Stop all work on the current Ed25519 HSS backend.
- [x] Stop all genuine succinct-HSS feasibility and implementation work.
- [x] Select actively secure Streaming Yao as the sole Ed25519 replacement.
- [x] Preserve the fresh baseline below as simulator/runtime history; it is not
      a secure-protocol latency baseline.
- [x] Keep ECDSA on strict Router A/B threshold-PRF derivation and additive
      scalar shares, with no Yao dependency.
- [x] Reprovision all development Ed25519 wallets under one frozen Yao-era
      context; retain no compatibility backend or runtime flag.
- [x] Delete the old backend, its routes, and legacy-only fixtures after the
      replacement release gates pass.

## Fresh Baseline

Environment:

- repository commit: `f88d3a73438a`;
- host: Apple M4 Pro, macOS arm64;
- Rust: `1.96`;
- Node: `22.13`.

Fresh focused p50 measurements:

| Path                                             |        p50 |
| ------------------------------------------------ | ---------: |
| Native one-shot hidden evaluation                | `113.36ms` |
| Native production continuation hidden evaluation | `124.65ms` |
| Direct Chromium worker-handle artifact           | `180.35ms` |
| Durable WASM client artifact, worker handle      | `418.88ms` |
| Durable WASM client artifact, serialized session | `503.98ms` |
| Durable WASM server advance                      | `510.63ms` |
| Durable WASM finalize                            |  `32.89ms` |

Current durable server-advance buckets:

| Bucket                         | Approximate p50 |
| ------------------------------ | --------------: |
| Session materialization        |          `48ms` |
| Add-stage response             |           `8ms` |
| Message-schedule continuations |       `161.5ms` |
| Round-core continuations       |         `128ms` |
| Output projection              |       `119.5ms` |
| Unbucketed                     |          `45ms` |

The direct Chromium and durable measurements are separate harnesses. Their
difference is an O8-M0 investigation target. The `180.35ms` result is a lower
runtime envelope, not a product-path baseline.

Native sampling of the production continuation flow produced:

- SHA-256 compression: `2,128 / 8,509` top-of-stack samples, `25.0%`;
- BLAKE3 compression: `2,075 / 8,509`, `24.4%`;
- message-schedule loop: `2,181` samples;
- round-core loop: `1,546` samples;
- `memmove`: `524` samples.

These samples support a representation, checkpoint, and state-transition
experiment. They do not assign all hash samples to avoidable work.

## What Optimization 7 Established

Retain these conclusions:

- Worker-resident handles materially outperform serialized client state.
- Boundary copy and finalize are second-order relative to hidden evaluation.
- The retained `Ch` root and clamped scalar reducer were real wins.
- Small continuation conversion changes did not move the product path.
- Allocation-only, scratch-only, label-only, and helper-local rewrites are
  exhausted at the current abstraction boundary.
- Product retention must use the maximum of the parallel legs.

Optimization 8 adds four findings:

1. The batched server invocation still simulates 64 message-schedule and 80
   round-core request/response transitions internally.
2. Those transitions repeatedly clone and reconstruct large schedule and state
   objects.
3. Schedule checkpoints repeatedly reconstruct and hash the growing schedule.
4. The active role-separated transport view exposes counterparty input roots.

## O8-S0: Security Prerequisite and Current-Backend Disposition

Status: **closed by replacement decision; finding remains deletion-blocking**

Severity: **critical**

Confidence: **high; the client-side recovery was reproduced through public
crate APIs**

The documented requirements say neither party may learn plaintext `d` or `a`
and that the client must not reconstruct the server roots:

- [protocol invariants](../specs/protocol.md#non-negotiable-invariants);
- [security goals](../security.md#core-security-goals);
- [current boundary requirement](../security.md#current-boundary-status).

The active server-input delivery serializes both share sides for `y_server` and
`tau_server` in [wire/mod.rs](../src/wire/mod.rs#L629). The client decrypts and
returns both sides in [client/api.rs](../src/client/api.rs#L257). For each input
bit, the crate's own decoding relation is:

```text
clear_bit = (left.share_word + right.share_word) mod 2
```

The decoding implementation is in
[ddh_hss.rs](../src/ddh/ddh_hss.rs#L6299).

Delivering one current transport side is also insufficient. Each
`DdhHssTransportWord` carries the counterparty commitment in
[ddh_hss.rs](../src/ddh/ddh_hss.rs#L732), while client/server 1-bit commitments
map deterministically to the compressed identity or Ed25519 basepoint in
[ddh_hss.rs](../src/ddh/ddh_hss.rs#L3766).

The reverse direction has the same joined-share shape. The client serializes
joined `y_client` and `tau_client` bundles in
[client/api.rs](../src/client/api.rs#L710), and the server deserializes them in
[server/api.rs](../src/server/api.rs#L590).

Disposition:

- [x] Peer confidentiality remains a product requirement.
- [x] The current backend is excluded from production retention decisions.
- [x] Current-backend reproducer and repair work is canceled; this source
      evidence is sufficient to require deletion.
- [x] Party views, adversarial tests, and independent review move to the active
      Yao plan.

Transport AEAD protects against an outside observer. It does not hide plaintext
from the party holding the corresponding transport key.

Security prerequisites discovered during the same review move to the selected
Yao and retained signing owners:

- [ ] Make role-signing round-one nonce state single-use and consumed by value;
      remove `Clone` and reusable borrowed finalization inputs.
- [ ] Give persisted nonce or preprocessing records an atomic
      `available -> reserved -> consumed | destroyed` lifecycle.
- [ ] Replace `!is_small_order()` point acceptance with the required
      prime-order/torsion-free validation.
- [ ] Remove secret-dependent OT branch selection and secret-dependent branch
      payload indexing.

Exit criteria:

- the current backend is explicitly classified as research-only, accepted
  under a deliberately revised trust model, or scheduled for deletion;
- the production candidate has a written party-view argument and adversarial
  view tests;
- all active documentation states one consistent security model.

## Measurement Contract

Every experiment records:

- baseline commit and candidate commit;
- host, toolchain, browser, build flags, and session source;
- exact commands and benchmark output directory;
- warmup and sample count;
- p50, p95, peak WASM memory, and memory drift;
- server advance, client artifact, finalize, and their critical-path maximum;
- artifact, transcript, checkpoint, root, and decoded-output digests;
- physical operation counters when the experiment changes hidden-eval kernels;
- correctness, boundary, constant-time, and security-review results;
- final decision with date and reason.

Discovery gate:

- paired before/after builds in the same environment;
- target bucket improves by at least `5%` and exceeds observed noise;
- no correctness or memory-drift regression.

Retention gate:

- at least 24 sequential focused samples after warmup;
- intended product-path benchmark completed;
- `max(server advance, client artifact) + finalize` improves by at least
  `25ms`, or the result is a documented prerequisite for the next retained
  experiment;
- p95 does not regress by more than `5%`;
- peak memory remains inside the current product limit;
- all non-negotiable gates below pass.

Native measurements are diagnostic. Retention requires Worker/WASM and intended
browser-path evidence.

## Non-Negotiable Gates

Every retained current-backend change requires:

- byte-equivalent outputs and externally meaningful artifacts, or a new backend
  version with semantic-equivalence fixtures;
- parser rejection for stale, unknown, and mixed backend objects;
- boundary corruption tests for every new encoded state;
- fixed public loop bounds, indexes, protocol widths, and allocation sizes;
- a manual constant-time review and an automated analyzer run when the analyzer
  is available;
- `cargo hss-fv all`;
- a focused tail benchmark and intended product-path benchmark.

Every replacement-protocol change also requires:

- a written ideal functionality and party-view argument;
- standard Ed25519 reference-vector and randomized differential tests;
- role-specific output privacy tests;
- replay, concurrent-consume, and crash-retry tests for preprocessing state;
- independent cryptographic review;
- an explicit payload, memory, and network budget.

## No-Legacy Rule

- Alternative kernels live only in benchmark or test code during measurement.
- Accepted semantic changes receive one new backend version.
- Persistence and request boundaries reject stale, unknown, or mixed objects.
- Runtime fallback and dual production implementations are prohibited.
- Delete obsolete continuation states, protocol messages, tests, fixtures, and
  helper paths after selection.
- Temporary boundary compatibility requires a named deletion point. Development
  state may be invalidated instead of migrated.

## Experiment Dashboard

| ID    | Track           | Status           | Dependency   | Primary target                     | Keep gate                                          |
| ----- | --------------- | ---------------- | ------------ | ---------------------------------- | -------------------------------------------------- |
| O8-S0 | Security        | Closed by replacement | None    | Party-view confidentiality         | Old backend must be deleted                        |
| O8-M0 | Measurement     | Canceled              | None    | Canonical product baseline         | Historical measurements retained                  |
| O8-A1 | Current backend | Canceled              | —       | Bulk server execution              | No further HSS optimization                        |
| O8-A2 | Current backend | Canceled              | —       | One-shot client execution          | No further HSS optimization                        |
| O8-A3 | Current backend | Canceled              | —       | Clamped scalar reduction           | No further HSS optimization                        |
| O8-A4 | Current backend | Canceled              | —       | Arithmetic-share projector         | No further HSS optimization                        |
| O8-A5 | Current backend | Canceled              | —       | Packed/SIMD stage kernel           | No further HSS optimization                        |
| O8-B1 | Replacement     | Superseded            | Yao plan | Fixed-circuit two-party evaluation | `docs/yaos-ab.md`                                  |
| O8-B2 | Replacement     | Superseded            | Yao plan | OT and preprocessing               | `docs/yaos-ab.md`                                  |
| O8-B3 | Replacement     | Superseded            | Yao plan | Product replacement                | `docs/yaos-ab.md`                                  |

## O8-M0: Reconcile the Product Measurement Topology

Status: **canceled; historical question only**

Expected direct win: none.

Question:

Why does the isolated Chromium worker-handle artifact measure `180.35ms` while
the durable Node worker-handle artifact measures `418.88ms`, and which envelope
matches the intended product client?

Deliverables:

- [ ] Run the same fixture, projection mode, backend bytes, and worker-resident
      session through Chromium, Node, and the intended iframe/worker product route.
- [ ] Record decode, materialization, hidden evaluation, output projection,
      artifact encoding, message scheduling, and main-thread handoff separately.
- [ ] Run the server leg with the intended Durable Object/Worker topology or its
      closest controlled harness.
- [ ] Execute server advance and client artifact concurrently in the product
      trace.
- [ ] Collect at least 24 sequential samples after warmup.
- [ ] Record p50, p95, peak memory, memory drift, and payload bytes.
- [ ] Name one canonical baseline for O8-A1 through O8-A5.

Exit criterion:

- one report explains the direct Chromium versus durable Node gap and provides
  the baseline critical path used by every later keep/reject decision.

## O8-A1: Consuming Bulk Server Executor

Status: **canceled; no current-backend optimization work**

Hypothesis:

The server advance spends substantial time simulating fine-grained protocol
transitions inside one invocation. A consuming stage-owned executor can remove
that work while preserving the fixed computation and externally required
bindings.

Current evidence:

- [runtime/flow.rs](../src/runtime/flow.rs#L107) loops over 64 schedule and 80
  round-core transitions;
- [hidden_eval_executor.rs](../src/ddh/hidden_eval_executor.rs#L3248) clones the
  growing schedule on every extension;
- [hidden_eval_executor.rs](../src/ddh/hidden_eval_executor.rs#L3298)
  reconstructs all 80 schedule words for every round;
- [hidden_eval_executor.rs](../src/ddh/hidden_eval_executor.rs#L3374) clones the
  complete schedule after every round;
- [server/state.rs](../src/server/state.rs#L316) clones the full server state at
  every transition;
- [hidden_eval_executor.rs](../src/ddh/hidden_eval_executor.rs#L1730)
  reconstructs and hashes the growing schedule checkpoint.

Estimated result to test:

- durable server advance: `510.63ms -> 300ms-345ms`.

This is an experiment hypothesis, not a forecast or floor.

Implementation shape:

- one owned stage-specific execution state;
- fixed schedule storage with no per-round schedule clone;
- mutable or consuming round kernel state;
- scratch allocated once per complete stage;
- one conversion into stage-local representation and one reviewed boundary
  materialization;
- checkpoint digests computed once and carried by typed state;
- typed transcript transitions in memory;
- wire encoding only at external request and persistence boundaries.

Lifecycle states must make invalid transitions unrepresentable. Suggested
shape:

```text
AddComplete -> ScheduleComplete -> RoundsComplete -> Projected -> Finalized
```

Each transition consumes the narrow prior state. Avoid optional continuation
bags and broad state clones.

Tasks:

- [ ] Capture the exact external messages, checkpoints, artifacts, and outputs
      that must remain stable.
- [ ] Define the consuming execution-state union and transition API.
- [ ] Build the bulk executor in benchmark-only code.
- [ ] Remove internal `WireMessage` encode/decode from the measured path.
- [ ] Keep schedule words and round state in stage-owned storage.
- [ ] Compute every required checkpoint once.
- [ ] Add stage-level and final-output differential fixtures.
- [ ] Inspect generated WASM for unexpected copies and allocator calls.
- [ ] Run discovery benchmarks.
- [ ] Run retention benchmarks if discovery passes.

Keep criteria:

- exact externally required output and binding equivalence;
- no complete schedule or server-state clone in the hot loops;
- fixed public loop bounds and allocation sizes;
- durable advance improves by at least `20%` and `75ms`;
- product critical path passes the retention gate;
- all non-negotiable gates pass.

Retention action:

- replace the production incremental executor;
- delete the 144-transition production path and its legacy-only fixtures;
- retain boundary parsers only for currently valid objects.

Reject when:

- the candidate only redistributes time among continuation buckets;
- durable advance improves by less than `75ms`;
- p95 or memory regresses beyond the retention limit;
- the candidate requires both bulk and incremental production runtimes.

## O8-A2: One-Shot Client Worker Path

Status: **canceled; no current-backend optimization work**

Hypothesis:

The client artifact builder can reuse the existing one-shot stage executor and
remove its 64+80 continuation loop. The likely isolated gain is modest.

Current paths:

- continuation loop:
  [client/api.rs](../src/client/api.rs#L380);
- existing one-shot helper:
  [hidden_eval_executor.rs](../src/ddh/hidden_eval_executor.rs#L3095).

Measured native A/B evidence:

- one-shot hidden evaluation: `113.36ms`;
- production continuation hidden evaluation: `124.65ms`.

The schedule-plus-round routing delta implies a `5ms-15ms` hypothesis for
Worker/WASM. Measure it directly.

Tasks:

- [ ] Route benchmark artifact construction through the one-shot helper.
- [ ] Keep the evaluator session worker-resident.
- [ ] Serialize session state only at an external persistence boundary.
- [ ] Compare artifacts, role outputs, commitments, and transcript bindings.
- [ ] Measure Chromium worker, Node worker, and intended product worker.
- [ ] Check main-thread responsiveness and worker memory.

Keep criteria:

- exact artifact and output equivalence, or one versioned semantic replacement;
- no serialized-state round trip inside the hot path;
- Chromium product-worker evidence;
- no main-thread or p95 regression;
- the refreshed parallel critical path passes the retention gate, or this
  change eliminates the duplicate production continuation executor used by
  O8-A1.

Retention action:

- keep one stage executor for client and server arithmetic;
- delete the client continuation loop and obsolete fixtures.

## O8-A3: Ed25519 Pseudo-Mersenne Clamped Reduction

Status: **canceled; no current-backend optimization work**

Hypothesis:

The clamped scalar can be reduced with a smaller fixed circuit than three full
256-bit subtract/select passes.

For Ed25519:

```text
a = x0 + q * 2^252
q in {4, 5, 6, 7}
l = 2^252 + c
a mod l = x0 - q * c mod l
```

`q * c` is at most 128 bits. The candidate uses a fixed-width selection for
`q * c`, one subtraction, and one borrow correction. Secret `q` must not affect
branches, indexes, loop counts, or allocation sizes.

Current reducer:

- [hidden_eval_executor.rs](../src/ddh/hidden_eval_executor.rs#L4519).

Tasks:

- [ ] Write the algebra and canonical-range proof.
- [ ] Cover every `q` value exhaustively.
- [ ] Test boundaries around `0`, `q*c`, `l-1`, and `2^252-1`.
- [ ] Run large randomized differential tests against the retained reducer.
- [ ] Compare final Ed25519 public keys and role outputs.
- [ ] Inspect generated WASM for secret branches and table indexing.
- [ ] Measure reducer and whole-projector p50/p95.
- [ ] Determine whether commitments or transcript semantics require a backend
      version change.

Keep criteria:

- proof and differential fixtures pass;
- generated code has a fixed secret-independent control shape;
- projector improvement exceeds observed noise;
- product critical path passes the retention gate when this result is combined
  with O8-A4 or another named prerequisite.

No millisecond win is assigned until the Worker/WASM experiment runs.

## O8-A4: Arithmetic-Share Output Projector

Status: **canceled; no current-backend optimization work**

Hypothesis:

One reviewed Boolean-to-arithmetic conversion after SHA-512 can keep scalar
reduction, `tau`, masks, and role outputs in arithmetic shares modulo `l`. This
removes several 256-bit Boolean add/reduction circuits from
[hidden_eval_executor.rs](../src/ddh/hidden_eval_executor.rs#L4115).

Implementation requirements:

- branch-specific typed Boolean and arithmetic share states;
- explicit canonical ranges at every conversion boundary;
- no broad casts or partially initialized share objects;
- a written proof for modular addition, masking, and role-output relations;
- fixed control flow for all secret values;
- a new backend version when transcript semantics change.

Tasks:

- [ ] Inventory every Boolean consumer after SHA-512.
- [ ] Define the narrow arithmetic-share state and valid transitions.
- [ ] Prove `x_client_base` and `x_server_base` output relations.
- [ ] Build a differential projector harness.
- [ ] Compare commitments, public keys, decoded scalars, and role outputs.
- [ ] Measure conversion, reduction, mask, client-output, and server-output
      buckets independently.
- [ ] Run full Worker/WASM and intended product-path benchmarks.

Keep criteria:

- exact final Ed25519 and role-output equivalence;
- all proof and constant-time gates pass;
- projector p50 improves by at least `20%`;
- end-to-end critical path passes the retention gate.

## O8-A5: Packed Stage Kernel and WASM SIMD

Status: **canceled; no current-backend optimization work**

Hypothesis:

After transition and checkpoint overhead is removed, contiguous structure-of-
arrays storage can expose remaining round and schedule work to WASM SIMD.

The build already enables SIMD. This experiment must change the data layout and
generated instructions rather than repeat a compiler-flag change.

Tasks:

- [ ] Profile the O8-A1 winner and identify the remaining arithmetic kernel.
- [ ] Define fixed-width packed lanes with reviewed alignment.
- [ ] Inspect generated WASM before benchmarking.
- [ ] Compare scalar and SIMD kernels in isolated benchmark code.
- [ ] Run Chromium, Node, and intended Worker measurements.
- [ ] Record code size, compile time, peak memory, and low-power-device results.

Keep criteria:

- stage and final semantic equivalence;
- no secret-dependent lane selection;
- hidden-eval p50 improves by at least `10%` across the intended runtimes;
- product critical path passes the retention gate.

## O8-B1: Fixed-Circuit Two-Party Replacement Spike

Status: **superseded by `docs/yaos-ab.md` Phases 1 through 6**

Goal:

Prototype a passive/semi-honest fixed circuit for the exact standard Ed25519
seed-to-scalar and role-output functionality. Use free-XOR, half-gates, and
role-specific output decoding. Keep the prototype isolated from production
code until its performance and party views are reviewed.

The circuit must preserve:

- canonical seed `d` and standard Ed25519 compatibility;
- `d = LE32(y_client + y_server mod 2^256)`;
- SHA-512, clamping, and canonical reduction modulo `l`;
- the selected `tau` and role-output relation;
- client-only client output and server-only server output;
- export semantics when export is explicitly authorized.

Measure:

- AND and XOR gate counts;
- circuit construction and garbling time;
- online evaluator time;
- preprocessing time;
- bytes sent in each direction;
- browser Worker and server Worker p50/p95;
- peak memory and memory drift;
- complete client and server protocol views;
- intended `max(legs) + finalize` product path.

Tasks:

- [ ] Freeze the ideal functionality and leakage statement.
- [ ] Specify garbler/evaluator roles and role-specific output decoding.
- [ ] Generate or hand-build the fixed circuit in benchmark-only code.
- [ ] Count gates before assigning a payload estimate.
- [ ] Add standard Ed25519 vectors and randomized differential fixtures.
- [ ] Add adversarial view tests for both parties.
- [ ] Benchmark garbling and evaluation separately in Worker/WASM.
- [ ] Model network time at recorded payload sizes.
- [ ] Obtain independent cryptographic review.

Initial keep gate:

- exact reference and randomized semantic agreement;
- written passive/semi-honest party-view argument;
- no reconstructable counterparty root in either view;
- fixed secret-independent execution shape;
- online focused `max(legs) + finalize` below `250ms`;
- payload and memory fit explicit product limits;
- independent review approves progression to O8-B2.

`200ms` remains the stretch target. Record it as achieved only from the
intended product benchmark.

Background references:

- [Half-Gates: Two Halves Make a Whole](https://www.cs.virginia.edu/~evans/pubs/ec2015/)
- [TLSNotary/mpz browser and Worker reference implementation](https://github.com/tlsnotary/tlsn)
- [A Unified Framework for Succinct Garbling](https://eprint.iacr.org/2025/442.pdf)

## O8-B2: OT Extension and Atomic Preprocessing Tickets

Status: **superseded by `docs/yaos-ab.md` Phases 6 and 7**

Goal:

Move expensive base-OT and garbling setup outside the authenticated online
critical path without creating reusable nonce, OT, or circuit state.

Required lifecycle:

```text
Available -> Reserved -> Consumed
                     -> Destroyed
```

Each transition is atomic and consumes the prior state. A ticket binds:

- environment and organization;
- wallet/account/key identity;
- operation and authorization scope;
- backend and circuit version;
- server key version;
- transcript/session identifier;
- expiration and one-use nonce.

Tasks:

- [ ] Select and review the OT-extension construction.
- [ ] Define consuming ticket states with no `Clone` path.
- [ ] Define atomic reserve, consume, abort, expiration, and crash recovery.
- [ ] Add concurrent-consume and replay tests.
- [ ] Add mixed-wallet, mixed-environment, and mixed-backend rejection tests.
- [ ] Measure offline work and online residual work separately.
- [ ] Measure storage bytes, generation throughput, and exhaustion behavior.
- [ ] Review pre-auth DDoS and ticket-farming surfaces.

Keep criteria:

- security review approves the construction and lifecycle;
- every replay and concurrent-consume fixture passes;
- online critical path improves by at least `50ms`;
- ticket generation and storage fit explicit operational budgets;
- no correctness dependency on process-local memory.

## O8-B3: Product Replacement and Old-Backend Deletion

Status: **superseded by `docs/yaos-ab.md` Phases 8 through 15**

Goal:

Integrate one reviewed backend, migrate only at external boundaries when
required, and delete the current production implementation.

Tasks:

- [ ] Assign the final backend and circuit version.
- [ ] Reject stale, unknown, and mixed objects at every request and persistence
      boundary.
- [ ] Integrate the selected client/server protocol with typed lifecycle states.
- [ ] Remove current joined-share transport types from production code.
- [ ] Delete the incremental execution path and obsolete backend kernels.
- [ ] Delete legacy-only tests, fixtures, snapshots, mocks, and guards.
- [ ] Update protocol, security, recovery, export, and optimization docs.
- [ ] Run full correctness, formal, boundary, security, Worker/WASM, and product
      validation.
- [ ] Complete independent review before production enablement.

Retention criteria:

- O8-S0 is closed;
- O8-B1 and O8-B2 gates pass;
- all non-negotiable gates pass;
- intended product latency, payload, and memory budgets pass;
- only one production backend remains.

## Product-Constraint Decision Points

These decisions can remove more latency than a kernel rewrite, and each changes
the product model.

### O8-D0: Canonical Seed Export

Status: **closed; canonical Ed25519 seed export is mandatory**

Keeping standard Ed25519 seed export requires the hidden SHA-512 path. A
scalar-native distributed key lifecycle could remove that path and would no
longer provide the same canonical seed export semantics.

- [x] Confirm standard seed export remains non-negotiable.

### O8-D1: Reconstruction Frequency

Status: **canceled with the HSS backend**

Durably wrapping a client signing share or activating an exact persisted sealed
session can remove repeated HSS reconstruction from unlock/session flows. It
does not reduce first-registration hidden-eval latency and changes the durable
share exposure model.

No tasks remain in this document. Any future session-frequency work requires a
new product plan independent of the deleted HSS backend.

### O8-D2: Security Level

Status: **closed; actively secure Yao is the production target**

The active Yao plan owns construction selection, proof, payload, cost, and
independent-review gates. A passive or covert downgrade cannot ship.

## Recommended Order

There is no remaining Optimization 8 execution order. Continue with
`docs/yaos-ab.md`: isolated reference and manifest crates first, active Yao
security next, then Router/Cloudflare/SDK integration.

## Experiment Record Template

Copy this block under the relevant experiment when recording a candidate:

```text
Candidate:
Date:
Baseline commit:
Candidate commit:
Environment:
Commands:
Output directory:

Correctness:
Security:
Constant-time:
Boundary/persistence:

Metric                         Baseline    Candidate    Delta
server advance p50
server advance p95
client artifact p50
client artifact p95
finalize p50
max(advance, artifact)+finalize
peak WASM memory
artifact bytes
request bytes
response bytes

Decision: retained | rejected | prerequisite-only
Reason:
Deletion work completed:
```

## Decision Log

| Date       | ID    | Candidate                      | Decision                    | Evidence                                                      | Follow-up                                         |
| ---------- | ----- | ------------------------------ | --------------------------- | ------------------------------------------------------------- | ------------------------------------------------- |
| 2026-07-10 | O8-S0 | Current role-separated backend | Production-blocking finding | Public-API client-view recovery and source review             | Freeze ideal functionality and select replacement |
| 2026-07-10 | O8-M0 | Fresh benchmark/profile pass   | Baseline input              | M4 Pro native, Node durable, and Chromium direct measurements | Reconcile intended product topology               |
| 2026-07-10 | O8-CLOSE | All HSS implementation tracks | Canceled and superseded     | Approved Router A/B Yao architecture decision                 | Continue only in `docs/yaos-ab.md`                 |

## Validation Commands

This closed plan has no implementation validation commands. The active isolated
slice uses:

```sh
cargo fmt --manifest-path crates/ed25519-yao/Cargo.toml -- --check
cargo test --manifest-path crates/ed25519-yao/Cargo.toml
cargo fmt --manifest-path tools/ed25519-yao-generator/Cargo.toml -- --check
cargo test --manifest-path tools/ed25519-yao-generator/Cargo.toml
```

All product, active-security, deployment, and SDK validation is defined in
`docs/yaos-ab.md` and remains deferred.

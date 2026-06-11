# Optimization v5: Executor-Wide Materialization Rewrite

Date created: June 10, 2026

Status: in progress.

## Goal

Redesign the hidden-eval executor around explicit materialization boundaries so
HSS can run faster and more predictably across browser, native, iOS, and
embedded-class devices.

The immediate target is the current browser/native registration path. The later
target is constrained runtimes where CPU, memory, allocation count, and
predictability matter as much as p50 latency.

This plan preserves the current HSS trust model:

- split/local execution remains the production boundary
- evaluator-visible state does not widen
- exportability stays intact
- threshold-at-registration remains intact
- byte-equivalent transcript behavior is preferred unless a backend-versioned
  protocol change is explicitly approved

## Background

Earlier optimization work established the main lessons:

- `optimization-experiment-ledger.md` is the canonical index of retained,
  rejected, and instrumentation-only latency experiments from refactor-61,
  refactor-62, refactor-64, optimization 5, and optimization 6.
- `optimization-v3.md` showed that durable wins came from kernel shape, denser
  local storage, and fused local kernels.
- `optimization-v4.md` showed that route and Worker transport waste was largely
  removed, leaving real ceremony execution as the dominant cost.
- `refactor-64` retained two `CoreBitWordSide` slices:
  - round-core `sigma0` / `sigma1`
  - message-schedule `small_sigma0` / `small_sigma1`

Those slices worked because transient XOR intermediates did not need
commitments until a later boundary. The next rewrite should generalize that
idea across the executor instead of adding more local helper rewrites.

## Current Baseline

Latest retained refactor-64 p50 snapshots:

- native `total_hidden_eval`: about `131.8ms`
- browser hidden eval: about `201.5ms`
- product client artifact bucket: about `450ms` to `472ms`
- server HSS prepare: about `378ms` to `383ms`

The likely byte-equivalent executor-wide win is modest on desktop:

- native hidden eval: about `6ms` to `20ms`
- browser hidden eval: about `10ms` to `30ms`
- product client artifact bucket: about `20ms` to `70ms`

The same percentage may matter more on embedded-class CPUs, where the baseline
could be several times slower and allocation pressure can dominate user-visible
performance.

## Main Hypothesis

The current executor still materializes some words earlier than needed.

The rewrite should classify every internal value by what consumers truly need:

- share bits
- provenance digest
- commitment
- transport or wire material
- debug or checkpoint material

Then each kernel should accept the narrowest valid representation. Commitment
derivation should happen only at explicit consumption boundaries.

## Non-Goals

- Do not revive the insecure direct arithmetic-to-Boolean shortcut that
  reconstructs joined values.
- Do not add duplicate production kernels for fallback.
- Do not add native-only production shortcuts.
- Do not keep compatibility branches after a new executor representation
  becomes the only production path.
- Do not preserve byte-equivalence by broad casts or untyped compatibility
  shapes.
- Do not optimize diagnostics in a way that changes protocol control flow.

## Constant-Time And Security Constraints

- Loop bounds must come from public circuit shape: SHA-512 word width, round
  count, stage/window count, and validated artifact dimensions.
- No secret-dependent branches.
- No secret-dependent indexing.
- No secret-dependent allocation sizes.
- No early return based on secret share contents.
- No division or variable-time arithmetic on secret-derived values.
- No joined hidden-value reconstruction.
- No expanded evaluator-visible or client-visible secret material.
- Any backend-versioned protocol rewrite needs explicit transcript, provenance,
  and verification analysis before implementation.

## Representation Model

The executor should move toward a small set of explicit internal types.

```rust
// Packed share bits and provenance only.
// No commitments.
struct CoreBitWordSide;

// Core left/right pair for a Boolean word.
struct CoreBitWordPair;

// Share bits, provenance, and commitments.
// This is required only at commitment-consuming boundaries.
struct MaterializedBitWordSide;

// Arithmetic word pair used by add/A2B boundaries.
struct ArithmeticWordPair;

// Wire or transport-ready material.
struct TransportWord;
```

Rules:

- A helper that only needs bits and provenance accepts core values.
- A helper that feeds multiplication material accepts materialized values only
  if the multiplication transcript consumes commitments.
- A helper that emits output bundles accepts or returns transport material only
  at the output boundary.
- Conversion from core to materialized form is named, measured, and audited.
- Core logic should not accept raw strings, raw DB/request shapes, or loose
  optional lifecycle objects.

## Materialization Boundaries

The rewrite should make these boundaries explicit:

- multiplication material inputs
- A2B carry-chain inputs that consume commitments
- checkpoint digest computation
- output projector bundle emission
- validation/debug materialization
- transport/wire message construction

Every other materialization should be treated as suspicious until the
commitment-consumption graph proves it is required.

## Phase 1: Commitment-Consumption Graph

Goal:

- map where commitments are consumed and where core values are enough

Tasks:

- [x] Add a table for every hidden-eval helper and stage:
      `input_sharing`, `add_stage`, `message_schedule`, `round_core`,
      `output_projector`, delivery/open/join, and finalization.
- [x] Classify each helper input as bits-only, provenance-only,
      commitment-consuming, transport-consuming, or debug-only.
- [x] Identify all current `LocalBitWordSide` materializations.
- [x] Mark which materializations are protocol-bound.
- [x] Mark which materializations are avoidable under byte-equivalence.
- [x] Add a generated or manually checked graph section to this document.
- [x] Add a source guard that prevents new implicit materialization helpers in
      hot executor code without updating the graph.

Keep gate:

- no code rewrite in this phase unless it is instrumentation or documentation
- graph must explain why `Ch`, `Maj`, A2B, and output projection are safe or
  blocked

### Phase 1 Snapshot: Commitment-Consumption Graph

Classification legend:

- **Bits**: share bits and public shape only.
- **Provenance**: provenance digests are consumed, commitments are not.
- **Commitment**: share commitments are consumed by transcript, material,
  validation, or output construction.
- **Transport**: transport words or bundles are consumed or emitted.
- **Debug**: checkpoint, digest, trace, or validation-only material.

Stage and helper graph:

| Stage / helper | Current inputs | Commitment consumers | Current materialization boundary | Phase 1 classification | Rewrite signal |
| --- | --- | --- | --- | --- | --- |
| input sharing / `share_input_bit_bundles_for_clear_input` | clear client and server inputs | input-share commitments and bundle commitments | shared/input bundles are materialized immediately | Commitment, transport at server-input delivery | Protocol-bound at input boundary |
| add stage / `execute_add_stage` and `add_two_local_bit_words_right_transport_bundles` | split local client word plus server transport words | transport validation, XOR/add carry chain, multiplication carry gate | output `SplitLocalBitWord` after each bit sum | Commitment and transport | Potential only with a larger carry-kernel rewrite |
| message schedule prefix / `initial_one_block_schedule_prefix_local_words` | add-stage `d_bits` and constant suffix words | later accumulation consumes commitments | local schedule words are materialized before accumulation | Commitment at later B2A/A2B boundary | Safe candidate for longer core storage |
| message schedule sigma / `small_sigma0_core_bits_into`, `small_sigma1_core_bits_into` | materialized schedule words and constants | final sigma words feed B2A accumulation | transient `xor01` and final `xor012` stay in `CoreBitWordPair` until B2A | Bits/provenance until B2A boundary | Native slice retained |
| message schedule accumulation / `add_message_schedule_words_to_arithmetic_naive` | prior schedule words and core sigma words | `materialize_core_bit_pair_to_arithmetic_word_pair_naive` derives sigma commitments for B2A base material | Boolean-to-arithmetic conversion materializes arithmetic words | Commitment | Native and direct browser benchmark retained |
| message schedule output / `arithmetic_word_pair_to_split_local_bits_secure` | arithmetic schedule word | arithmetic share commitments seed A2B bit decomposition and carry chain | split local schedule word materialized after A2B | Commitment | Larger A2B rewrite required for meaningful change |
| round sigma / `big_sigma0_local_bits_core_into`, `big_sigma1_local_bits_core_into` | materialized round state words | final sigma commitments feed `temp1` / `temp2` B2A | transient XOR intermediates are core-only; final sigma materializes | Bits/provenance until final sigma | Already partially retained |
| round `Ch` / `ch_local_bits_into` | materialized `e`, `f`, `g` | `yz` commitments feed multiplication material digest in `eval_mul_local_bit_pair_batch_raw_xor_base_public_into` | `yz` and choose output are materialized | Commitment | Blocked for byte-equivalence unless multiplication material shape changes |
| round `Maj` / `maj_local_bits_into` | materialized `a`, `b`, `c` | `xy` and `xz` commitments feed multiplication material digest in `eval_maj_local_bit_pair_batch_raw_public_into` | majority output is materialized | Commitment | Blocked for byte-equivalence unless multiplication material shape changes |
| `temp1` / `temp2` adders | materialized Boolean words | B2A base material includes each input bit commitment | arithmetic temp words materialize before local arithmetic add | Commitment | Needs B2A proof-shape rewrite for a larger win |
| `state3` B2A | materialized `d` state word | B2A base material includes bit commitments | arithmetic `state3` materialized | Commitment | Same as B2A |
| `new_a_bits` / `new_e_bits` A2B | arithmetic words | arithmetic commitments derive split bits, zero, sums, carry gate, and next carry | split local new state words materialize after secure A2B | Commitment | Largest likely round-core target; may require backend-versioned A2B v2 |
| output projector clamp / `extract_clamped_a_bits_local` | materialized final SHA-512 words and constants | copied final commitments and constant commitments become reduced scalar inputs | clamped scalar materialized | Commitment | Candidate only if output projector owns a typed core/canonical scalar representation |
| output reduction / `reduce_scalar_bits_mod_l_with_constants_local` | materialized scalar words | subtract, select, multiplication gates, and XORs consume commitments | reduced scalar materialized after each reduction round | Commitment | Logical materialization reduction required; allocation-only rewrites rejected historically |
| output tau / `add_words_bits_mod_l_canonical_inputs_right_transport_bundles_local` | client tau local word plus server tau transport words | transport validation and carry/mul commitments | tau sum materialized | Commitment and transport | Bound to server-input transport validation |
| output bundles / `build_hidden_bit_output_bundle`, `build_hidden_bit_output_transport_bundle_pair`, `canonicalize_hidden_bit_output_words` | split local output words | output owner commitments and bundle commitments are emitted | output wire bundles materialize at boundary | Transport and commitment | Protocol-bound at output boundary |
| continuation materializers / `materialize_*_with_pool` helpers | persisted continuations and staged projector inputs | checkpoint validation and output construction | continuation state becomes executor words | Debug and commitment | Keep explicit; useful graph guard target |

Guarded materialization/helper inventory:

- `materialize_into`
- `materialize_round_sigma_into`
- `materialize_message_schedule_continuation_with_split_server_inputs_with_pool`
- `materialize_projector_inputs_from_add_stage_inputs`
- `materialize_output_bundles_from_continuations_with_pool`
- `materialize_server_output_bundles_from_continuations_with_pool`
- `materialize_output_bundles_from_projector_inputs_with_pool`
- `materialize_staged_server_execution_with_split_server_inputs_with_pool`
- `add_words_bits_mod_l_canonical_inputs_right_transport_bundles_local`
- `add_transport_bundle`
- `add_two_local_bit_words_right_transport_bundles`
- `build_hidden_bit_output_bundle`
- `build_hidden_bit_output_transport_bundle_pair`
- `build_hidden_bit_output_transport_bundle_from_canonical`
- `canonicalize_hidden_bit_output_words`
- `materialize_core_bit_pair_to_arithmetic_word_pair_naive`

Phase 1 conclusions:

- `Ch` and `Maj` stay blocked for byte-equivalent core-only rewrites because
  their transient XOR commitments are included in multiplication material
  digests.
- B2A and A2B are the main round-core bottlenecks, but both currently consume
  commitments as part of their proof shape.
- Message schedule remains the safest next byte-equivalent representation
  target because part of its sigma path already proved the core-only pattern.
- Output projector work should target fewer logical materializations or emitted
  transport words. Allocation-only changes are not a sufficient signal.

## Phase 2: Materialization Counters

Goal:

- make materialization count and commitment derivation visible before rewriting

Tasks:

- [x] Add debug-only counters for core words, materialized local words,
      commitment derivations, provenance derivations, and transport words.
- [x] Add per-stage counters for `message_schedule`, `round_core`,
      `output_projector`, and delivery.
- [x] Add counters for A2B `new_a_bits` and `new_e_bits`.
- [x] Add counters for `Ch` and `Maj` multiplication-material paths.
- [x] Add native benchmark output fields for these counters.
- [x] Add browser/direct-WASM output fields for the same logical counters.
- [x] Ensure counters are diagnostic-only and unavailable to protocol control
      flow.

Status:

- The crate-local profile now exposes `stage_operation_counts` with retained
  stage counts plus round-substage pressure for sigma, `Ch`, `Maj`, B2A, and
  A2B paths.
- Native hidden-eval benchmark JSON includes `stage_operation_counts`, and its
  CLI summary prints the highest-signal pressure counters.
- The browser/direct-WASM report now includes `operation_counts` and
  `stage_operation_counts`; the collector summary prints the same high-signal
  pressure counters as native.
- The direct hidden-eval profile leaves `delivery` counters at zero because
  delivery accounting lives outside the direct executor profile. Delivery timing
  remains benchmarked separately.

Keep gate:

- counters must not change hidden-eval equivalence output
- counter-enabled timing is diagnostic only

## Phase 3: Executor IR And Type Boundaries

Goal:

- make invalid materialization states hard to express in the executor

Tasks:

- [ ] Promote the existing `CoreBitWordSide` idea into a broader executor-local
      representation module.
- [x] Add `CoreBitWordPair` for left/right Boolean words.
- [x] Add explicit materialization functions with names that describe the
      consuming boundary.
- [ ] Split helpers by required input type instead of accepting broad local
      word shapes.
- [ ] Delete helper overloads that exist only to preserve old calling style.
- [x] Add tests or compile-time fixtures for invalid conversions.
- [x] Keep all shape fields required: width, side, provenance, and circuit
      stage identity.

Keep gate:

- `hidden_eval_equivalence` must pass before any benchmark matters
- no unsafe casts or broad object-style state replacement

Status:

- `CoreBitWordPair` now carries round-sigma left/right core bits as one valid
  executor-local state.
- Round sigma materialization now goes through
  `materialize_round_sigma_into`, making the commitment-consuming boundary
  explicit.
- The old `RoundKernelCoreBooleanWord` wrapper was removed.
- `CoreBitWordSide` and `CoreBitWordPair` now carry an explicit
  `CoreBitWordStage` discriminator. The current stages are
  `MessageScheduleSigma0`, `MessageScheduleSigma1`, `RoundCoreSigma0`, and
  `RoundCoreSigma1`.
- The materialization graph guard now verifies the `CoreBitWordSide` and
  `CoreBitWordPair` field shape: circuit stage, side, packed public bit width,
  provenance, and no commitments in the core side.
- Unit tests now reject wrong-side, wrong-width, mismatched-length, zero-width,
  overwide, wrong-stage, and per-bit provenance-mismatch core conversions before
  they reach arithmetic materialization.

## Phase 4: Message Schedule End-To-End

Goal:

- finish the safest executor-wide slice first

Rationale:

- existing small-sigma `CoreBitWordSide` work already improved the message
  schedule
- message-schedule small sigma has a clear pattern where transient XOR
  commitments are not consumed before final materialization

Tasks:

- [x] Extend core storage through message-schedule accumulation.
- [x] Delay materialization until arithmetic addition or checkpoint boundary.
- [x] Preserve labels, provenance input order, and emitted commitments.
- [x] Benchmark native hidden eval.
- [x] Benchmark direct browser/Node HSS artifact.
- [x] Run product registration smoke only if native and direct-WASM move in the
      same direction.

Status:

- The normal executor and `advance_message_schedule_continuation_with_pool`
  now keep `small_sigma0` and `small_sigma1` in `CoreBitWordPair` form.
- `materialize_core_bit_pair_to_arithmetic_word_pair_naive` derives the same
  B2A commitment material at the arithmetic boundary, preserving the old labels
  `a`, `b`, `c`, `d`, `ab`, `abc`, and `abcd`.
- The old single-side core XOR helper was removed after this path switched to
  pair-core transforms.
- The message-schedule stage and continuation path now reuse public label
  buffers for `message_schedule/{t}` labels and the arithmetic-adder child
  labels. The proof labels remain byte-equivalent.

Native release smoke, macOS/aarch64, `--stage-warmup 1 --stage-iterations 1
--samples 6 --primitive-warmup 0 --primitive-iterations 1`:

- Baseline `HEAD`: `message_schedule` median `25.701ms`,
  `total_hidden_eval` median `144.805ms`.
- Current slice: `message_schedule` median `22.598ms`,
  `total_hidden_eval` median `143.471ms`.
- Interpretation: keep as a native message-schedule win, but require
  direct-WASM/browser confirmation before considering Phase 4 complete.

Native allocation smoke, macOS/aarch64, `--warmup 1 --samples 5`:

- Baseline `HEAD`: `profile_hidden_eval_for_clear_input` median `7.83MB`
  allocated across `37,289` allocation calls; `message_schedule` median
  `2.71MB` across `4,551` calls.
- Current slice: `profile_hidden_eval_for_clear_input` median `6.28MB`
  allocated across `35,891` allocation calls; `message_schedule` median
  `1.16MB` across `3,153` calls.
- Interpretation: the Phase 4 native slice reduced both message-schedule
  latency and allocation pressure. The full hidden-eval p50 improvement is
  small because round-core and output-projector still dominate.

Direct-WASM/browser status:

- Added a crate-local `browser-benchmark` wasm shim for
  `prepare_prime_order_ddh_hidden_eval`, `probe_prime_order_ddh_hidden_eval`,
  and `execute_prime_order_ddh_hidden_eval_*` so the browser report can be
  refreshed without SDK/product rebuilds.
- Rebuilt `web/generated/pkg` and refreshed the browser report with headless
  Chrome 149 on macOS/aarch64.
- Current direct browser hidden-eval: mean `208.5ms`, median `208.6ms`, p95
  `209.7ms`, prepare `223.9ms`, message schedule `32.8ms`, round core
  `130.1ms`, output projector `34.6ms`, reference match `true`.
- Product registration smoke remains pending because it exercises files outside
  `crates/ed25519-hss/**`.

Keep gate:

- improve `message_schedule` or `total_hidden_eval`
- no `round_core` or output-projector regression beyond noise

## Phase 5: Round-Core Boundary Rewrite

Goal:

- reduce round-core materialization while respecting multiplication and A2B
  proof boundaries

Tasks:

- [x] Add direct browser round-core pressure counters before choosing a rewrite
      target.
- [x] Split round-core into explicit sub-kernels:
      `sigma`, `ch`, `maj`, `temp1`, `temp2`, `state3`, `new_a_bits`,
      `new_e_bits`.
- [x] Keep `sigma` on core storage through the existing retained path.
- [x] Re-evaluate `Ch` and `Maj` with the graph:
      - if transient commitments feed multiplication material, keep them
        materialized
      - if a byte-equivalent core material input exists, implement it as one
        vertical slice
- [x] Re-evaluate `temp1` and `temp2` adders for avoidable materialization
      across arithmetic conversion boundaries.
  - [x] Add byte-equivalent public label scratch reuse for `temp1`/`temp2`
        arithmetic-adder labels.
- [x] Re-evaluate `new_a_bits` and `new_e_bits` A2B as the largest remaining
      round sub-buckets.
  - [x] Add byte-equivalent public label scratch reuse for the existing secure
        A2B helper.
- [x] Reject local operation-count reductions unless they reduce logical
      materialization or improve direct browser worker p50.

Status:

- Direct browser Phase 5 measurement snapshot, headless Chrome 149 on
  macOS/aarch64: total hidden-eval mean `209.4ms`, median `209.4ms`, p95
  `211.0ms`, message schedule `32.0ms`, round core `127.5ms`, output projector
  `37.4ms`, reference match `true`.
- Browser pressure counters: message schedule local/core materializations
  `26,624` / `16,384`; round-core local materializations `103,424`; output
  projector local materializations `2,048`; `Ch` multiplication paths `5,120`;
  `Maj` multiplication paths `5,120`; sigma0/sigma1 local materializations
  `10,240` each; `state3` B2A paths `5,120`; `temp1` B2A paths `25,600`;
  `temp2` B2A paths `10,240`; `new_a_bits` A2B paths `5,120`;
  `new_e_bits` A2B paths `5,120`.
- The graph still shows `Ch`, `Maj`, B2A, and A2B commitments are consumed by
  current proof material. The next implementation step should be a
  byte-equivalent measurement/structure slice around existing sigma labels and
  temporary adder scratch/materialization boundaries, or a spec-first A2B v2
  design if the remaining wins are protocol-bound.
- Byte-equivalent public label scratch reuse for the existing arithmetic adders
  is retained as a small Phase 5 slice. It preserves the same labels and
  commitment-producing helper calls while reusing the temporary label buffer.
  Native quick smoke moved `total_hidden_eval` median from the prior current
  slice `143.471ms` to `142.705ms`, and direct browser hidden-eval moved from
  mean `209.4ms` / round core `127.5ms` to mean `206.9ms` / round core
  `125.7ms`. Allocation smoke moved full hidden-eval from `6.28MB` /
  `35,891` calls to `6.269MB` / `35,652` calls.
- The follow-up message-schedule label scratch slice is retained because
  direct browser hidden-eval repeat-run landed at mean `205.0ms`, message
  schedule `31.2ms`, and round core `124.7ms`. Native quick smoke stayed noisy
  (`total_hidden_eval` median `143.788ms`, message schedule `22.339ms`), but
  allocation pressure improved to `6.256MB` / `35,335` calls. A same-build
  browser run also produced `203.8ms`; treat the saved `205.0ms` report as the
  conservative comparison point.
- The round-core batch executor and one-round continuation path now share
  explicit sub-kernel helpers for `sigma1`, `ch`, `temp1`, `sigma0`, `maj`,
  `temp2`, `state3`, `new_a_bits`, and `new_e_bits`. This is retained as an
  architecture milestone for the next slices: native quick smoke was
  neutral-to-positive (`total_hidden_eval` median `143.056ms`, round-core
  median `89.580ms`), allocation stayed at `6.256MB` / `35,335` calls, and
  direct browser repeated at mean `206.0ms`, round core `125.2ms`, reference
  match `true`.
- The safe A2B slice reuses the public `zero` / `sum` child-label buffer in the
  existing secure arithmetic-to-Boolean helper. It preserves the same labels,
  carry-chain helper, and emitted commitments. Native quick smoke was noisy
  (`total_hidden_eval` median `143.493ms`, round-core median `90.279ms`), but
  allocation pressure improved to `6.248MB` / `35,113` calls. Direct browser
  repeated at mean `200.8ms`, round core `122.8ms`, reference match `true`.
  Larger `new_a_bits` / `new_e_bits` gains remain proof-shape work because the
  current A2B carry chain consumes bit, zero, sum, and carry commitments.
- The output-projector label-buffer slice is retained as a small public-shape
  cleanup. It replaces hot-loop `format!` calls in fixed-modulus subtraction
  and select helpers with reusable buffers while preserving the exact labels.
  Native release smoke landed at `total_hidden_eval` median `130.828ms` and
  `output_projector` median `24.058ms`. Allocation smoke reported
  `profile_hidden_eval_for_clear_input` at `5.38MB` / `5,143` calls, but that
  result is larger than this label-only change should explain, so the browser
  result is the retention signal. Direct browser/WASM landed at mean
  `199.4ms`, median `198.1ms`, p95 `203.3ms`, round core `117.8ms`, output
  projector `34.0ms`, reference match `true`.
- A diagnostic stage-operation-count opt-out was rejected. It moved operation
  count calculation behind explicit profiled entry points, but native
  registration-style p50 regressed from the post-revert reference
  `145.156ms` client artifact / `136.966ms` hidden eval to `148.854ms` and
  `147.873ms` client artifact across two native runs. After a forced SDK
  rebuild, product smoke `20260610-093125Z` reported
  `ed25519EvaluationArtifactMs` p50 at `484/492/484/478ms`, worse than the
  retained source. No code from this experiment is retained.

Keep gate:

- improve `round_core` p50 in native and browser/direct-WASM
- product artifact bucket must improve before retention

## Phase 6: A2B Kernel Redesign

Goal:

- find larger wins around `round_new_a_bits` and `round_new_e_bits`

Known constraint:

- the insecure joined arithmetic-to-Boolean shortcut is permanently rejected
- the current secure carry-chain shape may require commitments in places that
  local micro-optimizations cannot remove

Tasks:

- [x] Write a mini-spec for the current A2B proof shape.
- [x] Identify exactly which commitments bind carry-chain state.
- [x] Design a byte-equivalent representation rewrite if possible.
- [x] If byte-equivalence blocks meaningful gains, draft a backend-versioned
      A2B v2 protocol candidate.
- [x] Add equivalence tests for current backend version.
- [x] Cover current-backend label, provenance, share-side, and width
      rejection/commitment behavior.
- [x] Add explicit carry-order and downgrade negative tests with the A2B v2
      transcript root.

Keep gate:

- byte-equivalent path must improve both direct-WASM and product p50
- backend-versioned path requires a protocol review before implementation

### Phase 6 Mini-Spec: Current Secure A2B Shape

Scope:

- Converts a local arithmetic word pair `(left_word, right_word)` into split
  local Boolean bits without opening carries.
- Used by message-schedule output words and by round-core `new_a_bits` /
  `new_e_bits`.
- Current backend labels are protocol material and must remain byte-identical
  unless a backend version changes.

Boundary labels:

- Caller passes a label such as `round_core/{round}/new_a_bits`.
- The wrapper derives `{label}/zero` under
  `phase-a-arith-to-bool-zero`.
- The carry-chain gadget derives `{label}/sum/{idx}` and its related per-bit
  child labels under the caller's `{label}/sum` prefix.

Inputs:

- `left_word`: left arithmetic share with width `1..=64`.
- `right_word`: right arithmetic share with the same width.
- `zero_left` / `zero_right`: width-1 zero words derived from both arithmetic
  share provenance digests and commitments.
- Validation rejects wrong share sides, mismatched widths, zero words with the
  wrong side or width, and widths outside `1..=64`.

Per-bit proof shape for index `idx`:

1. Derive `left/{idx}` using `phase-a-arith-share-to-bool`, the left
   arithmetic share provenance digest, left share commitment, and side tag
   `left`.
2. Derive `right/{idx}` using `phase-a-arith-share-to-bool`, the right
   arithmetic share provenance digest, right share commitment, and side tag
   `right`.
3. Derive `xor_ab/{idx}` from the left/right bit provenance.
4. Derive `sum/{idx}` from `xor_ab` and the prior carry provenance.
5. Derive `a_xor_carry/{idx}` from the left bit and prior carry provenance.
6. Derive `carry/{idx}` through the local multiplication path over `xor_ab`
   and `a_xor_carry`.
7. Derive `next_carry/{idx}` from the left bit, a provenance-bound zero right
   word, and the carry gate output.
8. Emit `sum_left` / `sum_right` as the Boolean bit pair for `idx`.

Commitment/provenance bindings:

- Arithmetic input share commitments bind every `left/{idx}` and `right/{idx}`
  bit derivation.
- Arithmetic input provenance digests bind every decomposed bit derivation.
- The wrapper's `zero` words are bound to both arithmetic share provenance
  digests and commitments.
- Each `sum/{idx}` consumes the previous carry provenance, so the carry order is
  serial and label/order-sensitive.
- Each `carry/{idx}` consumes multiplication material for `xor_ab` and
  `a_xor_carry`.
- Each `next_carry/{idx}` consumes the current left bit provenance and carry
  gate output, which binds the next iteration.

Current conclusion:

- A larger byte-equivalent rewrite cannot skip per-bit derivation,
  multiplication carry material, zero material, or carry-order provenance.
- Remaining meaningful wins likely need a backend-versioned A2B v2 protocol
  that changes the proof shape. The current safe path is limited to public
  label scratch and allocation cleanup.

Byte-equivalent rewrite decision:

- Reusing public label scratch is the retained byte-equivalent slice.
- Reusing more intermediate storage without changing commitments does not remove
  the dominant work: the current multiplication helper hashes the per-bit input
  commitments for `xor_ab` and `a_xor_carry`, and the carry chain remains
  serial because each `sum/{idx}` and `next_carry/{idx}` consumes prior carry
  provenance.
- A larger byte-equivalent rewrite is rejected for now. It would either keep the
  same logical materialization count or silently change transcript material.

### Phase 6 Candidate: Backend-Versioned A2B v2

Status: implemented in `optimization-6` as
`ddh_hss_backend_v2_a2b_committed_root` after committed-root binding review.
The retained implementation uses committed root material per side and
precomputed BLAKE3 carry-material bases.
Negative coverage from `optimization-6` now covers stale backend downgrade
rejection, wrong root labels, width/share-side metadata, altered arithmetic
commitments/provenance, carry index/order, and emitted output bit commitments
at the A2B boundary digest.

Candidate backend identifier:

- `prime_order_ddh_hidden_eval_a2b_v2`
- This identifier must be carried in artifact metadata, benchmark reports, and
  any persisted/request boundary that can receive hidden-eval material.

Design goal:

- Reduce per-bit commitment construction and material hashing in
  `round_core/{round}/new_a_bits` and `round_core/{round}/new_e_bits`.
- Preserve exportability and the current browser trust model.
- Keep arithmetic share values local; do not open carries or the joined
  arithmetic value.

Candidate shape:

1. Build one A2B word transcript root per arithmetic word:
   `{label}/a2b_v2/root`.
2. Bind the root to:
   - backend identifier
   - word width
   - arithmetic left/right share commitments
   - arithmetic left/right provenance digests
   - caller label
3. Derive left/right decomposed bit cores from the word root and bit index,
   rather than constructing committed `left/{idx}` and `right/{idx}` local
   words under the current `phase-a-arith-share-to-bool` domain.
4. Run the same Boolean addition semantics:
   - `xor_ab = left_bit xor right_bit`
   - `sum = xor_ab xor carry`
   - `a_xor_carry = left_bit xor carry`
   - `carry_gate = xor_ab * a_xor_carry`
   - `next_carry = left_bit xor carry_gate`
5. Use a v2 multiplication material domain that binds to the word root,
   operation label, bit index, and operand provenance, rather than hashing four
   per-bit commitments that v2 no longer constructs.
6. Emit committed output bits only for the Boolean result words that leave the
   A2B boundary. Intermediate left/right decompositions, xor values, carry
   values, and carry gates stay core/provenance-only unless a later boundary
   needs them.

Transcript label proposal:

- Root: `{label}/a2b_v2/root`
- Decomposed bits: `{label}/a2b_v2/left/{idx}`,
  `{label}/a2b_v2/right/{idx}`
- Sum output: `{label}/a2b_v2/sum/{idx}`
- Carry multiply material: `{label}/a2b_v2/carry/{idx}`
- Next carry: `{label}/a2b_v2/next_carry/{idx}`

Expected retained commitments:

- The arithmetic input share commitments.
- One root commitment/provenance digest per A2B word side, if protocol review
  requires a committed root instead of a digest-only root.
- The emitted Boolean output bit commitments.

Expected removed commitments:

- Per-bit committed `left/{idx}` and `right/{idx}` local words.
- Per-bit committed zero material after the root binds arithmetic inputs.
- Intermediate committed XOR/carry material that never leaves the A2B boundary.

Security review questions:

- Is a digest-only word root enough, or does the server need a committed root
  word per side?
- Does the v2 multiplication material root bind enough information when
  per-bit operand commitments are removed?
- Which intermediate values must remain committed for transcript auditability,
  replay resistance, and hidden-eval equivalence?
- Can the v2 carry chain remain strictly ordered through provenance alone?
- What downgrade checks reject mixing v1 and v2 A2B material in one artifact?

Implementation sequence if approved:

1. Add backend-version enum/value and artifact metadata field.
2. Add v1/v2 dispatch only at the backend boundary; core executor code should
   use typed backend capabilities rather than compatibility flags.
3. Implement A2B v2 behind the new backend version.
4. Add byte-equivalence tests for v1 and semantic-equivalence tests for v2.
5. Add negative tests for mismatched backend version, labels, provenance root,
   carry order, and width.
6. Benchmark native, direct browser/WASM, and product registration smoke.

Current-backend test coverage:

- `phase_a_naive_conversion_round_trip_matches_original_word` and
  `phase_a_naive_five_word_sum_matches_wrapping_reference` cover current v1 A2B
  semantic equivalence.
- `phase_a_a2b_label_change_changes_commitments_not_value` covers the current
  label-binding rule: different A2B labels preserve the decoded value but
  produce different commitments/provenance.
- `phase_a_a2b_rejects_invalid_arithmetic_pair_metadata` covers provenance,
  width, and share-side rejection before A2B execution.
- Carry-order coverage is indirect for v1 through byte-equivalence and
  roundtrip tests because the carry sequence is internal to the helper. A2B v2
  must add explicit negative tests around carry-order transcript roots.

Internal review decision:

- A2B v2 changed proof shape materially enough to require protocol review
  before implementation. That review selected committed root material per side,
  then `optimization-6` implemented and benchmarked the candidate.
- A digest-only A2B root is not sufficient for implementation readiness because
  the current multiplication material path hashes operand commitments. Removing
  per-bit committed inputs requires committed root material per side or an
  equivalent binding proof.
- The SHA-256 carry-material implementation regressed native p50. The retained
  BLAKE3-base implementation moved native, direct browser/WASM, and product
  smoke in the right direction.
- Current-backend byte-equivalent output-projector and representation cleanup
  is no longer the active lane; the next latency work should either finalize
  this A2B v2 slice or pivot to refactor-61/62 registration critical-path
  overlap.

Review package:

- Target call sites:
  - `round_core/{round}/new_a_bits`
  - `round_core/{round}/new_e_bits`
- Measured opportunity from product smoke `20260610-130323Z`:
  `new_a_bits` `24ms` p50 and `new_e_bits` `24ms` p50 in the wallet-iframe
  Ed25519-only worker split. A retained v2 must move product
  `ed25519EvaluationArtifactMs` beyond smoke noise; it will not save the full
  `48ms` because output bits and carry semantics still exist.
- Root label: `{label}/a2b_v2/root`.
- Root domain: `phase-a-arith-to-bool-v2-root`.
- Root inputs:
  - backend identifier `prime_order_ddh_hidden_eval_a2b_v2`
  - caller label
  - word width
  - left/right arithmetic share commitments
  - left/right arithmetic share provenance digests
  - left/right share-side tags
  - carry-order policy id
  - output commitment policy id
- Carry material label: `{label}/a2b_v2/carry/{idx}`.
- Carry material domain: `phase-a-arith-to-bool-v2-carry`.
- Carry material inputs:
  - root digest
  - bit index
  - previous carry provenance digest
  - decomposed left/right bit provenance digests
  - `xor_ab` provenance digest
  - `a_xor_carry` provenance digest
- Retained commitments:
  - arithmetic input share commitments
  - emitted Boolean output bit commitments
  - optional root commitments if digest-only roots are not enough
- Candidate removed commitments:
  - per-bit committed left/right decomposition words
  - per-bit zero commitments
  - intermediate committed `xor_ab`, `a_xor_carry`, `carry_gate`, and
    `next_carry` values that never leave the A2B boundary
- Semantic equivalence:
  - v2 output bits decode to the same value as v1 for every tested arithmetic
    word
  - v2 preserves fixed-width `mod 2^n` semantics for widths `1..=64`
  - v2 branches and indexes depend only on public width and bit index
- Required negative tests:
  - v2 material under a v1 backend identifier and v1 material under a v2
    backend identifier
  - mixed v1/v2 A2B material in one artifact
  - wrong caller label
  - wrong width
  - swapped share sides
  - altered arithmetic share commitment
  - altered arithmetic share provenance digest
  - altered root digest
  - skipped or reordered carry index
  - altered emitted output bit commitment
- Implementation sequence if approved:
  1. Add a typed backend-version discriminator for hidden-eval kernels.
  2. Add root/carry material builders for A2B v2.
  3. Keep v1 byte-equivalent tests unchanged.
  4. Add v2 semantic-equivalence tests against v1 decoded values.
  5. Add v2 downgrade and negative tests.
  6. Add native benchmark first. Continue only if `round_new_a_bits`,
     `round_new_e_bits`, `round_core`, and total hidden eval improve.
  7. Add direct-WASM artifact benchmark.
  8. Run product registration smoke.
  9. Run full `ed25519-hss` tests and formal verification after retaining.
- Open review questions:
  - What exact committed-root or equivalent-root binding replaces the current
    per-bit operand commitments?
  - Does carrying multiplication material from root/provenance without per-bit
    operand commitments preserve the intended transcript audit surface?
  - Which intermediate values need commitments for downgrade resistance rather
    than semantic correctness?
  - Should B2A receive a matching v2 root at the same backend version, or can
    A2B change independently?
  - How should backend versioning appear in persisted/browser worker artifacts
    so stale v1/v2 material cannot mix?

Implementation-readiness decision:

- A digest-only A2B root is not sufficient for implementation. The current
  multiplication material path hashes operand commitments; removing per-bit
  operand commitments without replacing that binding changes more than the A2B
  representation.
- Protocol review approved committed root material per side. The retained
  implementation carries typed backend and A2B kernel versions through params,
  evaluation keys, artifacts, worker/session state, and benchmark reports.
- Constant-time review: the v2 loop shape can be constant-time if branches and
  indexes depend only on public word width and public bit index. No
  implementation should introduce division, modulo, table lookup, allocation
  sizing, or early return based on arithmetic share values, decomposed bits, or
  carry bits. Carry order is public and fixed; carry values are secret-derived
  and may influence bit-masked arithmetic only.
- Completed in `optimization-6`:
  - committed-root binding documented and implemented
  - typed backend and A2B kernel versions added
  - stale backend wire strings rejected at serialized session-state and staged
    artifact boundaries
  - legacy backend/A2B kernel enum variants deleted
  - root/carry negative tests added for label, width, share side, commitment,
    root mismatch, and carry index/order
  - native, direct browser/WASM, product smoke, full crate tests, and formal
    verification recorded
- Remaining follow-up:
  - optional explicit width-matrix and emitted-output-commitment tamper tests
    if more A2B changes are made
- Post-cleanup formal verification after deleting obsolete variants passed:
  `cargo hss-fv verus-check` reported `96 verified, 0 errors`; anti-drift
  reported `10 passed`.

## Phase 7: Output Projector Rewrite

Goal:

- reduce output-projector logical materialization and bundle construction

Tasks:

- [x] Use the graph to identify output-projector values that need transport
      material and values that only need core/provenance data.
- [x] Avoid allocation-only rewrites unless logical materialization falls or
      direct browser p50 improves.
  - [x] Retain the fixed-modulus subtraction/select label-buffer slice because
        it preserved transcript labels and improved direct browser mean/median.
  - [x] Reject direct output canonicalization after product smoke regressed
        client-artifact p50 despite native allocation and direct-WASM signals.
- [x] Design a staged output projector that emits bundles once.
- [x] Preserve output labels, masks, client-base behavior, and transcript
      binding.
- [x] Benchmark native and direct-WASM for retained Phase 7 slices.
- [x] Run product smoke for the direct output canonicalization candidate.
- [x] Re-run product smoke after the rejected shortcut revert once the current
      SDK TypeScript blocker is fixed.

Status:

- Output transport remains protocol-bound: `canonical_seed`, `client_output`,
  and `x_relayer_base` bundles need emitted commitments and transport material.
- `reduced_a_bits`, `tau_bits`, and base output additions still materialize
  under the current proof shape. Reducing their logical materializations needs a
  staged output projector or backend-versioned scalar-reduction rewrite.
- The retained Phase 7 slice only changes public label construction. It does not change
  branch behavior, data-dependent access, materialization counts, commitments,
  or emitted bundles.
- The direct output canonicalization candidate removed the temporary
  shared-word vector from `canonicalize_hidden_bit_output_words`, but product
  smoke rejected it. Smoke runs `20260610-085232Z` and `20260610-085440Z`
  showed `ed25519EvaluationArtifactMs` p50 at `484/482/480/477ms` and
  `480/485/470/473ms`, worse than the prior retained client-artifact baseline
  around `449/451/444/443ms`.
- Native allocation during the rejected candidate: output-projector /
  `profile_hidden_eval_for_clear_input` improved from `5.38MB` / `5,143` calls
  to `5.29MB` / `5,140` calls. The first browser repeat was noisy
  (`201.6ms` mean) due to unrelated round-core movement, and the second direct
  browser repeat improved to `198.0ms` mean. Product p50 stayed the keep gate,
  so the shortcut was reverted.
- After reverting direct output canonicalization, native registration-style
  smoke improved versus the rejected candidate: client artifact p50
  `151.101ms -> 145.156ms`, hidden-eval total p50 `142.462ms -> 136.966ms`,
  round-core p50 `89.284ms -> 86.020ms`, output-projector p50
  `29.901ms -> 28.448ms`.
- Direct browser/WASM after the revert, headless Chrome 149 on macOS/aarch64:
  total mean `203.6ms`, median `203.5ms`, p95 `205.4ms`, message schedule
  `30.7ms`, round core `123.7ms`, output projector `35.4ms`, reference match
  `true`.
- Post-revert product smoke was temporarily blocked in the current worktree by
  unrelated SDK TypeScript `Uint8Array<ArrayBufferLike>` / `BufferSource`
  errors during `packages/sdk-web` rebuild. The rebuild blocker is fixed with
  explicit owned-`ArrayBuffer` boundary conversions, and
  `pnpm -C packages/sdk-web exec tsc -p tsconfig.build.json` passes. Crate-local
  checks after the revert passed: `hidden_eval_equivalence`, materialization
  source guard, wasm32 library check, and the full non-ignored crate test suite
  (`101 passed`, `4 ignored`, `330.39s`).
- Post-revert product smoke `20260610-093753Z` passes after rebuilding the SDK:
  four scenarios, five successful runs each. `ed25519EvaluationArtifactMs` p50
  is `482/491/484/478ms`; worker `buildArtifactMs` p50 for the first scenario
  is `475ms`, with hidden eval dominated by `round_core` `244ms`,
  `output_projector` `156ms`, and `message_schedule` `34ms`. This is a valid
  retained-source rebaseline, but it is slower than the earlier retained
  client-artifact baseline around `449/451/444/443ms`, so the next candidate
  needs to target real representation or protocol-kernel work.

### Phase 7B: Staged Output Projector Candidate

Status:

- retained. The first implementation keeps the current protocol and wire shape,
  but routes output-bundle materialization through an internal staged boundary.

Current shape:

- `compute_output_projector_core_bits` materializes `reduced_a_bits` and
  `tau_bits`.
- `execute_output_projector_stage` materializes `client_base_bits`,
  `client_output_bits`, and `x_relayer_base_bits` as full `SplitLocalBitWord`
  values before output bundle construction.
- `build_hidden_bit_output_bundle` canonicalizes output bits into
  `DdhHssSharedWord` values and derives a bundle commitment.
- `build_hidden_bit_output_transport_bundle_pair` canonicalizes once, then
  emits left and right transport bundles from the same canonical word list.
- The rejected direct canonicalization shortcut showed that shaving only a
  temporary vector is insufficient. Product timing is the keep gate.

Architecture:

- Introduce an internal `StagedOutputWord256` representation for projector
  outputs that need bundle emission. It owns exactly 256 public-width bit
  positions, left/right share words, and provenance digests. It does not change
  wire structs or backend labels.
- Add a boundary-only materializer:
  `materialize_staged_output_bundle(owner, label, staged_word)`. This derives
  the exact current left/right output commitments, builds the exact current
  canonical shared-word list, and emits the existing `DdhHssInputShareBundle`
  or `DdhHssTransportBundle` values.
- Keep arithmetic helpers unchanged for the first implementation. The slice
  should only replace output-boundary `SplitLocalBitWord -> shared words ->
  bundle` plumbing with a typed staged output boundary.
- Preserve the current `canonical_seed`, `client_output`, and `x_relayer_base`
  bundle labels and commitments. Any scalar-reduction or modular-add proof
  rewrite belongs in a later backend-versioned plan.
- Make ownership explicit: `canonical_seed` and `client_output` are
  client-owned output bundles; `x_relayer_base` is server-owned transport
  material with left/right share-side views over one canonical staged word.

Implementation todo:

- [x] Add a byte-equivalence fixture that compares current output bundles with
      the staged boundary for trusted-server and client-masked projection.
- [x] Add `StagedOutputWord256` only inside `hidden_eval_executor`; do not
      expose it through protocol or wire structs.
- [x] Convert `build_hidden_bit_output_bundle` and
      `build_hidden_bit_output_transport_bundle_pair` to share one staged
      materialization path.
- [x] Keep `canonicalize_hidden_bit_output_words` only as the boundary parser
      or delete it if the staged path fully replaces it.
- [x] Benchmark native, direct browser/WASM, and product smoke before deciding
      retention.

Keep gate:

- output bundle bytes and commitments must match the current backend exactly
- `hidden_eval_equivalence` and output-bundle fixtures must pass before timing
- logical materialization or emitted transport work must fall, or direct browser
  worker p50 must improve before product smoke
- product `ed25519EvaluationArtifactMs` must improve; allocation-only wins are
  not enough

Result:

- kept. The staged output boundary preserves current backend bytes and moved
  the product client artifact bucket in the right direction.
- validation:
  - `cargo test --manifest-path crates/ed25519-hss/Cargo.toml
    staged_output_boundary_matches_legacy_bundle_materialization` passed.
  - `cargo test --manifest-path crates/ed25519-hss/Cargo.toml
    hidden_eval_materialization_helpers_are_documented` passed.
  - `cargo test --manifest-path crates/ed25519-hss/Cargo.toml
    hidden_eval_equivalence` passed: `3` passed, `103` filtered.
- native direct hidden eval:
  - `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-phase7b-staged-output-native.json`
  - `total_hidden_eval` p50 `129.757ms`
  - `round_core` p50 `82.188ms`
  - `output_projector` p50 `23.463ms`
  - `message_schedule` p50 `20.228ms`
- native registration-style timing was noisy. Saved runs include
  `prime-order-registration-phase7b-staged-output-native-release-repeat.json`
  at `137.676ms` client artifact / `129.926ms` hidden eval p50, while
  `prime-order-registration-phase7b-staged-output-native-release-repeat2.json`
  had an outlier-heavy `160.730ms` client artifact / `149.808ms` hidden eval
  p50. Product smoke remains the keep gate.
- direct WASM artifact run `2026-06-10T09-58-26-689Z`:
  - browser worker-handle wall p50 `205.8ms`
  - browser hidden eval p50 `193.45ms`
  - browser round core p50 `119.9ms`
  - browser output projector p50 `41.15ms`
  - Node worker-handle wall p50 `457.773ms`
- product smoke `20260610-095927Z`:
  - all four scenarios passed, five successful runs each
  - `ed25519EvaluationArtifactMs` p50 improved from the previous
    retained-source rebaseline `482/491/484/478ms` to `463/467/459/457ms`
  - SDK p50 improved from `1698/1717/1342/1359ms` to
    `1633/1650/1273/1295ms`
  - HSS worker `buildArtifactMs` p50 is now `455/461/457/458ms`
  - hidden eval p50 in product is `419/422/422/423ms`
- logical materialization counters intentionally stayed unchanged. This slice is
  a boundary and ownership cleanup that prepares the next output-projector
  reduction; the next slice must target fewer output-side local words or
  commitment/provenance derivations.

Keep gate:

- reduce logical materializations or transport words
- improve direct browser worker p50
- no product registration regression

## Phase 7C: Repeated-Selector Select Batch

Status:

- retained. This is a small output-projector scratch/allocation slice. It does
  not reduce logical materializations, but it removes repeated selector vector
  construction in `select_local_bit_words` while preserving the same
  multiplication material order, labels, openings, commitments, and provenance.

Architecture:

- Add `eval_mul_local_word_pair_batch_repeated_left_public` for the public-shape
  case where a selector bit pair is multiplied by every branch-delta bit.
- Keep the existing per-index materialization logic and label order inside the
  repeated-selector batch loop so the path uses the same transcript material as
  the prior slice-slice batch path.
- Route `select_local_bit_words` through the repeated-left batch path instead
  of allocating cloned selector vectors.
- Treat this as a scratch/allocation cleanup. It is not the deeper Phase 7C
  staged-output-state rewrite originally proposed, because the current
  output-side add/sub/select proof shape still consumes commitment-bearing local
  words.

Validation:

- `cargo test --manifest-path crates/ed25519-hss/Cargo.toml
  hidden_eval_equivalence -- --nocapture` passed: `3` passed, `103` filtered.
- `cargo test --manifest-path crates/ed25519-hss/Cargo.toml
  hidden_eval_materialization_helpers_are_documented -- --nocapture` passed.
- `cargo test --manifest-path crates/ed25519-hss/Cargo.toml
  staged_output_boundary_matches_legacy_bundle_materialization -- --nocapture`
  passed.

Benchmarks:

- Native direct hidden eval:
  `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-phase7c-repeated-selector-native.json`
  - `total_hidden_eval` p50 `128.910ms`
  - `round_core` p50 `81.547ms`
  - `output_projector` p50 `23.726ms`
  - `message_schedule` p50 `20.051ms`
- Native allocation:
  `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-phase7c-repeated-selector-alloc.json`
  - `profile_hidden_eval_for_clear_input` p50 allocation dropped to about
    `4.916MB` across `5,123` calls. The retained Phase 7 label-buffer slice was
    about `5.38MB` across `5,143` calls, so this removes only a small call count
    but a visible amount of short-lived selector cloning.
- Direct WASM artifact run `2026-06-10T10-08-53-023Z`:
  - browser worker-handle wall p50 `205.75ms`
  - browser hidden eval p50 `193.35ms`
  - browser round core p50 `119.65ms`
  - browser output projector p50 `41.65ms`
  - Node worker-handle wall p50 `466.002ms`
- Product smoke `20260610-100938Z`:
  - all four scenarios passed, five successful runs each
  - `ed25519EvaluationArtifactMs` p50 moved from Phase 7B
    `463/467/459/457ms` to `460/460/455/457ms`
  - SDK p50 is `1654/1670/1269/1283ms`
  - HSS worker `buildArtifactMs` p50 is `454/453/456/458ms`
  - hidden eval p50 in product is `418/417/420/424ms`

Keep gate:

- retained because product client-artifact p50 improved or stayed flat across
  all four smoke scenarios, and byte-equivalence checks passed.
- this should be the last allocation-only output select cleanup unless a new
  profile shows a specific public-shape allocation bucket that affects product
  p50.

## Phase 7D: Carry-Gate Material-Base Reuse

Status:

- retained. This is a byte-equivalent carry-gate cleanup that reuses the public
  multiplication-material hash base across fixed-width carry loops.

Architecture:

- Add `DdhHssLocalMulMaterialBase` as a prepared public-domain hash base derived
  from the evaluation key and local multiplication domain.
- Add a `eval_mul_local_word_pairs_core_with_material_base_public` entrypoint
  for loops that already execute many bit-multiplication gates under the same
  evaluation key.
- Keep label bytes, input commitments, opening order, product material digest
  suffixes, output provenance, and materialized local words identical to the
  current backend.
- Route A2B carry gates and local add carry gates through the prepared-base
  helper. This covers `eval_add_cross_share_local_arithmetic_word_bits_secure`,
  `add_two_local_bit_words_profiled`,
  `add_two_local_bit_words_right_transport_bundles`, and
  `add_two_local_bit_words_right_shared_bits`.

Constant-time review:

- The prepared base depends only on public evaluation-key material and a fixed
  domain.
- Reuse happens inside public-width loops: SHA-512 word width, scalar width, and
  validated transport/input lengths.
- The change adds no secret-dependent branches, indexes, allocation sizes, or
  early returns.

Validation:

- `cargo test --manifest-path crates/ed25519-hss/Cargo.toml
  hidden_eval_equivalence -- --nocapture` passed: `3` passed, `103` filtered.

Benchmarks:

- Native direct hidden eval:
  `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-material-base-reuse-native.json`
  - `total_hidden_eval` p50 `127.882ms`
  - `round_core` p50 `81.233ms`
  - `output_projector` p50 `23.708ms`
  - `message_schedule` p50 `19.640ms`
- Direct WASM artifact run `2026-06-10T10-23-17-523Z`:
  - browser worker-handle wall p50 `200.75ms`
  - browser hidden eval p50 `188.6ms`
  - browser round core p50 `116.7ms`
  - browser output projector p50 `41.0ms`
  - Node worker-handle wall p50 `459.574ms`
- Product smoke `20260610-102403Z`:
  - all four scenarios passed, five successful runs each
  - `ed25519EvaluationArtifactMs` p50 moved from Phase 7C
    `460/460/455/457ms` to `459/459/453/455ms`
  - SDK p50 is `1656/1657/1265/1285ms`
  - HSS worker `buildArtifactMs` p50 is `452/452/451/455ms`
  - hidden eval p50 in product is `416/416/419/419ms`

Keep gate:

- retained because byte-equivalence passed and native, direct-WASM, and product
  artifact p50 all moved in the right direction.
- the win is small. Future prepared-base reuse should target output-projector
  borrow/subtraction gates or other loops with clear repeated multiplication
  material setup.

## Phase 7E: Borrow-Path Material-Base Reuse

Status:

- retained. This extends the Phase 7D public material-base reuse to the
  fixed-modulus subtraction path used by output-projector scalar reduction.

Architecture:

- Add `eval_mul_local_word_pairs_with_material_base_public`, the materialized
  counterpart to the Phase 7D core helper.
- Thread one prepared `DdhHssLocalMulMaterialBase` through
  `sub_local_bit_words_with_ed25519_l`.
- Route both borrow cases through that shared base:
  - `borrow_zero` direct multiplication
  - `borrow_one` via the internal `or_local_word_pairs` helper
- Delete the now-unused per-call multiplication wrappers so the executor has
  one explicit material-base path for local bit multiplication.
- Preserve current labels, branch order, commitments, provenance, borrow
  sequence, and materialized output words.

Constant-time review:

- The reused base is public evaluation-key/domain material.
- `ed25519_l_bit(idx)` is a public fixed modulus branch.
- The loop is exactly 256 public scalar bits.
- The change adds no secret-dependent branching, indexing, allocation size, or
  early return.

Validation:

- `cargo test --manifest-path crates/ed25519-hss/Cargo.toml
  hidden_eval_equivalence -- --nocapture` passed: `3` passed, `103` filtered.
- `cargo check --manifest-path crates/ed25519-hss/Cargo.toml` passed.
- `cargo hss-fv verus-check` passed after updating a stale anti-drift fixture
  path from the old `client/src` SDK layout to `packages/sdk-web/src`: Verus
  `96` verified, `0` errors, and anti-drift `10` passed.
- `cargo test --manifest-path crates/ed25519-hss/Cargo.toml` passed:
  `102` passed, `4` ignored.

Benchmarks:

- Native direct hidden eval:
  `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-material-base-borrow-native.json`
  - `total_hidden_eval` p50 `126.459ms`
  - `round_core` p50 `80.039ms`
  - `output_projector` p50 `23.318ms`
  - `message_schedule` p50 `19.654ms`
- Direct WASM artifact run `2026-06-10T10-31-55-959Z`:
  - browser worker-handle wall p50 `201.2ms`
  - browser hidden eval p50 `188.65ms`
  - browser round core p50 `117.45ms`
  - browser output projector p50 `40.5ms`
  - Node worker-handle wall p50 `462.582ms`
- Product smoke repeat `20260610-103434Z`:
  - all four scenarios passed, five successful runs each
  - `ed25519EvaluationArtifactMs` p50 moved from Phase 7D
    `459/459/453/455ms` to `450/451/447/447ms`
  - SDK p50 is `1598/1638/1250/1290ms`
  - HSS worker `buildArtifactMs` p50 is `443/445/449/450ms`
  - hidden eval p50 in product is `407/410/416/417ms`

Keep gate:

- retained because byte-equivalence passed, native hidden eval improved,
  direct browser stayed flat within noise while output projector improved
  slightly, and product artifact p50 improved across all four scenarios in the
  repeat.
- this closes the obvious per-loop public material-base reuse targets. Further
  byte-equivalent work should target larger representation or logical-work
  reductions.

## Phase 7F: Select Scratch Reduction Candidate

Status:

- rejected. This was a byte-equivalent output-side select scratch candidate,
  but native timing regressed enough to stop before direct-WASM/product smoke.

Architecture:

- Keep `select_local_bit_words` labels and gate order unchanged:
  `branch_delta/{idx}`, `bit/{idx}`, then `selected/{idx}`.
- Keep the repeated-left multiplication batch from Phase 7C.
- Stop storing cloned false-branch local words in separate scratch vectors.
  Re-read the false branch at the final output XOR boundary.
- Preserve branch-delta words because the multiplication batch still consumes
  the full branch-delta vector under the current transcript shape.

Keep gate:

- failed at the native hidden-eval gate.

Validation and benchmark:

- `cargo test --manifest-path crates/ed25519-hss/Cargo.toml
  hidden_eval_equivalence -- --nocapture` passed: `3` passed, `103` filtered.
- Native direct hidden eval:
  `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-phase7f-select-scratch-native.json`
  - `total_hidden_eval` p50 regressed from Phase 7E `126.459ms` to
    `134.289ms`
  - `round_core` p50 regressed from `80.039ms` to `85.625ms`
  - `output_projector` p50 regressed from `23.318ms` to `24.483ms`
  - `message_schedule` p50 regressed from `19.654ms` to `20.732ms`

Decision:

- reverted. Re-reading false-branch words at the final select boundary saved
  scratch vectors but added enough packed-word reconstruction and cache churn to
  lose on native timing. This reinforces the current rule that allocation-only
  output-select rewrites are poor candidates unless a profile shows direct
  product impact.

## Phase 7G: Validated Local-Word Accessor Candidate

Status:

- rejected. This was a byte-equivalent hot-loop accessor candidate, but native
  timing was flat-to-negative on the first run and clearly negative on repeat.

Architecture:

- Add an internal `LocalBitWordSide::local_word_validated` accessor for loops
  that have already validated shape and public width at the boundary.
- Use it only in private executor loops over public indices: output clamp,
  local add, fixed-modulus subtraction, and select.
- Preserve the recoverable `local_word` accessor for boundary-style reads where
  invalid shape should still return `ProtoError`.
- Keep all labels, commitments, provenance, material digests, output words, and
  loop bounds unchanged.

Keep gate:

- failed at the native hidden-eval gate.

Validation and benchmark:

- `cargo test --manifest-path crates/ed25519-hss/Cargo.toml
  hidden_eval_equivalence -- --nocapture` passed: `3` passed, `103` filtered.
- Native direct hidden eval:
  `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-phase7g-validated-local-word-native.json`
  - `total_hidden_eval` p50 moved from Phase 7E `126.459ms` to `126.745ms`
  - `round_core` p50 regressed from `80.039ms` to `80.767ms`
  - `output_projector` p50 improved slightly from `23.318ms` to `23.261ms`
- Native repeat:
  `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-phase7g-validated-local-word-native-repeat.json`
  - `total_hidden_eval` p50 regressed to `130.339ms`
  - `round_core` p50 regressed to `82.794ms`
  - `output_projector` p50 regressed to `23.661ms`

Decision:

- reverted. Removing recoverable accessor checks did not improve the native
  executor; the compiler and cache profile appear to prefer the original
  accessor shape.

## Phase 7H: Output-Projector Scratch Arena

Status:

- partially explored. The first scalar-reduction scratch-buffer slice was
  rejected; the broader arena idea only remains viable if it reduces logical
  output-projector work, not just allocation churn.

Rationale:

- Phase 7F and Phase 7G both showed that small accessor/scratch edits can make
  timing worse even when they appear to reduce work locally.
- The retained Phase 7E allocation profile shows output projector remains the
  largest direct hidden-eval allocation bucket:
  `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-phase7e-retained-alloc.json`
  - `profile_hidden_eval_for_clear_input`: `4.916MB`, `5,123` allocation calls,
    `1.402MB` peak live above start
  - `probe_checkpoint_output_projector`: `4.916MB`, `5,123` allocation calls,
    `1.402MB` peak live above start
  - `probe_checkpoint_round_core`: `2.677MB`, `4,847` allocation calls,
    `1.198MB` peak live above start
  - `probe_checkpoint_message_schedule`: `1.140MB`, `2,773` allocation calls,
    `1.040MB` peak live above start

Architecture:

- Add a private output-projector scratch arena that owns reusable
  `SplitLocalBitWord` / `LocalBitWordSide` buffers for 256-bit scalar words.
- Convert the scalar-reduction and canonical-add helpers one at a time to
  `_into` forms that fill caller-owned output buffers while preserving the
  current labels, multiplication material, commitments, and provenance.
- Keep public structs, wire bundles, checkpoints, and backend labels unchanged.
- Keep invalid shape validation at helper entry boundaries. Inner loops may use
  arena buffers only after dimensions and ownership have been checked.

Todo:

- [x] Add hidden-eval byte-equivalence signature harness for arena-backed
      executor candidates before changing more hot-path code.
- [x] Add byte-equivalence fixtures for arena-backed scalar reduction and
      canonical modular addition.
- [ ] Add private `SplitLocalBitWordScratch` or equivalent reusable buffer type.
- [x] Try fixed-modulus subtraction plus scalar-reduction ping-pong `_into`
      helpers as the first arena sub-slice.
- [x] Reject the first scalar-reduction arena sub-slice after native latency
      regressed despite lower allocation.
- [ ] Convert select to an `_into` helper only if it reduces allocation without
      repeating the rejected Phase 7F false-branch reread shape.
- [ ] Convert output-projector canonical add paths only after scalar reduction
      is byte-equivalent and benchmark-positive.
- [ ] Benchmark native latency and allocation before direct-WASM.

Rejected sub-slice: scalar-reduction `_into` ping-pong buffers.

- Implemented reusable `difference` and `selected` `SplitLocalBitWord` buffers
  for `reduce_scalar_bits_mod_l_with_constants_local`, with `_into` variants
  for fixed-modulus subtraction and select.
- Preserved the existing select shape, including false-branch scratch words, to
  avoid repeating the Phase 7F false-branch reread regression.
- Validation passed:
  `cargo test --manifest-path crates/ed25519-hss/Cargo.toml
  hidden_eval_equivalence -- --nocapture`: `3` passed, `103` filtered.
- Allocation improved:
  `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-phase7h-reduce-arena-alloc.json`
  - `profile_hidden_eval_for_clear_input`: `4.916MB` / `5,123` calls to
    `4.522MB` / `5,051` calls
  - `probe_checkpoint_output_projector`: `4.916MB` / `5,123` calls to
    `4.522MB` / `5,051` calls
- Native timing regressed:
  `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-phase7h-reduce-arena-native.json`
  - `total_hidden_eval` p50 moved from Phase 7E `126.459ms` to `127.959ms`
  - `output_projector` p50 moved from `23.318ms` to `23.493ms`
- Native repeat:
  `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-phase7h-reduce-arena-native-repeat.json`
  - `total_hidden_eval` p50 was `127.493ms`
  - `output_projector` p50 was `23.566ms`

Arena precondition baseline:

- The arena byte-equivalence harness and scalar/canonical-add same-session
  fixtures are now in place before another hot-path rewrite.
- Current allocation baseline:
  `crates/ed25519-hss/docs/benchmarks/refactor-64/optimization-5/arena-preconditions/ddh-hidden-eval-current-alloc.json`
  - `profile_hidden_eval_for_clear_input`: `4.158117MB`, `5,091` allocation
    calls, `1.402363MB` peak live above start
  - `probe_checkpoint_output_projector`: `4.158117MB`, `5,091` allocation
    calls, `1.402363MB` peak live above start
- Current native timing baseline:
  `crates/ed25519-hss/docs/benchmarks/refactor-64/optimization-5/arena-preconditions/ddh-hidden-eval-current-native.json`
  - `total_hidden_eval` p50 `114.320ms`
  - `round_core` p50 `72.444ms`
  - `message_schedule` p50 `20.068ms`
  - `output_projector` p50 `18.110ms`
- Interpretation: use these two reports only as same-machine comparison points
  for the next arena candidate. They are not a new retained-performance claim,
  because this timing run is slower than earlier retained v4 snapshots.

Decision:

- reverted. The allocation reduction was real, but latency stayed negative.
  Future arena work must remove logical work or improve product/browser p50,
  rather than only reusing output buffers.

Keep gate:

- hidden-eval equivalence must pass after each sub-slice.
- native allocation must fall materially and native latency must be flat or
  better.
- direct browser/WASM must be flat or better.
- product artifact p50 must improve before retaining the arena path.

## Phase 7I: Public-Multiple Clamped Scalar Reduction

Status:

- retained. This is a protocol-kernel optimization, because it changes internal
  reduction labels/provenance while preserving the decoded scalar and hidden
  eval reference output.

Rationale:

- `scalar_a` is clamped before reduction, so it is below `2^255`.
- Ed25519 `L` is about `2^252`, which means the clamped value is below `8L`.
- The current output projector reduces `scalar_a` by running seven conditional
  subtract-by-`L` rounds.
- A public-multiple reduction can instead conditionally subtract `4L`, `2L`,
  and `L`, removing four subtract/select rounds from the `scalar_a` path.

Architecture:

- Keep the generic seven-round subtract-by-`L` helper for tests and any
  future 256-bit values that are not proven clamped below `8L`.
- Add a clamped-scalar-only helper that performs fixed public-multiple
  subtraction for shifts `[2, 1, 0]`, representing `4L`, `2L`, and `L`.
- Implement the shifted modulus bit as a public bit lookup from
  `ED25519_L_BYTES_LE`, with no secret-dependent branches or indexes.
- Keep each subtract/select round fixed-width over 256 bits.
- Update operation-count fixtures only if the decoded scalar/reference tests
  and hidden-eval reference match remain correct.

Todo:

- [x] Add the clamped-scalar reduction helper and route only `scalar_a` through
      it.
- [x] Add or update a local scalar reduction test that compares the
      public-multiple helper against `reduce_scalar_mod_l`.
- [x] Run `hidden_eval_equivalence` and update logical operation-count fixtures
      only for the intentional transcript/materialization change.
- [x] Benchmark native hidden eval and allocation.
- [x] Run direct browser/WASM and product registration smoke only if native
      timing improves.

Validation and benchmark:

- Scalar reference:
  `cargo test --manifest-path crates/ed25519-hss/Cargo.toml
  local_clamped_scalar_multiple_reduction_matches_reference_scalar_mod_l -- --nocapture`
  passed: `1` passed, `106` filtered.
- Hidden-eval equivalence:
  `cargo test --manifest-path crates/ed25519-hss/Cargo.toml
  hidden_eval_equivalence -- --nocapture` passed: `3` passed, `104` filtered.
- Native allocation:
  `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-phase7i-clamped-multiple-alloc.json`
  - `profile_hidden_eval_for_clear_input`: Phase 7E `4.916MB` / `5,123`
    calls to `4.161MB` / `5,031` calls
  - `probe_checkpoint_output_projector`: same `4.161MB` / `5,031` calls
- Native hidden eval:
  `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-phase7i-clamped-multiple-native-repeat.json`
  - `total_hidden_eval` p50: Phase 7E `126.459ms` to `118.039ms`
  - `output_projector` p50: `23.318ms` to `16.151ms`
  - `reference_match=true`
- Direct HSS WASM artifact:
  `benchmarks/ed25519-hss-wasm/out/2026-06-10T11-19-11-795Z/summary.md`
  - browser worker-handle wall p50: Phase 7E `201.2ms` to `187.9ms`
  - browser hidden eval p50: `188.65ms` to `175.75ms`
  - browser output projector p50: `40.5ms` to `30.25ms`
  - browser reduce-a p50: `7.5ms`
- Product registration smoke:
  `benchmarks/registration-flow/out/20260610-112012Z/summary.md`
  - all four smoke scenarios passed, `5 / 5` successful runs each
  - `ed25519EvaluationArtifactMs` p50: Phase 7E `450/451/447/447ms` to
    `450/445/443/442ms`
  - HSS worker `buildArtifactMs` p50: `441/438/441/442ms`
  - worker `hiddenEvalOutputProjectorReduceAMs` p50: `8ms`
- Full crate validation:
  `cargo test --manifest-path crates/ed25519-hss/Cargo.toml` passed:
  `103` passed, `4` ignored.
- Formal verification:
  `cargo hss-fv verus-check` passed: Verus `96` verified, `0` errors;
  anti-drift `10` passed.

Decision:

- retained. The win is logical scalar-reduction work, not allocator-only churn.
  Constant-time review: new branches and indexes depend only on fixed public
  loop indices and public modulus-multiple metadata.

Keep gate:

- decoded reduced scalar must match `reduce_scalar_mod_l` for fixture coverage.
- hidden-eval output reference must still match.
- constant-time review must confirm all new branches/indexes use only public
  loop indices or public modulus metadata.
- native output-projector and total hidden-eval p50 must improve before
  retaining.
- product client-artifact p50 must improve before declaring the phase retained.

## Phase 7J: Canonical-Add Material-Base Reuse

Status:

- rejected.

Rationale:

- Output-projector canonical modular addition runs an addition, subtracts `L`,
  computes the public geq selector, then selects the canonical result.
- The addition and fixed-modulus subtraction each prepare the same public
  local-mul material base from the evaluation key.
- Phase 7D/7E showed that reusing this public base across fixed local kernels
  can reduce repeated setup without changing gate labels, provenance, or output
  commitments.

Architecture:

- Add material-base-taking variants for the local bit-word add helpers and the
  fixed-modulus subtraction helper.
- Keep the existing helper names as wrappers that prepare their own material
  base, so non-canonical call sites keep their current shape.
- Route only canonical-add helpers through a shared
  `DdhHssLocalMulMaterialBase`.
- Preserve every existing child label, loop bound, transport validation, and
  selector path.
- Treat the optimization as byte-equivalent unless benchmark evidence shows
  otherwise.

Todo:

- [x] Add `_with_material_base` variants for local/local, local/transport, and
      local/shared bit-word addition.
- [x] Add a `_with_material_base` variant for fixed-modulus subtraction.
- [x] Route the three canonical-add helpers through a shared public material
      base.
- [x] Run hidden-eval equivalence before benchmarking.
- [x] Benchmark native hidden eval and allocation.
- [x] Retain only if native latency is flat or better and allocation improves
      without changing decoded/reference outputs.

Validation and benchmark:

- Hidden-eval equivalence passed before the timing run:
  `3` passed, `104` filtered.
- Native hidden eval:
  `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-phase7j-canonical-add-material-base-native.json`
  - `total_hidden_eval` p50: Phase 7I repeat `118.039ms` to `122.843ms`
  - `output_projector` p50: Phase 7I repeat `16.151ms` to `16.656ms`
  - `reference_match=true`
- Native allocation:
  `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-phase7j-canonical-add-material-base-alloc.json`
  - `profile_hidden_eval_for_clear_input`: unchanged at `4.160562MB` /
    `5,031` calls
  - `probe_checkpoint_output_projector`: unchanged at `4.160562MB` /
    `5,031` calls

Decision:

- rejected and reverted. The candidate preserved output correctness but did not
  reduce allocation, and it regressed the output-projector p50. Preparing the
  public local-mul material base is not a meaningful bottleneck after Phase 7I.

## Phase 7K: Shifted Sigma Zero-Normalization

Status:

- rejected and reverted.

Rationale:

- `small_sigma0` and `small_sigma1` validate the same public left/right zero
  words while evaluating the shifted transform for each bit.
- The candidate normalized shifted transform specs once before the bit loop,
  making shift zero data required in a resolved internal representation.
- This was byte-equivalent and low risk, but it targeted only implementation
  overhead around the message-schedule sigma slice.

Validation and benchmark:

- Hidden-eval equivalence passed before benchmarking:
  `3` passed, `104` filtered.
- Native hidden eval candidate:
  `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-phase7k-shift-normalize-native.json`
  - `message_schedule` p50: Phase 7I repeat `19.118ms` to `19.993ms`
  - `round_core` p50: `79.370ms` to `83.740ms`
  - `output_projector` p50: `16.151ms` to `16.754ms`
  - `total_hidden_eval` p50: `118.039ms` to `123.720ms`
- Native hidden eval repeat:
  `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-phase7k-shift-normalize-native-repeat.json`
  - `message_schedule` p50: `19.442ms`
  - `round_core` p50: `80.940ms`
  - `output_projector` p50: `16.372ms`
  - `total_hidden_eval` p50: `120.498ms`

Decision:

- rejected and reverted. The candidate did not improve the targeted
  `message_schedule` bucket and total hidden-eval remained slower on repeat.

## Phase 8: Backend-Versioned HSS v2 Candidate

Goal:

- define the escape hatch if byte-equivalent materialization reaches a plateau
- cover the remaining large logical-work buckets: canonical-add output
  projection, A2B carry conversion, and round-core materialization

Trigger:

- the commitment-consumption graph shows most remaining commitments are
  protocol-bound
- byte-equivalent representation slices produce only small or noisy gains
- embedded or iOS profiles show HSS remains too slow or memory-heavy
- product smoke keeps `ed25519EvaluationArtifactMs` near `500ms` after Phase
  7I, with output-projector client-base and relayer-output around `60ms` to
  `65ms` each in the worker substep split

Tasks:

- [x] Define a new backend version identifier for the next protocol lane:
      `ddh_hss_backend_v3_b2a_mul_root` in `optimization-6.md`.
- [x] Specify transcript-label changes explicitly for the next protocol lane:
      `b2a_v2/root` and `mul_v2/root` in `optimization-6.md`.
- [x] Specify provenance and commitment rules for the next protocol lane in
      `optimization-6.md`.
- [x] Write a canonical-add / output-projector v2 mini-spec before changing
      code:
  - backend identifier
  - transcript roots for `x_client_base` and `x_relayer_base`
  - retained output commitments and emitted transport bundles
  - removed intermediate commitments, if any
  - downgrade behavior for mixed v1/v2 projector material
- [x] Specify A2B v2 if needed.
- [x] Add downgrade and mismatched-backend negative tests for the retained A2B
      v2 committed-root backend.
- [x] Add output-projector negative test requirements for mismatched label,
      owner, width,
      backend version, and altered output bundle commitment.
- [x] Complete the first output-projector v2 feasibility review against the
      current output commitments, projection-mode binding, and server-tau trust
      boundary.
- [x] Add wire compatibility boundaries at request/persistence edges only for
      the retained A2B v2 committed-root backend.
- [x] Run formal verification and hidden-eval equivalence for the retained A2B
      v2 committed-root protocol
      where applicable.

Keep gate:

- meaningful latency or memory gain beyond byte-equivalent rewrite
- clear protocol review
- no widened evaluator-visible secret material
- expected product client-artifact p50 improvement above benchmark noise before
  implementation, then native, direct-WASM, and product smoke improvement after
  implementation

Canonical-add / output-projector v2 mini-spec:

- Candidate backend identifier:
  `prime_order_ddh_hidden_eval_output_projector_v2`.
- Current v1 computes `tau = (tau_client + tau_relayer) mod L`,
  `x_client_base = (a + tau) mod L`, optional masked client output, and
  `x_relayer_base = (x_client_base + tau) mod L`, then emits the same
  `canonical_seed`, `client_output`, and `x_relayer_base` bundles.
- The v2 root is `{projector_label}/output_projector_v2/root`; it binds the
  backend identifier, projection mode, scalar width, Ed25519 `L`, input
  commitments/provenance for `a`, `tau`, optional mask material, and output
  labels.
- The only candidate worth implementing is a paired projection kernel that
  removes at least one full canonical-add equivalent from the current
  client-base / relayer-base path. A naive `a + 2*tau` rewrite is insufficient
  unless it proves it removes real add/sub/select or emitted transport work.
- Retained commitments: output commitments for `canonical_seed`,
  `client_output`, and `x_relayer_base`; input commitments/provenance for
  `a`, `tau`, and optional mask; backend-version-bound projector root.
- Possible removed commitments, subject to protocol review: intermediate
  selected `x_client_base` material in client-masked mode and intermediate
  canonical-add proof material that never leaves the projector boundary.
- Negative requirements: reject mixed v1/v2 projector material, wrong backend
  version, wrong projection mode, owner, label, width, modulus id, missing mask
  binding, or altered output bundle commitment.
- Expected win before implementation: removing one full canonical-add
  equivalent could save roughly `50ms` to `65ms` p50 in product artifact
  construction, because smoke run `20260610-130323Z` measured
  output-projector client-base at `60ms` p50 and relayer-output at `65ms` p50
  in the wallet-iframe Ed25519-only worker split.
- Feasibility review: the simple `x_relayer_base = (a + 2*tau) mod L` rewrite
  is not useful under the current backend. `2*tau mod L` plus `a` still performs
  two canonical additions, and raw `a + 2*tau` is below `3L`, so it needs more
  reduction logic than the current second canonical add over two canonical
  inputs.
- The current `x_relayer_base` proof consumes committed `x_client_base`
  material. Skipping that materialization changes proof shape and must be
  backend-versioned.
- Trusted-server projection still emits `x_client_base`, and client-masked
  projection still needs canonical `x_client_base` for the blinded client
  output commitment.
- The fast `right_shared_bits` helper cannot be used for hidden server tau
  because `DdhHssSharedWord` carries both shares. It remains valid for
  client-provided mask material.
- Decision: do not implement Phase 8A as a byte-equivalent cleanup. Continue
  only if protocol review approves a paired projector root that preserves final
  output commitments while removing a full canonical add/sub/select equivalent;
  otherwise pivot to A2B v2 or larger round-core representation work.
- Follow-up from `optimization-6.md`: the first backend-versioned semantic
  paired-root implementation was benchmarked and rejected. It did not remove a
  product-visible canonical-add equivalent, and product artifact p50 regressed
  until the retained mixed shared-mask path was restored. Current retained
  state is product-neutral binding/version scaffolding plus the existing fast
  mixed-mask projector arithmetic; do not repeat the semantic projector
  rewrite without a stronger protocol shape.
- Follow-up from `optimization-6.md`: after A2B v2 retention, the next
  protocol lane is B2A / multiplication-material root v2. The draft backend id
  is `ddh_hss_backend_v3_b2a_mul_root`; root labels are `{label}/b2a_v2/root`
  and `{label}/mul_v2/root`; implementation remains blocked on protocol
  approval of the committed-root replacement bindings.

Round-core feasibility review:

- Product worker split in `20260610-130323Z` shows round core at `251ms` p50:
  `Ch` `25ms`, `Maj` `34ms`, `new_a_bits` `24ms`, `new_e_bits` `24ms`,
  `temp1` `9ms`, `temp2` `4ms`, and sigma around `7ms` each.
- The retained `CoreBitWordSide` slices already cover the safe sigma cases.
- `Ch` and `Maj` remain blocked for byte-equivalent helper rewrites because
  their operands feed multiplication-material commitments.
- `temp1`, `temp2`, and `state3` remain B2A-bound because conversion material
  hashes per-bit provenance and commitments.
- `new_a_bits` and `new_e_bits` remain A2B-bound because the current secure
  A2B proof binds arithmetic share commitments, zero material, per-bit sum
  provenance, carry multiplication material, and serial carry order.
- Decision: do not attempt another helper-level round-core scratch rewrite
  under the current backend. Meaningful round-core wins require A2B v2 or
  another backend-versioned B2A/multiplication-material root with explicit
  downgrade behavior and negative tests.

## Phase 9: Embedded And iOS Performance Profile

Goal:

- understand whether HSS should be default, optional, or policy-driven outside
  browser contexts

Target profiles:

- desktop browser with WASM worker
- mobile Safari / iOS WebView
- native iOS Rust or Swift bridge
- low-end ARM64 Linux
- embedded-class ARM board
- memory-constrained runtime with limited allocator throughput

Tasks:

- [x] Add a benchmark profile that reports wall time, peak memory estimate,
      allocation count, and artifact size.
  - [x] Record retained Phase 7E native allocation and peak-live snapshot with
        the existing allocation probe.
  - [x] Add `benchmark_ddh_hidden_eval_embedded_profile`, which combines
        stage/substage timing and allocation measurements into one compact
        native report.
- [x] Add a native release benchmark script for ARM64 Linux.
  - [x] Add `crates/ed25519-hss/scripts/run_embedded_profile_arm64_linux.sh`
        as the standard native-device runner for
        `benchmark_ddh_hidden_eval_embedded_profile`.
- [x] Add an iOS-oriented benchmark harness or documented Xcode/Swift bridge
      procedure.
  - [x] Add `crates/ed25519-hss/docs/ios-benchmark-procedure.md` with the
        physical-device, Rust-target, Xcode/Swift bridge, report, and decision
        gate procedure.
- [x] Add a low-memory stress benchmark that records allocation count and
      maximum live buffers.
  - [x] Add `benchmark_ddh_hidden_eval_memory_stress`, which reports allocation
        p50/p95/mean by operation and can fail on configured p95 budgets.
- [x] Compare local native Rust and direct browser/WASM executor snapshots.
- [ ] Compare physical-device ARM64 Linux, mobile Safari / iOS WebView, and
      native iOS bridge paths.
- [ ] Record whether HSS should be default, optional, or disabled by policy for
      each runtime class.
- [ ] Add an explicit decision gate for embedded defaults in SDK configuration.

Expected outcome:

- browser contexts likely keep HSS as the stronger default
- iOS/native secure enclave contexts may make HSS policy-driven
- embedded-class devices may require optional HSS, precompute during setup, or
  a backend-versioned compact kernel

Native embedded-profile baseline:

- Command:
  `cargo run --release --manifest-path crates/ed25519-hss/Cargo.toml --bin benchmark_ddh_hidden_eval_embedded_profile -- --stage-warmup 1 --stage-iterations 1 --stage-samples 4 --allocation-warmup 1 --allocation-samples 3 --output crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-embedded-profile-phase7i-baseline.json`
- Output:
  `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-embedded-profile-phase7i-baseline.json`
- macOS/aarch64 native p50:
  - `total_hidden_eval`: `126.740ms`
  - `round_core`: `85.404ms`
  - `message_schedule`: `20.689ms`
  - `output_projector`: `17.279ms`
  - `delivery_total`: `162.749ms`
- Largest measured allocation buckets:
  - `profile_hidden_eval_for_clear_input`: `4.160562MB`, `5,031` calls,
    `1.402285MB` peak live above start
  - `probe_checkpoint_output_projector`: same `4.160562MB`, `5,031` calls,
    `1.402285MB` peak live above start
  - `prepare_prime_order_succinct_hss`: `4.769303MB`, `17,411` calls,
    `2.247943MB` peak live above start

ARM64 Linux runner:

- Script:
  `crates/ed25519-hss/scripts/run_embedded_profile_arm64_linux.sh`
- Default output:
  `crates/ed25519-hss/docs/benchmarks/refactor-64/embedded/ddh-hidden-eval-embedded-profile-<os>-<arch>-<run>.json`
- Recommended target use:
  run the script directly on the ARM64 Linux device with
  `--require-arm64-linux` so the report reflects native CPU and allocator
  behavior.
- The script accepts the same fixture, stage, primitive, and allocation sample
  controls as the embedded profile binary.

iOS benchmark procedure:

- Procedure:
  `crates/ed25519-hss/docs/ios-benchmark-procedure.md`
- It requires physical-device release measurements and keeps simulator numbers
  as smoke-only.
- It uses the same embedded profile data model as native Linux: stage/substage
  timing, delivery timing, allocation count, peak live memory, artifact size,
  active windows, and total circuit steps.
- Native iOS and iOS WebView/WASM must be evaluated separately because their
  runtime and threat models differ.

Low-memory stress baseline:

- Command:
  `cargo run --release --manifest-path crates/ed25519-hss/Cargo.toml --bin benchmark_ddh_hidden_eval_memory_stress -- --warmup 1 --samples 3 --max-hidden-eval-allocated-bytes 5000000 --max-hidden-eval-allocation-calls 6000 --max-hidden-eval-peak-live-bytes 2000000 --max-prepare-allocated-bytes 6000000 --max-prepare-allocation-calls 20000 --max-prepare-peak-live-bytes 3000000 --output crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-memory-stress-phase7i-baseline.json`
- Output:
  `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-memory-stress-phase7i-baseline.json`
- macOS/aarch64 baseline budgets passed:
  - hidden eval p95: `4.160562MB`, `5,031` calls, `1.402285MB` peak live
  - prepare p95: `4.769303MB`, `17,411` calls, `2.247943MB` peak live
- Embedded or iOS budget gates should be set from physical-device profiles, not
  from this desktop baseline alone.

Benchmark artifact location:

- Refactor-64 HSS-local benchmark artifacts live under
  `crates/ed25519-hss/docs/benchmarks/refactor-64/`.
- Product registration-flow benchmark artifacts remain under top-level
  `benchmarks/registration-flow/out/` and `docs/benchmarks/registration-flow.md`.

Local native versus direct-WASM snapshot:

- Native macOS/aarch64 embedded profile:
  `total_hidden_eval` p50 `126.740ms`, `output_projector` p50 `17.279ms`,
  and hidden-eval allocation p95 `4.160562MB` across `5,031` calls.
- Direct browser/WASM retained Phase 7I snapshot:
  browser worker-handle wall p50 `187.9ms`, browser hidden-eval p50
  `175.75ms`, and browser output-projector p50 `30.25ms`.
- Physical ARM64 Linux, mobile Safari / iOS WebView, and native iOS bridge
  data remain pending because those measurements need target hardware.

Executor-IR guard validation:

- `cargo test --manifest-path crates/ed25519-hss/Cargo.toml --test
  materialization_graph_guard`: passed, `2` tests. Re-run after the
  executor-IR guard slice passed, `2` tests. Re-run after the stage-identity
  slice passed, `2` tests.
- `cargo test --manifest-path crates/ed25519-hss/Cargo.toml core_pair --lib`:
  passed, `1` test. Re-run after the stage-identity slice passed, `1` test.
- `cargo test --manifest-path crates/ed25519-hss/Cargo.toml
  core_bit_word_pair --lib`: passed, `1` test. Re-run after the stage-identity
  slice passed, `1` test.
- `cargo test --manifest-path crates/ed25519-hss/Cargo.toml
  hidden_eval_equivalence`: passed, `3` tests. Re-run after the stage-identity
  slice passed, `3` tests.
- `cargo test --manifest-path crates/ed25519-hss/Cargo.toml`: passed, `119`
  tests, `4` ignored. Re-run after the stage-identity slice passed, `119`
  tests, `4` ignored.
- `cargo hss-fv verus-check`: passed after removing the unused test-only
  `CoreBitWordStage` variant; Verus reported `96` verified and `0` errors,
  and anti-drift reported `10` passed.
- Post round-sigma B2A rejection validation:
  - `cargo test --manifest-path crates/ed25519-hss/Cargo.toml
    hidden_eval --lib`: passed, `17` tests.
  - `cargo test --manifest-path crates/ed25519-hss/Cargo.toml --features
    hss-physical-counters hidden_eval_equivalence`: passed, `3` tests.
  - `cargo test --manifest-path crates/ed25519-hss/Cargo.toml --test
    materialization_graph_guard`: passed, `2` tests after deleting stale
    `materialize_sigma0` / `materialize_sigma1` guard entries.
  - `cargo test --manifest-path crates/ed25519-hss/Cargo.toml`: passed,
    `128` tests, `4` ignored.
  - `cargo hss-fv verus-check`: passed; Verus reported `96` verified and
    `0` errors, and anti-drift reported `10` passed.
- Post arena-candidate byte-equivalence harness validation:
  - `cargo test --manifest-path crates/ed25519-hss/Cargo.toml
    hidden_eval_equivalence`: passed, `2` tests.
  - `cargo test --manifest-path crates/ed25519-hss/Cargo.toml
    arena_scalar_reduction_and_canonical_add_byte_equivalence_fixtures`:
    passed, `1` test.
  - `cargo test --manifest-path crates/ed25519-hss/Cargo.toml --test
    materialization_graph_guard`: passed, `2` tests.
- Direct HSS browser/WASM after the `CoreBitWordStage` guard slice:
  - rebuilt `web/generated/pkg` with `wasm-pack build crates/ed25519-hss
    --target web --out-dir web/generated/pkg --release --no-typescript
    --features browser-benchmark`
  - regenerated the browser benchmark bundle with
    `cargo run --manifest-path crates/ed25519-hss/Cargo.toml --bin
    emit_browser_cache_benchmark_bundle -- --output-dir
    crates/ed25519-hss/web/generated`
  - output:
    `crates/ed25519-hss/docs/benchmarks/refactor-64/optimization-5/browser-ddh-hidden-eval-corebit-stage-identity-refreshed-bundle.json`
  - `browser_ddh_reference_match`: `true`
  - browser hidden-eval mean/median/p95:
    `194.867ms` / `186.300ms` / `213.100ms`
  - stage timings: round core `134.400ms`, message schedule `29.000ms`,
    output projector `47.800ms`
  - operation counts matched the retained A2B v2 report, so this is timing
    variance or guard-slice overhead, not a logical materialization change.
- Native hidden-eval after the `CoreBitWordStage` guard slice:
  - output:
    `crates/ed25519-hss/docs/benchmarks/refactor-64/optimization-5/ddh-hidden-eval-corebit-stage-identity.json`
  - repeat output:
    `crates/ed25519-hss/docs/benchmarks/refactor-64/optimization-5/ddh-hidden-eval-corebit-stage-identity-repeat.json`
  - p50 `total_hidden_eval`: `122.902ms`, repeat `125.119ms`
  - p50 `round_core`: `82.254ms`, repeat `84.149ms`
  - interpretation: keep the stage identity slice as type/validation hardening.
    Do not run product smoke for this slice because the lower-level benchmark
    does not improve against the retained A2B v2 baseline.

## Phase 10: Validation And Formal Checks

Tasks:

- [x] Run `cargo test --manifest-path crates/ed25519-hss/Cargo.toml
      hidden_eval_equivalence` after each slice.
- [x] Run full `cargo test --manifest-path crates/ed25519-hss/Cargo.toml`
      before retaining any slice.
- [x] Run `cargo hss-fv verus-check` after retained crypto-kernel changes.
- [x] Run direct HSS WASM artifact benchmarks before product smoke.
- [ ] Run product registration smoke only after lower-level gates pass.
- [x] Run source guards for materialization graph drift.
- [x] Document every rejected candidate with benchmark output and reason in
      `optimization-experiment-ledger.md`.

## Keep And Revert Rules

Keep a slice only if:

- hidden-eval equivalence passes
- constant-time review finds no new secret-dependent behavior
- transcript labels and provenance stay byte-identical for byte-equivalent
  slices, or the protocol-kernel transcript change is explicitly specced and
  validated
- native and direct-WASM benchmarks move in a compatible direction
- product registration smoke confirms a real artifact-path win
- complexity is proportional to the measured improvement

Revert or redesign if:

- the win is allocation-only and product timing regresses
- direct-WASM regresses materially
- the change depends on diagnostic state
- the code introduces duplicate production paths
- commitments are skipped where the graph says they are consumed
- the rewrite makes protocol review harder without measurable gain

## Current Todo

- [x] Build the commitment-consumption graph.
- [x] Add materialization and commitment counters.
  - [x] Add browser/direct-WASM counter fields.
- [ ] Define executor IR type boundaries.
  - [x] Land the `CoreBitWordPair` round-sigma slice.
  - [x] Add core-shape source guards and invalid-conversion tests for
        `CoreBitWordPair` materialization.
  - [x] Add explicit `CoreBitWordStage` identity to core sides/pairs and reject
        wrong-stage materialization.
- [x] Implement the message-schedule end-to-end slice.
  - [x] Land the native core-sigma B2A boundary.
  - [x] Compare native allocation pressure against `HEAD`.
  - [x] Restore crate-local direct-WASM/browser benchmark exports.
  - [x] Confirm direct-WASM/browser timing.
  - [x] Run product registration smoke after lower-level changes are ready to
        cross the crate boundary.
- [ ] Implement the round-core boundary slice only after the graph identifies a
      safe target.
  - [x] Add direct browser round-core pressure counters.
  - [x] Split round-core into shared sub-kernel helpers.
  - [x] Add secure A2B public label scratch reuse.
  - [x] Retain carry-gate material-base reuse after byte-equivalence,
        direct-WASM, native, and product smoke benchmarks.
  - [x] Retain borrow-path material-base reuse after byte-equivalence,
        direct-WASM, native, product smoke, and product smoke repeat.
  - [x] Reject round-sigma B2A-boundary materialization after physical counters
        stayed flat, native p50 regressed, and allocation calls increased.
- [x] Draft A2B v2 only if byte-equivalent A2B is blocked by protocol-bound
      commitments.
  - [x] Add explicit carry-order and downgrade negative tests with the A2B v2
        transcript root before implementation.
  - [x] Record internal A2B v2 review decision.
  - [x] Write the A2B v2 protocol-review package.
  - [x] Record that A2B v2 is not implementation-ready with a digest-only root.
  - [x] Protocol-review A2B v2 root, material digest, and retained commitment
        rules before implementation.
- [x] Draft output-projector rewrite only if it reduces logical
      materialization.
  - [x] Classify output-projector transport/core boundaries.
  - [x] Retain byte-equivalent output-projector label-buffer slice after native
        and direct-WASM benchmarks.
  - [x] Reject direct output canonicalization after product smoke regressed.
  - [x] Resolve the SDK TypeScript `BufferSource` rebuild blocker that
        prevented the post-revert product smoke rerun.
  - [x] Re-run product smoke for the reverted Phase 7 state after SDK
        TypeScript errors are resolved.
  - [x] Reject the diagnostic stage-operation-count opt-out after native and
        product smoke both regressed.
  - [x] Implement the Phase 7B staged output boundary only after adding
        output-bundle byte-equivalence fixtures.
  - [x] Benchmark Phase 7B native and direct browser/WASM before deciding
        whether product smoke is justified.
  - [x] Run product smoke for Phase 7B and retain the staged output boundary
        after product client-artifact p50 improved.
  - [x] Retain Phase 7C repeated-selector select batch after byte-equivalence,
        native/direct-WASM benchmarks, allocation probe, and product smoke.
  - [x] Review deeper output-projector representation and defer under the
        current backend because scalar reduction/add/select still consume
        commitment-bearing local words.
  - [x] Reject Phase 7F select scratch reduction after equivalence and native
        benchmark regression.
  - [x] Reject Phase 7G validated local-word accessor after equivalence and
        native benchmark regression.
  - [x] Reject Phase 7H output-projector scratch arena after allocation
        improved but native latency regressed.
  - [x] Reject Phase 7J canonical-add material-base reuse after hidden-eval
        equivalence passed but native timing regressed and allocation stayed
        flat.
  - [x] Reject Phase 7K shifted sigma zero-normalization after hidden-eval
        equivalence passed but native message-schedule and total hidden-eval
        p50 regressed.
  - [x] Decide the next output-projector representation only if it reduces
        logical local words, commitment/provenance derivations, or scalar
        reduction work.
  - [ ] Design a deeper output-projector representation only if it can reduce
        logical local words, commitment/provenance derivations, or scalar
        reduction work.
- [x] Add embedded and iOS benchmark profiles.
- [x] Move refactor-64 HSS benchmark artifacts to the crate-local benchmark
      directory.
- [x] Add wallet-iframe transport diagnostics and confirm transport is
      secondary to passkey prompt time and HSS client artifact construction in
      smoke run `20260610-130323Z`.
- [ ] Compare physical ARM64 Linux, mobile Safari / iOS WebView, and native
      iOS bridge measurements against the local native/direct-WASM snapshot.
- [ ] Decide whether embedded HSS is default, optional, or policy-gated.

Current output-projector decision:

- No further current-backend output-projector representation slice is justified
  from the available evidence. Phase 7F, 7H, 7J, and 7K show that allocation
  cleanup, direct canonicalization, select scratch, and canonical-add base reuse
  either regress latency or fail to reduce the logical transcript work.
- The next output-projector attempt should be a protocol-reviewed backend
  change that removes commitment/provenance derivations or scalar-reduction
  work. Otherwise, the next latency lane should stay on B2A/multiplication-root
  protocol work or registration-path overlap/precompute.

## Immediate Next Steps

Backend-versioned protocol-kernel implementation now lives in
`crates/ed25519-hss/docs/optimization-6.md`. Use this document as the
historical/current-backend optimization record and use optimization 6 for A2B
v2 or reviewed output-projector root-v2 implementation work.

June 11 update: `optimization-6.md` now owns the live A2B v2 committed-root
candidate. The BLAKE3-base carry-material version improved native hidden-eval
p50 to `118.436ms` from the scaffold baseline `126.177ms`; direct browser/WASM
also improved to `170.5ms` mean from the typed-backend reference `200.867ms`.
Product registration smoke `20260610-170749Z` passed all four scenarios and
moved `ed25519EvaluationArtifactMs` p50 to `445/445/443/443ms`. The legacy
backend and A2B kernel enum variants were deleted, stale backend wire strings
now fail during serialized driver-state and staged-artifact deserialization,
and A2B v2 rejects wrong-index carry material before carry-gate multiplication.

1. Use `crates/ed25519-hss/docs/benchmarks/refactor-64/` as the canonical
   location for HSS-local refactor-64 benchmark outputs.
2. Treat A2B v2 committed-root as retained in `optimization-6.md`; focused
   downgrade, carry-order, emitted-commitment, and semantic width tests now
   pass.
3. Treat product smoke `20260610-170749Z` as the retained A2B v2 HSS product
   baseline, and use smoke run `20260610-130323Z` for wallet-iframe transport
   ranking. Avoid diagnostics-only operation-count changes.
4. Do not continue small output-select or accessor micro-edits. Phase 7F and
   Phase 7G both regressed at the native gate.
5. Phase 7J canonical-add material-base reuse was rejected and reverted after
   native timing regressed and allocation stayed flat.
6. Stop output-projector setup micro-edits unless the candidate removes logical
   scalar-reduction/addition work or emitted transport work.
7. Do not retry shifted sigma zero-normalization; Phase 7K regressed the
   message-schedule and total hidden-eval native p50.
8. Move the next optimization attempt to a reviewed backend-versioned
   canonical-add/scalar-reduction/B2A candidate, a larger round-core
   stage-owned storage design with a specific commitment-boundary proof, or
   registration-path parallel/precompute work from refactor-61/62/66.
9. If the output projector cannot reduce logical work under byte-equivalence,
   move back to larger round-core stage-owned storage or a reviewed
   backend-versioned A2B/canonical-add/scalar-reduction candidate.
10. Current-backend round-core helper rewrites are not approved after the Phase
    8B audit. A2B v2 is retained, so the next HSS-runtime implementation
    requires protocol review of either an output-projector root-v2 replacement
    or a new B2A/multiplication-material root. The retained
    `output_projector_binding_v1` scaffold is only hardening and future-version
    plumbing.
11. Collect physical ARM64 Linux and iOS measurements before deciding embedded
   default policy.

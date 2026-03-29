# Succinct-Garbling Security Refactor Plan

## Goal

Eliminate the production execution pattern where the client/evaluator holds a
joined hidden value that contains both share halves.

The original issue is not just `DdhHssSharedWord`. It is any production
evaluator-visible value that carries both:

- `left_word`
- `right_word`

That includes the current `DdhHssDerivedWord` model.

The refactor is complete only when production evaluator execution no longer
depends on joined hidden values during the hot path.

## Security Problem Statement

Today, the normal evaluator flow is narrower than before, but production hidden
evaluation still advances through joined in-memory values. That means:

- the evaluator still holds both share halves in one runtime object
- stage boundaries still rejoin left/right state into one production value
- the trust boundary is improved, but not yet truly role-local

What must be true at the end:

- the evaluator never needs a production value that directly contains both
  relayer share halves
- joined values exist only in trusted simulation, test, or explicitly trusted
  profiling code
- production execution uses split/local representations end-to-end through the
  hot arithmetic path

## Non-Goals

This refactor is not trying to:

- optimize performance first
- preserve old helper surfaces for compatibility
- keep duplicate joined and split production paths alive
- improve the broader SSR roadmap priority

Breaking changes and cleanup are expected.

## Correctness-First Rule

This is a correctness-first executor/backend rewrite.

Implementation order must follow this rule:

1. define the backend value model and semantics first
2. prove the new local/split operations are correct in unit tests
3. port one executor slice at a time onto that model
4. only after the model is stable should we optimize it

Do not accept shortcuts that:

- preserve joined hot-path values just to keep benchmarks low during bring-up
- optimize old joined helpers that are going away
- add compatibility layers that hide whether execution is actually split/local

The benchmark gate still matters, but it is subordinate to semantic
correctness during this rewrite.

## Target Architecture

### 1. Boundary-only joined values

`DdhHssSharedWord` and `DdhHssDerivedWord` should only exist at:

- input delivery boundaries
- output projection boundaries
- trusted simulation/test helpers

They must not be the production hot-path value model.

### 2. Production local/split stage values

Production evaluator arithmetic should run on role-local vector-like values,
not per-bit joined words.

Minimum target shape:

- evaluator-local bit-vector or word-slice type
- garbler-local bit-vector or word-slice type
- helpers that operate over whole slices or words without rejoining per bit

The important property is semantic, not the exact Rust type name:

- production local values carry one side only
- stage outputs remain split/local until an explicit boundary rejoin

### 3. Stage-local arithmetic kernels

The core arithmetic path should be expressed as stage-local kernels:

- xor over local slices
- rotate/reindex over local slices
- batched Beaver-mul over local slices
- carry propagation over local slices

The executor should not rebuild per-bit joined objects inside those kernels.

## Current State

Already improved:

- server-input packet handling is narrower
- server output stays split longer
- `Ch` and `Maj` now have whole-stage local/split slices
- the main carry helper now advances carry as local left/right words
- the transport-backed adder now uses the same local/split carry model
- Beaver material for local multiplication is now derived from split/local
  operands without rejoining first
- add-stage output now feeds the message schedule as split/local stage state
- message schedule stays split/local across the full stage
- round core stays split/local across the full round path
- output-projector scalar reduction and canonical mod-`l` addition now stay
  split/local until the final output boundary
- the production constant pool now materializes split/local words directly
- client ingress now converts shared input bundles to split/local once at stage
  entry instead of rebuilding joined derived bits
- final output bundles are now rebuilt directly from split/local words at the
  boundary without a derived-word detour
- joined-derived conversion helpers are now test-only and no longer available
  to production call sites
- executor-local split words now use dedicated bit-vector side storage instead
  of `DdhHssLocalBitSlice` as the internal stage container
- executor-local split words now pack share bits instead of storing one byte
  per bit in the hot-path container
- the hot executor helpers no longer convert split-local storage back into the
  deprecated `DdhHssLocalBitSlice` adapter model for xor or mul
- sigma, `Ch`, and `Maj` kernels now synthesize directly on packed split/local
  stage storage instead of materializing temporary rotated stage words first
- the output projector now extracts the clamped scalar directly into one packed
  split/local word instead of bouncing through temporary byte words and a
  flatten pass
- paired local xor now derives provenance and commitments once per left/right
  share pair in the hot executor paths instead of hashing the same metadata
  twice
- Beaver multiplication in the independent-bit executor kernels now reuses one
  initialized material-derivation base across whole local slices instead of
  rebuilding that shared hashing setup independently for each bit gate

Still unresolved:

- joined value types still exist in trusted simulation/tests and a few
  boundary-only helpers

## Rewrite Plan

### Phase 0. Freeze and clean the checkpoint

Purpose:

- stop incremental boundary surgery
- establish one security-first baseline before the larger rewrite

Tasks:

- [x] remove dead joined compatibility helpers as they become unused
- [x] keep one production path only
- [x] keep security and benchmark notes current

Exit criteria:

- no duplicate legacy production helpers remain for the already-ported seams

### Phase 1. Backend model rewrite

Purpose:

- define the real production value model before more executor work

Tasks:

- [x] introduce dedicated production local vector types in
  `crates/succinct-garbling/src/ddh_hss.rs`
- [x] make the representation explicit and executor-oriented:
  - one side’s shares
  - one side’s commitments
  - one side’s provenance payload
- [x] define the minimum backend surface for executor bring-up:
  - `xor`
  - `rotate`
  - `constant_xor`
  - `and_beaver_batch`
  - carry propagation over a full word
  - explicit boundary rejoin helpers only where unavoidable
- [x] separate trusted simulation helpers from production helpers at the type level

Correctness gates:

- unit tests for every vector operation against the existing joined model
- equivalence tests for:
  - xor
  - rotation/reindex
  - batched Beaver multiply
  - carry propagation over full words

Exit criteria:

- the new backend surface is sufficient for one executor stage without using
  joined per-bit production values

### Phase 2. First executor rewrite slice

Purpose:

- prove the new backend model can drive a real executor stage end-to-end

Tasks:

- [x] choose one bounded stage and port it fully to the new vector model
- [x] prefer the dominant arithmetic seam:
  - full word addition / carry propagation
- [x] keep the entire stage on the vector model internally
- [x] allow rejoin only at the stage output boundary if still necessary

Correctness gates:

- stage-level equivalence tests against the current joined implementation
- property tests on random words and wraparound cases

Exit criteria:

- one production executor stage is fully on the new vector model
- no per-bit joined values are rebuilt inside that stage

### Phase 3. Message schedule rewrite

Purpose:

- remove joined values from the first major hot path after the carry stage

Tasks:

- [x] port small-sigma helpers to vector operations
- [x] port schedule accumulation to vector carry/add helpers
- [x] keep schedule words split/local across the full stage

Correctness gates:

- schedule word-for-word equivalence against the current implementation
- full fixture equivalence tests at the schedule boundary

Exit criteria:

- message schedule no longer advances through `Vec<DdhHssDerivedWord>` in the
  production hot path

### Phase 4. Round-core rewrite

Purpose:

- remove joined values from the main SHA-512 round path

Tasks:

- [x] port:
  - `Sigma0`
  - `Sigma1`
  - `Ch`
  - `Maj`
  - `temp1`
  - `temp2`
  - state update
- [x] keep round state split/local across the round
- [x] minimize or eliminate stage-boundary rejoins introduced during bring-up

Correctness gates:

- per-round state equivalence
- full hidden-eval output equivalence on the fixture corpus

Exit criteria:

- round core no longer advances through joined production words

### Phase 5. Boundary cleanup

Purpose:

- make joined runtime values boundary-only in practice, not just in comments

Tasks:

- [x] restrict `DdhHssDerivedWord` and `DdhHssSharedWord` usage to:
  - transport and bundle boundaries
  - output projection boundaries
  - trusted simulation/tests
- [x] delete any remaining production executor helper that requires joined words
- [x] tighten visibility where possible

Correctness gates:

- negative tests proving production paths cannot call trusted joined helpers
- no production call site depends on joined hot-path values

Exit criteria:

- the production hidden-eval hot path no longer uses joined hidden value types

### Phase 6. Optimization of the hardened model

Purpose:

- recover performance after the semantics are correct and stable

Tasks:

- [x] dedicated executor-local bit-vector storage for split stage words
- [x] packed bit storage
- [x] remove hot-path adapter churn back into deprecated local bit-slice helpers
- [x] fused stage kernels
- [x] fewer stage-boundary rejoins
- [x] reused Beaver material across whole slices
- [x] lower-overhead provenance/commitment derivation inside local kernels

Exit criteria:

- optimization work targets only the new hardened model, not deprecated joined
  helpers

### Phase 7. Optional Benchmark-Gated Optimization Campaign

Purpose:

- optimize the hardened split/local protocol without reopening security
  boundaries
- make every performance change earn its keep with measured results
- this phase is not required for the security refactor to be considered
  complete

Rules:

1. implement exactly one bounded optimization step at a time
2. run the benchmark suite immediately after that step
3. keep the step only if it improves the measured baseline or clearly improves
   memory behavior without regressing total runtime
4. proceed to the next step only after recording the result of the previous step
5. do not batch multiple speculative optimizations into one measurement step

Benchmark gate for every step:

- run correctness tests first:
  - `cargo test --manifest-path crates/succinct-garbling/Cargo.toml --lib -- --nocapture`
  - `cargo test --manifest-path crates/succinct-garbling/Cargo.toml --lib prime_order_succinct_hss_matches_reference_fixture_smoke -- --ignored --nocapture`
- run the benchmark suite and record the result in
  `crates/succinct-garbling/optimization.md`
- compare against the most recent accepted baseline before keeping the change

Phases:

#### Phase 7A. Establish the post-refactor baseline

Tasks:

- [x] rerun native release hidden-eval benchmarks on the hardened split/local path
- [x] rerun browser hidden-eval benchmarks on the hardened split/local path
- [x] record the new baseline in `crates/succinct-garbling/optimization.md`
- [x] identify the hottest remaining split/local kernels from measured output,
  not guesswork

Exit criteria:

- there is one current post-refactor baseline for both native and browser runs
- the next optimization step is chosen from measured hot spots

#### Phase 7B. Bounded optimization loop

Per-step workflow:

1. choose one bounded optimization candidate
2. implement that candidate only
3. run correctness tests
4. run native and browser benchmarks
5. keep the change only if the benchmark result improves or holds neutral with
   a clear secondary win
6. record the result before starting the next candidate

Candidate queue:

- [x] reuse Beaver material across whole local slices where gate labels and
  provenance semantics remain valid
- [x] lower provenance and commitment derivation overhead inside local kernels
- [ ] reduce per-bit label construction overhead in the hottest loops
  - focus first on `round_core/{round}/temp1`, carry propagation, `sum`,
    `carry`, and `next_carry` label churn in the split/local add helpers
  - prefer precomputed stable label prefixes or cheaper label assembly over
    broad helper rewrites
- [ ] lower digest setup overhead in hot local arithmetic helpers
  - target per-gate digest initialization in local xor, add, and mul helpers
  - reuse prefix state only when it avoids extra vector staging and holds up in
    both native and browser runs
- [ ] reintroduce scratch reuse inside packed split/local arithmetic helpers
  - retry only if a narrower helper-local reuse plan exists
  - do not reintroduce broad scratch plumbing that already regressed
- [ ] fuse additional packed split/local kernels only where benchmarks show a
  real bottleneck
  - avoid another whole-slice xor batching pass
  - prefer a narrow `temp1`-specific or carry-specific fusion if a trace points
    to one exact seam
- [ ] reduce allocation and cloning in output bundle reconstruction if it shows
  up in measured profiles
  - keep this behind measured evidence because current profiles still point at
    `round_core`, not result assembly

Extended future todo list if the optional campaign is reopened:

1. Profile `round_core` and `round_temp1` again before writing code so the next
   candidate is chosen from fresh traces, not stale intuition.
2. Try one label-construction candidate only, then rerun correctness, native,
   and browser gates.
3. If label work does not help, move to one digest-prefix candidate in the hot
   local arithmetic helpers.
4. Only after that, retry any fusion work, and keep it scoped to one measured
   seam rather than a slice-wide wrapper pass.
5. Defer output bundle reconstruction work until a profile shows it materially
   contributes to end-to-end time.
6. After every accepted step, update `crates/succinct-garbling/optimization.md`
   before starting the next candidate.

Measured next hotspot after the published post-hardening checkpoint:

- `round_core` remains the dominant stage in both native and browser runs
- `round_temp1` remains the largest measured round-core substage

Exit criteria:

- every accepted optimization step has a recorded benchmark delta
- no accepted optimization step weakens the split/local security boundary

#### Phase 7C. Stop condition and checkpointing

Tasks:

- [x] stop when the next bounded candidate fails to improve the current baseline
- [x] publish the accepted optimization checkpoint in
  `crates/succinct-garbling/optimization.md`
- [x] summarize which candidates were kept, reverted, or deferred

Status:

- Phase 7 is paused at the current accepted checkpoint by choice
- the optional campaign already hit multiple rejected candidates, so there is
  no reason to keep tuning without a new optimization direction
- if optimization work resumes, restart from the extended Phase 7B todo list
  above instead of retrying already-rejected broad candidates

Exit criteria:

- optimization work stops on measured plateau rather than open-ended tuning
- the optimization log reflects the current accepted checkpoint

## Keep/Revert Rule

Because this is a correctness-first security refactor, regressions are allowed
when they remove real joined production execution and move the code toward the
final executor/backend model.

Keep a change if:

- it is semantically correct
- it removes a real production joined-value seam
- correctness tests pass
- the new structure is clearly on the path to the final model

Revert a change if:

- it is not yet correct
- it is wrapper-only or constructor-only
- it does not reduce evaluator capability
- it keeps duplicate old and new production paths alive

## Completion Criteria

This security refactor is complete only when all of the following are true:

- production evaluator execution no longer holds joined hidden values in the
  hot path
- production message schedule and round core do not depend on
  `DdhHssDerivedWord` or `DdhHssSharedWord`
- joined hidden values are restricted to boundaries and trusted-only code
- the old joined production helpers have been deleted
- if optional optimization work is pursued, it targets only the hardened
  executor/backend model

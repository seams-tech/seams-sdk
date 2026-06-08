# HSS Protocol And Runtime Latency

Date created: June 8, 2026

Status: active; first hot-loop candidate benchmarked and rejected; direct WASM
artifact benchmark, logical object counters, and server ceremony sub-bucket
timings added.

## Goal

Make Ed25519 HSS registration fast enough that choosing HSS is primarily a
trust-model decision, not a latency compromise.

The near-term target is to cut HSS critical-path runtime significantly while
preserving protocol correctness, transcript binding, provenance where required,
and constant-time behavior. The longer-term target is to make HSS viable on
browser, native, iOS, and selected embedded runtimes.

This plan follows Path A: preserve the current HSS trust model. Exportability
and threshold-at-registration are requirements. Do not replace HSS with a flow
where the client creates the full Ed25519 seed, computes the full scalar, and
then splits or seals a server component. That path preserves exportability, but
it collapses the threshold property at registration because the client
temporarily knows the full export seed and signing scalar.

## Relationship To Existing Plans

- `docs/refactor-55-hss-optimize-registration.md` owns the registration-specific
  HSS optimization history and current Phase E1 A2B/boolean-helper spec.
- `docs/refactor-59-optimize.md` owns full registration benchmarking and the
  measured `1500ms` registration target gap.
- `docs/refactor-65-hss-optional.md` owns optional bootstrap profiles for
  runtimes where HSS should not be mandatory.
- This plan owns deeper HSS protocol/runtime performance work.

## Current Read

Latest retained registration benchmark:

- scenarios: four smoke scenarios, five successful runs each
- baseline before finalize cache fast path: `20260608-030241Z`
- latest retained run after finalize cache fast path: `20260608-051326Z`
- latest instrumentation run: `20260608-053047Z`
- SDK registration total: `1933ms` to `2134ms` p50 across the smoke scenarios
- browser-observed total: `2816ms` to `3228ms` p50 across the smoke scenarios
- HSS client evaluation artifact: `666ms` to `673ms` p50
- `/wallets/register/start`: server total `371ms` to `373ms` p50, dominated by
  HSS prepare at `370ms` to `372ms` p50
- start-route split: signing-root server-input derivation is `366ms` to
  `368ms` p50 and server-session preparation is `356ms` to `359ms` p50; they
  run in parallel, so both branches matter
- server-session preparation split: `prepare_prime_order_succinct_hss` accounts
  for `354ms` to `357ms` p50; driver-state extraction, client offer creation,
  caching, and state encoding are each single-digit milliseconds
- `/wallets/register/hss/respond`: server total `94ms` to `109ms` p50,
  dominated by server-input delivery preparation at `73ms` to `74ms` p50
- `/wallets/register/finalize`: server total `216ms` to `222ms` p50 after
  reusing the cached prepared server session
- HSS finalize sub-buckets: serialized server-session materialization is now
  `0ms` p50 on the product path because the cached prepared server session is
  reused; artifact decode, report finalization, and report encoding are each
  single digit milliseconds

Latest fine-grained client-owned hidden-eval ranking:

- `hiddenEvalRoundCoreMs`: p50 roughly `296ms` to `301ms`
- `hiddenEvalOutputProjectorMs`: p50 roughly `270ms` to `281ms`
- `hiddenEvalMessageScheduleMs`: p50 roughly `58ms` to `59ms`
- inside round core:
  - `hiddenEvalRoundNewABitsMs`: about `45ms` to `46ms` p50
  - `hiddenEvalRoundNewEBitsMs`: about `45ms` to `46ms` p50
  - `hiddenEvalRoundMajMs`: about `38ms` to `39ms` p50
  - `hiddenEvalRoundChMs`: about `31ms` to `32ms` p50

Interpretation:

- worker transport, decode, materialization, and encode are now secondary for
  the retained browser-worker path
- small label-buffer cleanups helped, but they will not reach a `1500ms` full
  registration target by themselves
- significant wins require attacking hidden-eval representation, hashing,
  allocation, A2B/carry conversion, output projection, or protocol shape
- the first A2B destination-reuse experiment improved native p50 but did not
  improve the browser/WASM HSS worker path, so no code from that candidate is
  retained
- a direct Ed25519 HSS WASM artifact benchmark now exists at
  `benchmarks/ed25519-hss-wasm`; baseline run
  `2026-06-08T01-36-06-388Z` measured `node_client_artifact_worker_handle_wasm`
  at 690.641ms p50 and `browser_client_artifact_worker_handle_wasm` at
  339.650ms p50
- logical hidden-eval object counters now flow through the client artifact
  benchmark; smoke run `2026-06-08T01-58-13-255Z` reported 12,800 local-word
  materializations, 1,024 shared-word materializations, 1,536 transport-word
  materializations, 17,928 commitment materializations, 15,360 provenance digest
  materializations, and 57,128 logical label writes per artifact
- the client-owned artifact path now uses a one-shot production hidden-eval
  helper that skips checkpoint digest retention; smoke run
  `2026-06-08T02-11-25-255Z` was mixed and should not be treated as a latency
  win by itself
- server-owned ceremony diagnostics now expose OT reconstruction, server input
  open/share/commitment/transcript, result assembly, and output sealing
  finalization buckets; finalize diagnostics expose artifact decode, serialized
  server-session materialization, report finalization, and report encoding
  buckets
- registration product-path diagnostics now include
  `wallets_register_hss_respond`; the normal registration flow uses the
  role-separated server-input-delivery path, while the server-owned ceremony
  buckets apply to same-process/server-owned artifact export paths
- the finalize fast path reuses the cached prepared server session when the
  staged artifact arrives as bytes; this removed about `241ms` to `244ms` p50
  from the product finalize route
- the next registration-path bottlenecks are client artifact construction,
  signing-root server-input derivation, and core HSS session preparation; HSS
  respond is useful to keep instrumented, but it is already relatively small
- treat the direct browser artifact benchmark as a per-artifact lower bound;
  keep `benchmark:registration-flow:smoke` as the product-path benchmark

## Constraints

HSS is cryptographic code. Every optimization must preserve:

- export-compatible Ed25519 seed semantics
- the hidden seed path `y_client + y_relayer -> d -> SHA-512(d) -> clamp -> a`
- threshold-at-registration: neither client nor server learns plaintext `d` or
  plaintext `a`
- the server-blind deployed boundary where the server does not receive the
  client's recoverable secret or client output mask
- no secret-dependent branches
- no secret-dependent indexing
- no secret-dependent allocation sizes
- no variable-time arithmetic on secret-derived values
- fixed public loop bounds for SHA-512 words, rounds, and validated stage counts
- transcript label and gate schedule stability unless the backend version is
  deliberately changed
- route and persistence compatibility only at explicit boundaries

Diagnostics must remain observational and must never influence control flow.

Out of scope for this plan:

- non-exportable additive scalar-share bootstrap
- client-origin exportable seed split where the client materializes `d` and `a`
  before assigning a server share
- server-origin exportable seed split where the server materializes `d` and `a`
  before assigning a client share
- any protocol that makes either participant able to reconstruct the full
  export seed during registration

Those profiles can be discussed in optional-bootstrap planning only if their
trust model is explicitly different from HSS.

## Approach A: Measurement And Profiling First

Goal:

- replace aggregate timing with enough evidence to choose the right runtime or
  protocol change

Tasks:

- [ ] add a native Rust HSS registration benchmark that bypasses browser/WASM
      and route overhead
- [x] add a WASM-only benchmark for
      `build_client_owned_staged_evaluator_artifact`
- [x] add logical object/materialization counters for hidden-eval execution
- [x] add counters for `DdhHssLocalWord`-shape materializations, commitments,
      provenance digest materializations, and logical label generation
- [ ] add native allocator byte counters or heap-profiler instructions if
      logical counters make object churn the next limiting factor
- [ ] add native flamegraph support for `crates/ed25519-hss`
- [ ] add optional browser/WASM profiling instructions for Chrome performance
      traces
- [ ] capture peak memory and payload sizes for client prepare, respond,
      evaluate, and finalize
- [x] split server prepare/finalize timing into protocol sub-buckets
- [x] split registration start timing into server-input derivation and
      server-session preparation branch timings
- [x] record baseline results in `docs/benchmarks/registration-flow.md` or a new
      HSS-specific benchmark report

Keep rule:

- always keep profiling if it is diagnostics-only and does not change protocol
  behavior

## Approach B: Production Representation Audit

Goal:

- identify which labels, commitments, provenance digests, and checkpoint data
  are required for production security versus testing, diagnostics, or protocol
  validation

Tasks:

- [x] classify every digest and commitment in hidden-eval execution as one of:
      security-critical, transcript-binding, validation-only, diagnostics-only,
      or redundant
- [x] identify which fields must be byte-identical for protocol compatibility
- [x] identify which fields can move behind a debug/profile build feature
- [x] identify which fields can be compacted without changing public protocol
      outputs
- [x] define a production execution profile and a validation execution profile
- [x] require explicit backend-version change for any transcript-affecting
      representation change

Potential win:

- moderate to large if provenance hashing and per-bit commitment construction
  dominate runtime

Risk:

- high. This can accidentally weaken transcript binding or remove useful
  validation evidence. No code change should land before the audit is explicit.

### Initial Audit Result

Classification rule:

- `protocol-critical`: required for current HSS security or party-to-party
  validation. Byte output must stay identical unless the backend version and
  protocol spec change.
- `transcript-binding`: included in a commitment, digest, run binding, AAD, or
  label domain. Bytes must stay identical unless the backend version changes.
- `validation-only`: needed to catch malformed local execution, test fixtures,
  continuation replay, or diagnostics, but not required on the production happy
  path after all remote inputs have already been validated.
- `diagnostics-only`: timing, probe, or benchmark data. It must remain
  observational.
- `compactable`: the representation may change if the public commitments,
  output bundles, and validation semantics stay byte-identical.

Current field matrix:

| Data | Current usage | Classification | Compatibility rule | Optimization direction |
| --- | --- | --- | --- | --- |
| `DdhHssSharedWord.left_word` / `right_word` | Actual additive shares consumed by hidden eval and output projection. | `protocol-critical` | Must preserve arithmetic value and word width. | Can move into packed fixed-width storage if accessors preserve value semantics. |
| `DdhHssLocalWord.share_word` | Local share consumed by local DDH arithmetic helpers. | `protocol-critical` | Must preserve value, side, and width. | Strong candidate for packed local-side arrays or arenas. |
| `DdhHssSharedWord.left_commitment` / `right_commitment` | Inputs to `input_commitment_for_key`, stage digests, transport validation, and output commitments. | `protocol-critical`, `transcript-binding` | Must stay byte-identical for current backend version. | Can be stored compactly or recomputed at validation boundaries only if all transcript bytes stay identical. |
| `DdhHssLocalWord.share_commitment` | Carried through local operations and used to derive downstream provenance/commitments. | `protocol-critical`, `transcript-binding` | Must stay byte-identical for current backend version. | Can be represented as side arrays beside packed shares. |
| `DdhHssTransportWord.share_commitment` / `counterparty_commitment` | Validated by `validate_transport_word_pair_public` and included in `transport_bundle_commitment`. | `protocol-critical`, `transcript-binding` | Must stay byte-identical in transport messages. | Do not remove from wire format without a backend-version change. |
| `provenance_digest` on shared/local/transport words | Validates transport pairing, feeds `commit_word` for derived owners, and enters input/stage/bundle commitments. | `protocol-critical`, `transcript-binding` | Must stay byte-identical for current backend version. | Can be compacted in memory; cannot move behind debug/profile in the current protocol. |
| `DdhHssInputShareBundle.commitment` | Bundle commitment used in combined input commitment and run binding. | `protocol-critical`, `transcript-binding` | Must stay byte-identical for current backend version. | Can be cached once per bundle; do not remove from persisted/wire boundary. |
| `DdhHssTransportBundle.commitment` | Validates left/right transport bundle agreement and reconstructed input commitment. | `protocol-critical`, `transcript-binding` | Must stay byte-identical for current backend version. | Keep in transport boundary; internal packed form may carry one bundle-level commitment. |
| `client_input_commitment` / `server_input_commitment` | Bound into `run_binding_for_key` with artifact digest, context binding, and candidate digest. | `protocol-critical`, `transcript-binding` | Must stay byte-identical for current backend version. | Keep as run summary fields. |
| `DdhHiddenEvalCheckpointDigests` | Stage-by-stage trace validation and continuation checks. | `validation-only`, partly `transcript-binding` for current continuation APIs | Continuation APIs must preserve byte-identical digests. Full one-shot production evaluation can avoid retaining all checkpoint digests if outputs are validated elsewhere. | Separate trace/continuation profile from one-shot production profile. |
| `DdhHiddenEvalStageProfile` / `DdhHiddenEvalOperationCounts` | Benchmark and profiling output. | `diagnostics-only` | Must never influence execution. Serialization shape can evolve as diagnostics. | Keep outside protocol structs and skip in production hot path where possible. |
| Human-readable labels passed to gates and bundle builders | Domain separation for shares, provenance, commitments, OT payloads, and output bundles. | `transcript-binding` | Label bytes must stay byte-identical for current backend version. | Replace `format!` with structured label writers only when resulting bytes match exactly. |
| Error strings and probe status values | Developer diagnostics. | `diagnostics-only` | No protocol compatibility requirement. | Can change with diagnostics. |

Production execution profile:

- validate remote transport bundles at request boundaries
- keep share values, word widths, side tags, commitments, provenance digests,
  labels, input commitments, transport commitments, and run binding bytes
  identical to the current backend version
- return only production outputs needed by the caller: canonical seed output,
  client output bundle, server transport bundles, run commitments, and necessary
  transport commitments
- skip `DdhHiddenEvalCheckpointDigests`, probes, timing profiles, logical
  counters, and stage-continuation materialization unless the caller requests a
  validation or continuation profile

Validation execution profile:

- retain checkpoint digests for add stage, message schedule, round core, and
  output projection
- retain continuation structs and staged materialization data
- retain timing and logical counter profiles for benchmark builds
- run negative tests for mismatched labels, provenance digests, output kind,
  replayed transport bundles, and backend-version downgrade attempts

Compaction decisions from this audit:

- Allowed without backend-version change: packed in-memory storage for local
  shares, commitments, and provenance digests; structured label writers that
  emit identical bytes; one-shot production APIs that avoid returning trace-only
  checkpoint digests.
- Requires backend-version change: removing or changing provenance digest bytes,
  changing commitment derivation domains, changing label bytes, changing bundle
  commitment inputs, changing transport wire fields, or changing run binding
  inputs.

## Approach C: Hot-Loop Local Optimizations

Goal:

- reduce cost in the already-measured hot loops without changing protocol shape

Candidates:

- A2B destination-writer helper for `new_a_bits` and `new_e_bits`
- A2B raw carry-gadget specialization for already-local arithmetic word pairs
- `maj` and `ch` destination-writing scratch reuse
- output-projector scratch reuse
- fewer temporary `DdhHssLocalWord` objects
- fewer intermediate `Vec` allocations in round state and schedule state
- pre-sized arena-backed storage for fixed-width words

Existing spec:

- `docs/refactor-55-hss-optimize-registration.md` Phase E1 already pins the
  labels, provenance, gate schedule, constant-time constraints, and validation
  gates for the first A2B/boolean-helper candidates

Implementation order:

1. A2B destination-writer candidate. Rejected after browser/WASM smoke.
2. Logical object-construction counters. Landed.
3. Production representation audit.
4. A2B raw carry-gadget candidate only if counters show object churn inside the
   carry conversion is material in browser/WASM.
5. `maj`/`ch` helper candidate.
6. output-projector scratch candidate.

Keep rule:

- keep only if protocol validation passes and benchmark results show a stable
  HSS p95 win with small complexity or clear p50/p95 improvement across smoke
  scenarios

## Approach D: Structured Labels And Prefix Hashers

Goal:

- remove hot-loop string formatting and repeated hasher setup without changing
  transcript bytes

Candidates:

- replace repeated `format!` and label string assembly with structured label
  writers
- precompute round label prefixes where labels are public and deterministic
- precompute child-label prefix hashers for repeated gate families
- derive labels from fixed public indices while preserving byte-equivalent label
  output
- add byte-equivalence tests for old and new labels

Potential win:

- small to moderate if label construction remains a meaningful slice after
  hot-loop scratch reuse

Risk:

- medium. Label bytes are transcript material. Require fixtures proving
  byte-equivalence before benchmarking.

## Approach E: Packed Or Arena-Backed Execution Representation

Goal:

- reduce object churn by moving from object-per-bit execution to fixed-width
  packed arrays or arena-backed records

Candidates:

- store 64-bit local bit words in contiguous left/right arrays
- store provenance digests in side arrays
- store commitments in side arrays
- use stable handles or indices into an arena instead of cloning full
  `DdhHssLocalWord` values
- specialize fixed-width SHA-512 word operations around public width `64`
- separate public shape metadata from secret share values

Potential win:

- large. This is the first approach likely to produce a major runtime reduction
  if object churn and hashing dominate.

Risk:

- high. This is a representation rewrite and must be split into small
  byte-equivalence-preserving steps.

Required gate:

- implement an equivalence harness before rewriting hot paths
- compare final hidden-eval outputs, checkpoint digests, and public artifacts
  against the current representation

## Approach F: Binary And Compact Payloads

Goal:

- reduce serialization and transport overhead after core runtime costs are
  better understood

Candidates:

- binary worker messages for large one-shot artifacts
- transferable `ArrayBuffer` payloads
- compact evaluation result payloads
- compact staged artifact encoding
- route-level binary payloads only after browser worker payloads are proven
  useful

Current priority:

- lower than hidden-eval executor work for latency because latest diagnostics
  show worker decode, materialization, and encode are secondary on the retained
  worker-handle path

Potential win:

- small to moderate for browser registration
- useful for memory pressure and embedded transport even if runtime win is small

## Approach G: Native, SIMD, And Parallel Runtime Paths

Goal:

- make HSS faster on native and selected browser runtimes without changing the
  trust model

Candidates:

- native Rust benchmark and optimization profile separate from WASM
- Rust compiler profile tuning per target
- WebAssembly SIMD for fixed-width public-lane operations where safe
- native SIMD for digest/commitment or bit operations where library support is
  constant-time
- worker parallelism across independent public windows or gate batches
- server-side parallelism for prepare/finalize if transcript order remains
  deterministic

Constraints:

- parallel work must be partitioned by public indices only
- result assembly must be deterministic
- no scheduling decision can depend on secret share contents
- browser thread support must not become a correctness dependency

Potential win:

- moderate for SIMD
- moderate to large if server prepare/finalize can parallelize independent
  public batches

Risk:

- medium to high. Constant-time and deterministic transcript review required.

## Approach H: Protocol-Level Redesign

Goal:

- get a step-function improvement if representation and runtime work cannot
  make HSS fast enough, while preserving exportability and
  threshold-at-registration

Candidates:

- reduce the number of hidden-eval gates needed for registration
- change the output projection strategy
- precompute reusable public or server-side material safely
- use a different HSS primitive for the registration bootstrap only if it keeps
  `d` and `a` hidden from both parties
- split high-cost proof/validation material from the critical path
- introduce a backend-versioned compact HSS protocol

Required gate:

- write a separate protocol spec before implementation
- define threat model, transcript, replay protection, downgrade behavior, and
  compatibility boundary
- prove that neither party materializes the full export seed or signing scalar
  during registration
- add protocol-validation tests before any benchmark-driven keep decision

Potential win:

- large or 2x+

Risk:

- very high. Treat this as a protocol project, not a refactor.

## Approach I: Move Work Off The Critical Path

Goal:

- reduce user-visible registration latency while HSS remains expensive

Candidates:

- pre-auth HSS prepare
- registration ceremony precomputation
- post-auth finalize minimization
- background HSS readiness audit

Tasks:

- [x] route registration HSS respond diagnostics into the product-path benchmark
- [x] add a finalize fast path that reuses the cached prepared server session
      when the staged artifact arrives as bytes
- [x] validate the finalize fast path with `cargo check` for the server WASM
      export and relay-server TypeScript checks
- [x] benchmark the finalize fast path with `benchmark:registration-flow:smoke`
      and keep it only if the product-path finalize route improves

Ownership:

- this plan should record which HSS operations are movable
- route-shape and UX changes belong in dedicated registration-critical-path
  plans

Potential win:

- large for user-visible latency

Risk:

- medium to high. Scope binding, expiry, replay protection, and user-visible
  success semantics must be explicit.

## Recommended Order

1. Measurement and profiling.
2. Logical allocation and object-construction counters.
3. Production representation audit.
4. Native allocator or heap-profiler evidence if packed representation is still
   ambiguous.
5. `maj`/`ch` and output-projector scratch candidates only where counters show
   browser/WASM object churn.
6. Structured label and prefix-hasher work.
7. Packed/arena representation if profiling supports it.
8. Native/SIMD/parallel runtime experiments.
9. Protocol-level redesign only if the above cannot meet targets.

Do not start with protocol redesign. First prove whether current HSS is slow
because of unavoidable cryptographic work or because the implementation carries
too much object, label, hashing, and diagnostics overhead in production.

## Targets

Near-term HSS targets:

- reduce client eval artifact p50 from about `677ms` to below `500ms`
- reduce client eval artifact p95 below `600ms`
- reduce HSS prepare and finalize p50 by at least `20%` each, or explain why the
  server path is protocol-bound

Stretch HSS targets:

- client eval artifact p50 below `300ms`
- total HSS critical path below `900ms`
- native HSS registration path fast enough for iOS-class devices
- embedded recommendation backed by measured runtime and memory numbers

Full registration target:

- HSS runtime work alone is unlikely to guarantee `1500ms max`
- reaching that user-visible target probably also requires moving prepare or
  finalize work off the post-auth critical path

## Validation Ladder

For instrumentation-only changes:

- `cargo fmt --manifest-path crates/ed25519-hss/Cargo.toml`
- targeted benchmark command
- `git diff --check`

For HSS Rust behavior changes:

- `cargo fmt --manifest-path crates/ed25519-hss/Cargo.toml`
- `cargo test --manifest-path crates/ed25519-hss/Cargo.toml`
- `CC_wasm32_unknown_unknown=/opt/homebrew/opt/llvm/bin/clang cargo check --manifest-path wasm/hss_client_signer/Cargo.toml --target wasm32-unknown-unknown`
- `pnpm -C sdk type-check`
- `CC_wasm32_unknown_unknown=/opt/homebrew/opt/llvm/bin/clang pnpm benchmark:registration-flow:smoke`

For protocol-shape changes:

- protocol spec update
- backend-version decision
- protocol-validation fixtures
- negative tests for mismatched labels, provenance, output kind, replay, and
  downgrade behavior
- full registration benchmark

## Current Checklist

- [x] Choose Path A for this plan: preserve current HSS trust model,
      exportability, and threshold-at-registration.
- [x] Capture native hidden-eval baseline for the current DDH executor.
- [x] Run Phase E1 A2B destination-reuse experiment.
- [x] Reject A2B destination-reuse candidate after browser/WASM smoke showed no
      HSS worker improvement.
- [ ] Add native HSS registration benchmark.
- [x] Add WASM-only HSS artifact benchmark.
- [x] Add hidden-eval logical allocation and object-construction counters.
- [x] Split one-shot client artifact evaluation from checkpoint-retaining trace
      evaluation.
- [x] Split server HSS prepare/finalize into protocol sub-buckets.
- [x] Complete production representation audit.
- [x] Benchmark A2B candidate against `20260607-152114Z`.
- [ ] Implement `maj`/`ch` scratch candidate only if A2B results justify more
      local hot-loop work.
- [ ] Decide whether structured labels/prefix hashers are still worth doing
      after allocation and object counters land.
- [ ] Decide whether packed/arena representation is justified.
- [ ] Decide whether a protocol-level redesign is necessary.

## Open Questions

- How much runtime is spent in hashing versus arithmetic versus allocation?
- Can server prepare/finalize parallelize independent public batches safely?
- Does WASM SIMD help the actual hot loops, or are they object/hash-bound?
- What is the lowest embedded class that should be expected to run HSS?
- Should native HSS use the same artifact format as browser HSS?
- What benchmark threshold makes HSS acceptable as the default on iOS?

## Keep And Revert Rules

Keep an optimization only if:

- protocol validation passes
- constant-time review finds no new secret-dependent behavior
- benchmark results improve a measured target consistently
- complexity is proportional to the win
- transcript or backend-version impact is explicit

Revert or redesign if:

- labels or provenance drift unexpectedly
- a speedup only appears in one noisy scenario
- diagnostics start influencing execution
- object representation gets harder to validate without measurable gain
- protocol changes are made without a spec and backend-version decision

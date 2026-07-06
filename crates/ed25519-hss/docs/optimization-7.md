# Optimization 7: HSS 200ms Stretch Experiments

Status: planning inventory with July 6 experiment outcomes recorded. Do not
implement from this file until the required proof, equivalence, and product-path
gates for the selected experiment are in place.

Date created: July 6, 2026

## Purpose

List the remaining credible HSS experiments that could move the registration
HSS critical path toward a `~200ms` class target.

The current HSS path has already exhausted most helper-level and allocation-only
work. The next wins must remove logical work, change a reviewed representation
boundary, or move expensive work out of the user-visible critical path without
weakening the staged HSS trust model.

This file is intentionally more aggressive than `optimization-6.md`: it includes
complete re-architecture candidates, but each candidate names the proof and
benchmark gate needed before code should land.

## Baseline

Use the latest `refactor-83D-hss-subsecond-tail.md` numbers as the product-path
baseline:

- durable Worker/WASM HSS advance: about `475ms-501ms` in focused tail runs;
- client artifact build: about `480ms-495ms` in focused tail runs;
- durable HSS finalize: about `21ms-32ms` after compact finalize context and
  output-projection moves;
- main remaining HSS compute buckets:
  - advance message schedule plus round core: about `264ms-280ms`;
  - advance output projection: about `96ms-114ms`;
  - client hidden-eval arithmetic: about `340ms` inside a `~480ms` artifact leg.

Objective function: the advance and client-artifact legs run in parallel and
are nearly equal, and finalize is already `~21-32ms`. The user-visible HSS
cost is therefore `max(advance leg, artifact leg)` plus a small finalize
tail. Cutting one leg to `200ms` while the other stays near `480ms` saves
approximately nothing. Every experiment below is judged against the max of
the legs, not against its own bucket.

Effort-allocation context: the non-HSS registration tail (ECDSA persistence
`~551ms`, client material `~384ms`, enrollment material `~366ms`, session
hydration `~289ms`) is currently larger than the whole HSS section and is
owned by the 83D follow-up refactor. High-risk experiments here (E8, E11)
compete with much cheaper non-HSS engineering for the same total-elapsed
milliseconds; fund accordingly.

Older crate docs remain useful for experiment triage:

- `optimization-experiment-ledger.md` is the canonical retained/rejected list.
- `optimization-6.md` records the current retained backend:
  `ddh_hss_backend_v4_ch_gated_select_root`.
- `docs/benchmarks/refactor-64/summary.md` records why many allocation-only and
  helper-local edits were rejected.

## July 6 Experiment Outcomes

The latest optimization pass produced one large product-path latency win, but
it did not come from changing the HSS protocol.

Retained:

- Passkey ECDSA registration persistence tail: reduced from roughly
  `~565ms` to about `45ms` in the recorded product trace. The dominant cost was
  not relayer network latency or local record persistence; it was duplicate
  Shamir client-unseal work while hydrating warm ECDSA sessions for Tempo and
  Arc. The accepted change caches the deterministic server-sealed PRF result in
  volatile passkey-confirm worker memory under an explicit registration scope:
  wallet id, credential id, signing grant id, relayer, server-seal key version,
  Shamir prime, and `sha256(prfFirst)`. Each target still performs its own
  authorization and policy check, then reuses the derived sealed secret only
  when that scoped cache key matches. Result:
  `ecdsaRegistrationWarmSessionSealApplyClientUnsealMs` dropped from about
  `527ms` to `0ms`, and
  `ecdsaRegistrationPersistenceMs` dropped to about `45ms`.
- Email OTP combined unlock/session frequency reduction: combined ECDSA unlock
  now tries to activate an exact persisted Ed25519 sealed session before
  falling back to HSS reconstruction. This is a structural win that reduces
  duplicate Ed25519 HSS reconstruction when sealed material is already
  sufficient. A fresh product benchmark is still needed to quantify the exact
  combined-path unlock delta.

Rejected or closed:

- Curve-level persistence parallelization: rejected. The trial worsened total
  passkey registration from about `2367ms` to `2496ms`,
  `ecdsaRegistrationPersistenceMs` from about `551ms` to `855ms`, and
  `thresholdEd25519SigningSessionHydrationMs` from about `289ms` to `538ms`.
  Ed25519 and ECDSA persistence share signer-worker and IndexedDB readwrite
  resources, so the attempted overlap time-sliced one bottleneck.
- Byte-returning Shamir unseal: rejected. Replacing string-returning unseal with
  byte-returning unseal plus JS base64url encoding moved the client-unseal
  bucket from about `527ms` to `535ms`. The cost is modular Shamir unseal work,
  not JS string serialization.
- Current-backend continuation cleanup: closed as an internal cleanup that did
  not satisfy the product keep rule. The next byte-equivalent HSS path would be
  a larger stage-owned representation or shared arithmetic kernel, not more
  continuation-conversion work.
- Covert-security / spot-check transcript: design-only. Toy checks show naive
  random sampling is weak; random-linear checks require transcript roots to be
  committed before the verifier challenge. This remains the only credible
  `~200ms` protocol lever in this file, but it changes the security model and
  needs explicit product/security acceptance before implementation.

Current interpretation:

- Under the current malicious-security transcript model, HSS appears to be near
  a `~300ms-400ms` practical floor for this backend, with current product legs
  still around the `~500ms` class until a larger representation or protocol
  change lands.
- The highest-return user-visible latency work is now outside this crate's HSS
  core: non-HSS registration tail, unlock benchmark-driven reconstruction
  frequency, and session hydration/persistence paths.

Acceptance bar recorded for the retained non-HSS win:

- the server-sealed PRF result cache remains volatile worker memory only;
- reuse requires the explicit passkey-registration scope above;
- missing cache scope disables reuse instead of widening it;
- each ECDSA target still performs its own server authorization and policy
  update;
- source/unit guards pin wallet id, credential id, and signing grant id in the
  cache key.

Remaining product-latency work, in order of value:

- quantify the Email OTP combined unlock delta with a fresh intended benchmark
  after refreshing the local Google token;
- split `thresholdEd25519SigningSessionHydrationMs`, the last unexamined
  registration hydration bucket after ECDSA persistence dropped out of the top
  list;
- decide the Refactor-8X EVM-only/no-Ed25519 profile, which is the remaining
  >500ms registration lever;
- keep covert-security parked unless product/security explicitly accepts the
  changed model and its commit-before-challenge transcript requirement.

Closed as already handled: the Email OTP enrollment/material overlap candidate.
The July 6 trace showed the work is already overlapped; additional concurrency
would duplicate existing promises rather than remove serial latency.

## Non-Negotiable Gates

Every retained experiment must pass:

- byte-equivalence or backend-versioned semantic equivalence for artifacts,
  commitments, roots, decoded outputs, and durable checkpoints;
- `cargo hss-fv all`;
- boundary corruption tests for every new encoded state or proof object;
- focused tail benchmark:
  `pnpm benchmark:ed25519-hss:tail -- --warmup 1 --iterations 3`;
- product-path intended registration benchmark before retention;
- movement in `max(advance leg, artifact leg)` in the product trace — a
  bucket-only win that does not move the max of the parallel legs is not
  retained (see Objective function in the Baseline);
- constant-time review for secret-dependent branches, indexes, loop bounds,
  allocation sizes, and protocol-width choices.

Protocol-changing experiments also require:

- a new backend version string;
- parser rejection for stale/unknown backend versions at every boundary;
- downgrade/mixing fixtures proving old and new backend objects cannot combine;
- a written proof note naming each removed commitment/provenance item and its
  replacement binding.

## Do Not Recycle

The following directions have already failed or are too weak for this target:

- allocation-only helper edits;
- packed local metadata as a narrow container change;
- round-state scratch reuse;
- output-projector label reuse, select-stream, fused canonicalization, and the
  first semantic paired-root rewrite;
- A2B destination reuse and A2B output recycling;
- B2A-only core-sigma committed root;
- full `Maj` transient XOR/multiply root helper swap;
- local-add carry-root v5;
- round-sigma B2A-boundary experiment;
- derived-commitment prefix-hasher reuse;
- native-only kernels as the default product path;
- process-local handle persistence as correctness-critical state;
- shortcuts that reconstruct joined secret values.
- eager pre-auth HSS derivation as an active product path, unless a future
  design closes the DDoS surface and auth-derived input dependency without
  weakening recovery/export semantics.

## Experiment Ranking

### E0: Current-Backend Profiling Refresh

Target: measurement correctness.

Expected win: none directly.

Before any new optimization, refresh the current retained backend with the same
instrumentation used in 83D:

- product Worker/WASM stage timings for advance and client artifact;
- physical keyed-digest and derived-commitment domain counters;
- client worker-handle versus serialized-state comparison;
- p50/p95 drift across at least 24 sequential advance/finalize cycles;
- a no-op WASM echo probe at the real payload sizes (`~59KB` artifact,
  large advanced-state blobs) to price the JS-to-WASM boundary copy and
  serde cost per call — the one instrumentation gap left from the 83D
  candidate list, and the natural pair for E7's generated-code inspection.

Exit criterion: a one-page profile that says whether the current top HSS bucket
is `round_core`, `message_schedule`, `output_projection`, boundary copy, or
durable persistence. If this profile does not agree with 83D, fix the
measurement before code changes.

E0 refresh, July 6, 2026:

- default tail run:
  `benchmarks/ed25519-hss-tail/out/2026-07-06T06-37-47-219Z/summary.md`;
  `clientArtifactMs median=490.601`, `advanceWallMs median=503.833`,
  `finalizeWallMs median=32.571`;
- worker-handle client run:
  `benchmarks/ed25519-hss-tail/out/2026-07-06T06-37-59-685Z/summary.md`;
  `clientArtifactMs median=432.080`, `advanceWallMs median=506.560`,
  `finalizeWallMs median=32.163`;
- 24-cycle drift run:
  `benchmarks/ed25519-hss-tail/out/2026-07-06T06-38-39-085Z/summary.md`;
  sequential `advanceWallMs median=501.207`, `p95=503.446`, with no WASM
  memory growth;
- boundary-copy probes are visible and small relative to hidden eval:
  advance payload copy is about `26ms-27ms`, finalize payload copy is about
  `23ms-24ms`;
- current advance buckets in the drift run are stable:
  `advanceMessageScheduleRoundsMs median=159`,
  `advanceRoundCoreRoundsMs median=124`,
  `advanceOutputProjectionMs median=120`;
- physical counters from
  `benchmarks/ed25519-hss-tail/out/2026-07-06T06-38-39-085Z/ddh-hidden-eval-physical-counters.json`
  still point at broad hidden-eval work, led by `eval_xor_local_word` in
  keyed-digest and derived-commitment domains.

Conclusion: the next current-backend work should target hidden-eval arithmetic
and representation. Boundary copy, durable persistence, and finalize are no
longer first-order HSS blockers. E2 remains the safest narrow implementation
experiment; E1/E3 are the likely paths to larger movement.

### E1: Executor-Wide Stage-Owned Representation

Target: `round_core`, `message_schedule`, and client hidden-eval arithmetic.

Expected win: `50ms-150ms` if it removes broad commitment/provenance
materialization, with upside on low-power devices.

This is the primary current-backend candidate. Generalize the retained
`CoreBitWordSide`/deferred-materialization wins into a stage-owned representation
that carries share bits and provenance roots through a whole stage, materializing
commitments only at reviewed boundaries.

First deliverable:

- a byte-equivalence harness over complete staged evaluator artifacts;
- a materialization graph fixture that proves each commitment is created before
  any consumer that needs it;
- a no-product-code prototype behind a benchmark-only feature.

Keep rule:

- retain only if direct browser/WASM and product `ed25519EvaluationArtifactMs`
  both move.

Risk:

- high. This touches the shape that earlier small arena/scratch experiments
  tried to approximate. The value comes from making the representation large
  enough to remove logical work, not from moving buffers around.

### E2: Message-Schedule Core-Lane Rewrite

Target: message schedule, currently about `150ms-188ms` in some focused runs and
part of the `264ms-280ms` advance message-schedule-plus-round-core bucket.

Expected win: `20ms-60ms`.

Optimization 5 identified message schedule as the safest byte-equivalent target
because part of the sigma path already proved the core-only pattern. Rebuild the
message schedule around core-only words until the exact point where commitments
are consumed.

First deliverable:

- a commitment-consumption graph for `small_sigma0`, `small_sigma1`, and the W
  extension path;
- fixtures proving no schedule word escapes without the required commitment.

E2 inspection, July 6, 2026:

- `execute_message_schedule_stage` builds schedule words `W[0..80]` as
  `SplitLocalBitWord`. Each extension computes `small_sigma0(W[t-15])` and
  `small_sigma1(W[t-2])` as `CoreBitWordPair`, materializes those sigma values
  to arithmetic, adds `W[t-16] + sigma0 + W[t-7] + sigma1`, then converts the
  result back to split-local bits.
- The sigma core values do not escape the extension step. The only escaping
  value is the final `W[t]` split-local word.
- The full schedule escapes through three current consumers:
  `digest_split_local_bit_words(b"message_schedule", words)`,
  `DdhHiddenEvalMessageScheduleContinuation.schedule_words`, and
  `execute_round_stages(..., &schedule_output.words)`.
- Therefore the first implementation slice should preserve the public
  continuation and round-core inputs as `SplitLocalBitWord`. The experiment
  should be an internal accumulation/kernel rewrite with byte-equivalent
  schedule outputs, checkpoint digests, and artifacts.

First implementation slice:

- add a focused schedule-extension equivalence fixture that compares every
  generated `W[t]` and the message-schedule checkpoint digest against the
  retained backend;
- prototype an alternate internal accumulation path behind a benchmark-only
  feature or private selector;
- add full artifact equivalence before retaining any alternate accumulation
  path;
- keep the continuation wire shape unchanged until the alternate path moves
  `max(advance leg, artifact leg)` in product traces.

Implementation progress, July 6, 2026:

- added
  `prime_order_succinct_hss_message_schedule_incremental_extension_matches_full_stage`
  in `tests/protocol_flow/mod.rs`; it compares incremental `W[16..80]`
  generation against the full-stage schedule and checks the completed
  message-schedule digest;
- validation:
  `cargo test --manifest-path crates/ed25519-hss/Cargo.toml prime_order_succinct_hss_message_schedule_incremental_extension_matches_full_stage --test mod`.
- added the first current-backend compression slice in
  `advance_message_schedule_continuation_with_pool`: unchanged continuation
  words are preserved from the incoming shared-word continuation, and only the
  appended `W[t]` word is serialized from split-local form. This keeps the
  continuation wire shape unchanged while removing repeated reserialization of
  already-bound schedule words.
- extended the slice to reconstruct only the four recurrence inputs
  (`W[t-16]`, `W[t-15]`, `W[t-7]`, and `W[t-2]`) instead of every prior
  schedule word on each incremental round.
- validation:
  `cargo hss-fv all` passed, and the focused tail benchmark
  `benchmarks/ed25519-hss-tail/out/2026-07-06T08-11-51-348Z/summary.md`
  reported `advanceMessageScheduleRoundsMs: 163ms`,
  `advanceWallMs: 513.196ms`, and `clientArtifactMs: 495.701ms`.
  This is a byte-equivalent internal compression, but it does not yet satisfy
  the product-level keep rule. The next E2/E1 implementation should target the
  full stage-owned representation or the shared arithmetic kernels rather than
  more continuation-conversion cleanup.

Risk:

- medium. It is narrower than E1 and should be attempted first if we want a
  low-blast-radius experiment.

### E3: Round-Core Vector Kernel

Target: round core, historically the most expensive executor stage.

Expected win: `30ms-100ms`.

Build a round-core-specific kernel that processes fixed-width word lanes with
contiguous storage and fewer per-bit object transitions. This is a structural
kernel rewrite, not another helper-local `Ch`/`Maj` edit.

Allowed shape:

- branch on public stage and round indexes only;
- operate on stage-owned word arrays;
- preserve retained `Ch` gated-select and `Maj` pair-XOR semantics;
- keep all backend transcript bytes stable unless paired with a backend-version
  proof.

First deliverable:

- a benchmark-only duplicate kernel selected by a typed backend test harness;
- stage-level equivalence over all SHA-512 rounds;
- physical counter comparison for `eval_xor_local_word`,
  `eval_mul_local_material`, and derived commitments.

Risk:

- high. v3 already warns that helper-level `Ch`/`Maj` rewrites at the old
  abstraction layer should stay dead.

### E4: A2B v3 Aggregate Carry Root

Target: A2B and round-core carry paths.

Expected win: `20ms-80ms`.

The retained A2B v2 BLAKE3-base committed-root was a real win. A v3 should ask
whether multiple carry commitments can be bound under a single aggregate
carry-root per word or per operation, with per-bit derivations from that root.

Required proof:

- exact aggregate-root preimage;
- bit-index and width binding;
- side and owner binding;
- transcript downgrade behavior;
- replacement proof for every removed per-bit commitment/provenance item.

Risk:

- high. The SHA-256 per-bit v2 form regressed badly, and the B2A-only root did
  not move latency enough. This experiment needs protocol review before code.

### E5: Multiplication-Material Root Beyond Retained `Ch`

Target: multiplication material in `round_core`.

Expected win: `20ms-80ms`.

The retained `Ch` gated-select root is the largest protocol-runtime win in
optimization 6. A follow-on should search for another multiplication-material
family where an operation-root removes more logical work than it adds in root
hashing.

First candidate area:

- multiplication material shared by repeated fixed-width gates where the current
  transcript emits side-specific commitments that could be replaced by a
  reviewed operation root.

Required proof:

- operation-kind enum;
- operand-root shape;
- label and bit-index policy;
- exact mapping from old per-bit material to new root-derived material.

Risk:

- high. Full `Maj` root and local-add carry-root v5 both lost. Start with a
  counter-only design review and a native proof prototype.

### E6: Output-Projector Root v2

Target: output projection and the client artifact tail.

Expected win: `40ms-100ms` only if it removes a full canonical-add/select
equivalent.

The first paired-root semantic rewrite failed because it displaced the retained
mixed shared-mask path and did not remove enough product-visible work. A v2 must
start from the current mixed shared-mask path and preserve the fast masked
client-output behavior.

Required proof:

- preserve `canonical_seed`, `client_output`, and `x_server_base` commitments;
- preserve projection-mode binding;
- prove the removed work is a full logical operation, not only an allocation or
  label-formatting change.

Risk:

- high. Product smoke is the decisive gate for this experiment.

### E7: WASM SIMD Kernel Specialization

Target: group/field arithmetic inside hidden-eval loops.

Expected win: `10ms-60ms`.

The 83D `simd128` build flag is retained, but the code may still miss
SIMD-friendly layout because it was not designed around vector lanes. Audit the
hot arithmetic loops for patterns that prevent LLVM from using SIMD in
`wasm32-unknown-unknown`.

Allowed work:

- layout changes that keep transcript bytes identical;
- fixed-size arrays where public width is known;
- removing iterator/object shapes that block vectorization.

Rejected work:

- `curve25519_dalek_bits="64"` for Worker/WASM, already measured as a
  regression;
- `wasm-opt -O3` as a default build, already too small for the artifact-size
  cost.

Risk:

- medium. This can be byte-equivalent, but it needs disassembly or generated
  code inspection so we know SIMD is actually emitted.

### E8: Durable Precomputation Tickets

Target: critical-path advance and client artifact arithmetic.

Expected win: `50ms-200ms` if enough context-independent work can be prepaid.

Introduce protocol-level precomputation tickets for HSS material that is
independent of wallet identity, registration intent, and client proof. Tickets
would be generated before registration, stored durably, and consumed exactly
once when the real ceremony binds public context.

This is the standard MPC offline/online split: the ticket is a one-time
correlated-randomness bundle (OT material, garbling randomness,
beaver-style multiplication material) generated in an offline phase and
bound to public context at consumption. Frame the design review in those
terms — the literature on offline/online MPC preprocessing is the right
lens for both the classification and the replay-safety proof, rather than
a from-scratch analysis.

First deliverable:

- classify every expensive input as context-independent, context-bound public,
  or secret-dependent — i.e., map the protocol onto the offline/online
  decomposition and identify what fraction of the stage loops consumes
  offline-generatable material;
- prove a ticket cannot be replayed across wallets, environments, or backend
  versions;
- define a durable consumed-state record with atomic reservation.

Risk:

- very high. If the expensive work depends on ceremony secrets or context, this
  collapses to the current durable checkpoint model. This is still worth a proof
  pass because it is one of the few paths that could save hundreds of
  milliseconds without unsafe live-handle assumptions.

### E9: Single-Invocation Streaming Ceremony

Target: Cloudflare/Worker request boundaries and live runtime materialization.

Expected win: `50ms-200ms` in deployments that can keep one invocation open for
the whole HSS ceremony.

Run prepare, client add-stage request handoff, server advance, artifact
verification, and finalize through one long-lived HTTP/RPC invocation. The
client streams the add-stage request and later the artifact into the same
invocation; the server keeps live evaluator/garbler state in normal stack/heap
memory for that invocation only.

This is standard HTTP streaming shape, not WebSocket pinning. It is a separate
deployment mode because it changes request topology.

Required proof:

- durable fallback remains production-reachable;
- cancellation leaves no partially committed wallet state;
- request timeout budgets are compatible with Cloudflare and self-hosted Node;
- no success signal is emitted until durable finalized state is written.

Risk:

- high product complexity. It may be attractive for Node/VM deployments and
  less attractive for Cloudflare if Worker request duration or streaming
  behavior becomes brittle.
- topology drift. A streaming mode is exactly the "second runtime path" that
  the 83D constraints forbid and that killed the 83C native port: two request
  topologies with one exercised is how equivalence rots. If pursued, it must
  be all-or-nothing per deployment — a deployment runs streaming or durable,
  never a fallback ladder between the two inside one deployment — and the
  durable path remains the only Cloudflare shape unless p95 evidence forces
  the issue.

### E10: Native Self-Hosted HSS Engine Port

Target: deployments outside Cloudflare Workers.

Expected win: `0ms-100ms` on the current workload, larger only if native code can
keep warm ceremony state or use CPU features unavailable to WASM.

Keep the native engine as an optional provider behind the HSS engine port for
Node/VM/self-hosted deployments. Do not make it the default Cloudflare path
unless new measurements show a decisive p95 win after Worker-to-service hop
costs.

Required proof:

- same boundary parser and backend-version rejection as Worker/WASM;
- same formal verification suite;
- side-by-side benchmark with route provenance proving which engine ran.

Risk:

- operational complexity. Previous container numbers did not justify making
  this the default path.

### E11: HSS Protocol v2 With MPC-Friendly Derivation

Target: complete replacement of the SHA-512 hidden-eval bottleneck.

Expected win: `100ms-300ms+` if successful.

Design a new threshold Ed25519 registration/export protocol that avoids
evaluating the current SHA-512-shaped HSS circuit on the critical path. The
replacement must preserve the current product properties:

- threshold ownership;
- exportability through the approved threshold export flow;
- no party learns the full seed/scalar during normal registration/signing;
- deterministic public-key derivation and stable wallet identity;
- auditable recovery semantics.

Same-key constraint (July 6, 2026, product decision): standard Ed25519 seed
export matters for this product. The public key is
`clamp(SHA-512(seed)[0..32]) * B`, and the base shares are shares of that
SHA-512-derived scalar — so any direction that generates base shares
MPC-natively produces a public key with **no corresponding standard seed**
(a matching seed would require inverting SHA-512). Deferring the evaluation
to export cannot keep the same public key, and MPC-native scalars cannot
keep standard seed export. Both deferral directions are therefore closed
under the same-key + seed-export constraints; they reopen only if the
product ever accepts expanded-key-format export.

Dependency audit, July 6, 2026:

- Normal Ed25519 signing consumes `xClientBaseB64u`, `xRelayerBaseB64u`, and
  the public key. The signing worker and FROST path do not consume the
  canonical seed.
- Existing formal and protocol-flow tests prove the public key derived from
  base shares equals the committed public key
  (`fv_hss_fexp_003_public_key_projection_matches_scalar_projection` and the
  protocol-flow base-share projection checks).
- Registration currently opens the seed output and derives the keypair in
  `deriveThresholdEd25519RegistrationMaterialFromHssFinalize`; the resulting
  public key is used as `relayerKeyId` and persisted as wallet identity.
- The server persists the finalized seed output for recovery/export. The SDK
  registration response deliberately excludes `seedOutputMessageB64u`, so
  export already runs through an explicit recovery/export ceremony rather than
  through registration response material.
- A cheap identity/export split is feasible to investigate: derive
  `publicKey`/`relayerKeyId` from base shares during registration, retain the
  finalized seed output durably, and open the seed only inside the export flow.
  This should save only seed opening plus seed-keypair derivation. It does not
  remove the current hidden evaluation, because the existing backend computes
  `canonical_seed`, `x_client_base`, and `x_server_base` together.
- A real `~200ms` lazy-export win would require a backend-versioned protocol
  change that generates normal signing base shares through an MPC-native path.
  That path is closed under the current same-key and standard seed-export
  constraints.

Candidate directions:

- eager derivation, now parked: it preserves the same key and seed export, but
  creates DDoS pressure and depends on auth/recovery input timing;
- cheap identity/export split that defers seed opening while preserving the
  current backend (small win: seed opening plus keypair derivation only);
- protocol-v2 lazy export derivation that moves normal signing base-share
  generation off the SHA-512 HSS critical path — **closed under the current
  same-key/seed-export constraint** (see above); viable only if the product
  accepts expanded-key export;
- use an MPC-friendly PRF or hash inside a backend-versioned protocol —
  same export-format caveat;
- precompute shares of the expensive derivation under a future context binding;
- separate the export-grade secret derivation from the fast signing authority
  only if the user-visible wallet key remains cryptographically coherent.

Required proof:

- cryptographic design review before code;
- formal model of what replaces SHA-512 HSS (or, for lazy export derivation,
  proof that deferring it preserves deterministic public-key derivation,
  stable wallet identity, and the approved export flow's guarantees);
- migration story for dev wallets can be breaking, but mixed-backend objects
  must be rejected at boundaries.

Risk:

- highest. This is parked under current same-key, seed-export, DDoS, and
  auth-input constraints. Reopen only if those product constraints change.

### E12: Covert-Security Spot-Check Transcript

Target: commitment/provenance domains across hidden-eval arithmetic.

Expected win: `100ms-300ms+` only if product accepts a changed security model.

Design note: `covert-security-spot-check.md`.

Replace part of the current per-gate/per-bit committed transcript with a
covert-security or probabilistic-verification transcript. The aim is to catch
and attribute cheating with a quantified probability while cutting the measured
commitment/provenance domains that dominate the E0 counters.

This is not byte-equivalent and not malicious-security equivalent. It must use
a new backend version and new boundary objects.

First design-review questions:

- Is covert security acceptable for wallet registration/recovery material?
- What detection probability is acceptable, and how is a detected cheat handled?
- Can any useful relation family be batch-checked without reconstructing joined
  secrets?
- Does simple sampling have meaningful detection probability for one-gate
  output attacks? If not, can a random linear or aggregate-root check produce a
  strong bound?

Required proof:

- written product acceptance of the security-model change;
- cryptographic soundness bound for each checked relation family;
- no joined secret reconstruction in normal registration/signing/export;
- constant-time review for public challenge selection and fixed-width checks;
- downgrade/mixing fixtures for `covert_hss_backend_v1` objects.

Risk:

- highest. This buys latency by changing what the transcript proves. It should
  stay a design note until the security/product decision is explicit.

## Recommended Order

1. Keep the E0 profile current whenever backend internals change.
2. Treat the E11 first question as answered for the current backend: seed
   opening can likely be deferred (small cleanup win), but base-share
   generation pays the SHA-512 hidden eval, and MPC-native base shares are
   closed by the same-key/seed-export constraint. Eager derivation is currently
   demoted because it adds DDoS pressure and depends on auth/recovery inputs.
3. Review E12 as the only remaining credible `~200ms` protocol lever. Stop it
   at design if covert security is not acceptable.
4. Try E2 as the safest byte-equivalent implementation experiment.
5. Start E1 if the goal is a meaningful current-backend breakthrough.
6. Design-review E4/E5/E6 only after E1/E2 show where materialization is still
   forced.
7. Keep E8 and full E11 parked unless product constraints change.
8. Use E9/E10 only for deployment-specific modes after the Worker/WASM path has
   a fresh p95 profile.
9. If E12 is rejected, treat `300ms-400ms` as the likely current-protocol HSS
   plateau and shift most product-latency work to the non-HSS tail, unlock
   frequency reduction, and the Refactor-8X EVM-only/no-Ed25519 profile.

## Validation Commands

Minimum validation for any retained code change:

```sh
cargo fmt --manifest-path crates/ed25519-hss/Cargo.toml
cargo test --manifest-path crates/ed25519-hss/Cargo.toml
cargo hss-fv all
pnpm benchmark:ed25519-hss:tail -- --warmup 1 --iterations 3
pnpm build:sdk
```

Run intended registration benchmarks before marking a product-path optimization
retained.

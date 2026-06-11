# Optimization 6: Backend-Versioned HSS v2

Status: retained. The semantic paired-root projector rewrite was implemented,
benchmarked, and rejected after product-smoke regression. The retained
protocol-kernel slices are A2B v2 committed-root with precomputed BLAKE3
carry-material bases, the v3 `Maj` pair-XOR provenance fold, and the v4 `Ch`
gated-select root; the
output-projector binding scaffold remains as product-neutral future-version
plumbing. The local-add carry-root v5 experiment was benchmarked and rejected
because its small counter win did not translate to a reliable native/browser
latency win.

Date created: June 10, 2026

Experiment ledger:

- `optimization-experiment-ledger.md` is the canonical index of retained,
  rejected, and instrumentation-only latency experiments. Check it before
  retrying any current-backend micro-edit, output-projector rewrite, A2B/B2A
  protocol root, multiplication-material root, or arena representation change.

Executive experiment ledger:

- Approved and retained:
  - typed backend-version scaffold and stale-backend parser rejection
  - output-projector binding scaffold as protocol-hardening / future-v2 plumbing
  - A2B v2 committed-root carry material with precomputed BLAKE3 bases
  - `Maj` pair-XOR provenance fold
  - `Ch` gated-select root, currently the largest retained HSS runtime win in
    this plan
- Rejected after benchmark:
  - semantic output-projector paired-root arithmetic rewrite
  - A2B v2 per-bit SHA-256 carry-material implementation
  - B2A-only core-sigma committed-root experiment
  - full `Maj` transient XOR/multiply root helper swap
  - local-add carry-root v5
  - round-sigma B2A-boundary experiment
  - allocation-only and byte-equivalent helper edits that improved counters but
    failed native, direct-WASM, or product keep gates
- Needs approval before code:
  - any second B2A committed-root attempt
  - any new multiplication-material root that removes more logical work than
    the retained `Ch` root
  - any broader protocol-root replacement, including output-projector paired
    root v2 or an A2B follow-on that changes emitted commitment semantics
- Needs a harness before code:
  - true executor-wide representation rewrite. The first deliverable is a
    byte-equivalence harness that proves artifacts, commitments, roots, and
    decoded outputs match the retained backend before hot representation code
    changes.
- Needs device data before retention:
  - embedded/iOS-specific tuning. Desktop/browser wins are useful but do not
    prove low-power CPU, memory pressure, allocator behavior, or JIT/AOT
    behavior on iOS and embedded targets.

## Goal

Implement the next meaningful HSS runtime win after the current-backend
byte-equivalent plateau.

The candidate must preserve the current browser trust model: the client never
constructs the full Ed25519 seed or signing scalar during registration, and
exportability remains available through the threshold export flow.

This plan turns the protocol-review notes from `optimization-5.md` and
`docs/refactor-64-hss-protocol-runtime-latency.md` into an implementation
sequence. The obvious current-backend helper-level edits have now been tried;
remaining HSS runtime candidates are larger protocol or representation work:

- protocol-reviewed v2 work:
  - A2B follow-on work beyond the retained committed-root BLAKE3-base slice
  - output-projector paired-root v2
  - B2A / multiplication-material root changes
- true executor-wide representation rewrite with a byte-equivalence harness
- embedded/iOS-specific profiling and tuning

The next patch should start from one of those lanes. Avoid another narrow
helper micro-edit unless it demonstrably removes logical work rather than only
moving allocation or hash counters.

## Current Read

Retained Phase 7I product smoke `20260610-112012Z`:

- `ed25519EvaluationArtifactMs` p50: `450/445/443/442ms`
- browser direct HSS artifact worker-handle p50: `187.9ms`
- browser hidden-eval p50: `175.75ms`
- browser output-projector p50: `30.25ms`
- product worker output-projector split before Phase 7I showed client-base
  around `60ms` and relayer-output around `65ms`

Latest full registration smoke `20260610-135445Z` shows wallet-iframe full SDK
latency is now mostly passkey prompt decision wait, but HSS artifact
construction remains shared across Passkey, OTP, wallet-iframe, and host-origin
flows. HSS runtime work is still useful for margin, embedded/iOS viability, and
OTP/passkey parity.

Latest output-projector binding plus mixed shared-mask restore smoke
`20260610-154615Z`:

- `ed25519EvaluationArtifactMs` p50: `468/470/467/466ms`
- `hiddenEvalOutputProjectorMs` p50: `148/149/151/151ms`
- `hiddenEvalOutputProjectorClientOutputMs` p50: `4/4/4/4ms`
- `hiddenEvalOutputProjectorLocalWordMaterializations` p50: `2560`
- compared with the regressed binding-only run `20260610-153553Z`,
  artifact p50 improved from `515/515/516/515ms` and client-output p50
  improved from `59/59/61/61ms`
- compared with the retained full smoke `20260610-135445Z`, artifact p50 is
  effectively baseline/noise: `471/468/462/463ms`

Current planning anchor:

- source commit: `68cebd88`, plus the current dirty refactor-64 /
  optimization-5 HSS worktree state
- retained A2B v2 baseline set: native/direct-WASM/product benchmark outputs
  under `crates/ed25519-hss/docs/benchmarks/refactor-64/optimization-6/`,
  product smoke `20260610-170749Z`, and focused validation below
- first retained implementation track: `output_projector_binding_v1`, a
  backend-versioned binding scaffold for output-projector commitments
- second implementation track: `a2b_committed_root_v2`, retained after
  committed-root multiplication-material binding review

Naming note: earlier planning text calls the semantic projector candidate `v2`
because it would replace the original projector proof shape. The retained
output-projector binding scaffold remains the v1-shaped product-neutral
scaffold. The retained A2B candidate used backend string
`ddh_hss_backend_v2_a2b_committed_root`; the current retained backend string is
`ddh_hss_backend_v4_ch_gated_select_root`. The semantic paired-root projector
arithmetic rewrite was rejected.

June 11 update: A2B v2 with committed-root carry material is now the live
candidate under backend string `ddh_hss_backend_v2_a2b_committed_root`. The
first per-bit SHA-256 carry-material implementation regressed native
hidden-eval p50. Replacing that with a precomputed BLAKE3 carry-material base
produced a native hidden-eval p50 win, direct browser/WASM win, and product
registration smoke win while passing crate/formal validation.

June 11 B2A-root update: a first B2A-only core-sigma root experiment under
temporary backend string `ddh_hss_backend_v3_b2a_root` was implemented,
benchmarked, and rejected. It reduced the physical B2A base counters from
`896` keyed digests / `1792` derived commitments to `768` / `1536`, but native
hidden-eval p50 stayed around `124.2-124.6ms`, above the retained A2B v2 best
`118.436ms`. The code path was reverted before the later `Maj` pair-XOR fold;
benchmark artifacts remain as rejection evidence.

June 11 `Ch` gated-select update: the root-bound `Ch` helper swap is retained
under backend string `ddh_hss_backend_v4_ch_gated_select_root`. It keeps final
`choose` outputs committed, removes transient committed `yz` material and
materialized gated-product commitments, and derives the select multiplication
material from a `Ch` root-base digest. Native total hidden-eval p50 improved
from the retained v3 `118.248ms` to `108.737ms`; direct browser/WASM moved from
`172.800ms` to `168.567ms`; product smoke `20260611-041314Z` passed all four
scenarios with `ed25519EvaluationArtifactMs` p50 `430/431/422/420ms`.

## Non-Goals

- Do not replace HSS with client-generated full-seed bootstrap.
- Do not keep duplicate production backends after a v2 candidate is retained.
- Do not add runtime feature flags or legacy compatibility branches.
- Do not make benchmark-only diagnostics influence protocol control flow.
- Do not implement digest-only A2B roots; the current review says digest-only
  binding is not sufficient.

Persistence/request boundary compatibility is allowed only while parsing stale
or rejected material. Internal code should normalize to the current typed
backend version immediately.

## Candidate Ranking

1. **Output-projector paired-root v2**
   - Larger plausible p50 win if it removes one full canonical-add equivalent:
     roughly `50ms` to `65ms` before smoke noise.
   - Main risk: it must preserve final output commitments while removing or
     replacing intermediate `x_client_base` canonical-add proof material.
   - Implement only after protocol review approves the paired-root proof shape.

2. **A2B v2**
   - Targets `new_a_bits` and `new_e_bits`, historically about `24ms` each in
     product worker substeps.
   - Main risk: current multiplication material hashes operand commitments.
     Removing per-bit operand commitments needs committed-root or
     equivalent-root binding.
   - Implement only after protocol review approves that root binding.

3. **Stop HSS-runtime protocol work temporarily**
   - If neither v2 root is approved, return to refactor-61/62 registration
     overlap, wallet-iframe activation UX, embedded policy, or optional-HSS
     work.

## Phase 0: Baseline Freeze

Goal:

- preserve a clean comparison point before protocol-shape code changes.

Tasks:

- [x] Record the current retained source commit and benchmark set.
- [x] Re-run native hidden-eval, direct browser/WASM artifact, and product
      registration smoke only if the worktree has changed materially since
      `20260610-112012Z`.
- [x] Save baselines under
      `crates/ed25519-hss/docs/benchmarks/refactor-64/optimization-6/`.
- [x] Confirm `hidden_eval_equivalence` and full crate tests pass before
      retaining protocol material.
- [x] Confirm `cargo hss-fv verus-check` passes before retaining protocol
      material.

Keep gate:

- baseline reports are reproducible enough to detect a product p50 win above
  smoke noise.

## Phase 1: Protocol Review Decision

Goal:

- choose exactly one v2 kernel to implement first.

Tasks:

- [x] Write the output-projector paired-root review note:
      - retained output commitments
      - removed intermediate commitments
      - root inputs and labels
      - downgrade behavior
      - negative tests
      - expected p50 win
- [x] Write the A2B v2 root-binding review note:
      - committed-root or equivalent-root binding
      - multiplication-material digest replacement
      - retained emitted output commitments
      - carry-order binding
      - downgrade behavior
      - negative tests
- [x] Decide the first implementation track:
      - `output_projector_paired_root_v2`
      - `a2b_committed_root_v2`
      - `blocked`
- [ ] If blocked, stop this plan and return to non-HSS-runtime latency work.

Decision rule:

- Choose output-projector v2 first if the paired root can remove at least one
  full canonical-add equivalent while preserving final output commitments.
- Choose A2B v2 first if root binding is approved and the paired projector root
  does not remove real logical work.

Review decision:

- Implement `output_projector_paired_root_v2` first, starting with typed
  backend-version plumbing and downgrade tests. The semantic projector rewrite
  stays gated on approval of the paired-root commitment replacement.
- Keep `a2b_committed_root_v2` as the second candidate. It is still viable, but
  the current multiplication material hashes operand commitments, so removing
  per-bit operand commitments requires committed-root or equivalent-root
  binding before implementation.
- Continue non-HSS runtime work if paired-root review fails or if scaffold-only
  benchmark/validation exposes product risk.

Implementation result:

- The semantic paired-root arithmetic rewrite did not produce the expected
  product win. It was rejected after product smoke showed artifact p50 around
  `503-519ms`.
- The regression was amplified by accidentally displacing the retained mixed
  shared-mask path, which moved masked client-output p50 from about `4ms` to
  about `59-61ms`.
- The mixed shared-mask path is restored. Current product smoke is back to the
  `466-470ms` artifact p50 range.
- The remaining output-projector v1 work in code is metadata/binding
  scaffolding, not a retained semantic projector arithmetic replacement.

### Output-Projector Paired-Root Review Note

Retained output commitments:

- `canonical_seed` output commitments stay emitted and transport-bound.
- `client_output` commitments stay emitted because local backup/export flows
  consume that output shape.
- `x_relayer_base` commitments and transport bundles stay emitted for the
  relayer-side threshold material.
- Input commitments/provenance for reduced scalar `a`, `tau`, and optional mask
  stay bound into the projector root.

Removed intermediate commitments:

- The only approved removal target is projector-internal `x_client_base` /
  canonical-add proof material that does not leave the paired projector
  boundary.
- Scalar-reduction, tau transport validation, and final output bundle
  commitments remain protocol-bound unless the v2 proof explicitly replaces
  them.
- A shortcut such as proving only `a + 2*tau` is insufficient because it does
  not by itself preserve the required `client_output` and `x_relayer_base`
  commitments under both projection modes.

Root inputs and labels:

- backend/kernel version, projector label, projection mode, scalar width
  `256`, modulus id `ed25519_l`, output owner labels, and per-output labels
  must be public root inputs.
- reduced scalar `a`, `tau`, and optional mask commitments/provenance must be
  bound into the root with side/owner labels.
- Client-masked mode must bind mask commitments; unmasked mode must bind the
  absence of a mask as a distinct public mode.

Downgrade behavior:

- v1 material cannot satisfy a v2 projector root.
- v2 material cannot be accepted by the v1 output projector.
- Mixed v1/v2 params, evaluation key, worker request, or output bundle metadata
  must fail before hidden evaluation starts.

Negative tests:

- wrong backend version, projection mode, owner, label, scalar width, modulus
  id, missing mask binding, altered `client_output` commitment, altered
  `x_relayer_base` commitment, and mixed v1/v2 material.

Expected p50 win:

- Product worker substeps previously showed output-projector client-base around
  `60ms` and relayer-output around `65ms`.
- A retained paired-root rewrite must move native output-projector p50, direct
  browser/WASM worker-handle p50, and product `ed25519EvaluationArtifactMs` p50
  above smoke noise. A benchmark-only allocation win is not enough.

### A2B v2 Root-Binding Review Note

Committed-root or equivalent-root binding:

- Current multiplication material hashes operand commitments. A2B v2 needs a
  reviewed root commitment or equivalent binding that replaces those per-bit
  operand commitments without widening evaluator-visible secrets.
- A digest-only root remains rejected because it does not prove the same
  committed operand relationship consumed by multiplication material.

Multiplication-material digest replacement:

- The replacement must bind arithmetic input commitments/provenance, share-side
  tags, public bit indexes, carry-order policy, caller label, and output
  commitment policy.
- Carry material must bind previous carry provenance, decomposed left/right bit
  provenance, `xor_ab`, `a_xor_carry`, and emitted output bit commitments in a
  fixed public order.

Retained commitments and carry-order binding:

- Arithmetic input share commitments remain retained.
- Emitted Boolean output bit commitments remain retained because callers
  consume them.
- Carry order must be public, fixed-width, and downgrade-tested; skipped or
  reordered carry indexes must fail.

Downgrade and negative tests:

- wrong backend version, mixed material, wrong caller label, wrong width,
  swapped share sides, altered arithmetic commitment/provenance, altered root,
  skipped/reordered carry indexes, and altered emitted output commitments.

Expected p50 win:

- A2B v2 targets `new_a_bits` and `new_e_bits`, historically about `24ms` each
  in product worker substeps. Retained output/carry overhead means the net win
  is likely smaller than the output-projector candidate.

## Phase 2: Typed Backend Version Scaffold

Goal:

- make invalid v1/v2 material mixing unrepresentable before changing kernel
  semantics.

Architecture:

```rust
enum HiddenEvalKernelVersion {
    V2OutputProjectorPairedRoot,
    V2A2BCommittedRoot,
}

struct HiddenEvalBackendProfile {
    kernel_version: HiddenEvalKernelVersion,
    transcript_domain: &'static str,
}
```

The final implementation should use names that match existing crate style. The
important property is that backend version is a typed value, not an ad-hoc
string checked repeatedly in core logic.

Initial scaffold inspection:

- Before Phase 2, `DdhHssParams` and `DdhHssEvaluationKey` carried
  `backend_version: String`.
- Key generation filled both fields from `DDH_HSS_BACKEND_VERSION`.
- `ddh/mod.rs` re-exports `DDH_HSS_BACKEND_VERSION`, and wire artifacts carry
  the evaluation key through request/response types.
- Phase 2 introduces the typed version at construction and executor entry, then
  serializes/parses strings only at wire, artifact, persistence, and
  test-fixture boundaries.

Tasks:

- [x] Add a typed hidden-eval backend/kernel version.
- [x] Carry the typed version through:
      - [x] params / evaluation key construction
      - [x] client request
      - [x] evaluator driver state
      - [x] artifact build
      - [x] worker request/response messages
      - [x] benchmark reports
- [x] Parse raw artifact/backend strings once at request/persistence/test
      boundaries.
- [x] Reject mixed-version material before hidden eval starts.
- [x] Add type/static fixtures or tests rejecting invalid version combinations.
- [x] Keep v1 code only as fixture/baseline code during the experiment; delete
      obsolete production paths after a v2 candidate is retained.

Status:

- `DdhHssBackendVersion` now carries the current backend version as a typed
  value while preserving the existing `ddh_hss_backend_v0` wire string.
- `DdhHssParams` and `DdhHssEvaluationKey` now carry
  `DdhHssBackendVersion`.
- Keygen constructs params/evaluation keys with `DdhHssBackendVersion::CURRENT`.
- Unknown backend-version strings are rejected during deserialization before
  they become internal params or evaluation keys.
- A params/evaluation-key version-pair guard now exists at public-state
  construction. It is mostly a v2 guardrail until a second version exists.
- Client OT offers, client OT requests, client/server driver state, staged
  evaluator artifacts, evaluation reports, native benchmark reports, and
  allocation benchmark reports now expose the typed backend version.
- Worker transport frames now carry the typed backend version and reject
  unsupported versions before payload decoding.
- Client/server state materialization now rejects backend-version mismatches
  before a runtime session is reconstructed.

Validation:

- [x] focused backend-version unit tests
- [x] hidden-eval equivalence for the unchanged kernel
- [x] protocol-flow filtered integration tests
- [x] wasm32 library check with `browser-benchmark`
- [x] direct-WASM artifact smoke to prove version plumbing does not regress

Direct browser/WASM smoke:

- Command:
  `node crates/ed25519-hss/scripts/collect_browser_cache_benchmark.mjs --debug-port 57514 --server-origin http://127.0.0.1:8765 --bundle-path generated/bundle.json --timeout-ms 180000 --output crates/ed25519-hss/docs/benchmarks/refactor-64/optimization-6/browser-ddh-hidden-eval-typed-backend-version.json`
- Output:
  `crates/ed25519-hss/docs/benchmarks/refactor-64/optimization-6/browser-ddh-hidden-eval-typed-backend-version.json`
- Result:
  - `browser_ddh_available`: `true`
  - `browser_ddh_reference_match`: `true`
  - `browser_ddh_mean_ns`: `200866666.71435037`
  - `browser_ddh_probe_total_hidden_eval_ns`: `203500000`
  - `browser_ddh_round_mean_ns`: `128400000`
  - `browser_ddh_schedule_mean_ns`: `32400001`

## Phase 3A: Output-Projector Paired-Root v1

Goal:

- prove `x_client_base` and `x_relayer_base` under one projector root while
  removing at least one full canonical-add/sub/select equivalent.

Current v1 shape:

1. `tau = tau_client + tau_relayer mod L`
2. `x_client_base = a + tau mod L`
3. `client_output = x_client_base` or `x_client_base + mask`
4. `x_relayer_base = x_client_base + tau mod L`
5. emit `canonical_seed`, `client_output`, and `x_relayer_base` bundles

Required paired-root inputs:

- backend/kernel version
- projector label
- projection mode
- scalar width `256`
- modulus id `ed25519_l`
- `reduced_a_bits` commitments/provenance
- `tau_bits` commitments/provenance
- optional mask commitments/provenance
- output labels for `canonical_seed`, `client_output`, and `x_relayer_base`

Retained commitments:

- final output commitments for `canonical_seed`
- final output commitments for `client_output`
- final output commitments and transport bundles for `x_relayer_base`
- input commitments/provenance for `a`, `tau`, and optional mask

Candidate removed commitments:

- intermediate selected `x_client_base` material that does not leave the
  paired projector boundary
- per-step canonical-add intermediate commitments that are replaced by the
  paired root and final output commitments

Protocol review package:

- [x] Draft the review package from the current v1 code path.
- [x] Get explicit approval for the paired-root commitment replacement before
      implementing v2 projector semantics.

Current v1 code path:

- `compute_output_projector_core_bits` clamps and reduces `a` into
  `reduced_a_bits`, then computes `tau_bits = tau_client + tau_relayer mod L`
  from the relayer transport bundles.
- Trusted-server projection computes `x_client_base = a + tau mod L`, emits it
  as `ClientOutputValueKind::UnmaskedClientBase` with bundle label
  `x_client_base`, then computes `x_relayer_base = x_client_base + tau mod L`.
- Client-masked projection computes the same internal `x_client_base`, shares
  a `client_output_mask`, emits `client_output = x_client_base + mask mod L` as
  `ClientOutputValueKind::ClientBlindedBase` with bundle label
  `x_client_base_blinded`, then computes
  `x_relayer_base = x_client_base + tau mod L`.
- Both modes still build and emit final bundles for `canonical_seed`,
  `client_output`, and `x_relayer_base`.

Proposed v2 root:

- Root domain: `ddh_hss_output_projector_paired_root_v2`.
- Public root inputs:
  - typed backend version, projection mode, scalar width `256`, modulus id
    `ed25519_l`, and fixed projector label
  - output owner labels for `canonical_seed`, `client_output`, and
    `x_relayer_base`
  - output value kind domain tag: `unmasked_client_base` or
    `client_blinded_base`
  - output bundle labels: `canonical_seed`, `x_client_base` or
    `x_client_base_blinded`, and `x_relayer_base`
- Committed/private root inputs:
  - reduced `a` commitments/provenance
  - `tau` commitments/provenance
  - mask commitments/provenance in client-masked mode
  - explicit no-mask mode binding in trusted-server mode
- Output bindings retained outside the paired root:
  - final `canonical_seed` output commitment
  - final `client_output` commitment and packet binding
  - final `x_relayer_base` transport bundle commitments
  - existing evaluation digest/output delivery bindings

Approval criteria:

- The paired root may replace only projector-internal canonical-add proof
  material for `x_client_base` and the paired relayer derivation.
- Final output commitments and output packet/transport bindings remain emitted
  unless the boundary format is explicitly versioned.
- The v2 proof must bind both equations:
  `client_output = a + tau` or `a + tau + mask`, and
  `x_relayer_base = a + 2*tau`.
- Public branches may depend only on backend version, projection mode, scalar
  width, modulus id, and loop indexes.
- The rewrite must not make the evaluator observe a full Ed25519 seed, full
  signing scalar, mask value, or unmasked client output in client-masked mode.

Rejected shortcut:

- A direct `x_relayer_base = a + 2*tau` proof alone is not sufficient. It does
  not bind the `client_output` relationship, and masked mode needs the
  `x_client_base`/mask relationship preserved without revealing
  `x_client_base`.

Required negative tests:

- unknown or wrong backend version
- mixed v1/v2 params, evaluation key, worker request, or output bundle metadata
- wrong projection mode
- wrong scalar width
- wrong modulus id
- wrong output owner
- wrong output label
- wrong output value-kind domain tag
- missing no-mask binding in trusted-server mode
- missing mask binding in client-masked mode
- altered reduced-`a` commitment/provenance
- altered `tau` commitment/provenance
- altered mask commitment/provenance
- altered `client_output` commitment
- altered `x_relayer_base` commitment
- v1 output material accepted under v2, or v2 material accepted under v1

Implementation slice after approval:

1. Add a typed backend variant for the approved v2 projector backend.
2. Add projector root metadata structs and label/domain constants.
3. Add the v2 root builder with narrow typed inputs for each projection mode.
4. Add the v2 output-projector kernel behind the typed backend version.
5. Keep final output wire bundles identical for the first implementation pass.
6. Add v1/v2 semantic fixtures that compare decoded `client_output`,
   `x_relayer_base`, and public key outputs.
7. Run native hidden-eval, direct browser/WASM artifact, product smoke, and
   formal verification gates before retaining the rewrite.

Tasks:

- [x] Draft protocol-review package from the current v1 projector code path.
- [x] Approve the paired-root commitment replacement.
- [x] Add typed backend variant for the approved v2 projector backend.
- [x] Add root metadata structs, root builder, and label constants for
      projector binding v1.
- [ ] Add a retained paired projection kernel with fixed public width.
      The first semantic implementation was benchmarked and rejected.
- [x] Preserve existing output wire bundles unless the backend metadata
      explicitly changes at the boundary.
- [ ] Add complete negative tests:
      - [x] wrong output value-kind domain tag
      - [x] missing mask binding in client-masked mode
      - [x] altered `client_output` commitment
      - [x] trusted vs masked projection root separation
      - [x] wrong backend version through existing transport/backend parser
            rejection
      - [ ] mixed v1/v2 projector material after a second accepted version is
            retained
      - [ ] wrong projection mode in full artifact verification
      - [ ] wrong owner
      - [ ] wrong label
      - [ ] wrong scalar width
      - [ ] wrong modulus id
      - [ ] missing no-mask binding in trusted-server mode
      - [ ] altered reduced-`a` commitment/provenance
      - [ ] altered `tau` commitment/provenance
      - [x] altered mask commitment/provenance
      - [ ] altered `x_relayer_base` commitment
      - [ ] v1 output material accepted under v2
      - [ ] v2 output material accepted under v1
- [x] Add semantic tests comparing decoded v2 outputs with v1 fixture outputs.
- [x] Benchmark native output projector and total hidden eval.
- [x] Benchmark direct browser/WASM artifact.
- [x] Run product registration smoke.
- [x] Rename retained scaffold from paired-root wording to
      `output_projector_binding_v1`.

Implementation note:

- Implemented `ddh_hss_backend_v1_output_projector_binding`.
- The arithmetic material root seed binds the typed backend version, key
  context, scalar width, modulus id, and reduced-`a`/`tau` commitment metadata.
- The final output-projector binding additionally binds projection mode, mask
  metadata, output value kind, `canonical_seed`, `client_output`, and
  `x_relayer_base` commitments.
- The retained projector arithmetic is still the current mixed shared-mask
  arithmetic. The semantic root-bound arithmetic candidate was removed after
  product smoke failed the keep gate.

Validation:

- `cargo test --manifest-path crates/ed25519-hss/Cargo.toml output_projector --lib`
- `cargo test --manifest-path crates/ed25519-hss/Cargo.toml hidden_output_projection_matches_reference_output_shares --lib`
- `cargo test --manifest-path crates/ed25519-hss/Cargo.toml hidden_eval_equivalence`
- `cargo test --manifest-path crates/ed25519-hss/Cargo.toml protocol_flow`
- `cargo check --release --manifest-path crates/ed25519-hss/Cargo.toml --lib`
- `cargo check --manifest-path crates/ed25519-hss/Cargo.toml --target wasm32-unknown-unknown --features browser-benchmark --lib`
- `cargo test --manifest-path crates/ed25519-hss/Cargo.toml`
- `cargo hss-fv verus-check`
- After restoring the mixed shared-mask path:
  - `cargo test --manifest-path crates/ed25519-hss/Cargo.toml output_projector --lib`
  - `cargo test --manifest-path crates/ed25519-hss/Cargo.toml hidden_eval_equivalence`
  - `cargo test --manifest-path crates/ed25519-hss/Cargo.toml protocol_flow`
  - `cargo check --release --manifest-path crates/ed25519-hss/Cargo.toml --lib`
  - `cargo check --manifest-path crates/ed25519-hss/Cargo.toml --target wasm32-unknown-unknown --features browser-benchmark --lib`
  - `cargo test --manifest-path crates/ed25519-hss/Cargo.toml`: `108 passed, 4 ignored`
  - `cargo hss-fv verus-check`: `96 verified, 0 errors`; anti-drift `10 passed`

Native benchmark:

- Output:
  `crates/ed25519-hss/docs/benchmarks/refactor-64/optimization-6/ddh-hidden-eval-output-projector-paired-root-v1.json`
- Command:
  `cargo run --release --manifest-path crates/ed25519-hss/Cargo.toml --bin benchmark_ddh_hidden_eval -- --stage-warmup 0 --stage-iterations 1 --samples 6 --output crates/ed25519-hss/docs/benchmarks/refactor-64/optimization-6/ddh-hidden-eval-output-projector-paired-root-v1.json`
- Result:
  - pre-rename backend version:
    `ddh_hss_backend_v1_output_projector_paired_root`
  - `output_projector` median: `15.689ms`
  - `total_hidden_eval` median: `127.461ms`
  - retained Phase 7I native output-projector p50 was about `16.151ms`
  - net native output-projector improvement: about `0.46ms`

Retention read:

- Reject the semantic root-bound arithmetic candidate for now. It did not
  produce a product artifact win after accounting for the restored mixed
  shared-mask path.
- Keep the output-projector binding scaffold only as protocol-hardening /
  future-version plumbing while it remains product-neutral.
- This does not deliver the hoped-for `50ms` class win because earlier Phase 7I
  work had already reduced the output-projector p50 and because the product
  worker path is dominated by the existing canonical client-base and relayer
  output additions.

Direct browser/WASM benchmark:

- Output:
  `crates/ed25519-hss/docs/benchmarks/refactor-64/optimization-6/browser-ddh-hidden-eval-output-projector-paired-root-v1.json`
- Result:
  - `browser_ddh_available`: `true`
  - `browser_ddh_reference_match`: `true`
  - `browser_ddh_mean_ns`: `186966666.6984558`
  - `browser_ddh_probe_total_hidden_eval_ns`: `186800001`
  - `browser_ddh_round_mean_ns`: `121299998`
  - `browser_ddh_schedule_mean_ns`: `30100001`
  - `browser_ddh_output_projector_local_materializations`: `2048`
- Previous typed-backend direct-WASM smoke reported
  `browser_ddh_mean_ns` about `200.867ms`, so this is about `13.9ms` faster
  in the direct browser benchmark. The probe total moved from about `203.5ms`
  to `186.8ms`, a roughly `16.7ms` improvement.

Product registration smoke:

- Semantic paired-root arithmetic candidate:
  - `20260610-152426Z`: `ed25519EvaluationArtifactMs` p50
    `515/515/519/512ms`
  - `20260610-152611Z`: no-rebuild repeat p50 `503/506/505/505ms`
  - rejected because it regressed product p50 versus `20260610-135445Z`
    `471/468/462/463ms`
- Binding-only path before mixed-mask restoration:
  - `20260610-153553Z`: p50 `515/515/516/515ms`
  - root cause: masked client-output p50 regressed from about `4ms` to
    `59-61ms`
- Binding plus restored mixed shared-mask path:
  - `20260610-154615Z`: p50 `468/470/467/466ms`
  - output-projector p50 `148/149/151/151ms`
  - masked client-output p50 `4/4/4/4ms`
  - local materializations stay at `2560`
  - product latency is back to baseline/noise, with no retained latency win

Keep gate:

- native output-projector p50 improves at least modestly
- direct browser/WASM worker-handle p50 improves above noise
- product `ed25519EvaluationArtifactMs` p50 improves above smoke noise
- no output commitment or transport-bundle regression

## Phase 3B: A2B v2 With Committed Root

Goal:

- reduce `new_a_bits` / `new_e_bits` conversion work by replacing per-bit
  intermediate commitment material with an approved root/carry proof shape.

Required root inputs:

- backend/kernel version
- caller label
- public word width
- left/right arithmetic share commitments
- left/right arithmetic share provenance digests
- left/right share-side tags
- carry-order policy id
- output commitment policy id

Required carry material inputs:

- root commitment or equivalent binding proof
- public bit index
- previous carry provenance digest
- decomposed left/right bit provenance digests
- `xor_ab` provenance digest
- `a_xor_carry` provenance digest

Retained commitments:

- arithmetic input share commitments
- emitted Boolean output bit commitments
- committed root material per side, or reviewed equivalent binding

Candidate removed commitments:

- per-bit committed left/right decomposition words
- per-bit zero commitments
- intermediate committed `xor_ab`, `a_xor_carry`, `carry_gate`, and
  `next_carry` values that never leave the A2B boundary

Binding decision:

- Use committed A2B root material per share side.
- The root material is not a digest-only transcript note. It is the committed
  replacement for the per-bit operand commitments consumed by the current
  multiplication material path.
- The root binds backend/kernel version, caller label, public width, left and
  right arithmetic input commitments, left and right arithmetic provenance
  digests, share-side tags, carry-order policy, and output commitment policy.
- The root does not bind actual emitted output commitments directly. That would
  be circular because carry material is needed before those output commitments
  exist. The final A2B boundary must bind the root digest and actual emitted
  output bit commitments together.
- Each carry-material derivation binds the root commitment, public bit index,
  previous carry provenance, decomposed bit provenance, `xor_ab` provenance,
  and `a_xor_carry` provenance.
- Downgrade protection must reject v1 material under v2 and v2 root material
  under v1 at artifact, worker, and request/persistence boundaries.
- Constant-time rule: root and carry metadata may depend on public width,
  public labels, public bit index, commitments, and provenance digests; secret
  share values and carry bits may influence only bit-masked arithmetic.

Tasks:

- [x] Add typed current A2B kernel-version scaffold and parser rejection tests
      for unknown kernel identifiers.
- [x] Bind the current A2B kernel version into v1 zero material and bit
      decomposition provenance so later v2 material has an explicit downgrade
      boundary.
- [x] Add committed-root material builders.
- [x] Add carry material builders.
- [x] Add fixed-width A2B v2 conversion kernel.
- [x] Preserve output bit commitments expected by callers.
- [x] Add negative tests:
      - [x] stale backend wire strings at serialized session-state and
            staged-artifact deserialization boundaries
      - [x] mixed v1/v2 A2B root/carry material made unrepresentable by
            deleting the legacy v1 kernel variant
      - [x] wrong caller label at carry-material-base preparation
      - [x] wrong width through arithmetic-pair validation
      - [x] swapped left/right share sides through arithmetic-pair validation
      - [x] altered arithmetic input commitment in root material
      - [x] altered arithmetic provenance digest
      - [x] altered root commitment/digest through v1/v2 root rejection
      - [x] skipped/out-of-range carry index
      - [x] reordered carry index changes carry-material digest and is rejected
            at carry-gate evaluation
      - [x] altered emitted output bit commitment at the A2B boundary digest;
            public artifact rejection is covered by `protocol_validation`
- [x] Add semantic tests comparing decoded v2 output bits with the pre-A2B
      Boolean reference for widths `1..=64`.
- [x] Benchmark `round_new_a_bits`, `round_new_e_bits`, `round_core`, and total
      hidden eval natively.
- [x] Benchmark direct browser/WASM artifact.
- [x] Run product registration smoke.

Implementation note:

- The live A2B derivation now uses `ddh_hss_a2b_kernel_v2_committed_root` and
  backend string `ddh_hss_backend_v2_a2b_committed_root`.
- Unknown A2B kernel-version wire strings are rejected at parse time.
- A v2 committed-root material builder now constructs per-side committed root
  material and binds kernel version, label, width, arithmetic input
  commitments/provenance, share-side tags, carry-order policy, and output
  commitment policy.
- A v2 carry-material builder now binds committed-root material, bit index,
  previous carry provenance, decomposed bit provenance, `xor_ab` provenance, and
  `a_xor_carry` provenance.
- The fixed-width v2 conversion kernel keeps per-bit decomposed operands,
  `xor_ab`, and `a_xor_carry` as core words. It materializes only the emitted
  output `sum` bits and uses the carry-material digest for the carry-gate
  multiplication helper.
- The first implementation used fresh SHA-256 carry-material derivation per
  bit and regressed. The retained candidate precomputes a BLAKE3
  carry-material base once per A2B word and clones it per bit.
- Current negative coverage rejects wrong root labels, out-of-range carry
  indexes, altered arithmetic commitments/provenance, altered emitted output
  bit commitments at the A2B boundary digest, and v1 root material passed to
  the v2 carry-material builder.
- Artifact/worker boundary coverage now rejects stale backend strings while
  deserializing serialized evaluator/garbler driver states and staged
  artifacts. The old backend enum variants were deleted, so stale backend
  material cannot become internal state.
- Local A2B v2 root/carry material is current-only after deleting the legacy v1
  kernel variant. Wrong-index carry material is rejected before the carry-gate
  multiplication helper runs.

Validation:

- `cargo check --release --manifest-path crates/ed25519-hss/Cargo.toml --lib`
- `cargo check --manifest-path crates/ed25519-hss/Cargo.toml --target
  wasm32-unknown-unknown --features browser-benchmark --lib`
- `cargo test --manifest-path crates/ed25519-hss/Cargo.toml a2b_kernel --lib`:
  `2 passed`
- `cargo test --manifest-path crates/ed25519-hss/Cargo.toml phase_a_a2b --lib`:
  `6 passed`
- `cargo test --manifest-path crates/ed25519-hss/Cargo.toml hidden_eval_equivalence`:
  `3 passed`
- `cargo test --manifest-path crates/ed25519-hss/Cargo.toml protocol_validation`:
  `14 passed`
- `cargo test --manifest-path crates/ed25519-hss/Cargo.toml protocol_flow`:
  `11 passed, 4 ignored`
- `cargo hss-fv verus-check`: `96 verified, 0 errors`; anti-drift `10 passed`
- `cargo test --manifest-path crates/ed25519-hss/Cargo.toml`:
  `113 passed, 4 ignored` after the BLAKE3-base v2 kernel candidate.
- Post-cleanup `cargo hss-fv verus-check` after deleting obsolete backend/A2B
  kernel variants: `96 verified, 0 errors`; anti-drift `10 passed`.

Native benchmark:

- Output:
  `crates/ed25519-hss/docs/benchmarks/refactor-64/optimization-6/ddh-hidden-eval-a2b-kernel-version-scaffold.json`
- Command:
  `cargo run --release --manifest-path crates/ed25519-hss/Cargo.toml --bin benchmark_ddh_hidden_eval -- --stage-warmup 0 --stage-iterations 1 --samples 6 --output crates/ed25519-hss/docs/benchmarks/refactor-64/optimization-6/ddh-hidden-eval-a2b-kernel-version-scaffold.json`
- Result:
  - `total_hidden_eval` median: `126.177ms`
  - `round_core` median: `84.536ms`
  - `output_projector` median: `17.260ms`
  - `message_schedule` median: `20.580ms`

A2B v2 native benchmark:

- Rejected SHA-256 carry-material output:
  `crates/ed25519-hss/docs/benchmarks/refactor-64/optimization-6/ddh-hidden-eval-a2b-v2-committed-root-kernel.json`
- Rejected SHA-256 result:
  - `total_hidden_eval` median: `137.310ms`
  - `round_core` median: `92.671ms`
  - regressed versus scaffold baseline `126.177ms` / `84.536ms`
- Retained BLAKE3-base output:
  `crates/ed25519-hss/docs/benchmarks/refactor-64/optimization-6/ddh-hidden-eval-a2b-v2-committed-root-kernel-blake3-base.json`
- Retained BLAKE3-base result:
  - `total_hidden_eval` median: `118.436ms`
  - `round_core` median: `79.376ms`
  - `message_schedule` median: `18.956ms`
  - `output_projector` median: `16.848ms`
  - native p50 improvement versus scaffold baseline: `7.741ms`
  - native p50 improvement versus the rejected SHA-256 attempt: `18.874ms`

Direct browser/WASM benchmark:

- Output:
  `crates/ed25519-hss/docs/benchmarks/refactor-64/optimization-6/browser-ddh-hidden-eval-a2b-v2-committed-root-blake3-base.json`
- Result:
  - `browser_ddh_available`: `true`
  - `browser_ddh_reference_match`: `true`
  - `browser_ddh_mean_ns`: `170500000`
  - `browser_ddh_probe_total_hidden_eval_ns`: `171299999`
  - `browser_ddh_round_mean_ns`: `109900000`
  - `browser_ddh_schedule_mean_ns`: `26900001`
  - improved versus typed-backend direct browser mean `200.867ms` and
    probe-total `203.500ms`

Product registration smoke:

- Run ID: `20260610-170749Z`
- Result: all four scenarios passed with five successful runs each.
- `ed25519EvaluationArtifactMs` p50:
  - wallet iframe, Ed25519 only: `445ms`
  - wallet iframe, Ed25519 plus ECDSA: `445ms`
  - host origin, Ed25519 only: `443ms`
  - host origin, Ed25519 plus ECDSA: `443ms`
- HSS worker `buildArtifactMs` p50:
  - wallet iframe scenarios: `438ms` / `438ms`
  - host-origin scenarios: `443ms` / `443ms`
- Compared with the output-projector binding/scaffold smoke
  `20260610-154615Z` at `468/470/467/466ms`, product artifact p50 improved by
  about `23/25/24/23ms`.
- Compared with the retained Phase 7I smoke `20260610-112012Z` at
  `450/445/443/442ms`, the result is roughly flat-to-slightly-positive:
  `5/0/0/-1ms`.
- Full wallet-iframe browser p50 remains dominated by passkey prompt and
  wallet iframe confirmation timing: `2452ms` / `2282ms`. Host-origin browser
  p50 is `1621ms` / `1637ms`.

Keep gate:

- `round_new_a_bits` and `round_new_e_bits` improve enough to move total hidden
  eval
- direct browser/WASM moves in the same direction
- product `ed25519EvaluationArtifactMs` improves above smoke noise
- protocol review signs off on the replacement commitment binding

Retention read:

- Retain the A2B v2 committed-root BLAKE3-base candidate. It improves the
  typed-backend/scaffold comparison in native, direct browser/WASM, and product
  smoke, and it remains at least neutral against the stronger retained Phase 7I
  product baseline.
- Treat the candidate as not fully finalized until the final post-cleanup
  validation pass is recorded and the retained code is committed.

## Phase 4: Boundary And Downgrade Tests

Goal:

- make v2 material impossible to misuse at artifact, worker, request, and
  persistence boundaries.

Tasks:

- [x] Add artifact parser tests rejecting stale backend wire strings.
- [x] Add worker serialized-session boundary tests rejecting stale backend wire
      strings before materialization.
- [x] Delete legacy backend and A2B kernel enum variants from internal domain
      types.
- [x] Keep transport-frame tests rejecting unsupported backend wire strings.
- [x] Close mixed-backend parser tests by deleting the legacy backend/A2B
      variants and rejecting stale wire strings at existing parser boundaries.
- [x] Close worker request kernel-mismatch tests by keeping kernel version out
      of request metadata and rejecting stale backend strings before worker
      materialization.
- [x] Close stale v1 request/persistence tests by deleting v1 internal material
      states after retention.
- [x] Add downgrade coverage by deleting v1 material states from internal types
      and rejecting stale v1 wire strings at parser boundaries.
- [x] Add tamper tests for labels, widths, owners, commitments, and root
      material.
- [x] Remove obsolete compatibility paths once v2 is retained.

## Phase 5: Constant-Time Review

Goal:

- ensure the v2 kernel does not introduce secret-dependent timing behavior.

Rules:

- Branches may depend only on public kernel version, public projection mode,
  public word width, and public loop index.
- Allocation sizing may depend only on public shape.
- Table/index access may depend only on public indexes.
- Secret-derived bits, carry values, arithmetic shares, and hidden scalar words
  must not control branches, early returns, allocation sizes, table indexes,
  division, or modulo operations.

Tasks:

- [x] Add constant-time notes beside the v2 implementation.
- [x] Review new Rust code manually for secret-dependent branch/control flow.
- [x] Attempt static timing analysis on touched Rust files where practical.
- [x] Triage every flagged division/modulo/branch/table access as public-shape
      or secret-derived.
- [ ] Include ARM64 and x86_64 analyzer runs if the analyzer supports the
      touched files cleanly.

Constant-time review status:

- Manual review found new branches only on public projection mode, public
  shape/length checks, fixed loop indexes, and public Ed25519 modulus bits.
- New root-bound multiplication keeps the existing secret-share arithmetic
  shape and uses public width `1` for reductions.
- Static analyzer run was blocked because the referenced
  `ct_analyzer/analyzer.py` script is not present in the local
  `constant-time-analysis` skill directory.
- ARM64/x86_64 analyzer runs are still pending on a local analyzer install.

## Phase 6: Benchmark And Retention Gates

Benchmark order:

1. native hidden-eval targeted benchmark
2. native allocation/memory-stress benchmark
3. direct browser/WASM artifact benchmark
4. product registration smoke
5. embedded/iOS benchmark after desktop/browser retention

Required outputs:

- all benchmark JSON under
  `crates/ed25519-hss/docs/benchmarks/refactor-64/optimization-6/`
- summary entry in `crates/ed25519-hss/docs/benchmarks/refactor-64/summary.md`
- retained/rejected note in this plan

Keep only if:

- protocol review is complete
- hidden-eval semantic/equivalence tests pass
- negative downgrade/tamper tests pass
- constant-time review passes
- native and direct-WASM timings improve a measured target
- product smoke confirms a real `ed25519EvaluationArtifactMs` p50 win
- complexity is proportional to the measured improvement

Reject or revert if:

- the win appears only in allocation counters
- product smoke regresses
- direct-WASM regresses materially
- root binding is ambiguous
- commitments are removed without reviewed replacement binding
- v1/v2 material can mix after boundary parsing

## Phase 7: Formal Verification And Finalization

Tasks:

- [x] Run `cargo test --manifest-path crates/ed25519-hss/Cargo.toml
      hidden_eval_equivalence`.
- [x] Run `cargo test --manifest-path crates/ed25519-hss/Cargo.toml`.
- [x] Run `cargo hss-fv verus-check`.
- [x] Run wasm32 check for the crate paths affected by worker artifacts.
- [x] Run product registration smoke after SDK rebuild.
- [x] Delete obsolete v1 production paths after mixed-version downgrade tests.
- [x] Update `optimization-5.md` and `docs/refactor-64-hss-protocol-runtime-latency.md`
      with the retained/rejected decision.

## Immediate Next Steps

- [x] Treat A2B v2 committed-root as retained after focused negative coverage,
      semantic width tests, native/direct-WASM/product benchmarks, and
      post-cleanup formal checks.
- [x] Do not add another current-backend helper-level HSS runtime micro-edit
      without a new proof that it reduces logical work. The recent rejected
      output-projector, A2B packing, material-base, and shifted-sigma candidates
      covered the obvious byte-equivalent micro-slices.
- [x] Choose the next implementation lane from:
   - a protocol-reviewed output-projector/root-v2 replacement,
   - a new backend-versioned B2A or multiplication-material root,
   - refactor-61/62/66 registration-path overlap or precompute work that helps
     both Passkey and OTP flows.
- [x] Draft the backend-versioned B2A / multiplication-material root lane
      before implementation.
- [x] Complete a first review pass of the B2A / multiplication-material root
      binding and record implementation blockers.
- [x] Run the first B2A-only core-sigma root experiment and reject it after the
      native keep gate failed.
- [ ] Approve a stronger B2A committed-root binding before re-implementing
      `ddh_hss_backend_v3_b2a_root`.
- [ ] Approve the multiplication-material root binding before implementing the
      later v4 multiplication-root backend.
- [ ] ARM64/x86 static analyzer runs and physical embedded/iOS benchmarks remain
      external-environment work; do not block retained desktop/browser results
      on those measurements.

## Remaining Larger Experiments

Status: open. These are the remaining meaningful HSS runtime lanes after the
retained A2B/`Maj`/`Ch` work and the rejected helper-level experiments.

### Protocol-reviewed v2 work

Candidate work:

- A2B v2 follow-on:
  - Treat the retained committed-root BLAKE3-base A2B kernel as the baseline.
  - Only revisit A2B if a new proof shape removes additional logical work,
    changes the emitted commitment policy with review, or eliminates a larger
    carry/materialization family than the retained v2 slice.
  - Do not repeat the per-bit SHA-256 carry-material approach.
- Output-projector paired-root v2:
  - Revisit only with an approved proof that removes a product-visible
    canonical-add equivalent while retaining `canonical_seed`,
    `client_output`, and `x_relayer_base` commitments or a reviewed replacement
    boundary.
  - The earlier semantic rewrite failed product smoke; a new attempt needs a
    clearer replacement claim than the rejected paired-root arithmetic patch.
- B2A / multiplication-material root changes:
  - The first B2A-only core-sigma root improved small physical counters and
    failed native p50.
  - The next attempt should target a larger logical-work bucket, likely a
    stronger multiplication-material root or a combined B2A/mul-root design
    that reduces repeated operand commitment hashing across `Ch`, `Maj`,
    carry-like helpers, and Boolean combiners.
  - Any second B2A attempt or broader multiplication-root change needs an
    approved root-binding spec before Rust backend code.

Protocol to-do:

- [ ] Pick exactly one next protocol candidate.
- [ ] Write the candidate-specific approval packet with exact backend/kernel
      strings, operation kinds, boundary kinds, root inputs, emitted commitment
      policy, downgrade behavior, negative-test matrix, and expected logical
      work removed.
- [ ] Run physical-counter benchmarks before native p50.
- [ ] Run direct browser/WASM only after native p50 moves in the expected
      direction.
- [ ] Run product smoke only after direct browser/WASM confirms the lower-level
      win.
- [ ] Run full crate tests and `cargo hss-fv verus-check` before retention.

### Executor-wide representation rewrite

Candidate work:

- Replace the current hot executor representation with true stage-owned,
  arena-backed storage for core words, bit sides, commitments, provenance, and
  transient material.
- Make the representation rewrite semantics-preserving first. The expected win
  is from allocation locality, fewer small object moves, fewer materialization
  conversions, and better embedded/mobile memory behavior rather than protocol
  simplification.
- This is the right lane if protocol review blocks new root replacements or if
  embedded/iOS profiling shows allocator and memory-layout pressure dominate.

Required first deliverable:

- A byte-equivalence harness that proves the rewritten executor emits exactly
  the same artifacts as the retained backend before changing hot code broadly.

Harness to-do:

- [ ] Add deterministic fixture generation for retained backend inputs.
- [ ] Compare decoded outputs, output commitments, root digests, transcript
      labels, serialized staged artifacts, worker request/response payloads,
      and public evaluation reports byte-for-byte where the existing format is
      stable.
- [ ] Compare semantic decoded outputs where nondeterministic salts or random
      OT material intentionally differ.
- [ ] Run the harness before and after each representation slice.
- [ ] Keep the first representation patch behaviorless except for storage
      layout, then benchmark native, direct-WASM, product worker, and allocation
      counters.

Representation to-do:

- [ ] Map current `CoreBitWordSide`, `CoreBitWordPair`, local words, committed
      words, and output-projector material into ownership stages.
- [ ] Identify stage boundaries where committed material must still be emitted.
- [ ] Replace one internal stage with arena-backed indices.
- [ ] Prove byte equivalence before expanding the representation change.
- [ ] Retain only if native/direct-WASM/product p50 or embedded/mobile memory
      behavior improves enough to justify the complexity.

### Embedded/iOS-specific profiling and tuning

Candidate work:

- Measure the retained backend on representative low-power CPUs, iOS Safari /
  WebView, and any native/embedded WASM or Rust targets we expect to support.
- Separate CPU time, allocation count, peak memory, worker startup, WASM
  instantiation, code-cache behavior, and thermal/battery-sensitive repeated
  runs.
- Use this data to decide whether executor-wide representation work, allocator
  tuning, batch-size changes, worker reuse, or optional-HSS policy matters most
  for embedded/iOS.

Device to-do:

- [ ] Define the device matrix: desktop baseline, iOS Safari/WebView, low-end
      Android/WebView if relevant, and at least one lower-power embedded class.
- [ ] Add benchmark scripts that can run the same hidden-eval and artifact
      construction cases on those targets.
- [ ] Capture p50/p90/p99, allocation/peak-memory where available, startup
      cost, and repeated-run thermal drift.
- [ ] Compare host-origin and wallet-iframe style worker topologies where the
      platform supports both.
- [ ] Feed the results back into either the representation rewrite lane or a
      platform-specific runtime-tuning lane.

## Phase 8: B2A And Multiplication-Material Root v2

Goal:

- attack the remaining round-core logical-work buckets after A2B v2 retention
- reduce commitment/provenance derivations in B2A and local multiplication
  material where the current transcript shape requires per-bit commitments
- preserve the current HSS trust model, exportability, and threshold property

Why this is the next HSS lane:

- Current-backend output-projector variants have been exhausted without a
  retained product-visible win beyond Phase 7I and the retained scaffold.
- A2B v2 delivered the latest real protocol-kernel improvement by replacing
  per-bit committed carry material with committed-root material and a
  precomputed BLAKE3 base.
- B2A and multiplication material still consume per-bit commitments in hot
  round-core paths:
  - `temp1`
  - `temp2`
  - `state3`
  - message-schedule accumulation
  - `Ch` / `Maj` multiplication inputs

Current B2A shape:

- `split_local_bit_pair_to_arithmetic_word_pair_naive` and
  `materialize_core_bit_pair_to_arithmetic_word_pair_naive` build a base
  arithmetic word under `phase-a-bool-to-arith-base`.
- The base material binds each input bit provenance and commitment, then
  emits a committed local arithmetic pair.
- The packed left/right values stay local, but transcript material still scales
  with per-bit commitment material.
- The committed arithmetic output is consumed immediately by local arithmetic
  adders, then many outputs flow into A2B v2 or later B2A boundaries.

Current multiplication-material shape:

- `Ch`, `Maj`, and carry-like helpers use local multiplication material that
  hashes operand commitments or equivalent material.
- The current graph treats `Ch` and `Maj` as protocol-bound because their
  transient XOR products feed multiplication-material commitments.
- A2B v2 proved the useful pattern: replace repeated per-bit operand commitment
  hashing with a committed root plus operation/index/provenance-bound material.

Candidate backend identifiers:

- B2A-only first slice: `ddh_hss_backend_v3_b2a_root`
- Later multiplication-material slice:
  `ddh_hss_backend_v4_b2a_mul_root` or
  `ddh_hss_backend_v4_mul_material_root`; choose the exact v4 name after the
  multiplication-root review decides whether it depends on the v3 B2A root.

Candidate kernel identifiers:

- `ddh_hss_b2a_kernel_v2_committed_root`
- `ddh_hss_mul_material_kernel_v2_committed_root`

Candidate B2A root:

- Root label: `{label}/b2a_v2/root`
- Root domain: `phase-a-bool-to-arith-v2-root`
- Public inputs:
  - backend identifier
  - B2A kernel identifier
  - caller label digest
  - public width
  - share-side policy id
  - output arithmetic commitment policy id
- Committed/private inputs:
  - one committed Boolean-word root per side
  - aggregate bit provenance digest per side
  - aggregate bit commitment digest per side
- Emitted output:
  - the committed arithmetic left/right pair expected by existing arithmetic
    adders
  - an output digest that binds the Boolean root and arithmetic commitments

B2A-only v3 approval packet:

- Backend string: `ddh_hss_backend_v3_b2a_root`.
- Kernel string: `ddh_hss_b2a_kernel_v2_committed_root`.
- First caller family: message-schedule sigma B2A, because it already reaches
  the B2A boundary through `CoreBitWordPair` and avoids the higher-risk
  `Ch`/`Maj` multiplication transcript shape.
- Second caller family, only after the first slice benchmarks cleanly:
  `temp1`/`temp2`/`state3` B2A.
- Root construction:
  - derive one committed Boolean-word root per share side under
    `phase-a-bool-to-arith-v2-root`
  - bind backend string, B2A kernel string, caller label digest, width,
    share-side policy, output arithmetic commitment policy, aggregate
    provenance digest, and aggregate bit commitment digest
  - reject width outside `1..=64`, wrong share side, mismatched left/right
    width, mismatched per-bit provenance, and stale backend/kernel strings
- Output construction:
  - preserve the current packed left value and adjusted-right arithmetic value
  - build the arithmetic output commitments from the Boolean root material and
    output label
  - bind root commitment/provenance, output arithmetic commitment/provenance,
    width, label digest, and kernel string into the B2A output digest
- Downgrade behavior:
  - v2 A2B material and v3 B2A material are different domains
  - current v2 backend artifacts must fail under the v3 backend parser
  - v3 B2A root material must fail under the current v2 backend parser
  - stale B2A kernel strings must fail at artifact/session deserialization
    before hidden eval starts
- Constant-time rule:
  - all branches and allocations depend only on public width, public labels,
    public backend/kernel versions, and fixed caller family
  - share bits, aggregate digests, arithmetic shares, and root commitments must
    not control branch shape, allocation size, lookup indexes, division, modulo,
    or early return
- Approval question:
  - Does a committed Boolean-word root plus B2A output digest preserve the same
    audit surface as the current per-bit material passed directly to
    `phase-a-bool-to-arith-base`?
- Retention gate:
  - first native benchmark must improve message-schedule accumulation or total
    hidden eval without increasing logical materialization counts
  - direct browser/WASM must move in the same direction before product smoke
  - product smoke runs only if lower-level timings justify crossing the SDK
    boundary

B2A-only v3 review note:

- Current physical-counter baseline:
  `crates/ed25519-hss/docs/benchmarks/refactor-64/optimization-6/ddh-hidden-eval-b2a-root-review-physical-counters.json`.
- Current backend string in that diagnostic run:
  `ddh_hss_backend_v2_a2b_committed_root`.
- Current B2A pressure per hidden eval:
  - `physical_keyed_digest_phase_a_bool_to_arith_base`: `896`
  - `physical_derived_commitment_phase_a_bool_to_arith_base`: `1792`
- The first safe B2A-only design still derives per-bit commitments so the root
  can bind aggregate bit commitment material. That means it cannot remove the
  `1792` B2A-derived commitment hashes in the current trust model.
- The likely first-slice win is smaller: reduce the B2A base-material fan-in
  from per-bit provenance/commitment slices to one committed root/output digest
  per word, and remove the scratch vector that stores per-bit material before
  hashing.
- Treat `ddh_hss_backend_v3_b2a_root` as an experiment until native and
  direct-WASM benchmarks show movement. Revert if it only changes transcript
  shape without measurable latency or embedded allocation benefit.

First B2A-only v3 experiment result:

- Temporary backend string: `ddh_hss_backend_v3_b2a_root`.
- Scope: message-schedule sigma B2A through `CoreBitWordPair`.
- Native benchmark outputs:
  - `crates/ed25519-hss/docs/benchmarks/refactor-64/optimization-6/ddh-hidden-eval-b2a-root-v3-core-sigma.json`
  - `crates/ed25519-hss/docs/benchmarks/refactor-64/optimization-6/ddh-hidden-eval-b2a-root-v3-core-sigma-repeat.json`
  - `crates/ed25519-hss/docs/benchmarks/refactor-64/optimization-6/ddh-hidden-eval-b2a-root-v3-core-sigma-physical-counters.json`
- Native p50 was `124.617562ms` and repeat `124.2108335ms`; this failed the
  lower-level keep gate against the retained A2B v2 best `118.436ms`.
- After reverting the code path, the restored v2 backend benchmark
  `crates/ed25519-hss/docs/benchmarks/refactor-64/optimization-6/ddh-hidden-eval-b2a-root-v3-reverted-a2b-v2.json`
  reference-matched with native p50 `124.5294375ms` and backend string
  `ddh_hss_backend_v2_a2b_committed_root`, confirming the B2A-root experiment
  was noise-band rather than a retained latency win.
- Physical counters improved in the targeted B2A base bucket:
  - keyed digest derivations: `896 -> 768`
  - derived commitment hashes: `1792 -> 1536`
- Decision: reject and revert the code path. The counter improvement is useful
  design evidence, but the material-root shape did not reduce runtime enough
  to justify a backend-version bump, direct-WASM benchmark, or product smoke.
- Follow-up requirement: any second B2A attempt needs a stronger proof shape
  that removes more logical work than this core-sigma aggregate-root slice.

Counter-guided next target:

- The restored v2 physical-counter baseline shows the larger remaining hash
  buckets are outside the B2A base path:
  - `physical_keyed_digest_eval_xor_local_word`: `143218`
  - `physical_derived_commitment_eval_xor_local_word`: `140004`
  - `physical_keyed_digest_eval_mul_local_material`: `35328`
  - `physical_derived_commitment_eval_mul_local_material`: `70656`
  - `physical_keyed_digest_eval_mul_local`: `21504`
  - `physical_derived_commitment_eval_mul_local`: `26624`
- B2A base is only `896` keyed digests and `1792` derived commitments in that
  same run. A B2A-only root needs to remove a larger caller family or become
  part of a broader multiplication-material root to matter.
- Next optimization work should focus on a protocol-reviewed multiplication /
  XOR commitment root that can reduce repeated operand commitment hashing
  across `Ch`, `Maj`, carry-like helpers, and Boolean combiners.

Candidate multiplication-material root:

- Root label: `{label}/mul_v2/root`
- Root domain: `phase-a-local-mul-v2-root`
- Public inputs:
  - backend identifier
  - multiplication-material kernel identifier
  - operation kind: `ch`, `maj`, `a2b_carry`, `b2a_correction`, or future
    public-shape operation kind
  - public width
  - operation label digest
- Committed/private inputs:
  - committed operand roots or committed single-bit roots
  - operand provenance digests
  - operand share-side tags
- Per-bit material:
  - derive from the root, public bit index, operation kind, and operand
    provenance
  - avoid rehashing full per-bit operand commitments when the committed root
    already binds them

Proposed typed multiplication-material operation kinds:

```rust
enum DdhHssMulMaterialV2OperationKind {
    A2bCarry,
    B2aCorrection,
    ChYz,
    ChSelect,
    MajXy,
    MajXz,
    MajCombine,
}
```

Operation-kind rules:

- `A2bCarry` maps to the retained A2B v2 carry-gate shape. It is included so
  the v3 root taxonomy remains compatible with the retained v2 carry-material
  lesson.
- `B2aCorrection` is the first likely implementation target for B2A root work.
  It covers correction material derived while converting Boolean word pairs to
  arithmetic word pairs.
- `ChYz` and `ChSelect` remain separate because the `Ch` helper has an
  intermediate product and a choose output with different operand lifetimes.
- `MajXy`, `MajXz`, and `MajCombine` remain separate because the `Maj` helper
  has two product inputs and a final combination step with distinct
  provenance.
- Unknown operation kinds must fail at the boundary parser before hidden eval
  starts.

Security requirements:

- Digest-only roots are rejected for implementation readiness. Any root that
  replaces per-bit commitments must include committed material or an equivalent
  binding accepted by protocol review.
- v1 and v2 material must be impossible to mix after parser boundaries.
- Root and material metadata may depend only on public shape, labels, backend
  version, operation kind, and public bit index.
- Secret-derived bits, carries, arithmetic shares, and hidden scalar words must
  not control branches, allocation sizes, table indexes, division, modulo, or
  early returns.
- The evaluator-visible surface must not widen. The client must not learn a
  joined seed, joined scalar, or joined arithmetic word.

Review status:

- Draft complete.
- Implementation is blocked until protocol review accepts the binding for the
  backend being changed:
  - B2A committed-root material must replace the current per-bit Boolean
    commitment material used by `phase-a-bool-to-arith-base` before any B2A
    backend code lands.
  - Multiplication-material root must replace the current per-operation operand
    commitment material used by `Ch`, `Maj`, carry-style helpers, and any
    future B2A correction multiplication before any multiplication-material
    backend code lands.
- The main review question is whether aggregate Boolean-word roots plus output
  arithmetic commitments preserve the same audit surface as current per-bit
  commitments in `phase-a-bool-to-arith-base`.
- The multiplication-material root needs a precise operation-kind taxonomy
  before code changes. `Ch`, `Maj`, B2A correction, and A2B carry material have
  different operand lifetimes and should not share a loose stringly-typed
  domain.
- The first implementation slice should target one B2A caller family, likely
  `temp1`/`temp2` or message-schedule sigma B2A, before touching `Ch`/`Maj`.
  `Ch`/`Maj` multiply material has higher proof-shape risk because transient
  XOR product material currently feeds multiplication transcript inputs.

Approval checklist:

- B2A root approval must specify the exact Boolean roots, aggregate
  provenance/commitment digests, output arithmetic commitments, labels, width
  policy, and downgrade behavior.
- Multiplication-root approval must specify the exact operation-kind enum,
  operand-root shape, per-bit material derivation, label policy, width policy,
  and downgrade behavior.
- Backend versioning decision: ship B2A root and multiplication-material root
  as staged backend versions. B2A-only v3 has lower proof-shape risk and can
  target `temp1`/`temp2` or message-schedule sigma B2A before `Ch`/`Maj`.
  Multiplication-material root remains a later backend because it changes
  product-material binding for helpers with different operand lifetimes.
- No Rust backend-version, root struct, parser, or kernel code should be added
  before the relevant approval is recorded here.

Expected win:

- B2A sub-buckets in the product worker split are smaller than total round
  core, so this is unlikely to create a single dramatic win.
- A retained B2A/mul-root v2 should be judged on combined movement:
  - native `round_core`
  - browser hidden eval
  - product `ed25519EvaluationArtifactMs`
  - allocation count only as supporting evidence
- Target: a credible retained win is `20ms` to `50ms` product artifact p50,
  or a smaller p50 win with a clear embedded/low-memory benefit.

Implementation sequence:

- [x] Select B2A / multiplication-material root v2 as the next HSS protocol
      lane after A2B v2.
- [x] Draft the B2A / multiplication-material root v2 review package.
- [x] Complete the first review pass and record implementation blockers.
- [x] Implement and reject the first B2A-only core-sigma root experiment.
- [ ] Approve a stronger B2A committed-root replacement binding before any
      second implementation attempt.
- [ ] Approve the multiplication-material committed-root replacement binding.
- [x] Draft the multiplication/XOR root approval packet around the dominant
      `eval_xor_local_word` and `eval_mul_local_material` buckets before
      writing backend code.
- [x] Complete the Phase 9 boundary-graph audit for XOR and multiplication
      helpers.
- [x] Draft the first-slice `Maj` transient XOR/multiply root spec.
- [x] Draft the second-slice `Ch` gated-select root spec.
- [x] Draft the third-slice local-add carry root spec.
- [x] Draft the Phase 9A approval and implementation-readiness checklist.
- [x] Define the typed operation-kind enum for v2 multiplication material at
      the spec level.
- [x] Decide whether B2A root and multiplication-material root ship together
      under `ddh_hss_backend_v3_b2a_mul_root` or as separate backend versions.
- [ ] Add the B2A-only typed backend/kernel version after stronger B2A root
      approval.
- [ ] Add B2A root metadata structs with narrow typed inputs after stronger
      B2A root approval.
- [x] Add the typed Mul/XOR kernel, operation-kind, and boundary-kind scaffold
      in Rust with parser/serde rejection tests and no helper behavior change.
- [x] Add behaviorless multiplication-root metadata structs with narrow typed
      inputs and root sensitivity tests.
- [x] Add behaviorless `Ch` root metadata and digest builders with label,
      index, commitment, provenance, width, and share-side sensitivity tests.
- [ ] Convert the first `Maj` helper only after multiplication-root approval.
- [ ] Add semantic tests comparing decoded v2 arithmetic outputs with current
      v1 outputs.
- [ ] Add negative tests:
  - wrong backend version
  - wrong B2A kernel version
  - wrong multiplication-material kernel version
  - wrong caller label
  - wrong operation kind
  - wrong public width
  - swapped share sides
  - altered Boolean root commitment
  - altered Boolean root provenance
  - altered arithmetic output commitment
  - altered multiplication-material root
  - v1 B2A material accepted under v2
  - v2 B2A material accepted under v1
- [ ] Benchmark native hidden eval before direct-WASM.
- [ ] Benchmark direct browser/WASM before product smoke.
- [ ] Run product registration smoke only if lower-level benchmarks move in a
      compatible direction.
- [ ] Run full `ed25519-hss` tests and `cargo hss-fv verus-check` before
      retention.

## Phase 9: Multiplication/XOR Root Approval Packet

Status: drafted; boundary-graph audit complete; behaviorless typed/root
scaffold landed. Helper behavior changes remain blocked until protocol review
accepts the root binding.

Why this replaces the next B2A-only attempt:

- The B2A-only core-sigma experiment only touched `896` keyed digests and
  `1792` derived commitments out of the restored v2 physical-counter profile.
- The dominant remaining physical buckets are:
  - `eval_xor_local_word`: `143218` keyed digests and `140004` derived
    commitments
  - `eval_mul_local_material`: `35328` keyed digests and `70656` derived
    commitments
  - `eval_mul_local`: `21504` keyed digests and `26624` derived commitments
- A retained protocol-runtime win needs to reduce those larger buckets or move
  them out of the post-auth artifact critical path.

Candidate backend naming:

- Because the B2A-only v3 experiment was rejected and no v3 backend was
  retained, the next experimental backend can use
  `ddh_hss_backend_v3_mul_xor_root`.
- If a stronger B2A root lands first, use the staged v4 name already described
  in Phase 8 for the multiplication-material root.
- The codebase should expose exactly one current backend string after a
  candidate is retained. Rejected backend strings stay in benchmark artifacts
  and docs only.

Boundary graph requirement:

- Classify every XOR and multiplication output before code:
  - internal-only core value
  - internal committed local value
  - transport/emitted value
  - output bundle value
- Internal-only core values may be represented by root-bound provenance without
  immediate derived commitments.
- Values that cross a public, transport, backup, or output-bundle boundary must
  keep committed material or a reviewed equivalent-root commitment.
- The graph must cover `Ch`, `Maj`, message-schedule accumulation, `temp1`,
  `temp2`, `state3`, and A2B carry material.

Boundary graph audit:

| Caller family | Current helper path | Current boundary | First viable rewrite |
| --- | --- | --- | --- |
| SHA small/big sigma | `xor_transformed_local_bit_word_pair_core_*` into `CoreBitWordPair` | Internal core until B2A/add boundary | Already stage-owned; no immediate Phase 9 target |
| A2B v2 `xor_ab` / `a_xor_carry` | `xor_local_bit_pair_core_from_raw_public` | Internal core; carry material binds provenance | Already retained in A2B v2; keep as reference shape |
| A2B v2 `sum` | `xor_local_bit_pair_core_from_raw_public` then `materialize_local_word_core` | Committed local output bit | Keep committed because it is emitted into `SplitLocalBitWord` |
| Local add `xor_ab` | `xor_local_word_pairs_public` | Committed local operand for `sum` and carry material | Candidate for root-bound internal committed operand |
| Local add `sum` | `xor_local_word_core_pairs_materialized_public` | Committed local output bit | Keep committed because it is emitted into `SplitLocalBitWord` |
| Local add `a_xor_carry` | `xor_local_word_core_pairs_materialized_public` | Committed local operand for carry material | Candidate for root-bound internal committed operand |
| Local add `carry_gate` | `eval_mul_local_word_pairs_core_with_material_base_public` | Internal core carry | Candidate for multiplication-root material |
| `Ch` `yz` | `xor_split_local_bit_words_into` | Internal committed operand used by gated select | Strong candidate: keep as root-bound committed word instead of per-bit local commitments |
| `Ch` gated select | `eval_mul_local_bit_pair_batch_raw_xor_base_public_into` | Committed local output into `choose` | Candidate for combined multiply/XOR root; final `choose` remains committed |
| `Maj` `xy` / `xz` | `xor_local_bit_from_raw_public` inside `eval_maj_local_bit_pair_batch_raw_public_into` | Transient committed local operands for multiplication material | Strongest first target because both XOR outputs are immediately consumed by one multiply |
| `Maj` gated product | raw local multiplication in `eval_maj_local_bit_pair_batch_raw_public_into` | Committed local product before XOR with `x` | Candidate for multiplication-root material |
| `Maj` final output | manual `eval-xor-local-word` commitment | Committed local output into `majority` | Keep committed because `majority` feeds `temp2` |
| `select_local_bit_words` branch delta | `xor_local_word_pairs_public` | Committed local operand for selector multiply | Lower priority; output projector path already had mixed product results |
| output projector/reduction XORs | `xor_local_word_pairs_public` around public modulus/select work | Committed local or output-bound material | Avoid in Phase 9; prior projector attempts were noisy/regressive |

First implementation order after approval:

1. `Maj` transient XOR/multiply root for `xy`/`xz` and the gated product.
2. `Ch` `yz` plus gated-select multiply/XOR root.
3. Local-add carry material for `xor_ab` and `a_xor_carry`, only after the
   `Maj`/`Ch` root shape proves out.

Constant-time audit notes:

- Existing loop counts, labels, and allocation sizes are public width/index
  driven. Phase 9 must preserve that property.
- Existing bit operations read secret share bits, but branch shape does not
  depend on those bits in the audited helper paths.
- `reduce_word` width is public in the audited paths. Do not introduce
  division, modulo, table indexing, allocation size changes, or early returns
  from secret share values.

### Phase 9A: First Slice, `Maj` Transient XOR/Multiply Root

Status: spec drafted; implementation blocked on protocol approval.

Current code shape:

- `maj_local_bits_into` calls
  `eval_maj_local_bit_pair_batch_raw_public_into`.
- For each bit, the current helper materializes:
  - `xy_left` and `xy_right` with domain `eval-xor-local-word`
  - `xz_left` and `xz_right` with domain `eval-xor-local-word`
  - multiplication material from the `xy` and `xz` provenance/commitments
  - `gated_left` and `gated_right` with domain `eval-mul-local`
  - final majority output by XORing `x` with the gated product under
    `eval-xor-local-word`
- The final majority output must remain a committed local bit because it feeds
  `temp2`.
- The transient `xy` and `xz` outputs are the first replacement target because
  they are consumed immediately by the same multiplication material.

Proposed `Maj` root:

- Backend string: `ddh_hss_backend_v3_mul_xor_root` if this root lands before a
  stronger B2A root.
- Kernel string: `ddh_hss_mul_xor_kernel_v2_committed_root`.
- Root domain: `ddh_hss_maj_transient_xor_mul_root_v2`.
- Operation kinds:
  - `MajXy`
  - `MajXz`
  - `MajCombine`
- Public inputs:
  - backend version
  - kernel version
  - round/caller label digest
  - public bit width
  - public bit index
  - operation kind
  - boundary kind `InternalCommittedLocal` for `xy`/`xz`
  - boundary kind `InternalCore` for the gated product if it is not materialized
    before final majority output
- Private/committed inputs:
  - `x`, `y`, and `z` share-side tags
  - `x`, `y`, and `z` provenance digests
  - `x`, `y`, and `z` commitments if the operand is already a committed local
    word
  - committed `xy`/`xz` root digest in place of four transient XOR commitments
- Outputs:
  - root-bound `xy` and `xz` core/provenance material for multiplication
  - multiplication material digest derived from the root, bit index, and
    `MajCombine`
  - final committed majority output with the same logical value as the current
    helper

Derivation rules:

- Build one per-bit `Maj` root from the current `x`, `y`, and `z`
  provenance/commitments and public labels.
- Derive `xy` and `xz` share values by XORing the corresponding shares.
- Do not commit `xy`/`xz` as standalone `DdhHssLocalWord` values unless a
  later boundary requires it.
- Derive multiplication material from the `Maj` root plus `MajCombine`, public
  bit index, and the root-bound `xy`/`xz` provenance.
- Derive the final majority commitment from:
  - original `x` provenance/commitment
  - gated-product provenance/root
  - public bit index
  - operation kind `MajCombine`
  - backend/kernel version
- The final output value must equal `majority(x, y, z) = x xor ((x xor y) *
  (x xor z))` under split shares.

Negative tests before benchmark:

- wrong backend version rejected before hidden eval
- wrong `Maj` kernel version rejected before hidden eval
- wrong operation kind for `xy`, `xz`, or combine rejected
- wrong boundary kind rejected
- wrong public bit index rejected
- wrong public width rejected
- swapped share sides rejected
- altered `x`, `y`, or `z` provenance rejected
- altered `x`, `y`, or `z` commitment rejected
- altered `xy`/`xz` root digest rejected
- v2 retained A2B root material rejected by the `Maj` root parser
- rejected B2A root material rejected by the `Maj` root parser
- decoded majority output matches the current helper across fixture corpus

Expected counter movement:

- `eval_xor_local_word` should drop because `xy` and `xz` transient
  commitments are removed or delayed.
- `eval_mul_local_material` should drop because multiplication material hashes a
  root digest instead of four per-bit operand commitments.
- `eval_mul_local` may stay mostly flat unless the gated product also remains
  internal-core until the final majority output.
- Allocation-only movement is insufficient.

June 11 `Maj` root experiment:

- A semantic `Maj` helper patch replaced transient `xy`/`xz` local-word
  materialization with the Phase 9A root digest scaffold.
- Physical counters moved in the intended XOR bucket:
  - `physical_keyed_digest_derivations`: `248002 -> 227522` (`-20480`)
  - `physical_keyed_digest_eval_xor_local_word`: `143218 -> 122738`
    (`-20480`)
  - `physical_derived_commitment_hashes`: `247172 -> 226692` (`-20480`)
  - `physical_derived_commitment_eval_xor_local_word`: `140004 -> 119524`
    (`-20480`)
  - `physical_keyed_digest_eval_mul_local_material`: unchanged at `35328`
  - `physical_mul_material_hashes`: unchanged at `14848`
- Native p50 rejected the semantic patch:
  - retained A2B-v2 reverted baseline:
    `ddh-hidden-eval-b2a-root-v3-reverted-a2b-v2.json`, total hidden-eval
    p50 `124.529ms`
  - `Maj` root semantic patch:
    `ddh-hidden-eval-maj-root-native.json`, total hidden-eval p50 `132.786ms`
  - best retained A2B BLAKE3-base run:
    `ddh-hidden-eval-a2b-v2-committed-root-kernel-blake3-base.json`, total
    hidden-eval p50 `118.436ms`
- Decision: reject the semantic helper swap and keep only the behaviorless root
  scaffold/tests. The extra root hashing outweighed the saved transient XOR
  materialization.

June 11 `Maj` pair-XOR fold:

- Retained a cheaper `Maj` transient XOR fold under current backend string
  `ddh_hss_backend_v3_a2b_maj_pair_xor`.
- The helper now builds `xy` and `xz` with the existing pair helper instead of
  four side-specific single-bit XOR helper calls. This halves the provenance
  derivations for those transient XOR pairs without adding root hashing.
- The stale single-side raw XOR helper was deleted after the pair fold became
  the only retained `Maj` path.
- Physical counters:
  - baseline `ddh-hidden-eval-b2a-root-review-physical-counters.json`
  - retained `ddh-hidden-eval-maj-pair-xor-v3-physical-counters.json`
  - `physical_keyed_digest_derivations`: `248002 -> 237762` (`-10240`)
  - `physical_keyed_digest_eval_xor_local_word`: `143218 -> 132978`
    (`-10240`)
  - `physical_derived_commitment_hashes`: unchanged at `247172`
  - `physical_derived_commitment_eval_xor_local_word`: unchanged at `140004`
- Native benchmark:
  - retained/reverted A2B-v2 baseline:
    `ddh-hidden-eval-b2a-root-v3-reverted-a2b-v2.json`, total hidden-eval
    p50 `124.529ms`
  - pre-version-bump pair-XOR repeats:
    `ddh-hidden-eval-maj-pair-xor-native.json` p50 `122.110ms` and
    `ddh-hidden-eval-maj-pair-xor-native-repeat.json` p50 `122.128ms`
  - retained v3 backend run:
    `ddh-hidden-eval-maj-pair-xor-v3-native.json`, total hidden-eval p50
    `118.248ms`, round-core p50 `78.460ms`
- Direct browser/WASM:
  - rebuilt `web/generated/pkg` with `wasm-pack build crates/ed25519-hss
    --target web --out-dir web/generated/pkg --release --no-typescript
    --features browser-benchmark`
  - regenerated `crates/ed25519-hss/web/generated/bundle.json`
  - output:
    `browser-ddh-hidden-eval-maj-pair-xor-v3.json`
  - `browser_ddh_reference_match`: `true`
  - `browser_ddh_mean_ns`: `172.800ms`
  - `browser_ddh_probe_total_hidden_eval_ns`: `180.800ms`
  - `browser_ddh_round_mean_ns`: `109.800ms`
  - `browser_ddh_schedule_mean_ns`: `27.800ms`
  - This is flat/slightly slower than the retained A2B v2 direct-browser
    reference `170.5ms`, so product smoke is deferred until direct-browser
    movement is repeated or product-level validation is explicitly needed.
- Decision: retain. This is a small but repeatable provenance-derivation
  reduction, and the v3 run is effectively tied with the best retained A2B
  BLAKE3-base run while beating the latest reverted baseline.

Post-retention cheap-fold audit:

- `Ch` already computes the transient `yz = y xor z` operand through
  `xor_split_local_bit_words_into`, which uses the raw-public pair helper per
  bit. There is no analogous low-risk pair-XOR fold left in the current `Ch`
  helper.
- The local-add carry path already uses pair/core helpers for `xor_ab`, `sum`,
  `a_xor_carry`, carry-gate input material, and `next_carry`. The remaining
  materialization cost is a boundary/protocol decision rather than a stale
  single-side helper.
- Next executable work in this lane is therefore protocol-reviewed Phase 9B
  `Ch` root material or Phase 9C local-add carry-root material. Product smoke
  remains deferred for the retained `Maj` pair-XOR fold because direct
  browser/WASM was flat.

Keep gate for Phase 9A:

- physical counters move in the targeted buckets before latency benchmarking
- native hidden-eval p50 improves beyond noise
- hidden-eval equivalence and decoded `Maj` tests pass
- direct browser/WASM moves in the same direction before product smoke
- no final `majority` output commitment is removed without an accepted
  replacement

### Phase 9B: Second Slice, `Ch` Gated-Select Root

Status: implemented and retained under
`ddh_hss_backend_v4_ch_gated_select_root`.

June 11 cheap-fold audit: `yz` already uses raw-public pair XOR material. A
helper-level `Ch` patch would repeat an exhausted pattern; proceed only with
the root-bound gated-select design below.

June 11 scaffold update: behaviorless `DdhHssChRootInput`,
`DdhHssChRootDigests`, and digest builders now exist. They bind the `yz` root
separately from the select root and have focused sensitivity tests. This
scaffold landed before the retained runtime helper swap below.

June 11 retained implementation update: `ch_local_bits_into` now routes through
`eval_ch_local_bit_pair_batch_root_public_into`. The helper derives `yz` as an
internal core value, derives select multiplication material from a precomputed
`Ch` root-base digest plus public bit index and committed `x/y/z` inputs, keeps
the gated product internal, and commits only the final `choose` output. The old
raw multiply/xor-base helper and executor `yz` split helper were deleted.

Retained validation and benchmark artifacts:

- physical counters:
  `ddh-hidden-eval-ch-root-v4-physical-counters.json`
  - keyed digests: `237,762 -> 222,402`
  - derived commitments: `247,172 -> 195,972`
  - `eval_mul_local_material` keyed digests: `35,328 -> 19,968`
  - `eval_mul_local_material` derived commitments: `70,656 -> 39,936`
- native:
  `ddh-hidden-eval-ch-root-v4-native.json`
  - total hidden-eval p50: `118.248ms -> 108.737ms`
  - round-core p50: `78.460ms -> 69.237ms`
  - `round_ch` p50: `16.320ms -> 6.969ms`
- direct browser/WASM:
  `browser-ddh-hidden-eval-ch-root-v4.json`
  - `browser_ddh_reference_match`: `true`
  - `browser_ddh_mean_ns`: `172.800ms -> 168.567ms`
  - `browser_ddh_round_mean_ns`: `109.800ms -> 101.900ms`
- product smoke:
  `benchmarks/registration-flow/out/20260611-041314Z`
  - all four smoke scenarios passed, five successful runs each
  - `ed25519EvaluationArtifactMs` p50: `430/431/422/420ms`
  - worker `hiddenEvalTotalMs` p50: `385/385/385/384ms`
  - worker `hiddenEvalRoundChMs` p50: `12/11/11/11ms`
- validation:
  - `hidden_eval --lib`: `17 passed`
  - full `ed25519-hss` lib tests: `47 passed`
  - wasm32 browser-benchmark library check passed
  - `cargo hss-fv verus-check`: `96 verified, 0 errors`; anti-drift
    `10 passed`

Current code shape:

- `ch_local_bits_into` calls `eval_ch_local_bit_pair_batch_root_public_into`
  directly with `x`, `y`, and `z`.
- The helper computes `yz = y xor z` as internal core material.
- It derives per-bit root-bound multiplication material for `x * yz`.
- The helper computes the gated product as internal core material, then emits
  `choose = z xor gated`.
- The final `choose` output must remain committed because it feeds `temp1`.
- The transient `yz` operand and gated product are no longer standalone
  committed local words.

Proposed `Ch` root:

- Backend string: reuse `ddh_hss_backend_v3_mul_xor_root` if Phase 9A is the
  retained v3 backend.
- Kernel string: `ddh_hss_mul_xor_kernel_v2_committed_root`.
- Root domain: `ddh_hss_ch_gated_select_root_v2`.
- Operation kinds:
  - `ChYz`
  - `ChSelect`
- Public inputs:
  - backend version
  - kernel version
  - round/caller label digest
  - public bit width
  - public bit index
  - operation kind
  - boundary kind `InternalCommittedLocal` for `yz`
  - boundary kind `InternalCore` for the gated product if it is only consumed by
    final `choose`
- Private/committed inputs:
  - `x`, `y`, and `z` share-side tags
  - `x`, `y`, and `z` provenance digests
  - `x`, `y`, and `z` commitments for the existing committed operands
  - committed `yz` root digest in place of transient per-bit `yz` commitments
- Outputs:
  - root-bound `yz` core/provenance material for multiplication
  - multiplication material digest derived from the `Ch` root, bit index, and
    `ChSelect`
  - final committed `choose` output with the same logical value as the current
    helper

Derivation rules:

- Build one per-bit `Ch` root from current `x`, `y`, and `z`
  provenance/commitments plus public labels.
- Derive `yz` share values by XORing `y` and `z` shares.
- Avoid standalone `yz` local commitments unless a later boundary consumes
  `yz` outside the gated-select operation.
- Derive multiplication material from the `Ch` root, public bit index,
  operation kind `ChSelect`, and root-bound `yz` provenance.
- Derive final `choose` commitment from:
  - original `z` provenance/commitment
  - gated-product provenance/root
  - public bit index
  - operation kind `ChSelect`
  - backend/kernel version
- The final output value must equal `choose(x, y, z) = z xor (x * (y xor z))`
  under split shares.

Negative tests before benchmark:

- wrong backend version rejected before hidden eval
- wrong `Ch` kernel version rejected before hidden eval
- wrong operation kind for `yz` or select rejected
- wrong boundary kind rejected
- wrong public bit index rejected
- wrong public width rejected
- swapped share sides rejected
- altered `x`, `y`, or `z` provenance rejected
- altered `x`, `y`, or `z` commitment rejected
- altered `yz` root digest rejected
- decoded choose output matches the current helper across fixture corpus

Expected counter movement:

- `eval_xor_local_word` should drop because transient `yz` commitments are
  removed or delayed.
- `eval_mul_local_material` should drop because multiplication material hashes a
  root digest instead of per-bit `x`/`yz` operand commitments.
- `eval_mul_local` may drop if the gated product remains core until final
  `choose`.

Keep gate for Phase 9B:

- Phase 9A passed or was rejected for a reason unrelated to the root model
- physical counters move in the targeted buckets before latency benchmarking
- native hidden-eval p50 improves beyond noise
- hidden-eval equivalence and decoded `Ch` tests pass
- direct browser/WASM moves in the same direction before product smoke
- final `choose` output remains committed or has an accepted replacement

### Phase 9C: Third Slice, Local-Add Carry Root

Status: implemented experimentally and rejected. The source is restored to the
retained v4 `Ch` backend.

June 11 implementation result: a v5 local-add carry-root candidate routed
`a_xor_carry` through core provenance and derived carry-gate material from an
adder-root digest while keeping emitted `sum` bits committed. It reduced
physical derived commitments from the retained v4 `195,972` to `192,900`, with
keyed digests flat at `222,402`, but the latency movement was not reliable:
native p50 runs were `110.754ms`, `108.432ms`, and `109.122ms` versus retained
v4 `108.737ms`; direct browser/WASM moved to `167.833ms` on the first v5
attempt, then regressed to `171.600ms` after digest trimming. The change was
reverted because it added root-material hashing on a hot carry path while only
removing a small number of commitments.

Rejected benchmark artifacts:

- `ddh-hidden-eval-local-add-carry-root-v5-physical-counters.json`
- `ddh-hidden-eval-local-add-carry-root-v5-native.json`
- `ddh-hidden-eval-local-add-carry-root-v5-native-repeat.json`
- `browser-ddh-hidden-eval-local-add-carry-root-v5.json`
- `ddh-hidden-eval-local-add-carry-root-v5-trimmed-physical-counters.json`
- `ddh-hidden-eval-local-add-carry-root-v5-trimmed-native.json`
- `browser-ddh-hidden-eval-local-add-carry-root-v5-trimmed.json`

June 11 cheap-fold audit: the local-add path already uses pair/core helpers for
the obvious XORs and carry transitions. Further reductions require the
root-bound carry design below.

Current code shape:

- Local adders compute `xor_ab = a xor b` as committed local words.
- They compute `sum = xor_ab xor carry` and emit committed `sum` bits into the
  output `SplitLocalBitWord`.
- They compute `a_xor_carry = a xor carry` as committed local words.
- Carry material multiplies `xor_ab * a_xor_carry`, producing an internal core
  carry gate.
- The next carry remains core until another boundary.
- `sum` must stay committed because it is the public local-bit output of the
  adder.

Proposed local-add carry root:

- Backend string: reuse `ddh_hss_backend_v3_mul_xor_root` if Phase 9A/9B land
  under that backend.
- Kernel string: `ddh_hss_mul_xor_kernel_v2_committed_root`.
- Root domain: `ddh_hss_local_add_carry_root_v2`.
- Operation kinds:
  - `XorPair`
  - `XorWithCarry`
  - `A2bCarry`
- Public inputs:
  - backend version
  - kernel version
  - adder/caller label digest
  - public bit width
  - public bit index
  - operation kind
  - boundary kind `InternalCommittedLocal` for `xor_ab` and `a_xor_carry`
  - boundary kind `OutputBundle` or `InternalCommittedLocal` for `sum`,
    depending on the caller boundary
- Private/committed inputs:
  - `a`, `b`, and previous carry share-side tags
  - `a`, `b`, and carry provenance digests
  - `a`, `b`, and carry commitments when the input is already committed
  - root-bound `xor_ab` and `a_xor_carry` digests in place of transient
    per-bit commitments
- Outputs:
  - root-bound `xor_ab` and `a_xor_carry` core/provenance material for carry
    multiplication
  - committed `sum` output
  - internal core carry gate and next carry

Derivation rules:

- Build one per-bit local-add root from current `a`, `b`, and carry
  provenance/commitments plus public labels.
- Derive `xor_ab` as core material first.
- Derive `sum` from `xor_ab` and carry, then commit it under the same logical
  output label as the current adder.
- Derive `a_xor_carry` as core material for carry multiplication.
- Derive multiplication material from the local-add root, bit index, and
  operation kind `A2bCarry`.
- Derive next carry as core material unless an explicit caller boundary demands
  committed local words.
- The final adder output must match the current split-bit addition semantics.

Negative tests before benchmark:

- wrong backend version rejected before hidden eval
- wrong carry kernel version rejected before hidden eval
- wrong operation kind rejected
- wrong boundary kind rejected
- wrong public bit index rejected
- wrong public width rejected
- swapped share sides rejected
- altered `a`, `b`, or carry provenance rejected
- altered `a`, `b`, or carry commitment rejected
- altered `xor_ab` or `a_xor_carry` root digest rejected
- decoded add output matches the current helper across fixture corpus

Expected counter movement:

- `eval_xor_local_word` should drop if `xor_ab` and `a_xor_carry` avoid
  transient commitments.
- `eval_mul_local_material` should drop if carry material hashes the local-add
  root instead of operand commitments.
- `eval_mul_local` may drop if carry-gate products remain core through
  next-carry derivation.

Keep gate for Phase 9C:

- Phase 9A and/or 9B prove the shared root model is worth extending
- physical counters move in the targeted buckets before latency benchmarking
- native hidden-eval p50 improves beyond noise
- hidden-eval equivalence and decoded adder tests pass
- direct browser/WASM moves in the same direction before product smoke
- every emitted `sum` bit remains committed or has an accepted replacement

### Phase 9D: Approval And First-Patch Readiness

Status: typed scaffold and behaviorless root builders landed. The retained
runtime helper change in this lane is the Phase 9B `Ch` gated-select root.
Future helper behavior changes that remove commitments or provenance material
are blocked until the relevant candidate-specific approval is recorded here.

Approved and retained:

- A2B v2 committed-root carry material with precomputed BLAKE3 bases.
- `Maj` pair-XOR provenance fold under
  `ddh_hss_backend_v3_a2b_maj_pair_xor`.
- `Ch` gated-select root under `ddh_hss_backend_v4_ch_gated_select_root`.
- Output-projector binding scaffold as product-neutral protocol hardening and
  future-version plumbing.

Rejected:

- Semantic output-projector paired-root arithmetic rewrite. It failed the
  product keep gate and did not remove a product-visible canonical-add
  equivalent.
- A2B v2 SHA-256 per-bit carry-material implementation. It regressed native
  p50 before the BLAKE3-base replacement.
- B2A-only core-sigma committed-root experiment. It improved a small physical
  counter bucket without improving native p50.
- Full `Maj` transient XOR/multiply root helper swap. Extra root hashing
  outweighed the removed transient XOR materialization.
- Local-add carry-root v5 experiment. It reduced a small commitment bucket but
  did not produce reliable native or browser latency movement.
- Round-sigma B2A-boundary experiment. Physical counters stayed flat, native
  p50 regressed, and allocation calls increased.

Needs approval before code:

- Any second B2A committed-root attempt.
- Any new multiplication-material root that removes more logical work than the
  retained `Ch` root.
- Any broader protocol-root replacement, including output-projector root v2,
  B2A/multiplication combined roots, or any rewrite that removes existing
  commitment/provenance material.

Approval packet requirements for the next candidate:

- Exact backend and kernel strings.
- Exact operation-kind and boundary-kind enums.
- Exact root inputs: backend version, kernel version, operation kind, boundary
  kind, label digest, width, bit index, share-side tags, operand provenance
  digests, and operand commitments.
- Exact replacement claim: which current commitment/provenance material is
  removed and what root binding replaces it.
- Final emitted commitment policy for every value crossing a transport,
  backup, export, output-bundle, or public artifact boundary.
- Downgrade behavior for stale backend/kernel strings and mixed material.
- Benchmark gate: physical counters first, native p50 second, direct
  browser/WASM third, product smoke last.

Patch sequence:

1. Typed scaffold: complete
   - add `DdhHssMulXorKernelVersion`
   - add `DdhHssRootedCombinerKind`
   - add `DdhHssCombinerBoundaryKind`
   - add current-only parse/serde tests and unknown-string rejection tests
   - keep helper execution unchanged
2. Root builders: complete
   - add `DdhHssCommittedWordRoot`
   - add `DdhHssCommittedWordPairRoot`
   - add `DdhHssRootedCombinerInput`
   - add `Maj` root digest builder with narrow typed inputs
   - add unit tests for root sensitivity to kind, boundary, width, index,
     label, side, provenance, and commitment
   - keep helper execution unchanged
3. Candidate approval packet:
   - choose exactly one of the candidates in "Needs approval before code"
   - record the exact replacement binding and boundary commitments
   - add the candidate-specific negative-test matrix before helper behavior
     changes
4. Semantic helper swap:
   - add a rooted helper beside the current helper for the approved candidate
   - route only the approved caller family through the rooted helper under the
     new backend version
   - keep final boundary outputs committed unless the approval packet records a
     reviewed replacement
   - delete the older current-path helper only if the rooted helper is retained
5. Focused validation:
   - decoded majority output fixture tests
   - `hidden_eval_equivalence`
   - stale backend/kernel parser rejection tests
   - `git diff --check`
6. Benchmark sequence:
   - native physical counters with `hss-physical-counters`
   - native hidden eval p50 only if counters move
   - direct browser/WASM only if native p50 moves
   - product smoke only if direct browser/WASM moves

First-patch reject rules:

- reject before native p50 if physical counters do not reduce
  `eval_xor_local_word` or `eval_mul_local_material`
- reject before direct browser/WASM if native p50 regresses beyond noise
- reject before product smoke if direct browser/WASM regresses materially
- reject immediately if final majority output loses its committed boundary
- reject immediately if parser or downgrade tests allow mixed kernel material

Proposed typed roots:

```rust
enum DdhHssRootedCombinerKind {
    XorPair,
    XorWithCarry,
    ChYz,
    ChSelect,
    MajXy,
    MajXz,
    MajCombine,
    A2bCarry,
    B2aCorrection,
}

struct DdhHssCommittedWordPairRoot {
    width_bits: u16,
    left: DdhHssCommittedWordRoot,
    right: DdhHssCommittedWordRoot,
}

struct DdhHssRootedCombinerInput {
    backend_version: DdhHssBackendVersion,
    kernel_version: DdhHssMulXorKernelVersion,
    kind: DdhHssRootedCombinerKind,
    label_digest: [u8; 32],
    width_bits: u16,
    bit_index: u16,
    left_pair: DdhHssCommittedWordPairRoot,
    right_pair: DdhHssCommittedWordPairRoot,
    boundary: DdhHssCombinerBoundaryKind,
}

enum DdhHssCombinerBoundaryKind {
    InternalCore,
    InternalCommittedLocal,
    Transport,
    OutputBundle,
}
```

Root binding rules:

- Bind backend version, kernel version, operation kind, boundary kind, label
  digest, width, share-side tags, operand-root commitments, operand-root
  provenance, and public bit index.
- Derive per-bit multiplication material from the root plus operation kind and
  index, so the hot path avoids rehashing full operand commitments for every
  bit.
- Derive XOR outputs as core values where the boundary graph proves the value
  does not need an immediate local commitment.
- Materialize committed local words only at explicit boundaries, using the root
  digest, output side, index, and boundary kind as material.
- Reject stale backend/kernel strings at deserialization or worker-request
  boundaries. Internal logic must never accept raw strings.

Security questions for review:

- Does root-bound internal-core XOR output preserve the same transcript
  binding for every downstream consumer that currently relies on
  `eval-xor-local-word` commitments?
- Which `Ch` and `Maj` intermediates are purely internal, and which become
  multiplication-material operands that require committed roots?
- Can multiplication material safely bind committed operand roots once per word
  plus public bit index, instead of hashing each operand commitment per bit?
- Does any output used by transport, export, backup, recovery, or final output
  bundles lose a concrete commitment?
- Are operation-kind and boundary-kind enums narrow enough to prevent mixing
  `Ch`, `Maj`, A2B carry, and B2A correction material?

Implementation to-do:

- [x] Add `DdhHssMulXorKernelVersion` and current-only parser.
- [x] Add `DdhHssRootedCombinerKind` and `DdhHssCombinerBoundaryKind` with
      exhaustive tests.
- [x] Add behaviorless committed-local word-root builders and `Maj` root
      digest inputs.
- [x] Retain the cheap `Maj` pair-XOR fold under
      `ddh_hss_backend_v3_a2b_maj_pair_xor` after physical counters, native
      hidden eval, direct browser/WASM, full crate tests, and wasm32 checks.
- [x] Audit `Ch` and local-add for another low-risk pair-XOR fold; both paths
      already use pair/core helpers, so the next work is protocol-rooted.
- [x] Implement and retain the root-bound `Ch` gated-select helper under
      `ddh_hss_backend_v4_ch_gated_select_root`.
- [x] Delete the obsolete raw multiply/xor-base helper and executor `yz` split
      helper after routing `Ch` through the v4 helper.
- [x] Defer internal-core materialization builders; the first full `Maj` root
      helper swap was rejected, and the retained `Ch` root helper did not need
      a generic materialization builder.
- [x] Convert the lower-risk `Maj` transient `xy`/`xz` pair fold first and
      retain it under `ddh_hss_backend_v3_a2b_maj_pair_xor`.
- [x] Add byte/equivalence coverage through hidden-eval equivalence, decoded
      root sensitivity tests, and the retained `Ch` direct-browser/product
      validation path.
- [x] Add current negative tests for wrong kind, boundary, width, side, label,
      root, index, backend version, and kernel version where the retained root
      scaffolds expose typed boundary parsers.
- [x] Implement Phase 9C local-add carry-root experimentally and reject it
      after physical counters, native p50, and browser/WASM failed the keep
      gate.
- [x] Implement the round-sigma B2A-boundary experiment and reject it after
      physical counters stayed flat, native p50 regressed, and allocation calls
      increased.
- [x] Run native physical counters before native p50 benchmarks.
- [x] Run direct browser/WASM only if physical counters and native p50 move in
      the expected direction.
- [x] Run product smoke only after direct browser/WASM confirms the lower-level
      win.

Keep gate:

- protocol review accepts the committed-root or equivalent-root binding
- targeted physical buckets move materially, especially
  `eval_xor_local_word`, `eval_mul_local_material`, or `eval_mul_local`
- hidden-eval semantic/equivalence tests pass
- downgrade and tamper tests pass
- constant-time review passes
- native p50 improves beyond noise
- direct browser/WASM moves in the same direction
- no committed boundary value loses transcript binding
- formal verification and hidden-eval equivalence remain green before
  retention
- product smoke confirms a real artifact p50 improvement or a documented
  embedded/low-memory benefit

Reject or redesign if:

- the win appears only in allocation counters
- product smoke regresses
- direct-WASM regresses materially
- the root binding is ambiguous
- the design removes commitments without accepted replacement binding
- v1/v2 material can mix after boundary parsing

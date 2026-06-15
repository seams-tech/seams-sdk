# HSS Optimization Experiment Ledger

Date created: June 11, 2026

Scope: refactor-61, refactor-62, refactor-64, `optimization-5.md`, and
`optimization-6.md` latency work that affects Ed25519 HSS registration and
hidden-eval runtime.

Use this ledger before proposing another optimization. It records retained
experiments, rejected experiments, neutral guardrail work, and benchmark
signals. Benchmark numbers are same-machine/same-run-family comparisons unless
the entry says otherwise.

## Current Retained Baseline

Current retained protocol backend:

- `ddh_hss_backend_v4_ch_gated_select_root`

Latest retained Phase 9B signals:

- Native hidden-eval p50: `118.248ms -> 108.737ms`
- Native round-core p50: `78.460ms -> 69.237ms`
- Native `round_ch` p50: `16.320ms -> 6.969ms`
- Direct browser/WASM mean: `172.800ms -> 168.567ms`
- Product `ed25519EvaluationArtifactMs` p50:
  `430/431/422/420ms`
- Product worker `hiddenEvalTotalMs` p50:
  `385/385/385/384ms`

Earlier retained checkpoints still matter as comparison anchors:

- Phase 7E borrow-path material-base reuse product p50:
  `450/451/447/447ms`
- Phase 7I public-multiple clamped scalar reduction direct browser hidden-eval
  p50: `188.65ms -> 175.75ms`
- A2B v2 BLAKE3-base product p50:
  `445/445/443/443ms`

## Protocol Approval State

Approved and retained:

- A2B v2 committed-root carry material with precomputed BLAKE3 bases.
- `Maj` pair-XOR provenance fold under
  `ddh_hss_backend_v3_a2b_maj_pair_xor`.
- `Ch` gated-select root under `ddh_hss_backend_v4_ch_gated_select_root`.
- Output-projector binding scaffold as product-neutral hardening and
  future-version plumbing.

Rejected:

- Semantic output-projector paired-root arithmetic rewrite.
- A2B v2 SHA-256 per-bit carry-material implementation.
- B2A-only core-sigma committed-root experiment.
- Full `Maj` transient XOR/multiply root helper swap.
- Local-add carry-root v5 experiment.
- Round-sigma B2A-boundary experiment.

Needs approval before code:

- Any second B2A committed-root attempt.
- Any new multiplication-material root that removes more logical work than
  the retained `Ch` root.
- Any broader protocol-root replacement, including output-projector root v2,
  B2A/multiplication combined roots, or any rewrite that removes existing
  commitment/provenance material.

## Product And Registration-Path Experiments

| Experiment | Status | Signal | Decision |
| --- | --- | --- | --- |
| Refactor 62 preauth HSS prepare | Retained | `walletRegisterPrepareWaitMs` p50/p95 became `0ms`; `walletRegisterStartMs` p50 `4ms` to `7ms`; SDK p50 around `1989/2026/1636/1692ms` in the recorded smoke run. | Server HSS prepare is hidden under passkey proof time for the current passkey smoke path. |
| Worker-resident HSS session handle | Retained | Removed client-side session materialization from the staged artifact path. | Keep. This reduces staged artifact plumbing and supports later fast paths. |
| Finalize cached-session fast path | Retained | Removed about `241ms` to `244ms` p50 from product finalize. | Keep. Finalize materialization can be zero in the cached-session case because materialization already happened earlier. |
| Output-projector shared client-base path | Retained | Product-visible output-projector path improved before later protocol work. | Keep as part of the current projector baseline. |
| Output-projector mixed shared-mask path | Retained | Restoring this path fixed a product regression where masked client-output p50 moved from about `4ms` to `59-61ms`. | Keep. Do not displace this path when experimenting with projector roots. |
| Wallet-iframe transport diagnostics | Retained instrumentation | Smoke run `20260610-130323Z` showed transport was secondary to passkey prompt time and HSS client artifact construction. | Continue using these diagnostics for ranking, not control flow. |

## Early Refactor-64 Rejections

These are recorded from the chat handoff and historical benchmark artifacts.
Several came before the crate-local `optimization-5.md` ledger became the
primary record.

| Experiment | Status | Signal | Decision |
| --- | --- | --- | --- |
| First output-projector algebra simplification | Rejected | Failed protocol validation. | Do not retry algebraic projector changes without an explicit backend-versioned proof shape. |
| A2B destination reuse | Rejected | Improved native p50, did not improve browser/WASM worker path. | Browser/WASM is the keep gate for A2B representation edits. |
| Packed local metadata | Rejected | Reduced allocation calls too little and regressed direct browser artifact timing. | Allocation-call reduction alone is weak evidence. |
| Round-state scratch reuse | Rejected | Improved native allocation and regressed product client-artifact p50. | Product smoke rejected it. |
| Fused output canonicalization | Rejected | Saved too little allocation and regressed Node direct artifact timing. | Do not repeat output canonicalization fusions without removing logical work. |
| Standalone output-projector label reuse | Rejected | Improved native allocation and direct artifact timing, regressed product host-origin client-artifact p50. | Product p50 wins over lower-level allocation signals. |
| Output-projector select-stream | Rejected | Reduced native allocation and direct artifact p50, regressed product client-artifact p50 by `15ms` to `30ms`. | Select-streaming is a product-regression pattern. |
| A2B output recycling | Rejected | Improved native allocation, regressed direct artifact p50 on Node and browser. | Do not recycle A2B output buffers unless browser timing moves first. |

## Current-Backend Runtime Experiments

### Phase 5 And Round-Core Structure

| Experiment | Status | Signal | Decision |
| --- | --- | --- | --- |
| Direct browser round-core pressure counters | Retained instrumentation | Baseline direct browser hidden-eval mean `209.4ms`; message schedule `32.0ms`; round core `127.5ms`; output projector `37.4ms`; reference match `true`. | Keep counters for ranking. |
| Public label scratch reuse for arithmetic adders | Retained | Native median `143.471ms -> 142.705ms`; direct browser mean `209.4ms -> 206.9ms`; allocation `6.28MB / 35,891` calls to `6.269MB / 35,652` calls. | Small retained byte-equivalent cleanup. |
| Message-schedule label scratch | Retained | Direct browser repeat mean `205.0ms`; allocation `6.256MB / 35,335` calls. Native was noisy. | Keep because browser and allocation moved in the right direction. |
| Round-core sub-kernel split | Retained architecture | Native median about `143.056ms`; allocation stayed `6.256MB / 35,335` calls; direct browser mean `206.0ms`. | Keep as architecture for future targeted slices. |
| Secure A2B public label scratch | Retained | Allocation `6.248MB / 35,113` calls; direct browser mean `200.8ms`; reference match `true`. | Keep. Larger A2B gains require a protocol shape. |
| Output-projector label-buffer cleanup | Retained | Native median `130.828ms`; output projector median `24.058ms`; direct browser mean `199.4ms`, median `198.1ms`. | Keep. This was public label construction only. |
| Diagnostic stage-operation-count opt-out | Rejected | Native registration-style p50 regressed from `145.156ms` client artifact / `136.966ms` hidden eval to `148.854ms` and `147.873ms`; product p50 `484/492/484/478ms`. | Reverted. Diagnostics must not perturb product timing. |

### Output Projector And Scalar Reduction

| Experiment | Status | Signal | Decision |
| --- | --- | --- | --- |
| Direct output canonicalization | Rejected | Allocation improved from `5.38MB / 5,143` calls to `5.29MB / 5,140` calls; product smoke regressed to `484/482/480/477ms` and `480/485/470/473ms` versus prior baseline around `449/451/444/443ms`. | Reverted. Temporary-vector savings do not justify product regression. |
| Phase 7B staged output boundary | Retained | Native hidden-eval p50 `129.757ms`; direct browser worker p50 `205.8ms`; product p50 improved from `482/491/484/478ms` to `463/467/459/457ms`. | Keep. Boundary ownership cleanup moved product p50. |
| Phase 7C repeated-selector select batch | Retained | Native p50 `128.910ms`; allocation about `4.916MB / 5,123` calls; product p50 `460/460/455/457ms`. | Keep as the last small allocation-only select cleanup unless a new product-impacting profile appears. |
| Phase 7D carry-gate material-base reuse | Retained | Native p50 `127.882ms`; browser hidden-eval p50 `188.6ms`; product p50 `459/459/453/455ms`. | Keep. Byte-equivalence and product moved in the same direction. |
| Phase 7E borrow-path material-base reuse | Retained | Native p50 `126.459ms`; output projector p50 `23.318ms`; product p50 `450/451/447/447ms`. | Keep. This closed the obvious public material-base reuse targets. |
| Phase 7F select scratch reduction | Rejected | Native p50 regressed `126.459ms -> 134.289ms`; output projector `23.318ms -> 24.483ms`. | Reverted. Re-reading false-branch words caused cache/reconstruction cost. |
| Phase 7G validated local-word accessor | Rejected | First run flat-to-negative: `126.459ms -> 126.745ms`; repeat regressed to `130.339ms`. | Reverted. Accessor-check removal did not help. |
| Phase 7H scalar-reduction arena ping-pong | Rejected | Allocation improved `4.916MB / 5,123` calls to `4.522MB / 5,051` calls; native p50 regressed `126.459ms -> 127.959ms`, repeat `127.493ms`. | Reverted. Allocation improvement without latency is insufficient. |
| Arena byte-equivalence harness and preconditions | Retained guardrail | Added hidden-eval byte-equivalence signature harness and scalar/canonical-add same-session fixtures. Current precondition baseline: allocation `4.158117MB / 5,091` calls; native p50 `114.320ms`; output projector `18.110ms`. | Keep as guardrail. The baseline is a comparison point, not a retained-performance claim. |
| Phase 7I public-multiple clamped scalar reduction | Retained | Allocation `4.916MB / 5,123` calls to `4.161MB / 5,031` calls; native p50 `126.459ms -> 118.039ms`; output projector `23.318ms -> 16.151ms`; browser hidden-eval p50 `188.65ms -> 175.75ms`; product p50 `450/451/447/447ms -> 450/445/443/442ms`. | Keep. This removed logical scalar-reduction work. |
| Phase 7J canonical-add material-base reuse | Rejected | Native p50 regressed `118.039ms -> 122.843ms`; output projector `16.151ms -> 16.656ms`; allocation unchanged at `4.160562MB / 5,031` calls. | Reverted. Public material-base preparation is not a bottleneck after Phase 7I. |
| Phase 7K shifted sigma zero-normalization | Rejected | Native p50 regressed `118.039ms -> 123.720ms`; repeat `120.498ms`; message schedule failed to improve. | Reverted. Do not retry this normalization. |

### Guardrails, Embedded Profiles, And Stage Identity

| Experiment | Status | Signal | Decision |
| --- | --- | --- | --- |
| Materialization graph guard | Retained guardrail | `materialization_graph_guard` passed after stale entries were removed. | Keep. Use it to prevent accidental logical materialization drift. |
| CoreBitWord stage identity guard | Retained hardening | Direct browser median `186.300ms` with operation counts matching retained A2B v2; native p50 `122.902ms`, repeat `125.119ms`. | Keep as type/validation hardening. Do not product-smoke it as a perf win. |
| Embedded profile benchmark | Retained instrumentation | Native macOS/aarch64 baseline p50: total `126.740ms`, round core `85.404ms`, output projector `17.279ms`; hidden-eval allocation `4.160562MB / 5,031` calls. | Keep. Physical ARM64 Linux and iOS data remain pending. |
| Low-memory stress benchmark | Retained instrumentation | macOS/aarch64 budget passed: hidden-eval p95 `4.160562MB / 5,031` calls / `1.402285MB` peak live; prepare p95 `4.769303MB / 17,411` calls / `2.247943MB` peak live. | Keep. Set device budgets from physical hardware, not desktop numbers. |
| iOS benchmark procedure | Retained documentation | Added physical-device procedure for native iOS and WebView/WASM. | Use before deciding embedded/iOS HSS policy. |

## Backend-Versioned Protocol Experiments

### Typed Backend And Projector Roots

| Experiment | Status | Signal | Decision |
| --- | --- | --- | --- |
| Typed backend-version scaffold | Retained hardening | Direct browser smoke reference matched; typed version rejects unknown backend strings at boundaries. | Keep. This makes backend mixing explicit. |
| Output-projector paired-root semantic rewrite | Rejected | Native output-projector moved only about `0.46ms`; semantic product smoke regressed to `515/515/519/512ms`, repeat `503/506/505/505ms` versus `471/468/462/463ms`. | Reverted. It did not remove a product-visible canonical-add equivalent. |
| Output-projector binding-only scaffold | Retained hardening | After restoring mixed shared-mask path, product p50 returned to `468/470/467/466ms`; local materializations stayed `2560`; no retained latency win. | Keep as product-neutral protocol-hardening/future-version plumbing. |
| Binding-only path before mixed-mask restoration | Rejected intermediate | Product p50 `515/515/516/515ms`; root cause was masked client-output p50 `59-61ms` instead of about `4ms`. | Do not displace mixed shared-mask arithmetic again. |

### A2B v2

| Experiment | Status | Signal | Decision |
| --- | --- | --- | --- |
| A2B kernel-version scaffold | Retained hardening | Native scaffold p50 `126.177ms`; round core `84.536ms`; output projector `17.260ms`. | Keep as baseline for A2B v2. |
| A2B v2 SHA-256 carry-material root | Rejected | Native p50 regressed to `137.310ms`; round core `92.671ms`. | Rejected. Fresh SHA-256 carry material per bit was too expensive. |
| A2B v2 BLAKE3-base carry-material root | Retained | Native p50 `118.436ms`; round core `79.376ms`; browser mean `170.5ms`; product p50 `445/445/443/443ms`; about `23/25/24/23ms` better than output-projector binding smoke `468/470/467/466ms`. | Keep. Protocol review approved committed-root material per side. |
| Legacy backend/A2B variants cleanup | Retained cleanup | Stale backend strings fail at serialized driver-state and staged-artifact boundaries; wrong-index carry material is rejected before multiplication. | Keep. No internal legacy compatibility paths. |

### B2A And Multiplication-Material Roots

| Experiment | Status | Signal | Decision |
| --- | --- | --- | --- |
| B2A-only core-sigma root | Rejected | Physical B2A base counters improved `896` keyed digests / `1792` commitments to `768` / `1536`; native p50 `124.617ms`, repeat `124.211ms`, above retained A2B v2 best `118.436ms`; reverted reference `124.529ms` showed noise-band movement. | Rejected. Counter movement was too small for latency. |
| Behaviorless Mul/XOR root scaffold | Retained hardening | Added typed kernel/kind/boundary scaffolds and root sensitivity tests without helper behavior changes. | Keep as future protocol plumbing. |
| Full `Maj` transient XOR/multiply root | Rejected | Physical counters improved `eval_xor_local_word` by `20,480` keyed digests and `20,480` commitments, but native p50 regressed to `132.786ms` versus retained A2B-v2 reverted baseline `124.529ms` and best A2B BLAKE3 `118.436ms`. | Rejected. Extra root hashing outweighed saved transient XOR materialization. |
| Cheap `Maj` pair-XOR fold | Retained | Physical keyed digests `248,002 -> 237,762`; native p50 `122.110ms`/`122.128ms` pre-version, retained v3 run `118.248ms`; direct browser mean `172.800ms`, flat/slightly slower than A2B v2 `170.5ms`. | Retained as small provenance-derivation reduction. Product smoke deferred because direct browser was flat. |
| `Ch` cheap-fold audit | Closed | `Ch` already used raw-public pair XOR material for `yz`. | No low-risk pair fold remained. Proceeded to protocol-rooted `Ch`. |
| `Ch` gated-select root | Retained | Keyed digests `237,762 -> 222,402`; derived commitments `247,172 -> 195,972`; `eval_mul_local_material` keyed digests `35,328 -> 19,968`; native p50 `118.248ms -> 108.737ms`; browser mean `172.800ms -> 168.567ms`; product p50 `430/431/422/420ms`. | Keep. This is the current retained backend. |
| Local-add carry root v5 | Rejected | Derived commitments `195,972 -> 192,900`; keyed digests flat; native runs `110.754ms`, `108.432ms`, `109.122ms` versus retained v4 `108.737ms`; direct browser first `167.833ms`, trimmed variant regressed `171.600ms`. | Reverted. Added root hashing on a hot carry path for a small commitment reduction. |
| Round-sigma B2A-boundary experiment | Rejected | Operation counts stayed flat; native p50 `122.902ms`, repeat `125.119ms`; allocation calls increased. | Rejected. Retain the existing round-sigma materialization path. |

## Open Or Blocked Candidates

| Candidate | Status | Required before implementation |
| --- | --- | --- |
| Stronger B2A committed-root replacement | Blocked | Approve exact Boolean roots, aggregate provenance/commitment digests, output arithmetic commitments, labels, width policy, and downgrade behavior. |
| New multiplication-material root beyond retained `Ch` | Blocked | Approve exact operation-kind enum, operand-root shape, per-bit derivation, label policy, width policy, and downgrade behavior. |
| Output-projector root v2 | Blocked | Must remove a full logical canonical-add/sub/select equivalent while preserving `canonical_seed`, `client_output`, and `x_server_base` output commitments. |
| Deeper arena-backed executor representation | Guardrails ready | Need a byte-equivalence harness for the target boundary and a candidate that removes logical work or improves browser/product p50. Small accessor/scratch edits have repeatedly regressed. |
| Physical ARM64 Linux and iOS measurements | Pending hardware | Run target-device profiles before deciding whether HSS is default, optional, or policy-gated outside browser contexts. |

## Rules Learned

- Product `ed25519EvaluationArtifactMs` is the final keep gate for
  product-path optimizations.
- Direct browser/WASM must move before product smoke unless a product-only
  hypothesis is explicit.
- Allocation-only improvements often regress latency in this codebase.
- Removing temporary vectors rarely matters unless logical commitments,
  provenance derivations, or emitted transport work also fall.
- Output-projector micro-edits are exhausted under the current backend after
  Phase 7I. New projector work needs a protocol-reviewed root or a proof that
  logical scalar-reduction/add/select work falls.
- A2B SHA-256 per-bit root material is too expensive. Precomputed BLAKE3 bases
  were the retained form.
- Root-bound helper rewrites must first move physical counters, then native
  p50, then direct browser/WASM, then product smoke.
- Final boundary commitments must remain emitted unless a reviewed replacement
  binding exists.
- All new root and arena indexing must use public width, public bit index,
  public labels, and public backend/kernel versions only.

# Refactor 83D: HSS Subsecond Tail Latency

Date created: July 5, 2026

Status: Phase 0, the Phase 1 finalized-state checkpoint, the Phase 2 E1/E2/E3
probes, E4 client-session measurement, the Phase 3 output-opening/projection
moves, compact finalize context, and durable server advance checkpoint are
implemented. The E6 sequential-drift probe shows no WASM memory growth across
repeated durable advance/finalize cycles. The E2 raw/compressed advanced-state
storage probe is measured and remains a persistence-size follow-up rather than
an HSS critical-path blocker. Stage-loop candidates have measured outcomes,
and the final intended passkey plus Email OTP benchmark rerun is green.
Follow-up non-HSS registration buckets are recorded for the next registration
latency refactor.

## Goal

Reduce the remaining Ed25519 HSS registration tail after Refactors 83B and 83C:

- HSS advance: from about `542-561ms` toward `<400ms`.
- HSS finalize: from about `590-637ms` toward `<400ms`.
- Client artifact build (`ed25519EvaluationArtifactMs`): from about
  `471ms` toward `<400ms` — this is an HSS bucket, and once advance drops
  below it, it becomes the critical parallel leg.
- Total registration: toward `<2.2s` for Email OTP and `<2.5s` for passkey on
  the local intended Worker/WASM path.

Total-target arithmetic, stated up front so the scope is honest: hitting both
server bucket targets yields roughly `~2.4s` Email OTP / `~2.7s` passkey from
83D's own scope (advance drops below the `~471ms` artifact leg, so the
parallel section saves only `~90ms`; finalize saves `~237ms`). The final
`~250ms` to `<2.2s` / `<2.5s` lives in buckets outside this plan —
`ed25519ClientMaterialMs` (~410ms), `emailOtpEnrollmentMaterialMs` (~390ms),
`thresholdEd25519SigningSessionHydrationMs` (~300ms), and for passkey
`ecdsaRegistrationPersistenceMs` (~560-607ms) — plus the client artifact
work now included above. The `<2.2s`/`<2.5s` totals are reachable only if
Phase 4 spawns the follow-up refactor for those buckets; 83D alone is
expected to land near `~2.4s`/`~2.7s`.

This is a focused HSS state-format and protocol-boundary optimization plan. It
does not revive Cloudflare Containers, native sidecars, WebSocket pinning, or
process-local handle persistence.

Platform note: the HSS hot-path WASM packages now require fixed-width
WebAssembly SIMD. Cloudflare Workers documents SIMD support, and this SDK is in
development, so the build uses the faster artifact directly instead of carrying
a second non-SIMD fallback.

Unlock is deliberately out of scope: its remaining `~2.4s`
`ed25519MaterialRestoreMs` (the largest single latency prize in the codebase)
belongs to a separate unlock migration onto the 83B advance/durable pattern,
not to this tail plan.

## Baseline

Latest post-cleanup intended benchmark, July 5, 2026:

| Flow                 |     Total | Advance | Finalize | Advance source         | Finalize source         |
| -------------------- | --------: | ------: | -------: | ---------------------- | ----------------------- |
| Email OTP, Tempo+Arc | `2,766ms` | `561ms` |  `637ms` | `durable_workerd_wasm` | `durable_advanced_eval` |
| Passkey, Tempo+Arc   | `3,122ms` | `542ms` |  `590ms` | `durable_workerd_wasm` | `durable_advanced_eval` |

Representative advance split:

- WASM advance: `515-536ms`;
- serialized session materialize: `152-153ms`;
- message-schedule rounds: `184-196ms`;
- round-core rounds: `134-135ms`;
- persistence: `12-15ms`.

Representative finalize split:

- HSS finalize: `568-600ms`;
- serialized session materialize: `149-151ms`;
- output projection: `79-81ms`;
- report assembly: `83-85ms`;
- open server output: `159-160ms`;
- open seed output: `97-98ms`.

Trace files:

- `test-results/intended-lifecycle-traces/1783258261598-email_otp.registration-brisk-meadow-2vpm9x-intended-lifecycle-trace.json`
- `test-results/intended-lifecycle-traces/1783258267070-passkey.registration-cedar-quartz-xvm5rb-intended-lifecycle-trace.json`

## Implementation Progress

July 5, 2026:

- Added the focused durable Worker/D1-style HSS tail benchmark:
  `pnpm benchmark:ed25519-hss:tail`.
- Confirmed the focused pre-optimization tail:
  - `advanceWallMs`: `460.028ms` median;
  - `finalizeWallMs`: `387.509ms` median;
  - separate server output open: `142.764ms` median;
  - separate seed output open: `86.721ms` median.
- Folded server output opening and optional seed output opening into
  durable-advanced finalize while the evaluator/garbler sessions are already
  materialized.
- Removed the unused serialized `evaluation_report_json` payload from the
  server WASM finalize boundary.
- Confirmed the focused post-optimization tail:
  - `advanceWallMs`: `461.704ms` median;
  - `finalizeWallMs`: `405.906ms` median;
  - folded server output open: `5ms` median;
  - folded seed output open: `0ms` median.

Focused benchmark evidence:

- Before: `benchmarks/ed25519-hss-tail/out/2026-07-05T14-08-25-871Z/summary.md`
- After: `benchmarks/ed25519-hss-tail/out/2026-07-05T14-18-39-695Z/summary.md`

The implemented win removes about `~225-230ms` of duplicated post-finalize
materialization/opening work from registration flows that need both server and
seed outputs. The remaining finalize tail is now dominated by
`finalizeSerializedSessionMaterializeMs` (`~136ms`) and
`finalizeOutputProjectionMs` (`~176ms`). Advancing further toward `<400ms`
requires the Phase 1/2 state-format and projection-loop work below.

July 6, 2026:

- Split server-side HSS materialization timings into:
  - serialized-session decode;
  - runtime materialization;
  - evaluator-session materialization;
  - garbler-session materialization.
- Threaded those fields through server route diagnostics, SDK-web route
  diagnostics parsing, and the focused tail benchmark.
- Confirmed the final default-WASM focused benchmark after the rejected build
  experiment was backed out:
  `benchmarks/ed25519-hss-tail/out/2026-07-05T16-14-06-063Z/summary.md`.
  - `clientArtifactMs`: `533.597ms` median.
  - `advanceWallMs`: `473.622ms` median.
  - `finalizeWallMs`: `409.507ms` median.
  - `openServerOutputMs`: `5ms` median.
  - `openSeedOutputMs`: `0ms` median.
- Confirmed intended passkey registration still passes with the split fields
  preserved end to end:
  `test-results/intended-lifecycle-traces/1783268164653-passkey.registration-lunar-meadow-45xqvg-intended-lifecycle-trace.json`.
  - Total: `2,912ms` (`3,122ms` baseline).
  - `walletRegisterHssAdvanceStateMs`: `534ms`.
  - `registrationHssAdvanceStateMaterializeRuntimeMs`: `99ms`.
  - `registrationHssAdvanceStateMaterializeGarblerSessionMs`: `54ms`.
  - `registrationHssAdvanceStateMessageScheduleRoundsMs`: `184ms`.
  - `registrationHssAdvanceStateRoundCoreRoundsMs`: `133ms`.
  - `walletRegisterFinalizeMs`: `344ms`.
  - `registrationHssFinalizeMs`: `321ms`.
  - `registrationHssFinalizeMaterializeRuntimeMs`: `99ms`.
  - `registrationHssFinalizeMaterializeGarblerSessionMs`: `52ms`.
  - `registrationHssFinalizeOpenServerOutputMs`: `5ms`.
  - `registrationHssFinalizeOpenSeedOutputMs`: `0ms`.
- Confirmed Email OTP intended benchmark after folded output
  opening:
  `test-results/intended-lifecycle-traces/1783268159401-email_otp.registration-jade-bloom-96qmup-intended-lifecycle-trace.json`.
  - Total: `2,508ms` (`2,766ms` baseline).
  - `walletRegisterHssAdvanceStateMs`: `554ms`.
  - `registrationHssAdvanceStateMaterializeRuntimeMs`: `102ms`.
  - `registrationHssAdvanceStateMaterializeGarblerSessionMs`: `54ms`.
  - `registrationHssAdvanceStateMessageScheduleRoundsMs`: `189ms`.
  - `registrationHssAdvanceStateRoundCoreRoundsMs`: `138ms`.
  - `ed25519EvaluationArtifactMs`: `454ms`.
  - `walletRegisterFinalizeMs`: `376ms`.
  - `registrationHssFinalizeMs`: `346ms`.
  - `registrationHssFinalizeMaterializeRuntimeMs`: `99ms`.
  - `registrationHssFinalizeMaterializeGarblerSessionMs`: `52ms`.
  - `registrationHssFinalizeOpenServerOutputMs`: `5ms`.
  - `registrationHssFinalizeOpenSeedOutputMs`: `1ms`.
- Ran the E1 `curve25519_dalek_bits="64"` WASM build-flag probe and rejected
  it: `advanceWallMs` regressed to `685.327ms`, `finalizeWallMs` regressed to
  `634.786ms`, and `clientArtifactMs` regressed to `686.954ms`.
  Evidence:
  `benchmarks/ed25519-hss-tail/out/2026-07-05T16-09-57-016Z/summary.md`.
  The default WASM artifacts were rebuilt after the experiment.
- Ran `cargo hss-fv all`; vectors, parity, Aeneas/Lean, Verus, and Verus
  anti-drift checks passed.
- Added the E3 wasm-bindgen boundary-copy probe and confirmed the boundary is
  material for the large finalize payload:
  `benchmarks/ed25519-hss-tail/out/2026-07-05T16-24-05-696Z/summary.md`.
  - Advance boundary payload: `244,283` bytes.
  - `boundaryCopyAdvancePayloadWallMs`: `17.181ms` median.
  - Finalize boundary payload: `1,180,903` bytes.
  - `boundaryCopyFinalizePayloadWallMs`: `81.954ms` median.
  - Rust-side `decodeArgsMs` accounts for the measured copy time; field
    summarization is `0ms`.
    This does not dominate the full finalize bucket, but it is above the
    `15-20ms` threshold in E3. The next boundary optimization should be paired
    with E2 advanced-state trimming or a direct linear-memory large-argument
    path, because most of the cost is proportional to the `~1.18MB` finalize
    payload.
- Added the E2 advanced-state size census:
  `benchmarks/ed25519-hss-tail/out/2026-07-05T16-30-04-660Z/summary.md`.
  It showed the `~1.05MB` advanced state was almost entirely
  `execution_state` (`1,022,872` bytes), with `round_core` at `884,204`
  bytes and `projector_inputs` at `138,502` bytes.
- Moved artifact-independent output projection into advance and persisted a
  finalized eval state for the finalize route. The persisted finalized state
  also clears the now-unused `hidden_eval_program`.
  Evidence:
  `benchmarks/ed25519-hss-tail/out/2026-07-05T16-37-26-521Z/summary.md`.
  - `advanced_server_eval_state_bytes`: `67,333` median, down from about
    `1,048,650`.
  - `boundaryCopyFinalizePayloadWallMs`: `13.826ms`, down from `~82ms`.
  - `advanceWallMs`: `577.869ms`, with `advanceOutputProjectionMs` at
    `112ms`.
  - `finalizeWallMs`: `161.233ms`, with `finalizeOutputProjectionMs` at
    `0ms`.
  - Focused parallel HSS tail improves from about
    `max(532ms client, 474ms advance) + 409ms finalize = 941ms` to
    `max(533ms client, 578ms advance) + 161ms finalize = 739ms`.
    This validates the Phase 3 budget because the work movement reduces total
    elapsed tail time rather than only shifting a bucket.
- Confirmed final intended registration benchmarks after the finalized-state
  checkpoint:
  - Email OTP:
    `test-results/intended-lifecycle-traces/1783269560909-email_otp.registration-opal-zenith-gjw4qk-intended-lifecycle-trace.json`.
    Total `2,399ms`, violations `[]`, `walletRegisterHssAdvanceStateMs`
    `608ms`, `ed25519EvaluationArtifactMs` `447ms`,
    `walletRegisterFinalizeMs` `207ms`, and route-level
    `registrationHssFinalizeMs` `184ms`.
  - Passkey:
    `test-results/intended-lifecycle-traces/1783269566163-passkey.registration-violet-zenith-bb3shm-intended-lifecycle-trace.json`.
    Total `2,786ms`, violations `[]`, `walletRegisterHssAdvanceStateMs`
    `595ms`, `ed25519EvaluationArtifactMs` `448ms`,
    `walletRegisterFinalizeMs` `192ms`, and route-level
    `registrationHssFinalizeMs` `176ms`.
  - Remaining top buckets are outside 83D's HSS-finalize scope: Email OTP has
    `ed25519ClientMaterialMs` `380ms`, `emailOtpEnrollmentMaterialMs`
    `362ms`, `walletRegisterPrepareMs` `296ms`, and
    `thresholdEd25519SigningSessionHydrationMs` `285ms`; passkey has
    `ecdsaRegistrationPersistenceMs` `559ms`,
    `thresholdEd25519SigningSessionHydrationMs` `296ms`, and `authProofMs`
    `263ms`.
- Added a Stage Loop Microbenchmarks section to the focused harness output.
  It uses the same deterministic durable fixture and reports:
  advance message-schedule rounds, advance round-core rounds, combined advance
  stage loops, advance output projection, client hidden-eval message-schedule,
  client hidden-eval round-core, client hidden-eval total, and client
  hidden-eval unattributed time.
  Evidence:
  `benchmarks/ed25519-hss-tail/out/2026-07-05T16-48-36-290Z/summary.md`.
  - `advance_message_schedule_plus_round_core_ms`: `280ms` median.
  - `advance_output_projection_ms`: `111ms` median.
  - `client_hidden_eval_total_ms`: `337ms` median.
  - `client_hidden_eval_unattributed_ms`: `217ms` median.
- Added WASM-surface corruption coverage for the finalized advanced-state
  boundary:
  `tests/unit/thresholdEd25519.hssWasmSurface.unit.test.ts`. It proves valid
  durable-advanced finalize succeeds, then rejects a mismatched staged
  evaluator artifact and truncated finalized advanced-state bytes. Existing D1
  durable-record parser coverage continues to reject wrong add-stage digest
  width, wrong projection mode, expired records, and malformed finalized report
  records.
- Added native Rust boundary coverage for the durable server advance checkpoint:
  `server_driver_state_rejects_corrupt_advance_runtime_checkpoint` rejects a
  wrong context binding, mismatched advance artifact digest, truncated advance
  artifact bytes, and wrong hidden-eval program digest before materialization.
- Ran the existing native embedded hidden-eval profile as reference-only
  allocation evidence:
  `benchmarks/ed25519-hss-tail/out/2026-07-05T16-54-native-embedded-profile.json`.
  Release-mode stage timing confirms native round-core is the dominant loop
  bucket (`66.212ms` p50), followed by message schedule (`18.346ms`) and
  output projector (`16.863ms`). Allocation probes identify the largest
  pressure points as output projector (`4,157,080B`, `5,091` calls), round
  core (`2,672,907B`, `4,905` calls), and message schedule (`1,141,387B`,
  `2,837` calls). This is a reference signal only; Worker/WASM remains the
  product path.
- Adopted the E1 `-C target-feature=+simd128` WASM build for HSS hot-path
  release packages: NEAR signer browser/server HSS builds and the HSS client
  signer build now append `-C target-feature=+simd128` in
  `packages/sdk-web/scripts/build/build-wasm.sh`. The initial probe was:
  `benchmarks/ed25519-hss-tail/out/2026-07-05T16-56-46-533Z/summary.md`.
  It improved `clientArtifactMs` to `480.617ms`, `advanceWallMs` to
  `549.727ms`, `finalizeWallMs` to `154.288ms`, and
  `client_hidden_eval_unattributed_ms` to `187ms`. After making SIMD the
  default for those packages, the focused benchmark recorded:
  `benchmarks/ed25519-hss-tail/out/2026-07-05T17-02-06-522Z/summary.md`.
  - `clientArtifactMs`: `481.371ms` median.
  - `advanceWallMs`: `546.644ms` median.
  - `finalizeWallMs`: `153.899ms` median.
  - `advance_message_schedule_plus_round_core_ms`: `281ms` median.
  - `client_hidden_eval_unattributed_ms`: `187ms` median.
    SIMD is now a landed HSS hot-path build optimization, but advance remains
    above the `<400ms` target.
- Ran the E1 `wasm-opt -O3` probe against the current SIMD artifacts and
  rejected it as a default build change. The standard rebuilt baseline was
  `benchmarks/ed25519-hss-tail/out/2026-07-05T17-43-49-126Z/summary.md`;
  the `-O3` variant was
  `benchmarks/ed25519-hss-tail/out/2026-07-05T17-44-15-007Z/summary.md`.
  `clientArtifactMs` improved from `480.809ms` to `467.014ms`, but
  `advanceWallMs` moved only from `544.347ms` to `540.805ms`, and the server
  WASM artifact grew from `2.6MB` to `3.1MB`. The variant does not materially
  improve the current critical path.
- Confirmed intended registration benchmarks after the SIMD build landed:
  - Email OTP:
    `test-results/intended-lifecycle-traces/1783271282752-email_otp.registration-maple-fjord-cte7su-intended-lifecycle-trace.json`.
    Total `2,293ms`, violations `[]`, `walletRegisterHssAdvanceStateMs`
    `587ms`, `ed25519EvaluationArtifactMs` `411ms`, route-level
    `registrationHssFinalizeMs` `169ms`, and
    `registrationHssFinalizeReportMs` `5ms`.
  - Passkey:
    `test-results/intended-lifecycle-traces/1783271287187-passkey.registration-golden-lantern-mmg3be-intended-lifecycle-trace.json`.
    Total `2,684ms`, violations `[]`, `walletRegisterHssAdvanceStateMs`
    `573ms`, `ed25519EvaluationArtifactMs` `409ms`, route-level
    `registrationHssFinalizeMs` `159ms`, and
    `registrationHssFinalizeReportMs` `4ms`.
  - Remaining top buckets are still outside this HSS tail slice: Email OTP has
    `ed25519ClientMaterialMs` `363ms`, `emailOtpEnrollmentMaterialMs`
    `347ms`, and `thresholdEd25519SigningSessionHydrationMs` `282ms`;
    passkey has `ecdsaRegistrationPersistenceMs` `555ms`,
    `thresholdEd25519SigningSessionHydrationMs` `292ms`, and `authProofMs`
    `249ms`.
- Added a compact finalize context emitted during advance and persisted beside
  the durable advanced eval. Durable finalize now validates that context against
  the finalized eval state and staged evaluator artifact, then assembles the
  finalize packet/report from serialized opener state without rebuilding the
  shared runtime, evaluator session, or garbler session.
  Evidence:
  `benchmarks/ed25519-hss-tail/out/2026-07-05T17-32-12-562Z/summary.md`.
  - `finalize_context_bytes`: `406` median.
  - `finalizeSerializedSessionMaterializeMs`: `0ms`.
  - `finalizeMaterializeRuntimeMs`: `0ms`.
  - `finalizeMaterializeEvaluatorSessionMs`: `0ms`.
  - `finalizeMaterializeGarblerSessionMs`: `0ms`.
  - `finalizeWallMs`: `22.314ms` median.
  - `advanceWallMs`: `548.528ms` median.
  - `clientArtifactMs`: `488.035ms` median.
  - `advance_message_schedule_plus_round_core_ms`: `277ms` median.
  - `client_hidden_eval_unattributed_ms`: `193ms` median.
    Finalize is now below the `<400ms` target with margin. The remaining HSS
    work is advance/client hidden-eval profiling and any intended-run
    confirmation after the SDK build copies the new WASM artifacts.
- Reran the intended passkey registration benchmark after the compact finalize
  context, regenerated WASM packages, and SDK build:
  `test-results/intended-lifecycle-traces/1783272819948-passkey.registration-indigo-voyage-377m93-intended-lifecycle-trace.json`.
  - Total: `2,541ms`.
  - Violations: `[]`.
  - `walletRegisterHssAdvanceStateMs`: `584ms`.
  - `ed25519EvaluationArtifactMs`: `409ms`.
  - `walletRegisterFinalizeMs`: `53ms`.
  - route-level `registrationHssFinalizeMs`: `34ms`.
  - `registrationHssFinalizeSerializedSessionMaterializeMs`: `0ms`.
  - `registrationHssFinalizeMaterializeRuntimeMs`: `0ms`.
  - `registrationHssFinalizeMaterializeGarblerSessionMs`: `0ms`.
  - `registrationHssFinalizeReportMs`: `3ms`.
  - `registrationHssFinalizeOpenServerOutputMs`: `5ms`.
  - `registrationHssFinalizeOpenSeedOutputMs`: `1ms`.
    The paired Email OTP intended benchmark did not reach registration in that
    run because the Google `id_token` had expired at `/session/exchange`; no
    Email OTP HSS trace was produced there. The final validation section
    records the later fresh-token Email OTP rerun.
- Probed an in-place `ServerEvalState` transition path for the server-local
  advance loop, then rejected and removed it: the fresh Worker/WASM tail run
  stayed flat (`advanceWallMs` `485.450ms`, `finalizeWallMs` `31.664ms`), so
  the extra transition API surface was not worth carrying.
- Confirmed the final retained focused Worker/WASM benchmark after that
  rollback:
  `benchmarks/ed25519-hss-tail/out/2026-07-05T18-36-29-328Z/summary.md`.
  - `clientArtifactMs`: `475.551ms` median.
  - `advanceWallMs`: `485.709ms` median.
  - `advanceMessageScheduleRoundsMs`: `154ms` median.
  - `advanceRoundCoreRoundsMs`: `121ms` median.
  - `advanceOutputProjectionMs`: `114ms` median.
  - `finalizeWallMs`: `31.885ms` median.
  - `boundaryCopyAdvancePayloadWallMs`: `25.655ms` median.
  - `boundaryCopyFinalizePayloadWallMs`: `22.912ms` median.
- Confirmed the final worker-handle focused benchmark, matching the product
  registration client-session path:
  `benchmarks/ed25519-hss-tail/out/2026-07-05T18-37-50-170Z/summary.md`.
  - `clientArtifactMs`: `407.042ms` median.
  - `advanceWallMs`: `475.877ms` median.
  - `finalizeWallMs`: `30.641ms` median.
  - `boundaryCopyAdvancePayloadWallMs`: `25.115ms` median.
  - `boundaryCopyFinalizePayloadWallMs`: `22.266ms` median.
- Added client artifact sub-buckets to the focused runner and measured the E4
  worker-handle path that registration uses after client-request preparation.
  The first pass
  `benchmarks/ed25519-hss-tail/out/2026-07-05T17-48-00-403Z/summary.md`
  proved artifact materialization is already `0ms` in the real client path;
  the follow-up
  `benchmarks/ed25519-hss-tail/out/2026-07-05T17-53-07-457Z/summary.md`
  threads the output-projector profile through the client API.
  - `prepareAddStageRequestMs`: `21.351ms` median.
  - `clientArtifactMs`: `408.642ms` median.
  - `clientArtifactMaterializeSessionMs`: `0ms` median.
  - `clientArtifactBuildArtifactMs`: `407ms` median.
  - `clientArtifactHiddenEvalTotalMs`: `313ms` median.
  - `clientArtifactHiddenEvalOutputProjectorMs`: `186ms` median.
  - `clientArtifactHiddenEvalOutputProjectorClientBaseMs`: `44.526ms` median.
  - `clientArtifactHiddenEvalOutputProjectorServerOutputMs`: `49.723ms` median.
  - `client_hidden_eval_unattributed_ms`: `7ms` median.
    The earlier serialized-state benchmark measured `81ms` of artifact-side
    materialization that the real worker-handle registration path does not pay
    in this bucket. E4 is therefore closed as measured: the client pool/session
    is already prebuilt before the artifact leg, and the remaining client
    bucket is hidden-eval arithmetic.
- Added a durable server advance checkpoint to the serialized server driver
  state. The checkpoint persists bincode-safe artifact bytes plus public
  binding digests and finalize context, validates those facts against the
  garbler evaluation key, and materializes only the hidden-eval program needed
  for the advance stage loop. Durable advance no longer rebuilds the full
  shared runtime, CPU execution program, or execution result from
  `SharedRuntimeState`.
  Evidence:
  `benchmarks/ed25519-hss-tail/out/2026-07-05T18-20-24-149Z/summary.md`.
  - `advanceMaterializeRuntimeMs`: `0ms` median, down from `129ms` in the
    worker-handle reference run.
  - `advanceSerializedSessionMaterializeMs`: `47ms` median, now entirely
    evaluator/garbler session materialization.
  - `advanceWallMs`: `485.876ms` median.
  - `boundaryCopyAdvancePayloadWallMs`: `25.564ms` median.
  - `finalizeWallMs`: `31.280ms` median.
  - `clientArtifactMs`: `415.607ms` median.
    The checkpoint is a clear state-format win, but advance remains above the
    `<400ms` target because the remaining work is dominated by
    `advanceMessageScheduleRoundsMs` (`154ms`), `advanceRoundCoreRoundsMs`
    (`122ms`), `advanceOutputProjectionMs` (`118ms`), and garbler-session
    materialization (`46ms`).
- Probed a prepared-garbler-OT checkpoint and rejected it. The probe reduced
  `advanceMaterializeGarblerSessionMs` from `46ms` to `3ms`, but it increased
  the serialized advance/finalize payloads from about `383KB`/`339KB` to
  `598KB`/`554KB`. Boundary-copy time rose enough that the end-to-end tail was
  flat or worse. Evidence:
  `benchmarks/ed25519-hss-tail/out/2026-07-05T18-16-59-513Z/summary.md`.
  The probe code was removed; prepared OT words stay runtime-only.

## Constraints

- Keep the 83B durable advanced-eval and finalized-report correctness model.
- Do not persist WASM/native process handles.
- Do not add compatibility flags or alternate runtime paths.
- Keep serialized replay out of normal registration finalize.
- Optimize total elapsed registration time, not an isolated timing bucket.
- Keep unlock/session HSS replay changes out of scope unless a phase explicitly
  measures and scopes them.

## Hypotheses

1. The `~150ms` materialization cost appears in both advance and finalize. A
   lower-cost durable state encoding or checkpoint shape may reduce both.
2. The stage loops after the pool fix are now `~320-330ms` total before output
   projection. Further gains likely require Rust/WASM arithmetic and allocation
   profiling. The client artifact build shares the same crate code and runs at
   `~3.9x` its native cost (`471ms` vs `122ms` native post-pool-fix), so the
   same profiling likely pays there too.
3. Finalize no longer spends its tail in output projection, output opening, or
   durable session materialization: latest route-level HSS finalize is
   `34ms`, and the focused benchmark is `~21-22ms`. The HSS-critical section
   is now dominated by advance (`~525-585ms`) and the parallel client artifact
   leg (`~409-488ms`).
4. Registration total time is also affected by non-HSS buckets:
   `ed25519ClientMaterialMs`, `emailOtpEnrollmentMaterialMs`,
   `thresholdEd25519SigningSessionHydrationMs`, and (passkey)
   `ecdsaRegistrationPersistenceMs`. 83D only owns HSS buckets; per the
   total-target arithmetic in the Goal, those buckets need their own
   follow-up refactor for the `<2.2s`/`<2.5s` totals to close.

## Non-Goals

- Do not reintroduce `native_service` provenance or sidecar startup.
- Do not make Durable Object memory a correctness dependency.
- Do not store `preparedSessionHandle`, `stagedEvaluatorArtifactHandle`, or any
  other process-local HSS handle in D1/DO state.
- Do not merge Ed25519 and ECDSA record shapes.
- Do not weaken transcript/context/add-stage digest binding.

## Phase 0: Measurement Harness

- [x] Add a focused HSS tail benchmark command that runs registration advance
      and finalize fixtures without full browser registration.
- [x] Record per-stage allocation counts where the Rust/WASM boundary can expose
      them cheaply.
- [x] Add trace summarization that prints: - materialize/decode; - add-stage response; - message-schedule rounds; - round-core rounds; - output projection; - output opening; - report assembly; - encode/persist.
- [x] Keep intended registration traces as the user-visible validation gate.

Exit criteria:

- [x] We can reproduce the core durable HSS tail buckets outside the browser.
- [x] The implemented output-opening optimization has before/after numbers from
      the same harness.

## Phase 1: Durable State Format And Materialization

- [x] Inspect the current serialized `ServerEvalState` and prepared-session
      state sizes.
- [x] Split materialization timing into decode, runtime materialization,
      evaluator-session materialization, and garbler-session materialization.
- [x] Add allocation and validation sub-timings if the next profiling pass
      needs more detail than the runtime/evaluator/garbler split provides.
- [x] Evaluate a compact durable advanced-state encoding that avoids rebuilding
      expensive runtime structures in finalize.
- [x] Evaluate whether advance can persist a finalized runtime-neutral
      checkpoint that finalize can consume with less materialization work.
- [x] Add corruption tests for any new encoding: - wrong context binding; - wrong add-stage digest; - wrong projection mode; - expired record; - truncated/corrupted bytes.
- [x] Delete old state-shape code if the new encoding replaces it.

Exit criteria:

- Finalize materialization is eliminated on the durable advanced path.
- Advance materialization remains above `75ms`; it is now tracked as part of
  the open advance/client loop work rather than the finalize tail.

Progress note: the initial focused benchmark reported
`advanced_server_eval_state_bytes` at about `1,048,784-1,049,221` bytes and
`staged_evaluator_artifact_bytes` at about `59,576` bytes. The finalized-state
checkpoint reduced the advanced state to about `67,333` bytes. The compact
finalize-context follow-up adds a `406` byte context record and removes
serialized session/runtime/evaluator/garbler materialization from durable
finalize entirely. Advance still pays runtime construction (`~83ms`) and
garbler-session construction (`~47ms`), while decode and evaluator-session
materialization remain effectively noise in the measured path.

## Phase 2: Stage-Loop Rust/WASM Profiling

- [x] Profile message-schedule and round-core loops after the pool fix.
- [x] Identify remaining allocation, clone, and bounds-check hotspots.
- [x] Check whether stage input/output buffers can be reused inside one advance
      operation without changing transcript semantics.
- [x] Check whether `wasm-bindgen` data conversion copies dominate any stage.
- [x] Profile the client artifact build path
      (`build_client_owned_staged_evaluator_artifact`, browser WASM) with the
      same lens: it shares the crate code, runs at `~3.9x` native, and becomes
      the critical parallel leg once advance drops below `~471ms`. Apply
      allocation/copy fixes that transfer; record the client bucket
      before/after in the intended traces.
- [x] Add microbenchmarks for the stage loops with fixed deterministic inputs.
- [x] Keep native benchmark comparison only as a reference signal; Worker/WASM
      remains the product path.

Exit criteria:

- Combined message-schedule plus round-core timing drops below `250ms`, or the
  doc records the next algorithmic bottleneck.
- `ed25519EvaluationArtifactMs` drops below `400ms`, or the doc records why
  the client build is already at its practical WASM floor.

Progress note: the focused benchmark now reports advance message schedule at
about `160-188ms`, advance round core at about `125-137ms`, and client
artifact hidden eval at about `340-352ms`. The first build-flag probe
(`curve25519_dalek_bits="64"`) regressed all HSS buckets and is rejected.
The Stage Loop Microbenchmarks table is now emitted in each focused summary so
future loop work can compare fixed-input sub-buckets without re-parsing raw
samples. The latest fixed-input run reports combined advance message-schedule
plus round-core at `280ms`, advance output projection at `111ms`, and client
hidden-eval unattributed time at `217ms`; deeper Rust profiling should target
those buckets next. Native allocation profiling names output projector, round
core, and message schedule as the largest allocation-pressure probes. Loop
optimization beyond the measured build/profile candidates is deferred to a
future algorithmic HSS slice.

July 6 follow-up: the latest drift-enabled focused run
`benchmarks/ed25519-hss-tail/out/2026-07-05T17-38-00-796Z/summary.md`
reports fixed-input combined advance message-schedule plus round-core at
`264ms` median / `265ms` p95, advance output projection at `96ms` median /
`97ms` p95, client hidden eval at `296ms` median / `306ms` p95, and finalize
at `21.493ms` median / `21.637ms` p95. The stage-loop code already uses
compact bit-slice working buffers inside the arithmetic kernels; the remaining
outer request/response objects are transcript-bound stage messages. Reusing or
mutating those messages would blur protocol state rather than remove the
dominant DDH arithmetic work, so the buffer-reuse check is closed as evaluated.
The next algorithmic bottleneck is the message-schedule/round-core arithmetic
itself plus output-projector arithmetic. The worker-handle client path now
shows only `~7ms` of hidden-eval unattributed time; the dominant client
projector slices are `client_base` (`~45ms`) and `server_output` (`~50ms`).

## Phase 3: Finalize Output Projection And Opening

Overlap budget constraint: advance executes in parallel with the client
artifact build (`~471ms`, both start after the add-stage request is
prepared). Advance is the critical leg whenever it exceeds the artifact
build, so work moved from finalize into advance is free only while advance
stays under that leg — after Phases 1-2 land advance near `~390ms`, the
free budget is roughly `80ms`; beyond it, every moved millisecond is 1:1
bucket-shifting that the plan's own constraints forbid. Every Phase 3 move
must show total-elapsed improvement in the intended trace, not just a
smaller finalize bucket.

- [x] Split `registrationHssFinalizeReportMs` into projection, packet assembly,
      output opening, and seed/key derivation if any sub-bucket remains hidden.
- [x] Determine which finalize work depends on the full client artifact and
      which work depends only on durable advanced eval.
- [x] Move artifact-independent finalize preparation into the advance record
      only if the transcript binding remains explicit and testable, and only
      within the overlap budget above (verify advance stays under the client
      artifact leg in the intended trace after each move).
- [x] Evaluate specialized registration projection paths for: - `registration_seed_and_output`; - `registration_output_only`.
- [x] Add benchmark checks proving folded output opening stays bound to the same
      ceremony context and add-stage request.

Exit criteria:

- [x] Duplicated output-opening materialization is removed. Focused finalize
      first drops from `~617ms` effective finalize-plus-open work
      (`387ms + 143ms + 87ms`) to `~406ms`, then the finalized-state
      checkpoint drops focused finalize to `~161ms`.
- [x] Advance may exceed the client artifact leg after output projection moves,
      but the focused parallel tail still improves (`~941ms` to `~739ms`).
- [x] Intended registration traces confirm the same critical-path improvement
      in browser flows.

## Phase 4: Total Registration Rebalance

- [x] Rerun intended passkey and Email OTP Tempo+Arc registration benchmarks.
- [x] Verify advance still starts before client artifact build.
- [x] Verify the critical-path summary shows total elapsed improvement, not only
      bucket movement.
- [x] Record newly dominant non-HSS buckets for the follow-up refactor the
      Goal arithmetic anticipates. Known candidates:
      `ed25519ClientMaterialMs` (~410ms), `emailOtpEnrollmentMaterialMs`
      (~390ms), `thresholdEd25519SigningSessionHydrationMs` (~300ms), and
      (passkey) `ecdsaRegistrationPersistenceMs` (~560-607ms).

Exit criteria:

- [x] Email OTP registration is under the `~2.4s` in-scope expectation:
      latest intended trace is `2,083ms`.
- [x] Passkey registration has HSS finalize below the target and records the
      remaining top bucket outside 83D: latest intended trace is `2,367ms`,
      with `ecdsaRegistrationPersistenceMs` at `551ms`.
- [x] Intended harness violations remain `[]`.

## Candidate Experiments (July 6 review)

Additional experiments grounded in the current progress-note numbers. Each is
listed with its target bucket and the phase it slots into; promote into the
phase checklists as they are picked up.

### E1: WASM build-flag matrix (Phase 2)

Current build-flag probes are complete. The `curve25519_dalek_bits="64"`
variant is rejected: it made durable materialization much slower and regressed
advance, finalize, and client artifact timings. The
`-C target-feature=+simd128` probe is adopted for HSS hot-path release
packages: it improves client artifact and advance modestly while leaving
advance above target. The `wasm-opt -O3` probe is rejected for the default
build because it gives only a `~3.5ms` advance improvement while increasing the
server artifact from `2.6MB` to `3.1MB`.

- Rebuild `near_signer` (pkg-server) and `hss_client_signer` with,
  individually then combined:
  - ~~`RUSTFLAGS='--cfg curve25519_dalek_bits="64"'`~~ — rejected; it
    regressed advance, finalize, and client artifact timings in Worker/WASM;
  - `-C target-feature=+simd128` plus `wasm-opt --enable-simd` — adopted for
    HSS hot-path release packages;
  - ~~`wasm-opt -O3` versus the default `-O`~~ — rejected; it gives no
    meaningful critical-path win for the artifact-size cost.
- [x] Measure each variant with `benchmark:ed25519-hss:tail` and the
      advance-sources runner; the artifact-provenance guard enforces same-code
      comparisons.
- Cost: ~1-2h per variant. Expected: `10-40%` on group-arithmetic loops.

### E2: Advanced-state census, trim, and encoding (Phase 1)

Initial `advanced_server_eval_state_bytes` was `~1,049,221` bytes. The
finalized-state checkpoint reduced it to about `67,333` bytes. The compact
finalize context is `406` bytes and lets finalize avoid all durable session
materialization. This removes the immediate D1 row-size and finalize
materialization risk, making raw BLOB/compression a lower-priority p95 and
persistence experiment.

- [x] Per-field size census of the serialized advanced state: which fields are
      true state versus tables re-derivable from a small seed in `<10ms`.
- [x] Trim to the minimal finalize input (finalize needs projection/packet
      inputs, not stage history).
- [x] Persist the compact finalize context needed to rebuild the packet/report
      from the finalized eval state without full runtime/session materialization.
- [x] Persist the durable server advance checkpoint needed to avoid full
      `SharedRuntimeState` materialization during advance. The remaining
      advance materialization is evaluator/garbler session state, and the
      prepared-garbler-OT checkpoint was rejected because payload-copy growth
      erased the internal materialization win.
- [x] Measure raw BLOB and compression storage economics before changing the
      D1 schema. Evidence:
      `benchmarks/ed25519-hss-tail/out/2026-07-06T04-24-01-848Z/summary.md`.
  - Raw MessagePack advanced state: `67,569` median bytes.
  - Current base64url text: `90,092` median bytes.
  - Current JSON envelope: `90,126` median bytes.
  - gzip: `22,106` median bytes, `0.967ms` median compress,
    `0.130ms` median decompress.
  - deflate: `22,094` median bytes, `0.506ms` median compress,
    `0.107ms` median decompress.
    Raw BLOB saves about a quarter of the envelope size. Compression saves
    about three quarters of it, with sub-millisecond median inflate/deflate in
    the Node zlib proxy. This is worth keeping as a storage/payload-size
    follow-up, but it does not target the current `~500ms` advance arithmetic
    bucket.
- [ ] Implement compressed raw BLOB storage only if D1 row size, payload
      transfer, or p95 persistence becomes the next measured bottleneck.

### E3: wasm-bindgen boundary copy probe (Phase 2)

- [x] Add a no-op echo WASM export accepting the same payload sizes (`~1MB`
      state, `~59KB` artifact); measure pure JS-to-WASM copy and serde cost per
      call.
- [x] After the finalized-state checkpoint, the finalize boundary dropped to
      `13.826ms` for a `~199KB` payload. A direct linear-memory large-argument
      path is no longer justified for this registration tail.

### E4: Client pool prebuild during auth idle (Phase 2, client leg)

- [x] Measure the setup/pool-construction fraction of the client artifact build
      (`~340ms` hidden eval inside the `~471ms` bucket).
- [x] Verify the registration path already uses the client worker-session
      handle produced by client-request preparation. In worker-handle mode,
      `clientArtifactMaterializeSessionMs` is `0ms`, `clientArtifactMs` is
      `408.642ms`, and `clientArtifactBuildArtifactMs` is `407ms`.
- [x] Close extra client-pool prebuild work as unnecessary for this slice. The
      remaining client bucket is hidden-eval arithmetic; setup and session
      materialization are no longer material contributors.

### E5: Projection at advance (Phase 3, budget-gated)

`finalizeOutputProjectionMs` is now the largest finalize sub-bucket
(`~176ms`). The client output mask derives from the client secret plus
context and is independent of the artifact (`clientOutputMaskHandle` exists
before the artifact build starts).

- [x] First verify in the crate that the projection response consumes only the
      mask/commitment and projection mode, never artifact fields.
- [x] Move output projection into advance and persist the finalized eval
      checkpoint. The benchmark shows the move is a net win because it also
      removes the `~1MB` finalize payload and its `~82ms` boundary copy.
- [x] Binding remains enforced by the existing finalized-state/artifact checks:
      context binding, add-stage digest, projection mode, run binding, input
      commitments, and evaluation digest are all verified before report assembly.
- [x] Reject the server-only output projector shortcut: a focused probe that
      skipped discarded client-output bundle construction moved durable
      `advanceWallMs` only from `485.709ms` to `484.167ms`, while the
      worker-handle run regressed from `475.877ms` to `486.779ms`. The shared
      projector stays in place.

### E6: Memory-churn and p95 drift probe (Phase 0 extension)

- [x] Run N sequential advance+finalize cycles in the focused Node/WASM isolate
      proxy for the Worker/WASM path; record WASM memory growth and latency
      drift across iterations.
- The pre-checkpoint `~1MB` per-registration state was a heap-churn suspect.
  Current `~67KB` state still needs a p95 drift run before E2's raw BLOB or
  compression tasks are worth prioritizing. Medians alone will not show this.

Result: the focused Node/WASM isolate drift proxy now runs with
`--drift-iterations`. The first recorded run
`benchmarks/ed25519-hss-tail/out/2026-07-05T17-38-00-796Z/summary.md` used
12 sequential cycles. Server and client WASM memory buffers had `0` byte
growth, advance p95 was `532.040ms`, client artifact p95 was `476.370ms`, and
finalize p95 was `21.741ms`.

The follow-up run
`benchmarks/ed25519-hss-tail/out/2026-07-06T04-24-01-848Z/summary.md` used
24 sequential cycles after the later HSS checkpoint work. Server, client, and
threshold-PRF WASM memory buffers again had `0` byte growth. Drift p95 was
`501.297ms` for advance, `495.305ms` for client artifact, and `31.957ms` for
finalize. Raw BLOB/compression is therefore deferred as a persistence p95
experiment, not an HSS tail blocker.

### E7: Parallelize curve persistence (seed for the Phase 4 follow-up)

Non-HSS, recorded here so it is not lost: passkey traces show
`ecdsaRegistrationPersistenceMs` (`~560-607ms`) running sequentially after
Ed25519 persistence in `commitRegistrationPersistencePlan`. The two curve
domains are logically separate, but they still share local persistence and
worker resources.

- [x] Measure the actual dependency, then attempt concurrent Ed25519/ECDSA
      persistence commits. Result: rejected and reverted. The clean passkey
      benchmark worsened from `2367ms` to `2496ms`; `ecdsaRegistrationPersistenceMs`
      grew from `551ms` to `855ms`, and
      `thresholdEd25519SigningSessionHydrationMs` grew from `289ms` to `538ms`.
      The overlap created IndexedDB/worker contention rather than a net
      critical-path win.
- Evidence traces:
  `1783277453598-passkey.registration-opal-raven-kku3ac-intended-lifecycle-trace.json`
  baseline,
  `1783304604290-passkey.registration-verdant-atlas-sa3dny-intended-lifecycle-trace.json`
  parallel-persistence trial,
  `1783304971072-passkey.registration-verdant-raven-mrbss8-intended-lifecycle-trace.json`
  post-rollback check. The post-rollback branch buckets returned near
  baseline (`ecdsaRegistrationPersistenceMs: 570ms`,
  `thresholdEd25519SigningSessionHydrationMs: 303ms`), while the total stayed
  noisy at `2566ms`.
- Follow-up direction: profile the ECDSA persistence branch itself. The
  experiment shows that local persistence is still a real tail bucket, but
  curve-level concurrency is the wrong granularity.
- Rule for future overlap experiments: verify resource independence before
  scheduling independence. A candidate pair must have disjoint data dependencies
  and disjoint bottleneck resources: worker thread, IndexedDB readwrite store
  set, and relayer connection pattern. The rejected E7 trial passed the data
  check, then failed the resource check because both legs funnel through the
  same signer-worker and `seams_wallet` IndexedDB transaction lane.

### E8: Split ECDSA registration persistence (Phase 4 seed)

The E7 result makes the next ECDSA optimization subtraction, not scheduling.
`ecdsaRegistrationPersistenceMs` remains a top passkey bucket at roughly
`~550-570ms`, and hiding it behind Ed25519 persistence created contention.

- [x] Add first-level ECDSA registration persistence sub-buckets:
      client-finalize, client material store, server bootstrap,
      passkey bootstrap store, role-local ready-record persistence, passkey
      warm-session hydration, Email OTP session commit, local record
      persistence, and target count.
- [x] Record the first split. Evidence:
  - `1783308220935-passkey.registration-golden-summit-duqmcx-intended-lifecycle-trace.json`
    shows `ecdsaRegistrationPersistenceMs: 565ms`,
    `ecdsaRegistrationSessionFinalizeMs: 562ms`,
    `ecdsaRegistrationWarmSessionHydrationMs: 553ms`, and
    `ecdsaRegistrationTargetCount: 2`.
  - All other new ECDSA sub-buckets were `0-2ms`, so the top-level bucket is
    passkey warm-session hydration rather than bootstrap, local records, or
    material storage.
- [x] Trial a narrower passkey warm-session hydration overlap after ordered
      record persistence. Result: rejected and reverted. Evidence:
      `1783308462723-passkey.registration-opal-lantern-ydkbsv-intended-lifecycle-trace.json`
      moved `ecdsaRegistrationPersistenceMs` only from `565ms` to `553ms`,
      while total registration stayed flat (`2543ms` to `2546ms`). The
      post-revert trace
      `1783308759858-passkey.registration-indigo-voyage-jqv3u4-intended-lifecycle-trace.json`
      returned the ECDSA shape to `ecdsaRegistrationPersistenceMs: 563ms`,
      `ecdsaRegistrationSessionFinalizeMs: 561ms`, and
      `ecdsaRegistrationWarmSessionHydrationMs: 553ms`. Its higher total
      (`3170ms`) came from an unrelated `authProofMs: 910ms` spike.
- [x] Split `passkey_warm_session_hydration` inside the warm-session service:
      worker readiness, worker material put, total sealed-record persistence,
      seal transport resolution, existing-record read, policy read,
      server-seal apply, sealed-record register, and verify read.
- [x] Record whether Tempo+Arc currently pays one warm-session hydration path
      per ECDSA target or one batched operation for the wallet-family key
      material. Evidence:
      `1783309379793-passkey.registration-jade-meadow-v6q4dp-intended-lifecycle-trace.json`.
  - `ecdsaRegistrationTargetCount: 2`.
  - `ecdsaRegistrationPersistenceMs: 567ms`.
  - `ecdsaRegistrationSessionFinalizeMs: 564ms`.
  - `ecdsaRegistrationWarmSessionHydrationMs: 556ms`.
  - `ecdsaRegistrationWarmSessionSealedRecordPersistMs: 555ms`.
  - `ecdsaRegistrationWarmSessionSealApplyServerSealMs: 551ms`.
  - worker put, local register, existing-record read, policy read, and verify
    read are `0-2ms` aggregate.
    The current path hydrates and applies the server seal per ECDSA target; it
    is not a wallet-family batched operation.
- [x] Split `sealed_record_apply_server_seal` inside the passkey confirm worker:
      Shamir runtime setup, client seal, `/wallet-session/seal/apply-server-seal`
      fetch, server response parse, client unseal, and local policy update.
      Evidence:
      `1783309831703-passkey.registration-indigo-grove-vykqsp-intended-lifecycle-trace.json`.
  - `ecdsaRegistrationWarmSessionSealApplyServerSealMs: 558ms`.
  - `ecdsaRegistrationWarmSessionSealApplyRuntimeSetupMs: 0ms`.
  - `ecdsaRegistrationWarmSessionSealApplyClientSealMs: 10ms`.
  - `ecdsaRegistrationWarmSessionSealApplyServerRouteMs: 20ms`.
  - `ecdsaRegistrationWarmSessionSealApplyClientUnsealMs: 527ms`.
  - `ecdsaRegistrationWarmSessionSealApplyPolicyUpdateMs: 0ms`.
    The network/server route is not the latency source. The Shamir client
    unseal leg dominates the remaining passkey ECDSA registration tail.
- [x] Investigate the Shamir client-unseal hot path: measure payload sizes,
      confirm whether the two Tempo+Arc target unseals duplicate identical
      wallet-family work, and decide between a typed wallet-family sealed
      refresh command or a Shamir runtime optimization.
  - Rejected byte-returning unseal as an optimization. Evidence:
    `1783310165303-passkey.registration-lunar-tempo-6ubzhq-intended-lifecycle-trace.json`.
    Switching passkey seal apply from `removeClientSealWithKeyHandle` to
    `removeClientSealWithKeyHandleToBytes` plus JS base64url encoding moved
    `ecdsaRegistrationWarmSessionSealApplyClientUnsealMs` from `527ms` to
    `535ms` and `ecdsaRegistrationPersistenceMs` from `572ms` to `581ms`.
    The cost is the modular Shamir unseal work, not string serialization.
  - Accepted volatile server-sealed-secret reuse inside the passkey confirm
    worker. Evidence:
    `1783310980151-passkey.registration-silver-zenith-yjhcxp-intended-lifecycle-trace.json`.
    The worker now caches the deterministic server-sealed PRF result under
    `(walletId, credentialIdB64u, signingGrantId, relayerUrl,
signingSessionSealKeyVersion, shamirPrimeB64u, sha256(prfFirstB64u))` after
    the first successful server-seal apply. The cache is volatile worker memory
    only. Each target still performs its own
    `/wallet-session/seal/apply-server-seal` authorization and policy check,
    then reuses the derived sealed secret only when the scoped cache key
    matches. Result:
    `ecdsaRegistrationPersistenceMs: 45ms`,
    `ecdsaRegistrationWarmSessionHydrationMs: 33ms`,
    `ecdsaRegistrationWarmSessionSealedRecordPersistMs: 31ms`,
    `ecdsaRegistrationWarmSessionSealApplyServerSealMs: 27ms`,
    `ecdsaRegistrationWarmSessionSealApplyClientSealMs: 11ms`,
    `ecdsaRegistrationWarmSessionSealApplyServerRouteMs: 16ms`, and
    `ecdsaRegistrationWarmSessionSealApplyClientUnsealMs: 0ms`.
    The ECDSA tail is no longer a top passkey registration bucket.
- [x] Re-evaluate the Email OTP material/enrollment overlap candidate with the
      resource-independence rule first. Result: no implementation change.
      Evidence:
      `1783304572920-email_otp.registration-frost-quartz-gv3avp-intended-lifecycle-trace.json`.
      `emailOtpEnrollmentMaterialMs: 359ms` and
      `ed25519ClientMaterialMs: 378ms` both appear in the measured-work top
      buckets, but `measuredWorkMs: 2842ms` exceeds `totalElapsedMs: 2030ms`
      by `812ms`, and the code already starts
      `emailOtpEnrollmentMaterial` before awaiting Ed25519 client material.
      Later Email OTP Ed25519 and ECDSA preparation paths consume the same
      promise. Additional concurrency would duplicate the existing overlap
      rather than remove a serial dependency.

## Validation

Minimum validation for each implementation slice:

```text
pnpm -C packages/sdk-server-ts exec tsc -p tsconfig.build.json --noEmit
pnpm -C packages/sdk-web exec tsc -p tsconfig.build.json --noEmit
pnpm build:sdk
pnpm benchmark:ed25519-hss:tail -- --warmup 1 --iterations 3
cargo hss-fv all
node tests/scripts/check-cloudflare-d1-runtime-boundaries.mjs
node tests/scripts/check-intended-behaviour-contract-boundaries.mjs
pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/cloudflareD1RouterApiRegistrationCeremony.unit.test.ts --reporter=line
```

Latest focused validation:

- `cargo test --manifest-path crates/ed25519-hss/Cargo.toml server_driver_state_rejects_corrupt_advance_runtime_checkpoint`
  passed.
- `cargo hss-fv all` passed after the durable server advance checkpoint
  corruption coverage was added.
- `cargo hss-fv all` passed again after the rejected in-place-state probe was
  removed from the retained code.
- `pnpm benchmark:ed25519-hss:tail -- --warmup 1 --iterations 3` passed and
  produced
  `benchmarks/ed25519-hss-tail/out/2026-07-05T18-36-29-328Z/summary.md`.
- `pnpm benchmark:ed25519-hss:tail -- --warmup 1 --iterations 3 --drift-iterations 24`
  passed after the advanced-state storage-encoding probe was added and produced
  `benchmarks/ed25519-hss-tail/out/2026-07-06T04-24-01-848Z/summary.md`.
- `node ./benchmarks/ed25519-hss-tail/src/runner.mjs --warmup 1 --iterations 3 --client-session-source worker_handle`
  passed and produced
  `benchmarks/ed25519-hss-tail/out/2026-07-05T18-37-50-170Z/summary.md`.
- `cargo hss-fv all` passed after the client output-projector profile was
  threaded through the HSS crate and WASM benchmark.
- `node --check benchmarks/ed25519-hss-tail/src/runner.mjs` passed.
- `node ./benchmarks/ed25519-hss-tail/src/runner.mjs --warmup 1 --iterations 3 --client-session-source worker_handle`
  produced
  `benchmarks/ed25519-hss-tail/out/2026-07-05T17-53-07-457Z/summary.md`.
- `pnpm build:sdk` passed against the regenerated WASM artifacts.
- `cargo test --manifest-path crates/ed25519-hss/Cargo.toml hidden_output_projection_matches_reference_output_shares`
  passed after the rejected server-only output projector shortcut was removed.
- `cargo hss-fv all` passed on the final retained tree after the rejected
  server-only output projector shortcut was removed.
- Current completion validation batch passed:
  - `cargo test --manifest-path crates/ed25519-hss/Cargo.toml server_driver_state_rejects_corrupt_advance_runtime_checkpoint`
  - `pnpm -C packages/sdk-server-ts exec tsc -p tsconfig.build.json --noEmit`
  - `pnpm -C packages/sdk-web exec tsc -p tsconfig.build.json --noEmit`
  - `node tests/scripts/check-cloudflare-d1-runtime-boundaries.mjs`
  - `node tests/scripts/check-intended-behaviour-contract-boundaries.mjs`
  - `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/cloudflareD1RouterApiRegistrationCeremony.unit.test.ts --reporter=line`
  - `pnpm build:sdk`

Final validation:

```text
SEAMS_INTENDED_PERSIST_TRACE=1 SEAMS_INTENDED_SKIP_BUILD=1 pnpm -C tests exec playwright test -c playwright.intended.benchmark.ci.config.ts e2e/intended-behaviours/passkey.registration.benchmark.test.ts e2e/intended-behaviours/email-otp.registration.benchmark.test.ts --reporter=line
```

Latest final validation:

- `SEAMS_INTENDED_PERSIST_TRACE=1 SEAMS_INTENDED_SKIP_BUILD=1 pnpm -C tests exec playwright test -c playwright.intended.benchmark.ci.config.ts e2e/intended-behaviours/passkey.registration.benchmark.test.ts e2e/intended-behaviours/email-otp.registration.benchmark.test.ts --reporter=line`
  passed.
- Email OTP trace:
  `test-results/intended-lifecycle-traces/1783277449166-email_otp.registration-cedar-voyage-nqn68j-intended-lifecycle-trace.json`.
  - Total: `2,083ms`.
  - Violations: `[]`.
  - `walletRegisterHssAdvanceStateMs`: `514ms`.
  - `ed25519EvaluationArtifactMs`: `408ms`.
  - route-level `registerHssAdvanceStateTotalMs`: `504ms`.
  - route-level `registrationHssAdvanceStateWasmMs`: `500ms`.
  - route-level `registrationHssAdvanceStateMessageScheduleRoundsMs`: `183ms`.
  - route-level `registrationHssAdvanceStateRoundCoreRoundsMs`: `132ms`.
  - route-level `registrationHssAdvanceStateOutputProjectionMs`: `81ms`.
  - route-level `registrationHssFinalizeMs`: `41ms`.
  - route-level `registerFinalizeTotalMs`: `53ms`.
- Passkey trace:
  `test-results/intended-lifecycle-traces/1783277453598-passkey.registration-opal-raven-kku3ac-intended-lifecycle-trace.json`.
  - Total: `2,367ms`.
  - Violations: `[]`.
  - `walletRegisterHssAdvanceStateMs`: `493ms`.
  - `ed25519EvaluationArtifactMs`: `406ms`.
  - route-level `registerHssAdvanceStateTotalMs`: `486ms`.
  - route-level `registrationHssAdvanceStateWasmMs`: `481ms`.
  - route-level `registrationHssAdvanceStateMessageScheduleRoundsMs`: `178ms`.
  - route-level `registrationHssAdvanceStateRoundCoreRoundsMs`: `130ms`.
  - route-level `registrationHssAdvanceStateOutputProjectionMs`: `76ms`.
  - route-level `registrationHssFinalizeMs`: `29ms`.
  - route-level `registerFinalizeTotalMs`: `35ms`.

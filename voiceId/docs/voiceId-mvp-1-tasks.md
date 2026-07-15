# VoiceID MVP 1 Tasks

Status: E0 contract, continuous-audio pipeline, and analysis-claim lifecycle
implemented. Active work is limited to VoiceID accuracy, latency, resource use,
and runtime resilience.

Specification: [VoiceID MVP 1](voiceId-mvp-1.md).

Long-term security target:
[VoiceID Signing Security Profile](voiceId-signing-security-profile.md).

Wallet signing, browser containment, and authenticator hardware are deferred
during this plan. The active tasks improve the standalone VoiceID engine.

## Completed: Domain Cutover

- [x] Add branded enrollment, verification, challenge, model, threshold,
      template, prompt-set, timestamp, and encrypted-template values.
- [x] Represent enrollment as `pending_continuous_recording`,
      `analyzing_continuous_recording`, `failed`, `enrolled`, or `disabled`.
- [x] Represent verification as `issued`, `analyzing`,
      `evidence_observed`, `rejected`, `uncertain`, `expired`, or
      `analysis_failed`.
- [x] Require branch-specific fields and reject invalid combinations with
      `never` fields.
- [x] Add `VoiceIdExperimentalBrowserEvidence`,
      `VoiceIdStepUpOnlyEvidence`, and branded `VoiceIdAttestedEvidence` types.
- [x] Make every evidence tier structurally signing-ineligible.
- [x] Add type fixtures proving E0 and attested evidence cannot enter a signing
      boundary.
- [x] Remove authorization, signing-policy, caller transaction, and SDK Router
      adapter code from the VoiceID implementation.
- [x] Add exhaustive result and lifecycle switches.

## Completed: Recording Contract

- [x] Replace repeated enrollment uploads with one continuous recording.
- [x] Issue four enrollment prompt segments in one server-owned sequence.
- [x] Publish 12-second minimum, 18-second target, and 30-second maximum gates.
- [x] Commit the enrollment template only after phrase, embedding quality, and
      template construction succeed.
- [x] Persist one failed enrollment state after a terminal enrollment failure.
- [x] Use one verification recording per fresh challenge.
- [x] Generate challenge nonce and expected phrase on the server.
- [x] Remove expected phrase, transcript, score, policy, and signing context from
      client recording inputs.
- [x] Consume completed and expired verifications in service lifecycle state.

## Completed: Evidence API

- [x] Publish only the `/voice-id/evidence/*` route family.
- [x] Publish `signingEligible: false` in health and capability metadata.
- [x] Return E0 evidence only after phrase, speaker, and quality checks accept.
- [x] Describe browser freshness, PAD, capture profile, and microphone integrity
      limits in the evidence object.
- [x] Return rejected and uncertain branches with machine-readable reasons.
- [x] Remove the normal SDK module registration path.
- [x] Update the demo to one enrollment recording and one verification
      recording.
- [x] Keep wallet, Router admission, and SigningWorker imports outside active
      VoiceID sources.

## Completed: Boundary And Persistence Hardening

- [x] Parse JSON, multipart fields, metadata, ids, Python responses, and D1 rows
      once at their boundaries.
- [x] Bound audio request size, decoded duration, and decoder execution time.
- [x] Return explicit public DTOs, keep encrypted templates server-side, and
      parse browser responses into precise unions at the fetch boundary.
- [x] Persist full typed lifecycle records in D1 v4 tables.
- [x] Verify D1 index fields against parsed record payloads.
- [x] Encrypt durable templates with AES-GCM-256 and metadata-bound AAD.
- [x] Keep raw audio outside lifecycle storage and ordinary audit events.
- [x] Require explicit verifier and transcript-provider configuration.
- [x] Keep fake providers explicitly selected by local development launchers.
- [x] Add an architecture guard for the evidence/signing separation.

## Gate A: Continuous-Audio Model Pipeline

- [x] Decode audio before accepting duration, sample-rate, channel, and codec
      claims.
- [x] Run VAD and retain only non-overlapping accepted speech windows in memory.
- [x] Require minimum usable speech, phonetic coverage, and prompt order from
      decoded content.
- [x] Reject multi-speaker, duplicated, clipped, low-SNR, low-speech, and
      incoherent enrollment windows.
- [x] Build a normalized, versioned, quality-weighted template from diverse
      windows.
- [x] Zero or release decoded audio, intermediate windows, and embeddings after
      template commit or failure.
- [x] Add interruption and decoder-failure branches to the enrollment union.
- [x] Add tests proving a failed session leaves no partial template material.

Exit gate: a single user ceremony yields multiple internal evidence windows and
one atomic template decision.

## Gate B: Atomic Lifecycle Transitions

- [x] Add compare-and-swap terminal commits for pending enrollment recordings.
- [x] Add compare-and-swap terminal commits for issued verification challenges.
- [x] Make D1 transitions conditional on the expected lifecycle state.
- [x] Return `invalid_state` to every concurrent loser.
- [x] Claim lifecycle state before expensive verifier computation so concurrent
      losers do no duplicate work.
- [x] Define recovery for a worker crash after claim and before terminal commit.
- [x] Add concurrent verification and duplicate enrollment transition tests.
- [ ] Add timeout, worker-crash, and response-loss tests.

Exit gate: one enrollment id and one verification id each produce at most one
terminal computation across multiple workers.

## Gate C: Reproducible Performance And Accuracy Baseline

- [ ] Define one versioned fixture manifest for enrollment, genuine
      verification, zero-effort impostors, phrase errors, and presentation
      attacks.
- [ ] Collect consented, subject-disjoint recordings across days, microphones,
      rooms, distances, codecs, sample rates, accents, and noise conditions.
- [ ] Freeze subject-disjoint development, calibration, and evaluation splits.
- [ ] Add one benchmark command that emits machine-readable results and a human
      report from the same run.
- [ ] Measure speaker FAR, FRR, EER, uncertainty, and retry rate with confidence
      intervals.
- [ ] Measure phrase substitution, omission, insertion, reordering, and
      ambiguity outcomes.
- [ ] Measure cold and warm p50, p95, and p99 latency for decode, VAD, phrase,
      speaker, PAD, template aggregation, and the complete pipeline.
- [ ] Record model-load time, peak resident memory, CPU/GPU utilization, queue
      time, and failure rate.
- [ ] Freeze explicit latency and resource budgets for server GPU, embedded
      NVIDIA, embedded CPU, and iOS research profiles.

Exit gate: every optimization and model change can be compared against one
reproducible accuracy, latency, and resource baseline.

## Gate D: Single-Decode Shared Inference Runtime

- [ ] Decode and resample each capture exactly once into bounded mono 16 kHz
      PCM inside the verifier boundary.
- [ ] Reuse the same authoritative PCM, VAD result, and accepted speech windows
      for phrase, speaker, PAD, and template processing.
- [ ] Preserve independent typed phrase, speaker, quality, and PAD decisions.
- [ ] Run phrase, speaker, and PAD inference concurrently after common quality
      gates accept.
- [ ] Replace request-scoped model startup with persistent workers that load
      each model once and report readiness.
- [ ] Add bounded queues, backpressure, per-stage deadlines, cancellation, and
      deterministic overload results.
- [ ] Zero shared PCM, feature, window, and embedding buffers after the terminal
      decision.
- [ ] Prove shared preprocessing produces stable scores across repeated runs.

Exit gate: one bounded preprocessing pass feeds warm concurrent inference with
no duplicate decode, resample, VAD, or model initialization.

## Gate E: Speaker And Phrase Model Selection

- [ ] Evaluate the current ECAPA model, NVIDIA TitaNet, and one compact x-vector
      baseline on the frozen corpus.
- [ ] Compare accuracy, cross-session drift, cross-device stability, warm
      latency, memory, and quantization loss.
- [ ] Evaluate current Whisper phrase matching against Parakeet or Nemotron
      Speech and a constrained expected-phrase scorer.
- [ ] Include CTC forced alignment or phoneme-level scoring in the constrained
      phrase experiment.
- [ ] Require phrase scoring to detect substitutions, omissions, insertions,
      reordering, and extra speech.
- [ ] Select the smallest model that meets each approved platform profile's
      frozen accuracy and latency budgets.
- [ ] Version model weights, preprocessing, adapter, threshold, phrase grammar,
      and calibration as one immutable manifest.
- [ ] Return `uncertain` for unsupported capture profiles and scores outside the
      calibrated region.

Exit gate: selected speaker and phrase models beat the baseline within frozen
accuracy and runtime budgets on held-out subjects.

## Gate F: Presentation-Attack Detection

- [x] Add a strict subject-disjoint PAD manifest parser and fail-closed report
      generator with confidence intervals and attack/capture-profile grouping.
- [ ] Integrate an AASIST-style PAD baseline behind a typed verifier boundary.
- [ ] Feed PAD from the shared canonical PCM and speech windows.
- [ ] Build separate replay, synthesis, voice conversion, splice, relay, and
      digital-injection evaluation sets.
- [ ] Include attacks generated by current voice-cloning systems and attacks
      tuned against the selected speaker model.
- [ ] Report APCER, BPCER, uncertainty, and latency by attack class and capture
      profile.
- [ ] Calibrate accepted, uncertain, and rejected regions without folding PAD
      into the speaker score.
- [ ] Run PAD concurrently with phrase and speaker inference.

Exit gate: PAD meets its frozen per-attack accuracy and latency budgets on the
held-out attack set and fails closed outside measured profiles.

## Gate G: Enrollment And Template Robustness

- [ ] Benchmark the minimum recording duration, usable speech, window count,
      and phonetic coverage required for stable templates.
- [ ] Compare quality-weighted averaging with medoid and robust outlier-resistant
      aggregation.
- [ ] Measure same-speaker template stability across days, microphones, rooms,
      and vocal variation.
- [ ] Reject enrollment when internal windows lack sufficient diversity or
      produce unstable leave-one-window-out scores.
- [ ] Tune one quality-only retry without reintroducing repeated enrollment
      uploads.
- [ ] Evaluate quarantined high-confidence template adaptation for drift and
      poisoning resistance; keep automatic adaptation disabled until it passes.
- [ ] Version the aggregation rule and template format with the selected speaker
      model manifest.

Exit gate: one continuous enrollment produces a compact template that meets
cross-session stability and impostor-separation budgets.

## Gate H: Optimized Builds And Runtime Resilience

- [ ] Export and benchmark ONNX Runtime, TensorRT, and Core ML builds only for
      target profiles they materially improve.
- [ ] Measure FP32, FP16, and quantized variants against the frozen score and
      decision regression suite.
- [ ] Add timeout, forced-worker-crash, response-loss, model-load-failure, and
      automatic-worker-replacement tests.
- [ ] Fuzz malformed media and exercise decoder limits, truncated input,
      unsupported codecs, and oversized captures.
- [ ] Load test bounded concurrency, queue saturation, cancellation, and retry
      behavior.
- [ ] Run long soak tests that detect memory, file-descriptor, process, and GPU
      resource growth.
- [ ] Reject a release when accuracy, p95/p99 latency, memory, or failure-rate
      budgets regress.

Exit gate: each supported runtime profile passes the same frozen decisions,
fault campaigns, soak tests, and performance budgets.

## Deferred Platform Work

The following work resumes after Gate H:

- cross-origin browser iframe containment;
- embedded secure microphone and protected authenticator prototypes;
- WebAuthn and CTAP2 assertion integration;
- Router, wallet, and SigningWorker integration;
- audio-visual PAD.

These projects retain their existing security specifications. They do not
occupy the active VoiceID engine queue.

## Current Validation

Run the cheapest complete VoiceID checks:

```sh
pnpm -C voiceId type-check
pnpm -C voiceId test
pnpm -C voiceId signing-architecture:guard
pnpm -C voiceId verifier:test
pnpm -C voiceId pad:test
```

Deployment and model checks remain separate:

```sh
pnpm -C voiceId smoke:python-http
pnpm -C voiceId worker:guard
pnpm -C voiceId container:guard
pnpm -C voiceId fixtures:validate
pnpm -C voiceId fixtures:evaluate:ecapa
```

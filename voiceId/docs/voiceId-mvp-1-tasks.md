# VoiceID MVP 1 Tasks

Status: the engine foundation and one Dia2 1B CUDA qualification are
implemented. Active work is limited to producing the complete reproducible
corpus, calibrating the current model stack, confirming enrollment stability,
and rerunning the Mac release budget.

Specification: [VoiceID MVP 1](voiceId-mvp-1.md).

Long-term security target:
[VoiceID Signing Security Profile](voiceId-signing-security-profile.md).

Wallet signing remains out of scope. This plan produces E0 research evidence
and a measured VoiceID engine. It does not claim authenticator-grade user
verification.

## Fixed MVP Profile

- Runtime: Apple Silicon macOS.
- Language: English.
- Models: Moonshine Tiny Streaming, SpeechBrain ECAPA, and AASIST.
- Enrollment: one continuous guided recording.
- Verification: one fresh server-owned challenge and one recording.
- Corpus: synthetic identities plus owner-consented recordings.
- Human population FAR, FRR, and EER remain unavailable until a real
  multi-subject corpus exists.
- Warm post-utterance p95 target: 500 ms; hard ceiling: 1 second.
- First-attempt completion target: at least 95%.
- Retry policy: one quality-driven retry, then another authentication method.
- Runtime ceiling: 1.5 GB of model assets and 3 GB peak resident memory.

## Completed Foundation

- [x] Model enrollment, verification, evidence, and persistence as precise
      lifecycle unions.
- [x] Keep every VoiceID evidence tier structurally ineligible for wallet
      signing.
- [x] Use one continuous enrollment recording and one verification recording.
- [x] Generate the challenge and expected phrase on the server.
- [x] Commit lifecycle results atomically and reject concurrent losers.
- [x] Bound media size, decoded duration, decoder time, and verifier admission.
- [x] Decode and resample once, compute VAD once, and share accepted PCM across
      phrase, intent, speaker, quality, and PAD analysis.
- [x] Run Moonshine, ECAPA, and AASIST through one persistent verifier sidecar.
- [x] Cache closed-set intent state and isolate each Moonshine transcription.
- [x] Zero exposed request-owned PCM, speech windows, embeddings, and model
      tensors after terminal decisions.
- [x] Build one versioned enrollment template from diverse internal windows and
      reject unstable enrollment.
- [x] Add immutable model, corpus, provenance, and calibration manifests.
- [x] Add resumable ElevenLabs and Dia2 corpus generators plus an immutable
      consented-capture importer.
- [x] Add deterministic replay, codec, noise, and room-response fixture
      augmentation with source-to-derived SHA-256 bindings.
- [x] Add a fail-closed calibration freeze that binds intent, speaker, PAD,
      capture-profile, and retry decisions to the corpus, model, and budget
      report hashes.
- [x] Add a cross-day enrollment-stability report for the three-session
      ceremony, including leave-one-out stability, cross-session similarity,
      speech gates, and shortest reliable duration.
- [x] Add candidate stability, malformed-media, overload, recovery, and release
      budget checks.
- [x] Measure a 1,042 ms Moonshine sample at 254.085 ms p50, 264.268 ms p95,
      and 268.937 ms p99 on Apple Silicon.

## Phase 1: Produce The Minimum Corpus

- [ ] Make both generators operational:
      - [ ] demonstrate one ElevenLabs designed-voice generation with a
            working credential;
      - [x] complete one Dia2 1B job on a temporary CUDA worker and record its
            immutable output/provenance report.
- [ ] Produce and freeze development, calibration, and evaluation partitions
      containing stable generated identities and three owner-consented sessions
      from different days. Include:
      - genuine owner enrollment and verification;
      - approve, reject, cancel, repeat, and unrelated intent;
      - missing, substituted, reordered, and extra challenge words;
      - zero-effort synthetic impostors;
      - owner-conditioned clone attacks;
      - direct digital synthesis and acoustic replay;
      - codec, noise, and room-response transformations;
      - immutable audio, model, consent, and generator bindings.

Exit condition: one frozen corpus passes readiness checks. Reports distinguish
synthetic, owner-conditioned, and bona-fide-owner cohorts.

## Phase 2: Calibrate The Current Stack

- [ ] Run the frozen corpus through Moonshine Tiny, ECAPA, and AASIST and
      measure:
      - intent and challenge error by case;
      - owner genuine acceptance, uncertainty, and retry rate;
      - synthetic-impostor and owner-clone acceptance;
      - APCER and BPCER for each included attack and capture profile;
      - cold initialization and warm p50, p95, and p99 latency;
      - peak resident memory, CPU use, queue time, and failure rate.
- [ ] Freeze intent, speaker, PAD, capture-profile, and retry decisions in one
      calibration record; return `uncertain` outside that record and produce
      one passing Mac release-budget report.

Exit condition: the pinned stack meets the fixed accuracy, latency, memory,
retry, uncertainty, and attack budgets on held-out data.

## Phase 3: Confirm Enrollment UX

- [ ] Measure template stability across the three owner sessions and find the
      shortest reliable enrollment within the current 12-second minimum,
      18-second target, and 30-second maximum.
- [ ] Freeze usable-speech, window-count, phonetic-coverage, and one-retry
      requirements without weakening speaker, challenge, or PAD decisions.

Exit condition: one guided recording produces a stable template and a clear
retry result.

## Phase 4: Qualify Runtime Resilience

- [x] Run one fault campaign covering model-load failure, forced worker
      termination, response loss, request timeout, queue saturation, and
      recovery.
- [x] Run one long soak covering memory, file descriptors, worker count, and
      latency drift.
- [ ] Rerun the release-budget checker after Phases 1 and 2 freeze the corpus
      and calibration budgets.

The fault campaign and soak runner are available as
`pnpm -C voiceId runtime:resilience`. The final release-budget rerun remains
pending the frozen corpus and calibration record from Phases 1 and 2.

Exit condition: the Mac profile stays within frozen budgets and fails closed
under overload and runtime faults.

## MVP Completion

MVP 1 is complete when all four active phases pass with the pinned model,
corpus, calibration, capture profile, and retry policy. The result remains E0
research evidence and cannot authorize wallet signing.

## Deferred Work

The following items are removed from the active queue:

- human population FAR, FRR, and EER;
- Moonshine Small promotion and comparisons with Whisper, Parakeet, Nemotron,
  TitaNet, x-vector, or other alternative models;
- Dia2 2B and broader generator catalogues;
- dedicated voice-conversion, splice, and relay campaigns;
- iPhone/Core ML, Linux, embedded NVIDIA, and robot inference profiles;
- ONNX, TensorRT, FP16, and quantized optimization comparisons;
- strict erasure guarantees for opaque native allocator buffers;
- automatic enrollment-template adaptation;
- Japanese support;
- audio-visual PAD;
- browser iframe containment, secure microphone hardware, WebAuthn, CTAP2,
  Router, wallet, and SigningWorker integration.

A deferred item returns only when an active MVP gate fails or the MVP is
complete.

## Inputs Needed From The Owner

- a working ElevenLabs API credential;
- three short recording sessions across different days;
- approval to repin the Dia2 source if the archived revision cannot be
  recovered, followed by a new one-job CUDA qualification;
- access to a temporary CUDA worker or cloud project for the remaining Dia2
  corpus jobs; the one-job CUDA qualification is complete for the old pin.

Current external gate status (2026-07-31): no working ElevenLabs credential is
available; the previously supplied credential in ignored root `.env.local` returns
HTTP 401. One Dia2 1B generation completed on a
temporary Spot L4 worker; its evidence is recorded in
`verifier-spike/reports/dia2-one-job-2026-07-31.md`. The worker, temporary
bucket, and one-GPU quota override were removed after verification. A later
full-batch attempt did not produce a corpus because available CUDA capacity and
runtime setup were unavailable; no full synthetic corpus is claimed. The
pinned Dia2 source revision `8687268f4ed3ed20704638fd353b51491de3b476` is no
longer fetchable from the upstream repository, so a full rerun must first
recover that archive or explicitly repin and repeat the one-job qualification.
The ElevenLabs generation and owner recordings remain outstanding.

## Validation

Install the benchmark-spike package once before running the Python checks:

```sh
python3 -m pip install -e voiceId/verifier-spike
```

```sh
pnpm -C voiceId type-check
pnpm -C voiceId test
pnpm -C voiceId signing-architecture:guard
pnpm -C voiceId verifier:test
pnpm -C voiceId benchmark:test
pnpm -C voiceId runtime:resilience --iterations 1000 --output /tmp/voiceid-runtime-resilience.json
pnpm -C voiceId smoke:python-http
```

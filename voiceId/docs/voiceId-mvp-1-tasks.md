# VoiceID MVP 1 Tasks

Status: E0 contract, continuous-audio pipeline, and analysis-claim lifecycle
implemented. Active work is limited to VoiceID accuracy, latency, resource use,
and runtime resilience.

Specification: [VoiceID MVP 1](voiceId-mvp-1.md).

Long-term security target:
[VoiceID Signing Security Profile](voiceId-signing-security-profile.md).

Wallet signing, browser containment, and authenticator hardware are deferred
during this plan. The active tasks improve the standalone VoiceID engine.

## Approved Solo MVP Research Profile

- The MVP corpus starts with stable generated identities from Dia2 and
  ElevenLabs. Human population claims remain unavailable until a real
  multi-subject corpus replaces or supplements these fixtures.
- Synthetic fixtures may measure pipeline correctness, phrase and intent
  accuracy, synthetic-impostor rejection, presentation-attack response,
  latency, memory, resilience, and retry behavior. Reports MUST label these
  cohorts as synthetic and MUST NOT publish their results as human speaker FAR,
  FRR, or EER.
- Audio-conditioned synthesis may use owner-consented reference recordings.
  The manifest records the consent handle and separates the conditioning media
  from generated output.
- D1 stores relational manifest, provenance, consent, lifecycle, deletion, and
  report metadata. Encrypted audio objects live in a private R2 bucket or an
  equivalent encrypted object store. Raw audio does not live in D1 rows.
- Research-corpus retention is project-lifetime with no automatic expiry.
  Explicit deletion, key revocation, and deletion receipts remain required.
  Production diagnostic-media TTL rules remain unchanged.
- The first runtime profile is Apple Silicon macOS. iPhone 16 is the first
  capture profile and the second on-device inference target.
- Dia2 generation uses an ephemeral rented CUDA worker. The cloud account,
  checkpoint cache, and generator runtime remain outside production VoiceID.
  Generic synthetic generation may use a cost-optimized provider; conditioned
  owner audio requires private storage, restricted access, and worker teardown.
- Each Dia2 corpus-generation campaign has a $50 compute ceiling, automatic
  shutdown after completion or idle timeout, verified R2 upload before
  teardown, and no retained VM or checkpoint volume.
- The first calibration boundary is English. Japanese follows after the
  English model and challenge policy are frozen.

Initial performance budgets:

- warm post-utterance decision p95 target: 500 ms; hard MVP ceiling: 1 second;
- complete spoken ceremony: report separately because capture duration
  dominates inference latency;
- bona-fide first-attempt completion target: at least 95%; quality-driven retry
  target: at most 5%; allow one retry before another authentication method;
- Mac research runtime: at most 1.5 GB of production model assets and 3 GB peak
  resident memory, excluding offline fixture generators;
- iPhone downloadable model pack: at most 350 MB with at most 750 MB peak
  resident memory.

Download approval inventory, reviewed 2026-07-22:

| Artifact | Published download | MVP use |
| --- | ---: | --- |
| Moonshine Tiny Streaming F32 | 178 MB | First phrase and intent candidate |
| Moonshine Small Streaming F32 | 562 MB | Accuracy comparison on Mac |
| SpeechBrain ECAPA bundle | 89.1 MB | Current speaker baseline |
| Dia2 1B | 4.31 GB | First offline synthetic generator on CUDA |
| Dia2 2B | 7.68 GB | Optional attack-generator comparison |
| ElevenLabs | Remote API | Immediately usable generated and cloned voices |

Dependency caches and runtime libraries add to these checkpoint sizes. The
listed artifacts are approved for download when their implementation phase
begins. Any newly introduced artifact above 1 GB requires size disclosure and
approval before transfer.

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
- [x] Add timeout, worker-crash, and response-loss tests.

Exit gate: one enrollment id and one verification id each produce at most one
terminal computation across multiple workers.

## Gate C: Reproducible Performance And Accuracy Baseline

- [x] Define one versioned fixture manifest for enrollment, genuine
      verification, zero-effort impostors, phrase errors, and presentation
      attacks.
- [x] Require immutable audio hashes, consent references, complete capture
      profiles, and subject-disjoint development, calibration, and evaluation
      partitions at the benchmark-manifest boundary.
- [x] Add one dependency-free inventory command that emits machine-readable
      JSON and a human report from the same validated manifest run and fails
      readiness when required cases or attack classes are absent.
- [x] Extend the benchmark provenance boundary with exact
      `consented_human_capture` and `synthetic_generation` branches. Require
      generator, model, voice identity, seed, license, request hash, and
      optional conditioning-consent metadata for synthetic entries.
- [ ] Generate the solo MVP corpus with subject-disjoint stable synthetic
      identities, challenge errors, generic attacks, and owner-conditioned
      cloning attacks split across Dia2 and ElevenLabs families.
- [x] Make every benchmark report distinguish synthetic-identity,
      owner-conditioned, and bona-fide-human cohorts and suppress human
      population FAR, FRR, and EER when the required human cohort is absent.
- [x] Download and checksum the approved Moonshine Tiny/Small F32 and native
      streaming assets, the closed-set intent model, and ECAPA bundle in the
      immutable local model manifest.
- [ ] Collect consented, subject-disjoint recordings across days, microphones,
      rooms, distances, codecs, sample rates, accents, and noise conditions.
- [ ] Freeze subject-disjoint development, calibration, and evaluation splits.
- [ ] Extend the inventory command to run the selected model adapters and emit
      machine-readable measurement results and a human report from the same
      run.
- [ ] Measure speaker FAR, FRR, EER, uncertainty, and retry rate with confidence
      intervals.
- [ ] Measure phrase substitution, omission, insertion, reordering, and
      ambiguity outcomes.
- [ ] Measure semantic approve, reject, cancel, repeat, and unrelated-intent
      outcomes independently from unpredictable challenge-token coverage.
- [ ] Measure cold and warm p50, p95, and p99 latency for decode, VAD, phrase,
      speaker, PAD, template aggregation, and the complete pipeline.
- [ ] Record model-load time, peak resident memory, CPU/GPU utilization, queue
      time, and failure rate.
- [ ] Freeze explicit latency and resource budgets for server GPU, embedded
      NVIDIA, embedded CPU, and iOS research profiles.

Exit gate: every optimization and model change can be compared against one
reproducible accuracy, latency, and resource baseline.

## Gate D: Single-Decode Shared Inference Runtime

- [x] Decode and resample each capture exactly once into bounded mono 16 kHz
      PCM inside the verifier boundary.
- [x] Compute canonical VAD once and reuse its exact activity and speech windows
      for audio quality and enrollment-template construction.
- [x] Reuse one verifier-owned canonical PCM decode for verification phrase,
      intent, and speaker analysis through `analyze-verification`.
- [ ] Feed the same accepted VAD windows into speaker and PAD models and extend
      the shared decode to enrollment template processing.
- [x] Preserve independent typed phrase, intent, speaker, quality, and PAD
      decisions.
- [ ] Run phrase, intent, speaker, and PAD inference concurrently after common
      quality gates accept.
- [x] Replace request-scoped model startup with a persistent HTTP sidecar that
      loads each model once and reports exact runtime readiness. Delete the
      request-scoped Python subprocess transport.
- [x] Add bounded sidecar inference admission, configurable queue wait, and a
      deterministic overload response.
- [x] Claim verification before the combined phrase, intent, and speaker
      analysis begins; the split-provider adapter remains only for fake and
      non-Moonshine research modes.
- [x] Add persistent workers for the selected phrase and intent models
      that load each model once and report readiness.
- [ ] Add bounded queues, backpressure, per-stage deadlines, cancellation, and
      deterministic overload results.
- [x] Zero current sidecar PCM, speech-window, template, and speaker-embedding
      buffers after the terminal decision.
- [ ] Extend terminal buffer zeroing to the selected phrase, intent, and PAD
      feature buffers.
- [x] Prove the canonical baseline pipeline produces stable templates, quality
      evidence, and speaker scores across repeated runs.
- [ ] Extend the repeated-run regression to each selected phrase, intent,
      speaker, and PAD model adapter.

Exit gate: one bounded preprocessing pass feeds warm concurrent inference with
no duplicate decode, resample, VAD, or model initialization. The current
verification route satisfies the single-decode boundary for the Python /
Moonshine profile; PAD concurrency, shared VAD windows, and enrollment reuse
remain open.

## Gate E: Moonshine-First Intent, Phrase, And Speaker Model Selection

- [x] Run the first phrase-model spike with
      [Moonshine](https://github.com/moonshine-ai/moonshine) Tiny Streaming and
      Small Streaming.
- [x] Feed Moonshine the verifier-owned canonical mono 16 kHz PCM. Do not use
      `MicTranscriber`. Keep VAD and accepted speech-window ownership in the
      verifier until Moonshine window reuse is implemented.
- [x] Evaluate Moonshine `IntentRecognizer` as a separate semantic-intent
      scorer over a closed set containing approve, reject, cancel, repeat, and
      unrelated outcomes.
- [x] Expose the analysis through the Python sidecar and TypeScript provider.
      The default `expected_phrase` mode keeps enrollment safe; action labels
      become authoritative only after lifecycle records carry a typed intent.
- [x] Run the native Tiny-then-Small streaming smoke benchmark over an
      ephemeral synthetic speech corpus and record load, warm latency, phrase,
      intent, cohort, and human-metric-suppression outcomes.
- [ ] Compare exact normalized phrase matching with a hybrid policy that
      requires unpredictable challenge-token coverage in any order and accepts
      natural-language variations of the requested intent.
- [x] Keep speaker identity, semantic intent, challenge freshness, phrase
      evidence, quality, and PAD as independent typed results. Do not use
      diarization speaker ids as enrolled-speaker identity.
- [ ] Calibrate the intent threshold and the score margin between the winning
      intent and conflicting intents. Return `uncertain` for ambiguous,
      out-of-set, or low-margin utterances.
- [ ] Determine whether the lower-level runtime exposes token probabilities,
      decoder logits, or alignment scores suitable for a calibrated uncertainty
      result. Record unavailable evidence explicitly.
- [ ] Compare Moonshine with the current Cloudflare Whisper baseline on phrase
      substitutions, omissions, insertions, reordering, extra speech, accents,
      noise, and truncated captures.
- [ ] Compare task completion time, retry rate, user corrections, semantic
      intent accuracy, challenge-token error, and combined unauthorized
      acceptance for exact and hybrid policies.
- [ ] Measure model download size, cold initialization, warm p50/p95/p99
      end-of-utterance latency, complete capture latency, peak memory, and CPU
      use first on Apple Silicon macOS, then iPhone 16/Core ML. Linux x86 and
      robot-class CPU follow after the Apple profiles are reproducible.
- [ ] Pin the Moonshine release, model hashes, architecture, quantization, ONNX
      Runtime providers, preprocessing, and transcript normalization in the
      experiment manifest.
- [ ] Restrict the first product-shaped spike to MIT-licensed English models.
      Keep non-English models in research until their commercial license is
      approved.
- [ ] Promote Moonshine only if it meets the frozen phrase accuracy, latency,
      resource, reproducibility, and licensing budgets.
- [ ] Evaluate Parakeet, Nemotron Speech, and a constrained CTC or phoneme
      scorer only after the Moonshine decision, or when Moonshine misses a
      frozen gate.
- [ ] Evaluate the current ECAPA model, NVIDIA TitaNet, and one compact x-vector
      speaker baseline on the frozen corpus.
- [ ] Compare speaker accuracy, cross-session drift, cross-device stability,
      warm latency, memory, and quantization loss.
- [ ] Select the smallest intent, phrase, and speaker models that meet each
      approved platform profile's frozen budgets.
- [ ] Version model weights, preprocessing, adapters, intent and phrase
      thresholds, challenge grammar, and calibration as one immutable manifest.
- [ ] Return `uncertain` for unsupported capture profiles and scores outside the
      calibrated region.

Exit gate: selected intent, phrase, and speaker models beat the baseline within
frozen accuracy and runtime budgets on held-out subjects.

## Gate F: Presentation-Attack Detection

- [x] Add a strict subject-disjoint PAD manifest parser and fail-closed report
      generator with confidence intervals and attack/capture-profile grouping.
- [ ] Integrate an AASIST-style PAD baseline behind a typed verifier boundary.
- [ ] Feed PAD from the shared canonical PCM and speech windows.
- [ ] Build separate replay, synthesis, voice conversion, splice, relay, and
      digital-injection evaluation sets.
- [ ] Use pinned
      [Dia2](https://github.com/nari-labs/dia2) 1B and 2B checkpoints as
      reproducible English prompt-targeted synthesis generators. Produce both
      generic-voice and audio-conditioned attacks from consented reference
      recordings.
- [ ] Use ElevenLabs Voice Design identities for the first immediately
      available synthetic cohort and an owner-authorized clone for a separate
      prompt-targeted attack cohort. Pin API model ids, voice ids, settings,
      request hashes, output hashes, plan/license evidence, and generation
      timestamps.
- [ ] Run Dia2 1B first on a CUDA host. Download Dia2 2B only when the 1B and
      ElevenLabs results leave a measured attack-coverage gap.
- [ ] Generate correct-intent attacks containing fresh challenge tokens in
      varied order, then exercise direct digital injection, acoustic replay,
      codec conversion, noise, and room-response transformations.
- [ ] Record the Dia2 repository revision, weight hashes, architecture,
      reference-audio consent handle and duration, script, challenge tokens,
      seed, sampling configuration, output duration, generation latency, and
      transformation chain in the attack manifest.
- [ ] Include multiple unrelated current text-to-speech and voice-conversion
      systems, attacks tuned against the selected speaker model and PAD, and
      held-out generators unavailable during calibration.
- [ ] Keep Dia2 and every attack-generation tool in the offline fixture
      pipeline and outside production VoiceID packages, verifier images, and
      runtime dependencies.
- [ ] Report APCER, BPCER, uncertainty, and latency by attack class and capture
      profile.
- [ ] Report whether prompt-targeted generation completes within the challenge
      validity window and include that timing in combined unauthorized-
      acceptance analysis.
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
pnpm -C voiceId benchmark:test
```

Deployment and model checks remain separate:

```sh
pnpm -C voiceId smoke:python-http
pnpm -C voiceId worker:guard
pnpm -C voiceId container:guard
pnpm -C voiceId fixtures:validate
pnpm -C voiceId fixtures:evaluate:ecapa
```

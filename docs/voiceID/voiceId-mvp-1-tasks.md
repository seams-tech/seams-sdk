# VoiceID MVP 1 Tasks

Status: implementation in progress. Phases 0-6 have a typed fake-verifier MVP
scaffold with automated validation and manual browser-demo validation. Phase 13
has the fake transcript provider boundary in place. Phase 14 has fixture
capture/export tooling and local fixture retention docs, and Phase 7 can now
validate exported fixture bundles and produce a model-selection report template.
Phase 8 now has dependency-free Python verifier JSON request/response schemas.
The TypeScript Python verifier adapter boundary is in place behind
`VoiceIdVerifier`. An initial local owner fixture bundle has been collected for
enrollment, owner verification, wrong-phrase, too-short, and owner
voice-variant negative cases. Synthetic different-speaker clips have also been
added for early negative scoring, and noisy owner clips have been added for
low-quality behavior checks.
Fixture validation now includes an optional `ffprobe` media-stream check for
confirming manifest entries point to decodable audio streams.
A local MFCC/log-mel spectral baseline has been run against the fixture set.
The owner enrollment and owner verification clips have been refreshed with
laptop-microphone recordings, and refreshed laptop-microphone wrong-phrase
clips now cover rhyming but incorrect phrases. Refreshed laptop-microphone noisy
clips now include a cafe setting. Legacy short owner enrollment captures have
been reclassified as short fixtures, and legacy unstable iPhone/Continuity
microphone owner verification captures have been reclassified as noisy fixtures.
The spectral baseline now accepts all refreshed owner verification clips and
rejects all current different-speaker clips. A pretrained SpeechBrain ECAPA-TDNN
evaluation has also been run against the same 30-clip fixture set, and
`speechbrain/spkrec-ecapa-voxceleb` is the recommended first real
speaker-embedding model for the MVP verifier boundary. Independent human
different-speaker fixtures, model-backed verifier service integration, Python
process lifecycle, durable storage, existing server integration, and SDK module
integration remain open.

This task plan implements the standalone browser-captured, server-verified
VoiceID MVP described in `docs/voiceID/voiceId-mvp-1.md`.

## Implementation Shape

The MVP should ship as a standalone `voiceId/` workspace first. Wallet/auth SDK
integration is a later module-registration phase after the lifecycle, API, and
verifier boundary work independently.

Architecture:

```text
Browser demo
  -> voiceId/client capture + API client
  -> voiceId/server HTTP routes
  -> route boundary parsers
  -> VoiceIdService
  -> VoiceIdEnrollmentStore / VoiceIdVerificationStore
  -> VoiceIdVerifier interface
  -> FakeVoiceIdVerifier first
  -> Python verifier adapter after verifier spike
```

Ownership boundaries:

- `voiceId/shared`: domain types, result unions, ids, records, parsers, prompt
  normalization, and type fixtures.
- `voiceId/client`: microphone capture, recording lifecycle, API client, and
  browser-only helpers.
- `voiceId/server`: HTTP route adapters, request parsing, service lifecycle,
  store interfaces, in-memory store, audit events, and verifier adapter.
- `voiceId/verifier-spike`: local experiments for model choice and thresholds.
- `voiceId/verifier`: production-shaped Python verifier service once the spike
  chooses a model.
- `voiceId/demo`: standalone browser UI for enrollment and verification.

Data movement rules:

- Browser code owns `Blob` and `MediaRecorder` objects.
- Routes convert multipart request parts into typed `VoiceIdAudioInput` and
  metadata before calling service code.
- Service methods accept typed domain objects only.
- Raw audio can pass from route boundary to verifier call inside a typed sample.
- Stores persist enrollment state, verification state, encrypted templates, and
  audit data. Stores never persist raw audio.
- Python verifier responses are parsed once by the TypeScript adapter into
  `VoiceIdSpeakerMatchResult`, `VoiceIdPhraseMatchResult`, and
  `VoiceIdAudioQualityResult`.

## Core Data Structures

Create these files before route or UI work:

```text
voiceId/shared/src/assertNever.ts
voiceId/shared/src/ids.ts
voiceId/shared/src/audio.ts
voiceId/shared/src/prompts.ts
voiceId/shared/src/results.ts
voiceId/shared/src/states.ts
voiceId/shared/src/records.ts
voiceId/shared/src/parsers.ts
voiceId/shared/src/index.ts
```

Minimum domain model:

- `UserId`, `VoiceIdEnrollmentId`, `VoiceIdVerificationId`,
  `VoiceIdPromptSetId`, `VoiceIdModelVersion`, `VoiceIdTemplateVersion`,
  `IsoDateTime`, `EncryptedBytes`.
- `VoiceIdAudioMetadata`: MIME type, duration ms, sample rate when known,
  channel count when known, byte length, captured-at timestamp, and client
  recorder name.
- `VoiceIdAudioInput`: typed audio bytes plus `VoiceIdAudioMetadata`; this is
  the only server-side type allowed to carry raw audio bytes.
- `VoiceIdEnrollmentSample`: enrollment id, user id, expected phrase, attempt
  number, audio input.
- `VoiceIdVerificationSample`: verification id, user id, enrollment id,
  expected phrase, attempt number, audio input.
- `VoiceIdEnrollmentState`: `not_enrolled`, `enrollment_pending`, `enrolled`,
  `disabled`.
- `VoiceIdEnrollmentRecord`: persisted pending/enrolled/disabled record with
  encrypted template only after finalization.
- `VoiceIdVerificationRecord`: issued/completed/expired record with typed
  result only after completion.
- `VoiceIdVerificationResult`: `accepted`, `rejected`, `uncertain`.
- `VoiceIdVerificationChecks`: separate `phrase`, `speaker`, and `quality`
  branches.
- `VoiceIdVerifier`: interface for fake and Python-backed implementations.

Required invariants:

- `not_enrolled` has no enrollment id or template version.
- `enrollment_pending` has no template version or encrypted template.
- `enrolled` requires model version, template version, and encrypted template.
- `disabled` requires `disabledAt`.
- `issued` verification records have no completed result data.
- Completed verification records require a result whose `kind` matches the
  record state.
- Accepted verification requires accepted phrase, speaker, and quality checks.
- Rejected verification records include a machine-readable rejection reason.
- Uncertain verification records include a machine-readable uncertainty reason.

## Sequencing Rules

Follow this order so each phase has a small blast radius:

1. Scaffold `voiceId/` and make type-check run.
2. Add shared domain types and type fixtures.
3. Add fake verifier behind the final verifier interface.
4. Build server service and in-memory stores against the fake verifier.
5. Add standalone HTTP routes and route tests.
6. Add browser capture and API client.
7. Add standalone demo and verify the fake end-to-end flow.
8. Run the verifier spike with browser-recorded fixtures.
9. Add Python verifier adapter behind the existing interface.
10. Add encrypted durable storage and retention behavior.
11. Integrate routes into the existing server through a capability boundary.
12. Add optional wallet/auth SDK module registration.

Phase gates:

- Gate 1: shared types, type fixtures, fake verifier, service tests pass.
  Completed by `pnpm -C voiceId type-check` and `pnpm -C voiceId test`.
- Gate 2: browser demo completes fake enrollment and fake verification.
  Completed manually in the browser against the fake verifier.
- Gate 3: verifier spike shows same-user/different-user score separation.
- Gate 4: Python verifier works through the TypeScript adapter boundary.
- Gate 5: encrypted template storage and raw-audio retention tests pass.
- Gate 6: existing server registers VoiceID routes through a module boundary.
- Gate 7: SDK exposes VoiceID as an optional capability with lazy browser
  capture loading.
- Gate 8: transcript provider boundary supports fake and external ASR adapters.
- Gate 9: intent-digest binding connects spoken commands to typed wallet
  intents.
- Gate 10: embedded liveness policy can combine audio, video, and device
  context.
- Gate 11: MPC policy consumes owner-presence and intent-bound results without
  treating voice as a signing secret.

## Next Implementation Track

The working scaffold proves browser capture, fake speaker verification,
lifecycle state, route shape, and fake transcript separation. The next
implementation track should proceed in this order:

1. Wire `speechbrain/spkrec-ecapa-voxceleb` into the Python verifier behind the
   existing `VoiceIdVerifier` interface.
2. Add explicit audio quality gating before speaker scoring so noisy, clipped,
   or too-short captures return `uncertain`.
3. Keep transcript/phrase matching as a separate provider boundary. Speaker
   embeddings prove speaker similarity; they do not prove command correctness.
4. Add independent human different-speaker clips before tightening thresholds or
   making stronger security claims.
5. Compare fallback models only if ECAPA has calibration, licensing, latency, or
   deployment problems.
6. Add intent binding for transaction commands and `intentDigest`.
7. Add audio/video liveness policy for embedded devices.
8. Feed owner-presence and intent-bound results into wallet policy.
9. Integrate MPC signing only after policy and liveness boundaries are typed.

## Model Recommendation

Use `speechbrain/spkrec-ecapa-voxceleb` as the first real speaker-verification
model for the MVP.

Recommended policy:

- Use ECAPA embeddings for speaker similarity only.
- Build the owner template from accepted owner enrollment embeddings.
- Score verification embeddings with cosine similarity against the mean owner
  template.
- Start with the local fixture threshold from
  `voiceId/verifier-spike/reports/speechbrain-ecapa-2026-06-11.md`, then
  recalibrate after collecting independent human different-speaker clips.
- Treat noisy, clipped, too-short, or low-speech captures as `uncertain` before
  speaker acceptance.
- Reject wrong phrases through transcript/phrase verification even when the
  speaker score is high.
- Keep raw audio at the route/verifier boundary only; persist encrypted
  templates and model metadata, not raw biometric clips.

Fallback model policy:

- Try `speechbrain/spkrec-xvect-voxceleb` only if we need a classic x-vector
  baseline for comparison.
- Try `pyannote/embedding` only if its access, licensing, and deployment weight
  are acceptable.
- Try `nvidia/speakerverification_en_titanet_large` only if a heavier NeMo stack
  becomes worthwhile for deployment.
- Avoid adding multiple model stacks to the MVP path unless ECAPA fails a
  concrete requirement.

## Phase 0: Workspace Scaffold

Goal: create an isolated `voiceId/` workspace with no wallet/auth SDK coupling.

- [x] Add `voiceId/package.json`, `voiceId/tsconfig.json`, and
  `voiceId/README.md`.
- [x] Add `voiceId` to `pnpm-workspace.yaml`.
- [x] Add `voiceId/shared`, `voiceId/client`, `voiceId/server`, and
  `voiceId/demo` package entrypoints.
- [x] Use a strict TypeScript config with no implicit `any` and exact optional
  property types.
- [x] Add scripts:
  - [x] `pnpm -C voiceId type-check`
  - [x] `pnpm -C voiceId test`
  - [x] `pnpm -C voiceId dev`
  - [x] `pnpm -C voiceId dev:all`
  - [x] `pnpm -C voiceId fixtures:validate`
  - [x] `pnpm -C voiceId fixtures:validate:media`
  - [x] `pnpm -C voiceId fixtures:validate:json`
  - [x] `pnpm -C voiceId fixtures:report`
  - [x] `pnpm -C voiceId fixtures:evaluate:spectral`
  - [x] `pnpm -C voiceId fixtures:evaluate:ecapa`
  - [x] `pnpm -C voiceId verifier:test`
- [x] Add folder structure:
  - [x] `voiceId/shared/src`
  - [x] `voiceId/client/src`
  - [x] `voiceId/server/src`
  - [x] `voiceId/verifier`
  - [x] `voiceId/verifier-spike`
  - [x] `voiceId/demo/src`
  - [x] `voiceId/fixtures`
  - [x] `voiceId/tests`
- [x] Add `voiceId/tests/type-fixtures`.
- [x] Keep dependencies minimal: TypeScript, Vite for demo, and test runner only.

Validation:

- [x] `pnpm -C voiceId type-check` runs with an empty scaffold.
- [x] Root workspace install recognizes `voiceId`.

## Phase 1: Shared Domain Types

Goal: define precise lifecycle and result types before any UI or route code.

- [x] Add `voiceId/shared/src/assertNever.ts`.
- [x] Add branded id/string types:
  - [x] `UserId`
  - [x] `VoiceIdEnrollmentId`
  - [x] `VoiceIdVerificationId`
  - [x] `VoiceIdPromptSetId`
  - [x] `VoiceIdModelVersion`
  - [x] `VoiceIdTemplateVersion`
  - [x] `IsoDateTime`
- [x] Add `EncryptedBytes`.
- [x] Add `VoiceIdAudioInput`; this is the only server-side raw-audio carrier.
- [x] Add `VoiceIdEnrollmentState` discriminated union.
- [x] Add `VoiceIdEnrollmentRecord` persisted-state union.
- [x] Add `VoiceIdVerificationRecord` persisted-state union.
- [x] Add `VoiceIdVerificationResult` discriminated union.
- [x] Add `VoiceIdVerificationChecks` with separate phrase, speaker, and
  quality results.
- [x] Add typed sample inputs:
  - [x] `VoiceIdEnrollmentSample`
  - [x] `VoiceIdVerificationSample`
  - [x] `VoiceIdAudioMetadata`
- [x] Add boundary parsers for JSON metadata.
- [x] Add prompt phrase and digit-code normalization helpers.
- [x] Export only domain-safe builders and parsers from `voiceId/shared/src`.

Type fixtures:

- [x] `enrollmentId` cannot appear on `not_enrolled`.
- [x] `templateVersion` cannot appear on `enrollment_pending`.
- [x] `disabledAt` cannot appear on `enrolled`.
- [x] `encryptedTemplate` cannot appear on pending enrollment records.
- [x] `accepted` verification requires phrase and speaker results.
- [x] `issued` verification record cannot contain completed result data.
- [x] Raw request bodies cannot be passed into core service functions.
- [x] `Blob`, `File`, and `FormData` cannot be passed into server service
  functions.

Validation:

- [x] `pnpm -C voiceId type-check` rejects invalid fixtures with
  `@ts-expect-error`.
- [x] Unit tests cover phrase normalization for digit phrases.

## Phase 2: Fake Verifier Boundary

Goal: implement the verifier interface with deterministic fake behavior.

- [x] Add `voiceId/server/src/verifier/VoiceIdVerifier.ts`.
- [x] Add `voiceId/server/src/verifier/FakeVoiceIdVerifier.ts`.
- [x] Define typed verifier operations:
  - [x] `extractEnrollmentEmbedding`
  - [x] `buildTemplate`
  - [x] `verifySpeaker`
- [x] Define verifier input/output types in shared or server boundary files:
  - [x] enrollment embedding result
  - [x] template build result
  - [x] speaker verification result
  - [ ] verifier unavailable error
- [x] Add fake audio quality evaluator:
  - [x] too short -> `uncertain`
  - [x] marked noisy fixture -> `uncertain`
  - [x] valid fixture -> deterministic score
- [x] Add fake phrase matcher:
  - [x] exact phrase match
  - [x] digit phrase normalization
  - [x] phrase mismatch
- [x] Add fake speaker matcher:
  - [x] matching fixture id -> accepted
  - [x] mismatching fixture id -> rejected
  - [x] low score fixture -> uncertain
- [x] Make fake verifier behavior fixture-driven through explicit metadata, not
  filename parsing inside core service code.

Validation:

- [x] Unit tests cover every fake verifier branch.
- [x] Core server tests depend only on verifier interface, not fake internals.

## Phase 3: Server State Machines

Goal: implement enrollment and verification lifecycle with in-memory storage.

- [x] Add `VoiceIdEnrollmentStore`.
- [x] Add `VoiceIdVerificationStore`.
- [x] Add in-memory implementations for standalone MVP.
- [x] Add `VoiceIdService`.
- [x] Define service config:
  - [x] enrollment prompt expiry
  - [x] verification prompt expiry
  - [x] max enrollment sample attempts
  - [x] max verification attempts
  - [x] required accepted enrollment samples
  - [x] speaker score threshold
- [x] Implement enrollment lifecycle:
  - [x] `startEnrollment`
  - [x] `addEnrollmentSample`
  - [x] `finalizeEnrollment`
  - [x] `disableEnrollment`
- [x] Implement verification lifecycle:
  - [x] `startVerification`
  - [x] `verifySample`
- [x] Enforce attempt limits and expiry.
- [x] Enforce minimum accepted enrollment sample count.
- [x] Delete/discard raw audio after fake extraction boundary returns.
- [x] Emit audit events without raw audio:
  - [x] enrollment started
  - [x] enrollment sample accepted/rejected/uncertain
  - [x] enrollment finalized
  - [x] verification issued
  - [x] verification accepted/rejected/uncertain

Validation:

- [x] Enrollment rejects too-short samples.
- [x] Enrollment rejects low-quality samples.
- [x] Finalize rejects insufficient accepted samples.
- [x] Verification rejects expired prompts.
- [x] Verification rejects phrase mismatch.
- [x] Verification rejects speaker mismatch.
- [x] Verification returns uncertain for low-quality runtime audio.
- [x] Verification accepts matching speaker and phrase.

## Phase 4: Standalone HTTP Routes

Goal: expose the standalone VoiceID API without touching existing server routes.

- [x] Add `voiceId/server/src/routes.ts`.
- [x] Add `voiceId/server/src/http/requestParsing.ts`.
- [x] Add `voiceId/server/src/http/jsonResponses.ts`.
- [x] Add route handlers:
  - [x] `POST /voice-id/enrollment/start`
  - [x] `POST /voice-id/enrollment/sample`
  - [x] `POST /voice-id/enrollment/finalize`
  - [x] `POST /voice-id/enrollment/disable`
  - [x] `POST /voice-id/verification/start`
  - [x] `POST /voice-id/verification/sample`
- [x] Parse multipart audio and JSON metadata at the route boundary.
- [x] Convert route inputs into `VoiceIdEnrollmentSample` or
  `VoiceIdVerificationSample` immediately.
- [x] Return typed JSON result unions.
- [x] Map service errors to stable HTTP status codes:
  - [x] malformed request -> 400
  - [x] missing enrollment or verification -> 404
  - [x] expired prompt -> 409
  - [x] too many attempts -> 429
  - [x] verifier unavailable -> 503
- [x] Add a standalone dev server for the demo.
- [x] Add `GET /` and `GET /health` responses so the API does not look dead
  when opened directly in a browser.

Validation:

- [x] Route tests cover valid enrollment flow.
- [x] Route tests cover valid verification flow.
- [x] Route tests cover malformed metadata.
- [x] Route tests cover missing audio blob.

## Phase 5: Browser Capture Client

Goal: implement browser microphone capture using native browser APIs.

- [x] Add `voiceId/client/src/capture/microphone.ts`.
- [x] Add `voiceId/client/src/capture/mediaRecorder.ts`.
- [x] Add `voiceId/client/src/capture/audioBlob.ts`.
- [x] Add `voiceId/client/src/VoiceIdClient.ts`.
- [x] Add `voiceId/client/src/VoiceIdRecorder.ts`.
- [x] Add enrollment client:
  - [x] start enrollment
  - [x] upload enrollment sample
  - [x] finalize enrollment
- [x] Add verification client:
  - [x] start verification
  - [x] upload verification sample
- [x] Handle microphone permission denied.
- [x] Handle browser unsupported state.
- [x] Handle recording timeout.
- [x] Stop tracks after recording.
- [x] Keep raw blobs only in active UI state.
- [x] Convert recorded clips to multipart requests at the client API boundary.

Validation:

- [x] Browser demo can request microphone permission.
- [x] Browser demo can record a clip and upload it.
- [x] Client type-check passes without importing wallet/auth SDK code.
- [x] Client fetch calls stay bound to the browser runtime.

## Phase 6: Standalone Demo

Goal: make model and lifecycle quality visible before wallet integration.

- [x] Add `voiceId/demo/index.html`.
- [x] Add `voiceId/demo/src/main.ts`.
- [x] Add minimal styles.
- [x] Model demo state as a discriminated union:
  - [x] idle
  - [x] enrolling
  - [x] enrolled
  - [x] verifying
  - [x] accepted
  - [x] rejected
  - [x] uncertain
  - [x] error
- [x] Demo screen sections:
  - [x] enrollment status
  - [x] current prompt
  - [x] record sample button
  - [x] sample quality result
  - [x] finalize enrollment button
  - [x] verification prompt
  - [x] verify button
  - [x] phrase result
  - [x] speaker score/threshold
  - [x] final result
- [x] Show security posture notice: phase 1 is speaker verification, not
  liveness.
- [x] Disable demo actions until their lifecycle prerequisites are satisfied.

Validation:

- [x] Manual browser enrollment works against fake verifier.
- [x] Manual browser verification works against fake verifier.
- [x] Demo does not bundle ML models.

## Phase 7: Verifier Spike

Goal: choose the first real speaker-verification model with measured evidence.

- [x] Add `voiceId/verifier-spike/README.md`.
- [x] Add `voiceId/verifier-spike/pyproject.toml`.
- [x] Add `compare_models.py`.
- [x] Add fixture manifest format:
  - [x] fixture id
  - [x] audio file name
  - [x] speaker label
  - [x] phrase label
  - [x] expected relation to enrollment speaker
  - [x] capture device
  - [x] duration
  - [x] environment notes
  - [x] captured-at timestamp
  - [x] byte length
  - [x] MIME type
- [x] Add verifier-spike manifest/audio loader:
  - [x] schema version validation
  - [x] expected relation validation
  - [x] duplicate fixture id rejection
  - [x] duplicate audio file name rejection
  - [x] missing audio file rejection
  - [x] byte-length mismatch rejection
  - [x] optional media stream validation through `ffprobe`
  - [x] fixture inventory summary output
- [x] Add package scripts for fixture validation.
- [x] Add package script for model-selection report template output.
- [x] Add package script for local spectral baseline evaluation.
- [x] Add candidate model report scaffold:
  - [x] candidate model id
  - [x] adapter name
  - [x] preprocessing notes
  - [x] embedding dimension notes
  - [x] threshold policy notes
  - [x] latency measurement notes
  - [x] required measurement sections
- [ ] Collect model-evaluation fixtures:
  - [x] same-user enrollment clips
  - [x] same-user verification clips
  - [x] synthetic different-speaker clips
  - [ ] independent human different-speaker clips
  - [x] owner voice-variant negative clips
  - [x] phrase mismatch clips
  - [x] noisy clips
  - [x] short clips
- [x] Run local MFCC/log-mel spectral baseline against the current fixtures.
- [x] Write baseline report:
  - [x] score ranges
  - [x] latency estimate
  - [x] false accepts and false rejects against synthetic/different-speaker negatives
  - [x] known fixture gap: refresh full-duration owner enrollment clips
  - [x] known fixture gap: refresh owner-side fixtures with one stable microphone path
- [x] Refresh owner enrollment clips with current 3500 ms laptop-mic recordings.
- [x] Refresh owner verification clips with current 3500 ms laptop-mic recordings.
- [x] Refresh owner-side wrong-phrase clips with current 3500 ms laptop-mic
  recordings.
- [x] Refresh owner-side noisy clips with current 3500 ms laptop-mic cafe
  recordings.
- [ ] Optionally refresh owner voice-variant clips with the laptop microphone for
  consistent calibration.
- [x] Compare first pretrained speaker-verification model:
  - [x] `speechbrain/spkrec-ecapa-voxceleb`
- [ ] Compare fallback pretrained speaker-verification models if ECAPA
  calibration or deployment constraints require it:
  - [ ] `speechbrain/spkrec-xvect-voxceleb`
  - [ ] `pyannote/embedding`
  - [ ] `nvidia/speakerverification_en_titanet_large`
- [ ] Measure:
  - [x] baseline embedding extraction latency
  - [x] baseline same-user score distribution
  - [x] baseline different-user score distribution
  - [x] baseline phrase mismatch behavior
  - [x] baseline low-quality behavior
  - [x] ECAPA embedding extraction latency
  - [x] ECAPA same-user score distribution
  - [x] ECAPA different-user score distribution
  - [x] ECAPA phrase mismatch behavior
  - [x] ECAPA low-quality behavior
- [x] Write a short baseline report.
- [x] Write a short pretrained model-selection report.
- [x] Record selected model id, preprocessing requirements, embedding
  dimensions, score threshold, and expected CPU latency.
- [x] Add brief literature review and source PDFs in `voiceId/research`.

Validation:

- [x] Fixture loader validates exported manifests before model comparison.
- [x] Optional media validator confirms fixture files contain audio streams.
- [x] Report template includes fixture inventory and candidate model sections.
- [x] Baseline report records false accepts, false rejects, score ranges, and
  current fixture limitations.
- [x] ECAPA report identifies model version, threshold policy, and known gaps.
- [x] ECAPA report includes false accept and false reject counts on fixtures.

## Phase 8: Python Verifier Service

Goal: replace fake verifier with a real verifier behind the same boundary.

- [x] Add `voiceId/verifier/pyproject.toml`.
- [x] Add `voiceid_verifier/audio_quality.py`.
- [x] Add `voiceid_verifier/embeddings.py`.
- [x] Add `voiceid_verifier/scoring.py`.
- [x] Add `voiceid_verifier/app.py`.
- [x] Add JSON request/response schemas for:
  - [x] enrollment embedding extraction
  - [x] template build
  - [x] speaker verification
- [x] Add dependency-free schema parsers for Python verifier request bodies.
- [x] Add typed JSON response builders for:
  - [x] enrollment embedding response
  - [x] built/rejected template response
  - [x] accepted/rejected/uncertain speaker response
- [x] Wire placeholder verifier app through schema handlers:
  - [x] enrollment embedding JSON handler
  - [x] template build JSON handler
  - [x] speaker verification JSON handler
  - [x] cosine scoring over placeholder embeddings
- [ ] Implement:
  - [ ] normalize/resample audio
  - [ ] voice activity detection
  - [ ] log-mel/MFCC-like feature extraction or model-required preprocessing
  - [ ] embedding extraction
  - [ ] cosine scoring
  - [x] placeholder model/threshold version reporting
- [ ] Integrate selected ECAPA model:
  - [ ] load `speechbrain/spkrec-ecapa-voxceleb` once per verifier process
  - [ ] extract 192-dimensional enrollment embeddings
  - [ ] build mean owner template from accepted enrollment embeddings
  - [ ] extract verification embedding
  - [ ] score verification with cosine similarity against the owner template
  - [ ] report ECAPA model id, adapter id, template version, and threshold version
- [ ] Add quality-first decision policy:
  - [ ] too-short clips return `uncertain`
  - [ ] clipped or header-only clips return `uncertain`
  - [ ] low-speech or low-SNR clips return `uncertain`
  - [ ] speaker scoring runs only after quality accepts the capture
- [ ] Add threshold calibration config:
  - [ ] default to the ECAPA fixture threshold for local MVP testing
  - [ ] store threshold version with enrollment templates
  - [ ] require recalibration after independent human different-speaker fixtures
- [x] Add TypeScript verifier adapter that parses Python responses into
  `VoiceIdSpeakerMatchResult`.
- [x] Add injected Python verifier transport boundary for:
  - [x] enrollment embedding extraction
  - [x] template build
  - [x] speaker verification
- [x] Add adapter request builders for:
  - [x] typed audio metadata without fixture-only behavior
  - [x] base64 audio payload
  - [x] template references
  - [x] enrollment embeddings
- [x] Add adapter response parsers for:
  - [x] enrollment embedding response
  - [x] built/rejected template response
  - [x] accepted/rejected/uncertain speaker response
- [ ] Keep Python process lifecycle explicit:
  - [ ] local subprocess mode for dev
  - [ ] HTTP sidecar mode for later deployment
  - [ ] timeout and unavailable handling

Validation:

- [x] Fake verifier and Python verifier satisfy the same TypeScript interface.
- [x] Python verifier schema tests cover typed accepted/rejected/uncertain
  speaker response branches.
- [x] TypeScript adapter tests cover Python request construction and response
  parsing.
- [x] Raw model outputs do not cross into core server service code.

## Phase 9: Durable Storage And Retention

Goal: replace in-memory storage with encrypted template storage.

- [ ] Design storage records for enrollment and verification.
- [ ] Add encrypted template serialization.
- [ ] Add template encryption key config.
- [ ] Add raw audio deletion after extraction/verification.
- [ ] Add optional diagnostic retention config with retention window.
- [ ] Add audit events with score bands and result kinds.
- [ ] Add storage adapter interface before choosing concrete persistence.
- [ ] Store model version, template version, threshold version, and enrollment
  prompt set id with each template.

Validation:

- [ ] Pending enrollment records cannot contain encrypted templates.
- [ ] Enrolled records require encrypted templates.
- [ ] Verification records do not store raw audio.
- [ ] Retention config controls diagnostic artifact persistence.

## Phase 10: Existing Server Integration

Goal: integrate routes after standalone VoiceID passes tests.

- [ ] Add a VoiceID server capability module boundary.
- [ ] Register VoiceID routes through the module boundary.
- [ ] Keep VoiceID lifecycle/stores under VoiceID ownership.
- [ ] Keep existing wallet/auth routes free of VoiceID concrete imports.
- [ ] Expose only typed route registration and policy result surfaces to the
  existing server.
- [ ] Add route tests against the integrated server adapter.

Validation:

- [ ] Existing server tests pass.
- [ ] VoiceID routes work through integrated server.
- [ ] No direct VoiceID imports appear in unrelated wallet/auth core files.

## Phase 11: SDK Module Integration

Goal: expose VoiceID as an optional SDK capability.

- [ ] Add wallet/auth module registration types.
- [ ] Add `VoiceIdCapability` client module.
- [ ] Add VoiceID route client.
- [ ] Add lazy loading for VoiceID browser capture.
- [ ] Keep VoiceID out of the default SDK happy-path bundle.
- [ ] Add an SDK-facing typed result adapter from `VoiceIdVerificationResult`
  into the auth policy module.
- [ ] Add module integration tests.

Validation:

- [ ] SDK can run without VoiceID module registered.
- [ ] SDK can register VoiceID module and call enroll/verify APIs.
- [ ] Bundle report confirms no verifier/model code ships to browser.

## Phase 12: Cutover Review

Goal: decide whether the browser VoiceID MVP is ready for policy experiments.

- [ ] Review false accept / false reject fixture metrics.
- [ ] Review privacy and retention behavior.
- [ ] Review browser bundle impact.
- [ ] Review route and storage security.
- [ ] Confirm phase 1 is still labeled speaker verification only.

## Phase 13: Transcript Provider Boundary

Goal: separate "what did the user say" from "does this sound like the owner".

- [x] Add `VoiceIdTranscriptProvider` interface.
- [x] Add transcript result types:
  - [x] accepted transcript
  - [x] rejected transcript
  - [x] uncertain transcript
  - [x] provider unavailable
- [x] Add `FakeTranscriptProvider`.
- [ ] Add provider config for external ASR services.
- [ ] Add planned adapters:
  - [ ] `DeepgramTranscriptProvider`
  - [ ] `ElevenLabsTranscriptProvider`
  - [ ] `WisprFlowTranscriptProvider` if API access is available
- [x] Keep transcript providers out of browser bundle by default.
- [x] Route phrase verification through the transcript provider boundary.
- [x] Keep speaker verification in `VoiceIdVerifier`.

Validation:

- [x] Unit tests prove phrase match can use a fake transcript provider.
- [x] Provider failure returns `uncertain`, not accepted.
- [x] Server service still separates phrase, speaker, and quality checks.

## Phase 14: Fixture Capture And Export

Goal: collect real browser audio fixtures for model evaluation.

- [x] Add fixture capture mode to the demo.
- [x] Add fixture metadata manifest:
  - [x] fixture id
  - [x] speaker label
  - [x] phrase label
  - [x] expected same-user/different-user relation
  - [x] capture device
  - [x] duration
  - [x] environment notes
- [x] Add export action for audio clips and manifest.
- [x] Add fixture collection checklist in `voiceId/fixtures/README.md`.
- [ ] Collect fixtures:
  - [x] owner enrollment clips
  - [x] owner verification clips
  - [x] synthetic different-speaker clips
  - [ ] independent human different-speaker clips
  - [x] owner voice-variant negative clips
  - [x] wrong-phrase clips
  - [x] noisy clips
  - [x] too-short clips
- [x] Refresh owner enrollment clips with current full-duration laptop-mic
  recordings.
- [x] Refresh owner verification clips with current full-duration laptop-mic
  recordings.
- [x] Refresh owner-side wrong-phrase clips with current full-duration
  laptop-mic recordings.
- [x] Refresh owner-side noisy clips with current full-duration laptop-mic cafe
  recordings.
- [ ] Optionally refresh owner voice-variant clips with the laptop microphone.
- [x] Add retention warning for local fixture capture.
- [x] Ignore raw fixture artifacts from git by default.

Validation:

- [x] Exported manifest references every captured audio file.
- [x] Fixture loader rejects missing or malformed manifest entries.
- [x] Fixture media validator rejects clips without a decodable audio stream.
- [x] Fixture collection docs include retention guidance.

## Phase 15: Intent Binding

Goal: bind spoken commands to concrete wallet or robot actions.

- [ ] Add typed intent structures:
  - [ ] robot command intent
  - [ ] token transfer intent
  - [ ] wallet session intent
- [ ] Add `intentDigest` builder.
- [ ] Add spoken-command parser boundary.
- [ ] Add canonical command examples:
  - [ ] `send 1 USDC to Bob`
  - [ ] `send 50 USDC to bob.near`
  - [ ] `authorize wallet session for device X`
- [ ] Bind phrase or transcript result to the canonical intent.
- [ ] Add expiry and replay protection to intent-bound verification records.

Validation:

- [ ] Same spoken command produces the same canonical intent and digest.
- [ ] Different amount, recipient, device, or expiry changes the digest.
- [ ] Voice verification cannot be accepted for a different intent.

## Phase 16: Embedded Liveness Policy

Goal: add local owner-presence policy for robotics and embedded devices.

- [ ] Add liveness result types:
  - [ ] accepted
  - [ ] rejected
  - [ ] uncertain
- [ ] Add audio liveness signals:
  - [ ] speech duration
  - [ ] speech freshness
  - [ ] microphone capture source
  - [ ] replay-risk heuristics
- [ ] Add visual liveness signals:
  - [ ] face present
  - [ ] rough mouth movement
  - [ ] audio/video timing correlation
- [ ] Add local device context:
  - [ ] device id
  - [ ] robot sidecar id
  - [ ] capture timestamp
  - [ ] local policy version
- [ ] Keep liveness separate from speaker verification and transcript matching.

Validation:

- [ ] Voice-only verification can be accepted for demo policy only.
- [ ] Wallet policy requires liveness result for embedded signing flows.
- [ ] Missing liveness returns `uncertain` or requires step-up.

## Phase 17: Wallet Policy And MPC Integration

Goal: consume VoiceID as owner presence for intent-bound MPC signing.

- [ ] Add wallet policy input:
  - [ ] owner presence result
  - [ ] transcript result
  - [ ] speaker result
  - [ ] liveness result
  - [ ] `intentDigest`
  - [ ] model and policy versions
- [ ] Add policy tiers:
  - [ ] low-risk robot command
  - [ ] low-value known-recipient payment
  - [ ] new-recipient payment
  - [ ] high-value or anomalous payment
- [ ] Add step-up requirements for risky actions.
- [ ] Bind MPC signing session to `intentDigest`.
- [ ] Ensure VoiceID never signs directly and never acts as a bearer secret.
- [ ] Add server co-signer policy checks before participation.
- [ ] Add embedded device/sidecar policy boundary.

Validation:

- [ ] Accepted VoiceID alone cannot create a signature.
- [ ] MPC signing requires an accepted policy decision and matching
  `intentDigest`.
- [ ] Step-up is required for configured high-risk policies.
- [ ] Server logs include policy version and result kind without raw audio.

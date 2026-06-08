# VoiceID MVP 1 Tasks

Status: implementation in progress. Phases 0-6 have a typed fake-verifier MVP
scaffold with automated validation. Real model selection, durable storage,
existing server integration, and SDK module integration remain open.

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
  Implemented as a local demo; manual browser verification remains open.
- Gate 3: verifier spike shows same-user/different-user score separation.
- Gate 4: Python verifier works through the TypeScript adapter boundary.
- Gate 5: encrypted template storage and raw-audio retention tests pass.
- Gate 6: existing server registers VoiceID routes through a module boundary.
- Gate 7: SDK exposes VoiceID as an optional capability with lazy browser
  capture loading.

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

- [ ] Browser demo can request microphone permission.
- [ ] Browser demo can record a clip and upload it.
- [x] Client type-check passes without importing wallet/auth SDK code.

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

Validation:

- [ ] Manual browser enrollment works against fake verifier.
- [ ] Manual browser verification works against fake verifier.
- [x] Demo does not bundle ML models.

## Phase 7: Verifier Spike

Goal: choose the first real speaker-verification model with measured evidence.

- [x] Add `voiceId/verifier-spike/README.md`.
- [x] Add `voiceId/verifier-spike/pyproject.toml`.
- [x] Add `compare_models.py`.
- [x] Add fixture manifest format:
  - [x] fixture id
  - [x] speaker label
  - [x] phrase label
  - [x] expected relation to enrollment speaker
  - [x] capture device
  - [x] duration
- [ ] Collect browser-recorded fixtures:
  - [ ] same-user enrollment clips
  - [ ] same-user verification clips
  - [ ] different-user clips
  - [ ] phrase mismatch clips
  - [ ] noisy/short clips
- [ ] Compare 2-3 pretrained speaker-verification models.
- [ ] Measure:
  - [ ] embedding extraction latency
  - [ ] same-user score distribution
  - [ ] different-user score distribution
  - [ ] phrase mismatch behavior
  - [ ] low-quality behavior
- [ ] Write a short model-selection report.
- [ ] Record selected model id, preprocessing requirements, embedding
  dimensions, score threshold, and expected CPU latency.

Validation:

- [ ] Report identifies model version, threshold policy, and known gaps.
- [ ] Report includes false accept and false reject counts on fixtures.

## Phase 8: Python Verifier Service

Goal: replace fake verifier with a real verifier behind the same boundary.

- [x] Add `voiceId/verifier/pyproject.toml`.
- [x] Add `voiceid_verifier/audio_quality.py`.
- [x] Add `voiceid_verifier/embeddings.py`.
- [x] Add `voiceid_verifier/scoring.py`.
- [x] Add `voiceid_verifier/app.py`.
- [ ] Add JSON request/response schemas for:
  - [ ] enrollment embedding extraction
  - [ ] template build
  - [ ] speaker verification
- [ ] Implement:
  - [ ] normalize/resample audio
  - [ ] voice activity detection
  - [ ] log-mel/MFCC-like feature extraction or model-required preprocessing
  - [ ] embedding extraction
  - [ ] cosine scoring
  - [ ] model/threshold version reporting
- [ ] Add TypeScript verifier adapter that parses Python responses into
  `VoiceIdSpeakerMatchResult`.
- [ ] Keep Python process lifecycle explicit:
  - [ ] local subprocess mode for dev
  - [ ] HTTP sidecar mode for later deployment
  - [ ] timeout and unavailable handling

Validation:

- [ ] Fake verifier and Python verifier satisfy the same TypeScript interface.
- [ ] Python verifier returns typed accepted/rejected/uncertain branches.
- [ ] Raw model outputs do not cross into core server service code.

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

Goal: decide whether VoiceID is ready for policy experiments.

- [ ] Review false accept / false reject fixture metrics.
- [ ] Review privacy and retention behavior.
- [ ] Review browser bundle impact.
- [ ] Review route and storage security.
- [ ] Confirm phase 1 is still labeled speaker verification only.
- [ ] Decide next phase:
  - [ ] anti-spoofing
  - [ ] audio-visual liveness
  - [ ] wallet policy simulation
  - [ ] robotics/Reachy integration

# VoiceID MVP 1 Tasks

Status: experimental browser scaffold implemented; signing-security cutover
required.

The repository has a fake-verifier browser flow, an ECAPA Python sidecar,
quality-first scoring, ASR and route boundaries, encrypted template storage,
Cloudflare deployment adapters, fixture tooling, and normal-SDK module mounting.
It also has caller-owned phrase/digest checks and broad owner-presence/liveness
policy plumbing. Those results are E0 research evidence. They cannot authorize
Router admission or SigningWorker use.

The current fixtures are useful for development and model comparison. They do
not establish a production false-accept rate because the cohort lacks the
required independent speakers, cross-day sessions, channel coverage, and PAD
attack corpus.

The authoritative security and recording contract is
[VoiceID Signing Security Profile](voiceId-signing-security-profile.md). It
requires one guided enrollment recording, one challenge-bound verification
recording, E0/E1/E2 evidence tiers, server-owned Router binding and challenges,
passkey-backed browser signing, approved device/PAD evidence for E2, and an
atomically reserved one-use Router grant.

This task plan implements the standalone browser-captured, server-scored
research MVP described in [VoiceID MVP 1](voiceId-mvp-1.md).

The follow-on ECAPA, quality-gating, intent-binding, PAD, and wallet/MPC policy
plan is in [VoiceID MVP 2](voiceId-mvp-2.md).

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
- Raw audio can pass from the route boundary to one verifier call inside a typed
  capture.
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
- `VoiceIdAudioMetadata`: boundary-observed byte length plus advisory MIME,
  duration, sample-rate, channel, timestamp, and recorder fields. The decoder
  establishes the authoritative media profile.
- `VoiceIdAudioInput`: typed audio bytes plus `VoiceIdAudioMetadata`; this is
  the only server-side type allowed to carry raw audio bytes.
- `VoiceIdEnrollmentCapture`: one enrollment id, server challenge, capture
  attempt, exact-audio hash, capture profile, and audio input.
- `VoiceIdVerificationCapture`: one verification id, enrollment id, stored
  Router binding, server challenge, capture attempt, exact-audio hash, capture
  profile, and audio input.
- `VoiceIdEnrollmentState`: `not_enrolled`, `enrollment_pending`, `enrolled`,
  `disabled`.
- `VoiceIdEnrollmentRecord`: persisted pending/enrolled/disabled record with
  encrypted template only after finalization.
- `VoiceIdVerificationRecord`: issued/completed/expired record with typed
  result only after completion.
- `VoiceIdVerificationResult`: `signing_candidate`, `step_up_required`,
  `rejected`, `uncertain`, or `expired`.
- `VoiceIdEvidence`: E0, E1, or E2 with branch-specific builders.
- `VoiceIdVerificationChecks`: separate phrase, speaker, quality, freshness,
  PAD, device-proof, capture-profile, and Router-binding branches.
- `VoiceIdVerifier`: interface for fake and Python-backed implementations.

Required invariants:

- `not_enrolled` has no enrollment id or template version.
- `enrollment_pending` has no template version or encrypted template.
- `enrolled` requires model version, template version, and encrypted template.
- `disabled` requires `disabledAt`.
- `issued` verification records have no completed result data.
- Completed verification records require a result whose `kind` matches the
  record state.
- E2 requires accepted phrase, speaker, quality, freshness, PAD, device proof,
  capture profile, calibration, and Router binding.
- E0 and E1 cannot carry a signing candidate or grant.
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
- Gate 9: the experimental command parser and caller-owned digest-equality path
  are tested as E0 only.
- Gate 10: browser evidence is structurally E0 and every browser transaction
  completes through passkey admission.
- Gate 11: the server creates the immutable Router binding and challenge before
  capture; mutation tests cover every bound field.
- Gate 12: an approved embedded capture profile supplies device proof and PAD
  calibration before E2 is enabled.
- Gate 13: Router reserves one R1 grant atomically, and concurrent replay tests
  prove that only one request can reach SigningWorker.

## Next Implementation Track

Completed prototype capabilities:

- [x] ECAPA is available behind `VoiceIdVerifier`.
- [x] Quality gates run before speaker scoring.
- [x] Transcript matching remains separate from speaker similarity.
- [x] Encrypted template storage and retention boundaries exist.
- [x] VoiceID routes mount through the normal SDK module boundary.
- [x] The demo exercises enrollment, verification, and an E0 policy result
      without invoking signing APIs.

Replacement track:

- [ ] Implement the one-session enrollment and one-capture verification UX in
      [VoiceID UI](voiceID-UI.md).
- [ ] Replace fixed sample-count APIs and state with usable-speech evidence and
      internal window aggregation.
- [ ] Add E0/E1/E2 builders and delete broad signing-facing
      owner-presence/liveness acceptance types.
- [ ] Authenticate the route before challenge creation and derive subject,
      wallet, session, tenant, policy, and Router binding from server context.
- [ ] Make the expected phrase, nonce, expiry, and canonical Router digest tuple
      server-owned.
- [ ] Keep browser signing passkey-backed and add tests proving E0/E1 cannot call
      a signing continuation.
- [ ] Run the subject-disjoint evidence-duration experiment before changing the
      local development threshold.
- [ ] Add an approved embedded capture agent, exact-audio device proof, and
      calibrated PAD before enabling E2.
- [ ] Implement the Router admission adapter and atomic one-use grant state in
      [Router policy issuer](voiceId-router-policy-issuer.md).
- [ ] Add concurrent reservation, request mutation, expiry, revocation, worker
      failure, deletion, and passkey fallback tests.

## Model Recommendation

Use `speechbrain/spkrec-ecapa-voxceleb` as the first real speaker-verification
model for the MVP.

Recommended policy:

- Use ECAPA embeddings for speaker similarity only.
- Segment one continuous enrollment recording into non-overlapping VAD windows.
- Reject low-quality, duplicate, multi-speaker, and incoherent windows.
- Build the owner template as a normalized, versioned, quality-weighted centroid
  of accepted window embeddings.
- Score the verification capture against that normalized centroid under the
  calibrated aggregation policy.
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
  - [x] `pnpm -C voiceId dev:all:verifier`
  - [x] `pnpm -C voiceId dev:verifier`
  - [x] `pnpm -C voiceId fixtures:validate`
  - [x] `pnpm -C voiceId fixtures:validate:media`
  - [x] `pnpm -C voiceId fixtures:validate:json`
  - [x] `pnpm -C voiceId fixtures:report`
  - [x] `pnpm -C voiceId fixtures:evaluate:spectral`
  - [x] `pnpm -C voiceId fixtures:evaluate:ecapa`
  - [x] `pnpm -C voiceId bundle:guard`
  - [x] `pnpm -C voiceId worker:guard`
  - [x] `pnpm -C voiceId container:guard`
  - [x] `pnpm -C voiceId aws:guard`
  - [x] `pnpm -C voiceId nitro:guard`
  - [x] `pnpm -C voiceId robot:guard`
  - [x] `pnpm -C voiceId container:build:cloudflare`
  - [x] `pnpm -C voiceId smoke:python-http`
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
- [x] Add the prototype typed sample inputs:
  - [x] `VoiceIdEnrollmentSample`
  - [x] `VoiceIdVerificationSample`
  - [x] `VoiceIdAudioMetadata`
- [ ] Replace the prototype inputs with `VoiceIdEnrollmentCapture` and
      `VoiceIdVerificationCapture`; delete the sample types after callers migrate.
- [ ] Add server challenge, capture profile, exact-audio hash, E0/E1/E2, and
      one-use grant state types.
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
- [ ] E0/E1 cannot be passed to signing policy or continuation functions.
- [ ] Invalid E2 branches and grant lifecycle combinations fail static
      `@ts-expect-error` fixtures.

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
  - [x] verifier unavailable error
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
- [x] Define the prototype service config:
  - [x] enrollment prompt expiry
  - [x] verification prompt expiry
  - [x] max enrollment sample attempts
  - [x] max verification attempts
  - [x] required accepted enrollment samples
  - [x] speaker score threshold
- [x] Implement the prototype enrollment lifecycle:
  - [x] `startEnrollment`
  - [x] `addEnrollmentSample`
  - [x] `finalizeEnrollment`
  - [x] `disableEnrollment`
- [x] Implement the prototype verification lifecycle:
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
- [ ] Replace fixed sample counts with usable-speech evidence, capture attempt
      limits, and one continuous enrollment capture.
- [ ] Replace `addEnrollmentSample` and `verifySample` with narrow capture-state
      methods; delete the old lifecycle after route/client migration.
- [ ] Add server challenge, immutable Router binding, E0/E1/E2 evidence, and
      one-use grant stores.

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
- [x] Add prototype route handlers:
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
- [ ] Add authenticated `POST /voice-id/enrollment/capture` and
      `POST /voice-id/verification/capture` routes with server-owned challenge
      lookup.
- [ ] Derive subject and Router scope from authenticated server context.
- [ ] Delete `/enrollment/sample`, `/verification/sample`, and client-supplied
      security context after the capture routes land.

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
- [x] Add the prototype enrollment client:
  - [x] start enrollment
  - [x] upload enrollment sample
  - [x] finalize enrollment
- [x] Add the prototype verification client:
  - [x] start verification
  - [x] upload verification sample
- [x] Handle microphone permission denied.
- [x] Handle browser unsupported state.
- [x] Handle recording timeout.
- [x] Stop tracks after recording.
- [x] Keep raw blobs only in active UI state.
- [x] Convert recorded clips to multipart requests at the client API boundary.
- [ ] Add `recordGuidedEnrollment()` for one continuous prompt-segmented
      recording and `recordVerification()` for one challenge-bound recording.
- [ ] Upload original capture bytes once, with advisory client metadata.
- [ ] Delete per-sample upload and fixed-count recorder APIs after migration.

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
- [x] Prototype demo screen sections:
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
- [ ] Replace sample counters and repeated record buttons with usable-speech
      progress, one guided enrollment control, and one verification control.
- [ ] Require passkey confirmation before every browser transaction proceeds to
      ordinary Router admission.
- [ ] Label browser VoiceID outcomes as experimental voice verification rather
      than signing-grade liveness.

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
- [x] Measure:
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
- [x] Implement:
  - [x] normalize/resample audio
  - [x] voice activity detection
  - [x] log-mel/MFCC-like feature extraction or model-required preprocessing
  - [x] embedding extraction
  - [x] cosine scoring
  - [x] placeholder model/threshold version reporting
- [x] Integrate selected ECAPA model:
  - [x] load `speechbrain/spkrec-ecapa-voxceleb` once per verifier process
  - [x] extract 192-dimensional enrollment embeddings
  - [x] build mean owner template from accepted enrollment embeddings
  - [x] extract verification embedding
  - [x] score verification with cosine similarity against the owner template
  - [x] report ECAPA model id, adapter id, template version, and threshold version
- [x] Add quality-first decision policy:
  - [x] too-short clips return `uncertain`
  - [x] clipped or header-only clips return `uncertain`
  - [x] low-speech or low-SNR clips return `uncertain`
  - [x] speaker scoring runs only after quality accepts the capture
- [x] Add threshold calibration config:
  - [x] default to the ECAPA fixture threshold for local MVP testing
  - [x] store threshold version with enrollment templates
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
- [x] Keep Python process lifecycle explicit:
  - [x] local subprocess mode for dev
  - [x] HTTP sidecar transport client for later deployment
  - [x] long-running Python HTTP sidecar server
  - [x] timeout handling for subprocess transport
  - [x] unavailable handling mapped into service-level verifier errors
  - [x] env-based verifier selection for fake, subprocess, and HTTP modes
  - [x] sidecar-backed dev launcher for API, demo, and verifier
- [x] Document verifier runtime mode in MVP 2:
  - [x] Python verifier runs server-side or in a local robot sidecar
  - [x] browser clients capture and upload audio; they do not run ECAPA
  - [x] iOS/mobile clients capture and upload audio through the same typed API
  - [x] robot clients call a local sidecar or remote VoiceID server
  - [x] Cloudflare deployment keeps Workers capture/API/policy code separate
        from Container-hosted ECAPA inference
  - [x] The Cloudflare deployment plan references the existing
        [Router A/B SigningWorker design](../../docs/router-a-b-SPEC.md); no VoiceID
        admission adapter is implemented
  - [x] AWS deployment supports normal servers and Nitro Enclave custody through
        a parent-instance bridge while preserving Router A/B signer semantics
  - [x] on-device browser/iOS verification is deferred to a later portability
        track
- [x] Validate verifier runtime mode in implementation:
  - [x] client bundle checks prove no PyTorch, SpeechBrain, or model weights ship
        to browser/mobile clients
  - [x] server-side Python verifier can run through a local subprocess entrypoint
  - [x] HTTP sidecar transport exposes the same typed verifier operations from
        TypeScript callers
  - [x] Python HTTP sidecar server exposes the same typed verifier operations
  - [x] API smoke test completes enrollment and verification through
        `python-http`
  - [x] Cloudflare Worker adapter avoids Node-only APIs in request, policy,
        intent, and storage logic
  - [x] Cloudflare Container deployment can host the Python ECAPA verifier
        sidecar
  - [x] Container packaging guard validates Dockerfile, `.dockerignore`,
        verifier package metadata, E0 threshold labeling, component-only
        authority, authenticated transport, and transient-media rules
  - [x] Optional AWS ordinary-server SDK portability can host the same HTTP
        verifier sidecar
  - [x] Optional AWS ordinary-server guard validates the verifier service
        runbook, authenticated sidecar transport, retention/AAD rules, and
        atomic grant-store boundary
  - [x] Optional Nitro Enclave SDK portability shape can carry verifier/policy
        requests over parent-instance vsock
  - [x] Optional Nitro Enclave guard validates that raw audio and ECAPA
        inference stay outside the enclave, E2/reserved-grant requests cross the
        bridge, and biometric/SigningWorker roles remain separate
  - [x] robot-local sidecar path can call the same typed verifier API
  - [x] robot-local guard validates the Reachy-style app, local/wallet
        sidecars, server challenge, Router binding, E0/E1/E2, PAD, passkey,
        atomic reservation, and independent safety boundaries

Validation:

- [x] Fake verifier and Python verifier satisfy the same TypeScript interface.
- [x] Python verifier schema tests cover typed accepted/rejected/uncertain
      speaker response branches.
- [x] TypeScript adapter tests cover Python request construction and response
      parsing.
- [x] Raw model outputs do not cross into core server service code.

## Phase 9: Durable Storage And Retention

Goal: replace in-memory storage with encrypted template storage.

- [x] Design storage records for enrollment and verification.
- [x] Add Cloudflare-compatible enrollment and verification row serializers:
  - [x] pending enrollment rows carry no template material
  - [x] enrolled/disabled enrollment rows require encrypted template material
  - [x] issued verification rows carry no result data
  - [x] completed verification rows carry typed result JSON
- [x] Add encrypted template serialization.
- [x] Add template encryption key config:
  - [x] Cloudflare Workers secret binding source
  - [x] robot-local secret environment source
  - [x] AES-GCM-256 algorithm validation
  - [x] key id, rotation version, and AAD label validation
  - [x] config carries key references, not secret values
- [x] Add raw capture exclusion after extraction/verification:
  - [x] storage rows contain no raw audio bytes
  - [x] storage rows contain no raw media capture payloads
  - [x] storage parser rejects raw capture columns at the persistence boundary
- [x] Add optional diagnostic retention config with retention window:
  - [x] diagnostics default to disabled
  - [x] Cloudflare R2 diagnostic artifact target
  - [x] robot-local diagnostic file target
  - [x] explicit raw diagnostic media opt-in
  - [x] retention TTL validation
  - [x] artifact size cap validation
- [x] Add audit events with score bands and result kinds:
  - [x] typed audit result kind
  - [x] enrollment sample quality score band
  - [x] verification phrase confidence score band
  - [x] verification speaker score and threshold score bands
  - [x] verification quality signal score band
  - [x] audit events exclude raw capture fields
- [x] Add storage adapter interface before choosing concrete persistence.
- [x] Add Cloudflare D1/Durable-Object-compatible store adapter:
  - [x] schema statements create enrollment and verification tables
  - [x] D1 enrollment store implements `VoiceIdEnrollmentStore`
  - [x] D1 verification store implements `VoiceIdVerificationStore`
  - [x] reads parse persisted rows at the storage boundary
  - [x] writes use prepared statements and bound parameters
- [x] Store model version, template version, threshold version, and enrollment
      prompt set id with each template.
- [x] Wire template key config into actual template wrapping/unwrapping:
  - [x] parse AES-GCM-256 raw keys from configured Cloudflare/robot secret
        locations
  - [x] wrap enrolled/disabled templates before persistence
  - [x] unwrap templates after persistence reads before verifier scoring
  - [x] bind envelope AAD to user id, enrollment id, model version, template
        version, threshold version, key id, rotation version, and AAD label
- [x] Wire Cloudflare Worker runtime storage:
  - [x] `VOICEID_STORAGE_KIND=cloudflare-d1` selects D1-backed stores
  - [x] `VOICEID_D1_DATABASE` binding is validated at the Worker boundary
  - [x] D1 enrollment store is wrapped with AES-GCM template encryption
  - [x] D1 verification store persists typed verification records

Validation:

- [x] Pending enrollment records cannot contain encrypted templates.
- [x] Enrolled records require encrypted templates.
- [x] Verification records do not store raw audio.
- [x] D1-compatible stores roundtrip enrollment and verification records.
- [x] D1-compatible stores reject malformed persisted rows with raw capture
      columns.
- [x] Template wrapping store persists AES-GCM envelopes and returns verifier
      templates to core service code.
- [x] Template envelope decryption rejects records whose enrollment metadata no
      longer matches the wrapped template AAD.
- [x] Cloudflare Worker flow stores wrapped templates in D1 and sends unwrapped
      verifier templates to the Python HTTP sidecar.
- [x] Template encryption key config rejects missing or invalid key source,
      algorithm, key id, rotation version, and AAD label.
- [x] Retention config controls diagnostic artifact persistence.
- [x] Audit events include result kinds and score bands without raw audio or
      diagnostic media capture data.

## Phase 10: Existing Server Integration

Goal: integrate routes after standalone VoiceID passes tests.

- [x] Add a VoiceID server capability module boundary.
- [x] Register VoiceID routes through the module boundary.
- [x] Keep VoiceID lifecycle/stores under VoiceID ownership.
- [x] Keep existing wallet/auth routes free of VoiceID concrete imports.
- [x] Expose typed route registration surfaces to the existing server.
- [x] Expose the current typed E0 policy-simulation surfaces to the existing
      server:
  - [x] `VoiceIdIntentDigest` requires an unpadded base64url 32-byte digest
  - [x] the prototype accepted result requires matching `intentDigest` and a
        broad accepted or `not_required` liveness branch; this remains E0
  - [x] rejected and uncertain results carry typed reasons and no signing
        authority
  - [x] intent mismatch rejects otherwise accepted owner-presence evidence
- [ ] Delete the broad accepted/`not_required` policy surface after E0/E1/E2
      consumers migrate.
- [x] Add route tests against the integrated server adapter.
- [x] Mount the VoiceID capability in the actual SDK server/router entrypoints:
  - [x] `RouterApiOptions.routeExtensions` accepts Cloudflare-only,
        Express-only, or universal route extensions
  - [x] Cloudflare relay router includes Cloudflare/universal extension routes
        in its route surface and dispatch chain
  - [x] Express relay router includes Express/universal extension routes in its
        route surface and registration chain
  - [x] SDK router route surfaces reject duplicate extension route ids and
        method/path collisions
- [x] Add server-side VoiceID SDK relay-extension adapter:
  - [x] `createVoiceIdRouterApiRouteExtension()` converts a
        `VoiceIdServerCapability` into a universal router API route extension
  - [x] Cloudflare dispatch calls the capability `Request -> Response` handler
        directly
  - [x] Express registration bridges Express requests/responses at the adapter
        boundary
  - [x] Adapter stays structurally compatible with SDK route extensions without
        importing SDK runtime code into the standalone VoiceID package

Validation:

- [ ] Existing server tests pass.
- [x] `pnpm -C packages/sdk-server-ts type-check`
- [x] `pnpm -C voiceId type-check`
- [x] `pnpm -C voiceId test`
- [x] `pnpm -C tests test:router-surface`
- [x] VoiceID routes work through integrated server adapter.
- [x] VoiceID policy surface rejects mismatched `intentDigest` values.
- [x] No direct VoiceID imports appear in unrelated wallet/auth core files.
- [x] Run `tests/unit/router.relayRouteSurface.unit.test.ts` through a
      no-webserver Playwright router config.

## Phase 11: SDK Module Integration

Goal: expose VoiceID as an optional SDK capability.

- [x] Add server-side relay-extension adapter for VoiceID API routes.
- [x] Add the existing optional SDK module registration types.
- [x] Add `VoiceIdCapability` client module:
  - [x] API-only capability exposes the existing `VoiceIdClient`
  - [x] Browser-capture capability exposes `createRecorder()`
- [x] Add VoiceID route client.
- [x] Add lazy loading for VoiceID browser capture.
- [x] Keep VoiceID out of the default SDK happy-path bundle.
- [x] Add an SDK-facing typed result adapter from `VoiceIdOwnerPresenceResult`
      into the auth policy module.
- [x] Add module integration tests.
- [ ] Expose the replacement as per-operation `VoiceEvidenceCapability` without
      widening global wallet auth-method unions during E0/E1.
- [ ] Replace `VoiceIdOwnerPresenceResult` with tiered evidence and passkey
      fallback branches.

Validation:

- [x] SDK can run without VoiceID module registered.
- [x] Standalone VoiceID client can create API-only and browser-capture
      capabilities.
- [x] VoiceID auth-policy adapter tests cover accepted, rejected, uncertain,
      expired, and intent-mismatch decisions.
- [x] Wallet/auth SDK can register VoiceID module and call enroll/verify APIs.
- [x] Bundle guard confirms no verifier/model code ships to browser.

## Phase 12: Cutover Review

Goal: decide whether the browser VoiceID MVP is ready for policy experiments.

- [x] Review false accept / false reject fixture metrics.
- [x] Review privacy and retention behavior.
- [x] Review browser bundle impact.
- [x] Review route and storage security.
- [x] Confirm phase 1 is still labeled speaker verification only.

## Phase 13: Transcript Provider Boundary

Goal: separate "what did the user say" from "does this sound like the owner".

- [x] Add `VoiceIdTranscriptProvider` interface.
- [x] Add transcript result types:
  - [x] accepted transcript
  - [x] rejected transcript
  - [x] uncertain transcript
  - [x] provider unavailable
- [x] Add `FakeTranscriptProvider`.
- [x] Add provider config for external ASR services:
  - [x] `VOICEID_TRANSCRIPT_PROVIDER=fake`
  - [x] `VOICEID_TRANSCRIPT_PROVIDER=cloudflare-workers-ai`
  - [x] `VOICEID_CLOUDFLARE_ASR_MODEL=@cf/openai/whisper`
- [ ] Add planned adapters:
  - [x] `CloudflareWorkersAiTranscriptProvider`
  - [ ] `DeepgramTranscriptProvider`
  - [ ] `ElevenLabsTranscriptProvider`
  - [ ] `WisprFlowTranscriptProvider` if API access is available
- [x] Keep transcript providers out of browser bundle by default.
- [x] Route phrase verification through the transcript provider boundary.
- [x] Keep speaker verification in `VoiceIdVerifier`.

Validation:

- [x] Unit tests prove phrase match can use a fake transcript provider.
- [x] Unit tests prove phrase match can use Cloudflare Workers AI ASR.
- [x] Cloudflare fetch-handler test verifies Workers AI ASR participates in the
      verification path.
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

Goal: replace the caller-owned digest prototype with the authoritative Router
binding and server challenge defined by the signing security profile.

Current E0 prototype:

- [x] Typed robot command, token transfer, and wallet-session intent structures
      exist.
- [x] A deterministic client/shared `intentDigest` builder and spoken-command
      parser exist.
- [x] Equality, expiry, and sequential-consumption route tests cover the
      prototype record.

Required cutover:

- [ ] Construct `RouterVoiceIntentBinding` with the existing typed Router A/B
      builders after authenticating the request.
- [ ] Derive user, wallet, account, session, tenant, environment, policy, and
      operation scope from authenticated server state.
- [ ] Persist the binding before issuing the random prompt and challenge.
- [ ] Make every voice-specific digest a domain-separated derivative of the
      Router tuple. Delete the independent authoritative `VoiceIdIntentDigest`
      path from wallet signing.
- [ ] Bind the exact uploaded-audio hash, device key, prompt, nonce, timing, and
      capture profile to the stored challenge.
- [ ] Invalidate the challenge after one submission, expiry, cancellation,
      transaction mutation, or quality retry.

Validation:

- [ ] Mutating any Router, challenge, device, prompt, audio-hash, expiry, or
      identity field invalidates the capture.
- [ ] Caller-supplied digests, transcripts, identity, timestamps, policy, or
      replay flags cannot enter authoritative core state.
- [ ] Parallel attempts cannot reuse one challenge or grant.

## Phase 16: Capture Evidence Boundary

Goal: replace broad owner-presence/liveness acceptance with independent,
assurance-tiered evidence.

Current E0 prototype:

- [x] Accepted, rejected, and uncertain policy shapes exist.
- [x] Speech duration, browser timestamps, microphone/source labels, replay
      heuristics, device ids, sidecar ids, and local policy versions can cross the
      route boundary as client-reported context.
- [x] Speaker, transcript, and broad liveness results remain separate in the
      prototype.
- [x] Camera, face, mouth, and lip-sync payloads are absent from the active MVP.

Required cutover:

- [ ] Rename client claims to untrusted capture telemetry and constrain all
      ordinary browser evidence to E0.
- [ ] Add E0/E1/E2 discriminated unions and branch-specific builders.
- [ ] Delete `not_required` and broad accepted liveness branches from
      signing-facing policy and tests.
- [ ] Add server-verified freshness, exact-audio device proof, approved capture
      profile, PAD, and calibration result types.
- [ ] Add static fixtures that reject direct E2 object literals, broad spreads,
      optional security fields, unsafe casts, and E0/E1 signing calls.
- [ ] Route unsupported or uncertain signing checks to passkey.

Validation:

- [ ] Browser evidence cannot construct E2 or issue a signing grant.
- [ ] Replay heuristics can reject or raise risk and cannot construct accepted
      PAD.
- [ ] Only a calibrated approved capture profile can construct E2.
- [ ] Audio-visual PAD work remains isolated in
      [Audio-Visual PAD Future Plan](voiceId-camera-liveness-future.md).

## Phase 17: Wallet Policy And Router Admission

Goal: keep browser signing passkey-backed and implement an atomic E2-to-R1
Router admission path for a future approved embedded pilot.

Current prototype:

- [x] VoiceID routes mount through `RouterApiModule`.
- [x] The normal SDK path can enroll, verify, and obtain an E0 policy result
      without invoking Router A/B signing.
- [x] Broad wallet/robot policy tiers and step-up outcomes are simulated.
- [x] The intended Router adapter contract is documented in
      [Router policy issuer](voiceId-router-policy-issuer.md).

Required cutover:

- [ ] Require passkey admission for every browser transaction, independent of
      whether E0 voice evidence succeeds.
- [ ] Evaluate only E2 with server-owned R1 risk policy.
- [ ] Issue an opaque reference to a server-side `issued` grant for one exact
      Router binding.
- [ ] Atomically compare-and-set `issued` to `reserved` at Router admission.
- [ ] Allow only the reservation holder to call SigningWorker.
- [ ] Transition success to `consumed`; transition timeout, cancellation,
      response loss, or worker failure to `failed_closed`.
- [ ] Keep Deriver A/B on setup, export, recovery, and SigningWorker refresh.
- [ ] Delete tests that equate a broad accepted policy decision with Router
      admission.

Validation:

- [ ] E0/E1 cannot call the signing continuation or widen a wallet session.
- [ ] Browser success followed by passkey authorizes through the passkey branch;
      the voice result remains E0.
- [ ] Concurrent requests cannot reserve one grant for different operations.
- [ ] Router and SigningWorker reject every digest, identity, policy, expiry, and
      transcript mutation.
- [ ] A reserved grant never returns to `issued` after a terminal failure.
- [ ] Audit records contain tier, result kinds, coarse score bands, and versions
      without raw audio, embeddings, or full transcripts.

## Phase 18: Recording And Enrollment Cutover

Goal: replace fixed clip counts with one guided capture ceremony and calibrated
usable-speech evidence.

- [ ] Replace `requiredSampleCount`, `acceptedSampleCount`, and per-sample route
      semantics with `evidenceTarget`, `evidenceProgress`, and capture-attempt state.
- [ ] Present three to five randomized prompt fragments in one enrollment
      recording with a provisional 12-second usable-speech target.
- [ ] Segment the recording internally with VAD; reject low-quality, duplicate,
      overlapping, multi-speaker, and embedding-incoherent windows.
- [ ] Store a normalized quality-weighted centroid with aggregation, capture,
      model, threshold, assurance, and prompt-set versions.
- [ ] Use one 3–5 second verification recording and permit at most one quality
      retry under a new challenge.
- [ ] Delete fixed multi-sample UI, routes, fixtures, mocks, and tests after the
      replacement path lands.
- [ ] Run the pre-registered evidence-duration experiment before freezing the
      production duration or threshold.

Validation:

- [ ] One continuous capture reaches the usable-speech target across supported
      browsers and approved device profiles.
- [ ] All windows from one session stay in the same dataset split.
- [ ] Enrollment fails closed when accepted evidence is insufficient.
- [ ] Raw capture deletion and template persistence verification work on every
      terminal branch.

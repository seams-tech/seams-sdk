# VoiceID MVP 1

Status: exploratory implementation spec.

This document scopes phase 1 to browser-captured, server-scored VoiceID. It
does not include robotics, MPC signing, x402, face recognition, or audio-visual
liveness. Those remain separate follow-on tracks.

Follow-on plan: [VoiceID MVP 2](voiceId-mvp-2.md) covers the next stage:
ECAPA-backed verification, quality-first gating, expanded calibration fixtures,
intent binding, and wallet/robot policy integration. Audio-visual PAD is tracked
separately in
[Audio-Visual PAD Future Plan](voiceId-camera-liveness-future.md).
Signing eligibility and the target recording protocol are defined in
[VoiceID Signing Security Profile](voiceId-signing-security-profile.md). This
MVP remains
experimental and cannot emit E2 signing-candidate evidence.

## Purpose

Build a standalone VoiceID MVP that can:

1. Establish a VoiceID enrollment from one guided browser capture segmented
   into prompt-aligned speech evidence.
2. Verify one future browser capture against that enrollment.
3. Return typed `accepted`, `rejected`, or `uncertain` results.
4. Stay isolated from the wallet/auth SDK until the VoiceID lifecycle and API
   shape are stable.

The first implementation should live under a dedicated `voiceId` folder so it
can move independently. After the MVP works, the wallet/auth SDK should expose a
module interface so VoiceID can plug into client capture, server routes, and
future auth policy without hard-coded VoiceID imports throughout the wallet
stack.

## Non-Goals

1. Training a speaker-verification model.
2. Shipping VoiceID as a signing-session authenticator.
3. Solving replay, deepfake, presentation attacks, or capture provenance beyond
   basic research heuristics.
4. Storing raw audio permanently.
5. Adding robotics/Reachy dependencies.
6. Refactoring all wallet auth flows before the VoiceID MVP proves useful.

## Security Posture

Phase 1 is **speaker verification**, not liveness. It verifies that a browser
recording is similar to the enrolled speaker and that the spoken phrase matches
the expected phrase. It should not be used alone as signing authority.

Known gaps:

1. Replay resistance is limited to prompt freshness and attempt limits.
2. Deepfake and voice-conversion detection are out of scope.
3. Browser microphone input can be virtualized or tampered with on a compromised
   client.
4. A successful result is a recoverable policy signal, not a cryptographic
   authenticator.

Phase 1 output may be used for product experiments, recovery UX research, and
step-up policy simulations. Browser wallet signing always pairs this evidence
with a user-verified passkey. A future direct R1 path requires the complete E2,
PAD, calibration, and Router grant profile.

## MVP Behavior

Enrollment:

```text
authenticated user
  -> browser asks for microphone permission
  -> user completes one guided recording ceremony
  -> client or server segments prompted speech into several windows
  -> server validates audio quality
  -> server extracts speaker embeddings
  -> server stores encrypted voice template
```

Verification:

```text
authenticated user
  -> server creates a short unpredictable phrase challenge
  -> browser records user saying the phrase
  -> server checks phrase match
  -> server extracts speaker embedding
  -> server compares embedding to stored template
  -> server returns experimental accepted / rejected / uncertain
```

Browser capture should use standard browser APIs:

1. `navigator.mediaDevices.getUserMedia({ audio: true })` for microphone access.
2. `MediaRecorder` for short enrollment and verification clips.
3. `AudioWorklet` later if low-latency streaming or client-side quality checks
   become necessary.

## Acceptance Criteria

Enrollment acceptance:

1. The UI performs one guided capture session and submits server-configured
   prompt segments.
2. The provisional experiment target is 12 seconds of usable speech across at
   least three accepted, non-duplicate segments.
3. Each segment passes decoded-duration, detected-speech, clipping, saturation,
   and noise checks.
4. Finalization rejects duplicate, outlier, multi-speaker, or incoherent
   enrollment segments.
5. Required evidence is configured in usable speech and coherent segment terms.
   A raw UI recording count is not a security threshold.

Verification acceptance:

1. Same-user fixtures in normal room conditions return experimental
   `accepted`.
2. Different-user samples return `rejected` in the basic test set.
3. Matching speaker with wrong phrase returns `rejected`.
4. Low-quality runtime audio returns `uncertain`.
5. Expired prompts return `rejected`.
6. A single accepted 3-5 second capture completes verification. Additional
   captures are quality retries and cannot vote an uncertain result into an
   accepted result.

Metric gate:

1. Record score distributions for same-user and independent-human different-
   user fixtures with speaker-disjoint evaluation splits.
2. Pick a provisional threshold from validation fixtures.
3. Report false accept and false reject counts for the fixture set.
4. Do not tune thresholds per user to force acceptance.

## Speaker Verification Pipeline

Server verifier flow:

```text
audio clip
  -> normalize / resample
  -> voice activity detection
  -> log-mel or MFCC-like features
  -> speaker embedding model
  -> compare runtime embedding against enrollment template
  -> threshold decision
```

Implementation notes:

1. Use a pretrained speaker-verification model for MVP.
2. Store model and threshold versions with every enrollment.
3. Store encrypted embeddings/templates, not raw enrollment audio.
4. Use cosine similarity first unless the selected model recommends a different
   scorer.
5. Add PLDA-style or calibrated neural scoring only after baseline metrics show
   cosine scoring is insufficient.

## Phrase And Speaker Checks

Phrase verification and speaker verification are separate checks:

```ts
type VoiceIdVerificationChecks = {
  phrase: VoiceIdPhraseMatchResult;
  speaker: VoiceIdSpeakerMatchResult;
  quality: VoiceIdAudioQualityResult;
};
```

Rules:

1. A correct speaker saying the wrong phrase is rejected.
2. A correct phrase spoken by the wrong speaker is rejected.
3. Low audio quality produces `uncertain` unless phrase mismatch or policy
   denial is already clear.
4. Phrase matching should normalize digit variants such as "one one six" to
   `116`, and reject ambiguous words when confidence is low.

## Verifier Spike

Before building deep SDK integration, run a short verifier spike:

```text
voiceId/verifier-spike/
  README.md
  pyproject.toml
  compare_models.py
  fixtures/
```

Spike goals:

1. Compare 2-3 pretrained speaker-verification models.
2. Test browser-recorded enrollment and verification clips.
3. Measure latency for embedding extraction and scoring.
4. Measure same-user vs different-user score separation.
5. Choose the first model, threshold policy, and audio quality gates.

The spike should write a short result summary before productionizing the
verifier boundary.

## Domain State

Use explicit lifecycle unions. Core logic must not accept raw request bodies,
raw strings, or broad partial objects.

```ts
type VoiceIdEnrollmentState =
  | {
      kind: 'not_enrolled';
      userId: UserId;
      enrollmentId?: never;
      templateVersion?: never;
    }
  | {
      kind: 'enrollment_pending';
      userId: UserId;
      enrollmentId: VoiceIdEnrollmentId;
      promptSetId: VoiceIdPromptSetId;
      evidenceTarget: {
        usableSpeechMs: number;
        promptSegmentCount: number;
      };
      evidenceProgress: {
        usableSpeechMs: number;
        acceptedPromptSegmentCount: number;
      };
      captureAttemptCount: number;
      expiresAt: IsoDateTime;
      templateVersion?: never;
    }
  | {
      kind: 'enrolled';
      userId: UserId;
      enrollmentId: VoiceIdEnrollmentId;
      modelVersion: VoiceIdModelVersion;
      templateVersion: VoiceIdTemplateVersion;
      assurance: 'research';
      enrolledAt: IsoDateTime;
      disabledAt?: never;
    }
  | {
      kind: 'disabled';
      userId: UserId;
      enrollmentId: VoiceIdEnrollmentId;
      modelVersion: VoiceIdModelVersion;
      templateVersion: VoiceIdTemplateVersion;
      assurance: 'research';
      disabledAt: IsoDateTime;
    };
```

```ts
type VoiceIdMvpVerificationResult =
  | {
      kind: 'experimental_accepted';
      evidence: VoiceIdExperimentalBrowserEvidence;
    }
  | {
      kind: 'rejected';
      verificationId: VoiceIdVerificationId;
      reason: VoiceIdMvpRejectionReason;
      observedChecks: VoiceIdObservedChecks;
      evidence?: never;
    }
  | {
      kind: 'uncertain';
      verificationId: VoiceIdVerificationId;
      reason: VoiceIdMvpUncertainReason;
      observedChecks: VoiceIdObservedChecks;
      evidence?: never;
    }
  | {
      kind: 'expired';
      verificationId: VoiceIdVerificationId;
      observedChecks?: never;
      evidence?: never;
    };
```

## Standalone Scaffold

Create a dedicated folder first:

```text
voiceId/
  README.md
  package.json
  tsconfig.json

  client/
    src/
      capture/
        microphone.ts
        mediaRecorder.ts
        audioBlob.ts
      enrollment/
        prompts.ts
        enrollmentClient.ts
      verification/
        verificationClient.ts
      domain/
        types.ts
        parsers.ts
        assertNever.ts

  shared/
    src/
      types.ts
      parsers.ts
      result.ts
      prompts.ts
      assertNever.ts

  server/
    src/
      VoiceIdService.ts
      VoiceIdEnrollmentStore.ts
      VoiceIdVerifier.ts
      routes.ts
      domain/
        types.ts
        parsers.ts
        assertNever.ts

  verifier/
    README.md
    pyproject.toml
    voiceid_verifier/
      __init__.py
      app.py
      audio_quality.py
      embeddings.py
      scoring.py

  verifier-spike/
    README.md
    pyproject.toml
    compare_models.py

  demo/
    src/
      index.html
      main.ts
      styles.css

  fixtures/
    prompts.json
    verification-results.json

  tests/
    enrollment.typecheck.ts
    verification.typecheck.ts
    enrollment.unit.test.ts
    verification.unit.test.ts
```

Rationale:

1. `voiceId/client` proves browser capture without touching the wallet SDK.
2. `voiceId/shared` keeps client and server domain types aligned.
3. `voiceId/server` proves lifecycle, stores, routes, and policy boundaries.
4. `voiceId/verifier` isolates model/runtime dependencies. Python is acceptable
   here because speaker-verification model tooling is strongest in Python.
5. `voiceId/demo` exposes a tiny enroll/verify UI before wallet integration.
6. The folder can later be split into package exports or merged into existing
   SDK/server boundaries after the API stabilizes.

## API Draft

Enrollment endpoints:

```http
POST /voice-id/enrollment/start
POST /voice-id/enrollment/capture
POST /voice-id/enrollment/finalize
POST /voice-id/enrollment/disable
```

Verification endpoints:

```http
POST /voice-id/verification/start
POST /voice-id/verification/capture
```

Request boundary rules:

1. Route handlers parse multipart audio and JSON metadata once.
2. Route handlers convert raw request data into precise internal types.
3. Core services accept `VoiceIdEnrollmentCapture` and
   `VoiceIdVerificationCapture`, not raw bodies or raw blobs.
4. Verifier vendor/model responses are parsed once into
   `VoiceIdSpeakerMatchResult`.

## Client MVP

Browser client responsibilities:

1. Request microphone permission.
2. Record one guided enrollment session and one short verification clip.
3. Display prompted phrases.
4. Upload audio as `Blob` plus structured metadata.
5. Surface quality feedback: too quiet, too short, too noisy, retry.
6. Never store raw enrollment audio beyond the active browser session.

Standalone demo page:

```text
voiceId/demo
  -> Enroll VoiceID
  -> Verify VoiceID
  -> Show phrase result, speaker score, threshold, and final decision
```

The demo should make model quality visible before any wallet/auth integration.

Initial capture path:

```text
getUserMedia
  -> MediaRecorder
  -> Blob
  -> upload multipart/form-data
```

Future capture path:

```text
getUserMedia
  -> AudioWorklet
  -> deterministic PCM analysis derivative and capture settings
  -> local VAD / quality hints / prompt segmentation
  -> streaming upload
```

Client capture metadata is diagnostic. The server computes duration and quality
from decoded audio. Browser device ids and timestamps do not prove trusted
microphone provenance. The upload preserves and hashes the original bytes
emitted by the capture API; analysis derivatives never upgrade browser evidence
beyond E0.

## Server MVP

Server responsibilities:

1. Issue and persist enrollment and verification challenges, prompts, expiry,
   and expected capture profile.
2. Track enrollment and verification attempt state.
3. Validate audio quality before model inference.
4. Call the verifier runtime.
5. Store encrypted speaker templates.
6. Apply attempt limits, expiry, and rate limits.
7. Return typed result unions.
8. Delete raw audio after extraction/verification unless diagnostics are
   explicitly enabled.
9. Recompute the exact original-audio hash and treat client timestamps, MIME,
   device labels, and source claims as advisory.

Privacy and retention requirements:

1. Raw enrollment audio is deleted after embedding extraction.
2. Raw verification audio is deleted after the result is computed.
3. Embeddings and templates are encrypted at rest.
4. Diagnostic retention requires explicit opt-in and a retention window.
5. Audit logs store score bands and result kinds, not raw audio or raw model
   tensors.

Storage tables or records:

```ts
type VoiceIdEnrollmentRecord = {
  userId: UserId;
} & (
  | {
      state: 'pending';
      enrollmentId: VoiceIdEnrollmentId;
      modelVersion: VoiceIdModelVersion;
      createdAt: IsoDateTime;
      expiresAt: IsoDateTime;
      templateVersion?: never;
      encryptedTemplate?: never;
      enrolledAt?: never;
      disabledAt?: never;
    }
  | {
      state: 'enrolled';
      enrollmentId: VoiceIdEnrollmentId;
      modelVersion: VoiceIdModelVersion;
      templateVersion: VoiceIdTemplateVersion;
      assurance: 'research';
      encryptedTemplate: EncryptedBytes;
      createdAt: IsoDateTime;
      enrolledAt: IsoDateTime;
      disabledAt?: never;
    }
  | {
      state: 'disabled';
      enrollmentId: VoiceIdEnrollmentId;
      modelVersion: VoiceIdModelVersion;
      templateVersion: VoiceIdTemplateVersion;
      assurance: 'research';
      encryptedTemplate: EncryptedBytes;
      createdAt: IsoDateTime;
      enrolledAt: IsoDateTime;
      disabledAt: IsoDateTime;
    }
);
```

```ts
type VoiceIdVerificationRecord = {
  userId: UserId;
  enrollmentId: VoiceIdEnrollmentId;
  challengeId: VoiceIdChallengeId;
  expectedPhrase: VoiceIdPromptPhrase;
} & (
  | {
      state: 'issued';
      verificationId: VoiceIdVerificationId;
      createdAt: IsoDateTime;
      expiresAt: IsoDateTime;
      completedAt?: never;
      result?: never;
    }
  | {
      state: 'experimental_accepted' | 'rejected' | 'uncertain';
      verificationId: VoiceIdVerificationId;
      createdAt: IsoDateTime;
      expiresAt: IsoDateTime;
      completedAt: IsoDateTime;
      result: VoiceIdMvpVerificationResult;
    }
  | {
      state: 'expired';
      verificationId: VoiceIdVerificationId;
      createdAt: IsoDateTime;
      expiresAt: IsoDateTime;
      completedAt: IsoDateTime;
      result?: never;
    }
);
```

## Verifier MVP

The verifier should be a narrow internal service or local process. It should
expose only stable typed operations:

```text
extractEnrollmentSegments(capture, promptTimeline) -> normalized embeddings + quality + coherence
buildTemplate(acceptedSegments) -> normalized weighted template + quality
verifyPhrase(capture, storedChallenge) -> phrase result
verifySpeaker(capture, template) -> speaker result
```

The first verifier can be Python-backed:

1. Normalize/resample audio.
2. Run voice activity detection.
3. Extract log-mel/MFCC-like features.
4. Extract speaker embedding with a pretrained model.
5. Compare with cosine similarity.
6. Return score, threshold, model version, and quality metadata.

Do not leak raw model outputs into core server logic.

Python verifier rationale:

1. The strongest pretrained speaker-verification tooling is currently in
   Python/PyTorch.
2. Python keeps model selection, VAD, feature extraction, and checkpoint loading
   isolated from TypeScript lifecycle code.
3. The server receives typed verifier results only.
4. The boundary can later swap to a Rust verifier, vendor API, or browser/WASM
   verifier without changing VoiceID lifecycle state.

## SDK Integration Plan

After the standalone MVP proves the lifecycle:

1. Add a module boundary to the wallet/auth SDK.
2. Integrate `voiceId/client` as a per-operation evidence capability.
3. Integrate `voiceId/server` routes through a server capability module.
4. Keep VoiceID-specific lifecycle under the VoiceID module.
5. Let browser wallet UI consume E0 only and authorize the transaction through
   passkey.
6. Defer global wallet-auth-method unions and account projection until an E2
   product decision requires them.

Current test target: feed the experimental normal-SDK result into policy
shadowing without calling signing. The relay/module path can mount VoiceID
routes and exercise enrollment and verification. Browser signing is added only
through passkey admission for the same server-owned Router operation.

Target client module shape:

```ts
type VoiceEvidenceCapability = {
  beginTransactionAuthorization(
    input: VoiceIdTransactionAuthorizationInput,
  ): Promise<VoiceIdTransactionAuthorizationStartResult>;
};
```

Target registration shape:

```ts
type VoiceIdRouterApiModule = {
  kind: 'voice_id_router_api_module';
  routes: VoiceIdRoutes;
};
```

Module integration rules:

1. VoiceID routes register through a server module, not by editing unrelated
   server routers directly.
2. VoiceID capture registers through `VoiceEvidenceCapability`, without adding
   VoiceID to global auth-method state.
3. Browser policy consumes `VoiceIdExperimentalBrowserEvidence` and exposes
   passkey as the authorizing continuation.
4. VoiceID lifecycle, stores, and verifier code stay under the VoiceID module.
5. E0/E1 never carry a grant, admission, or signing continuation.

## Validation

MVP type fixtures:

1. `enrollmentId` cannot appear on `not_enrolled`.
2. `templateVersion` cannot appear on `enrollment_pending`.
3. `disabledAt` cannot appear on `enrolled`.
4. `experimental_accepted` verification requires complete observed phrase,
   speaker, and quality results and carries E0 only.
5. `rejected` verification requires a rejection reason.
6. Core services reject raw request bodies.
7. `pending` enrollment records cannot contain encrypted templates.
8. `issued` verification records cannot contain completed results.
9. E0/E1 cannot construct a grant, reserved admission, or signing continuation.

MVP runtime tests:

1. Enrollment rejects insufficient usable speech.
2. Enrollment rejects low-quality, duplicate, multi-speaker, and incoherent
   segments.
3. Finalize rejects insufficient prompt coverage or template coherence.
4. Verification rejects expired prompts.
5. Verification rejects phrase mismatch.
6. Verification rejects speaker mismatch.
7. Verification returns uncertain for low-quality runtime audio.
8. Verification accepts matching speaker and phrase.

Phase gates:

1. **Gate 1**: fake verifier enrollment/verification state machines pass type
   fixtures and unit tests.
2. **Gate 2**: browser demo captures audio and completes fake enrollment and
   verification.
3. **Gate 3**: verifier spike shows usable same-user/different-user score
   separation.
4. **Gate 4**: Python verifier works through the typed server boundary.
5. **Gate 5**: encrypted template storage and retention rules are tested.
6. **Gate 6**: route integration into the existing server is added.
7. **Gate 7**: wallet/auth SDK module registration is added.
8. **Gate 8**: browser transaction UX signs only after passkey user verification
   for the same Router operation.
9. **Gate 9**: E2 remains disabled until an approved embedded capture and PAD
   profile passes the signing security gates.

## Implementation Order

1. Create `voiceId/` scaffold with domain types and fake verifier.
2. Add `voiceId/shared` for shared domain types and parsers.
3. Implement browser capture and upload against the fake server.
4. Implement the standalone demo page.
5. Implement server enrollment and verification state machines.
6. Add type fixtures for lifecycle guarantees.
7. Add fake verifier tests for all result branches.
8. Run the verifier spike and choose the first model.
9. Add Python verifier proof of concept behind the verifier boundary.
10. Add encrypted template storage and retention tests.
11. Add route integration into existing server after standalone tests pass.
12. Add SDK module registration points.
13. Wire `voiceId/client` into the SDK as a per-operation
    `VoiceEvidenceCapability` without widening global wallet auth-method unions.

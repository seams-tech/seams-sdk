# VoiceID MVP 2

Status: exploratory implementation spec.

This document scopes the second VoiceID MVP. MVP 1 proves browser capture,
typed lifecycle state, fake verification, fixture collection, and the model
spike. MVP 2 turns that scaffold into a real owner-presence signal that can feed
wallet, robot, and MPC policy.

## Purpose

Build a production-shaped VoiceID policy signal that can:

1. Verify speaker similarity with the selected ECAPA model.
2. Gate low-quality audio before speaker scoring.
3. Verify spoken phrases or commands through a transcript boundary.
4. Bind accepted speech to a canonical intent digest.
5. Add audio-visual liveness signals for embedded robotics.
6. Feed a typed owner-presence result into wallet/MPC policy.

VoiceID remains a recoverable owner-presence and liveness signal. The actual
cryptographic operation still comes from device-bound key material, MPC shares,
server policy, or another signing primitive.

## Scope Boundary

MVP 2 includes:

1. ECAPA-backed Python verifier integration.
2. Quality-first audio decision policy.
3. Fixture expansion and threshold calibration.
4. Transcript provider integration for phrase and command checks.
5. Intent digest binding for wallet sessions, token transfers, and robot
   commands.
6. Audio-visual liveness policy for robot/embedded flows.
7. Typed policy output for wallet/MPC signing session decisions.

MVP 2 does not include:

1. Training a custom speaker-verification model.
2. Treating voice as a cryptographic signature.
3. Full spoof-proof guarantees.
4. A final production storage/backend choice.
5. Requiring phone OTP when audio-visual liveness is available and policy
   accepts the risk.

## Architecture

```text
Browser or embedded device
  -> audio capture
  -> optional camera capture for embedded flows
  -> VoiceID client/module
  -> VoiceID server routes or local robot sidecar
  -> quality gate
  -> transcript provider
  -> ECAPA speaker verifier
  -> optional audio-visual liveness policy
  -> intent canonicalizer
  -> owner-presence policy result
  -> wallet/MPC/robot policy
```

Ownership boundaries:

- `voiceId/client`: capture, upload, browser lifecycle, and UI/demo hooks.
- `voiceId/server`: route parsing, service state, stores, policy assembly, and
  typed results.
- `voiceId/verifier`: ECAPA runtime, audio normalization, VAD, quality checks,
  embedding extraction, template building, and scoring.
- `voiceId/verifier-spike`: offline model comparison and calibration reports.
- `voiceId/research`: source PDFs and brief literature review.
- future embedded sidecar: local process on the robot that hosts capture,
  local policy, and optional wallet sidecar integration.

## Resolved Spec Decisions

### 1. Verifier Runtime Mode

Use a Python verifier process for MVP 2.

The ECAPA model does not run in the browser or in the iOS app for this MVP. It
runs behind the VoiceID service boundary:

- Browser deployment: browser captures audio and uploads it to the VoiceID API;
  the server calls the Python verifier sidecar.
- Mobile iOS deployment: native or web capture records audio and uploads it to
  the same VoiceID API; the server calls the Python verifier sidecar.
- Robot-local deployment: the robot app captures audio/video and calls a local
  Python verifier sidecar running on the robot or a nearby embedded computer.
- Server-backed robot deployment: the robot uploads typed captures to a remote
  VoiceID server, which calls the Python verifier sidecar.

Client platforms need capture adapters, not separate speaker-verifier
implementations:

- browser: `getUserMedia` plus `MediaRecorder`
- iOS native: `AVAudioEngine` or equivalent native audio capture
- robot: microphone/camera capture from the robot runtime

All clients send the same typed request shape to the VoiceID boundary. The
server or local sidecar owns decoding, normalization, VAD, quality checks,
embedding extraction, scoring, and threshold policy.

On-device browser or iOS verification is a later portability track. If we need
it, evaluate ONNX/Core ML/WASM/Rust verifier targets after the Python sidecar
proves the policy and model behavior. Do not make the MVP client bundle carry
PyTorch, SpeechBrain, or model weights.

### 2. Quality Gate Semantics

Speaker scoring runs only after audio quality accepts the capture.

Recommended outcomes:

- undecodable, corrupted, or header-only audio -> `uncertain`
- too short -> `uncertain`
- low speech duration -> `uncertain`
- low SNR or excessive background noise -> `uncertain`
- clipped or saturated audio -> `uncertain`
- phrase mismatch -> `rejected`
- speaker mismatch after quality acceptance -> `rejected`
- verifier unavailable -> `uncertain`

This keeps bad capture conditions out of the hard-rejection path and avoids
training policy code to treat microphone problems as identity failures.

### 3. Template Format

Use the mean of accepted ECAPA enrollment embeddings as the MVP owner template.

Store with each enrolled template:

- encrypted mean embedding
- model id: `speechbrain/spkrec-ecapa-voxceleb`
- adapter id
- embedding dimension
- template version
- threshold version
- enrollment sample count
- prompt set id
- created-at timestamp

Raw enrollment and verification audio should not be persisted by default.
Diagnostic retention requires explicit opt-in and a retention window.

### 4. Threshold Config

Use the current ECAPA fixture threshold only as `local_dev_v1`.

Rules:

- Store the threshold version with each template and verification result.
- Recalibrate before production policy use.
- Require independent human different-speaker fixtures before tightening the
  threshold.
- Keep noisy/low-quality fixtures out of hard false-accept/false-reject counts
  unless the quality policy accepts them.

### 5. Fixture Targets

Minimum fixture target before hardening thresholds:

- 3-5 owner enrollment clips
- 5 or more owner verification clips
- 5 or more independent human different-speaker clips
- 3 or more wrong-phrase clips
- 3 or more noisy clips
- 3 or more too-short or corrupt clips

Next fixture target before spoof-resistance claims:

- speaker-playback replay clips
- TTS or voice-clone clips
- robot microphone clips
- owner clips across multiple days, distances, and background conditions

### 6. Transcript Provider

Keep the fake transcript provider for tests. Add one real ASR provider after
ECAPA integration and quality gating are stable.

Recommended first real provider: Deepgram, because it has a public API and fits
the server-side transcript-provider boundary. ElevenLabs and Wispr Flow remain
useful to track for voice-agent UX, but they are not the speaker-verification
foundation.

Transcript results stay separate from speaker results. ASR decides what the user
said; ECAPA decides whether the voice sounds like the enrolled owner.

### 7. Intent Digest Schema

Define a canonical intent before wallet/MPC policy integration.

Required fields:

- intent kind
- action verb
- asset
- amount
- recipient
- source account or wallet id
- chain/network
- device id
- issued-at timestamp
- expiry timestamp
- nonce

Optional fields by intent kind:

- robot command id
- wallet session id
- spending limit
- memo or reference id

Any change to amount, recipient, device, chain, expiry, nonce, or command
changes the `intentDigest`.

### 8. Policy Result Shape

Use `VoiceIdOwnerPresenceResult` as the only wallet/robot-facing result.

Browser-only experiments may set liveness to `not_required` through explicit
policy config. Embedded privileged actions require liveness; missing liveness
returns `uncertain` or triggers step-up.

### 9. Storage Boundary

Use in-memory storage for local MVP tests. Durable storage must encrypt
templates and store model/threshold metadata.

Recommended storage rule:

- persistence stores encrypted templates and typed audit events
- persistence does not store raw audio by default
- request compatibility handling belongs at route/storage boundaries only
- core verifier and policy code receives typed internal records

Before real users, define where the template encryption key lives. For robot
local mode, this may be the robot sidecar keystore or OS keychain equivalent.
For server mode, this should be a server-managed KMS or equivalent secret
manager.

### 10. Audio-Visual Liveness Timing

Define liveness types in MVP 2. Full visual tracking can wait until a robot or
camera target is active.

The first liveness implementation should check:

- audio capture time window
- camera frame time window
- face present during speech
- mouth movement during speech
- rough correlation between mouth movement and audio energy

### 11. Fallback Models

Do not implement multiple verifier stacks up front.

Use ECAPA first. Compare fallback models only if ECAPA fails a concrete
requirement:

- x-vector for a classic baseline
- pyannote if access/licensing/deployment weight are acceptable
- TitaNet/NeMo if a heavier NVIDIA stack becomes useful

## Core Result Shape

MVP 2 should expose one policy result to wallet or robot code:

```ts
type VoiceIdOwnerPresenceResult =
  | {
      kind: 'accepted';
      userId: UserId;
      enrollmentId: VoiceIdEnrollmentId;
      verificationId: VoiceIdVerificationId;
      intentDigest: IntentDigest;
      speaker: VoiceIdSpeakerMatchResult;
      phrase: VoiceIdPhraseMatchResult;
      quality: VoiceIdAudioQualityResult;
      liveness: VoiceIdLivenessResult;
      modelVersion: VoiceIdModelVersion;
      thresholdVersion: VoiceIdThresholdVersion;
      expiresAt: IsoDateTime;
    }
  | {
      kind: 'rejected';
      verificationId: VoiceIdVerificationId;
      reason:
        | 'phrase_mismatch'
        | 'speaker_mismatch'
        | 'liveness_mismatch'
        | 'intent_mismatch'
        | 'expired'
        | 'too_many_attempts';
      intentDigest?: IntentDigest;
      modelVersion?: VoiceIdModelVersion;
      thresholdVersion?: VoiceIdThresholdVersion;
    }
  | {
      kind: 'uncertain';
      verificationId: VoiceIdVerificationId;
      reason:
        | 'low_audio_quality'
        | 'no_speech_detected'
        | 'low_snr'
        | 'clipped_audio'
        | 'model_low_confidence'
        | 'transcript_unavailable'
        | 'liveness_unavailable'
        | 'verifier_unavailable';
      intentDigest?: IntentDigest;
      modelVersion?: VoiceIdModelVersion;
      thresholdVersion?: VoiceIdThresholdVersion;
    };
```

Accepted results require accepted phrase, speaker, quality, liveness, and intent
checks for embedded signing flows. Browser-only policy experiments may configure
liveness as `not_required` only when the policy explicitly allows it.

## Workstream 1: ECAPA Verifier Integration

Goal: replace placeholder embeddings with the selected pretrained verifier.

Implementation tasks:

1. Load `speechbrain/spkrec-ecapa-voxceleb` once per Python verifier process.
2. Decode, normalize, and resample audio to the model input format.
3. Extract 192-dimensional enrollment embeddings.
4. Build an owner template from accepted enrollment embeddings.
5. Extract verification embeddings.
6. Score verification with cosine similarity against the owner template.
7. Return score, threshold, model id, adapter id, template version, and
   threshold version.
8. Keep raw model tensors inside `voiceId/verifier`.
9. Parse verifier output once in the TypeScript adapter.
10. Keep PyTorch, SpeechBrain, and model weights out of browser and iOS client
    bundles.

Validation:

1. Existing fake verifier tests still pass.
2. Python schema tests cover accepted, rejected, and uncertain ECAPA branches.
3. TypeScript adapter tests cover ECAPA model metadata and threshold metadata.
4. Fixture evaluation reproduces the ECAPA spike score ranges within expected
   numerical tolerance.
5. Bundle checks confirm client builds do not include verifier/model packages.

## Workstream 2: Quality-First Gating

Goal: reject or mark bad captures as `uncertain` before speaker scoring.

Quality signals:

1. Minimum duration.
2. Minimum speech duration after VAD.
3. Byte length and container sanity.
4. Clipping and saturation ratio.
5. Signal-to-noise estimate.
6. Silence percentage.
7. Unsupported sample rate or channel layout after decode.
8. Header-only or truncated recording detection.

Decision rules:

1. Too-short clips return `uncertain`.
2. Header-only, corrupted, or undecodable clips return `uncertain`.
3. Low-speech or low-SNR clips return `uncertain`.
4. Speaker scoring runs only after quality accepts the capture.
5. Quality metadata is logged without storing raw audio.

Validation:

1. Existing too-short fixtures return `uncertain`.
2. Noisy owner fixtures return `uncertain` unless the calibrated quality policy
   accepts them.
3. Clean owner verification fixtures can proceed to speaker scoring.

## Workstream 3: Fixtures And Calibration

Goal: build enough evidence to choose a reasonable operating threshold.

Fixture additions:

1. Independent human different-speaker clips.
2. More owner verification clips across days and distances.
3. More owner enrollment clips across stable microphone setups.
4. Replay clips from a speaker.
5. TTS or voice-clone style clips when available.
6. Noisy clips with controlled background noise levels.
7. Wrong-phrase clips with similar phonetics.
8. Robot microphone clips if Reachy or another embedded target is available.

Calibration outputs:

1. Same-user score distribution.
2. Different-speaker score distribution.
3. Wrong-phrase speaker score distribution.
4. Noisy/low-quality score distribution.
5. False accepts and false rejects at candidate thresholds.
6. Recommended threshold version and fixture manifest hash.

Validation:

1. Threshold report records model version, data manifest, and scoring backend.
2. Report separates phrase failures from speaker failures.
3. Report separates noisy/uncertain captures from hard negatives.

## Workstream 4: Transcript And Intent Binding

Goal: bind speech to the concrete action being authorized.

Transcript provider boundary:

```text
audio clip
  -> ASR/transcript provider
  -> transcript result
  -> command parser
  -> canonical intent
  -> intent digest
```

Canonical intents:

1. `send 1 USDC to Bob`
2. `send 50 USDC to bob.near`
3. `authorize wallet session for device X`
4. `run robot command Y until time T`

Rules:

1. Speaker verification does not decide command correctness.
2. Transcript confidence below threshold returns `uncertain`.
3. Ambiguous command parses return `uncertain`.
4. Amount, asset, recipient, device id, expiry, and nonce are included in the
   canonical intent.
5. Any change to amount, recipient, device, expiry, or nonce changes
   `intentDigest`.
6. Verification acceptance is scoped to exactly one `intentDigest`.

Validation:

1. Same command and parameters produce the same digest.
2. Different command parameters produce different digests.
3. A VoiceID result cannot authorize a different intent.
4. Expired intents cannot be accepted.

## Workstream 5: Audio-Visual Liveness

Goal: add owner-presence signals for embedded robot flows where phone OTP is
optional.

Audio liveness signals:

1. Fresh microphone capture.
2. Speech starts after the prompt or command window opens.
3. Speech duration is plausible for the command.
4. Replay-risk heuristics from audio quality and channel artifacts.

Visual liveness signals:

1. Face present near the robot.
2. Mouth movement detected during the speech window.
3. Audio energy roughly correlates with mouth movement timing.
4. Face track is present before and during the command.
5. Camera frame timestamp overlaps the audio capture window.

Policy:

1. Embedded privileged actions require audio liveness and visual liveness.
2. Missing camera or failed visual liveness returns `uncertain` for privileged
   actions.
3. Phone/watch OTP remains an optional step-up factor for high-value or
   uncertain flows.

Validation:

1. Accepted liveness requires overlapping audio and video timestamps.
2. Audio-only replay without mouth movement fails embedded liveness policy.
3. Visual-only presence without accepted speaker verification fails policy.
4. Missing liveness does not silently downgrade into accepted policy.

## Workstream 6: Wallet, MPC, And Robot Policy

Goal: consume VoiceID as owner presence for policy decisions.

Wallet/MPC policy flow:

```text
VoiceID accepted owner presence
  + intentDigest
  + device/session policy
  -> signing-session policy decision
  -> MPC signing session or rejection
```

Robot policy flow:

```text
owner voice + optional face/liveness
  -> accepted owner command
  -> robot performs allowed command

non-owner voice
  -> optional x402/payment flow
  -> robot performs paid public command if payment settles
```

Rules:

1. VoiceID never directly signs.
2. VoiceID outputs typed policy evidence.
3. MPC policy decides whether an owner-presence result can create a signing
   session.
4. Signing sessions bind to `intentDigest`, expiry, device id, and nonce.
5. High-value actions can require additional factors.

Validation:

1. Accepted owner presence can authorize only the matching intent.
2. Rejected or uncertain VoiceID cannot create a signing session.
3. MPC signing refuses stale or mismatched intent digests.
4. Audit events include result kinds and score bands, not raw audio.

## Deployment Shape

Browser-first deployment:

```text
browser demo
  -> VoiceID API
  -> Python verifier sidecar
  -> in-memory or durable template store
```

Robot-local deployment:

```text
reachy_app.py or robot app
  -> local Rust or Python wallet_sidecar
  -> local VoiceID sidecar
  -> optional server policy
  -> MPC signing/session service
```

Server-backed deployment:

```text
browser or robot
  -> VoiceID server routes
  -> verifier service
  -> encrypted template store
  -> policy/MPC service
```

The same typed result boundaries should support all three deployment shapes.

## Acceptance Criteria

MVP 2 is ready for policy experiments when:

1. ECAPA verifier works through the existing TypeScript verifier interface.
2. Quality-first gating prevents bad clips from reaching accepted speaker
   results.
3. Expanded fixture report includes independent human different-speaker clips.
4. Threshold version and model version are stored with templates.
5. Transcript/phrase verification is separate from speaker scoring.
6. Intent digest binding prevents reuse across commands.
7. Embedded liveness can combine audio and visual signals into typed policy
   results.
8. Wallet/MPC policy consumes VoiceID as owner presence only.
9. Raw audio retention remains disabled by default.

## Implementation Order

1. Wire ECAPA into `voiceId/verifier`.
2. Add quality-first gates and tests.
3. Add ECAPA model metadata to TypeScript verifier adapter responses.
4. Expand fixtures and rerun calibration reports.
5. Add canonical intent and `intentDigest` types.
6. Add transcript provider config for one real ASR provider.
7. Add wallet/robot policy result type.
8. Add audio-visual liveness types and local policy implementation.
9. Add embedded/robot sidecar architecture proof of concept.
10. Connect accepted owner-presence results to wallet/MPC policy simulation.

## Research Basis

The short literature review in `voiceId/research/README.md` supports this plan:

1. ECAPA/x-vector style embeddings are standard speaker-verification practice.
2. ASVspoof and speech deepfake literature treat spoof detection as a separate
   countermeasure layer.
3. Audio-visual spoofing work supports transcript and synchrony checks for
   liveness-sensitive command flows.
4. The product architecture should keep speaker, phrase, quality, liveness, and
   policy as separate typed branches.

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
5. Feed a typed owner-presence result into wallet/MPC policy.

VoiceID remains a recoverable owner-presence and liveness signal. The actual
cryptographic operation uses the existing Router A/B signer architecture in
`docs/router-A-B-signer.md`: Router owns public admission and policy, normal
signing flows through the dedicated SigningWorker, and Deriver A/B remain off
the hot signing path except for setup/export/recovery/SigningWorker refresh.

Camera, face, mouth, and lip-sync extraction are outside MVP 2. They are tracked
in `docs/voiceID/voiceId-camera-liveness-future.md`.

## Scope Boundary

MVP 2 includes:

1. ECAPA-backed Python verifier integration.
2. Quality-first audio decision policy.
3. Fixture expansion and threshold calibration.
4. Transcript provider integration for phrase and command checks.
5. Intent digest binding for wallet sessions, token transfers, and robot
   commands.
6. Typed policy output for wallet/MPC signing session decisions.

MVP 2 does not include:

1. Training a custom speaker-verification model.
2. Treating voice as a cryptographic signature.
3. Full spoof-proof guarantees.
4. A final production storage/backend choice.
5. Camera, face, mouth, or lip-sync extraction.
6. Requiring phone OTP when policy accepts the risk without step-up.

## Architecture

```text
Browser or embedded device
  -> audio capture
  -> VoiceID client/module
  -> VoiceID server routes or local robot sidecar
  -> quality gate
  -> transcript provider
  -> ECAPA speaker verifier
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
- robot-local sidecar: local process on the robot that hosts capture, local
  owner-presence policy, liveness, and optional wallet sidecar integration. The
  current runbook lives at `voiceId/deploy/robot-local/sidecar/README.md`, with
  `pnpm -C voiceId robot:guard` covering the shared Python HTTP verifier API
  and Cloudflare-hosted policy boundary.
- Cloudflare deployment: Workers/Pages host capture-facing API and static demo,
  Workers AI handles ASR where possible, D1/Durable Objects store typed state
  and Router A/B signer state, R2 stores opt-in diagnostics, Cloudflare
  Containers host the Python ECAPA verifier sidecar, and the existing Router A/B
  SigningWorker path performs MPC signing. The current container package lives
  at `voiceId/deploy/cloudflare/verifier-container/`, with
  `pnpm -C voiceId container:guard` covering the Dockerfile, `.dockerignore`,
  Python package metadata, and runbook shape.
- SDK relay integration: wallet/auth relay routers expose
  `RelayRouterOptions.routeExtensions` and generic `RelayRouterModule`
  registration, with Cloudflare-only, Express-only, and universal runtime
  branches. `createVoiceIdRelayRouteExtension()` converts a VoiceID server
  capability into a universal relay extension, and
  `createVoiceIdRelayRouterModule()` wraps that extension in the SDK module
  shape. Concrete VoiceID stores, verifiers, transcript providers, and liveness
  policy remain owned by `voiceId/`.
- Optional SDK portability: API Gateway/ALB plus ECS/EKS/EC2 can host the same
  API and Python verifier sidecar on ordinary servers. High-assurance
  SigningWorker custody or template-key custody can also move into AWS Nitro
  Enclaves behind a parent-instance bridge. These are optional SDK portability
  references, not the primary deployment target. The current ordinary-server
  runbook lives at
  `voiceId/deploy/aws/verifier-service/README.md`, with
  `pnpm -C voiceId aws:guard` covering the shared Python HTTP sidecar contract.

## Resolved Spec Decisions

### 1. Verifier Runtime Mode

Use a Python verifier process for MVP 2.

The ECAPA model does not run in the browser or in the iOS app for this MVP. It
runs behind the VoiceID service boundary:

- Browser deployment: browser captures audio and uploads it to the VoiceID API;
  the server calls the Python verifier sidecar.
- Mobile iOS deployment: native or web capture records audio and uploads it to
  the same VoiceID API; the server calls the Python verifier sidecar.
- Robot-local deployment: the robot app captures audio and calls a local
  Python verifier sidecar running on the robot or a nearby embedded computer.
- Server-backed robot deployment: the robot uploads typed captures to a remote
  VoiceID server, which calls the Python verifier sidecar.
- Cloudflare-backed deployment: browser, mobile, or robot clients call a
  Cloudflare Worker API. The Worker performs request parsing, policy assembly,
  ASR calls, state writes, and intent binding, then calls a Python verifier
  running in a Cloudflare Container over the same HTTP sidecar interface. If the
  policy accepts the owner-presence result, the Worker admits the request into
  the existing Router A/B normal-signing path; SigningWorker performs the MPC
  server-share operation.
- Optional AWS-backed SDK portability: browser, mobile, or robot clients can
  call the API running on ordinary AWS infrastructure. The Python verifier can
  run as a normal HTTP sidecar or service. TEE-sensitive SigningWorker material,
  template-key unwrap, or SigningWorker server-share operations can run inside a
  Nitro Enclave, with the parent EC2 instance translating the service request
  into enclave-local vsock messages.

The TypeScript API selects the verifier transport with
`VOICEID_VERIFIER_TRANSPORT=fake|python-subprocess|python-http`. The Python
verifier selects its model backend with `VOICEID_VERIFIER_BACKEND`, currently
`placeholder` or `ecapa`.

Cloudflare compatibility is a first-class constraint. Keep PyTorch,
SpeechBrain, ffmpeg, and ECAPA model weights out of ordinary Workers and Python
Workers; those dependencies belong in the verifier Container or in a robot-local
sidecar. Worker code should stay TypeScript-first and use typed HTTP/service
bindings to reach the verifier. Avoid Node-only APIs in shared request, policy,
intent, and storage modules unless they are isolated behind a server adapter.
The current verifier Container uses the same Python HTTP sidecar endpoints as
local development, binds to `0.0.0.0:8797`, supports optional ECAPA model
preload through `PRELOAD_ECAPA_MODEL=1`, and stores model caches under
container-local cache paths.

AWS compatibility is an optional SDK portability constraint. Keep the verifier
and policy interfaces transport-neutral enough to run on plain AWS servers,
ECS/EKS, or EC2 if needed. Nitro Enclaves are suitable for high-assurance secret
handling, SigningWorker custody, and server-share policy, but they have no
ordinary network access or persistent local storage. Anything inside an enclave
must communicate through the parent instance bridge, usually over vsock, and any
persistent state must live outside the enclave with authenticated/encrypted
request boundaries. The current Nitro bridge runbook lives at
`voiceId/deploy/aws/nitro-enclave-bridge/README.md`, with
`pnpm -C voiceId nitro:guard` covering the no-raw-audio, no-ECAPA-runtime,
attestation, KMS, Router A/B, and SigningWorker boundaries.

Client platforms need capture adapters, not separate speaker-verifier
implementations:

- browser: `getUserMedia` plus `MediaRecorder`
- iOS native: `AVAudioEngine` or equivalent native audio capture
- robot: microphone capture from the robot runtime

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
- verifier unavailable -> service-level `verifier_unavailable` error

This keeps bad capture conditions out of the hard-rejection path and avoids
training policy code to treat microphone problems as identity failures.
Verifier outages stay outside biometric result scoring so callers can retry or
route to another sidecar without recording a false identity outcome.

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

Keep the fake transcript provider for tests. The first real ASR provider is now
Cloudflare Workers AI using `@cf/openai/whisper`, selected because it is the
cheapest current hosted option for short MVP command clips and stays inside the
Cloudflare deployment path.

Enable it with:

```sh
VOICEID_TRANSCRIPT_PROVIDER=cloudflare-workers-ai
VOICEID_CLOUDFLARE_ASR_MODEL=@cf/openai/whisper
```

The Worker also needs a Cloudflare Workers AI binding named `AI`. Deepgram
Nova-3 remains the fallback for low-latency streaming or better command accuracy
if Cloudflare Whisper is not good enough. ElevenLabs and Wispr Flow remain useful
to track for voice-agent UX, but they are not the speaker-verification
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
templates and store model/threshold metadata. Cloudflare deployments should use
D1 or Durable Objects for enrollment, verification, pending intent, consumed
intent, and audit records. Use R2 only for explicit diagnostic media
retention with a deletion policy.
AWS deployments should use DynamoDB or Postgres/RDS for typed records, S3 for
explicit diagnostic retention, and KMS-backed envelope encryption for templates
and policy secrets.

The current Cloudflare storage boundary lives in
`voiceId/server/src/store/CloudflareVoiceIdStorageRows.ts`. It serializes
enrollment and verification records into D1/Durable-Object-friendly rows, parses
raw rows back into typed domain records, rejects raw capture columns, and keeps
encrypted template material only on enrolled or disabled enrollment states.
The concrete D1-compatible store adapter lives in
`voiceId/server/src/store/CloudflareVoiceIdD1Stores.ts`. It exposes schema
statements for enrollment and verification tables, uses Cloudflare-style
`prepare(...).bind(...).first()` reads and `prepare(...).bind(...).run()`
writes, and keeps persisted rows parsed at the storage boundary before core
service code sees them. Durable Object storage can use the same row serializers
and either call D1 through the same adapter or implement the same store
interfaces locally.
The Cloudflare Worker factory in `voiceId/server/src/cloudflare.ts` selects this
path with `VOICEID_STORAGE_KIND=cloudflare-d1` and a `VOICEID_D1_DATABASE`
binding. The enrollment store is automatically wrapped with AES-GCM template
encryption before persistence; verification records go directly through the
typed D1 store.
Template encryption key configuration lives in
`voiceId/server/src/store/VoiceIdTemplateEncryptionConfig.ts`. Cloudflare
deployments use a Workers secret binding source:

```sh
VOICEID_TEMPLATE_KEY_SOURCE=cloudflare-workers-secret
VOICEID_TEMPLATE_KEY_ALGORITHM=AES-GCM-256
VOICEID_TEMPLATE_KEY_ID=voiceid-template-key-<version>
VOICEID_TEMPLATE_KEY_SECRET_BINDING=VOICEID_TEMPLATE_ENCRYPTION_KEY
VOICEID_TEMPLATE_KEY_ROTATION_VERSION=<rotation-version>
VOICEID_TEMPLATE_KEY_AAD_LABEL=voiceid-template-v1
```

Robot-local deployments use the same config shape with
`VOICEID_TEMPLATE_KEY_SOURCE=robot-local-secret` and
`VOICEID_TEMPLATE_KEY_SECRET_ENV=<local-secret-env-name>`. The config boundary
stores key references and rotation metadata, not secret values.

Template wrapping lives in
`voiceId/server/src/store/VoiceIdTemplateEncryption.ts`. The current wrapper
expects the secret value to decode to a 32-byte AES-GCM-256 key, encrypts
enrolled and disabled templates before persistence, and unwraps templates after
store reads before verifier scoring. The AES-GCM additional authenticated data
binds the envelope to the user id, enrollment id, model version, template
version, threshold version, key id, rotation version, and AAD label. A template
copied to another enrollment or read under a different key rotation fails to
unwrap.

Diagnostic retention config lives in
`voiceId/server/src/store/VoiceIdDiagnosticRetentionConfig.ts`. Diagnostics
default to disabled. Cloudflare deployments can opt into bounded R2 diagnostics:

```sh
VOICEID_DIAGNOSTIC_RETENTION=cloudflare-r2
VOICEID_DIAGNOSTIC_POLICY_VERSION=diagnostics-v1
VOICEID_DIAGNOSTIC_R2_BUCKET_BINDING=VOICEID_DIAGNOSTICS_BUCKET
VOICEID_DIAGNOSTIC_RETENTION_TTL_SECONDS=3600
VOICEID_DIAGNOSTIC_CAPTURE_AUDIO=true
VOICEID_DIAGNOSTIC_CAPTURE_VIDEO=false
VOICEID_DIAGNOSTIC_MAX_ARTIFACT_BYTES=1048576
```

Robot-local diagnostics use `VOICEID_DIAGNOSTIC_RETENTION=robot-local-files`
and `VOICEID_DIAGNOSTIC_LOCAL_DIRECTORY=<path>`. Enabled diagnostics require at
least one explicit raw capture type, a TTL between 60 seconds and 7 days, and a
bounded artifact size.

Recommended storage rule:

- persistence stores encrypted templates and typed audit events
- persistence does not store raw audio by default
- request compatibility handling belongs at route/storage boundaries only
- core verifier and policy code receives typed internal records

VoiceID audit events now include typed result kinds and coarse score bands.
Enrollment sample events record only a quality signal band. Verification
completion events record phrase-confidence, speaker-score, speaker-threshold,
and quality-signal bands. Audit events do not carry raw audio, raw media,
embedding vectors, or full raw model outputs.

Before real users, define where the template encryption key lives. For robot
local mode, this may be the robot sidecar keystore or OS keychain equivalent.
For Cloudflare mode, prefer Workers Secrets for MVP wiring and move to a
dedicated KMS/HSM-style envelope before production custody. The verifier
Container should receive only the minimum secret material required for template
decrypt/encrypt or should call back to the Worker/storage boundary for template
access.
For AWS mode, use KMS-backed envelope encryption as the ordinary server path.
For Nitro Enclave mode, bind KMS decrypt/use to enclave attestation and keep
plaintext template keys or MPC share material inside the enclave for the
shortest possible operation window.

### 10. Liveness Boundary

MVP 2 keeps a typed liveness/owner-presence result boundary so wallet, robot,
and Router A/B policy can distinguish accepted, rejected, and uncertain
branches. Camera-backed liveness timing is deferred to
`docs/voiceID/voiceId-camera-liveness-future.md`.

The current MVP liveness boundary should focus on:

- audio capture time window
- speech freshness
- microphone/source attestation when available
- replay-risk heuristics
- explicit `not_required` policy branches for browser-only experiments

### 11. Fallback Models

Do not implement multiple verifier stacks up front.

Use ECAPA first. Compare fallback models only if ECAPA fails a concrete
requirement:

- x-vector for a classic baseline
- pyannote if access/licensing/deployment weight are acceptable
- TitaNet/NeMo if a heavier NVIDIA stack becomes useful

## Provider-Grade Feature Track

Goal: evolve the local VoiceID stack toward the standard set by commercial
voice-biometric providers such as Veridas while preserving our wallet-specific
auth model.

The public Veridas materials set a useful bar:

- [Voice Authentication](https://veridas.com/en/voice-biometric-authentication/)
  describes short enrollment and authentication samples, provider-managed
  biometric vectors, same-person decisions, deployment modes, and anti-spoofing
  as part of the authentication result.
- [das-Peak introduction](https://docs.veridas.com/das-peak/cloud/v2.20/)
  describes text-independent speaker similarity between two recordings,
  preprocessing, voice activity detection, noise analysis, irreversible voice
  vectors, score output from 0 to 1, and threshold selection using FPR/FNR.
- [das-Peak main features](https://docs.veridas.com/das-peak/cloud/v2.20/main-features/)
  lists 3-second minimum voice duration, vector-to-audio comparison latency,
  text-independent and language-aware matching, VAD, noise detection,
  authenticity detection, calibration modes, capture SDKs, and immediate
  deletion of cloud-processed personal data.
- [Voice Shield](https://veridas.com/en/voice-shield/) frames the spoof layer
  around recorded, manipulated, and AI-generated audio.

These are product references, not guaranteed targets for our MVP. The plan is
to implement the same feature classes, measure them honestly against our
fixtures, and tighten model, threshold, and capture quality until the local
system is fast and accurate enough for wallet policy experiments.

### Feature 1: Short-Sample Enrollment And Authentication

User outcome: enroll this browser or device once, then authenticate the enrolled
speaker from a short fresh sample.

Implementation requirements:

1. Keep enrollment and verification text-independent at the speaker layer.
   The speaker verifier decides whether the voice matches the enrolled template;
   the ASR and intent parser decide what the user said.
2. Accept clean short clips once VAD confirms enough speech. The product target
   is 3 seconds of usable speech; the verifier must report actual speech
   duration separately from container duration.
3. Keep the current 3-sample enrollment UX for template quality, then support a
   provider-grade fast enrollment mode once calibration proves one short sample
   is reliable for the selected capture channel.
4. Build templates from normalized speaker embeddings with model id, adapter
   id, threshold version, calibration mode, prompt policy, device id, and
   fixture-manifest hash.
5. Store encrypted templates and typed audit events. Raw enrollment audio stays
   disabled by default, with explicit diagnostic retention windows only.
6. Bind every authentication attempt to an enrolled device proof and a fresh
   capture session. Browser experiments can use the demo device id; wallet use
   requires the same device-binding pattern as email OTP or passkey-adjacent
   auth method flows.
7. Return separate quality, speaker, phrase, liveness/authenticity, device, and
   policy branches. A failure in one branch must remain visible to callers.

Provider-grade acceptance:

1. Clean 3-second clips from the enrolled user authenticate reliably on the
   primary browser microphone profile.
2. Same-speaker and different-speaker distributions are calibrated from real
   independent human fixtures.
3. Threshold versions include FPR, FNR, false-accept, false-reject, fixture
   manifest, capture channel, model version, and scoring backend.
4. Warm verifier latency is measured separately for decode, VAD/quality,
   embedding, scoring, ASR, and policy.
5. The UX can show recording, processing, accepted, rejected, uncertain, and
   retry states without exposing raw model detail.

### Feature 2: Audio Clip Speaker Comparison

User outcome: compare two arbitrary audio clips and decide whether they likely
belong to the same speaker.

This feature should live beside enrollment/authentication, not inside the wallet
auth path. It is useful for fixture analysis, support tooling, provider parity,
and future admin/debug flows.

Implementation requirements:

1. Add a dedicated comparison service boundary:

   ```text
   clip A + clip B
     -> decode and normalize each clip
     -> quality and VAD for each clip
     -> embedding extraction for each accepted clip
     -> cosine score plus calibrated threshold
     -> same_speaker / different_speaker / uncertain result
   ```

2. Define a `VoiceIdClipComparisonResult` union with:
   - `kind: 'same_speaker'`
   - `kind: 'different_speaker'`
   - `kind: 'uncertain'`
3. Include per-clip quality outcomes, score, threshold, model id, adapter id,
   threshold version, calibration mode, and timing breakdown.
4. Keep phrase transcript, wallet intent, enrollment id, and signing authority
   out of the clip-comparison result.
5. Add route and test coverage behind the VoiceID module boundary. SDK wallet
   code should consume owner-presence grants, not raw clip-comparison output.
6. Reuse the same model runtime and calibration reports as enrollment
   verification so the feature does not fork into a second verifier stack.

Provider-grade acceptance:

1. Clean same-speaker pairs and independent different-speaker pairs separate at
   the chosen threshold in the fixture report.
2. Low-quality, too-short, multi-speaker, or undecodable pairs return
   `uncertain` before speaker scoring.
3. Reports include score histograms and confusion matrices for same-speaker,
   different-speaker, wrong-phrase, noisy, and replay/synthetic subsets.
4. The API can compare two uploaded clips without storing raw audio by default.

### Feature 3: Spoofing, Deepfake, And Replay Detection

User outcome: block or step up attempts that sound like the owner but appear to
be recorded, synthetic, injected, replayed, or otherwise non-live.

This is a separate authenticity layer. Speaker similarity alone does not prove a
fresh human is present. For wallet signing, authenticity should combine audio
countermeasures, dynamic phrase or intent binding, device binding, capture
freshness, rate limits, and policy.

Implementation requirements:

1. Add a `VoiceIdAuthenticityResult` union:

   ```ts
   type VoiceIdAuthenticityResult =
     | { kind: 'accepted'; modelVersion: VoiceIdModelVersion; score: number }
     | {
         kind: 'rejected';
         reason:
           | 'replay_suspected'
           | 'synthetic_voice_suspected'
           | 'voice_conversion_suspected'
           | 'injected_audio_suspected'
           | 'multi_speaker_suspected';
         modelVersion: VoiceIdModelVersion;
         score: number;
       }
     | {
         kind: 'uncertain';
         reason:
           | 'insufficient_speech'
           | 'low_audio_quality'
           | 'model_low_confidence';
         modelVersion: VoiceIdModelVersion;
         score: number;
       }
     | {
         kind: 'uncertain';
         reason: 'authenticity_model_unavailable';
         modelVersion?: never;
         score?: never;
       };
   ```

2. Keep authenticity separate from speaker match and phrase match in all service
   and wallet-facing results.
3. Start with replay-risk heuristics that are cheap and explainable:
   - exact or near-duplicate audio fingerprint across attempts
   - repeated waveform/embedding patterns for different requested intents
   - suspicious channel metadata or missing browser capture timing
   - speech starting before the prompt window
   - implausible duration for the requested phrase
4. Add a model-backed countermeasure track after fixtures exist. Candidate
   classes include ASVspoof-trained AASIST, RawNet-style models, SSL/Wav2Vec2
   spoof detectors, and vendor-style replay classifiers. Pick one model after a
   measured spike, then expose it behind the same Python verifier HTTP boundary.
5. Build attack fixtures before making product claims:
   - loudspeaker replay of owner enrollment and verification clips
   - phone speaker replay
   - synthetic TTS for matching phrases
   - voice-clone samples when we can generate or source them lawfully
   - injected file uploads that bypass live microphone capture
   - multi-speaker and background speech clips
6. Bind verification to a dynamic transaction phrase or intent digest. A replay
   of an older accepted command should fail because the phrase, nonce, expiry,
   device id, and intent digest changed.
7. Use step-up for high-risk or uncertain authenticity outcomes. VoiceID can
   authorize low-risk tasks when all branches accept; risky wallet work should
   require passkey, email OTP, phone, or another factor when authenticity is
   uncertain.

Provider-grade acceptance:

1. Replay, synthetic, injected, and multi-speaker subsets appear in the
   calibration report with separate false-accept and false-reject numbers.
2. The service records spoof-model version, threshold version, calibration mode,
   capture channel, and timing for every authenticity result.
3. Accepted wallet policy requires accepted quality, phrase/intent,
   speaker, device, and authenticity branches for flows that enable
   spoof-resistance policy.
4. The UI shows a single user-facing decision while preserving branch-level
   diagnostics for audit and development.
5. No production claim says "deepfake-proof". Claims must reference measured
   attack classes, fixture versions, and known limitations.

### Provider-Grade Phased TODO

Phase A: tighten the local short-sample auth loop.

- [x] ECAPA verifier path behind the Python sidecar.
- [x] Quality-first gates before speaker scoring.
- [x] Encrypted template storage boundary.
- [x] Dynamic command phrase and intent digest binding in the demo.
- [ ] Require and report speech duration independently from recording duration.
- [ ] Add capture-channel calibration modes: `browser-lossless`,
  `mobile-lossless`, `telephone-channel`, and `robot-microphone`.
- [ ] Add timing breakdowns to verifier, ASR, and policy responses.
- [ ] Add fixture reports that summarize FPR/FNR by capture channel and
  threshold version.

Phase B: add first-class clip comparison.

- [ ] Define `VoiceIdClipComparisonResult` in `voiceId/shared`.
- [ ] Add Python verifier request/response schemas for clip-to-clip comparison.
- [ ] Add TypeScript adapter parsing and tests.
- [ ] Add a server route for development and fixture tooling.
- [ ] Add fixture report output for clip-pair score distributions.

Phase C: build the authenticity layer.

- [ ] Define `VoiceIdAuthenticityResult` and thread it through verifier,
  policy, auth-policy adapter, and audit events.
- [ ] Add cheap replay heuristics: duplicate audio fingerprint, stale prompt
  timing, repeated command audio, and channel metadata checks.
- [ ] Add replay and injected-audio fixture capture scripts.
- [ ] Spike one ASVspoof-style model behind the Python HTTP verifier boundary.
- [ ] Calibrate authenticity thresholds with attack-class-specific reports.

Phase D: optimize for provider-grade latency and quality.

- [ ] Preload model weights and expose sidecar warmup health.
- [ ] Cache enrollment embeddings/templates without caching raw audio.
- [ ] Measure p50/p95 decode, VAD, embedding, scoring, ASR, spoof detection,
  and policy time.
- [ ] Reduce payload size and normalize browser recording format before upload.
- [ ] Add regression fixtures that fail CI when latency or score separation
  moves outside configured bounds.

Phase E: integrate as wallet auth evidence.

- [ ] Keep VoiceID equivalent to email OTP: server-verified, device-bound,
  grant-issuing, and short-lived.
- [ ] Require accepted speaker, phrase/intent, authenticity, quality, and
  device branches before issuing a low-risk signing grant.
- [ ] Route uncertain authenticity to step-up.
- [ ] Keep clip comparison as tooling; wallet code consumes only
  owner-presence/auth-policy grants.

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

Accepted results require accepted phrase, speaker, quality, and intent checks.
Browser-only policy experiments may configure liveness as `not_required` only
when the policy explicitly allows it. Camera-backed liveness requirements belong
to `docs/voiceID/voiceId-camera-liveness-future.md`.

The implemented policy surface lives in `voiceId/shared/src/policy.ts` and is
exported through the VoiceID server index. `VoiceIdIntentDigest` is an unpadded
base64url 32-byte digest. `buildVoiceIdOwnerPresenceResult()` converts completed
verification records into accepted/rejected/uncertain owner-presence evidence,
and `evaluateVoiceIdOwnerPresenceForIntent()` rejects otherwise accepted
evidence when the requested intent digest differs.
The SDK-facing adapter now lives in `voiceId/shared/src/authPolicy.ts`.
`authorizeVoiceIdOwnerPresence()` maps owner-presence results into wallet,
signing-session, or robot-command policy decisions and keeps rejected,
uncertain, expired, and intent-mismatch branches outside signing authority.

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

## Workstream 5: Owner-Presence Policy Boundary

Goal: keep liveness and owner-presence decisions typed without adding camera
work to this MVP.

Audio and device signals:

1. Fresh microphone capture.
2. Speech starts after the prompt or command window opens.
3. Speech duration is plausible for the command.
4. Replay-risk heuristics from audio quality and channel artifacts.
5. Local device or sidecar context.

Policy:

1. Embedded privileged actions can require liveness or step-up once risk policy
   is defined.
2. Phone/watch OTP remains an optional step-up factor for high-value or
   uncertain flows.
3. Current browser-first policy experiments use voice, phrase, intent binding,
   device/session policy, and step-up rules without claiming camera liveness.
4. Camera-backed liveness policy is tracked separately in
   `docs/voiceID/voiceId-camera-liveness-future.md`.

Validation:

1. Accepted owner presence requires accepted speaker, phrase, quality, and
   matching intent.
2. Replay-risk audio returns rejected or uncertain policy branches.
3. Missing liveness does not silently downgrade into accepted policy when policy
   requires liveness.
4. Camera-specific validation lives in
   `docs/voiceID/voiceId-camera-liveness-future.md`.

## Workstream 6: Wallet, MPC, And Robot Policy

Goal: consume VoiceID as owner presence for policy decisions.

Wallet/MPC policy flow:

```text
VoiceID accepted owner presence
  + intentDigest
  + device/session policy
  -> Router admission policy decision
  -> Router A/B normal-signing request or rejection
  -> SigningWorker MPC server-share participation
```

The signing architecture is the existing Router A/B signer design in
`docs/router-A-B-signer.md`. VoiceID supplies typed owner-presence evidence and
the bound VoiceID `intentDigest` plus Router normal-signing digest tuple. Router
admission checks policy, quota, replay, session, and risk. Normal signing
remains:

```text
Client -> Router -> SigningWorker -> Router -> Client
```

Deriver A and Deriver B stay on setup/export/recovery/SigningWorker-refresh
ceremonies and are not introduced into the normal VoiceID signing path.
The concrete signer adapter should bind VoiceID policy evidence to
`RouterAbEd25519NormalSigningPrepareRequestV2`,
`RouterAbEd25519NormalSigningFinalizeRequestV2`, and
`RouterAbEd25519NormalSigningAdmissionMaterialV2`.

Robot policy flow:

```text
owner voice + policy-approved owner presence
  -> accepted owner command
  -> robot performs allowed command

non-owner voice
  -> optional x402/payment flow
  -> robot performs paid public command if payment settles
```

Rules:

1. VoiceID never directly signs.
2. VoiceID outputs typed policy evidence.
3. Router admission decides whether an owner-presence result can be forwarded to
   the active SigningWorker.
4. SigningWorker participation binds to Router `intent_digest`,
   `signing_payload_digest`, `admitted_signing_digest`, expiry, device id,
   nonce, request digest, and the existing Router A/B signer transcript fields.
5. High-value actions can require additional factors.

Validation:

1. Accepted owner presence can authorize only the matching intent.
2. Rejected or uncertain VoiceID cannot create a signing session.
3. Router A/B signing refuses stale or mismatched intent digests.
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
  -> Router A/B admission
  -> SigningWorker
```

The same typed result boundaries should support all deployment shapes. The
Cloudflare production path should reuse `docs/router-A-B-signer.md`; AWS
ordinary-server and Nitro deployments should preserve the same Router,
SigningWorker, and intent-binding semantics.

## Acceptance Criteria

MVP 2 is ready for policy experiments when:

1. ECAPA verifier works through the existing TypeScript verifier interface.
2. Quality-first gating prevents bad clips from reaching accepted speaker
   results.
3. Expanded fixture report includes independent human different-speaker clips.
4. Threshold version and model version are stored with templates.
5. Transcript/phrase verification is separate from speaker scoring.
6. Intent digest binding prevents reuse across commands.
7. Owner-presence policy can distinguish accepted, rejected, and uncertain
   liveness branches without requiring camera extraction in this MVP.
8. Wallet/MPC policy consumes VoiceID as owner presence only.
9. Raw audio retention remains disabled by default.
10. Short-sample enrollment/authentication reports speech duration, score,
    threshold, calibration mode, model version, and timing.
11. Clip-to-clip speaker comparison exists as a typed VoiceID capability outside
    wallet signing authority.
12. Spoof, deepfake, replay, injected-audio, and multi-speaker checks produce a
    separate authenticity result branch.
13. Calibration reports include independent human different-speaker clips and
    attack-class fixtures before any provider-grade claims.

## Implementation Order

Current completed pieces:

- [x] ECAPA runtime path is available behind the Python verifier boundary.
- [x] Quality-first gates run before speaker scoring.
- [x] ECAPA model and threshold metadata roundtrip through TypeScript adapter
  responses.
- [x] Canonical `VoiceIdIntentDigest` typing and intent-binding checks exist.
- [x] Wallet/robot auth-policy adapter maps owner-presence into typed accepted
  or rejected policy decisions.
- [x] SDK relay module registration can mount VoiceID routes while the SDK still
  runs without VoiceID registered.
- [x] Cloudflare Workers AI ASR provider can verify spoken phrase text behind
  the transcript-provider boundary.
- [x] Liveness policy can feed typed accepted/rejected/uncertain branches into
  owner-presence authorization.
- [x] Owner-presence authorization route combines completed verification,
  `intentDigest`, use case, and liveness evidence into an accepted or rejected
  auth-policy decision.
- [x] Cloudflare deployment boundaries keep browser/mobile clients free of
  Python, PyTorch, SpeechBrain, and model weights.

Remaining order:

1. Add normal SDK coverage for typed wallet policy consumption after
   owner-presence authorization.
2. Expand normal SDK demo or fixture coverage around that policy consumption.
3. Tighten short-sample enrollment/authentication with speech-duration reporting,
   capture-channel calibration modes, timing breakdowns, and updated fixture
   reports.
4. Add the first-class clip-to-clip speaker comparison capability.
5. Add the spoof, deepfake, replay, injected-audio, and multi-speaker
   authenticity layer.
6. Expand fixtures and rerun calibration reports across speaker, phrase,
   quality, and authenticity branches.
7. Add embedded/robot sidecar architecture proof of concept.
8. Defer Router A/B admission-adapter and signing tests until the normal SDK
   path works.
9. Future camera, face, mouth, and lip-sync work lives in
   `docs/voiceID/voiceId-camera-liveness-future.md`.

## Research Basis

The short literature review in `voiceId/research/README.md` supports this plan:

1. ECAPA/x-vector style embeddings are standard speaker-verification practice.
2. ASVspoof and speech deepfake literature treat spoof detection as a separate
   countermeasure layer.
3. Audio-visual spoofing work supports the separate future camera-liveness
   plan.
4. The product architecture should keep speaker, phrase, quality, liveness, and
   policy as separate typed branches.

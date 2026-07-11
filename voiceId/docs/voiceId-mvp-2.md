# VoiceID MVP 2

Status: exploratory implementation spec.

Normative signing requirements and evidence tiers:
[VoiceID Signing Security Profile](voiceId-signing-security-profile.md).

This document scopes the second VoiceID MVP. MVP 1 proves browser capture,
typed lifecycle state, fake verification, fixture collection, and the model
spike. MVP 2 turns that scaffold into typed speaker, phrase, quality, capture-
freshness, and experimental authenticity evidence for policy research.

## Purpose

Build a production-shaped VoiceID policy signal that can:

1. Verify speaker similarity with the selected ECAPA model.
2. Gate low-quality audio before speaker scoring.
3. Verify spoken phrases or commands through a transcript boundary.
4. Bind accepted speech to a canonical intent digest.
5. Feed E0 experimental or E1 step-up-only evidence into wallet/robot policy
   simulations.

MVP 2 cannot create E2 signing-candidate evidence or a signing grant. The actual
cryptographic operation uses the existing
[Router A/B signer architecture](../../docs/router-a-b-SPEC.md): Router owns
public admission and policy, normal
signing flows through the dedicated SigningWorker, and Deriver A/B remain off
the hot signing path except for setup/export/recovery/SigningWorker refresh.

Camera, face, mouth, and lip-sync extraction are outside MVP 2. They are tracked
in the [Audio-Visual PAD Future Plan](voiceId-camera-liveness-future.md).

## Scope Boundary

MVP 2 includes:

1. ECAPA-backed Python verifier integration.
2. Quality-first audio decision policy.
3. Fixture expansion and threshold calibration.
4. Transcript provider integration for phrase and command checks.
5. Intent digest binding for wallet sessions, token transfers, and robot
   commands.
6. E0/E1 policy output for wallet and robot experiments.

MVP 2 does not include:

1. Training a custom speaker-verification model.
2. Treating voice as a cryptographic signature.
3. An approved PAD model or signing-grade capture profile.
4. A final production storage/backend choice.
5. Camera, face, mouth, or lip-sync extraction.
6. Direct VoiceID authorization of wallet signing.

## Architecture

```text
authenticated transaction request
  -> server-canonical Router intent and signing payload
  -> server challenge
  -> one continuous browser or approved-device capture
  -> capture-boundary validation
  -> quality + phrase + speaker + freshness + PAD + device-proof results
  -> E0/E1/E2 evidence builder
  -> passkey step-up or server R1 policy
  -> one-use Router grant reservation
  -> existing Router A/B and SigningWorker flow
```

Browser capture stops at E0. The grant branch exists only for a future approved
embedded capture profile that satisfies the signing security profile. Robot
commands use the same independent evidence checks, followed by a separate robot
safety policy rather than wallet admission.

Ownership boundaries:

- `voiceId/client`: capture, upload, browser lifecycle, and UI/demo hooks.
- `voiceId/server`: route parsing, service state, stores, policy assembly, and
  typed results.
- `voiceId/verifier`: ECAPA runtime, audio normalization, VAD, quality checks,
  embedding extraction, template building, and scoring.
- `voiceId/verifier-spike`: offline model comparison and calibration reports.
- `voiceId/research`: source PDFs and brief literature review.
- robot-local sidecar: local process on the robot that hosts capture, local
  evidence policy, PAD integration, device proof, and optional wallet sidecar
  integration. The current runbook lives at
  `voiceId/deploy/robot-local/sidecar/README.md`, with
  `pnpm -C voiceId robot:guard` covering the shared Python HTTP verifier API and
  Cloudflare-hosted policy boundary.
- Cloudflare deployment: Workers/Pages host capture-facing API and static demo,
  Workers AI handles ASR where possible, D1/Durable Objects store typed state
  and Router A/B signer state, R2 stores opt-in diagnostics, Cloudflare
  Containers host the Python ECAPA verifier sidecar, and the existing Router A/B
  SigningWorker path performs MPC signing. The current container package lives
  at `voiceId/deploy/cloudflare/verifier-container/`, with
  `pnpm -C voiceId container:guard` covering the Dockerfile, `.dockerignore`,
  Python package metadata, and runbook shape.
- SDK relay integration: wallet/auth router API entrypoints expose
  `RouterApiOptions.routeExtensions` and generic `RouterApiModule`
  registration, with Cloudflare-only, Express-only, and universal runtime
  branches. `createVoiceIdRouterApiRouteExtension()` converts a VoiceID server
  capability into a universal router API route extension, and
  `createVoiceIdRouterApiModule()` wraps that extension in the SDK module shape.
  Concrete VoiceID stores, verifiers, transcript providers, evidence builders,
  and PAD policy remain owned by `voiceId/`.
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
  Router canonicalization, challenge creation, ASR calls, and state writes,
  then calls a Python verifier running in a Cloudflare Container over the same
  HTTP sidecar interface. Current browser results remain E0 and require passkey
  admission. A future E2 result may reach the existing Router A/B path only
  after server R1 policy issues a one-use grant and Router admission reserves it
  atomically. SigningWorker then performs the MPC server-share operation.
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

#### Capture Format And Calibration Profile

The client uploads the original bytes emitted by its capture API. The route
boundary validates the container, and the server records the codec discovered
during decode. Client MIME, duration, timestamps, device labels, and DSP metadata
are advisory.

Preferred browser negotiation uses the first supported platform format, such as
Opus in WebM/Ogg or platform AAC. Browser `MediaRecorder` output must not be
described as lossless. Native PCM or verified lossless encoding uses a distinct
capture profile.

```text
original bytes + original-byte hash
  -> decode while preserving native sample rate and channels
  -> PAD/fingerprint derivative under the native capture profile
  -> 16 kHz mono derivative for ECAPA
  -> ASR-specific derivative
  -> original multichannel timing for robot direction-of-arrival
```

Irreversible trimming, denoising, beamforming, resampling, or compression must
not destroy evidence required by PAD. Raw bytes remain ephemeral. Capture
profiles are concrete and versioned, for example
`web_mediarecorder_opus_v1`, `ios_native_pcm_v1`, and
`robot_array_pcm_v1`. An unvalidated enrollment/verification profile pair
returns `uncertain`.

### 2. Quality Gate Semantics

Speaker scoring runs only after audio quality accepts the capture.

Recommended outcomes:

- undecodable, corrupted, or header-only audio -> `uncertain`
- too short -> `uncertain`
- low speech duration -> `uncertain`
- low SNR or excessive background noise -> `uncertain`
- clipped or saturated audio -> `uncertain`
- multiple speakers or inconsistent enrollment windows -> `uncertain`
- unsupported enrollment/verification capture-profile pair -> `uncertain`
- duplicate enrollment or verification audio fingerprint -> `rejected`
- phrase mismatch -> `rejected`
- speaker mismatch after quality acceptance -> `rejected`
- verifier unavailable -> service-level `verifier_unavailable` error

This keeps bad capture conditions out of the hard-rejection path and avoids
training policy code to treat microphone problems as identity failures.
Verifier outages stay outside biometric result scoring so callers can retry or
route to another sidecar without recording a false identity outcome.

### 3. Template Format

Use one continuous, prompt-segmented enrollment session. VAD produces
non-overlapping speech windows, and the verifier rejects poor-quality,
duplicate, multi-speaker, or embedding-incoherent windows before template
construction. L2-normalize each accepted embedding, compute a versioned
quality-weighted centroid, then normalize the centroid again.

Store with each enrolled template:

- encrypted normalized centroid
- model id: `speechbrain/spkrec-ecapa-voxceleb`
- adapter id
- embedding dimension
- template version
- threshold version
- aggregation-policy version
- enrollment session id and assurance class
- accepted and rejected window counts
- aggregate usable-speech duration
- capture-profile id
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

### 5. Evidence-Duration And Capture-Profile Experiment

The number of UI recordings is not a calibration parameter. The experiment
selects the shortest usable-speech requirement that meets a pre-registered risk
and usability target for each capture-profile pair.

Candidate enrollment durations:

- 3, 6, 9, 12, and 15 seconds of aggregate usable speech;
- one continuous prompt-segmented session;
- one later strongly authenticated session on another day.

Candidate verification durations:

- 1.5, 2, 3, 4, and 5 seconds of usable speech;
- one challenge-bound capture per attempt;
- at most one quality retry with a new challenge.

Data rules:

- speaker-disjoint development and locked test cohorts;
- at least three sessions per enrolled speaker across two or more days;
- independent human impostors;
- all segments from one capture remain in the same split and count as one
  session;
- same-profile and calibrated cross-profile trials;
- replay, TTS, voice conversion, splicing, digital injection, and multi-speaker
  trials reported separately;
- thresholds, durations, and aggregation rules selected on development data
  once.

Reports include speaker FMR/FNMR and EER, end-to-end false-grant and false-
denial rates, quality uncertainty and retry rates, PAD attack-presentation and
bona-fide error by class, exact-challenge accuracy, p50/p95 latency, completion
time, and subject-level confidence intervals. MVP-sized fixtures can rank
configurations and cannot establish a signing-grade error rate.

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
said; ECAPA decides whether the voice sounds like the enrolled owner. The ASR
adapter receives the expected phrase from stored server challenge state. A
caller-provided `spokenPhrase`, transcript, or expected phrase is diagnostic
input only and cannot become core policy state.

### 7. Intent Digest Schema

For wallet signing, the existing Router A/B typed normal-signing intent and
signing payload are the only authoritative transaction representation. The
server builds and persists `RouterVoiceIntentBinding` before issuing a voice
challenge. Clients cannot supply an authoritative digest or canonicalization
version.

Any VoiceID challenge digest is a domain-separated derivative of the Router
operation id, operation fingerprint, `intent_digest`,
`signing_payload_digest`, `admitted_signing_digest`, challenge id, prompt hash,
device key, and expiry. Robot-only commands use an equivalent server-owned typed
command binding.

### 8. Policy Result Shape

Use the E0/E1/E2 `VoiceIdEvidence` union from the signing security profile.
Browser capture always produces E0. Missing or client-reported PAD/device proof
produces E0, E1, rejection, or uncertainty. `liveness_not_required` cannot
construct E2 evidence.

### 9. Storage Boundary

Use in-memory storage for local MVP tests. Durable storage must encrypt
templates and store model/threshold metadata. Cloudflare deployments should use
D1 or Durable Objects for enrollment, verification, immutable Router bindings,
server challenges, device-capture statements, evidence tiers, grant state,
atomic Router reservations, revocation, deletion receipts, and audit records.
Use R2 only for explicit diagnostic media retention with a deletion policy.
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
- any required persisted-data migration belongs at the storage boundary and is
  deleted after the rewrite completes
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

### 10. Challenge Freshness And PAD Boundaries

MVP 2 represents challenge freshness and PAD separately:

- server issue/receipt time, nonce, expiry, prompt hash, original-audio hash, and
  device signature establish protocol freshness and byte binding;
- browser timestamps, device labels, source labels, and replay-risk flags are
  untrusted telemetry;
- duplicate fingerprints and channel heuristics are research signals;
- PAD is a separate model-backed result for measured replay, synthesis,
  conversion, splicing, and injection classes;
- `not_required` cannot satisfy E2 construction;
- until PAD and an approved capture profile exist, every accepted browser result
  remains E0 and cannot issue a grant.

Audio-visual PAD is deferred to the
[Audio-Visual PAD Future Plan](voiceId-camera-liveness-future.md).

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

### Feature 1: Guided Enrollment And Short Authentication

User outcome: enroll this browser or device once, then authenticate the enrolled
speaker from a short fresh sample.

Implementation requirements:

1. Keep enrollment and verification text-independent at the speaker layer.
   The speaker verifier decides whether the voice matches the enrolled template;
   the ASR and intent parser decide what the user said.
2. Enrollment uses one continuous guided capture with three to five randomized
   prompt fragments and a provisional 10-15 second usable-speech target.
3. VAD creates non-overlapping prompt-aligned windows internally. The UI does not
   present those windows as separate recordings.
4. Reject prompt mismatch, low quality, duplicate windows, multiple speakers,
   PAD failures, embedding outliers, and incoherent enrollment clusters.
5. L2-normalize accepted embeddings, compute a quality-weighted centroid, and
   normalize the centroid again.
6. Verification uses one challenge-bound capture with a provisional 3-5 second
   usable-speech target and at most one quality retry under a new challenge.
7. Build templates with model id, adapter
   id, threshold version, calibration mode, prompt policy, device id, and
   fixture-manifest hash.
8. Store encrypted templates and typed audit events. Raw enrollment audio stays
   disabled by default, with explicit diagnostic retention windows only.
9. Bind every signing-grade attempt to verified device proof and a fresh capture
   session. Browser experiments remain E0 regardless of a demo device id.
10. Return separate quality, speaker, phrase, freshness, PAD, device-proof,
    capture-profile, and policy branches.

Provider-grade acceptance:

1. The duration experiment selects requirements for each capture-profile pair.
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
   code consumes only passkey admission or a server-side reserved R1 grant, never
   raw clip-comparison output.
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

1. Add a `VoiceIdAudioPadResult` union:

   ```ts
   type VoiceIdAudioPadResult =
     | { kind: 'accepted'; pad: VoiceIdAcceptedPad }
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
         reason: 'insufficient_speech' | 'low_audio_quality' | 'model_low_confidence';
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
     These signals may reject or raise risk. They cannot construct accepted PAD
     evidence or upgrade browser capture beyond E0.
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
6. Bind verification to the stored server challenge and canonical Router
   binding. This blocks stale fixed-phrase reuse. Prompt-targeted synthesis and
   live relay remain PAD attack classes and require measured coverage.
7. Use passkey step-up for browser, high-risk, unsupported, or uncertain wallet
   outcomes. A future approved embedded capture may authorize only explicit R1
   operations after every E2 branch and Router grant check accepts.

Provider-grade acceptance:

1. Replay, synthetic, injected, and multi-speaker subsets appear in the
   calibration report with separate false-accept and false-reject numbers.
2. The service records spoof-model version, threshold version, calibration mode,
   capture channel, and timing for every authenticity result.
3. E2 construction requires accepted quality, phrase, speaker, freshness, PAD,
   device proof, capture profile, calibration, and Router binding. Browser
   capture remains E0 regardless of heuristic outcome.
4. The UI shows a single user-facing decision while preserving branch-level
   diagnostics for audit and development.
5. No production claim says "deepfake-proof". Claims must reference measured
   attack classes, fixture versions, and known limitations.

### Provider-Grade Phased TODO

Phase A: tighten the local short-capture research loop.

- [x] ECAPA verifier path behind the Python sidecar.
- [x] Quality-first gates before speaker scoring.
- [x] Encrypted template storage boundary.
- [x] The demo contains a caller-owned command phrase and digest-equality
      prototype; it is E0-only and scheduled for replacement.
- [ ] Require and report speech duration independently from recording duration.
- [ ] Add concrete capture profiles such as `web_mediarecorder_opus_v1`,
      `ios_native_pcm_v1`, `telephone_pcmu_8khz_v1`, and
      `robot_array_pcm_v1`.
- [ ] Add timing breakdowns to verifier, ASR, and policy responses.
- [ ] Add fixture reports that summarize FPR/FNR by capture channel and
      threshold version.

Phase B: add first-class clip comparison.

- [ ] Define `VoiceIdClipComparisonResult` in `voiceId/shared`.
- [ ] Add Python verifier request/response schemas for clip-to-clip comparison.
- [ ] Add TypeScript adapter parsing and tests.
- [ ] Add a server route for development and fixture tooling.
- [ ] Add fixture report output for clip-pair score distributions.

Phase C: build the audio PAD layer.

- [ ] Define `VoiceIdAudioPadResult` and thread it through verifier,
      policy, auth-policy adapter, and audit events.
- [ ] Add research-only replay heuristics: duplicate audio fingerprint, stale
      prompt timing, repeated command audio, and channel metadata checks.
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

- [ ] Replace the broad owner-presence result with E0/E1/E2 evidence types.
- [ ] Make browser E0 and E1 results require passkey for signing.
- [ ] Require authenticated routes, server challenge ownership, accepted
      speaker, phrase, quality, freshness, PAD, device proof, approved capture
      profile, and Router binding before E2 construction.
- [ ] Issue a one-use grant only after server R1 risk policy accepts E2.
- [ ] Reserve and consume grants atomically at Router admission.
- [ ] Route uncertain authenticity or unsupported profiles to passkey.
- [ ] Keep clip comparison as tooling; wallet code consumes only
      tiered evidence and server-side grant references.

## Core Result Shape

MVP 2 targets the `VoiceIdEvidence` union defined in the signing security
profile:

- E0 `VoiceIdExperimentalBrowserEvidence` for ordinary browser capture and
  caller-controlled telemetry;
- E1 `VoiceIdStepUpOnlyEvidence` when useful evidence exists and a signing gate
  remains absent or uncertain;
- E2 `VoiceIdSigningCandidateEvidence` only when every independent check is
  server-verified under an approved capture and calibration profile.

The current `VoiceIdOwnerPresenceResult`, `VoiceIdLivenessResult`, and SDK auth-
policy adapter are experimental plumbing scheduled for replacement. Their
accepted and `not_required` branches cannot issue a grant or reach a signing
continuation. The cutover deletes those signing-facing paths rather than
maintaining parallel compatibility types.

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
9. Single-speaker consistency across enrollment windows.
10. Duplicate and near-duplicate capture fingerprints.

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

Goal: run the evidence-duration and capture-profile experiment before choosing
an operating threshold.

Fixture additions:

1. Independent human different-speaker clips.
2. Owner verification sessions across days, distances, and capture profiles.
3. Owner enrollment sessions across at least two days.
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
7. Duration, retry, and capture-profile recommendation with subject-level
   confidence intervals.

Validation:

1. Threshold report records model version, data manifest, and scoring backend.
2. Report separates phrase failures from speaker failures.
3. Report separates noisy/uncertain captures from hard negatives.

## Workstream 4: Transcript And Intent Binding

Goal: compare speech with a challenge for an already-fixed authoritative intent.

Transcript provider boundary:

```text
authenticated transaction request
  -> Router canonical intent and signing payload
  -> persisted RouterVoiceIntentBinding
  -> server prompt and challenge
  -> audio capture
  -> ASR transcript
  -> exact phrase comparison for the persisted binding
```

Rules:

1. Speaker verification does not decide command correctness.
2. Transcript confidence below threshold returns `uncertain`.
3. Ambiguous command parses return `uncertain`.
4. The expected phrase comes from stored server challenge state.
5. Wallet speech never constructs or mutates the authoritative transaction.
6. A transaction, challenge, prompt, device, or expiry change requires a new
   capture.

Validation:

1. Router builders deterministically reproduce the persisted digest tuple.
2. Mutating any Router, challenge, prompt, device, audio-hash, or expiry field
   invalidates the capture statement.
3. Caller-supplied phrase, digest, nonce, expiry, policy, or identity cannot
   become authoritative core state.

## Workstream 5: Evidence-Tier Boundary

Goal: replace the broad owner-presence/liveness result with E0/E1/E2 evidence.

1. Rename caller-reported timestamps, microphone ids, source labels, and replay
   flags to capture telemetry.
2. Add server-owned challenge freshness, device proof, PAD, capture profile,
   and Router binding as separate results.
3. Make browser capture construct E0 only.
4. Make missing, unapproved, or uncertain signing checks construct E1,
   rejection, or uncertainty.
5. Permit E2 construction only through the branch-specific builder in the
   signing security profile.
6. Delete `liveness_not_required` from signing-facing policy.

Validation uses type fixtures for direct object literals, broad spreads, raw
client context, unsafe casts, and invalid cross-tier combinations. Camera-
specific work remains in the
[Audio-Visual PAD Future Plan](voiceId-camera-liveness-future.md).

## Workstream 6: Wallet, MPC, And Robot Policy

Goal: keep browser signing passkey-backed and defer embedded VoiceID admission
to a future capped R1 pilot.

Wallet/MPC policy flow:

```text
browser E0/E1
  -> passkey user verification for exact Router binding
  -> ordinary Router admission

embedded E2
  -> server R1 risk policy
  -> issue one-use grant
  -> Router atomically reserves grant for exact operation
  -> SigningWorker receives admitted request
```

The signing architecture is the existing
[Router A/B signer design](../../docs/router-a-b-SPEC.md). The Router binding is
created before the challenge
and carried unchanged through evidence, grant, reservation, and admission.
Normal signing remains:

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
approved evidence + command policy
  -> admitted owner command
  -> independent robot safety controller
  -> robot performs an allowed command

non-owner voice
  -> optional x402/payment flow
  -> independent robot safety controller
  -> robot performs a paid public command if payment settles
```

Rules:

1. VoiceID never directly signs.
2. VoiceID outputs typed policy evidence.
3. Router admission accepts a passkey-admitted transaction or an atomically
   reserved R1 VoiceID grant.
4. SigningWorker participation binds to Router `intent_digest`,
   `signing_payload_digest`, `admitted_signing_digest`, expiry, device id,
   nonce, request digest, and the existing Router A/B signer transcript fields.
5. New recipients, elevated value, security changes, export, recovery, and
   safety-critical actions require passkey or prohibit voice.

Validation:

1. E0/E1 cannot issue a grant or call a signing continuation.
2. VoiceID cannot create or widen a signing session.
3. Concurrent requests cannot reserve one grant for different operations.
4. Router A/B signing refuses stale or mismatched bindings.
5. Audit events include evidence tier, versions, result kinds, and coarse bands
   without raw audio.

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
Cloudflare production path should reuse the
[Router A/B specification](../../docs/router-a-b-SPEC.md); AWS
ordinary-server and Nitro deployments should preserve the same Router,
SigningWorker, and intent-binding semantics.

## Acceptance Criteria

MVP 2 is ready for an E0 research deployment when:

1. ECAPA works through the TypeScript verifier interface and quality gating
   prevents invalid captures from reaching speaker scoring.
2. Enrollment uses one continuous guided recording, internal VAD windows, a
   normalized quality-weighted template, and explicit usable-speech evidence.
3. Verification uses one challenge-bound recording and at most one quality
   retry under a new challenge.
4. Speaker, phrase, quality, freshness, PAD, device proof, capture profile, and
   Router binding remain independent typed results.
5. The server owns the expected prompt and, for transaction experiments, builds
   the immutable Router binding before challenge creation.
6. Every browser result is structurally E0 and cannot issue a grant, call a
   signing continuation, or widen a wallet session.
7. Browser transaction demos complete through passkey admission for the exact
   Router operation.
8. Templates carry model, threshold, aggregation, capture-profile, and
   assurance versions; raw media retention remains disabled by default.
9. Duration and threshold reports use subject-disjoint cohorts, independent
   human impostors, session-level splits, confidence intervals, and separate
   attack-class results.
10. Replay heuristics remain research signals; accepted PAD requires a measured
    model and approved calibration record.
11. Clip comparison is a typed tooling capability with no signing authority.
12. Audit and deletion tests prove that audio, embeddings, full transcripts,
    and client diagnostics do not cross into Router, SigningWorker, or logs.

## Implementation Order

The repository currently has an experimental ECAPA path, quality-first scoring,
model and threshold metadata, encrypted template storage, route registration,
an ASR boundary, and broad owner-presence policy plumbing. The caller-owned
phrase/digest and `not_required` liveness branches are prototype behavior. They
are E0-only and do not establish Router admission.

Execute the replacement in this order:

1. Implement one guided enrollment session, one verification recording, usable-
   speech measurement, window coherence, and the versioned template aggregator.
2. Introduce E0/E1/E2 builders and static rejection fixtures. Delete the broad
   signing-facing owner-presence and `liveness_not_required` branches.
3. Authenticate routes, construct the typed Router intent server-side, persist
   it, and issue the challenge from server-owned state.
4. Add exact-audio hashing, typed capture profiles, short-lived challenge state,
   revocation, deletion receipts, and mutation/replay tests.
5. Run the evidence-duration experiment and expand subject-disjoint speaker,
   phrase, channel, and attack fixtures before selecting thresholds.
6. Keep every browser wallet demo passkey-backed while collecting E0 shadow
   evidence. Rewrite tests that currently treat broad accepted evidence as
   signing authority.
7. Add an approved embedded capture agent, device proof, and calibrated PAD.
   Keep E2 disabled until the profile release gates pass.
8. Implement server R1 policy, one-use grant storage, atomic Router reservation,
   and concurrent race tests before any capped E2 pilot.
9. Add clip comparison as independent tooling and evaluate audio-visual PAD
   through [Audio-Visual PAD Future Plan](voiceId-camera-liveness-future.md).

## Research Basis

The short literature review in `voiceId/research/README.md` supports this plan:

1. ECAPA/x-vector style embeddings are standard speaker-verification practice.
2. ASVspoof and speech deepfake literature treat spoof detection as a separate
   countermeasure layer.
3. Audio-visual spoofing work supports a separate future PAD plan with measured
   attack-class coverage.
4. The product architecture keeps speaker, phrase, quality, freshness, PAD,
   device proof, capture profile, Router binding, and policy as separate typed
   branches.

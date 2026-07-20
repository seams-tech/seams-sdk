# VoiceID MVP 1: E0 Evidence Service

Status: active implementation specification.

Normative signing requirements:
[VoiceID Signing Security Profile](voiceId-signing-security-profile.md).

Implementation plan:
[VoiceID MVP 1 Tasks](voiceId-mvp-1-tasks.md).

## Purpose

MVP 1 is a standalone browser-captured voice evidence service. It establishes a
clean recording ceremony, typed lifecycle state, verifier boundaries, durable
template protection, and honest E0 output. Wallet signing, Router admission,
and global authentication-method integration are outside this milestone.

The service answers a narrow research question: can the current phrase,
quality, and speaker-verification stack produce useful measurements from a
single coherent enrollment and verification experience?

## Security Classification

Every successful browser result has this classification:

```ts
type VoiceIdExperimentalBrowserEvidence = {
  kind: 'experimental_browser_evidence';
  verificationId: VoiceIdVerificationId;
  enrollmentId: VoiceIdEnrollmentId;
  observedChecks: VoiceIdObservedChecks;
  modelVersion: VoiceIdModelVersion;
  thresholdVersion: VoiceIdThresholdVersion;
  completedAt: IsoDateTime;
  signingAuthorization?: never;
};
```

The evidence records independent accepted phrase, speaker, and quality checks.
It also records these browser limits explicitly:

- capture freshness is a browser timing observation with
  `serverVerifiedFreshness: false`;
- PAD is unavailable;
- capture source is ordinary `MediaRecorder`;
- microphone integrity is unverified.

The API capability and health response publish `signingEligible: false`.
Successful evidence cannot construct a wallet authorization or signing
continuation.

## Trust Boundaries

The browser owns `Blob`, `MediaRecorder`, and microphone permission. Multipart
request parsing converts audio bytes and metadata into `VoiceIdAudioInput` once.
Core service methods accept branded identity and lifecycle types.

The following browser fields are advisory observations:

- MIME type and recorder label;
- capture timestamp;
- reported sample rate and channel count;
- reported duration.

The decoder and verifier own authoritative media and quality decisions. Raw
audio crosses the route boundary, transcript provider, and verifier boundary
during the request. It is excluded from persistence and audit records.
Route and sidecar boundaries reject empty audio and encoded media above 32 MiB.
Decoder probing and conversion use bounded execution time and reject decoded
audio beyond 30 seconds.

## Enrollment Ceremony

Enrollment uses one continuous recording:

- four server-owned prompt segments;
- 12 seconds minimum reported duration;
- 18 seconds target duration;
- 30 seconds maximum capture duration;
- one multipart upload;
- one final phrase and quality decision;
- one atomic template commit from the service perspective.

The active implementation combines the four prompts for ordered phrase
matching and passes the complete recording to one atomic verifier operation.
The verifier probes the source stream, validates media claims, decodes canonical
mono 16 kHz samples, runs VAD, rejects invalid or incoherent windows, and builds
one normalized quality-weighted template. Raw embeddings never cross the
verifier boundary.

Enrollment lifecycle:

```text
pending_continuous_recording
  -> analyzing_continuous_recording
       -> enrolled
            -> disabled
       -> failed

pending_continuous_recording
  -> failed
```

`pending_continuous_recording` carries the prompt sequence, expiry, duration
gates, model version, and no template fields. The service atomically moves it to
`analyzing_continuous_recording` before transcription or model work and records
a bounded analysis lease. `enrolled` requires encrypted template, model,
template, and threshold versions. `failed` contains a precise failure reason and
no partial template. `disabled` preserves the encrypted template fields for
record integrity and blocks verification.

The default enrollment analysis lease is 60 seconds. Recovery converts an
expired claim to `failed` with `analysis_timeout`; it never reuses the capture.

Failure reasons:

```text
expired
capture_too_short
capture_too_long
phrase_rejected
transcript_uncertain
decoder_failure
metadata_mismatch
interrupted_capture
insufficient_speech
insufficient_windows
duplicate_windows
multi_speaker
clipped_audio
low_snr
incoherent_windows
template_build_failed
analysis_timeout
verifier_unavailable
```

Enrollment, replacement, restoration, and adaptation require independent
user-verified authorization in a future authenticator integration. The E0 lab
route accepts a research `userId` and carries no production identity claim.

## Verification Ceremony

Verification uses one continuous 3–5 second recording. The server creates:

- `verificationId`;
- unpredictable challenge nonce;
- prompt base selected from server configuration;
- nonce-derived spoken fragment;
- creation and expiry times.

The client submits `userId`, `enrollmentId`, `verificationId`, audio bytes, and
audio metadata. It cannot choose the expected phrase, transcript, challenge,
policy, score, or signing context.

Verification lifecycle:

```text
issued
  -> analyzing
       -> evidence_observed
       -> rejected
       -> uncertain
       -> analysis_failed
  -> expired
```

Each result-bearing terminal record requires a matching result branch. The
service claims `analyzing` through a datastore compare-and-swap before calling
the transcript or speaker providers. Concurrent losers receive `invalid_state`
without repeating model work. A stale lease becomes `analysis_failed` with
`analysis_timeout`; the capture is never replayed.

The default verification analysis lease is 30 seconds.

Result evaluation order:

1. audio-quality rejection or uncertainty;
2. phrase rejection;
3. speaker rejection;
4. phrase or speaker uncertainty;
5. E0 evidence construction after every observed check accepts.

An expired or completed verification cannot be reused. A future quality retry
must issue a new challenge and verification id.

## Capture UX Requirements

The capture UI exists to produce valid, measurable recordings:

- keep the current prompt visible for the complete recording interval;
- show microphone permission, ready, recording, processing, accepted,
  uncertain, rejected, and expired states explicitly;
- derive enrollment progress from prompt coverage, usable speech, quality, and
  accepted windows instead of elapsed time alone;
- provide a clear cancel action that discards the current capture;
- issue a fresh challenge and verification id for every quality retry;
- keep status, prompts, errors, and controls available to keyboard and assistive
  technology users;
- avoid exposing model scores, thresholds, or diagnostics as user instructions.

Wallet confirmation, device-binding settings, SDK components, and
authenticator-management UI remain outside the active engine specification.

## Active HTTP Contract

```text
GET  /voice-id/health
POST /voice-id/evidence/enrollment/start
POST /voice-id/evidence/enrollment/recording
POST /voice-id/evidence/enrollment/disable
POST /voice-id/evidence/verification/start
POST /voice-id/evidence/verification/recording
```

JSON start and disable requests are parsed at the route boundary. Recording
requests use multipart form data:

```text
audio     Blob
metadata  JSON VoiceIdAudioMetadata
fields    JSON identity fields
```

There is no separate finalization request. The enrollment recording request
either commits a complete template or moves the record to `failed`.

Public response DTOs omit encrypted templates and persistence records. The
browser client parses each response into exact branded and discriminated types
at the fetch boundary; unexpected fields fail closed.

## Verifier And Transcript Providers

Provider selection is explicit:

```text
VOICEID_VERIFIER_TRANSPORT = fake | python-subprocess | python-http
VOICEID_TRANSCRIPT_PROVIDER = fake | cloudflare-workers-ai
```

Missing or invalid selections fail configuration. Development launchers choose
fake providers explicitly. Deployment-shaped tests choose the Python transport
and transcript provider explicitly.

Cloudflare storage selection is also explicit. `memory` is for isolated
research processes; durable experiments select `cloudflare-d1` and template
wrapping configuration.

Hosted browser access requires an exact origin allowlist. Wildcard CORS is
prohibited. Requests carrying an unapproved `Origin` fail before route
dispatch.

The TypeScript verifier adapter validates Python responses once and converts
them to exact result unions. Transport failures map to uncertainty or failed
enrollment; they never produce evidence.

The Python v2 verifier surface contains only:

```text
POST /voice-id/verifier/build-enrollment-template
POST /voice-id/verifier/verify-speaker
```

Enrollment audio and internal embeddings remain inside one atomic sidecar
operation. The transport has no embedding export or separate template-build
operation.

## Persistence And Privacy

Stores persist complete enrollment and verification union values. Cloudflare D1
uses v4 tables with indexed identity and lifecycle fields plus a parsed
`recordJson` payload.
The parser verifies that indexes match the record body.

Durable enrollment storage wraps verifier templates with AES-GCM-256. Key id,
rotation version, AAD label, user id, enrollment id, model version, template
version, and threshold version are authenticated as associated data.

Ordinary audit events contain lifecycle result kinds and coarse score bands.
They exclude raw audio, embeddings, complete transcripts, and raw model output.
Diagnostic audio retention is disabled unless a bounded research configuration
enables it explicitly.

## Acceptance Criteria

- TypeScript rejects invalid enrollment, verification, evidence, and signing
  combinations through discriminated unions and static fixtures.
- Enrollment presents four prompts in one recording ceremony.
- A failed enrollment persists no template or embedding collection.
- Verification prompts and nonce material originate on the server.
- The client request surface carries no expected phrase or signing state.
- Successful verification returns E0 evidence with signing eligibility fixed to
  false.
- Missing provider configuration fails closed.
- Durable parsers reject schema and index mismatches.
- Tests cover success, quality failure, phrase mismatch, expiry, replay,
  provider parsing, pre-computation claims, stale-lease recovery, persistence,
  and template wrapping.
- Architecture guards reject reintroduction of authorization code into active
  VoiceID sources.

## Active Engine Milestones

1. Produce one subject-disjoint benchmark for accuracy, stage latency, memory,
   resource use, uncertainty, and failure rate.
2. Feed phrase, intent, speaker, PAD, and template processing from one canonical
   decode and shared VAD result in persistent workers.
3. Test Moonshine Tiny Streaming and Small Streaming first for flexible
   challenge-token coverage and semantic-intent verification, then select and
   calibrate the phrase, intent, speaker, and PAD models on held-out subjects
   and attacks.
4. Improve continuous-enrollment aggregation and cross-session template
   stability.
5. Qualify optimized server, embedded, and iOS research builds with decision
   regressions, crash tests, overload tests, fuzzing, and soak tests.

The implementation checklist and exit gates are maintained in
[VoiceID MVP 1 Tasks](voiceId-mvp-1-tasks.md). Cross-origin iframe,
authenticator hardware, WebAuthn/CTAP2, wallet, and Router work are deferred
until the engine meets its frozen accuracy and runtime budgets.

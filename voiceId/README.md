# VoiceID E0 Evidence Lab

VoiceID currently provides browser-captured, server-scored voice evidence for
research. Wallet signing integration is frozen until the evidence service and
platform authenticator designs meet their own exit gates.

The active implementation:

- records one continuous 12–30 second enrollment ceremony containing four
  server-selected prompts;
- records one 3–5 second verification response to a fresh, unpredictable,
  server-selected prompt;
- evaluates phrase, audio quality, and speaker similarity independently;
- decodes claimed media to canonical mono 16 kHz audio, extracts internal VAD
  windows, and builds one quality-weighted template without exporting raw
  embeddings from the verifier;
- commits an enrollment template only after the complete recording succeeds;
- claims enrollment and verification lifecycle state before external model work
  and expires stale analysis claims;
- consumes each verification challenge after one capture;
- persists typed lifecycle records and encrypted templates without raw audio;
- returns `experimental_browser_evidence`; health and capability metadata publish
  `signingEligible: false`.

The implementation has no wallet authorization record, signing grant, Router
continuation, caller-selected transaction digest, or VoiceID signing adapter.

## Security Boundary

Ordinary browser microphone capture is E0 evidence. A cross-origin iframe can
isolate capture code, origin storage, microphone permission, and raw media from
the parent application. It cannot provide a trusted microphone path, measured
execution, presentation-attack detection, protected template matching, or
hardware-bound credential-key release.

Production browser signing requires a passkey over the exact Router operation.
Direct VoiceID signing requires an approved local user-verifying authenticator
that owns capture, matching, phrase verification, PAD, lockout, templates, and
credential-key release inside a protected boundary.

See:

- [Signing security profile](docs/voiceId-signing-security-profile.md)
- [Current MVP implementation spec](docs/voiceId-mvp-1.md)
- [Implementation tasks](docs/voiceId-mvp-1-tasks.md)
- [Provider research](docs/provider-references.md)

## Active API

```text
GET  /voice-id/health
POST /voice-id/evidence/enrollment/start
POST /voice-id/evidence/enrollment/recording
POST /voice-id/evidence/enrollment/disable
POST /voice-id/evidence/verification/start
POST /voice-id/evidence/verification/recording
```

Enrollment start returns the complete four-prompt sequence and duration gates.
The recording endpoint accepts one multipart upload containing audio, metadata,
`userId`, and `enrollmentId`.

Verification start creates the nonce, prompt, expiry, and verification id on the
server. The recording endpoint accepts identity fields and audio only. Caller
transcripts, expected phrases, policy labels, risk classifications, and
transaction fields are outside the request contract.

Route responses use explicit public DTOs. Enrollment template ciphertext,
challenge internals, and persistence records stay server-side. The browser
client validates each response once and returns precise result unions.

## Development

```sh
pnpm run voiceId:demo
pnpm -C voiceId type-check
pnpm -C voiceId test
pnpm -C voiceId signing-architecture:guard
pnpm -C voiceId verifier:test
pnpm -C voiceId smoke:python-http
```

`pnpm run voiceId:demo` starts the explicitly configured fake verifier, fake
transcript provider, E0 API on `http://127.0.0.1:5052`, and browser lab on
`http://127.0.0.1:5050`.

The deployment-shaped local flow runs the Python verifier sidecar:

```sh
pnpm -C voiceId dev:all:verifier
```

Provider selection is required. There are no implicit fake-provider defaults:

```sh
VOICEID_VERIFIER_TRANSPORT=fake
VOICEID_VERIFIER_TRANSPORT=python-http

VOICEID_TRANSCRIPT_PROVIDER=fake
VOICEID_TRANSCRIPT_PROVIDER=cloudflare-workers-ai
VOICEID_TRANSCRIPT_PROVIDER=python-moonshine
```

Cloudflare also requires an exact comma-separated browser-origin allowlist:

```sh
VOICEID_ALLOWED_ORIGINS=https://voice.example.com,https://wallet.example.com
```

The API reflects an allowed origin exactly and never emits wildcard CORS.

`python-http` requires `VOICEID_PYTHON_VERIFIER_URL`; local launchers set it to
`http://127.0.0.1:5051/voice-id/verifier/`. Cloudflare Workers AI ASR requires
the `AI` binding in Workers or `CLOUDFLARE_ACCOUNT_ID` and
`CLOUDFLARE_API_TOKEN` for the local REST adapter.

The Python sidecar loads its configured model before serving and publishes the
exact runtime metadata on `/health`. Inference admission is bounded:

```sh
VOICEID_VERIFIER_MAX_CONCURRENT_INFERENCES=1
VOICEID_VERIFIER_QUEUE_WAIT_MS=250
```

An exhausted queue returns a deterministic `overloaded` response. The SDK HTTP
deadline remains the outer request deadline.

The `python-http` plus `python-moonshine` profile routes verification through
`/voice-id/verifier/analyze-verification`. It decodes one canonical mono 16 kHz
PCM buffer and derives phrase, intent, speaker, and quality decisions from that
same buffer. PAD remains explicitly unavailable until its model and calibration
are complete.

The local ECAPA research threshold is `0.6352` under
`ecapa-local-dev-v1`. It is fixture-derived E0 configuration. Set
`VOICEID_SPEAKER_SCORE_THRESHOLD` explicitly when running a calibrated
experiment.

## Persistence And Privacy

In-memory stores support local development. Cloudflare D1 uses the v4 analysis-claim
tables from `voiceIdCloudflareD1SchemaStatements()`. Durable deployments wrap
templates with `VoiceIdTemplateWrappingEnrollmentStore` and an AES-GCM-256 key
configured at the storage boundary.

```sh
VOICEID_STORAGE_KIND=cloudflare-d1
VOICEID_TEMPLATE_KEY_SOURCE=cloudflare-workers-secret
VOICEID_TEMPLATE_KEY_ALGORITHM=AES-GCM-256
VOICEID_TEMPLATE_KEY_ID=voiceid-template-key-<version>
VOICEID_TEMPLATE_KEY_SECRET_BINDING=VOICEID_TEMPLATE_ENCRYPTION_KEY
VOICEID_TEMPLATE_KEY_ROTATION_VERSION=<rotation-version>
VOICEID_TEMPLATE_KEY_AAD_LABEL=voiceid-template-v1
```

Raw audio exists only during request parsing and verifier execution. Stores and
ordinary audit events exclude audio bytes, embeddings, complete transcripts,
and raw model output. Diagnostic retention is disabled by default and requires
explicit bounded configuration. Request and verifier boundaries cap encoded
audio at 32 MiB; decoding rejects media beyond 30 seconds and times out stalled
decoder processes.

## Research And Deployment Checks

```sh
pnpm -C voiceId bundle:guard
pnpm -C voiceId worker:guard
pnpm -C voiceId server-integration:guard
pnpm -C voiceId container:guard
pnpm -C voiceId aws:guard
pnpm -C voiceId nitro:guard
pnpm -C voiceId robot:guard
pnpm -C voiceId fixtures:validate
pnpm -C voiceId fixtures:validate:media
pnpm -C voiceId fixtures:evaluate:spectral
pnpm -C voiceId fixtures:evaluate:ecapa
pnpm -C voiceId pad:test
pnpm -C voiceId pad:evaluate
```

Fixture audio is a local research artifact and remains outside version control.
Model evaluation must use subject-disjoint speakers, multiple sessions,
multiple channels, and a representative replay/synthesis/injection corpus
before any threshold or PAD claim can advance.

## Next Gate

The active engineering plan is the standalone VoiceID engine:

1. build one reproducible accuracy, latency, and resource benchmark;
2. share one canonical decode, VAD result, and speech-window set across warm
   concurrent phrase, speaker, and PAD inference;
3. select and calibrate speaker, constrained phrase, and PAD models on held-out
   subjects and attacks;
4. improve continuous-enrollment template stability;
5. qualify optimized runtime builds with crash, overload, fuzz, and soak tests.

The detailed order and exit gates live in
[VoiceID MVP 1 Tasks](docs/voiceId-mvp-1-tasks.md). The
[signing security profile](docs/voiceId-signing-security-profile.md) retains the
deferred browser, authenticator, WebAuthn/CTAP2, Router, wallet, and
SigningWorker requirements without placing them in the active engine queue.

# VoiceID MVP

Standalone browser-captured, server-verified speaker verification MVP.

Phase 1 keeps VoiceID isolated from wallet/auth code. The server accepts typed
audio samples, runs phrase, quality, and speaker checks through a verifier
boundary, and stores enrollment/verification state without persisting raw audio.

Commands:

```sh
pnpm run voiceId:demo
pnpm -C voiceId type-check
pnpm -C voiceId test
pnpm -C voiceId dev:all
pnpm -C voiceId dev:all:verifier
pnpm -C voiceId dev:server
pnpm -C voiceId dev:verifier
pnpm -C voiceId dev
pnpm -C voiceId bundle:guard
pnpm -C voiceId worker:guard
pnpm -C voiceId server-integration:guard
pnpm -C voiceId container:guard
pnpm -C voiceId aws:guard
pnpm -C voiceId nitro:guard
pnpm -C voiceId robot:guard
pnpm -C voiceId smoke:python-http
pnpm -C voiceId fixtures:validate
pnpm -C voiceId fixtures:validate:media
pnpm -C voiceId fixtures:report
pnpm -C voiceId fixtures:evaluate:spectral
pnpm -C voiceId fixtures:evaluate:ecapa
pnpm -C voiceId verifier:test
pnpm -C voiceId container:build:cloudflare
```

`pnpm run voiceId:demo` is the repo-root alias for `dev:all`. It starts the API
on `http://127.0.0.1:5052` and the browser demo on `http://127.0.0.1:5050`.
`dev:all:verifier` starts the Python verifier sidecar with the ECAPA backend,
on `http://127.0.0.1:5051`, the API configured with
`VOICEID_VERIFIER_TRANSPORT=python-http`, and the browser demo.

Fixture capture exports should be placed in `voiceId/fixtures` with the manifest
named `voiceid-fixture-manifest.json`. Raw voice fixtures are local artifacts and
are ignored from git by default.

Use `fixtures:validate` for manifest and byte-length checks. Use
`fixtures:validate:media` when `ffprobe` is available and the fixture files
should be decoded enough to confirm they contain audio streams.

`fixtures:evaluate:ecapa` uses the optional SpeechBrain ECAPA-TDNN evaluator.
Install its Python dependencies before running it:

```sh
python3 -m pip install "speechbrain>=1.0.0" "torchaudio==2.6.*"
```

The first pretrained-model report is
`voiceId/verifier-spike/reports/speechbrain-ecapa-2026-06-11.md`.

The production-shaped Python verifier runs with the ECAPA backend by default
through:

```sh
pnpm -C voiceId dev:all:verifier
```

The current local ECAPA threshold from the browser fixture set is `0.6352`
(`ecapa-local-dev-v1`). Set `VOICEID_SPEAKER_SCORE_THRESHOLD` on the TypeScript
API process to override the speaker threshold. `dev:all:verifier` sets this
threshold automatically for the default ECAPA backend. Use
`VOICEID_VERIFIER_BACKEND=placeholder pnpm -C voiceId dev:all:verifier` only for
fast placeholder checks.

TypeScript server code can call the Python app through
`PythonSubprocessVoiceIdVerifierTransport` for local dev. It can call a
long-running sidecar through `PythonHttpVoiceIdVerifierTransport` when the
Python verifier is hosted as an HTTP process.

The TypeScript API server selects its verifier with:

```sh
VOICEID_VERIFIER_TRANSPORT=fake
VOICEID_VERIFIER_TRANSPORT=python-subprocess
VOICEID_VERIFIER_TRANSPORT=python-http
```

`python-http` expects the verifier sidecar at
`VOICEID_PYTHON_VERIFIER_URL`, defaulting to
`http://127.0.0.1:5051/voice-id/verifier/`. Run the sidecar locally with:

```sh
pnpm -C voiceId dev:verifier
```

Run the end-to-end API smoke through the Python HTTP verifier sidecar with:

```sh
pnpm -C voiceId smoke:python-http
```

Check that the Cloudflare Worker entrypoint avoids Node-only APIs with:

```sh
pnpm -C voiceId worker:guard
```

Check that the Python ECAPA verifier has a Cloudflare Container packaging
boundary with:

```sh
pnpm -C voiceId container:guard
```

The container Dockerfile lives at
`voiceId/deploy/cloudflare/verifier-container/Dockerfile`. Build it locally from
`voiceId/` with:

```sh
pnpm -C voiceId container:build:cloudflare
```

Check that the ordinary-server AWS runbook still uses the same Python HTTP
sidecar contract with:

```sh
pnpm -C voiceId aws:guard
```

The AWS verifier-service runbook lives at
`voiceId/deploy/aws/verifier-service/README.md`.

Check that the Nitro Enclave bridge shape stays narrow and uses the
parent-instance bridge boundary with:

```sh
pnpm -C voiceId nitro:guard
```

The Nitro Enclave bridge runbook lives at
`voiceId/deploy/aws/nitro-enclave-bridge/README.md`.

Check that the robot-local sidecar path uses the same HTTP verifier API and
Cloudflare-hosted policy boundary with:

```sh
pnpm -C voiceId robot:guard
```

The robot-local sidecar runbook lives at
`voiceId/deploy/robot-local/sidecar/README.md`.

Template encryption key config is parsed at the storage boundary. Cloudflare
deployments should provide:

```sh
VOICEID_TEMPLATE_KEY_SOURCE=cloudflare-workers-secret
VOICEID_TEMPLATE_KEY_ALGORITHM=AES-GCM-256
VOICEID_TEMPLATE_KEY_ID=voiceid-template-key-<version>
VOICEID_TEMPLATE_KEY_SECRET_BINDING=VOICEID_TEMPLATE_ENCRYPTION_KEY
VOICEID_TEMPLATE_KEY_ROTATION_VERSION=<rotation-version>
VOICEID_TEMPLATE_KEY_AAD_LABEL=voiceid-template-v1
```

Diagnostic artifact retention is disabled by default. Cloudflare R2 diagnostics
must be explicit:

```sh
VOICEID_DIAGNOSTIC_RETENTION=cloudflare-r2
VOICEID_DIAGNOSTIC_POLICY_VERSION=diagnostics-v1
VOICEID_DIAGNOSTIC_R2_BUCKET_BINDING=VOICEID_DIAGNOSTICS_BUCKET
VOICEID_DIAGNOSTIC_RETENTION_TTL_SECONDS=3600
VOICEID_DIAGNOSTIC_CAPTURE_AUDIO=true
VOICEID_DIAGNOSTIC_MAX_ARTIFACT_BYTES=1048576
```

Audit events include result kinds and coarse score bands only. They do not carry
raw audio, raw diagnostic media, embedding vectors, or full raw model outputs.

The existing-server integration boundary lives in
`voiceId/server/src/capability.ts`. `createVoiceIdServerCapability()` exposes
typed route metadata plus `Request -> Response` handlers so SDK server routers
can mount VoiceID without importing concrete VoiceID stores, verifiers, or
transcript providers.

The SDK relay routers expose a generic `RelayRouterOptions.routeExtensions`
hook. Cloudflare-only, Express-only, and universal extensions each carry their
own route metadata and runtime-native mount handlers. The SDK also exposes
generic `RelayRouterModule` registration for optional capabilities. VoiceID uses
that module surface to register `/voice-id/*` routes without adding VoiceID
imports to the wallet/auth router core.

`voiceId/server/src/sdkRelayExtension.ts` provides the server-side adapter:
`createVoiceIdRelayRouteExtension(createVoiceIdServerCapability(...))` returns a
universal relay extension, and
`createVoiceIdRelayRouterModule(createVoiceIdServerCapability(...))` wraps that
extension in the SDK module shape. Cloudflare calls the capability fetch handler
directly, and Express request/response conversion stays isolated at the adapter
boundary.

The owner-presence policy surface lives in `voiceId/shared/src/policy.ts`.
`buildVoiceIdOwnerPresenceResult()` converts completed verification records into
intent-bound owner-presence evidence, and
`evaluateVoiceIdOwnerPresenceForIntent()` rejects mismatched intent digests.
`voiceId/shared/src/authPolicy.ts` adds the SDK-facing policy adapter:
`authorizeVoiceIdOwnerPresence()` returns typed accepted evidence for wallet
sessions, wallet MPC signing, or robot commands, and returns rejected decisions
for intent mismatches, rejected owner presence, uncertain owner presence, and
expired evidence.

`POST /voice-id/owner-presence/authorize` is the server route for that policy
surface. It accepts a completed `verificationId`, `intentDigest`, use case, and
typed audio liveness and local device context signals. The route returns the
liveness result, the derived owner-presence result, and the final auth-policy
decision. Issued verifications that have not submitted an audio sample yet
return `invalid_state`.

Camera, face, mouth, and lip-sync work is not part of the current MVP. That
future track lives in
`docs/voiceID/voiceId-camera-liveness-future.md`. The current MVP keeps only the
audio/device liveness boundary in active code.

D1-compatible durable stores live in
`voiceId/server/src/store/CloudflareVoiceIdD1Stores.ts`. Use
`voiceIdCloudflareD1SchemaStatements()` to create the enrollment and
verification tables, then wire the D1 binding into
`CloudflareD1VoiceIdEnrollmentStore` and `CloudflareD1VoiceIdVerificationStore`.
The adapter uses Cloudflare-style prepared statements and parses persisted rows
back into typed VoiceID records at the storage boundary.

Cloudflare Worker runtime storage uses the D1 path when configured with:

```sh
VOICEID_STORAGE_KIND=cloudflare-d1
VOICEID_D1_DATABASE=<Cloudflare D1 binding>
```

Cloudflare Workers AI ASR is the first real transcript provider. It uses the
cheap `@cf/openai/whisper` model and stays behind the server-side
`VoiceIdTranscriptProvider` boundary:

```sh
VOICEID_TRANSCRIPT_PROVIDER=cloudflare-workers-ai
VOICEID_CLOUDFLARE_ASR_MODEL=@cf/openai/whisper
AI=<Cloudflare Workers AI binding>
```

The local Node dev server can use the same provider through the Cloudflare
Workers AI REST API:

```sh
CLOUDFLARE_ACCOUNT_ID=<account id> \
CLOUDFLARE_API_TOKEN=<workers ai token> \
VOICEID_TRANSCRIPT_PROVIDER=cloudflare-workers-ai \
pnpm run voiceId:demo
```

The browser demo also has a local phrase-check mode that uses the browser
`SpeechRecognition` API when available. If the demo is switched to simulated
phrase mode, the UI requires an explicit typed phrase and labels the phrase
result as simulated.

Keep `VOICEID_TRANSCRIPT_PROVIDER=fake` for deterministic local tests.

Template wrapping lives in
`voiceId/server/src/store/VoiceIdTemplateEncryption.ts`. The configured secret
must decode to a 32-byte AES-GCM-256 key. Wrap a durable enrollment store with
`VoiceIdTemplateWrappingEnrollmentStore` and `VoiceIdAesGcmTemplateCipher` so
enrolled templates are persisted as AES-GCM envelopes and unwrapped before the
verifier receives them.

Browser and mobile clients should not bundle PyTorch, SpeechBrain, or model
weights. They capture audio and call the VoiceID API; the server or local robot
sidecar owns ECAPA inference.

## Intent Binding

The shared browser/server layer exposes typed intent helpers in
`voiceId/shared/src/intents.ts`. Supported spoken command examples:

```text
send 1 USDC to Bob
send 50 USDC to bob.near
authorize wallet session for device X
command robot to stir the pot
```

`buildVoiceIdSpokenIntentBinding()` parses the spoken command, canonicalizes the
intent, and returns an unpadded base64url SHA-256 `intentDigest`. The digest
includes the intent kind, required fields, expiry, and nonce, so changing amount,
recipient, device, expiry, or nonce changes the digest.

Client capability constructors live in `voiceId/client/src/VoiceIdCapability.ts`.
Use `createVoiceIdApiOnlyCapability()` when a host app only needs the route
client. Use `createVoiceIdBrowserCaptureCapability()` when browser recording is
available; the recorder module is loaded lazily when `createRecorder()` is
called.

Cloudflare is the primary hosted deployment target. The TypeScript API/policy
boundary should stay Worker-compatible, and the Python ECAPA verifier should run
behind the HTTP sidecar boundary in Cloudflare Containers or a robot-local
sidecar. AWS ordinary-server and Nitro Enclave notes are optional SDK
portability references.

Cloudflare MPC signing is not a new VoiceID subsystem. VoiceID owner-presence
results should feed the existing Router A/B signer architecture in
`docs/router-A-B-signer.md`: Router admits an intent-bound request, normal
signing goes through the dedicated SigningWorker, and Deriver A/B stay off the
normal signing path.

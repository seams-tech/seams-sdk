# VoiceID Robot-Local Sidecar

Status: experimental embedded deployment; E2 disabled until calibration gates
pass.

Normative security requirements:
[VoiceID Signing Security Profile](../../../docs/voiceId-signing-security-profile.md).

This is the robot-local sidecar shape for a Reachy-style device. It keeps media
capture and low-latency verifier work near the robot. Cloudflare remains the
hosted Router A/B, policy, grant-state, and SigningWorker boundary.

Local execution alone does not make evidence signing-grade. The robot profile
must supply protected device proof, exact-media binding, calibrated PAD, an
approved capture profile, and the complete server-owned challenge flow before
it can construct E2. Until then, wallet operations require passkey.

## Processes

```text
reachy_app.py
  -> authenticated raw command request to Cloudflare
  -> server-canonical Router or robot-command binding
  -> server challenge and prompt
  -> one synchronized capture
  -> local quality/speaker/PAD components
  -> device signature over exact media hashes and binding
  -> E1 or future E2 evidence at the server boundary
  -> passkey or server R1 policy
  -> atomic Router grant reservation
  -> active SigningWorker
```

Recommended process boundaries:

- `reachy_app.py`: owns robot interaction, explicit listen behavior, prompt UI,
  synchronized microphone/camera capture, and robot actuation requests.
- `voiceid_sidecar`: owns audio decode, quality gates, ECAPA speaker matching,
  template building, and the same Python HTTP verifier API used by hosted
  deployments. Approved PAD may run behind a separate versioned adapter.
- `wallet_sidecar`: owns robot-local wallet client state, protected device key,
  local MPC client-share access, capture-statement signing, and authenticated
  calls to the Cloudflare API.
- Cloudflare Worker API: owns authentication, Router canonicalization,
  challenge creation, durable evidence/grant state, risk policy, x402/payment
  policy, Router admission, and the normal SigningWorker path.
- robot safety controller: independently admits or rejects motion, heat,
  pressure, cutting, force, tool, and workspace actions.

## Verifier API

The robot-local sidecar uses the same Python HTTP verifier API as local dev,
Cloudflare Containers, and ordinary servers:

- `POST /voice-id/verifier/extract-enrollment-embedding`
- `POST /voice-id/verifier/build-template`
- `POST /voice-id/verifier/verify-speaker`
- `GET /health`

Local environment:

```sh
VOICEID_VERIFIER_BACKEND=ecapa
VOICEID_VERIFIER_HOST=127.0.0.1
VOICEID_VERIFIER_PORT=5051
```

Caller environment:

```sh
VOICEID_VERIFIER_TRANSPORT=python-http
VOICEID_PYTHON_VERIFIER_URL=http://127.0.0.1:5051/voice-id/verifier/
VOICEID_VERIFIER_TIMEOUT_MS=10000
VOICEID_SPEAKER_SCORE_THRESHOLD=0.6352
```

Run the sidecar as a supervised process and expose it only on localhost. Remote
clients call the authenticated Cloudflare API. The ECAPA threshold above is a
local-development value and cannot construct E2.

## Enrollment

Signing-grade enrollment requires recent passkey or owner-admin authentication,
an enrolled protected device key, the approved robot capture profile, and
accepted enrollment PAD.

The user completes one continuous guided recording with three to five random
prompt fragments and a provisional 12-second usable-speech target. VAD creates
internal windows. The verifier rejects poor-quality, duplicate, multi-speaker,
prompt-incomplete, and embedding-incoherent windows, then builds a normalized,
quality-weighted template. Raw media is deleted after verified template
persistence.

## Owner Command Flow

```text
owner requests: "send 1 USDC to Bob"
  -> wallet_sidecar sends authenticated raw transaction fields
  -> Cloudflare resolves Bob and persists RouterVoiceIntentBinding
  -> Cloudflare returns one-use random prompt and capture profile
  -> reachy_app.py captures one response
  -> wallet_sidecar hashes exact uploaded bytes and signs capture statement
  -> local/hosted verifier returns separate phrase, speaker, quality, and PAD
  -> server verifies freshness, device proof, capture profile, and calibration
  -> unapproved profile returns E1 and passkey
  -> approved E2 enters server R1 policy
  -> Router atomically reserves an issued grant for the exact request digest
  -> reservation holder reaches SigningWorker
```

Speech never constructs or mutates the transaction. A changed transaction,
challenge, prompt, device, media hash, capture profile, identity, or expiry
requires a new attempt.

## Non-Owner Command Flow

For other speakers, policy rejects owner-only commands or returns a payment-
required path for explicitly public, low-risk actions. The x402/payment flow
belongs in the Cloudflare durable-state boundary.

```text
guest asks Reachy to perform a paid public task
  -> owner policy does not match the speaker
  -> Cloudflare returns payment requirements for exact RobotCommandDigest
  -> guest completes payment
  -> Worker verifies settlement and command scope
  -> independent safety controller evaluates the action
  -> Reachy receives a short-lived task authorization
```

Payment cannot buy privileged, owner-only, or unsafe robot commands. Protective
stop, pause, and freeze remain available without identity or payment.

## Capture Freshness And PAD

Keep these results independent:

- server challenge issue, receipt, expiry, and one-use state;
- exact original audio/video hashes;
- protected device-key signature and revocation state;
- approved microphone/camera capture profile;
- decoded usable-speech and single-speaker quality;
- phrase and speaker verification;
- calibrated audio PAD and, when required, audio-visual PAD.

Browser timestamps, microphone labels, source ids, local replay-risk flags, and
sidecar timestamps are telemetry. They cannot construct accepted freshness,
device proof, PAD, or E2.

Camera, face, mouth, active-speaker, and lip-sync work is specified in the
[Audio-Visual PAD Future Plan](../../../docs/voiceId-camera-liveness-future.md).

## Data Rules

Persist by default:

- encrypted template and enrollment assurance;
- model, threshold, aggregation, PAD, capture-profile, calibration, and policy
  versions;
- Router or robot-command binding;
- challenge, evidence tier, grant, reservation, and terminal state;
- device key id and revocation state;
- coarse audit result kinds and deletion receipts.

Do not persist by default:

- raw enrollment or verification media;
- embeddings outside the encrypted template store;
- full transcripts beyond the expected prompt;
- raw model responses, private keys, or signing shares.

Raw audio stays local when the approved verifier and PAD profile run locally.
Server-backed mode uploads exact capture bytes through the authenticated API.
Diagnostic upload always requires explicit consent, encryption, a short TTL,
and deletion enforcement.

## Cloudflare Primary Deployment

- Workers: authenticated API, Router binding, challenge creation, evidence
  assembly, R1 policy, x402/payment policy, and Router admission.
- Containers: hosted Python verifier and approved PAD adapters.
- D1 or Durable Objects: enrollment, verification, immutable binding,
  challenge, revocation, grant, reservation, terminal, and audit state.
- R2: opt-in diagnostic artifacts with explicit TTL and deletion receipts.

Robot-local components may compute low-latency evidence parts. The server parses
them once, verifies the device capture statement, assigns E0/E1/E2, and controls
all wallet admission.

## Validation

Run the local static guard:

```sh
pnpm -C voiceId robot:guard
```

Run the shared HTTP verifier smoke:

```sh
pnpm -C voiceId smoke:python-http
```

The security test plan adds challenge mutation, exact-media mismatch, device
revocation, injected audio, PAD attack classes, concurrent grant reservation,
terminal failure, and safety-state mutation coverage.

# VoiceID Robot-Local Sidecar

This is the robot-local sidecar shape for VoiceID. The concrete MVP target is a
Reachy-style robot, where `reachy_app.py` captures microphone input, then calls
a local VoiceID sidecar before allowing owner-only robot commands or wallet
actions.

Cloudflare is the primary hosted deployment target. The robot-local sidecar is
the embedded edge piece: it keeps capture and liveness close to the robot while
Cloudflare Workers, Containers, and the existing Router A/B SigningWorker path
handle hosted policy and signing flows.

## Processes

```text
reachy_app.py
  -> microphone capture
  -> local VoiceID client
  -> voiceid_sidecar over localhost
  -> ownerPresence + liveness + intentDigest evidence
  -> wallet_sidecar or Cloudflare Worker API
  -> Router A/B admission
  -> SigningWorker
```

Recommended process boundaries:

- `reachy_app.py`: owns robot interaction, wake/listen behavior, command UX,
  and robot actuation.
- `voiceid_sidecar`: owns audio decode, quality gates, ECAPA speaker matching,
  template building, and the same Python HTTP verifier API used by server
  deployments.
- `wallet_sidecar`: owns robot-local wallet client state, local MPC client-share
  access, payment client calls, and calls to the Cloudflare-hosted wallet API.
- Cloudflare Worker API: owns hosted route parsing, durable state, optional ASR,
  policy assembly, x402/payment policy, Router A/B admission, and the normal
  SigningWorker path.

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

For embedded Linux, run the sidecar as a supervised process and expose it only
on localhost. Browser, mobile, and remote users should call Cloudflare, not the
robot-local verifier port.

## Owner Command Flow

```text
owner says: "send 1 USDC to Bob"
  -> reachy_app.py captures audio
  -> local transcript or Cloudflare ASR produces canonical command
  -> intent canonicalizer builds intentDigest
  -> local VoiceID verifier checks quality and speaker
  -> local liveness policy checks microphone source, freshness, and replay risk
  -> ownerPresence evidence is assembled
  -> wallet_sidecar calls Cloudflare Worker API with intentDigest evidence
  -> Router A/B admits the request
  -> SigningWorker participates only for the admitted intent
```

VoiceID supplies ownerPresence evidence. It does not sign directly and it is not
a bearer secret.

## Non-Owner Command Flow

For other speakers, the local policy can reject owner-only commands or return a
payment-required path. The x402/payment flow belongs in the Cloudflare Worker
policy layer so payment settlement, replay protection, and task authorization
share the hosted durable-state boundary.

Example:

```text
Alice asks Reachy to perform a paid task
  -> local VoiceID says speaker is not owner
  -> Cloudflare Worker returns payment-required policy
  -> Alice scans a QR code or opens a payment link
  -> Worker verifies settlement
  -> Reachy receives a short-lived task authorization
```

## Data Rules

Raw audio stays local by default. Upload diagnostics only when explicitly
enabled with a retention window.

Persist by default:

- encrypted owner template
- model version
- threshold version
- policy version
- enrollment id
- verification id
- ownerPresence result
- liveness result
- intentDigest
- audit result kind

Do not persist by default:

- raw enrollment audio
- raw verification audio
- full unredacted transcripts beyond the canonical command

## Liveness

Robot liveness is a policy input separate from speaker matching:

- microphone capture timestamp
- speech duration and freshness
- microphone source attestation
- replay risk
- robot device id
- local sidecar id

Missing liveness should return `uncertain` for signing flows unless policy
explicitly allows voice-only demo mode.

Camera, face, mouth, and lip-sync liveness are deferred to
`voiceId/docs/voiceId-camera-liveness-future.md`.

## Cloudflare Primary Deployment

The robot sidecar should assume Cloudflare is the hosted control plane:

- Workers: capture-facing API, policy assembly, x402/payment policy, intent
  binding, and Router A/B admission.
- Containers: hosted Python ECAPA verifier for server-backed verification.
- D1 or Durable Objects: enrollment, verification, nonce, pending intent,
  consumed intent, and audit records.
- R2: opt-in diagnostic artifacts with explicit deletion policy.

Robot-local mode can verify owner presence locally for low-latency UX, then send
typed evidence to Cloudflare for hosted policy and signing. Server-backed mode
can upload typed captures to Cloudflare and use the hosted verifier Container.

## Validation

Run the local static guard:

```sh
pnpm -C voiceId robot:guard
```

Run the shared HTTP verifier smoke:

```sh
pnpm -C voiceId smoke:python-http
```

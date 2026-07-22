# VoiceID AWS Verifier Service

Status: optional ordinary-server verifier deployment; verifier output has no
signing authority.

Normative security requirements:
[VoiceID Signing Security Profile](../../../docs/voiceId-signing-security-profile.md).

This is the ordinary-server AWS deployment shape for the VoiceID Python verifier.
It uses the same HTTP sidecar contract as local development and Cloudflare
Containers.

## Runtime Shape

```text
browser, mobile, or robot
  -> VoiceID API service
  -> server-owned Router binding and challenge
  -> Python ECAPA verifier service
  -> VoiceID API service
  -> E0/E1/E2 evidence builder
  -> passkey or approved VoiceID authenticator assertion
  -> atomic Router A/B admission
  -> SigningWorker
```

The verifier does not own wallet signing. It returns quality, speaker, and
template results to the VoiceID API. It does not establish phrase correctness,
freshness, PAD, device proof, capture provenance, E2, or signing authorization.
Router A/B admission and SigningWorker remain responsible for the existing
normal-signing boundary.

## Image

Build the same verifier image from `voiceId/`:

```sh
docker build \
  -f deploy/cloudflare/verifier-container/Dockerfile \
  -t voiceid-verifier:local \
  .
```

Use `PRELOAD_ECAPA_MODEL=1` for production-style images that should avoid a slow
first ECAPA request. Preload proves availability only. E2 requires an immutable
approved record for the exact image digest, model weights, preprocessing,
threshold, capture profile, and calibration.

## Service Options

Use one of these ordinary-server placements:

- ECS service: run the verifier image as its own service and expose it only to
  the VoiceID API service through private service discovery or an internal load
  balancer.
- ECS sidecar: run the verifier container beside the TypeScript API container in
  the same task and point the API at `http://127.0.0.1:8797/voice-id/verifier/`.
- EC2 service: run the verifier container or process under the instance service
  manager and expose it only on a private interface.

Keep the browser and mobile clients on the VoiceID API. They should never call
the verifier service directly.

Cross-host API-to-verifier traffic requires authenticated and integrity-
protected transport, such as mTLS or a platform service binding with equivalent
workload identity. Enforce request-size, decoded-duration, media-container,
timeout, concurrency, and rate limits before inference. Verifier and proxy logs
must exclude raw media, embeddings, full transcripts, and raw model payloads.

## Environment

Verifier service:

```sh
VOICEID_VERIFIER_BACKEND=ecapa
VOICEID_VERIFIER_HOST=0.0.0.0
VOICEID_VERIFIER_PORT=8797
VOICEID_VERIFIER_MAX_CONCURRENT_INFERENCES=1
VOICEID_VERIFIER_QUEUE_WAIT_MS=250
VOICEID_ECAPA_MODEL_CACHE=/app/.cache/speechbrain-spkrec-ecapa-voxceleb
```

VoiceID API service:

```sh
VOICEID_VERIFIER_TRANSPORT=python-http
VOICEID_PYTHON_VERIFIER_URL=http://<verifier-host>:8797/voice-id/verifier/
VOICEID_VERIFIER_TIMEOUT_MS=10000
```

Health check:

```sh
curl http://<verifier-host>:8797/health
```

## Storage And Secrets

The verifier should receive only the data needed for the active verification
operation. Enrollment templates, threshold versions, verification state,
immutable Router bindings, server challenges, device and calibration versions,
revocation, deletion receipts, and audit records belong to the VoiceID API and
Router storage boundaries.

For ordinary AWS deployments:

- Store typed records in DynamoDB, Postgres/RDS, or the existing application
  database.
- Store opt-in diagnostic audio/video in S3 only with per-capture consent,
  encryption, separate access control, object-level expiry, and a maximum
  seven-day TTL.
- Encrypt ECAPA templates with KMS-backed envelope encryption and versioned AAD
  over subject, enrollment, template, model, threshold, key id, and key-rotation
  identities.
- Keep raw biometric clips out of persistent storage unless diagnostics are
  explicitly enabled.
- Keep E0/E1/E2 records structurally separate from passkey and VoiceID
  authenticator admission records.

## Nitro Enclave Boundary

Nitro Enclave support is a later hardening track. The ordinary-server verifier
service can stay outside the enclave. Use the parent EC2 instance as the bridge
when enclave-local policy, template-key unwrap, or SigningWorker share custody
is required.

The enclave boundary should receive typed policy or signing requests over the
parent-instance bridge. It should not require direct public network access, and
it should not become the capture-facing VoiceID API.

Moving policy or custody into an enclave does not upgrade browser evidence or
replace device-proof and PAD calibration requirements.

## Validation

Run the local static guard:

```sh
pnpm -C voiceId aws:guard
```

Run the existing HTTP sidecar smoke locally:

```sh
pnpm -C voiceId smoke:python-http
```

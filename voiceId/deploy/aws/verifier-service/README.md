# VoiceID AWS Verifier Service

This is the ordinary-server AWS deployment shape for the VoiceID Python verifier.
It uses the same HTTP sidecar contract as local development and Cloudflare
Containers.

## Runtime Shape

```text
browser, mobile, or robot
  -> VoiceID API service
  -> Python ECAPA verifier service
  -> VoiceID API service
  -> Router A/B admission
  -> SigningWorker
```

The verifier does not own wallet signing. It returns quality, speaker, and
template results to the VoiceID API. Router A/B admission and SigningWorker
policy remain responsible for intent-bound MPC signing decisions.

## Image

Build the same verifier image from `voiceId/`:

```sh
docker build \
  -f deploy/cloudflare/verifier-container/Dockerfile \
  -t voiceid-verifier:local \
  .
```

Use `PRELOAD_ECAPA_MODEL=1` for production-style images that should avoid a slow
first ECAPA request.

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

## Environment

Verifier service:

```sh
VOICEID_VERIFIER_BACKEND=ecapa
VOICEID_VERIFIER_HOST=0.0.0.0
VOICEID_VERIFIER_PORT=8797
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
pending intents, consumed intent nonces, and audit records belong to the
VoiceID API storage boundary.

For ordinary AWS deployments:

- Store typed records in DynamoDB, Postgres/RDS, or the existing application
  database.
- Store opt-in diagnostic audio/video in S3 with an explicit deletion policy.
- Encrypt ECAPA templates with KMS-backed envelope encryption before storage.
- Keep raw biometric clips out of persistent storage unless diagnostics are
  explicitly enabled.

## Nitro Enclave Boundary

Nitro Enclave support is a later hardening track. The ordinary-server verifier
service can stay outside the enclave. Use the parent EC2 instance as the bridge
when enclave-local policy, template-key unwrap, or SigningWorker share custody
is required.

The enclave boundary should receive typed policy or signing requests over the
parent-instance bridge. It should not require direct public network access, and
it should not become the capture-facing VoiceID API.

## Validation

Run the local static guard:

```sh
pnpm -C voiceId aws:guard
```

Run the existing HTTP sidecar smoke locally:

```sh
pnpm -C voiceId smoke:python-http
```

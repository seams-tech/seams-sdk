# VoiceID Nitro Enclave Bridge

This is the AWS Nitro Enclave bridge shape for VoiceID. It is a custody and
policy hardening track for AWS deployments that need enclave isolation around
template-key use, policy finalization, or SigningWorker share custody.

Nitro Enclaves have no external networking, no persistent storage, and no direct
interactive access. The parent EC2 instance owns network calls, storage calls,
logging, service discovery, and lifecycle management. The enclave receives only
small typed requests through the parent-instance bridge over vsock.

## Placement

```text
browser, mobile, or robot
  -> VoiceID API on parent-visible AWS service
  -> Python ECAPA verifier service outside enclave
  -> VoiceID policy assembler
  -> parent-instance bridge
  -> Nitro Enclave policy/custody worker over vsock
  -> parent-instance bridge
  -> Router A/B admission
  -> SigningWorker
```

Raw audio never enters the enclave. ECAPA model runtime stays outside the
enclave. The enclave receives quality, phrase, speaker, liveness, intent, and
storage metadata after the normal VoiceID API has parsed and normalized those
records.

## Parent Instance Responsibilities

The parent instance or parent-visible service owns:

- HTTPS ingress from browser, mobile, robot, or internal services.
- Audio upload parsing and raw audio retention policy.
- Calls to the Python ECAPA verifier service.
- Calls to ASR/transcript providers.
- Reads and writes for enrollment, verification, pending intent, consumed
  intent, and audit records.
- KMS, database, object storage, and service-discovery network calls.
- vsock transport to the enclave worker.

The parent instance is treated as an untrusted transport for the enclave
operation. It may assemble requests, but enclave policy should verify request
digests, nonces, versions, expiries, and KMS attestation context before using
plaintext keys or authorizing a signing decision.

## Enclave Responsibilities

The enclave can own one or more narrow operations:

1. `template_key_unwrap`: unwrap or use an encrypted template key under an
   attested KMS policy, then return only the minimum result needed by the
   parent-visible VoiceID service.
2. `policy_decision`: verify an owner-presence evidence bundle and
   `intentDigest`, then return an accepted, rejected, or uncertain policy
   decision.
3. `signing_worker_authorization`: verify that admitted Router A/B evidence
   matches the SigningWorker request transcript before server-share
   participation.

The enclave should avoid durable state. It can keep short-lived plaintext keys,
policy material, or MPC share material in memory for one operation window.

## Request Envelope

Use length-prefixed JSON or CBOR over vsock for the first implementation. The
typed envelope should be small and explicit:

```json
{
  "schemaVersion": 1,
  "requestId": "voiceid-enclave-request-...",
  "kind": "policy_decision",
  "issuedAt": "2026-06-13T00:00:00.000Z",
  "expiresAt": "2026-06-13T00:00:10.000Z",
  "nonce": "base64url-random-nonce",
  "intentDigest": "sha256:...",
  "ownerPresence": {
    "verificationId": "voiceid-verification-...",
    "enrollmentId": "voiceid-enrollment-...",
    "result": "accepted",
    "phrase": "accepted",
    "speaker": "accepted",
    "quality": "accepted",
    "liveness": "accepted",
    "modelVersion": "speechbrain-ecapa-voxceleb@...",
    "thresholdVersion": "ecapa-local-dev-v1",
    "policyVersion": "voiceid-policy-v1"
  },
  "routerAdmission": {
    "routerRequestDigest": "sha256:...",
    "deviceId": "device-...",
    "signingWorkerId": "signing-worker-..."
  }
}
```

Rules:

- `template_key_unwrap` requests include encrypted template-key material,
  template version, KMS key id, and attestation nonce.
- `policy_decision` requests include ownerPresence, transcript result, liveness
  result, `intentDigest`, policy version, expiry, and replay nonce.
- `signing_worker_authorization` requests include Router A/B admission evidence,
  SigningWorker id, request digest, `intentDigest`, expiry, and replay nonce.
- Responses include request id, result kind, policy version, reason code, and a
  digest of the accepted request.
- Responses never include raw audio, raw video, full transcripts beyond the
  canonical command, or plaintext template keys.

## Attestation And KMS

The enclave should generate an attestation document for sensitive operations.
KMS policy can bind decrypt or signing-key use to expected enclave measurements,
attestation nonce, image version, and parent instance context.

The parent instance forwards KMS requests or uses a KMS proxy. The enclave
validates that decrypted material corresponds to the request digest and expires
plaintext material immediately after use.

## Router A/B And SigningWorker Boundary

VoiceID supplies owner-presence evidence. Router A/B admission decides whether
an intent-bound request may reach the active SigningWorker. The enclave bridge
can harden the final policy decision or SigningWorker authorization, but it does
not replace Router admission.

SigningWorker participation must still bind to:

- `intentDigest`
- Router request digest
- device id
- expiry
- nonce
- policy version
- ownerPresence evidence digest

## Validation

Run the local static guard:

```sh
pnpm -C voiceId nitro:guard
```

Run the existing sidecar smoke for the non-enclave verifier path:

```sh
pnpm -C voiceId smoke:python-http
```

The first implementation task after this runbook is to add TypeScript envelope
types and parsers. The actual vsock transport should stay behind a bridge
adapter so local tests can use an in-memory transport.

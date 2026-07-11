# VoiceID Nitro Enclave Bridge

Status: optional custody/policy hardening track; it does not raise VoiceID
evidence assurance by itself.

Normative security requirements:
[VoiceID Signing Security Profile](../../../docs/voiceId-signing-security-profile.md).

This deployment uses AWS Nitro Enclaves for narrowly scoped template-key use,
R1 policy evaluation, or SigningWorker share custody. Nitro Enclaves have no
external networking, no persistent storage, and no direct interactive access.
The parent EC2 instance owns network and storage calls. Small typed requests
cross the parent-instance bridge over vsock.

Template/biometric policy and SigningWorker custody use separate enclave roles,
images, keys, and request unions. No enclave instance receives both biometric
template material and MPC share material.

## Placement

```text
browser, mobile, or robot
  -> authenticated VoiceID API on parent-visible AWS service
  -> server-owned Router binding and challenge
  -> Python ECAPA/PAD services outside enclave
  -> E0/E1 or E2 evidence builder
  -> parent-instance bridge
  -> Nitro Enclave key/policy/custody worker over vsock
  -> trusted Router grant store and atomic reservation
  -> active SigningWorker
```

Raw audio never enters the enclave. ECAPA model runtime stays outside the
enclave. PAD media inference also stays outside unless a separately measured
enclave build and capture profile are approved. The enclave receives only
parsed typed component results, `RouterVoiceIntentBinding`, version records,
and authenticated state references.

Browser capture remains E0. Moving policy or key custody into an enclave cannot
upgrade browser evidence to E2.

## Parent And Router Responsibilities

The parent-visible service owns:

- HTTPS ingress and route-boundary parsing;
- raw-media processing and deletion enforcement;
- calls to ECAPA, ASR, and PAD providers;
- construction and persistence of the Router binding and server challenge;
- encrypted enrollment/template records;
- device, model, threshold, calibration, and capture-profile revocation reads;
- transport over vsock;
- audit delivery without biometric payloads.

The trusted Router boundary owns durable grant state and the atomic
`issued -> reserved` transition. D1/Durable Objects, DynamoDB conditional writes,
or a transactional database may implement that state. The enclave cannot own
one-use semantics because it has no persistent storage.

Treat the parent as an untrusted transport for enclave operations. The enclave
verifies request digests, domain separators, nonces, versions, expiries,
attestation context, and authenticated state proofs issued by the trusted API,
Router, and grant store before using plaintext keys or returning an R1 risk
decision. Hash consistency without a trusted issuer is insufficient.

## Enclave Operations

The enclave supports only narrow operations:

1. `template_key_unwrap`: use an encrypted template key under attested KMS
   policy inside a dedicated biometric-processing enclave. Plaintext keys and
   templates remain inside that enclave; it returns only a typed comparison or
   newly encrypted template result.
2. `r1_policy_decision`: verify a parsed
   `VoiceIdSigningCandidateEvidence` bundle, the complete Router binding, risk
   inputs, calibration approval, and revocation proofs; return an accepted,
   step-up, or denied `VoiceIdRiskDecision`. It does not issue a bearer grant.
3. `signing_worker_authorization`: when the enclave hosts SigningWorker custody,
   verify a server-created `ReservedVoiceIdR1Grant` and the Router A/B request
   transcript before share participation.

The enclave keeps plaintext keys, policy material, and MPC share material in
memory for one operation window. It returns no reusable signing authority.

## Request Envelope

Use length-prefixed CBOR or a deterministic binary encoding over vsock for the
production boundary. JSON is acceptable only for the first local transport
spike. Parse the envelope once into a discriminated union.

Illustrative R1 policy request:

```json
{
  "schemaVersion": 2,
  "requestId": "voiceid-enclave-request-...",
  "kind": "r1_policy_decision",
  "issuedAt": "2026-07-11T00:00:00.000Z",
  "expiresAt": "2026-07-11T00:00:10.000Z",
  "nonce": "base64url-random-nonce",
  "routerBinding": {
    "operationId": "router-operation-...",
    "intentDigest": "base64url-public-digest",
    "signingPayloadDigest": "base64url-public-digest",
    "admittedSigningDigest": "base64url-public-digest"
  },
  "signingCandidate": {
    "kind": "signing_candidate_evidence",
    "verificationId": "voiceid-verification-...",
    "enrollmentId": "voiceid-enrollment-...",
    "speaker": "accepted",
    "phrase": "accepted",
    "quality": "accepted",
    "captureFreshness": "accepted",
    "pad": "accepted",
    "deviceProof": "verified",
    "captureProfile": "approved",
    "calibration": "approved"
  },
  "risk": {
    "requestedTier": "R1",
    "policyVersion": "voiceid-r1-policy-..."
  }
}
```

Rules:

- `template_key_unwrap` includes encrypted key material, template version, KMS
  key id, AAD digest, and attestation nonce.
- `r1_policy_decision` requires E2. E0/E1, raw scores, partial checks, and
  client-created identities or policy labels fail boundary parsing.
- `signing_worker_authorization` requires the exact Router request digest,
  reservation id, `ReservedVoiceIdR1Grant`, active SigningWorker id, expiry,
  and replay nonce.
- Responses include request id, exhaustive result kind, versions, reason code,
  and digest of the accepted request.
- Responses never include raw audio/video, embeddings, full transcripts,
  plaintext template keys, private signing keys, or shares.

## Attestation And KMS

The enclave generates an attestation document for sensitive operations. KMS
policy can bind decrypt or signing-key use to expected enclave measurements,
attestation nonce, image version, and parent-instance context.

The parent forwards KMS calls or uses a KMS proxy. The enclave verifies that
decrypted material matches the request AAD and digest, then erases plaintext at
the end of the operation window.

Attestation establishes the enclave build and key-release conditions. It does
not prove physical microphone provenance, PAD success, user consent, or correct
transaction display.

## Router A/B And Grant Boundary

E2 supplies evidence to R1 policy. An accepted risk decision causes the trusted
server to create an `issued` grant for one exact `RouterVoiceIntentBinding`.
Router atomically changes it to `reserved` before the first SigningWorker call.

SigningWorker authorization binds:

- grant and reservation ids;
- exact Router request digest;
- operation id and operation fingerprint;
- Router intent, signing-payload, and admitted-signing digests;
- subject, wallet, account, session, tenant, environment, network, and device;
- evidence, model, threshold, PAD, capture-profile, calibration, and policy
  versions;
- expiry, active SigningWorker identity, and normal-signing transcript.

Success transitions the grant to `consumed`. Timeout, cancellation, worker
failure, or response loss transitions it to `failed_closed`. It never returns
to `issued`.

## Validation

Run the local static guard:

```sh
pnpm -C voiceId nitro:guard
```

Run the existing sidecar smoke for the non-enclave verifier path:

```sh
pnpm -C voiceId smoke:python-http
```

Required tests cover envelope parsing, attestation/KMS failure, every field
mutation, E0/E1 rejection, revocation, stale calibration, concurrent grant
reservation, SigningWorker mismatch, terminal failure, and absence of biometric
data from logs and responses.

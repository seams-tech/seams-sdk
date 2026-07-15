# VoiceID AWS Nitro Enclave Bridge

Status: optional key and evidence hardening boundary; no VoiceID user
verification authority.

Normative security requirements:
[VoiceID Signing Security Profile](../../../docs/voiceId-signing-security-profile.md).

Nitro Enclaves have no microphone or direct peripheral path. They cannot own
voice capture and cannot implement the VoiceID authenticator boundary. This
deployment may protect template-key operations, validate typed evidence inputs,
or host an existing SigningWorker role. E0/E1/E2 evidence remains
signing-ineligible.

## Runtime Shape

```text
browser, iOS app, or robot
  -> ordinary VoiceID API and verifier
  -> E0/E1/E2 evidence
  -> parent-instance bridge
  -> vsock request to an attested enclave role
  -> typed evidence or key-operation result

wallet signing
  -> verified passkey or VoiceIdAuthenticatorAdmittedTransaction
  -> Router A/B admission
  -> active SigningWorker
```

Raw audio never enters the enclave. The ECAPA model runtime stays outside the
enclave. Neither an enclave signature nor Nitro attestation converts evidence
into authenticator UV.

## Enclave Constraints

Nitro Enclaves have no persistent storage and no external networking. The
parent EC2 instance is the parent-instance bridge for vsock transport, KMS
proxying, persistence, and service networking.

The parent is untrusted for plaintext enclave secrets. Every request includes a
fresh nonce, operation kind, caller workload identity, expiry, and complete
request digest. The enclave verifies its role-specific allowlist before using a
key.

## Supported Roles

### Evidence validation

The enclave may parse a `VoiceIdAttestedEvidence` bundle and verify:

- `RouterVoiceIntentBinding`, including `intentDigest`;
- device proof and exact-media hash;
- PAD, speaker, phrase, quality, freshness, capture-profile, model, threshold,
  and calibration versions;
- enclave request nonce, expiry, and workload identity.

The result is signing-ineligible evidence. It may be stored for audit, research,
or passkey step-up policy.

### Template key unwrap

A `template_key_unwrap` request may unwrap an encrypted template data key after
validating subject, enrollment, template, model, threshold, key version,
purpose, caller role, and expiry. Plaintext key material remains inside the
biometric enclave role.

### SigningWorker

An existing SigningWorker enclave may receive only a verified
`WalletSigningAuthorization` containing passkey admission or
`VoiceIdAuthenticatorAdmittedTransaction`. Raw evidence and raw assertion bytes
cannot enter that API.

Use separate enclave roles and separate KMS keys. No enclave instance receives
both biometric template material and MPC share material.

## Attestation And Key Policy

- Pin PCR measurements for the enclave image and role.
- Bind KMS key policy to the approved attestation document and workload role.
- Include version, nonce, expiry, request digest, and response digest in every
  vsock message.
- Reject debug builds, stale measurements, replayed nonces, unknown callers,
  and role mismatches.
- Rotate template and SigningWorker keys independently.

## Failure Rules

- Evidence validation failure returns rejected or uncertain evidence without a
  signing continuation.
- Template unwrap failure leaves the enrollment unavailable and may offer
  passkey recovery.
- SigningWorker failure closes the current Router attempt; retry requires a new
  cryptographic authorization ceremony.
- Parent disconnect, enclave restart, timeout, and response loss fail closed.

## Validation

- Raw media and ECAPA dependencies are absent from the enclave image.
- E0/E1/E2 cannot construct `WalletSigningAuthorization`.
- Nitro attestation cannot claim VoiceID UV.
- Template and SigningWorker roles use distinct images, policies, and KMS keys.
- Wrong nonce, expiry, caller, PCR measurement, role, Router binding, device
  proof, or evidence version fails closed.
- Only passkey or approved VoiceID authenticator admission reaches Router A/B
  and SigningWorker.

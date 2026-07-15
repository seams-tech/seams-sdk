# VoiceID Robot-Local Sidecar

Status: experimental robot-local evidence deployment; wallet signing requires
passkey or an approved VoiceID authenticator.

Normative security requirements:
[VoiceID Signing Security Profile](../../../docs/voiceId-signing-security-profile.md).

This runbook uses Reachy as the example robot. The local app and verifier may
produce E0/E1/E2 evidence for research and robot authority policy. Host-side
evidence never authorizes wallet signing.

## Runtime Shape

```text
Reachy microphone
  -> reachy_app.py
  -> wallet_sidecar capture boundary
  -> same Python HTTP verifier API
  -> E0/E1/E2 evidence
  -> robot authority policy + independent robot safety controller

wallet operation
  -> server-owned RouterVoiceIntentBinding and server challenge
  -> passkey or approved VoiceID authenticator assertion
  -> Router A/B admission
  -> SigningWorker
```

The robot host may produce a signed capture statement containing the server
challenge, prompt hash, Router binding, exact audio hash, capture interval,
microphone profile, model versions, and expiry. This device proof supports E2
attested evidence. It does not establish protected local biometric UV.

## Processes

### `reachy_app.py`

- owns robot microphone acquisition and command UX;
- displays or speaks the server-owned prompt;
- submits one continuous capture to `wallet_sidecar`;
- receives evidence and robot-policy outcomes;
- sends admitted robot commands to the independent safety controller.

### `wallet_sidecar`

- authenticates the robot and user session;
- requests the Router binding and challenge;
- hashes exact capture bytes and creates device proof;
- calls the local verifier endpoints;
- parses verifier output once at the boundary;
- submits evidence to the hosted policy service;
- requests passkey for wallet operations unless an approved external or
  embedded VoiceID authenticator is selected.

### Python verifier

The local sidecar uses the same Python HTTP verifier API as other deployments:

- `/voice-id/verifier/build-enrollment-template`
- `/voice-id/verifier/verify-speaker`
- `/health`

It returns component results and has no wallet authority.

## Local Configuration

```sh
VOICEID_VERIFIER_TRANSPORT=python-http
VOICEID_PYTHON_VERIFIER_URL=http://127.0.0.1:5051/voice-id/verifier/
VOICEID_VERIFIER_BACKEND=ecapa
```

The current development threshold is E0-only. E2 requires an immutable approved
record for the robot, microphone, capture profile, image, model, preprocessing,
threshold, PAD configuration, and calibration report.

## Evidence Path

```text
server challenge + RouterVoiceIntentBinding
  -> one robot microphone capture
  -> exact-media hash + device signature
  -> phrase + speaker + quality + freshness + PAD
  -> E0/E1/E2 evidence
  -> robot policy, policy shadowing, or passkey step-up
```

Raw audio stays local during ordinary operation and is deleted after the
terminal evidence result. Diagnostic retention requires explicit consent,
encryption, access control, purpose, and a short TTL.

## VoiceID Authenticator Option

For direct hands-free wallet authorization, add a dedicated microphone/MCU/
secure-element module or a production TEE profile that owns the microphone
peripheral. It exposes CTAP2 and returns a signed local-UV assertion.

```text
Router WebAuthn challenge
  -> protected module derives fresh phrase
  -> local speaker + phrase + quality + PAD
  -> protected counter and credential-key release
  -> signed UP + UV assertion
  -> Router verifies approved authenticator and operation
```

The ordinary Reachy Linux process transports the assertion. It cannot supply
audio to the authenticator or construct the admitted type.

## Robot Safety

Voice authority and safety are separate decisions:

```text
authorized owner command
  -> constrained robot command
  -> independent robot safety controller
  -> allowed motion or tool action
```

Emergency stop and protective pause remain ungated. Safety rejection overrides
identity authority. Multiple speakers, uncertain diarization, unsafe zones,
unexpected tools, stale state, and sensor faults fail closed.

## Storage And Privacy

The hosted service owns enrollment metadata, encrypted templates, immutable
Router bindings, challenges, evidence records, revocation, deletion receipts,
and audit events. It stores no default raw audio.

Audit data may include evidence tier, result kind, model and calibration
versions, device id, coarse score bands, Router digests, and timing bands. It
excludes audio, embeddings, full transcripts, and raw model payloads.

## Validation

- The current profile produces E0 or E1 until E2 calibration gates pass.
- E0/E1/E2 cannot construct wallet signing authorization.
- Browser and ordinary robot-host wallet operations require passkey.
- Device proof covers the exact capture and Router binding.
- PAD is independently calibrated by attack class and capture profile.
- Wrong challenge, intent, audio hash, device, model, expiry, or calibration
  invalidates E2.
- Raw audio deletion works on accepted, rejected, uncertain, expired, and
  failed branches.
- Only an approved VoiceID authenticator assertion can provide direct VoiceID
  wallet authorization.
- Router A/B and SigningWorker receive no raw evidence or biometric media.
- Robot safety tests remain independent of wallet authorization tests.

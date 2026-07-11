# VoiceID For Embedded Transaction Signing

Status: security positioning note.

Normative security requirements:
[VoiceID Signing Security Profile](voiceId-signing-security-profile.md).

This note explains how VoiceID should be framed for embedded devices, robotics,
and wallet transaction signing. It responds to common criticism of bank-style
voice authentication and clarifies the security role VoiceID plays in this
system.

## Core Position

VoiceID is a probabilistic speaker and spoken-intent signal. Browser capture can
support product experiments, accessibility, and risk policy. It cannot establish
trusted local presence because web microphone input and capture metadata are not
attested.

A future embedded VoiceID path may contribute E2 signing-candidate evidence only
after it satisfies the signing security profile: authenticated device proof,
trusted capture provenance, independent presentation-attack detection, a
server-generated challenge, exact transaction binding, and atomic one-use
admission.

VoiceID should never directly produce a wallet signature.

The signing authority remains cryptographic:

```text
owner speaks near embedded device
  -> server fixes the Router operation and issues a challenge
  -> approved device binds the exact capture to that challenge
  -> VoiceID verifies independent E2 checks
  -> server R1 policy issues one exact-operation grant
  -> Router reserves the grant atomically
  -> MPC signs only the admitted operation
```

Voice evidence enters a narrow admission policy. The device proof, server-owned
Router binding, one-use grant, MPC flow, and Router state transition define the
authorization boundary.

## Why Bank Voice ID Criticism Is Valid

Criticism of bank Voice ID is mostly correct for remote voice-password systems.
Those systems often treat a voiceprint as a reusable credential over a phone
channel. That is a weak design in the deepfake era because an attacker may be
able to replay, synthesize, or convert speech without being physically present.

Common failure patterns:

1. A static voiceprint acts like a password.
2. The user is remote and unseen.
3. The bank cannot bind the phrase to a live device context.
4. The same biometric signal is used for account recovery or broad account
   access.
5. Synthetic audio can be injected into the phone path.

Those critiques shape this threat model. An embedded VoiceID path is eligible
for study only when its device and capture guarantees are independently
specified and measured.

## Comparison With Platform Biometrics

Biometrics are probabilistic measurements and are not secrets.

Fingerprints can be lifted. Face scans can be spoofed. Voices can be cloned.
Those facts do not make biometrics useless. They mean biometric checks must be
bound to local device context, calibrated PAD, rate limits, and cryptographic
authorization.

TouchID and FaceID combine local comparison, protected sensors, platform rate
limits, trusted user interaction, and a hardware-backed key boundary. The
browser VoiceID MVP has a different assurance profile:

```text
platform biometric authenticator
  -> performs biometric comparison inside a protected authenticator boundary
  -> authorizes use of a device-bound private key
  -> returns a signed assertion without disclosing the biometric

browser VoiceID MVP
  -> records caller-controlled web audio
  -> measures phrase, quality, and speaker similarity
  -> returns experimental risk evidence that cannot authorize signing

future embedded VoiceID
  -> authenticates the device and capture session
  -> measures speaker, phrase, PAD, and optional audio-visual evidence
  -> contributes one input to tightly bounded policy
```

The biometric match is one input into a larger policy decision. A cloned voice
must not create signing authority.

## Rebuttal: Voice Cloning Alone Should Be Insufficient

Voice cloning is a serious bypass risk for voice-only authentication. The
embedded wallet design should require more than a matching voice timbre.

Required controls:

1. **Intent binding**: the spoken phrase or recognized command is bound to the
   exact action, recipient, amount, device, and expiry.
2. **Server challenge and capture binding**: the server issues the prompt only
   after the exact intent is fixed. An authenticated device signs the challenge,
   prompt hash, complete Router-binding digest, exact audio hash, capture
   interval, capture profile, and expiry.
3. **Presentation-attack detection**: an independently evaluated PAD path
   measures replay, synthesis, voice conversion, and injection risk. Challenge
   freshness alone is insufficient.
4. **Device-bound key material**: the client signing share remains on the
   embedded device or its sidecar.
5. **Server policy**: Router risk policy checks rate limits, device identity,
   allowed recipients, value limits, session freshness, and evidence versions.
6. **MPC signing**: a valid transaction signature requires participation from
   the device and server shares.
7. **Step-up policy**: high-value, new-recipient, anomalous, browser, or
   unsupported actions require passkey. A future phone/watch flow must return a
   device-bound cryptographic assertion before it can serve the same role.

The signing profile requires each layer to fail closed. The current browser MVP
does not satisfy this profile.

## Rebuttal: Prior Bank Bypasses Are Warnings, Not A Direct Match

Reported bank bypasses usually involve remote account access over phone audio.
That is a different setup from a robot or embedded device in the same room as
the owner.

Bank-style remote flow:

```text
caller audio
  -> remote phone channel
  -> bank voiceprint match
  -> broad account access or recovery
```

Embedded wallet flow:

```text
nearby owner command
  -> server-owned Router binding + challenge
  -> approved capture + exact-media device proof
  -> speaker + phrase + quality + freshness + PAD
  -> server R1 policy + one-use grant
  -> atomic Router reservation
  -> MPC signature for that operation only
```

The target boundary is narrow and one-use. Proximity itself is not trusted; the
approved capture profile and calibration must establish every claimed signal.

## Rebuttal: Cryptographic MFA Still Exists

MPC protects key custody and produces the signature. VoiceID supplies policy
evidence about the person and command. MPC does not improve the accuracy or
liveness of that evidence.

The embedded device should never treat a voiceprint as a private key, password,
seed phrase, or bearer token. VoiceID may supply E2 evidence to server policy.
Router admission still requires a reserved one-use grant, and the signature
still requires cryptographic shares.

## Embedded Device UX

Robotics changes the product constraint.

TouchID and FaceID are awkward for a moving robot, kitchen robot, tool-using
robot, or device across the room. The owner may be nearby while the robot is
busy, hot, wet, mobile, or physically unsafe to approach.

Voice is the natural command interface:

```text
"Send 1 USDC to Bob"
"Pay Alice for coffee"
"Start the paid demo mode"
"Stop"
```

For this class of device, the product goal is natural owner-command execution
within bounded risk. VoiceID supplies measured evidence while Router, MPC, and
robot safety policy enforce their separate boundaries.

## Policy Tiers

Use VoiceID differently based on risk.

| Action type                                                       | Required policy                                                             |
| ----------------------------------------------------------------- | --------------------------------------------------------------------------- |
| Browser wallet action                                             | Voice intent UX + user-verified passkey + exact intent binding              |
| Protective robot command                                          | No identity gate; safety controller handles execution                       |
| Low-risk owner robot action                                       | Authenticated device + speaker + challenge + calibrated PAD + safety policy |
| Low-value known-recipient embedded payment                        | Signing-grade voice evidence + strict caps/allowlist + exact intent + MPC   |
| New recipient, elevated value, export, recovery, or policy change | Passkey or equivalent cryptographic step-up                                 |

This keeps the happy path natural while preserving a clear escalation path.

## Recommended Wording

Use this framing in product and security docs:

> VoiceID supplies probabilistic speaker, spoken-command, and presentation-risk
> evidence for a specific, short-lived intent. Browser VoiceID is experimental
> and cannot authorize signing. An embedded deployment may construct E2 evidence
> only after authenticated capture, calibrated PAD, exact intent binding, and
> one-use policy admission succeed.

Short version:

> VoiceID supplies human evidence. A device-bound key and policy authorize the
> signature.

## Design Requirements

Before an embedded VoiceID flow can enter R1 signing policy:

1. The host derives identity and device scope from authenticated context rather
   than request-body identifiers.
2. Router typed transaction data is the source of truth for every signing
   digest and human-readable prompt.
3. The server issues a fresh challenge after fixing the exact intent.
4. The authenticated device binds the challenge, prompt, intent, audio hash,
   capture interval, and expiry in one signed proof.
5. Speaker, phrase, quality, capture freshness, PAD, device proof, and intent
   binding remain separate results.
6. Signing-eligible types require all mandatory results. Experimental and
   `not_required` branches cannot enter signing policy.
7. A storage transaction or compare-and-set operation reserves and consumes
   one-use authorization atomically with Router admission.
8. Raw audio and diagnostic media follow explicit retention and deletion rules.
9. High-risk transactions always require cryptographic step-up.

## What This Means For The MVP

The browser VoiceID MVP proves enrollment, speaker and phrase verification,
quality gates, verifier-boundary mechanics, intent-associated policy plumbing,
and experimental accepted/rejected/uncertain branches.

Completed research prerequisites:

1. Client/shared digest canonicalization and caller-supplied equality checks,
   classified as E0 prototype behavior.
2. Typed client-reported freshness and replay-risk policy inputs.
3. Client-reported device and sidecar context.
4. Wallet policy tiers and step-up results.
5. A deferred Router A/B adapter contract.

Remaining implementation work:

1. Replace fixed multi-sample enrollment with one guided continuous recording,
   internal VAD windows, and calibrated usable-speech evidence.
2. Replace client-asserted liveness with signing-profile evidence types.
3. Add authenticated subject and device proof to enrollment and verification.
4. Generate challenges and policy server-side and bind them to the exact Router
   digest tuple and captured-audio hash.
5. Implement and calibrate independent replay, synthesis, voice-conversion, and
   injection PAD.
6. Implement atomic authorization reservation and consumption.
7. Implement the concrete Router A/B admission adapter in
   [Router policy issuer](voiceId-router-policy-issuer.md).
8. Add an end-to-end test from an E2 policy-issued grant to Router
   admission, SigningWorker prepare/finalize, and signature after the normal SDK
   path works.
9. Calibrate speaker and PAD decisions with subject-disjoint human and attack
   fixtures across supported capture channels.

Camera, face, mouth, and lip-sync work is tracked separately in
[Audio-Visual PAD Future Plan](voiceId-camera-liveness-future.md).

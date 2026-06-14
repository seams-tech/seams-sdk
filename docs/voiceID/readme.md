# VoiceID For Embedded Transaction Signing

Status: security positioning note.

This note explains how VoiceID should be framed for embedded devices, robotics,
and wallet transaction signing. It responds to common criticism of bank-style
voice authentication and clarifies the security role VoiceID plays in this
system.

## Core Position

VoiceID is a local biometric owner-presence signal for an embedded device. It
belongs in the same product category as TouchID or FaceID: a liveness and
presence check that gates access to device-bound key material and policy-bound
signing flows.

VoiceID should never directly produce a wallet signature.

The signing authority remains cryptographic:

```text
owner speaks near embedded device
  -> device captures local voice and device context
  -> device derives or receives a bounded intent
  -> VoiceID checks local owner presence
  -> server policy checks risk and session constraints
  -> MPC signs only the bound intent
```

The voice signal helps decide whether the embedded client share may participate
in a signing session. The MPC flow, device-bound key material, server policy,
and intent digest define the actual authorization boundary.

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

Those critiques should shape our threat model. They do not rule out VoiceID as
a local presence factor for embedded devices.

## Rebuttal: VoiceID Is Like TouchID Or FaceID

Biometrics are presence signals. They are not secrets.

Fingerprints can be lifted. Face scans can be spoofed. Voices can be cloned.
Those facts do not make biometrics useless. They mean biometric checks must be
bound to local device context, sensor liveness, rate limits, and cryptographic
authorization.

The right comparison is:

```text
TouchID
  -> checks local finger presence
  -> unlocks device-bound key access
  -> secure enclave / OS policy gates use

FaceID
  -> checks local face presence
  -> evaluates liveness and attention
  -> device policy gates key use

Embedded VoiceID
  -> checks local owner voice presence
  -> pairs with command context, device policy, and optional step-up
  -> device + server policy gates MPC signing
```

The biometric match is one input into a larger policy decision. A cloned
fingerprint should not drain a wallet. A printed face should not drain a
wallet. A cloned voice should not drain a wallet.

## Rebuttal: Voice Cloning Alone Should Be Insufficient

Voice cloning is a serious bypass risk for voice-only authentication. The
embedded wallet design should require more than a matching voice timbre.

Required controls:

1. **Intent binding**: the spoken phrase or recognized command is bound to the
   exact action, recipient, amount, device, and expiry.
2. **Local freshness and replay resistance**: the robot or embedded device
   checks that speech is fresh, captured locally, and bound to the current
   command window. Camera-backed liveness is a separate future plan in
   `docs/voiceID/voiceId-camera-liveness-future.md`.
3. **Device-bound key material**: the client signing share remains on the
   embedded device or its sidecar.
4. **Server policy**: the server co-signer checks risk, rate limits, device
   identity, allowed recipients, value limits, and session freshness.
5. **MPC signing**: a valid transaction signature requires participation from
   the device and server shares.
6. **Step-up policy**: high-value, new-recipient, anomalous, or risky actions
   require phone, watch, passkey, or another explicit factor.

The attacker needs to satisfy a live local environment and policy stack. A
voice clone file alone should fail.

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
  -> local microphone + device context
  -> owner presence check
  -> intent digest
  -> device-bound client share
  -> server co-signer policy
  -> MPC signature for that intent only
```

The security boundary is narrower. The session is short-lived. The command is
scoped. The signing flow is tied to a specific intent.

## Rebuttal: Cryptographic MFA Still Exists

MPC is the cryptographic control.

VoiceID is a policy input. MPC is the signing mechanism.

The embedded device should never treat a voiceprint as a private key, password,
seed phrase, or bearer token. VoiceID authorizes the device to attempt a
policy-bound signing flow. The signature still requires cryptographic shares.

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
with bounded risk. VoiceID gives the device a local owner-presence signal while
MPC and policy enforce the transaction boundary.

## Policy Tiers

Use VoiceID differently based on risk.

| Action type | Required policy |
| --- | --- |
| Low-risk robot command | Voice match + local freshness |
| Owner-only robot action | Voice match + basic liveness |
| Low-value known-recipient payment | Voice match + intent binding + server policy + MPC |
| New recipient or medium-value payment | Voice + intent binding + MPC + tighter policy or step-up |
| High-value or anomalous payment | Voice + liveness + MPC + phone/watch/passkey step-up |

This keeps the happy path natural while preserving a clear escalation path.

## Recommended Wording

Use this framing in product and security docs:

> VoiceID is a biometric owner-presence check for embedded devices. It gates
> whether a device-bound signing share may participate in an MPC signing flow
> for a specific, short-lived intent. VoiceID does not replace cryptographic
> signing, server policy, or step-up authentication for risky transactions.

Short version:

> VoiceID is the presence signal. MPC is the signing control.

## Design Requirements

Before VoiceID can authorize embedded transaction signing:

1. Every signing request must have an `intentDigest`.
2. The spoken phrase or parsed command must bind to that `intentDigest`.
3. Voice matching must be separated from phrase or intent transcription.
4. Camera-backed liveness belongs to
   `docs/voiceID/voiceId-camera-liveness-future.md`.
5. The embedded device should keep its signing share device-bound.
6. The server co-signer should enforce risk policy before participating.
7. Raw audio and diagnostic media should have explicit retention rules.
8. High-risk transactions should require step-up authentication.

## What This Means For The MVP

The browser VoiceID MVP now proves enrollment, verification, phrase-match,
verifier-boundary mechanics, intent binding, liveness-aware owner-presence
policy, and wallet policy handoff.

Completed embedded transaction-signing prerequisites:

1. Intent-digest binding.
2. Owner-presence policy and replay resistance.
3. Device and sidecar policy context.
4. Wallet policy tiers and step-up results.
5. Router A/B normal-signing admission with matching `intentDigest`.
6. SigningWorker admission checks for admitted intent-bound requests.

Remaining implementation work:

1. Add normal SDK coverage for typed wallet policy consumption after
   owner-presence authorization.
2. Expand normal SDK demo or fixture coverage around that policy consumption.
3. Implement the concrete Router A/B policy issuer and key-management path in
   `docs/voiceID/voiceId-router-policy-issuer.md`.
4. Add an end-to-end test from accepted VoiceID wallet policy decision to Router
   JWT to admitted normal-signing request after the normal SDK path works.
5. Re-run fixture evaluation after verifier, threshold, or liveness-policy
   changes.
6. Collect true independent human different-speaker clips before tightening
   speaker thresholds.

Camera, face, mouth, and lip-sync work is tracked separately in
`docs/voiceID/voiceId-camera-liveness-future.md`.

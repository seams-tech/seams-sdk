# VoiceID Provider References

Status: research reference.

Normative signing requirements:
[VoiceID Signing Security Profile](voiceId-signing-security-profile.md).

Last reviewed: 2026-07-11. All product, certification, latency, accuracy, and
retention statements below are public vendor positioning to verify against a
dated primary source before use.

This document tracks credible VoiceID-as-a-service and voice biometric products
that can inform the wallet VoiceID design. The goal is to learn product shape,
API boundaries, risk controls, and UX patterns. These providers are references,
not integration commitments.

## Selection Criteria

A provider is worth studying if it has at least one of these signals:

- a production voice biometric authentication product
- an API, SDK, hosted service, private-cloud, or on-device deployment path
- public enterprise customers, partners, certifications, or analyst recognition
- explicit anti-spoofing, deepfake, liveness, or fraud-risk controls
- transaction, MFA, or high-risk action authorization language

## Highest-Relevance References

| Provider                                                          | Product shape                                                                                                                       | Public positioning to verify                                                                                                                                         | What to study                                                                                                                                                            |
| ----------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [ValidSoft](https://www.validsoft.com/)                           | Voice identity platform with Voice Verity, VoiceID, and VoiceMFA.                                                                   | Positions around deepfake detection, voice biometrics, MFA, contact center and digital channels, multiple deployment modes, and major MFA/contact-center partners.   | Transaction-bound voice authorization, device plus spoken digits plus voice, risk outcomes, and the difference between "real human", "right human", and "right outcome". |
| [Veridas](https://veridas.com/en/voice-biometric-authentication/) | Voice biometric authentication service with cloud storage, audio-file processing, streaming audio, and Genesys integration options. | Public success stories, vendor-described NIST/SdSV evaluation, 3-second authentication claims, anti-spoofing/deepfake detection, and voice vector storage model.     | Short enrollment and verification UX, provider-side voice vectors, anonymous account identifiers, PAD result shape, and API modes.                                       |
| [Daon](https://www.daon.com/)                                     | Identity platform with xVoice, xDeTECH synthetic voice detection, xAuth MFA, IdentityX, and TrustX.                                 | Long-running identity vendor, large-scale identity claims, financial services customers, crypto listed as an industry, and voice biometrics in its product taxonomy. | How voice becomes one auth factor inside broader identity orchestration. Study account projection, auth method selection, step-up, and risk policy.                      |
| [Mitek / ID R&D](https://www.miteksystems.com)                    | Digital identity and biometric authentication platform. ID R&D redirects into Mitek.                                                | Mitek markets MiPass as 4D biometric authentication with face match, face liveness, voice match, and voice liveness.                                                 | Bundled face/voice liveness, reusable identity/auth flow, and how voice is represented as one biometric signal inside identity verification.                             |

## Secondary References

| Provider                            | Product shape                                                                                                                      | Public positioning to verify                                                                                                                                                   | What to study                                                                                                                           |
| ----------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------- |
| [Pindrop](https://www.pindrop.com/) | Voice and video identity security for contact centers and meetings.                                                                | Mature voice security brand, Pindrop Passport for passive caller auth, Pindrop Protect for fraud risk, Pindrop Pulse for deepfake detection, major CCaaS/meeting integrations. | Passive authentication, device and behavior signals, risk scoring, fraud-watchlist ideas, and "right human" product framing.            |
| [Sensory](https://sensory.com/)     | On-device voice AI with text-dependent and text-independent speaker verification.                                                  | Long-running embedded voice vendor, on-device privacy positioning, voice biometrics and secure wake word products.                                                             | Local/on-device VoiceID, offline speaker verification, wake-word plus speaker verification, and privacy-preserving embedded deployment. |
| [VoicePIN](https://voicepin.com/)   | Voice authentication API for mobile apps, web apps, IVR, call centers, and IoT.                                                    | Public API/developer positioning, SaaS pricing language, playback detection, and multi-channel product claims.                                                                 | Simple developer-facing API shape, web microphone capture flow, sensitivity settings, playback detection, and pricing model.            |
| [Phonexia](https://phonexia.com/)   | On-premises and private-cloud speech platform for voice biometrics, speaker identification, transcription, and deepfake detection. | 20-year voice biometrics positioning, vendor-described NIST evaluation results, on-prem/private-cloud deployment, and forensic/call-center orientation.                        | Private deployment, sensitive audio handling, on-prem processing, and modular speech platform boundaries.                               |

## Cloud Reference

| Provider                                                                                       | Status                                                                                              | Useful pattern                                                                                                                                   |
| ---------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| [Amazon Connect Voice ID](https://docs.aws.amazon.com/connect/latest/adminguide/voice-id.html) | Retained as an architecture reference; verify current service availability before product planning. | Passive enrollment, net-speech requirements, voiceprints, spoof detection, known-fraudster watchlists, and encrypted stored audio/template data. |

## Open-Source And Model References

The local model/literature inventory lives in
[`voiceId/research/README.md`](../research/README.md). For provider teardown,
keep these as implementation comparison points:

| Project                                                                                                                                    | Use                                                                                                                   |
| ------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------- |
| [SpeechBrain](https://speechbrain.github.io/)                                                                                              | Open-source speech toolkit with speaker recognition and pretrained speaker verification models.                       |
| [pyannote.audio](https://github.com/pyannote/pyannote-audio)                                                                               | Speaker diarization and speaker embedding tooling. Useful if we need voiceprint or diarization comparisons.           |
| [NVIDIA NeMo Speaker Recognition](https://docs.nvidia.com/nemo-framework/user-guide/latest/nemotoolkit/asr/speaker_recognition/intro.html) | Speaker embedding and verification reference. Useful for TitaNet/ECAPA comparisons and production model alternatives. |

## Product Patterns To Borrow

The Veridas-specific public performance observations and research hypotheses are
tracked in
[`voiceId/docs/veridas-performance-benchmarks.md`](veridas-performance-benchmarks.md).

### Voice As Tiered Evidence

Commercial providers generally treat voice as a biometric verifier input, not as
a cryptographic secret. Our wallet boundary uses assurance tiers:

```text
browser capture
  -> E0 research evidence
  -> passkey authorization for the exact Router operation

approved embedded capture
  -> server-owned Router binding and unpredictable challenge
  -> exact-audio-hash device proof
  -> phrase + speaker + quality + freshness + calibrated PAD
  -> E2 signing candidate
  -> server R1 policy
  -> server-side one-use grant
  -> atomic Router reservation
```

VoiceID should not derive, unwrap, or store wallet signing material. It should
supply evidence to server policy, which gates the existing signing path.

### Three Result Layers

ValidSoft's product framing is a useful vocabulary reference when stated within
measured limits:

```text
bona-fide presentation within calibrated scope
  -> attack-class-specific PAD

right human
  -> enrolled speaker verification

right outcome
  -> server-canonical Router binding, prompt, device, and policy
```

The SDK should keep these as separate typed result branches. A good speaker
match should not hide a failed phrase match, stale intent digest, device
mismatch, or spoof risk.

### Device Binding

Signing-grade VoiceID requires a protected enrolled device key. The signature
covers the challenge, complete Router binding, prompt hash, exact uploaded-audio
hash, capture interval, and capture profile. A browser application key remains
E0 because it does not establish endpoint integrity or microphone provenance.

### Short-Lived Action Grants

The provider output is evidence. Server R1 policy may turn accepted E2 into an
opaque reference backed by a durable one-use record:

```text
E2 evidence
  -> issued server-side grant
  -> reserved for exact Router request digest
  -> consumed on success
     or failed_closed on terminal failure
```

Only explicit R1 policy can issue that grant. Browser, R2, and unsupported flows
require passkey. R3 operations prohibit VoiceID.

## Teardown Checklist

Use this checklist when analyzing provider docs, demos, or sales material.

- Enrollment
  - How many seconds of usable speech and how many authenticated sessions are
    required?
  - Can one continuous capture be segmented internally?
  - Is enrollment text-dependent, text-independent, or hybrid?
  - Does the provider store raw audio, embeddings, voiceprints, or both?
  - Is enrollment tied to a device, account identifier, or phone/call channel?
- Verification
  - How much audio is required?
  - Is verification passive or challenge-response?
  - Does the provider separately report speaker, phrase, quality, challenge
    freshness, and PAD?
  - Are thresholds configurable or fixed?
- Freshness and PAD
  - Does it detect replay, synthetic voice, voice conversion, or injection?
  - Are spoof scores returned separately from speaker scores?
  - Does the product claim real-time detection or async analysis?
- Policy and authorization
  - Does the provider issue a reusable session, one-use grant, or risk score?
  - Can the result bind to an operation, transaction, amount, recipient, or
    digest?
  - Does it model step-up requirements?
- Deployment
  - Cloud, private cloud, on-prem, on-device, or SDK?
  - Is there a browser/mobile capture SDK?
  - Is there a server-to-server API?
  - What compliance and data-retention controls are exposed?
- Developer experience
  - What does the simplest enrollment API look like?
  - What does the simplest verification API look like?
  - Are errors typed enough to drive UX?
  - Are there event streams or status phases for recording, processing, and
    policy decisions?

## Implications For Our SDK

- Treat E0/E1 as per-operation evidence capabilities, outside global wallet
  auth-method unions.
- Treat future E2 as input to server R1 policy, followed by a server-side
  one-use grant and atomic Router reservation.
- Keep passkeys as the client cryptographic authenticator. VoiceID should not
  become a key wrapper.
- Keep the VoiceID module responsible for capture, verification, provider
  adapters, template metadata, and policy evidence.
- Expose typed evidence events and opaque server handles. Wallet signing accepts
  only passkey admission or a reserved R1 grant.
- Start with our local verifier and fake/real ASR provider, but shape the
  boundary so a future provider can plug in behind the same result union.

## First Providers To Analyze

1. ValidSoft: highest relevance for transaction authorization and VoiceMFA.
2. Veridas: highest relevance for short enrollment/auth UX and provider API
   modes.
3. Daon: best reference for voice inside broader auth-method orchestration.
4. Sensory: best reference for a later on-device path.

Passive authentication, replay detection, on-device matching, or a short sample
duration does not make a provider output E2. E2 still requires the complete
device, capture, PAD, calibration, Router-binding, policy, and grant profile.

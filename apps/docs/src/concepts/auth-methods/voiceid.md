---
title: VoiceID
---

# VoiceID

VoiceID is an owner-presence signal. Threshold signing and policy are the
signing controls.

VoiceID verifies an enrolled speaker, spoken command, device context,
freshness, and policy constraints. It can issue a short-lived authorization
result that gates a specific signing continuation.

VoiceID is an authorization signal for a specific flow. It is not a wallet
private key, signing secret, recovery secret, account credential, or standalone
signing authority.

## Flow

```text
SDK transaction request
  -> canonical intent digest
  -> VoiceID command capture on enrolled device
  -> speaker, phrase, freshness, and device checks
  -> wallet policy decision
  -> one-use owner-presence or signing grant
  -> normal Router A/B signing continuation
```

## Policy Modes

Direct signing grants are appropriate only for low-risk, one-use, intent-bound
actions.

Riskier tasks should use VoiceID as the first check, then require passkey, Email
OTP, phone/watch, or another step-up method before export, recovery, new device
enrollment, high-value signing, new-recipient signing, or anomalous sessions.

## Requirements

1. Voice matching is separated from phrase or intent transcription.
2. The spoken command binds to the same `intentDigest` as the transaction.
3. Device binding is required for the tenable security model.
4. Voice templates and raw audio need explicit retention rules.
5. High-risk flows require step-up authentication.

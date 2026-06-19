# VoiceID Router Admission Adapter Contract

Status: deferred signing integration contract for the VoiceID policy to the
Router A/B signer normal-signing boundary.

This contract is for the later Router A/B signing phase. The current SDK test
track uses the normal SDK relay/module path with owner-presence policy results
and no Router A/B signer dependency.

## Purpose

VoiceID is owner-presence evidence. The admission adapter converts an accepted
wallet policy decision into evidence that Router admission can evaluate for one
concrete normal-signing intent.

Router remains the trusted admission boundary. VoiceID can supply policy
evidence, but Router derives the normal-signing admission material from the
typed Router A/B request:

```text
VoiceID verification
  -> owner-presence authorization
  -> wallet policy evaluation
  -> VoiceID admission evidence
  -> Router A/B normal-signing admission
  -> SigningWorker prepare/finalize
```

## Adapter Inputs

The adapter consumes a `VoiceIdWalletPolicyDecision`.

For `kind: "accepted"`, the decision must include:

- accepted owner-presence evidence
- accepted phrase/transcript result
- accepted speaker result
- accepted or explicitly-not-required liveness evidence
- `intentDigest`
- model version, threshold version, and policy version
- device and sidecar ids
- action tier
- Router A/B operation id and operation fingerprint
- Router A/B normal-signing `intent_digest`
- Router A/B `signing_payload_digest`
- Router A/B `admitted_signing_digest`

For `kind: "step_up_required"`, the adapter must not produce signing-admission
evidence from VoiceID alone.

## Router Admission Evidence

The evidence can be carried as a signed token, an internal server-side decision
record, or a typed in-process value, depending on deployment. Its semantics are
the same in each shape: it is an input to Router admission, not admission
itself.

Required evidence fields:

- `sub`: user subject
- `exp`: short-lived expiry, no later than the owner-presence intent expiry
- `sid` or `session_id`: session id
- `org_id`: organization id
- `project_id`: project id
- `environment`: environment id
- `account_id`: signing account id
- `operation_id`: Router A/B operation id
- `operation_fingerprint`: displayed operation fingerprint
- `intent_digest`: Router A/B normal-signing intent digest
- `voice_id_intent_digest`: VoiceID owner-presence intent digest when it differs
  from the Router A/B `intent_digest`
- `signing_payload_digest`: Router A/B typed signing-payload digest
- `admitted_signing_digest`: exact digest admitted for SigningWorker finalizer

All digest fields must use the same wire shape as `VoiceIdIntentDigest` and
Router A/B `PublicDigest32`: 43 base64url characters without padding. Router
rejects malformed, missing, stale, replayed, or mismatched values at the
admission boundary.

Admission evidence must not carry raw audio, diagnostic media, enrollment
templates, raw transcripts, private keys, client signature shares, or
SigningWorker material. The adapter audit record should include policy version,
decision kind, action tier, digest bands, and expiry.

## Router Admission

The client submits typed Router A/B normal-signing v2 requests:

- `RouterAbEd25519NormalSigningPrepareRequestV2`
- `RouterAbEd25519NormalSigningFinalizeRequestV2`

Router admission checks:

- verified session or bearer evidence
- accepted VoiceID wallet policy evidence
- request expiry and policy-evidence expiry
- session/account/project scope
- `intent_digest` equals the digest derived from the typed Router A/B
  normal-signing intent
- `signing_payload_digest` equals the digest derived from the typed signing
  payload
- `admitted_signing_digest` equals the digest admitted for the SigningWorker
  finalizer
- replay reservation for the Router normal-signing prepare/finalize lifecycle
- active `SigningWorker` state matches `NormalSigningScopeV1`

Router derives `RouterAbEd25519NormalSigningAdmissionMaterialV2` from the typed
intent and signing payload. Router forwards only admitted normal-signing
prepare/finalize work to the active `SigningWorker`. SigningWorker validates the
normal-signing scope, active SigningWorker identity, prepare binding,
signing-payload digest, and signature scheme before returning
`NormalSigningResponseV1`.

## Step-Up

New-recipient, high-value, or anomalous actions return `step_up_required` from
wallet policy. A later step-up flow may create a new accepted policy decision,
but the VoiceID-only decision remains non-signing.

## Remaining Work

- Implement the concrete admission adapter and any signed-evidence carrier the
  deployment needs.
- Add an end-to-end test from accepted VoiceID wallet policy decision to Router
  admission, SigningWorker prepare/finalize, and signature.
- Re-run fixture evaluation after verifier, threshold, or liveness-policy
  changes.
- Collect true independent human different-speaker clips before tightening
  speaker thresholds.

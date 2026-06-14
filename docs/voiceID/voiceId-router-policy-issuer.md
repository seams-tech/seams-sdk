# VoiceID Router Policy Issuer Contract

Status: deferred signing integration contract for the VoiceID policy to Router
A/B normal-signing boundary.

This contract is for the later Router A/B signing phase. The current SDK test
track uses the normal SDK relay/module path with owner-presence policy results
and no Router A/B issuer dependency.

## Purpose

VoiceID is owner-presence evidence. The Router A/B policy issuer converts an
accepted wallet policy decision into a short-lived Router JWT for one concrete
normal-signing intent.

The trusted issuer is the boundary between VoiceID policy and Router admission:

```text
VoiceID verification
  -> owner-presence authorization
  -> wallet policy evaluation
  -> policy issuer JWT
  -> Router A/B normal-signing admission
  -> SigningWorker
```

## Issuer Inputs

The issuer consumes a `VoiceIdWalletPolicyDecision`.

For `kind: "accepted"`, the decision must include:

- accepted owner-presence evidence
- accepted phrase/transcript result
- accepted speaker result
- accepted or explicitly-not-required liveness evidence
- `intentDigest`
- model version, threshold version, and policy version
- device and sidecar ids
- action tier

For `kind: "step_up_required"`, the issuer does not issue a normal-signing JWT
from VoiceID evidence alone.

## Router JWT

The JWT is an Ed25519-signed compact token whose public keys are configured in
the Router A/B Cloudflare adapter JWKS binding.

Router-required claims:

- `iss`: configured issuer
- `sub`: user subject
- `aud`: configured Router audience
- `exp`: short-lived expiry, no later than the owner-presence intent expiry
- `nbf`: optional not-before timestamp
- `iat`: optional issued-at timestamp
- `sid` or `session_id`: session id
- `org_id`: organization id
- `project_id`: project id
- `environment`: environment id
- `account_id`: signing account id
- `intentDigest`: unpadded base64url-encoded 32-byte digest string

`intentDigest` must use the same wire shape as `VoiceIdIntentDigest`: 43
base64url characters without padding. Router converts this claim into
`PublicDigest32` at the JWT boundary and rejects malformed, missing, or
mismatched claims.

The JWT must not carry raw audio, diagnostic media, enrollment templates, or raw
transcripts. The issuer audit record should include policy version, decision
kind, action tier, digest, and expiry.

## Router Admission

The client submits a `NormalSigningRequestV1` with the same `intent_digest`.

Router admission checks:

- JWT signature and configured issuer/audience
- request expiry and JWT expiry
- session/account/project scope
- `intentDigest` claim equals `NormalSigningRequestV1.intent_digest`
- replay reservation for the Router normal-signing request

Router forwards only a `CloudflareSigningWorkerAdmittedNormalSigningRequestV1`
to SigningWorker. SigningWorker validates accepted Router admission and the same
intent digest before executing the materialized signing handler.

## Step-Up

New-recipient, high-value, or anomalous actions return `step_up_required` from
wallet policy. A later step-up flow may create a new accepted policy decision
and issue a JWT, but the VoiceID-only decision remains non-signing.

## Remaining Work

- Implement the concrete policy issuer service and key-management path.
- Add an end-to-end test from VoiceID accepted policy decision to Router JWT to
  admitted normal-signing request.
- Re-run fixture evaluation after verifier, threshold, or liveness-policy
  changes.
- Collect true independent human different-speaker clips before tightening
  speaker thresholds.

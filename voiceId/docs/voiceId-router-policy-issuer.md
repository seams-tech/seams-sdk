# VoiceID Router Admission Adapter Contract

Status: target contract; implementation pending.

Normative security requirements:
[VoiceID Signing Security Profile](voiceId-signing-security-profile.md).

This document defines the only VoiceID path into the existing Router A/B
normal-signing boundary. The current browser and normal-SDK VoiceID paths
produce E0 research evidence and do not implement this adapter.

## Purpose

The adapter turns one server-side `issued` R1 grant into one atomically reserved
Router admission. It accepts a grant reference only when the grant was issued
from `VoiceIdSigningCandidateEvidence` for the exact canonical Router operation.

Browser evidence, E1 evidence, client-reported capture context, caller-selected
policy, and broad accepted liveness results are outside this contract.

Router remains the trusted admission boundary:

```text
server-canonical Router binding
  -> server challenge
  -> approved capture and E2 evidence
  -> server R1 policy
  -> issued one-use grant
  -> Router atomic reservation
  -> active SigningWorker
  -> consumed or failed_closed grant
```

VoiceID never invokes Deriver roles, handles signing shares, or constructs
`RouterAbEd25519NormalSigningAdmissionMaterialV2`.

## Adapter Input

The request boundary accepts an opaque grant reference alongside the normal
typed Router request. Authentication middleware supplies identity and tenant
scope. The client cannot provide authoritative identity, policy, evidence, or
digest fields.

```ts
export type VoiceIdRouterAdmissionRequest = {
  kind: 'voice_id_router_admission_request_v1';
  authenticatedContext: RouterAuthenticatedContext;
  grantReference: VoiceIdSigningGrantReference;
  normalSigningRequest: RouterAbEd25519NormalSigningPrepareRequestV2;
};
```

The adapter loads a server-side `VoiceIdSigningGrantState` and requires the
`issued` branch. The embedded grant contains:

- grant, verification, enrollment, policy, and calibration identifiers;
- user, wallet, account, device, session, organization, project, environment,
  and network scope derived by the server;
- the complete immutable `RouterVoiceIntentBinding`;
- speaker, phrase, quality, freshness, PAD, device-proof, capture-profile,
  model, threshold, and aggregation versions;
- issue and expiry times;
- maximum risk tier `R1`;
- no existing reservation or terminal result.

The adapter refuses:

- E0 or E1 evidence;
- an unapproved capture, model, threshold, PAD, or calibration version;
- client-created challenge, identity, policy, transcript, timestamp, source,
  replay-risk, or digest claims;
- expired, revoked, reserved, consumed, or failed-closed grants;
- any mismatch between authenticated scope, grant scope, stored Router binding,
  and the incoming typed Router request.

## Grant Reference And Server State

The grant is an authoritative server-side one-use record. A deployment may use
an authenticated opaque identifier or a signed reference to locate that record.
A self-contained bearer token cannot replace the state record or its atomic
transition.

An in-process adapter may pass a narrow server-created handle. The handle still
resolves to the same durable grant state before Router admission. Raw request
objects and client-created domain values never become trusted handles.

The grant record binds these Router fields through
`RouterVoiceIntentBinding`:

- operation id and operation fingerprint;
- Router normal-signing `intent_digest`;
- typed `signing_payload_digest`;
- `admitted_signing_digest` for the SigningWorker finalizer;
- subject, wallet, account, session, organization, project, environment, and
  network;
- expiry and policy version.

VoiceID does not maintain a second authoritative intent digest. Its challenge
digest is a domain-separated derivative of this Router tuple.

The evidence metadata also binds:

- server challenge id, nonce, and prompt hash;
- exact original capture hash;
- enrolled device-key thumbprint and capture-statement signature;
- capture-profile id;
- speaker, phrase, quality, PAD, model, threshold, aggregation, and calibration
  versions;
- grant id and maximum risk tier.

All `PublicDigest32` values use 43 unpadded base64url characters at the wire
boundary. The boundary parser rejects malformed values before core policy runs.

Grant records and audit events exclude raw audio, diagnostic media, templates,
embeddings, full transcripts, private keys, client shares, raw model responses,
and SigningWorker material.

## Atomic Router Admission

The client submits the existing typed Router A/B normal-signing v2 request.
Router performs one storage transaction or serialized Durable Object operation:

1. Authenticate the request and derive server identity and tenant scope.
2. Load the grant by opaque reference and require `kind: 'issued'`.
3. Rebuild `RouterAbEd25519NormalSigningAdmissionMaterialV2` from the typed
   normal-signing intent and payload.
4. Verify expiry, revocation, R1 policy, every scope field, every version, and
   the full Router digest tuple against the grant.
5. Derive the exact Router request digest.
6. Compare-and-set `issued` to `reserved`, recording the request digest,
   operation id, reservation id, and reservation time.

Only the process holding the resulting `ReservedVoiceIdR1Grant` may forward
prepare/finalize work to the active SigningWorker. A client cannot submit or
construct that type.

Router and SigningWorker independently validate the normal-signing scope,
active SigningWorker identity, prepare binding, signing-payload digest,
admitted-signing digest, signature scheme, expiry, and transcript fields already
required by the Router A/B specification.

## One-Use Lifecycle

The required lifecycle is:

```text
issued
  -> reserved(exact Router request digest)
  -> consumed(success)
     or failed_closed(timeout, cancellation, worker failure, response loss)

issued -> expired
issued -> revoked
```

Concurrent operations cannot reserve the same grant. A conflicting compare-and-
set loses before any SigningWorker call.

Server retries may observe the existing reservation only through a narrow
idempotency path for the same authenticated operation and exact request digest.
The reservation holder remains unique. Timeout, cancellation, SigningWorker
failure, or uncertain response delivery transitions to `failed_closed`. A
reserved grant never returns to `issued`; the user begins a new VoiceID
challenge.

Successful signing finalization transitions the reservation to `consumed` and
stores a non-sensitive signing receipt. Consumption is durably recorded before
an externally reusable success response is returned.

## Step-Up

Every browser/E0/E1 transaction follows the passkey path. New recipients,
elevated value, anomalous sessions, unsupported capture profiles, uncertain
checks, and all R2 operations also require passkey. R3 operations prohibit
VoiceID.

Passkey admission is independent. A voice failure does not prevent the user
from choosing passkey, subject to ordinary fraud and account policy.

## Failure And Audit Rules

- Missing or malformed inputs fail at the request boundary.
- Evidence, scope, digest, version, expiry, or policy mismatch fails before
  reservation.
- A race lost during reservation returns a replay/conflict result and never
  calls SigningWorker.
- Any terminal failure after reservation closes the grant permanently.
- Audit events record identifiers, evidence tier, reason codes, policy and model
  versions, coarse score bands, request digests, state transitions, and deletion
  receipts.

## Implementation Plan

- [ ] Add `VoiceIdSigningGrantState` storage with `issued`, `reserved`,
      `consumed`, `failed_closed`, `expired`, and `revoked` branches.
- [ ] Add branch-specific builders and static fixtures for issued and reserved
      state.
- [ ] Implement an authenticated opaque grant reference; keep authoritative
      evidence and scope server-side.
- [ ] Implement the Router adapter against the existing typed Router A/B
      builders.
- [ ] Add atomic compare-and-set storage for D1/Durable Objects and the selected
      ordinary-server store.
- [ ] Delete broad accepted policy and independent VoiceID digest inputs from
      signing-facing code and tests.
- [ ] Add passkey and E2 admission builders whose inputs cannot be interchanged.
- [ ] Add end-to-end prepare/finalize coverage through the active SigningWorker.

## Validation

- [ ] E0/E1 and raw verifier results fail static signing-call fixtures.
- [ ] Direct object literals, broad spreads, optional security fields, and
      unsafe casts cannot construct a reserved grant.
- [ ] Mutating any identity, tenant, Router, prompt, device, capture, version,
      policy, risk, or expiry field rejects admission.
- [ ] Two concurrent operations racing one grant produce one reservation and at
      most one SigningWorker call.
- [ ] Same-operation duplicate delivery remains single-owner and cannot produce
      a second signing call.
- [ ] Timeout, worker error, cancellation, and response loss produce
      `failed_closed` and cannot retry the grant.
- [ ] Passkey admission works without a successful VoiceID prerequisite.
- [ ] Logs and grants contain no raw media, embeddings, full transcripts,
      templates, shares, or raw model payloads.

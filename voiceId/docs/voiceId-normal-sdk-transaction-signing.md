# VoiceID Normal SDK Transaction Signing Plan

Status: E0 research integration exists; passkey and E2 admission work pending.

Normative security requirements:
[VoiceID Signing Security Profile](voiceId-signing-security-profile.md).

Related documents:

- [VoiceID MVP 1 tasks](voiceId-mvp-1-tasks.md)
- [VoiceID SDK auth integration](voiceId-sdk-auth-method-integration.md)
- [VoiceID MVP 2](voiceId-mvp-2.md)
- [Router admission adapter](voiceId-router-policy-issuer.md)
- [Router A/B signer architecture](../../docs/router-a-b-SPEC.md)

## Goal

Use browser VoiceID for spoken transaction confirmation and E0 research
evidence. A user-verified passkey authorizes every browser transaction for the
exact Router operation.

A future approved embedded path may authorize a capped R1 transaction only
after it produces E2, server risk policy issues a one-use grant, and Router
reserves that grant atomically.

```text
browser
  -> server-canonical Router operation and challenge
  -> E0 voice evidence
  -> passkey for the same Router operation
  -> ordinary Router admission
  -> active SigningWorker

approved embedded device
  -> server-canonical Router operation and challenge
  -> E2 signing-candidate evidence
  -> server R1 policy
  -> issued one-use grant
  -> atomic Router reservation
  -> active SigningWorker
```

Deriver A and Deriver B remain outside normal signing. VoiceID never imports or
calls role-specific signing internals.

## Current Implementation Boundary

The repository currently has:

- [x] VoiceID route mounting through the normal SDK module boundary.
- [x] Enrollment, verification, and owner-presence policy simulation.
- [x] A caller-owned command parser and digest-equality prototype.
- [x] Fake-verifier accepted, rejected, and uncertain branches.
- [x] Sequential expiry, mismatch, and duplicate-use coverage for the
      experimental authorization record.
- [x] Audit events that exclude raw audio.

Every item above is E0 research plumbing. The current path has no server-owned
Router challenge, passkey admission integration, E2 builder, signing-grade PAD,
atomic grant store, concrete Router adapter, or SigningWorker end-to-end test.
Sequential duplicate-use coverage does not prove concurrent one-use admission.

## Guardrails

- Browser capture always constructs E0.
- E0 and E1 cannot carry a signing candidate, grant, reserved admission, or
  signing continuation.
- The server authenticates identity and tenant scope before constructing the
  Router operation and challenge.
- The existing Router A/B typed intent and signing payload are the only
  authoritative transaction representation.
- A voice challenge digest is a domain-separated derivative of the Router
  digest tuple. VoiceID has no parallel authoritative transaction digest.
- Client timestamps, source labels, device ids, transcripts, policy labels,
  replay flags, and capture metadata are untrusted inputs.
- Fake verifier output cannot authorize a real Router or SigningWorker call.
- E2 requires accepted speaker, phrase, quality, freshness, PAD, device proof,
  capture profile, calibration, and Router binding.
- E2 remains evidence until server R1 policy issues a grant.
- Router reserves the grant before the first SigningWorker call.
- Terminal failure after reservation closes the grant permanently.
- R2 requires passkey. R3 prohibits VoiceID.

## Target Signing Boundary

Core signing accepts one of two admitted states:

```ts
export type VoiceIdTransactionAdmission = PasskeyAdmittedTransaction | ReservedVoiceIdR1Grant;

export type VoiceIdTransactionSigningResult =
  | { kind: 'signed'; receipt: NormalSigningReceipt }
  | { kind: 'passkey_required'; reason: VoiceIdStepUpReason }
  | { kind: 'rejected'; reason: VoiceIdRejectionReason }
  | { kind: 'uncertain'; reason: VoiceIdUncertainReason }
  | { kind: 'cancelled' }
  | { kind: 'failed'; reason: VoiceIdSigningFailureReason };

declare function signAfterAdmissionAccepted(
  admission: VoiceIdTransactionAdmission,
): Promise<VoiceIdTransactionSigningResult>;
```

The public flow cannot receive `ReservedVoiceIdR1Grant`. Router creates that
type only after the atomic server-side transition. All result switches are
exhaustive.

## Phase 0: Contract Cutover

- [ ] Add `VoiceIdExperimentalBrowserEvidence`,
      `VoiceIdStepUpOnlyEvidence`, and `VoiceIdSigningCandidateEvidence`.
- [ ] Add separate passkey and reserved-R1 admission builders.
- [ ] Replace broad owner-presence and liveness acceptance in signing-facing
      code with the tiered evidence union.
- [ ] Delete `liveness_not_required`, caller policy, and independent VoiceID
      transaction-digest inputs from the signing boundary.
- [ ] Add `@ts-expect-error` fixtures for direct E2/reserved-grant literals,
      broad spreads, optional security fields, unsafe casts, raw verifier results,
      and E0/E1 signing calls.
- [ ] Add exhaustive switches with `assertNever` for evidence, policy,
      admission, grant, and signing results.

Exit gate: no browser or fake-verifier value can call
`signAfterAdmissionAccepted`.

## Phase 1: Server-Owned Transaction And Challenge

- [ ] Authenticate the normal SDK request before VoiceID challenge creation.
- [ ] Build and persist `RouterVoiceIntentBinding` with the existing Router A/B
      typed builders.
- [ ] Derive the displayed summary from the same resolved operation.
- [ ] Issue a short-lived unpredictable prompt after the binding is fixed.
- [ ] Bind challenge id, prompt hash, expiry, identity scope, capture profile,
      and Router digest tuple in server state.
- [ ] Accept one challenge-response recording and at most one quality retry
      under a new challenge.
- [ ] Invalidate the challenge on submission, expiry, cancellation, or
      transaction mutation.
- [ ] Delete the caller-owned expected-phrase and authoritative digest path
      after migration.

Validation mutates amount, recipient, asset, account, network, operation,
payload, prompt, challenge, device, media hash, session, tenant, and expiry.
Every mutation must reject.

## Phase 2: Browser Passkey Signing

- [ ] Add browser orchestration that records E0 voice evidence, then offers
      passkey for the exact stored Router binding.
- [ ] Permit passkey selection even when voice is rejected, uncertain,
      unavailable, or skipped, subject to ordinary account policy.
- [ ] Build `PasskeyAdmittedTransaction` only after WebAuthn user verification
      succeeds and the assertion matches the Router challenge and scope.
- [ ] Route the admitted transaction through ordinary Router A/B signing.
- [ ] Keep the E0 result in audit/shadow telemetry and out of passkey authority.
- [ ] Add cancellation, passkey failure, challenge expiry, and transaction-
      mutation UX states.

The fake-verifier test flow uses fake voice plus a fake passkey admission
adapter. It never simulates real signing authority from fake voice.

## Phase 3: Embedded E2 Foundation

- [ ] Implement an approved capture agent with a protected enrolled device key.
- [ ] Sign the challenge, Router binding, prompt hash, exact uploaded-media hash,
      capture interval, and capture profile.
- [ ] Add calibrated audio PAD for replay, synthesis, conversion, splicing,
      injection, and relay classes.
- [ ] Add optional audio-visual PAD only through an approved profile.
- [ ] Construct E2 through a server-only branch-specific builder.
- [ ] Keep unsupported devices, profiles, models, languages, and uncertain
      checks in E1/passkey.
- [ ] Add revocation for enrollment, device, model, threshold, calibration, and
      capture profile.

Exit gate: the exact embedded profile passes the signing security profile’s
calibration, attack, privacy, shadow, and operational gates.

## Phase 4: R1 Policy And Atomic Grant

- [ ] Define explicit per-operation and rolling value caps, established-
      recipient age, allowlist, anomaly, rate-limit, retry, and grant-expiry rules.
- [ ] Evaluate only E2 with server-owned R1 policy.
- [ ] Store an `issued` grant containing the complete Router binding and all
      evidence/policy versions.
- [ ] Return only an authenticated opaque grant reference to the client.
- [ ] Implement `issued -> reserved -> consumed | failed_closed` plus
      `issued -> expired | revoked`.
- [ ] Compare-and-set `issued` to `reserved` for the exact Router request digest
      before any SigningWorker call.
- [ ] Make response loss, timeout, cancellation, and worker failure permanently
      `failed_closed`.
- [ ] Add a kill switch that routes every transaction to passkey.

## Phase 5: Router A/B Adapter

- [ ] Implement the contract in
      [Router admission adapter](voiceId-router-policy-issuer.md).
- [ ] Build `RouterAbEd25519NormalSigningPrepareRequestV2` with current branch-
      specific Router builders.
- [ ] Derive `RouterAbEd25519NormalSigningAdmissionMaterialV2` inside Router.
- [ ] Compare the derived intent, signing-payload, admitted-signing, operation,
      identity, tenant, policy, and expiry fields with the grant.
- [ ] Give only the reservation holder access to the active SigningWorker
      prepare/finalize path.
- [ ] Transition the grant durably before returning externally reusable success.
- [ ] Delete any temporary or duplicate VoiceID-specific Router request shape.

## Phase 6: Test And Developer Harness

- [ ] Update the normal SDK demo to use one guided enrollment recording and one
      challenge-bound verification recording.
- [ ] Show the canonical transaction summary and random prompt fragment.
- [ ] Label browser voice as experimental and show passkey as the authorizing
      action.
- [ ] Use a test-only synthetic E2 builder for isolated policy/grant tests. Keep
      it unreachable from production routes and bundles.
- [ ] Add an E2 Router end-to-end test through prepare, finalize, and signature.
- [ ] Add a test proving E0 success plus passkey signs through the passkey branch.
- [ ] Add a test proving passkey works after voice failure or skip.
- [ ] Add concurrent reservation tests with barriers, not sequential requests.
- [ ] Add mutation, expiry, revocation, duplicate delivery, response-loss,
      worker-failure, and kill-switch tests.
- [ ] Assert at most one SigningWorker call for every grant id.
- [ ] Delete fixtures and tests that treat broad accepted owner presence as
      signing authority.

## Phase 7: Calibration, Privacy, And Release

- [ ] Run the evidence-duration experiment with speaker-disjoint, cross-day,
      cross-device, language, noise, distance, and independent-human cohorts.
- [ ] Report speaker false-match/non-match and end-to-end false-grant rates with
      confidence intervals by capture profile and worst cohort.
- [ ] Report PAD attack-presentation and bona-fide rejection by attack class.
- [ ] Preserve original capture bytes only through verification, then delete
      them and record deletion receipts.
- [ ] Add template disable/delete, device revocation, diagnostic TTL, vendor
      deletion, backup expiry, and audit-minimization tests.
- [ ] Run a passkey-authorized shadow phase before an allowlisted capped R1
      pilot.
- [ ] Require independent security, privacy, product, and legal approval before
      production biometric enrollment.

## Acceptance Criteria

- Browser transactions require a user-verified passkey for the exact Router
  operation.
- Browser E0/E1, fake verifier output, and raw model output cannot construct a
  signing admission.
- The server owns the canonical Router binding and challenge.
- A future embedded transaction reaches signing only through E2, server R1
  policy, an issued grant, and atomic Router reservation.
- Router and SigningWorker reject every identity, tenant, operation, payload,
  challenge, device, media, version, policy, risk, and expiry mismatch.
- Two concurrent requests produce at most one reservation and one SigningWorker
  call.
- Every terminal failure after reservation closes the grant.
- R2 requires passkey and R3 prohibits VoiceID.
- Raw media, embeddings, templates, full transcripts, shares, and raw model
  responses never enter grants, Router state, SigningWorker input, or logs.

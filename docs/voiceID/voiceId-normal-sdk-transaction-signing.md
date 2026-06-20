# VoiceID Normal SDK Transaction Signing Plan

Status: implementation TODO list.

Related docs:

- [VoiceID MVP 1 tasks](voiceId-mvp-1-tasks.md)
- [VoiceID SDK auth method integration](voiceId-sdk-auth-method-integration.md)
- [VoiceID MVP 2](voiceId-mvp-2.md)
- [Router A/B signer architecture](../router-a-b-SPEC.md)

## Goal

Use VoiceID as an owner-presence policy input for transaction signing through
the normal SDK path first.

Target flow:

```text
SDK transaction request
  -> canonical VoiceID transaction intent
  -> intentDigest
  -> VoiceID verification
  -> owner-presence authorization
  -> wallet policy decision
  -> normal SDK signing path only when policy accepts
```

Router A/B signing integration now targets the signer architecture in
`docs/router-a-b-SPEC.md`: Router owns the public admission boundary, normal
signing flows through the active `SigningWorker`, and Deriver A/B stay out of
the hot signing path. VoiceID should depend on a narrow signing-gate adapter
around typed normal-signing prepare/finalize requests while avoiding concrete
Cloudflare role helpers.

## Guardrails

- VoiceID is owner-presence evidence. It never directly signs.
- The signing gate must require a matching `intentDigest`.
- Accepted VoiceID evidence is one-use and expiry-bound.
- Rejected, uncertain, expired, replayed, or mismatched VoiceID results cannot
  call the signing continuation.
- Step-up-required policy decisions cannot sign through VoiceID alone.
- The first implementation uses the normal SDK route/module path.
- Router A/B admission integration stays deferred until the normal SDK policy
  gate works.
- VoiceID must not call Deriver A, Deriver B, SigningWorker, or Cloudflare role
  internals directly.
- The VoiceID code should not duplicate Router A/B canonicalization. For signing
  integration, use the Router A/B v2 typed builders and vectors for
  `RouterAbEd25519NormalSigningIntentV2`,
  `RouterAbEd25519SigningPayloadV2`, and
  `RouterAbEd25519NormalSigningAdmissionMaterialV2`.

## Digest Boundary

The standalone voice loop can continue to use `VoiceIdIntentDigest` for spoken
command verification. The signing adapter must additionally bind the accepted
VoiceID evidence to the Router A/B normal-signing digest tuple:

- Router A/B `intent_digest`
- Router A/B `signing_payload_digest`
- Router A/B `admitted_signing_digest`

If VoiceID keeps a separate `voice_id_intent_digest`, the adapter must carry
both digests and prove they describe the same displayed transaction before
Router admission runs.

## Intermediate Phase: Prove The Voice Loop

Before integrating VoiceID into transaction signing, prove the standalone
VoiceID loop end to end:

```text
enroll owner voice with enrollment prompt samples
  -> build spoken command intent: "send 50 USDC to bob"
  -> record the spoken command
  -> verify phrase + speaker
  -> authorize owner presence for the intentDigest
  -> log accepted, rejected, or uncertain result
```

Enrollment and transaction verification are separate steps. Enrollment creates
the owner speaker template from enrollment-prompt samples. Transaction
verification uses the spoken transaction command as the expected phrase, checks
that the captured voice matches the enrolled speaker, then authorizes owner
presence for the matching `intentDigest`.

What already exists:

- [x] Enrollment lifecycle:
      start enrollment, record samples, require accepted samples, and finalize
      an enrolled template.
- [x] Verification lifecycle:
      start verification, bind it to `intentDigest`, record a sample, and
      produce accepted/rejected/uncertain verification results.
- [x] Spoken command parsing for token transfers such as
      `send 50 USDC to bob`.
- [x] Canonical `intentDigest` generation for spoken token-transfer commands.
- [x] Owner-presence authorization for completed verification records.
- [x] One-use owner-presence evidence after successful authorization.
- [x] Audit events for enrollment, verification, and owner-presence
      authorization.

What is still needed for the test loop:

- [x] Add a dedicated developer test path for this exact flow, using
      `send 50 USDC to bob` as the default spoken transaction command.
- [x] Show or persist a compact event log for:
      enrollment started, enrollment sample recorded, enrollment finalized,
      verification issued, verification completed, and owner-presence
      authorized.
- [x] Make accepted/rejected/uncertain verification outcomes easy to trigger in
      the fake-verifier path.
- [x] Add a route or harness assertion that the command phrase maps to the same
      `intentDigest` used by owner-presence authorization.
- [x] Add mismatch coverage proving completed VoiceID verification cannot
      authorize a different digest.
- [x] Add replay coverage proving accepted owner-presence evidence is one-use.
- [x] Keep this loop independent from normal SDK signing and Router A/B.

Acceptance for this intermediate phase:

- A developer can enroll a voice.
- A developer can speak or simulate `send 50 USDC to bob`.
- The system reports accepted, rejected, or uncertain.
- The system logs the result without raw audio or template material.
- The loop does not call any signing API.

## Phase 0: Freeze The Local Contract

- [ ] Define the local transaction-signing boundary as
      `VoiceIdTransactionSigningGate`.
- [ ] Make the gate accept an abstract transaction candidate instead of a
      concrete Router A/B request helper type.
- [ ] Make the gate receive a signing continuation callback:
      `signAfterVoiceIdAccepted(...)`.
- [ ] Return a discriminated result union:
      `signed`, `rejected`, `step_up_required`, `voice_id_required`,
      `cancelled`, and `failed`.
- [ ] Keep Router A/B signer API details contained to one adapter module.
- [ ] Add type fixtures proving rejected, uncertain, and step-up branches cannot
      carry a signing continuation result.

## Phase 1: Specify Transaction Intent Mapping

- [ ] Add a VoiceID transaction intent branch or a dedicated transaction-intent
      wrapper for normal SDK signing.
- [ ] Include required identity and signing fields:
      account id, network id, operation id, operation fingerprint, expiry,
      nonce, and transaction display summary.
- [ ] Include transaction-specific policy fields:
      recipient, token or asset, amount, chain/network, method/action kind,
      known-recipient status, and risk tier input.
- [ ] Include payload binding fields that can survive SDK signing refactors:
      Router A/B operation fingerprint, Router normal-signing `intent_digest`,
      `signing_payload_digest`, and `admitted_signing_digest` when available.
- [ ] Bind the VoiceID transaction intent to the same Router A/B typed normal
      signing intent used for admission.
- [ ] Build `intentDigest` from the canonical VoiceID transaction intent.
- [ ] Add fixtures showing amount, recipient, account, network, nonce, expiry,
      and payload changes all alter the digest.
- [ ] Add mismatch fixtures proving a spoken command for transaction A cannot
      authorize transaction B.

## Phase 2: Consume Owner-Presence In Wallet Policy

- [x] Extend normal SDK test coverage after
      `/voice-id/owner-presence/authorize`.
- [x] Convert the accepted owner-presence result into
      `VoiceIdWalletPolicyInput`.
- [x] Evaluate low-value known-recipient transactions as accepted.
- [x] Evaluate new-recipient transactions as `step_up_required`.
- [x] Evaluate high-value or anomalous transactions as `step_up_required`.
- [x] Preserve rejected, uncertain, expired, and intent-mismatch branches as
      non-signing policy decisions.
- [x] Add assertions that policy version, model version, threshold version,
      liveness evidence, device id, sidecar id, and `intentDigest` survive the
      adapter boundary.
- [ ] Add assertions that accepted wallet policy carries the Router A/B
      operation fingerprint and normal-signing digest tuple unchanged.

## Phase 3: Add The Normal SDK Signing Gate

- [ ] Implement the gate with this internal sequence:

```text
transaction candidate
  -> VoiceID transaction intent
  -> intentDigest
  -> start verification
  -> submit verification sample
  -> authorize owner presence
  -> evaluate wallet policy
  -> call signing continuation only for accepted policy
```

- [ ] Keep the signing continuation narrow: it receives the transaction
      candidate, the accepted wallet policy decision, and the matching
      `intentDigest`.
- [ ] Reject before signing when owner-presence authorization returns rejected,
      uncertain, expired, replayed, or mismatched evidence.
- [ ] Return `step_up_required` before signing when policy requires step-up.
- [ ] Add tests proving the continuation is never called for non-accepted
      branches.
- [ ] Add a source guard that the gate does not import Deriver A, Deriver B,
      SigningWorker, or Cloudflare role-specific code.

## Phase 4: Wire The Current Normal SDK Signing Path

- [ ] Add one adapter from `VoiceIdTransactionSigningGate` to the current Router
      A/B normal-signing v2 path.
- [ ] Build `RouterAbEd25519NormalSigningPrepareRequestV2` from the transaction
      candidate, active `NormalSigningScopeV1`, typed normal-signing intent, and
      typed signing payload.
- [ ] Derive `RouterAbEd25519NormalSigningAdmissionMaterialV2` and assert the
      wallet policy decision binds to the same `intent_digest`.
- [ ] Route accepted policy decisions through Router admission and the active
      `SigningWorker` prepare/finalize flow.
- [ ] Use the current branch-specific Router A/B builders for NEAR transaction,
      NEP-413, or delegate-action signing.
- [ ] Keep the adapter small so it can be replaced if public SDK helper names
      change.
- [ ] Delete any temporary adapter branch that exists only for a superseded
      signing request shape.

## Phase 5: Add SDK-Only End-To-End Coverage

- [ ] Add a normal SDK test harness that mounts VoiceID through
      `RelayRouterModule`.
- [ ] Run a fake-verifier flow:
      enroll, verify, authorize owner presence, evaluate wallet policy, and call
      a test signing continuation.
- [ ] Add an accepted low-value known-recipient transaction test.
- [ ] Add a step-up-required new-recipient transaction test.
- [ ] Add a high-value transaction test that blocks signing.
- [ ] Add an intent mismatch test where verification for transaction A attempts
      to sign transaction B.
- [ ] Add a replay test where the same owner-presence evidence is used twice.
- [ ] Add an expired-intent test.
- [ ] Add rejected and uncertain VoiceID tests.

## Phase 6: Add Demo Or Developer Harness

- [ ] Add a normal SDK transaction-signing demo path or scripted harness.
- [ ] Show transaction details before VoiceID capture:
      recipient, amount, token/network, account, expiry, and risk tier.
- [ ] Ask the user to speak the command derived from the displayed transaction.
- [ ] Show policy result:
      accepted, rejected, uncertain, or step-up required.
- [ ] Call a fake signing continuation first.
- [ ] Swap the fake continuation for the current Router A/B normal-signing
      adapter after the normal SDK policy gate passes.
- [ ] Keep fixture capture separate from transaction signing UX.

## Phase 7: Fixture And Threshold Readiness

- [ ] Collect true independent human different-speaker clips.
- [ ] Rerun the ECAPA fixture evaluation after those clips land.
- [ ] Recalibrate threshold only after the independent-speaker pass.
- [ ] Keep owner voice-variant refresh optional unless calibration remains
      ambiguous.
- [ ] Preserve raw-audio retention defaults and local fixture warnings.

## Phase 8: Router A/B Signing Integration

Start this phase after the normal SDK gate works.

- [ ] Map the accepted VoiceID wallet policy decision into Router A/B v2 normal
      signing admission for `RouterAbEd25519NormalSigningPrepareRequestV2`.
- [ ] Ensure Router A/B typed intent, signing payload, and VoiceID transaction
      intent bind to the same operation fingerprint, `intent_digest`,
      `signing_payload_digest`, and `admitted_signing_digest`.
- [ ] Add Router A/B E2E coverage from accepted VoiceID policy decision to
      Router admission, SigningWorker prepare/finalize, and signature.
- [ ] Keep Deriver A and Deriver B out of the normal signing hot path.
- [ ] Treat any signed VoiceID policy evidence as an input to Router admission,
      not as a replacement for Router-derived admission material.
- [ ] Delete any VoiceID-specific Router A/B compatibility path once the v2
      normal-signing path covers the active signing flow.

## Phase 9: Production Hardening

- [ ] Add audit events for transaction policy decisions with policy version,
      risk tier, result kind, and coarse score bands.
- [ ] Ensure audit events never include raw audio, raw templates, private keys,
      or full transaction secrets.
- [ ] Add rate limits for repeated VoiceID signing attempts.
- [ ] Add source guards proving VoiceID cannot call signing without an accepted
      wallet policy decision.
- [ ] Add source guards proving step-up-required policy decisions are
      non-signing.
- [ ] Document the supported transaction types and known non-goals.

## Acceptance Criteria

- A normal SDK transaction can be signed after accepted VoiceID owner presence
  and accepted wallet policy.
- A mismatched `intentDigest` cannot sign.
- Replayed owner-presence evidence cannot sign.
- Expired owner-presence evidence cannot sign.
- Rejected or uncertain VoiceID cannot sign.
- Step-up-required policy cannot sign through VoiceID alone.
- The first working path does not require VoiceID to bypass Router admission or
  call SigningWorker directly.
- The signing adapter can absorb Router A/B normal-signing SDK helper churn
  without changing VoiceID policy types.

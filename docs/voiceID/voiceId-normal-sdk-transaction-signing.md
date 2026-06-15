# VoiceID Normal SDK Transaction Signing Plan

Status: implementation TODO list.

Related docs:

- [VoiceID MVP 1 tasks](voiceId-mvp-1-tasks.md)
- [VoiceID MVP 2](voiceId-mvp-2.md)
- [Router A/B single wallet session plan](../router-a-b-single-session.md)
- [Router A/B signer architecture](../router-A-B-signer.md)

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

Router A/B signing integration remains a later hardening phase. The SDK signing
APIs are actively moving toward the single Wallet Session model described in
`docs/router-a-b-single-session.md`, so VoiceID should depend on a narrow
signing-gate adapter instead of concrete Router A/B helper names.

## Guardrails

- VoiceID is owner-presence evidence. It never directly signs.
- The signing gate must require a matching `intentDigest`.
- Accepted VoiceID evidence is one-use and expiry-bound.
- Rejected, uncertain, expired, replayed, or mismatched VoiceID results cannot
  call the signing continuation.
- Step-up-required policy decisions cannot sign through VoiceID alone.
- The first implementation uses the normal SDK route/module path.
- Router A/B issuer, JWT, and admission-token work stays deferred until the
  normal SDK policy gate works.
- The VoiceID code should not duplicate Router A/B canonicalization. When
  Router A/B v2 vectors are needed, use the Rust-vector-backed SDK builders.

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
- [ ] Keep signing API churn contained to one adapter module while
      `docs/router-a-b-single-session.md` is being implemented.
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
      transaction payload digest, Router A/B operation fingerprint, or current
      typed signing-payload digest when available.
- [ ] Build `intentDigest` from the canonical VoiceID transaction intent.
- [ ] Add fixtures showing amount, recipient, account, network, nonce, expiry,
      and payload changes all alter the digest.
- [ ] Add mismatch fixtures proving a spoken command for transaction A cannot
      authorize transaction B.

## Phase 2: Consume Owner-Presence In Wallet Policy

- [ ] Extend normal SDK test coverage after
      `/voice-id/owner-presence/authorize`.
- [ ] Convert the accepted owner-presence result into
      `VoiceIdWalletPolicyInput`.
- [ ] Evaluate low-value known-recipient transactions as accepted.
- [ ] Evaluate new-recipient transactions as `step_up_required`.
- [ ] Evaluate high-value or anomalous transactions as `step_up_required`.
- [ ] Preserve rejected, uncertain, expired, and intent-mismatch branches as
      non-signing policy decisions.
- [ ] Add assertions that policy version, model version, threshold version,
      liveness evidence, device id, sidecar id, and `intentDigest` survive the
      adapter boundary.

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
- [ ] Add a source guard that the gate does not import Router A/B issuer/JWT
      code.

## Phase 4: Wire The Current Normal SDK Signing Path

- [ ] Identify the current normal SDK signing entrypoint after the active
      Router A/B single-session refactor.
- [ ] Add one adapter from `VoiceIdTransactionSigningGate` to that entrypoint.
- [ ] Use the current Wallet Session credential model when the Router A/B v2
      SDK path is active.
- [ ] Use the current branch-specific request builder for NEAR transaction,
      NEP-413, or delegate-action signing when available.
- [ ] Keep the adapter small so it can be replaced when signing helper names
      settle.
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
- [ ] Swap the fake continuation for the current normal SDK signing adapter
      after the signing API refactor reaches a stable checkpoint.
- [ ] Keep fixture capture separate from transaction signing UX.

## Phase 7: Fixture And Threshold Readiness

- [ ] Collect true independent human different-speaker clips.
- [ ] Rerun the ECAPA fixture evaluation after those clips land.
- [ ] Recalibrate threshold only after the independent-speaker pass.
- [ ] Keep owner voice-variant refresh optional unless calibration remains
      ambiguous.
- [ ] Preserve raw-audio retention defaults and local fixture warnings.

## Phase 8: Router A/B Signing Integration

Start this phase after the normal SDK gate works and the single-session signing
refactor has a stable public SDK shape.

- [ ] Map the accepted VoiceID wallet policy decision into the Router A/B v2
      Wallet Session plus typed request flow.
- [ ] Ensure Router A/B request intent and VoiceID transaction intent bind to
      the same operation fingerprint and payload digest.
- [ ] Add Router A/B E2E coverage:
      accepted VoiceID policy decision to Router prepare/finalize to signature.
- [ ] Keep Deriver A and Deriver B out of the normal signing hot path.
- [ ] Keep Router A/B policy issuer/JWT work deferred unless the product needs
      a separate policy authority after the single-session model settles.
- [ ] Delete any VoiceID-specific Router A/B compatibility path once the v2
      Wallet Session path covers the active signing flow.

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
- The first working path does not require Router A/B issuer/JWT machinery.
- The signing adapter can absorb Router A/B single-session API churn without
  changing VoiceID policy types.

# VoiceID SDK Authorization Integration Plan

Status: per-operation E0 capability planned; global wallet auth method deferred.

Related documents:

- [VoiceID signing security profile](voiceId-signing-security-profile.md)
- [VoiceID UI/UX plan](voiceID-UI.md)
- [VoiceID MVP 1 tasks](voiceId-mvp-1-tasks.md)
- [Normal SDK transaction signing](voiceId-normal-sdk-transaction-signing.md)
- [Router admission adapter](voiceId-router-policy-issuer.md)
- [Router A/B signer architecture](../../docs/router-a-b-SPEC.md)

## Goal

Expose VoiceID as a per-operation SDK capability with explicit evidence tiers.
Browser VoiceID supplies spoken-intent UX and E0 research evidence. A passkey
authorizes the exact Router transaction. A future approved embedded path may
request server R1 admission after producing E2.

VoiceID is not added to global `WalletAuthMethod`, `AuthMethod`, account-option,
or session-auth unions during the E0/E1 phases. Those unions describe
authenticators with usable authority. Experimental biometric evidence has
different semantics.

## Current Integration Stance

- The current browser route/module and owner-presence policy paths are E0
  research plumbing.
- Passkey remains the cryptographic browser authorization method.
- Voice success is never a prerequisite for passkey. Rejection, uncertainty,
  outage, skip, or accessibility fallback may still lead to passkey under
  ordinary account policy.
- Email OTP may deliver notifications or recovery codes. It is not the signing
  step-up in this plan.
- VoiceID cannot unwrap, protect, restore, export, or enroll signing material.
- A browser key or `deviceId` string does not prove capture provenance, endpoint
  integrity, user verification, or physical microphone use.
- A future E2 path remains per-operation and issues no general signing session.

## SDK Semantics

The SDK exposes a `VoiceEvidenceCapability` beside auth capabilities:

```ts
export type VoiceEvidenceCapability = {
  beginTransactionAuthorization(
    input: VoiceIdTransactionAuthorizationInput,
  ): Promise<VoiceIdTransactionAuthorizationStartResult>;
};
```

`VoiceIdTransactionAuthorizationInput` contains the current authenticated wallet
session and raw transaction request. It contains no authoritative command,
expected phrase, identity, policy, digest, challenge, or expiry.

The server creates and returns an opaque operation handle plus display data:

```ts
export type VoiceIdTransactionAuthorizationStarted = {
  kind: 'voice_id_transaction_authorization_started';
  operationHandle: VoiceIdOperationHandle;
  displaySummary: VoiceIdTransactionDisplaySummary;
  prompt: VoiceIdPromptDisplay;
  captureProfile: VoiceIdCaptureProfileDisplay;
  expiresAtMs: number;
  submitCapture(input: VoiceIdChallengeCaptureInput): Promise<VoiceIdCaptureOutcome>;
};
```

The handle is an opaque reference to server-owned Router binding and challenge
state. It carries no client-readable grant or mutable lifecycle fields.

## Public Outcome Shape

The capture outcome separates evidence observation from authorization:

```ts
export type VoiceIdCaptureOutcome =
  | {
      kind: 'browser_evidence_observed';
      evidenceId: VoiceIdExperimentalEvidenceId;
      authorizeWithPasskey(): Promise<PasskeyTransactionAuthorizationResult>;
    }
  | {
      kind: 'step_up_required';
      reason: VoiceIdStepUpReason;
      authorizeWithPasskey(): Promise<PasskeyTransactionAuthorizationResult>;
    }
  | {
      kind: 'embedded_e2_observed';
      observationHandle: VoiceIdE2ObservationHandle;
      requestR1Signing(): Promise<VoiceIdR1SigningResult>;
    }
  | {
      kind: 'voice_unavailable';
      reason: VoiceIdUnavailableReason;
      authorizeWithPasskey(): Promise<PasskeyTransactionAuthorizationResult>;
    }
  | {
      kind: 'rejected';
      reason: VoiceIdRejectionReason;
      authorizeWithPasskey(): Promise<PasskeyTransactionAuthorizationResult>;
    }
  | {
      kind: 'uncertain';
      reason: VoiceIdUncertainReason;
      authorizeWithPasskey(): Promise<PasskeyTransactionAuthorizationResult>;
    }
  | { kind: 'expired' }
  | { kind: 'cancelled' }
  | { kind: 'failed'; reason: VoiceIdFlowFailureReason };
```

`requestR1Signing()` calls a server operation that evaluates E2 against current
R1 policy, creates an issued grant, atomically reserves it in Router, and enters
normal signing. The public client never receives
`VoiceIdSigningCandidateEvidence`, `VoiceIdSigningGrant`, or
`ReservedVoiceIdR1Grant`.

The browser flow always returns a branch with `authorizeWithPasskey()` or a
terminal lifecycle result. It never exposes `requestR1Signing()`.

## Example

```ts
const started = await seams.voiceEvidence.beginTransactionAuthorization({
  walletSession,
  transaction,
});

if (!started.ok) return started;

const outcome = await started.value.submitCapture({ capture });

switch (outcome.kind) {
  case 'browser_evidence_observed':
  case 'step_up_required':
  case 'voice_unavailable':
  case 'rejected':
  case 'uncertain':
    return outcome.authorizeWithPasskey();
  case 'embedded_e2_observed':
    return outcome.requestR1Signing();
  case 'expired':
  case 'cancelled':
  case 'failed':
    return outcome;
  default:
    return assertNever(outcome);
}
```

The convenience API may perform this orchestration internally. The domain
branches remain available for custom UI and exhaustive handling.

## Device And Capture Binding

Signing-grade enrollment binds the template to an enrolled device key,
approved capture profile, and assurance class. E2 verification requires a
device signature over:

- server challenge id and nonce;
- complete Router binding digest;
- prompt hash;
- exact uploaded-audio hash and any approved synchronized-video hash;
- capture start/end times;
- capture-profile id.

The server recomputes the media and binding hashes, verifies the signature,
enforces its own issue/receipt window, checks revocation, and parses the result
once into precise domain types. Client timing and sensor labels remain advisory.

## Existing Patterns To Reuse

| Pattern                     | Existing surface              | VoiceID use                                                          |
| --------------------------- | ----------------------------- | -------------------------------------------------------------------- |
| Result unions               | SDK public APIs               | Recoverable start, capture, passkey, and R1 outcomes                 |
| Domain dependency injection | `SeamsWeb` capability methods | Inject `VoiceEvidenceCapability` without widening wallet auth unions |
| React hooks                 | Existing auth hooks           | Reuse `busy`, `error`, and `start(...)` ergonomics                   |
| Route modules               | `RouterApiModule`             | Mount VoiceID-owned authenticated routes                             |
| SDK events                  | Typed SDK sent events         | Add enrollment, challenge, evidence, fallback, and terminal phases   |
| Normal signing              | Existing signer capability    | Accept only passkey admission or reserved R1 grant                   |

Account projection may display VoiceID enrollment status as a separate security
or accessibility capability. It must not present E0/E1 as an enabled signing
auth method.

## Phase 0: Evidence Contract Cutover

- [x] Mount experimental VoiceID routes through `RouterApiModule`.
- [x] Exercise enrollment, verification, and owner-presence policy simulation
      through the normal SDK host.
- [x] Preserve rejected, uncertain, expired, mismatch, and sequential duplicate
      branches as non-signing outcomes.
- [ ] Introduce E0/E1/E2 evidence and delete broad signing-facing
      owner-presence/liveness acceptance.
- [ ] Rename client liveness and device claims to untrusted capture telemetry.
- [ ] Add static fixtures proving E0/E1 cannot construct grants, reserved
      admission, or signing continuations.
- [ ] Mark the current caller-owned command/digest path E0 and delete it after
      the server-owned binding path lands.

## Phase 1: Per-Operation Public Capability

- [ ] Add `VoiceEvidenceCapability` and the branch-specific types above.
- [ ] Add `beginTransactionAuthorization(...)` to the public SDK capability
      dependency shape.
- [ ] Implement it in `SeamsWeb` without changing global wallet auth unions.
- [ ] Return Result-style unions for boundary and recoverable failures.
- [ ] Keep enrollment, verification, passkey, and R1 methods available only on
      their valid lifecycle branches.
- [ ] Add exhaustive public type fixtures and source checks.
- [ ] Emit typed events without raw audio, transcript, embedding, or model
      payload data.

## Phase 2: Recorder And React Adapter

- [ ] Add `useVoiceIdTransactionAuthorization(...)` with `start`, `busy`, and
      `error` ergonomics.
- [ ] Accept a recorder adapter; keep microphone UI outside core domain logic.
- [ ] Implement one guided enrollment recording with internal progress and one
      verification recording per challenge.
- [ ] Stop media tracks on every terminal branch and keep raw blobs only in
      active capture state.
- [ ] Offer passkey immediately when microphone permission is denied, capture is
      unsupported, or the user skips voice.
- [ ] Export the hook and public evidence types from the React entrypoint.

## Phase 3: Authenticated Server Operation

- [ ] Replace request-body identity, challenge, policy, expected phrase, and
      device context with authenticated server-derived state.
- [ ] Build and persist `RouterVoiceIntentBinding` before challenge creation.
- [ ] Issue the prompt, nonce, expiry, and capture profile server-side.
- [ ] Validate original capture bytes and exact-media hash at the route boundary.
- [ ] Keep concrete stores, verifier adapters, transcript providers, and PAD
      construction inside VoiceID-owned server setup.
- [ ] Add enrollment assurance, device registration, revocation, and deletion
      records.

## Phase 4: Browser Passkey Path

- [ ] Bind WebAuthn user verification to the same Router operation and session.
- [ ] Return `authorizeWithPasskey()` for E0, E1, unavailable, rejected, and
      uncertain browser outcomes.
- [ ] Permit direct passkey selection before or instead of voice capture.
- [ ] Call normal signing only with `PasskeyAdmittedTransaction`.
- [ ] Prove voice evidence cannot influence passkey assertion validation or
      widen the admitted operation.

## Phase 5: Embedded E2 Observation

- [ ] Add approved-device capture, exact-media proof, PAD, calibration, and
      capture-profile builders.
- [ ] Add a server-only E2 builder and opaque `VoiceIdE2ObservationHandle`.
- [ ] Keep the handle scoped to one subject, wallet, session, device, Router
      operation, challenge, policy version, and short expiry.
- [ ] Make uncertainty or unsupported profiles return passkey-required.
- [ ] Keep E2 unavailable in browser and fake-verifier production routes.

## Phase 6: R1 Signing Boundary

- [ ] Evaluate the observation handle against current server R1 policy.
- [ ] Store an issued one-use grant and return no mutable grant state to the
      client.
- [ ] Atomically reserve the exact Router request before any SigningWorker call.
- [ ] Make normal signing accept only `PasskeyAdmittedTransaction` or
      `ReservedVoiceIdR1Grant`.
- [ ] Permanently fail-close timeout, cancellation, worker failure, and response
      loss after reservation.
- [ ] Add concurrency, mutation, revocation, expiry, and kill-switch tests.

## Phase 7: Router A/B Adapter

- [ ] Implement the
      [Router admission adapter](voiceId-router-policy-issuer.md).
- [ ] Carry the server-created Router binding unchanged through evidence,
      policy, grant, reservation, and admission.
- [ ] Derive Router admission material inside Router with existing typed
      builders.
- [ ] Add an end-to-end E2 test through Router, active SigningWorker, and
      signature.
- [ ] Delete duplicate VoiceID-specific signing request and digest shapes.

## Phase 8: Global Auth Method Decision

Defer this phase until an E2 pilot exists and product requirements demonstrate
that VoiceID must appear in account-level auth-method selection.

- [ ] Decide whether VoiceID enrollment is an account capability or a true
      `WalletAuthMethod`.
- [ ] If it is a wallet auth method, widen `SIGNER_AUTH_METHODS`,
      `WALLET_AUTH_METHODS`, `WalletFlowAuthMethod`, account projection, persistence
      parsers, events, and every exhaustive switch in one change.
- [ ] Keep E0/E1 out of enabled-authenticator projections.
- [ ] Add persistence-boundary migration only if stored account records require
      it, then delete the migration after the rewrite completes.

## Acceptance Criteria

- Browser VoiceID appears as per-operation evidence and always signs through a
  user-verified passkey for the exact Router operation.
- Voice failure, uncertainty, outage, skip, or accessibility fallback does not
  block independent passkey selection.
- E0/E1 cannot carry an authorization handle, grant, reserved state, or signing
  continuation.
- The server owns identity, policy, Router binding, challenge, expected phrase,
  expiry, and evidence-to-grant decisions.
- A future embedded path exposes only an opaque E2 observation handle and enters
  signing through server R1 policy plus atomic Router reservation.
- React and non-React consumers can handle every result exhaustively.
- Global wallet auth unions remain unchanged until a separate account-level
  product decision and complete consumer cutover.
- Raw media, embeddings, templates, full transcripts, private keys, shares, and
  raw model responses never enter SDK events, account projection, grants, or
  signing inputs.

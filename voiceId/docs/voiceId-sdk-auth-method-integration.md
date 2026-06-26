# VoiceID SDK Auth Method Integration Plan

Status: implementation plan.

Related docs:

- [VoiceID UI/UX plan](voiceID-UI.md)
- [VoiceID MVP 1 tasks](voiceId-mvp-1-tasks.md)
- [VoiceID normal SDK transaction signing plan](voiceId-normal-sdk-transaction-signing.md)
- [VoiceID Router policy issuer](voiceId-router-policy-issuer.md)
- [Router A/B signer architecture](../../docs/router-a-b-SPEC.md)

## Goal

Expose VoiceID through the seams wallet SDK as a wallet auth method that follows
the same public API, React hook, route-module, account projection, event, and
signing-capability patterns used by passkey and email OTP flows.

The first useful integration is per-transaction owner-presence authorization for
normal SDK signing:

```text
SDK transaction request
  -> VoiceID transaction intent
  -> intentDigest
  -> VoiceID command verification
  -> owner-presence authorization
  -> wallet policy decision
  -> existing normal SDK signer capability continuation
```

VoiceID is policy evidence for a specific owner command and transaction intent.
The signing authority remains the existing SDK signing path.

## Current Integration Stance

- VoiceID should become a typed `WalletAuthMethod` only after the owner-presence
  result, policy result, public flow types, account projection, and event
  branches are ready together.
- Treat VoiceID as equivalent to email OTP at the wallet auth-method layer:
  server-verified auth that can issue a short-lived grant.
- The MVP should treat VoiceID as a per-operation auth method for low-risk
  transaction signing, using the accepted wallet policy decision to unlock the
  existing signing continuation.
- Riskier tasks should use VoiceID as the first check, then require email OTP,
  passkey, or another step-up method before export, recovery, new device
  enrollment, or high-risk signing.
- VoiceID should not protect or restore signing material by itself. Passkey PRF
  can unwrap client-side material; VoiceID issues server-side policy grants.
- Device-bound VoiceID is the default security model. Enrollment and
  verification should bind to an enrolled device context instead of treating
  voice audio as a remote reusable credential.
- Router A/B admission integration remains a later adapter phase after the
  normal SDK auth method and signing gate work.

## Auth Method Semantics

VoiceID should share the SDK auth-method surface with email OTP, while keeping
its security semantics explicit.

```text
passkey
  -> client cryptographic authenticator
  -> optional PRF/KEK for sealed client material

email OTP
  -> server-verified channel challenge
  -> short-lived auth/session/signing grant

VoiceID
  -> server-verified enrolled speaker + spoken intent + device context
  -> short-lived owner-presence/signing grant
```

This makes VoiceID a wallet auth method without turning biometric data into a
secret. The voice template is verifier material. The server-issued grant is the
auth artifact consumed by wallet policy and signing gates.

## Policy Modes

VoiceID should support two policy modes.

### Mode 1: Direct Signing Grant

For low-risk, intent-bound work, accepted VoiceID can directly authorize the
server side of the existing signing flow to participate in the bound operation.

Required conditions:

- enrolled speaker accepted
- spoken phrase matches the displayed transaction command
- `intentDigest` matches the transaction candidate
- enrolled device proof is valid
- authorization is one-use
- authorization is expiry-bound
- value, recipient, and session risk are within VoiceID policy

Target flow:

```text
display "send 50 USDC to bob"
  -> record voice on enrolled device
  -> verify speaker and phrase
  -> authorize owner presence for intentDigest
  -> issue one-use VoiceID signing grant
  -> call normal SDK signer continuation
```

### Mode 2: Step-Up Delivery

For risky tasks, accepted VoiceID starts the step-up flow and cannot complete the
operation by itself.

Use step-up for:

- key export
- wallet recovery
- new device enrollment
- high-value transaction signing
- new-recipient transaction signing
- suspicious device or session context
- repeated failed VoiceID attempts
- low-confidence or noisy audio

The step-up response should carry the allowed methods:

```ts
export type VoiceIdStepUpRequired = {
  kind: 'step_up_required';
  reason: VoiceIdStepUpReason;
  methods: readonly ['email_otp' | 'passkey'];
  voiceIdVerificationId: VoiceIdVerificationId;
  intentDigest: VoiceIdIntentDigest;
  expiresAtMs: number;
};
```

Email OTP is the delivery method for the next factor. Passkey is the
cryptographic step-up method. VoiceID remains the owner-presence prerequisite
that caused the server to offer that challenge.

## Device Binding

Device binding is required for the tenable VoiceID security model.

Enrollment should bind the voice template to a device identity:

- `deviceId`
- `devicePublicKey`
- device label and platform hints
- enrollment timestamp
- last verified timestamp
- allowed wallet/account ids
- verifier model and threshold versions

Verification should require device proof:

```text
server challenge
  -> enrolled device signs challenge
  -> browser records voice command
  -> server verifies device signature
  -> server verifies speaker, phrase, and quality
  -> server evaluates wallet policy
```

The practical assumption is that enrolled devices such as iPhones and MacBooks
already require a password, TouchID, FaceID, or equivalent OS login before the
browser can access the user's session. That device-access layer makes
device-bound VoiceID materially stronger than remote phone-channel voice auth.
VoiceID policy should still require challenge signatures, intent binding,
expiry, replay protection, and rate limits.

## Existing Patterns To Reuse

Use the same seams wallet surfaces that passkey and email OTP already use.

| Pattern | Existing surface | VoiceID integration |
| --- | --- | --- |
| Auth method domain | `packages/shared-ts/src/utils/signerDomain.ts` | Add `voice_id` to the wallet auth method unions when all consumers are ready. |
| Public auth API | `packages/sdk-web/src/SeamsWeb/publicApi/auth.ts` and `types.ts` | Add `beginVoiceIdWalletAuth(...)` beside `beginGoogleEmailOtpWalletAuth(...)`. |
| SDK implementation | `packages/sdk-web/src/SeamsWeb/SeamsWeb.ts` | Wire the public method through the same domain-method dependency shape. |
| React hook | `packages/sdk-web/src/react/hooks/useGoogleEmailOtpWalletAuth.ts` | Add `useVoiceIdWalletAuth(...)` with the same `busy`, `error`, and `start(...)` shape. |
| Route mounting | `packages/sdk-server-ts/src/router` route modules and `RelayRouterModule` | Mount VoiceID through `createVoiceIdRelayRouterModule()`. |
| Account projection | `packages/sdk-web/src/core/accountData/near/accountProjection.ts` | Recognize `voice_id` for stored account options and display routing. |
| SDK events | `packages/sdk-web/src/core/types/sdkSentEvents.ts` | Add VoiceID phases for enrollment, verification, authorization, and signing gate results. |
| Normal signing | `NearSignerCapability` in `packages/sdk-web/src/SeamsWeb/publicApi/types.ts` | Wrap existing signer methods with a VoiceID policy gate. |

## Target Public Shape

The SDK should expose VoiceID as an auth flow, then let signing proceed through
the existing signer capability.

```ts
const flowResult = await seams.auth.beginVoiceIdWalletAuth({
  walletSession,
  intent: {
    kind: 'voice_id_transaction_sign_v1',
    accountId,
    networkId,
    command: 'send 50 USDC to bob',
    transactionDigest,
    expiresAtMs,
  },
});

if (!flowResult.ok) return flowResult;

const verification = await flowResult.value.verifyCommand({
  audio: commandAudio,
});

switch (verification.kind) {
  case 'accepted':
    return await seams.near.signAndSendTransaction(transaction);
  case 'step_up_required':
    return verification;
  case 'rejected':
  case 'uncertain':
  case 'expired':
  case 'cancelled':
    return verification;
  default:
    return assertNever(verification);
}
```

The final implementation should hide most of this ceremony behind a gate helper
or SDK convenience API, while preserving the same typed flow boundaries.

## Domain Model

Add narrow VoiceID auth method types before widening global auth method unions:

```ts
export type VoiceIdWalletAuthIntent =
  | {
      kind: 'voice_id_transaction_sign_v1';
      accountId: AccountId;
      networkId: NetworkId;
      command: string;
      transactionDigest: VoiceIdIntentDigest;
      expiresAtMs: number;
    };

export type VoiceIdWalletAuthResult<TAccepted> =
  | { kind: 'accepted'; value: TAccepted }
  | { kind: 'step_up_required'; reason: VoiceIdStepUpReason }
  | { kind: 'rejected'; reason: VoiceIdRejectionReason }
  | { kind: 'uncertain'; reason: VoiceIdUncertaintyReason }
  | { kind: 'expired' }
  | { kind: 'cancelled' }
  | { kind: 'failed'; message: string };
```

The accepted branch should carry the server-issued grant instead of raw verifier
output:

```ts
export type VoiceIdSingleOperationGrant = {
  kind: 'voice_id_single_operation_grant_v1';
  grantId: VoiceIdGrantId;
  walletId: WalletId;
  accountId: AccountId;
  deviceId: VoiceIdDeviceId;
  enrollmentId: VoiceIdEnrollmentId;
  verificationId: VoiceIdVerificationId;
  intentDigest: VoiceIdIntentDigest;
  policyVersion: VoiceIdPolicyVersion;
  modelVersion: VoiceIdModelVersion;
  thresholdVersion: VoiceIdThresholdVersion;
  issuedAtMs: number;
  expiresAtMs: number;
  remainingUses: 1;
};
```

Global auth-method widening should happen in one pass:

- `SIGNER_AUTH_METHODS`
- `WALLET_AUTH_METHODS`
- `WalletFlowAuthMethod`
- account projection parsers
- session/auth event unions
- public type fixtures

Every switch that consumes auth method state should be exhaustive.

## Phase 0: Keep The Voice Loop Stable

- [x] Enroll owner voice through the VoiceID demo.
- [x] Verify the spoken command `send 50 USDC to bob`.
- [x] Bind the verification to the same `intentDigest` used by owner-presence
      authorization.
- [x] Consume accepted owner-presence through wallet policy.
- [x] Return rejected, uncertain, expired, replayed, and mismatch branches as
      non-signing policy decisions.
- [ ] Manually run the live browser microphone enrollment and command
      verification loop.

## Phase 1: Add SDK Auth Method Types

- [ ] Add `voice_id` as a narrow VoiceID auth method constant in shared domain
      code.
- [ ] Model VoiceID as a server-verified wallet auth method equivalent to email
      OTP, not as a passkey-style KEK or signer material source.
- [ ] Add VoiceID-specific public flow types in
      `packages/sdk-web/src/SeamsWeb/publicApi/types.ts`.
- [ ] Add `VoiceIdSingleOperationGrant`, `VoiceIdStepUpRequired`, and
      device-bound verification types.
- [ ] Add type fixtures proving invalid VoiceID flow states cannot be
      constructed.
- [ ] Add source or type checks for global auth method switch exhaustiveness.
- [ ] Widen `WalletAuthMethod`, `AuthMethod`, and `WalletFlowAuthMethod` only
      after all consumers have VoiceID branches.

## Phase 2: Add Public SDK Auth Flow

- [ ] Add `beginVoiceIdWalletAuth(...)` to `AuthCapability`.
- [ ] Add the matching `AuthCapabilityDomainMethods` dependency in
      `packages/sdk-web/src/SeamsWeb/publicApi/auth.ts`.
- [ ] Implement the method in `packages/sdk-web/src/SeamsWeb/SeamsWeb.ts`
      beside `beginGoogleEmailOtpWalletAuth(...)`.
- [ ] Keep enrollment and verification lifecycle operations branch-specific:
      enrollment flows cannot verify commands, and verification flows cannot
      finalize enrollment.
- [ ] Return Result-style unions for recoverable failures.
- [ ] Return `accepted` with a one-use grant only when wallet policy accepts the
      operation for VoiceID.
- [ ] Return `step_up_required` with allowed delivery methods for key export,
      recovery, high-value signing, new-recipient signing, new-device
      enrollment, and suspicious context.
- [ ] Emit typed SDK events for enrollment started, sample accepted,
      enrollment finalized, verification issued, verification completed,
      owner-presence authorized, and policy consumed.

## Phase 3: Add React Hook And UI Adapter

- [ ] Add `packages/sdk-web/src/react/hooks/useVoiceIdWalletAuth.ts`.
- [ ] Match the email OTP hook shape: `start(...)`, `busy`, and `error`.
- [ ] Accept microphone capture callbacks or a recorder adapter instead of
      hardwiring demo UI into the hook.
- [ ] Export the hook and public types from `packages/sdk-web/src/react/index.ts`.
- [ ] Keep UI prompt copy and display data outside core domain logic.

## Phase 4: Mount VoiceID Through Existing Server Adapters

- [ ] Register VoiceID routes through `RelayRouterModule`.
- [ ] Use `createVoiceIdRelayRouterModule()` as the VoiceID-owned module
      factory.
- [ ] Keep concrete VoiceID stores, verifier mode, and transcript provider
      construction inside VoiceID-owned server setup code.
- [ ] Add device registration and challenge verification at the VoiceID route
      boundary.
- [ ] Bind enrollment and verification records to `deviceId` and
      `devicePublicKey`.
- [ ] Add SDK server tests proving the generic route-module path can enroll,
      verify, and authorize owner presence.
- [ ] Keep raw audio inside typed route/verifier boundaries.

## Phase 5: Add Account Projection And Auth Method Display

- [ ] Update account projection parsing to recognize `voice_id`.
- [ ] Update account option grouping so passkey, email OTP, and VoiceID account
      options remain distinct.
- [ ] Update any display labels through existing account/auth display helpers.
- [ ] Add fixtures for unknown auth methods, passkey, email OTP, and VoiceID.

## Phase 6: Add The Normal SDK Signing Gate

- [ ] Implement `VoiceIdTransactionSigningGate` as the narrow boundary between
      VoiceID policy and existing signer methods.
- [ ] Make the gate accept a signing continuation:
      `signAfterVoiceIdAccepted(...)`.
- [ ] Pass only accepted one-use grants, the candidate transaction, and the
      matching `intentDigest` into the continuation.
- [ ] Spend the one-use grant before or atomically with signing continuation
      execution.
- [ ] Prove the continuation is never called for rejected, uncertain, expired,
      replayed, mismatched, cancelled, failed, or step-up-required outcomes.
- [ ] Use the existing `NearSignerCapability` methods as the first continuation
      target.

## Phase 7: Persisted Session Decision

Start this phase after the per-operation signing gate passes.

- [ ] Decide whether VoiceID is only a per-operation owner-presence method or
      also a signing-session method.
- [ ] If VoiceID becomes a session method, define how it authorizes or refreshes
      signing material without treating a biometric match as a signing secret.
- [ ] Keep key export, wallet recovery, and new-device enrollment behind
      step-up even when VoiceID verification accepts.
- [ ] Add sealed-recovery or session persistence branches only after the domain
      model can make invalid states unrepresentable.
- [ ] Add persistence parsers at the boundary and keep core logic on precise
      internal types.
- [ ] Add migration or compatibility handling only at persistence/request
      boundaries.

## Phase 8: Router A/B Adapter

Start this phase after the normal SDK auth method works.

- [ ] Add one adapter from accepted VoiceID wallet policy to the active Router
      A/B normal-signing admission shape.
- [ ] Bind VoiceID `intentDigest` to the Router A/B operation fingerprint and
      normal-signing digest tuple.
- [ ] Keep Router helper churn behind the adapter.
- [ ] Add an end-to-end test from accepted VoiceID policy decision to Router
      admission, SigningWorker prepare/finalize, and signature.

## Acceptance Criteria

- VoiceID is available through the same SDK auth capability surface as passkey
  and email OTP.
- VoiceID is treated as server-verified auth equivalent to email OTP, with
  one-use grants and step-up delivery for risky operations.
- React users can start VoiceID auth through a hook that follows the email OTP
  hook shape.
- SDK server users can mount VoiceID through the same route-module abstraction.
- Enrolled VoiceID is bound to a device identity, and verification requires a
  fresh device challenge response.
- Account projection can display and select VoiceID auth method entries.
- Accepted VoiceID owner-presence can authorize the normal SDK signing
  continuation for the bound transaction.
- Rejected, uncertain, expired, replayed, mismatched, cancelled, failed, and
  step-up-required outcomes cannot call signing.
- High-risk transactions route to step-up instead of signing through VoiceID
  alone.
- The first integrated path stays on the normal SDK signer capability before
  Router A/B adapter work.

# Add-Key Plan: Dual Email OTP and Passkey Accounts

Date updated: April 17, 2026

Status: future product plan. This document is not authoritative for current
transaction signing behavior. Current transaction auth selection and
signing-session rules live in
[../signing-session-architecture/](../signing-session-architecture/).

## Objective

Define the product and technical plan for letting existing wallets add a second login/signing method across Passkey and Google SSO + Email OTP accounts.

The clean model is:

1. `Passkey` and `EmailOTPKey` are always different account keys.
2. Adding either method means adding a new key to the same smart account.
3. Removing either method means removing or disabling that key and deleting any method-specific secret material.
4. Passkey-derived secrets are never wrapped by `shamir3pass` or stored server side.
5. Email OTP remains a lower-assurance convenience path because it uses Google SSO, 6-digit Email OTP, and server-side escrow in the auth path.

This plan is intentionally separate from the core Email OTP signing specs. It should only be implemented after the core Email OTP system is robust and locally tested.

## Product Model

Canonical account postures:

1. `Passkey-first account`
   - recommended default
   - strongest default user-facing account type
   - passkey PRF output stays non-escrowed
   - no Email OTP fallback unless the user explicitly adds one
2. `Google SSO + Email OTP account`
   - convenience onboarding path
   - lower assurance than passkey
   - uses Google SSO to authenticate the app user
   - uses 6-digit Email OTP to authorize `shamir3pass` unseal of the Email OTP secret source
3. `Multi-method account`
   - same wallet has both a passkey-controlled key and an Email-OTP-controlled key
   - both sign-in options can reach the same wallet address
   - effective security is bounded by the weakest active key

Product rule:

If we ship this cross-upgrade feature family, we should ship both directions or neither direction. Shipping only one direction makes the account model harder to explain and creates asymmetric product behavior.

## Security Position

The security framing must be explicit:

1. adding Passkey to an Email OTP account improves UX and can improve security only if the Email OTP key is later removed
2. adding Email OTP to a Passkey account is a convenience fallback and explicitly weakens the account
3. an account with both methods enabled is not equivalent to a Passkey-only account
4. product copy must not describe adding Passkey as a full upgrade while Email OTP remains enabled
5. product copy must not describe adding Email OTP as recovery without saying it lowers account security

Effective account strength:

```text
Passkey only                  -> strongest default
Passkey + Email OTP enabled   -> lower assurance, because Email OTP can still sign
Email OTP only                -> lower assurance convenience account
Email OTP -> Passkey only     -> upgraded only after Email OTP key and escrow are removed
```

## Key Model

Do not escrow passkey PRF output.

Rejected model:

```text
Passkey PRF output -> shamir3pass wrap -> server-side storage -> Email OTP unlocks passkey secret
```

Reason this is rejected:

1. it weakens the passkey security model
2. it creates misleading product semantics
3. it makes a passkey-derived account recoverable through mailbox/OTP compromise
4. it blurs the boundary between strong passkey signing and lower-assurance Email OTP signing

Accepted model:

```text
Passkey method   -> PasskeyKey
Email OTP method -> EmailOTPKey
Account          -> smart account with one or more active keys
```

Adding a method:

```text
existing active key signs addKey(new_method_key)
```

Removing a method:

```text
remaining active key signs removeKey(old_method_key)
```

## Feature 1: Add Passkey To Email OTP Account

Goal:

An Email OTP-first user can add a passkey to the same wallet address.

Flow:

1. user signs in with Google SSO
2. user enters Email OTP
3. Email OTP key signs an `addKey(PasskeyKey)` operation
4. client creates/registers a new passkey credential
5. passkey key material is derived from WebAuthn PRF
6. server/account records the new PasskeyKey as active for the same wallet
7. product prompts the user to optionally remove Email OTP to complete the security upgrade

Security outcome:

1. if Email OTP remains enabled, the account is still lower assurance
2. if Email OTP is removed and escrow is deleted/revoked, the account can be treated as Passkey-only going forward

Required UI copy:

1. `Add passkey sign-in` while Email OTP remains enabled
2. `Complete passkey upgrade` only when the user removes Email OTP
3. `Your account is still recoverable with Email OTP, so it is not passkey-only yet`

Implementation shape:

```text
EmailOTPKey signs addKey(PasskeyKey)
optional: PasskeyKey signs removeKey(EmailOTPKey)
optional: server deletes/revokes Email OTP escrow
```

## Feature 2: Add Email OTP To Passkey Account

Goal:

A Passkey-first user can add Google SSO + Email OTP as a convenience fallback to the same wallet address.

Flow:

1. user signs in with Passkey
2. app clearly warns that Email OTP is a lower-security fallback
3. user completes Google SSO binding
4. client generates a new random Email OTP secret `S`
5. Email OTP enrollment creates an `EmailOTPKey`
6. Passkey key signs an `addKey(EmailOTPKey)` operation
7. server stores only Email-OTP-specific escrow material for `EmailOTPKey`
8. passkey PRF output remains non-escrowed and never enters the Email OTP/shamir3pass path

Security outcome:

1. account becomes lower assurance while Email OTP fallback is enabled
2. disabling Email OTP returns the account to Passkey-only posture
3. audit/security screens should label the account as having a lower-security fallback enabled

Required UI copy:

1. `Add Email OTP fallback`
2. `This makes your account easier to access but less secure than passkey-only`
3. `Anyone who compromises your Google account/email could attempt this login path`

Implementation shape:

```text
PasskeyKey signs addKey(EmailOTPKey)
optional: PasskeyKey signs removeKey(EmailOTPKey)
server stores EmailOTPKey escrow only
server never stores passkey PRF output
```

## Shared Account Address Requirement

Both features must preserve a single wallet address.

Rules:

1. adding a login method must not create a second wallet address
2. Google SSO must detect existing bindings before offering a new wallet registration
3. account settings must show which login methods are linked to the current wallet
4. deleting a method must not delete the wallet itself
5. an account must never be left with zero active signing keys

## Authorization Requirements

Feature 1 authorization:

1. user must have a valid Google SSO app session
2. user must pass Email OTP unseal/signing flow
3. the current EmailOTPKey signs `addKey(PasskeyKey)`
4. optional removal of EmailOTPKey must be authorized by an active remaining key, preferably the newly added PasskeyKey

Feature 2 authorization:

1. user must authenticate with Passkey
2. PasskeyKey signs `addKey(EmailOTPKey)`
3. Email OTP enrollment must be confirmed by a fresh 6-digit OTP
4. server records the Email OTP method as lower assurance

Shared enforcement:

1. server validates account ownership and current active key set
2. server prevents removing the last active key
3. server records method type and assurance level per key
4. server emits audit events for add/remove method operations
5. sensitive operations may require Passkey even when Email OTP is enabled

## Data Model

Proposed method record:

```ts
type AccountSigningMethod = {
  methodId: string;
  walletId: string;
  methodType: 'passkey' | 'email_otp';
  keyId: string;
  publicKey: string;
  assurance: 'strong' | 'convenience';
  enabled: boolean;
  createdAtMs: number;
  disabledAtMs?: number;
};
```

Passkey-specific material:

```ts
type PasskeyMethodMetadata = {
  credentialId: string;
  rpId: string;
  prfEnabled: true;
};
```

Email-OTP-specific material:

```ts
type EmailOtpMethodMetadata = {
  googleSubject: string;
  emailHash: string;
  otpChannel: 'email_otp';
  escrowKeyVersion: string;
  escrowBlobId: string;
};
```

Rules:

1. `PasskeyMethodMetadata` must not contain escrowed PRF output
2. `EmailOtpMethodMetadata` must not point at passkey-derived material
3. `methodType` drives UX labels, risk labels, and policy gates
4. key deletion should soft-disable first, then hard-delete method-specific secret material when safe

## Policy Model

Account policy should expose:

```ts
type AccountAssuranceState = {
  activeMethods: Array<'passkey' | 'email_otp'>;
  strongestAvailable: 'passkey' | 'email_otp';
  weakestAvailable: 'passkey' | 'email_otp';
  effectiveAssurance: 'strong' | 'convenience';
  passkeyOnly: boolean;
  lowerSecurityFallbackEnabled: boolean;
};
```

Rules:

1. `passkeyOnly = true` only when no Email OTP key is enabled
2. `lowerSecurityFallbackEnabled = true` whenever Email OTP is enabled
3. `effectiveAssurance = convenience` whenever Email OTP is enabled
4. sensitive operations can require `methodType = passkey` even if Email OTP is enabled
5. policy gates must be server-authoritative

## UX Plan

Account settings should show login methods as first-class linked keys:

```text
Sign-in methods
- Passkey       Strong, recommended
- Email OTP     Convenience fallback, lower security
```

For Email OTP-first users:

1. show `Add passkey` as a recommended action
2. after passkey is added, show `Remove Email OTP to complete upgrade`
3. do not call the account Passkey-only until Email OTP is removed

For Passkey-first users:

1. show `Add Email OTP fallback` as optional
2. require an explicit security acknowledgement
3. after adding Email OTP, show a persistent lower-security fallback indicator

For multi-method users:

1. sign-in screen can show both options
2. account settings must show both active methods
3. security center must explain that Email OTP makes the account lower assurance

## Implementation Phases

### Phase 0: Finish Core Email OTP

- [x] finish local Email OTP registration/login/signing/export validation
- [ ] keep OTP-to-passkey upgrade work paused until core Email OTP is stable
- [x] finish iframe-origin ownership and worker-secret-boundary cleanup
- [x] remove legacy OTP recovery wording from normal login/register/signing surfaces
- [ ] resolve remaining threshold signer random-keypair/signing-root refactor items before building add-key flows

### Phase 1: Model Signing Methods As Account Keys

- [ ] introduce first-class `AccountSigningMethod` records
- [ ] tag existing Passkey keys as `methodType = 'passkey'`
- [ ] tag existing Email OTP keys as `methodType = 'email_otp'`
- [ ] add method assurance metadata
- [ ] add server-side invariant: account must always retain at least one active signing key
- [ ] add account method listing endpoint
- [ ] add account method audit events

### Phase 2: Feature 1 Add Passkey To Email OTP Account

- [ ] design passkey registration ceremony for an already-existing Email OTP wallet
- [ ] have EmailOTPKey authorize `addKey(PasskeyKey)`
- [ ] bind new passkey credential to the existing wallet address
- [ ] verify both Email OTP and Passkey can sign for the same wallet while both are enabled
- [ ] add optional `remove Email OTP` flow after passkey succeeds
- [ ] delete or revoke Email OTP escrow when EmailOTPKey is removed
- [ ] update account assurance state after each add/remove operation
- [ ] add E2E coverage for Email OTP account -> add Passkey -> remove Email OTP -> Passkey-only signing

### Phase 3: Feature 2 Add Email OTP To Passkey Account

- [ ] design Email OTP enrollment ceremony for an already-existing Passkey wallet
- [ ] generate a fresh random Email OTP secret `S`
- [ ] derive/register a separate `EmailOTPKey`
- [ ] have PasskeyKey authorize `addKey(EmailOTPKey)`
- [ ] store only Email-OTP-specific `shamir3pass` escrow material
- [ ] explicitly forbid wrapping or storing passkey PRF output
- [ ] mark account as lower assurance while Email OTP is enabled
- [ ] add optional `remove Email OTP fallback` flow
- [ ] add E2E coverage for Passkey account -> add Email OTP -> login/sign with either method -> remove Email OTP -> Passkey-only signing

### Phase 4: Product UX

- [ ] add account settings UI for linked sign-in methods
- [ ] add security labels for `Strong` and `Convenience fallback`
- [ ] add explicit warning before adding Email OTP to Passkey-first accounts
- [ ] add post-passkey-add prompt for Email OTP-first accounts: `Remove Email OTP to complete upgrade`
- [ ] update PasskeyAuthMenu to detect existing Google SSO bindings before showing registration
- [ ] add dev setting to switch Google SSO account-id formats for test coverage only
- [ ] make sure sign-in options route to the same wallet address when both methods are enabled

### Phase 5: Abuse, Recovery, And Policy Gates

- [ ] add rate limits for add/remove method operations
- [ ] require recent auth for method addition/removal
- [ ] require Passkey for high-risk operations when available
- [ ] emit audit events for every method add/remove attempt
- [ ] notify users when a new method is added
- [ ] notify users when a method is removed
- [ ] add admin/debug tooling to inspect method state without exposing secret material

## Open Questions

1. Should Email OTP removal after adding Passkey be a hard requirement for calling the flow an `upgrade`?
2. Should adding Email OTP to a Passkey account require a cooldown or delayed activation?
3. Should organizations be able to disable Feature 2 entirely by policy?
4. Should sensitive operations force Passkey whenever at least one PasskeyKey is active?
5. What is the exact smart-account `addKey` and `removeKey` payload format for each supported chain?
6. Should multi-method accounts show a persistent lower-assurance badge in all wallet UI, or only in account settings?

## Non-Goals

1. do not wrap passkey PRF output with `shamir3pass`
2. do not make Email OTP a recovery wrapper around passkey secrets
3. do not market multi-method accounts as Passkey-only
4. do not ship only one direction unless product explicitly accepts asymmetric UX
5. do not implement this before core Email OTP has stable local E2E coverage

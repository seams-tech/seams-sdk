# Refactor 109A — Multi-Method Wallet Authentication

Date created: August 20, 2026

Status: planned. This refactor must land before Refactor 109B.

## Goal

Allow one wallet to hold and use multiple active authentication methods across
both supported factor families:

- one or more Passkeys;
- one or more verified Email OTP factors;
- any valid combination of the two.

Each method opens the same wallet custody seed and authenticates the same
wallet. Every resulting Wallet Session still names the exact method that
authenticated it. Signing, export, factor management, and device management
remain scoped to that authority.

## Current state

The persistence model already stores several `wallet_auth_methods` rows per
wallet. The operating lifecycle remains same-family:

- `registration.addPasskey` can add another Passkey to a Passkey wallet;
- its nominal Email OTP authorization branch currently terminates with
  `Wallet add-passkey requires a fresh passkey owner proof`;
- no production `addEmailOtp` operation exists for an established wallet;
- Email OTP registration creates an Email OTP wallet, while Passkey
  registration creates a Passkey wallet;
- unlock and account-selection UI do not present all active methods for one
  wallet as deliberate alternatives.

The schema therefore expresses a capability the product cannot yet exercise.
Refactor 109A closes that gap before mixed-method device linking consumes it.

## Correct model

### One wallet, one custody seed, several factor envelopes

A wallet has one wallet custody seed. Adding a factor opens an existing
authenticated custody envelope and reseals that same seed for the new factor.
The operation derives no new owner roots and changes no key manifest.

Factor addition uses `WalletCustodySeedFromSealedEnvelopeV1`. It is not a
custody ceremony and must never produce or accept
`VerifiedWalletKeyManifestDigestV1`. The authenticated envelope already binds
the seed to the wallet and key manifest.

Every factor receives its own:

- canonical `WalletAuthMethodId`;
- `WalletAuthAuthority` and authority digest;
- sealed custody envelope;
- local projection when the current browser can operate that factor;
- Wallet Sessions issued from that exact authority.

Deleting or revoking one factor leaves the wallet seed, key manifest, sibling
factors, and their sessions intact. Revoking the final active factor is
refused unless a recovery replacement commits in the same operation.

### Authentication authority stays exact

An active Wallet Session authority resolves through exactly one active wallet
auth method. Runtime code never treats `walletId + auth kind` as an authority.
Passkey credentials, Email OTP provider subjects, and authority digests remain
distinct.

The method used to authorize factor addition and the method being added are
separate typed branches:

```ts
type ExistingOwnerProof =
  | { kind: 'passkey'; assertion: VerifiedPasskeyOwnerAssertion }
  | { kind: 'email_otp'; grant: VerifiedEmailOtpOwnerGrant };

type NewWalletFactor =
  | { kind: 'passkey'; registration: VerifiedPasskeyRegistration }
  | { kind: 'email_otp'; verification: VerifiedEmailOtpFactorGrant };
```

The boundary validates both branches once. Core factor-addition code accepts
only verified values and a seed obtained from an authenticated envelope.

### Email identity is verified before persistence

Adding Email OTP collects the email on the wallet-origin surface, normalizes
it once, and verifies a one-time code before creating any durable auth method.
The OTP challenge is bound to:

- wallet ID;
- add-auth-method intent and digest;
- current owner authority;
- normalized email hash and provider subject;
- expiry, attempt budget, and one-use consumption state.

The raw email is display input at the boundary. Core records retain the
verified provider subject and email hash. Existing privacy and masked-email
rules continue to apply.

## Product behavior

### Add Email OTP

From an unlocked wallet:

1. Open Authentication Methods in wallet settings.
2. Select **Add email code** and enter an email address.
3. Authorize the operation with the current factor.
4. Verify the code sent to the new email address.
5. Reseal the wallet custody seed for the verified Email OTP factor.
6. Commit the server auth method, sealed envelope, and local projection.
7. Display both methods as active.

### Add Passkey from an Email OTP wallet

From an unlocked Email OTP wallet:

1. Select **Add passkey**.
2. Authorize the operation with a fresh Email OTP owner grant.
3. Create the new Passkey and collect its PRF output.
4. Reseal the same custody seed for the Passkey factor.
5. Commit the Passkey auth method, authenticator, envelope, and local
   projection.

Passkey-to-Passkey addition follows the same typed operation and keeps its
fresh Passkey assertion.

### Unlock

When a wallet has several locally usable methods, the unlock surface lists
them explicitly:

- Passkeys show their device label;
- Email OTP factors show a server-approved masked destination;
- the most recently successful method may be highlighted;
- selection never changes the authority silently after a challenge starts.

Successful unlock creates one active Wallet Session authorization projection
for the selected method. Replacing that projection retires the old local
session without revoking its auth method.

## Atomic commit and recovery

Factor addition has one durable commit point. The commit includes:

- canonical wallet auth method;
- factor-specific sealed custody envelope;
- WebAuthn authenticator for Passkey;
- verified Email OTP factor reference for Email OTP;
- factor-addition audit event;
- revocation of the one-use verification grant.

The worker owns plaintext custody seed and factor material throughout reseal.
JavaScript receives opaque handles, public binding facts, and the final sealed
record.

Before the commit, cancellation consumes temporary challenges and discards
worker handles. After the commit, retry reads the exact committed result and
repairs missing client projections idempotently. It never creates a second
factor identity.

## Implementation phases

### Phase 1 — Make add-auth-method contracts factor-complete

- Replace Passkey-shaped add-auth-method intent and ceremony contracts with an
  exhaustive Passkey/Email OTP union.
- Replace the dead `AddPasskeyAuthorization.email_otp` branch with a real
  verified existing-owner proof.
- Give Email OTP challenge, verification, and finalize requests their own
  narrow branches.
- Parse raw route bodies into verified domain inputs at the request boundary.
- Delete Passkey-only compatibility shapes after all callers use the union.

Primary locations:

- `packages/shared-ts/src/utils/addAuthMethodRegistration.ts`
- `packages/shared-ts/src/utils/registrationIntent.ts`
- `packages/shared-ts/src/utils/walletAuthAuthority.ts`
- `packages/wallet-server/src/core/registrationContracts.ts`
- `packages/wallet-server/src/core/RegistrationCeremonyStore.ts`
- `packages/wallet-server/src/router/domains/walletRegistration/walletRegistrationRoutes.ts`

Exit criterion: the compiler rejects an unverified email, an authority-free
factor addition, and a finalize request whose factor branch differs from its
intent.

### Phase 2 — Add Email OTP to an established wallet

- Add an authenticated `registration.addEmailOtp` public operation.
- Reuse the existing OTP challenge store, delivery service, factor-secret
  derivation, and `email_otp_factor_release_v1` machinery.
- Require a fresh proof from the currently active owner authority.
- Open one authenticated existing custody envelope inside the worker.
- Reseal the custody seed for the verified Email OTP factor.
- Commit the auth method and envelope atomically at the server boundary.
- Persist the local Email OTP projection only after the server commit.

Primary locations:

- `packages/wallet/src/SeamsWeb/operations/authMethods/emailOtp/`
- `packages/wallet/src/SeamsWeb/publicApi/registration.ts`
- `packages/wallet/src/SeamsWeb/publicApi/types.ts`
- `packages/wallet/src/core/signingEngine/workerManager/workers/email-otp.worker.ts`
- `packages/wallet-server/src/router/cloudflare/d1/wallet/d1WalletAuthMethodService.ts`
- `packages/wallet-server/src/router/cloudflare/d1/registration/`

Exit criterion: a Passkey-created wallet locks, unlocks through its newly added
Email OTP factor, signs NEAR and EVM-family transactions, and exports both key
families under the Email OTP authority.

### Phase 3 — Add Passkey from an Email OTP authority

- Authorize Passkey addition with a verified Email OTP owner grant.
- Remove the Passkey-only owner-proof guard.
- Create the new Passkey and PRF-bound envelope through the existing Passkey
  registration and custody-link machinery.
- Preserve one WebAuthn creation prompt and one current-owner verification
  interaction.
- Persist authenticator, auth method, profile selection, and envelope
  idempotently.

Primary locations:

- `packages/wallet/src/SeamsWeb/operations/authMethods/passkey/addPasskey.ts`
- `packages/wallet/src/core/signingEngine/walletCustody/passkeyLink.ts`
- `packages/wallet/src/core/signingEngine/stepUpConfirmation/`
- `packages/wallet-server/src/router/cloudflare/d1/wallet/d1WalletAuthMethodService.ts`

Exit criterion: an Email-OTP-created wallet locks and unlocks through its newly
added Passkey with one Touch ID prompt.

### Phase 4 — Method inventory, selection, and revocation

- Add an Authentication Methods settings surface backed by canonical server
  records and exact local capability status.
- Display active, locally unavailable, paused, and revoked states directly.
- Let unlock choose one exact active local method.
- Revoke one method together with its active Wallet Sessions and local sealed
  material.
- Refuse removal of the final active method outside recovery replacement.
- Delete auth-kind inference from recent-account labels and first-record
  selection.

Primary locations:

- `packages/wallet/src/react/components/AccountMenuButton/`
- `packages/wallet/src/SeamsWeb/walletIframe/host/auth-menu/`
- `packages/wallet/src/SeamsWeb/operations/auth/login.ts`
- `packages/wallet/src/core/indexedDB/seamsWalletDB/`
- `packages/wallet-server/src/router/cloudflare/d1/wallet/`

Exit criterion: one wallet can switch between Passkey and Email OTP unlocks,
and revoking either method leaves the sibling method operational.

### Phase 5 — Cleanup and intended behavior

- Remove same-family assumptions, dead authorization branches, and fixtures
  that model one auth method per wallet.
- Update `docs/intended-behaviours.md` with mixed-method addition, unlock,
  signing, export, and revocation.
- Add type fixtures for invalid cross-branch intent/finalize combinations.
- Add behavioral coverage through shared factories.
- Run the real browser gate below before closing the refactor.

## Verification gate

Use a fresh wallet and clean browser profile for each origin method.

1. Register with Passkey, add Email OTP, lock, and unlock once with each
   method.
2. Register with Email OTP, add Passkey, lock, and unlock once with each
   method.
3. Under every selected authority, sign one NEAR transaction and one
   EVM-family transaction.
4. Export Ed25519 and ECDSA material with one user-presence interaction per
   export.
5. Revoke the newly added method and prove the original method still unlocks.
6. Repeat factor-addition finalize after a simulated lost response and prove
   it returns the same committed factor without a duplicate row or envelope.
7. Interrupt before commit and prove no active auth method or usable envelope
   remains.

## Non-goals

- Device linking is owned by Refactor 109B.
- Enterprise SSO remains Refactor 111.
- Recovery-factor replacement keeps its existing ceremony and proof types.
- This refactor does not merge base Email OTP factors with enrollment-scoped
  linked Email OTP owner authorities.

## Completion criteria

Refactor 109A is complete when mixed-method wallets work through registration,
factor addition, lock, unlock, signing, export, method inventory, and
single-factor revocation. A schema capable of storing both methods is
insufficient evidence.

# Registration Auth Method Refactor

## Goal

Registration should treat authentication method and signer-family selection as
separate axes.

Auth methods:

- Passkey.
- Email OTP.
- Future methods such as OIDC, hardware keys, or recovery authorities.

Signer selection:

- Ed25519 only.
- ECDSA only.
- Ed25519 and ECDSA together.

Every auth method should be able to request every signer-selection mode through
the same wallet-subject registration state machine. A wallet subject can later
have multiple active auth methods, for example two passkeys and one Email OTP
address, without creating a second wallet identity.

## Current Problem

The current registration API is signer-selection aware, but the authority is
implicit passkey authority:

```ts
registerWallet({
  walletSubject,
  rpId,
  signerSelection,
  options,
});
```

The implementation still carries passkey assumptions:

- `registerWallet()` requires `authenticatorOptions` internally.
- The client always calls WebAuthn registration confirmation.
- Events use passkey-specific interaction names.
- ECDSA registration derives its client root from passkey PRF output.
- Email OTP Ed25519 registration provisioning is disabled and explicitly
  throws until it can use a wallet-subject ceremony.

This is the wrong shape for first-class Email OTP and future auth methods. The
new API should expose the auth method explicitly, then route all auth methods
into one normalized registration ceremony.

## Target Model

Wallet identity, auth-method bindings, signer records, and signing sessions are
separate domain objects.

```ts
type WalletSubjectId = string & {
  readonly __walletSubjectIdBrand: unique symbol;
};

type WalletSubject = {
  walletSubjectId: WalletSubjectId;
  rpId: string;
  createdAtMs: number;
};

type WalletAuthMethodBinding =
  | {
      kind: 'passkey';
      authMethodId: string;
      walletSubjectId: WalletSubjectId;
      rpId: string;
      credentialIdB64u: string;
      credentialPublicKeyCoseB64u: string;
      counter: number;
      status: 'active';
      createdAtMs: number;
    }
  | {
      kind: 'email_otp';
      authMethodId: string;
      walletSubjectId: WalletSubjectId;
      rpId: string;
      emailHashHex: string;
      status: 'active';
      createdAtMs: number;
      verifiedAtMs: number;
    };
```

Registration authority is a discriminated union. Core registration code should
receive a verified authority branch, never raw route bodies or broad optional
auth bags.

```ts
type RegistrationAuthority =
  | {
      kind: 'passkey';
      webauthnRegistration: VerifiedRegistrationCredentialInput;
      prfFirstB64u: string;
    }
  | {
      kind: 'email_otp';
      emailOtpProof: VerifiedEmailOtpRegistrationProof;
      clientSecretSource: EmailOtpRegistrationClientSecretSource;
    };

type RegistrationSignerSelection =
  | {
      mode: 'ed25519_only';
      ed25519: Ed25519RegistrationSpec;
      ecdsa?: never;
    }
  | {
      mode: 'ecdsa_only';
      ecdsa: EcdsaRegistrationSpec;
      ed25519?: never;
    }
  | {
      mode: 'ed25519_and_ecdsa';
      ed25519: Ed25519RegistrationSpec;
      ecdsa: EcdsaRegistrationSpec;
    };

type NormalizedRegistrationRequest = {
  walletSubjectId: WalletSubjectId;
  rpId: string;
  authority: RegistrationAuthority;
  signerSelection: RegistrationSignerSelection;
  runtimePolicyScope: RuntimePolicyScope;
};
```

The matrix must be valid:

| Auth method | Ed25519 only | ECDSA only | Combined |
| --- | --- | --- | --- |
| Passkey | Yes | Yes | Yes |
| Email OTP | Yes | Yes | Yes |
| Future auth methods | Same state machine | Same state machine | Same state machine |

## Public SDK Shape

The primary public API should make auth method explicit:

```ts
type RegisterWalletArgs = {
  authMethod: RegistrationAuthMethodInput;
  walletSubject: RegisterWalletSubjectInput;
  rpId?: string;
  signerSelection: RegistrationSignerSelection;
  options?: RegistrationHooksOptions;
};

type RegistrationAuthMethodInput =
  | {
      kind: 'passkey';
      authenticatorOptions?: AuthenticatorOptions;
    }
  | {
      kind: 'email_otp';
      email: string;
      otpCode?: string;
      challengeId?: string;
    };
```

Narrow convenience wrappers should call the same API:

```ts
registration.registerWallet(args);
registration.registerWithPasskey(args);
registration.registerWithEmailOtp(args);
near.registerNearWallet(args); // passkey convenience wrapper unless authMethod is supplied
evm.registerEvmWallet(args);   // passkey convenience wrapper unless authMethod is supplied
```

Wrapper rules:

- Wrappers may fill signer-selection defaults.
- Wrappers may derive `rpId` from SDK config.
- Wrappers must pass an explicit `authMethod` branch to the core registration
  function.
- Wrappers must not implement their own registration ceremony.

## Server API Shape

The existing wallet-registration route family remains the primary state
machine:

- `POST /wallets/register/intent`
- `POST /wallets/register/start`
- `POST /wallets/register/hss/respond`
- `POST /wallets/register/finalize`

`/wallets/register/intent` should include:

- `walletSubject`
- `rpId`
- `signerSelection`
- `authMethod.kind`
- environment/runtime scope request context

`/wallets/register/start` should verify the authority proof for the intent:

- Passkey: WebAuthn `create()` credential bound to the
  `registrationIntentDigestB64u`.
- Email OTP: verified OTP proof bound to the same wallet subject, rpId,
  signer selection, runtime scope, and registration intent digest.

The ceremony store should persist the normalized authority branch after
verification. Later HSS respond/finalize steps consume the same ceremony state
regardless of auth method.

## Email OTP Registration Flow

Email OTP registration should support all signer modes.

Ed25519 only:

1. Allocate registration intent with `authMethod.kind = 'email_otp'`.
2. Verify Email OTP proof bound to the intent digest.
3. Run Ed25519 role-separated HSS registration.
4. Finalize wallet subject, Email OTP auth-method binding, Ed25519 signer
   facts, and optional immediate Ed25519 session.

ECDSA only:

1. Allocate registration intent with `authMethod.kind = 'email_otp'`.
2. Verify Email OTP proof bound to the intent digest.
3. Run ECDSA role-local keygen using Email OTP client secret material.
4. Finalize wallet subject, Email OTP auth-method binding, EVM-family wallet
   key facts, and optional immediate ECDSA session material.

Combined:

1. Allocate one registration intent with both signer families.
2. Verify one Email OTP proof bound to that intent.
3. Run Ed25519 HSS registration and ECDSA role-local keygen inside the same
   ceremony.
4. Finalize both signer families atomically for one wallet subject.

## Multiple Auth Methods Per Wallet

Initial registration creates the first auth-method binding for the wallet
subject. Later flows should add more bindings to the same wallet subject.

Add-auth-method routes should be separate from signer creation:

- `POST /wallets/:walletSubjectId/auth-methods/intent`
- `POST /wallets/:walletSubjectId/auth-methods/start`
- `POST /wallets/:walletSubjectId/auth-methods/finalize`

Rules:

- Adding an auth method requires existing wallet authority, such as an active
  passkey, Email OTP, or app-session policy that explicitly permits
  auth-method enrollment.
- Adding an auth method does not create signer records.
- Adding an auth method does not mutate Ed25519 or ECDSA key facts.
- Revoking an auth method does not delete signer records.
- A wallet must keep at least one active recovery or auth method unless the
  request is an explicit wallet deletion.

## Persistence Model

Server storage should expose a typed repository around a union model. The
physical schema can use either branch tables or a base table plus branch-specific
facts, as long as boundary parsing returns precise internal types.

Recommended logical shape:

- `wallet_subjects`
- `wallet_auth_methods`
- `wallet_auth_method_passkeys`
- `wallet_auth_method_email_otps`
- `wallet_signers`
- `wallet_registration_intents`
- `wallet_registration_ceremonies`
- `wallet_auth_method_enrollment_intents`
- `wallet_auth_method_enrollment_ceremonies`

Constraints:

- Unique active passkey credential per rpId: `(rpId, credentialIdB64u)`.
- Unique active Email OTP binding per wallet/rpId/email hash:
  `(walletSubjectId, rpId, emailHashHex)`.
- Auth-method rows must include `walletSubjectId`, `rpId`, `kind`, `status`,
  `createdAtMs`, and branch-specific facts.
- Completed registration ceremonies must not store raw OTP codes, PRF roots, or
  client secrets.

## Client Architecture

Refactor the client into authority adapters plus shared signer orchestration.

Authority adapters:

- `passkeyRegistrationAuthority`
  - collects WebAuthn `create()`
  - extracts passkey PRF material
  - builds passkey authority proof
  - supplies passkey-derived client secret source for Ed25519/ECDSA HSS
- `emailOtpRegistrationAuthority`
  - requests/verifies Email OTP challenge
  - builds Email OTP authority proof
  - supplies Email OTP-derived client secret source for Ed25519/ECDSA HSS

Shared registration orchestrator:

- allocates intent
- asks the selected authority adapter for proof and client secret source
- starts ceremony
- runs Ed25519 HSS when requested
- runs ECDSA role-local keygen when requested
- finalizes ceremony
- persists local wallet subject, auth-method binding, signer facts, and warm
  session material

The orchestrator should switch on:

- `authMethod.kind` for authority proof and client secret derivation.
- `signerSelection.mode` for Ed25519/ECDSA/combined signer work.

No function should infer auth method or signer mode from optional fields.

## Server Architecture

Refactor server registration into authority verification plus shared signer
ceremony services.

Authority verification:

- `verifyPasskeyRegistrationAuthority()`
- `verifyEmailOtpRegistrationAuthority()`

Shared registration service:

- `createRegistrationIntent()`
- `startWalletRegistration()`
- `respondWalletRegistrationHss()`
- `finalizeWalletRegistration()`

The service should consume `NormalizedRegistrationRequest` and ceremony state
unions. Authority verification should happen before HSS state is prepared.

## Phases

### Phase 1: Type And API Foundation

- [ ] Add shared `RegistrationAuthMethodInput` public types.
- [ ] Add internal `RegistrationAuthority` verified types.
- [ ] Add `WalletAuthMethodBinding` union types for passkey and Email OTP.
- [ ] Update `RegisterWalletArgs` to require explicit `authMethod`.
- [ ] Keep existing convenience wrappers by making them pass
      `{ kind: 'passkey' }` explicitly.
- [ ] Add type fixtures proving auth method and signer selection are
      orthogonal.
- [ ] Add type fixtures rejecting broad optional auth bags and exact-session
      identity fields in registration inputs.

### Phase 2: Persistence And Store Boundaries

- [ ] Add server wallet-auth-method store/repository interfaces.
- [ ] Add Postgres schema for wallet auth-method bindings.
- [ ] Add Cloudflare Durable Object storage support for auth-method bindings.
- [ ] Add local/client persistence shapes for wallet auth-method bindings.
- [ ] Keep old passkey authenticator reads behind a persistence-boundary
      parser only if needed for existing development data.
- [ ] Add tests for passkey and Email OTP binding normalization.

### Phase 3: Recast Passkey Registration As Authority Branch

- [ ] Move current passkey WebAuthn `create()` collection into a passkey
      authority adapter.
- [ ] Move passkey PRF client-secret derivation behind the passkey adapter.
- [ ] Update `registerWallet()` to consume `authMethod.kind === 'passkey'`.
- [ ] Keep current `registerPasskey`, `registerNearWallet`, and
      `registerEvmWallet` wrappers by forwarding explicit passkey auth method.
- [ ] Update server start route to verify passkey authority through the shared
      authority verifier.
- [ ] Preserve passkey registration semantics across Ed25519-only, ECDSA-only,
      and combined modes. Passkey and NEAR convenience wrappers must derive
      their default signer selection from configured provisioning defaults;
      explicit Ed25519-only remains available only through disabled ECDSA
      signer options or direct signer selection.

### Phase 4: Email OTP Registration Authority

- [ ] Define Email OTP registration challenge/proof payloads.
- [ ] Bind Email OTP challenge/proof to registration intent digest, rpId,
      wallet subject, signer selection, and runtime policy scope.
- [ ] Add Email OTP authority verifier on the server.
- [ ] Add Email OTP authority adapter on the client.
- [ ] Derive Email OTP client secret source for Ed25519 HSS registration.
- [ ] Derive Email OTP client secret source for ECDSA role-local keygen.
- [ ] Keep session reconstruction functions separate from fresh registration.

### Phase 5: Email OTP Signer Modes

- [ ] Implement Email OTP Ed25519-only wallet registration.
- [ ] Implement Email OTP ECDSA-only wallet registration.
- [ ] Implement Email OTP combined Ed25519 and ECDSA wallet registration.
- [ ] Persist Email OTP auth-method binding at finalize.
- [ ] Persist requested signer facts at finalize.
- [ ] Hydrate returned warm signing sessions after local persistence succeeds.
- [ ] Delete the explicit throw in `registerEmailOtpEd25519Capability()` after
      the replacement path is wired.

### Phase 6: Multiple Auth Methods Per Wallet

- [ ] Add add-auth-method intent/start/finalize route definitions.
- [ ] Add passkey add-auth-method flow for existing wallets.
- [ ] Add Email OTP add-auth-method flow for existing wallets.
- [ ] Add revocation flow for auth-method bindings.
- [ ] Enforce at-least-one-active-auth-method policy unless deleting wallet.
- [ ] Keep add-auth-method separate from add-signer.

### Phase 7: Cleanup And Guards

- [ ] Rename passkey-specific storage concepts that now mean auth-method
      binding.
- [ ] Add guard tests preventing `/registration/bootstrap` and
      `/registration/threshold-ed25519/hss/*` from returning.
- [ ] Add guard tests preventing optional auth fields from selecting
      registration lifecycle.
- [ ] Add guard tests proving Email OTP registration does not call
      reconstruction paths.
- [ ] Remove stale public paths that imply Email OTP Ed25519 registration is a
      sidecar.

## Test Matrix

Registration orchestration:

- [ ] Passkey plus Ed25519-only.
- [ ] Passkey plus ECDSA-only.
- [ ] Passkey plus combined.
- [ ] Email OTP plus Ed25519-only.
- [ ] Email OTP plus ECDSA-only.
- [ ] Email OTP plus combined.

Authority validation:

- [ ] Passkey credential challenge mismatch rejects.
- [ ] Email OTP challenge mismatch rejects.
- [ ] Email OTP proof for another wallet subject rejects.
- [ ] Email OTP proof for another signer selection rejects.
- [ ] Threshold-session auth rejects for fresh registration authority.

Persistence:

- [ ] Registration finalize persists exactly one initial auth-method binding.
- [ ] Combined registration persists both signer families atomically.
- [ ] Failed finalize persists no signer facts and no auth-method binding.
- [ ] Adding a second auth method preserves existing signer records.
- [ ] Revoking one auth method preserves other active auth methods.

Type coverage:

- [ ] Invalid auth-method branch combinations are rejected.
- [ ] Invalid signer-selection branch combinations are rejected.
- [ ] Broad object spreads cannot construct core registration requests.
- [ ] Raw route bodies cannot cross into core registration services.

## Validation

Run narrow checks after each phase:

- `pnpm -s type-check:sdk`
- `pnpm -s type-check:relay-server`
- Focused unit tests for touched registration/auth-method modules.
- Focused route-boundary tests for touched relay routes.
- `git diff --check`

Run broader checks before merging the full refactor:

- `pnpm build:sdk`
- Registration orchestration matrix tests.
- Wallet-registration relay route tests.
- Email OTP auth-method tests.
- Add-auth-method tests.

## Completion Criteria

- `registerWallet()` accepts explicit auth method and signer selection.
- Passkey and Email OTP support Ed25519-only, ECDSA-only, and combined
  registration through the same state machine.
- Initial registration creates the first auth-method binding.
- Existing wallets can add more auth-method bindings.
- Auth-method bindings and signer records are independent lifecycle objects.
- Legacy registration routes and sidecar paths stay deleted.

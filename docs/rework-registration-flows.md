# Rework Registration Flows

## Goal

Registration should support three first-class modes with one WebAuthn `create()` credential:

- Ed25519 only.
- ECDSA only.
- Ed25519 and ECDSA together.

Later signer creation should use a fresh WebAuthn `get()` assertion or an explicitly approved app-session policy. Initial registration should not require a threshold-session JWT, an Ed25519 session token, or a registration continuation JWT to create ECDSA key material.

## Current Shape

The current passkey registration path is NEAR-account and Ed25519 anchored:

1. Client creates a WebAuthn credential.
2. Client prepares threshold Ed25519 HSS material.
3. Server creates the NEAR account and returns an Ed25519 threshold-session JWT.
4. Server can also return `registrationContinuation.token`.
5. Client uses the continuation token to provision ECDSA through `/threshold-ecdsa/hss/*`.

That continuation token exists because ECDSA provisioning runs after `/registration/bootstrap` has already returned. It is protocol glue for the split flow. It should disappear from initial registration once Ed25519 and ECDSA creation are part of one registration ceremony.

## Target Model

Separate wallet identity, passkey identity, signer records, and signing sessions:

```ts
type WalletSubjectId = string & {
  readonly __walletSubjectIdBrand: unique symbol;
};

type WalletSubject = {
  walletSubjectId: WalletSubjectId;
  rpId: string;
  createdAtMs: number;
};

type AuthenticatorBinding = {
  walletSubjectId: WalletSubjectId;
  rpId: string;
  credentialIdB64u: string;
  credentialPublicKeyCoseB64u: string;
  counter: number;
  createdAtMs: number;
};
```

Signer selection must be an explicit state type. Core registration code should avoid optional signer fields:

```ts
type RegistrationSignerSelection =
  | {
      mode: 'ed25519_only';
      ed25519: Ed25519RegistrationSpec;
    }
  | {
      mode: 'ecdsa_only';
      ecdsa: EcdsaRegistrationSpec;
    }
  | {
      mode: 'ed25519_and_ecdsa';
      ed25519: Ed25519RegistrationSpec;
      ecdsa: EcdsaRegistrationSpec;
    };

type Ed25519RegistrationSpec = {
  nearAccountId: string;
  signerSlot: number;
  participantIds: NonEmptyParticipantIds;
};

type EcdsaRegistrationSpec = {
  subjectId: WalletSubjectId;
  chainTargets: NonEmptyArray<ThresholdEcdsaChainTarget>;
  participantIds: NonEmptyParticipantIds;
};
```

Boundary request parsing can accept raw JSON, then normalize once:

```ts
type NormalizedRegistrationRequest = {
  walletSubjectId: WalletSubjectId;
  rpId: string;
  webauthnRegistration: VerifiedRegistrationCredentialInput;
  signerSelection: RegistrationSignerSelection;
  runtimePolicyScope: RuntimePolicyScope;
};
```

After normalization, internal registration functions should receive `NormalizedRegistrationRequest` and concrete ceremony states.

## Registration Ceremony

Initial registration should be a server-owned ceremony with one WebAuthn `create()` verification. HSS remains multi-round where needed, using a server-side ceremony id for transcript correlation.

Suggested endpoints:

```http
POST /wallets/register/start
POST /wallets/register/hss/respond
POST /wallets/register/finalize
```

`/wallets/register/start`:

- Validates and normalizes raw request JSON.
- Verifies WebAuthn `create()` exactly once.
- Validates the challenge against a canonical registration intent digest.
- Creates a short-lived server-side registration ceremony record.
- Prepares Ed25519 HSS state when Ed25519 is requested.
- Prepares ECDSA HSS state when ECDSA is requested.
- Returns `registrationCeremonyId` plus the required per-signer HSS prepare payloads.

`/wallets/register/hss/respond`:

- Loads `registrationCeremonyId`.
- Accepts only transcript messages for signers requested at start.
- Verifies message binding to the prepared server state.
- Stores server HSS responses in the ceremony record.

`/wallets/register/finalize`:

- Loads `registrationCeremonyId`.
- Verifies final HSS transcript bindings.
- Finalizes requested signer material.
- Persists wallet subject, authenticator binding, and signer records.
- Creates a NEAR account only when Ed25519 registration requested account creation.
- Persists ECDSA smart-account signer metadata only when ECDSA is requested.
- Returns signer key refs and optional fresh signing-session auth tokens for immediate use.

`registrationCeremonyId` is an opaque server-side state handle. It should carry no JWT claims and no signing/export authority. Possession of the handle alone should be insufficient to create key material; the HSS transcript must validate against the client’s PRF-derived inputs.

## WebAuthn Challenge Binding

The WebAuthn `create()` challenge should bind the whole registration intent:

```ts
type RegistrationIntentV1 = {
  version: 'registration_intent_v1';
  walletSubjectId: WalletSubjectId;
  rpId: string;
  signerSelection: RegistrationSignerSelection;
  runtimePolicyScope: RuntimePolicyScope;
  nonceB64u: string;
};
```

Rules:

- The server verifies the `clientDataJSON.challenge` against the canonical digest of `RegistrationIntentV1`.
- The digest must include requested signer modes, NEAR account id when present, ECDSA chain targets, participant ids, and runtime policy scope.
- The server stores the verified normalized request on the ceremony record.
- Later HSS steps use the stored normalized request. They should not accept raw signer plan overrides.

## Client Secret Derivation

The client should derive signer-family inputs from the WebAuthn PRF output using domain-separated labels:

```ts
type RegistrationPrfRoot = Uint8Array & {
  readonly __registrationPrfRootBrand: unique symbol;
};

type Ed25519RegistrationClientSeed = Uint8Array & {
  readonly __ed25519RegistrationClientSeedBrand: unique symbol;
};

type EcdsaRegistrationClientRootShare = Uint8Array & {
  readonly __ecdsaRegistrationClientRootShareBrand: unique symbol;
};
```

Derivation labels:

- `seams:registration:ed25519-hss:v1`
- `seams:registration:ecdsa-hss:v1`

Rules:

- Parse WebAuthn PRF extension output once at the client boundary.
- Derive curve-specific internal types immediately.
- HSS transport should exchange protocol messages, rather than sending a raw PRF root to the relay.
- Zeroize raw PRF and derived secret buffers after ceremony finalization where runtime support allows.

## Initial Registration Modes

### Ed25519 Only

Inputs:

- `RegistrationSignerSelection.mode = 'ed25519_only'`
- `nearAccountId`
- Ed25519 participant ids and runtime scope

Output:

- Wallet subject
- Authenticator binding
- Ed25519 signer record
- NEAR account/access key registration result
- Optional Ed25519 signing-session auth token for immediate use

No ECDSA key, ECDSA smart-account record, or ECDSA signing session is created.

### ECDSA Only

Inputs:

- `RegistrationSignerSelection.mode = 'ecdsa_only'`
- `walletSubjectId`
- ECDSA chain targets
- ECDSA participant ids and runtime scope

Output:

- Wallet subject
- Authenticator binding
- ECDSA signer records for requested chain targets
- Optional smart-account deployment metadata
- Optional ECDSA signing-session auth token for immediate use

This mode requires wallet identity to be decoupled from NEAR account creation. `nearAccountId` should be absent from the normalized internal request.

### Ed25519 And ECDSA

Inputs:

- `RegistrationSignerSelection.mode = 'ed25519_and_ecdsa'`
- Ed25519 spec
- ECDSA spec
- Shared wallet subject, RP ID, and runtime scope

Output:

- Wallet subject
- Authenticator binding
- Ed25519 signer record
- ECDSA signer records
- NEAR account/access key registration result
- Optional per-curve signing-session auth tokens for immediate use

The server should prepare independent HSS work in parallel after WebAuthn verification where the runtime allows it.

## Later Signer Creation

Use one add-signer endpoint after wallet registration:

```http
POST /wallets/:walletSubjectId/signers/start
POST /wallets/:walletSubjectId/signers/hss/respond
POST /wallets/:walletSubjectId/signers/finalize
```

Auth options:

```ts
type AddSignerAuth =
  | {
      kind: 'webauthn_assertion';
      credential: WebAuthnAuthenticationCredential;
      expectedChallengeDigestB64u: string;
    }
  | {
      kind: 'app_session';
      claims: AppSessionClaims;
      policy: AddSignerAppSessionPolicy;
    };
```

Rules:

- Adding ECDSA later to an Ed25519-only wallet uses WebAuthn `get()` or an app session approved for signer provisioning.
- Adding Ed25519 later to an ECDSA-only wallet uses WebAuthn `get()` or an app session approved for NEAR account creation/linking.
- The add-signer challenge digest must include wallet subject id, signer kind, chain targets or NEAR account id, participant ids, and runtime policy scope.
- Threshold-session auth tokens should never authorize signer creation.
- Registration continuation JWTs should be deleted once this add-signer flow exists.

## Server Data Changes

Introduce or normalize these records:

```ts
type WalletSubjectRecord = {
  walletSubjectId: WalletSubjectId;
  rpId: string;
  status: 'active';
  createdAtMs: number;
};

type WalletAuthenticatorRecord = {
  walletSubjectId: WalletSubjectId;
  rpId: string;
  credentialIdB64u: string;
  credentialPublicKeyCoseB64u: string;
  counter: number;
  createdAtMs: number;
};

type WalletSignerRecord =
  | {
      kind: 'ed25519';
      walletSubjectId: WalletSubjectId;
      nearAccountId: string;
      signerSlot: number;
      publicKey: string;
      relayerKeyId: string;
      participantIds: NonEmptyParticipantIds;
      status: 'active';
      createdAtMs: number;
    }
  | {
      kind: 'ecdsa';
      walletSubjectId: WalletSubjectId;
      subjectId: WalletSubjectId;
      chainTarget: ThresholdEcdsaChainTarget;
      ecdsaThresholdKeyId: string;
      relayerKeyId: string;
      thresholdEcdsaPublicKeyB64u: string;
      ethereumAddress: string;
      participantIds: NonEmptyParticipantIds;
      status: 'active';
      createdAtMs: number;
    };
```

Required indexes:

- Unique `(rpId, credentialIdB64u)` for authenticator bindings.
- Unique `(walletSubjectId, kind, nearAccountId, signerSlot)` for Ed25519 signer records.
- Unique `(walletSubjectId, kind, chainTarget, ecdsaThresholdKeyId)` for ECDSA signer records.
- Unique ECDSA public key and owner address indexes within runtime scope.

## Client API Changes

Replace the current NEAR-first registration entrypoint with signer-selection APIs:

```ts
type RegisterWalletSubjectInput =
  | {
      kind: 'server_generated';
    }
  | {
      kind: 'provided';
      walletSubjectId: WalletSubjectId;
    };

type RegisterWalletArgs = {
  walletSubject: RegisterWalletSubjectInput;
  rpId: string;
  signerSelection: RegistrationSignerSelection;
  options?: RegistrationHooksOptions;
};

type AddWalletSignerArgs =
  | {
      kind: 'ed25519';
      walletSubjectId: WalletSubjectId;
      ed25519: Ed25519RegistrationSpec;
      options?: AddSignerHooksOptions;
    }
  | {
      kind: 'ecdsa';
      walletSubjectId: WalletSubjectId;
      ecdsa: EcdsaRegistrationSpec;
      options?: AddSignerHooksOptions;
    };
```

SDK modules:

- `seams.registration.registerWallet(args)`
- `seams.registration.addWalletSigner(args)`
- `seams.near.registerNearWallet(...)` as a small wrapper around `registerWallet({ signerSelection: { mode: 'ed25519_only', ... } })`
- `seams.evm.registerEvmWallet(...)` as a small wrapper around `registerWallet({ signerSelection: { mode: 'ecdsa_only', ... } })`

Delete the old continuation-token-based initial ECDSA provisioning path in the same refactor.

## Route Auth Policy

Registration route auth should be:

- `/wallets/register/start`: public WebAuthn proof route.
- `/wallets/register/hss/respond`: public threshold protocol state route bound to a ceremony id.
- `/wallets/register/finalize`: public threshold protocol state route bound to a ceremony id.
- `/wallets/:walletSubjectId/signers/*`: WebAuthn assertion or app-session policy route.

Threshold-session auth tokens are signing-session capabilities. They should be accepted by signing, presign, export, and session refresh routes only.

## Implementation Phases

### Phase 1: Types And Boundaries

- Add wallet subject, authenticator binding, signer selection, and ceremony state types.
- Add normalizers for raw registration requests.
- Add canonical registration intent digest encoding.
- Add architecture guards against optional lifecycle signer fields in core registration types.

### Phase 2: Server Ceremony

- Add `/wallets/register/start`, `/wallets/register/hss/respond`, and `/wallets/register/finalize`.
- Move WebAuthn `create()` verification into `register/start`.
- Store normalized signer selection on the ceremony record.
- Prepare Ed25519 and ECDSA HSS state from the same verified registration context.
- Finalize and persist requested signer records.

### Phase 3: Client Flow

- Add `registerWallet`.
- Build signer selection from config and explicit user options.
- Derive curve-specific PRF inputs with domain-separated labels.
- Run the combined registration ceremony for all selected signers.
- Persist returned signer refs under wallet subject identity.

### Phase 4: Add-Signer Flow

- Add `/wallets/:walletSubjectId/signers/*` routes.
- Add client `addWalletSigner`.
- Use WebAuthn `get()` challenge binding for later signer creation.
- Persist newly attached signer records without re-registering the authenticator.

### Phase 5: Cleanup

- Delete registration continuation JWT signing and validation paths.
- Delete initial-registration ECDSA post-provisioning through `/threshold-ecdsa/hss/*`.
- Delete mixed registration code paths that derive ECDSA authority from Ed25519 threshold-session JWTs.
- Rename threshold signing-session JWT fields to opaque auth-token names as covered by `docs/disambiguate-threshold-session-jwt.md`.
- Update route definitions and architecture guards.

## Tests

Add unit and integration coverage for:

- WebAuthn registration challenge binds `ed25519_only` signer selection.
- WebAuthn registration challenge binds `ecdsa_only` signer selection.
- WebAuthn registration challenge binds `ed25519_and_ecdsa` signer selection.
- Ed25519-only registration creates no ECDSA records.
- ECDSA-only registration creates no NEAR account.
- Combined registration creates both signer families from one WebAuthn `create()` verification.
- ECDSA initial registration rejects threshold-session auth tokens.
- Ed25519 initial registration rejects threshold-session auth tokens.
- Registration HSS respond/finalize rejects signer kinds absent from the stored ceremony.
- Later ECDSA add-signer succeeds from an Ed25519-only wallet with WebAuthn `get()`.
- Later Ed25519 add-signer succeeds from an ECDSA-only wallet with WebAuthn `get()`.
- App-session add-signer requires an explicit signer-provisioning policy.
- Deleted registration continuation token names are absent from production code.

## Decisions Before Implementation

- Wallet subject id source: server-generated opaque id, client-provided id normalized by server, or account-derived id for NEAR wrappers.
- ECDSA-only smart-account behavior: persist counterfactual metadata only, deploy immediately, or follow existing deployment policy.
- Ed25519 later behavior for ECDSA-only wallets: create a new NEAR account, attach to an existing account, or support both as explicit sub-modes.
- Runtime storage layout: new wallet subject tables or normalized records on top of existing identity and signer stores.

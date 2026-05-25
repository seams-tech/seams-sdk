# Rework Registration Flows

## Goal

Registration should support three first-class modes with one WebAuthn `create()` credential:

- Ed25519 only.
- ECDSA only.
- Ed25519 and ECDSA together.

Later signer creation should use a fresh WebAuthn `get()` assertion or an explicitly approved app-session policy. Initial registration should not require a threshold-session auth token, an Ed25519 session token, or a registration continuation JWT to create ECDSA key material.

Wallet unlock should mirror the same signer-family independence:

- Unlock Ed25519 only.
- Unlock ECDSA only.
- Unlock Ed25519 and ECDSA together.

ECDSA unlock may need authenticated key-facts inventory, but that authority
must come from wallet/authenticator auth or an explicit app-session policy. It
should not require an Ed25519 signing session, Ed25519 threshold-session auth
token, or NEAR account continuity.

## Current Shape

The current passkey registration path is NEAR-account and Ed25519 anchored:

1. Client creates a WebAuthn credential.
2. Client prepares threshold Ed25519 HSS material.
3. Server creates the NEAR account and returns an Ed25519 threshold-session auth token.
4. Server can also return `registrationContinuation.token`.
5. Client uses the continuation token to provision ECDSA through `/threshold-ecdsa/hss/*`.

That continuation token exists because ECDSA provisioning runs after `/registration/bootstrap` has already returned. It is protocol glue for the split flow. It should disappear from initial registration once Ed25519 and ECDSA creation are part of one registration ceremony.

## Current Flow Review Findings

Implementation should treat these current paths as the replacement targets:

- Server registration is split across `relayRegistrationBootstrap.ts`,
  `relayRegistrationThresholdEd25519Hss.ts`, Express route wrappers, and
  Cloudflare route wrappers. New `/wallets/register/*` handlers should live in
  new route modules, then the old wrappers should be deleted in the same
  cutover refactor.
- Current Ed25519 registration HSS stores registration material in
  `ThresholdSigningService` before `/registration/bootstrap` creates the
  account. Unified registration should finalize HSS material and persist wallet
  subject, authenticator binding, signer records, and optional NEAR account
  state from `/wallets/register/finalize`.
- The Ed25519 HSS crate and WASM boundary now use a role-separated active path.
  Registration routes should expose only server-visible HSS protocol messages:
  `clientRequestMessageB64u`, `serverInputDeliveryB64u`, and a
  client-owned staged evaluator artifact. Client-retained evaluator OT state,
  client input shares, PRF output, output masks, and opened client output stay
  inside the client or worker boundary.
- `AuthService.createAccountAndRegisterUser` currently combines WebAuthn
  verification, NEAR account provisioning, authenticator writes, Ed25519
  session minting, and obsolete ECDSA request parsing. Extract reusable helper
  behavior into wallet-subject registration services, then remove this method
  as a public registration path.
- Client `registerPasskeyInternal` currently validates a NEAR account, collects
  WebAuthn, runs Ed25519 registration HSS through legacy registration routes,
  calls `/registration/bootstrap`, then optionally provisions ECDSA through a
  continuation token. `registerWallet` should start at
  `/wallets/register/intent` and run every requested signer through one
  ceremony.
- `thresholdWarmSessionBootstrap.ts` currently mixes Ed25519 HSS protocol
  mechanics with managed grant issuance and relay calls. Keep reusable protocol
  mechanics, and move registration relay traffic into wallet-registration RPC
  helpers.
- UI-confirm registration currently builds `register:${nearAccountId}:${signerSlot}`
  digests and can mutate `signerSlot` during duplicate-credential retry. The
  new prompt flow should use immutable `RegistrationIntentV1` data from the
  server. Any retry that changes intent data must allocate a new intent and
  grant.
- Local registration persistence is NEAR-profile-first today. Wallet-subject
  records should become the source of truth. NEAR profile projection should be
  written only after wallet-subject persistence succeeds and only for Ed25519
  registrations.

## Target Model

Separate wallet identity, registration authority/auth-method bindings, signer
records, and signing sessions. Passkeys and Email OTP are first-class
auth-method bindings on a wallet subject; future auth methods should be added
as new binding branches instead of new registration subsystems:

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
      walletSubjectId: WalletSubjectId;
      rpId: string;
      credentialIdB64u: string;
      credentialPublicKeyCoseB64u: string;
      counter: number;
      createdAtMs: number;
    }
  | {
      kind: 'email_otp';
      walletSubjectId: WalletSubjectId;
      rpId: string;
      emailHashHex: string;
      createdAtMs: number;
      verifiedAtMs: number;
    };

type RegistrationAuthority =
  | {
      kind: 'passkey';
      webauthnRegistration: VerifiedRegistrationCredentialInput;
    }
  | {
      kind: 'email_otp';
      emailOtpProof: VerifiedEmailOtpRegistrationProof;
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
  chainTargets: NonEmptyArray<ThresholdEcdsaChainTarget>;
  participantIds: NonEmptyParticipantIds;
};
```

Boundary request parsing can accept raw JSON, then normalize once:

```ts
type NormalizedRegistrationRequest = {
  walletSubjectId: WalletSubjectId;
  rpId: string;
  authority: RegistrationAuthority;
  signerSelection: RegistrationSignerSelection;
  runtimePolicyScope: RuntimePolicyScope;
};
```

After normalization, internal registration functions should receive `NormalizedRegistrationRequest` and concrete ceremony states.

`walletSubjectId` is the sole wallet subject identifier in registration,
signer records, unlock, warm-up, and persistence-domain types. Do not add an
ECDSA-specific subject field to core types. If a cryptographic protocol or wire
endpoint still uses subject wording, the boundary adapter should project
`walletSubjectId` into that field and immediately normalize responses back to
wallet-subject types.

A wallet may have multiple active auth-method bindings over time, for example
one or more passkeys plus one or more Email OTP addresses. Registration creates
the first binding for a new wallet subject; add-auth-method/enrollment flows
must add additional bindings to the existing wallet subject without creating a
new wallet identity or mutating signer facts implicitly.

## Resolved Implementation Decisions

These decisions close the plan ambiguities that can otherwise create divergent
registration implementations:

- Wallet subject allocation happens before WebAuthn through
  `POST /wallets/register/intent`. `RegisterWalletSubjectInput.kind =
  'server_generated'` means the server allocates a fresh `walletSubjectId`;
  `kind = 'provided'` means the server validates the caller-provided id and
  reserves it for the short-lived intent.
- `/wallets/register/intent` is the environment-bound route. It resolves
  `runtimePolicyScope`, origin policy, API-key or bootstrap-token authority,
  requested registration auth method, and registration metering context.
  `/wallets/register/start` is a public proof route whose authority is the
  exact `registrationIntentGrant` plus the registration-authority proof for
  the matching digest. For passkey that proof is WebAuthn `create()`; for Email
  OTP it is verified Email OTP authority bound to the same intent.
- Registration ceremony state lives behind a new `RegistrationCeremonyStore`
  interface. Express production uses Postgres, Cloudflare uses Durable Object
  storage, and local tests may use memory. The current in-process Ed25519 HSS
  ceremony map remains usable only for local single-process tests after this
  rework.
- ECDSA initial registration performs one EVM-family HSS keygen per
  `EcdsaRegistrationSpec`, then writes one signer record per requested
  `chainTarget` carrying the same `EvmFamilyEcdsaWalletKey`.
- `EvmFamilyEcdsaWalletKey` is the canonical active ECDSA key type.
  `VerifiedEcdsaPublicFacts`, `ResolvedEvmFamilyEcdsaKey`, and
  `ThresholdEcdsaSecp256k1KeyRef` become boundary or transition projections.
  Core unlock, signing, export, budget, and warm-up code consumes
  `EvmFamilyEcdsaWalletKey`.
- Invalid development ECDSA profile rows are pruned through an explicit
  one-shot maintenance path. Runtime login and unlock report
  `repair_required` or `blocked` states; they do not synthesize direct
  `keyHandle` values for active signer records.
- Authenticated ECDSA key-facts inventory moves to a wallet-subject repair
  endpoint authorized by WebAuthn `get()` or an app-session policy with
  `ecdsa_key_facts_inventory` permission. Ed25519 threshold-session tokens have
  no signer-discovery authority.

## Registration Ceremony

Initial registration should be a server-owned ceremony with one WebAuthn
`create()` verification. HSS remains multi-round where needed, using a
server-side ceremony id for transcript correlation.

Endpoints:

```http
POST /wallets/register/intent
POST /wallets/register/start
POST /wallets/register/hss/respond
POST /wallets/register/finalize
```

`/wallets/register/intent`:

- Validates raw signer selection and requested wallet-subject allocation.
- Resolves the caller's runtime policy scope from the API key, bootstrap token,
  or managed registration grant context.
- Allocates or reserves `walletSubjectId`.
- Generates server nonce material.
- Returns `RegistrationIntentV1`, `registrationIntentDigestB64u`,
  `registrationIntentGrant`, and `expiresAtMs`.
- Records intent-grant replay state keyed by grant id until expiry.

`/wallets/register/start`:

- Validates and normalizes raw request JSON.
- Verifies WebAuthn `create()` exactly once.
- Validates the challenge against a canonical registration intent digest.
- Verifies `registrationIntentGrant` against the same digest, signer selection,
  `walletSubjectId`, `rpId`, nonce, runtime policy scope, origin binding, and
  expiry.
- Consumes the intent grant so it cannot start another ceremony.
- Creates a short-lived server-side registration ceremony record.
- Prepares Ed25519 HSS state when Ed25519 is requested.
- For Ed25519, returns the client prepare payload as
  `preparedSession.contextBindingB64u`,
  `preparedSession.evaluatorDriverStateB64u`, and
  `clientOtOfferMessageB64u`.
- For Ed25519, stores the wallet registration ceremony handle, intent, signer
  spec, and WebAuthn binding in `RegistrationCeremonyStore`; the threshold
  service's role-separated HSS ceremony record owns the prepared server session,
  garbler driver state, relayer input shares, operation, and expected context
  binding behind the `ceremonyHandle`.
- Prepares ECDSA HSS state when ECDSA is requested.
- Returns `registrationCeremonyId` plus the required per-signer HSS prepare payloads.

`/wallets/register/hss/respond`:

- Loads `registrationCeremonyId`.
- Accepts only transcript messages for signers requested at start.
- For Ed25519, accepts only
  `ThresholdEd25519HssServerVisibleClientRequestEnvelope`.
  `evaluatorOtStateB64u`, client input shares, PRF material, and output masks
  must be rejected at the request parser boundary.
- Verifies message binding to the prepared server state.
- For Ed25519, prepares role-separated `serverInputDeliveryB64u`, stores the
  responded lifecycle state, and clears raw relayer input shares from the
  ceremony record.
- Stores server HSS responses for each requested signer in the ceremony record.

`/wallets/register/finalize`:

- Loads `registrationCeremonyId`.
- Verifies final HSS transcript bindings.
- For Ed25519, accepts only the client-owned staged evaluator artifact envelope.
  Finalize must reject evaluator OT state, client input shares, PRF material,
  output masks, raw opened client output, and server-owned staged artifacts.
- Finalizes requested signer material.
- For Ed25519, finalizes the HSS report from the client-owned staged artifact,
  opens the server output on the server, and derives registration material from
  the role-separated finalized report.
- Persists wallet subject, authenticator binding, and signer records.
- Creates a NEAR account only when Ed25519 registration requested account creation.
- Persists ECDSA signer metadata only when ECDSA is requested.
- Returns signer key refs and optional fresh signing-session auth tokens for immediate use.

`registrationCeremonyId` is an opaque server-side state handle. It should carry no JWT claims and no signing/export authority. Possession of the handle alone should be insufficient to create key material; the HSS transcript must validate against the client’s PRF-derived inputs.

Intent request and response:

```ts
type CreateRegistrationIntentRequest = {
  walletSubject: RegisterWalletSubjectInput;
  rpId: string;
  signerSelection: RegistrationSignerSelection;
};

type RegistrationIntentGrant = string & {
  readonly __registrationIntentGrantBrand: unique symbol;
};

type CreateRegistrationIntentResponse = {
  intent: RegistrationIntentV1;
  registrationIntentDigestB64u: string;
  registrationIntentGrant: RegistrationIntentGrant;
  expiresAtMs: number;
};
```

Start request and response:

```ts
type WalletRegistrationStartRequest = {
  intent: RegistrationIntentV1;
  registrationIntentDigestB64u: string;
  registrationIntentGrant: RegistrationIntentGrant;
  webauthnRegistration: VerifiedRegistrationCredentialInput;
};

type WalletRegistrationStartResponse = {
  registrationCeremonyId: string;
  ed25519?: Ed25519RegistrationHssPreparePayload;
  ecdsa?: EcdsaRegistrationHssPreparePayload;
};

type EcdsaRegistrationHssPreparePayload = {
  kind: 'evm_family_ecdsa_keygen';
  chainTargets: NonEmptyArray<ThresholdEcdsaChainTarget>;
  prepare: ThresholdEcdsaHssPreparePayload;
};
```

HSS response requests are keyed by `registrationCeremonyId` and signer family.
ECDSA uses the single `evm_family_ecdsa_keygen` transcript from start; it does
not accept per-target keygen overrides during respond or finalize.

Ceremony persistence:

```ts
type RegistrationCeremonyRecord = {
  registrationCeremonyId: string;
  status: 'started' | 'hss_responded' | 'finalizing' | 'completed' | 'failed';
  intent: RegistrationIntentV1;
  normalizedRequest: NormalizedRegistrationRequest;
  webauthn: VerifiedRegistrationSummary;
  ed25519?: Ed25519RegistrationCeremonyState;
  ecdsa?: EcdsaRegistrationCeremonyState;
  routeContext: RegistrationRouteContext;
  createdAtMs: number;
  expiresAtMs: number;
};
```

The store must support atomic consume/take semantics for finalize. Expired
ceremonies release HSS server buffers and cannot be finalized.

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
- The WebAuthn challenge bytes are the decoded
  `registrationIntentDigestB64u` returned by `/wallets/register/intent`.
  Client code should not hash a display string or hash the digest again before
  passing it to `navigator.credentials.create()`.
- The digest must include requested signer modes, NEAR account id when present, ECDSA chain targets, participant ids, and runtime policy scope.
- The digest is computed from canonical JSON with sorted object keys,
  normalized chain-target encodings, normalized participant ids, and base64url
  nonce bytes. Client and server helpers must share fixtures for byte-for-byte
  digest parity.
- `registrationIntentGrant` claims bind `walletSubjectId`, `rpId`,
  `registrationIntentDigestB64u`, `runtimePolicyScope`, origin policy,
  environment ids, grant id, issued time, and expiry. The grant carries no
  signer material, no signing-session authority, and no continuation authority.
- The server stores the verified normalized request on the ceremony record.
- Later HSS steps use the stored normalized request. They should not accept raw signer plan overrides.
- UI-confirm registration should take `{ intent, registrationIntentDigestB64u }`
  as input. It should not require NEAR RPC context, nonce reservation, or
  `signerSlot` for the core WebAuthn prompt.
- Duplicate-credential retry must abandon the consumed or failed intent grant
  and allocate a new `/wallets/register/intent` response before prompting
  again. ECDSA-only registration has no signer-slot retry state.

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

## Ed25519 HSS Role Separation

The Ed25519 HSS integration should follow the current role-separated crate
boundary:

1. `/wallets/register/start` prepares the server session and returns
   `preparedSession.contextBindingB64u`,
   `preparedSession.evaluatorDriverStateB64u`, and
   `clientOtOfferMessageB64u` to the client.
2. The client worker prepares `clientRequestMessageB64u` and keeps
   `evaluatorOtStateB64u` locally.
3. `/wallets/register/hss/respond` receives only
   `clientRequestMessageB64u`, prepares `serverInputDeliveryB64u`, and clears
   raw relayer input shares from the server ceremony record.
4. The client worker builds a client-owned staged evaluator artifact from
   `evaluatorDriverStateB64u`, `evaluatorOtStateB64u`,
   `serverInputDeliveryB64u`, and `clientOutputMaskB64u`.
5. `/wallets/register/finalize` receives only the staged evaluator artifact,
   finalizes the report, opens the server output, derives the Ed25519
   registration material, and persists the signer.

Boundary rules:

- Server-visible Ed25519 HSS request types should use
  `ThresholdEd25519HssServerVisibleClientRequestEnvelope` or the equivalent
  wallet-registration type.
- Finalize request types should use
  `ThresholdEd25519HssClientOwnedStagedEvaluatorArtifactEnvelope` or the
  equivalent wallet-registration type.
- Server registration routes should reject `evaluatorOtStateB64u`,
  `yClientB64u`, `tauClientB64u`, `clientOutputMaskB64u`, `rClientB64u`,
  PRF fields, raw client output, seed output, and client-secret fields.
- `clientOutputMaskB64u` is required for client-owned staged artifact
  construction and client output opening, and it should remain client-local.
- Worker-resident handle optimizations may replace process-local serialized
  client state, while HTTP and persisted ceremony boundaries stay canonical and
  explicit.

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

No ECDSA key or ECDSA signing session is created.

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

Ed25519 add-signer intent must use explicit account behavior:

```ts
type Ed25519AddSignerSpec =
  | {
      mode: 'create_near_account';
      nearAccountId: string;
      signerSlot: number;
      participantIds: NonEmptyParticipantIds;
      keyPurpose: string;
      keyVersion: string;
      derivationVersion: number;
    }
  | {
      mode: 'link_existing_near_account';
      nearAccountId: string;
      signerSlot: number;
      participantIds: NonEmptyParticipantIds;
      keyPurpose: string;
      keyVersion: string;
      derivationVersion: number;
      accountOwnershipProof: NearAccountOwnershipProof;
    };
```

`link_existing_near_account` requires a server-verified proof that the wallet
subject is allowed to attach a signer to the existing NEAR account. Initial
Ed25519 registration wrappers use `create_near_account`.

Rules:

- Adding ECDSA later to an Ed25519-only wallet uses WebAuthn `get()` or an app session approved for signer provisioning.
- Adding Ed25519 later to an ECDSA-only wallet uses WebAuthn `get()` or an app session approved for NEAR account creation/linking.
- The add-signer challenge digest must include wallet subject id, signer kind, chain targets or NEAR account id, participant ids, and runtime policy scope.
- Threshold-session auth tokens should never authorize signer creation.
- Registration continuation JWTs should be deleted once this add-signer flow exists.

## Wallet Unlock Model

Unlock is signer-selection driven and independent of NEAR-first or
Ed25519-first assumptions:

```ts
type WalletUnlockSelection =
  | {
      mode: 'ed25519_only';
      ed25519: Ed25519UnlockSpec;
    }
  | {
      mode: 'ecdsa_only';
      ecdsa: EcdsaUnlockSpec;
    }
  | {
      mode: 'ed25519_and_ecdsa';
      ed25519: Ed25519UnlockSpec;
      ecdsa: EcdsaUnlockSpec;
    };

type Ed25519UnlockSpec = {
  walletSubjectId: WalletSubjectId;
  nearAccountId: string;
  signerSlot: number;
};

type EcdsaUnlockSpec = {
  walletSubjectId: WalletSubjectId;
  chainTargets: NonEmptyArray<ThresholdEcdsaChainTarget>;
};
```

Rules:

- Ed25519 unlock provisions Ed25519 signing sessions from Ed25519 signer
  records.
- ECDSA unlock provisions ECDSA signing sessions from ECDSA signer records.
- ECDSA-only unlock must work without a NEAR account, Ed25519 signer record, or
  Ed25519 signing session.
- Combined unlock may run Ed25519 and ECDSA planning independently and then
  provision both families in parallel where the runtime allows it.
- ECDSA key-facts inventory fetches require wallet/authenticator authority or
  an app-session policy with ECDSA unlock/read permission.
- The inventory state should be named for the domain need, such as
  `awaiting_key_facts_inventory` or
  `awaiting_authenticated_key_facts_inventory`; avoid Ed25519-specific names.
- Threshold-session auth tokens remain signing-session capabilities. They may
  refresh or reconnect an existing same-curve signing session, but they should
  not authorize signer discovery or cross-curve unlock.

Authenticated ECDSA key-facts inventory uses a wallet-subject repair endpoint:

```http
POST /wallets/:walletSubjectId/signers/ecdsa/key-facts/inventory
```

```ts
type WalletKeyFactsInventoryAuth =
  | {
      kind: 'webauthn_assertion';
      credential: WebAuthnAuthenticationCredential;
      expectedChallengeDigestB64u: string;
    }
  | {
      kind: 'app_session';
      claims: AppSessionClaims;
      policy: EcdsaKeyFactsInventoryPolicy;
    };

type EcdsaKeyFactsInventoryPolicy = {
  permission: 'ecdsa_key_facts_inventory';
  walletSubjectId: WalletSubjectId;
  chainTargets: NonEmptyArray<ThresholdEcdsaChainTarget>;
  runtimePolicyScope: RuntimePolicyScope;
  expiresAtMs: number;
};
```

The inventory challenge digest includes wallet subject id, RP ID, requested
chain targets, requested key handles when known, runtime policy scope, and a
server nonce. Normal unlock only reads local active signer records. The
inventory endpoint is reachable from explicit repair/recovery states and from
app sessions carrying the exact policy above.

## ECDSA Wallet Key Model

`keyHandle` is an opaque server selector for an integrated ECDSA key. It is
required when the client asks the ECDSA key server to prepare, refresh, export,
or sign with that key. `keyFacts` are the required security facts that prove the
handle points at the expected wallet key.

Core code should use one resolved active-key type that carries both facts:

```ts
type EcdsaKeyFacts = {
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  signingRootId: SigningRootId;
  signingRootVersion: SigningRootVersion;
  thresholdEcdsaPublicKeyB64u: ThresholdEcdsaPublicKeyB64u;
  thresholdOwnerAddress: EvmAddress;
  participantIds: NonEmptyParticipantIds;
};

type EvmFamilyEcdsaWalletKey = {
  kind: 'evm_family_ecdsa_wallet_key';
  keyHandle: EvmFamilyEcdsaKeyHandle;
  keyFacts: EcdsaKeyFacts;
};

type EcdsaWalletSignerRecord = {
  kind: 'ecdsa';
  walletSubjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
  walletKey: EvmFamilyEcdsaWalletKey;
  status: 'active';
  createdAtMs: number;
};
```

Rules:

- Server and persistence boundaries may parse raw `keyHandle`, legacy request
  names, or database field names once. Core registration, unlock, warm-up,
  signing, export, and budget logic consumes `EcdsaWalletSignerRecord` or
  `EvmFamilyEcdsaWalletKey` for resolved active keys.
- Transport helpers may project `keyHandle` from `EvmFamilyEcdsaWalletKey` when
  an endpoint only needs the server selector.
- Operations that select a wallet key, compare lanes, enforce same-address
  EVM-family policy, finalize budgets, or contact the ECDSA key server require
  `EvmFamilyEcdsaWalletKey`.
- Exact warm-up and reconnect lifecycle states require
  `EvmFamilyEcdsaWalletKey`; broad target-based registration intent must not
  flow into exact-session activation.
- Registration-before-finalize, authenticated inventory needed, blocked signer
  records, and raw profile metadata are separate discriminated states. They
  cannot manufacture `EvmFamilyEcdsaWalletKey` until direct `keyHandle` and all
  required `keyFacts` are present.
- No production code may derive `ecdsaThresholdKeyId`, `signingRootId`, or
  `signingRootVersion` from `keyHandle`.
- `legacy-key-handle:*` is an invalid persisted/request shape. Prune or
  recreate development data that still contains it.

Projection and transition rules:

- `EvmFamilyEcdsaWalletKey` is the storage and core-domain source of truth for
  active ECDSA signers.
- `VerifiedEcdsaPublicFacts` is a projection of `walletKey.keyHandle` plus the
  public subset of `walletKey.keyFacts`. Builders may accept
  `EvmFamilyEcdsaWalletKey` and wire responses; core active-signer code should
  not store `VerifiedEcdsaPublicFacts` by itself.
- `ResolvedEvmFamilyEcdsaKey` is a transition read model for availability and
  display surfaces. New activation, unlock, signing, export, and budget inputs
  should consume `EvmFamilyEcdsaWalletKey` directly.
- `ThresholdEcdsaSecp256k1KeyRef` remains a transport adapter shape at relay,
  worker, and external SDK boundaries until Phase 8 removes it from core
  surfaces.

Tradeoffs:

- Benefit: the active-key invariant is represented once. Core code cannot
  receive a `keyHandle` without the required wallet-key facts.
- Benefit: unlock, warm-up, reconnect, signing, export, and budget code can use
  one resolved key object instead of repeating parallel field checks.
- Benefit: partial states stay explicit. Registration-finalize pending,
  inventory-needed, blocked, and raw persistence records remain separate union
  branches.
- Cost: transport code still needs narrow `keyHandle` projections for endpoints
  that only require the server selector.
- Cost: persistence may need separate `keyHandle` and `keyFacts` indexes even
  though core code sees one active-key object.

## ECDSA KeyFacts Producer Invariant

Registration and add-signer finalization own the complete active ECDSA wallet
key shape. Login, unlock, signing, export, budget, and reconnect code should
consume `EvmFamilyEcdsaWalletKey`; they should not repair incomplete active
signer records during normal operation.

The current login regression came from tightening the consumer before the
producer. Unlock started requiring exact `keyHandle` selectors while existing
profile signer rows still lacked direct handles. The rework must finish the
producer side and remove runtime repair paths from normal login.

Rules:

- `/wallets/register/finalize` and `/wallets/:walletSubjectId/signers/finalize`
  must persist every active ECDSA signer record with:
  - `walletKey.keyHandle`
  - `walletKey.keyFacts.ecdsaThresholdKeyId`
  - `walletKey.keyFacts.signingRootId`
  - `walletKey.keyFacts.signingRootVersion`
  - `walletKey.keyFacts.thresholdEcdsaPublicKeyB64u`
  - `walletKey.keyFacts.thresholdOwnerAddress`
  - `walletKey.keyFacts.participantIds`
  - concrete `chainTarget`
- The server response for registration/add-signer finalization must return the
  same complete wallet-key facts that persistence writes.
- The client must persist the returned complete `EvmFamilyEcdsaWalletKey`
  directly into wallet-subject signer records and any profile projection used
  by unlock.
- Active ECDSA profile signer records that lack `keyHandle` are invalid. Current
  development rows in that shape must be pruned, rewritten by an explicit
  one-shot maintenance script, or recreated through registration/add-signer
  finalize.
- Login may use authenticated key-facts inventory only for explicit repair
  or recovery states. A normal unlock plan with active signer records should be
  local-only and should perform no `/threshold-ecdsa/key-identities` fetch.
- Runtime login must not derive `keyHandle` from `keyFacts`.
  There is one active selector path: registration/add-signer finalize produces
  `walletKey.keyHandle`, persistence stores it, and unlock consumes it.
- `legacy-key-handle:*` remains rejected at active signer boundaries. It is a
  prune/repair signal, never an active key id.

Sequencing:

1. Add the complete `EvmFamilyEcdsaWalletKey` result shape to server
   registration/add-signer finalization.
2. Persist that shape in client wallet-subject signer records and profile
   projections.
3. Add write-time invariants that reject active ECDSA signer records missing
   `keyHandle` or required `keyFacts`.
4. Prune, rewrite, or recreate current development data that lacks direct
   `keyHandle`.
5. Make active ECDSA profile parsing strict.
6. Move authenticated inventory fetches behind an explicit repair/recovery
   unlock state with user-visible diagnostics.

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
      chainTarget: ThresholdEcdsaChainTarget;
      walletKey: EvmFamilyEcdsaWalletKey;
      relayerKeyId: string;
      status: 'active';
      createdAtMs: number;
    };
```

Required indexes:

- Unique `(rpId, credentialIdB64u)` for authenticator bindings.
- Unique `(walletSubjectId, kind, nearAccountId, signerSlot)` for Ed25519 signer records.
- Unique `(walletSubjectId, kind, chainTarget, walletKey.keyHandle)` for ECDSA
  selector lookup.
- Unique `(walletSubjectId, kind, chainTarget,
  walletKey.keyFacts.ecdsaThresholdKeyId, walletKey.keyFacts.signingRootId,
  walletKey.keyFacts.signingRootVersion)` for ECDSA key-facts lookup.
- Unique ECDSA public key and owner address indexes within runtime scope.
- Funds-safety invariant: EVM SIGNERS MUST ALL SHARE THE SAME ADDRESS for the
  same wallet subject, RP, signing root, and key version. Registration may write
  separate Tempo/EVM lane records, but those records must carry one shared
  `walletKey.keyFacts`.

Registration ceremony tables:

- `wallet_registration_intents`
  - `grant_id`
  - `wallet_subject_id`
  - `rp_id`
  - `intent_digest_b64u`
  - `runtime_policy_scope_json`
  - `route_context_json`
  - `origin_policy_json`
  - `expires_at_ms`
  - `consumed_at_ms`
- `wallet_registration_ceremonies`
  - `registration_ceremony_id`
  - `wallet_subject_id`
  - `status`
  - `intent_json`
  - `normalized_request_json`
  - `webauthn_summary_json`
  - `ed25519_state_json`
  - `ecdsa_state_json`
  - `route_context_json`
  - `created_at_ms`
  - `expires_at_ms`

Postgres stores binary HSS state as base64url fields inside the state JSON or
as separate bytea columns if the implementation needs row-level updates. The
store API must expose typed ceremony states to core code.

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
      ed25519: Ed25519AddSignerSpec;
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
- `seams.near.registerNearWallet(...)` as a small wrapper around
  `registerWallet(...)` that requests Ed25519 plus the configured
  threshold-ECDSA provisioning targets by default; callers can pass
  `options.signerOptions` with Tempo/EVM disabled to request explicit
  Ed25519-only registration.
- `seams.evm.registerEvmWallet(...)` as a small wrapper around `registerWallet({ signerSelection: { mode: 'ecdsa_only', ... } })`
  - Implemented as narrow public wrappers: NEAR registration takes a
    `nearAccountId`, and EVM registration takes required `chainTargets` and
    `participantIds`.

Delete the old continuation-token-based initial ECDSA provisioning path in the same refactor.

Client registration sequence:

1. `registerWallet(args)` calls `/wallets/register/intent`.
2. The SDK computes the WebAuthn `create()` challenge from the returned
   `RegistrationIntentV1`.
3. The SDK collects one WebAuthn credential and parses PRF extension output.
4. The SDK calls `/wallets/register/start` with the returned grant and the
   verified intent digest.
5. The SDK runs requested Ed25519 and ECDSA HSS respond steps against the single
   `registrationCeremonyId`.
6. The SDK calls `/wallets/register/finalize`.
7. The SDK persists returned wallet-subject signer records and immediate
   signing-session material.

Current client RPC replacement map:

| Current helper or route                                                                                       | Replacement                                                                                                |
| ------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `createManagedRegistrationFlowGrant` for `/registration/bootstrap` or `/registration/threshold-ed25519/hss/*` | `/wallets/register/intent` route scope resolution and `registrationIntentGrant` issuance                   |
| `requestRegistrationCredentialConfirmation({ nearAccountId, signerSlot })`                                    | `requestRegistrationCredentialConfirmation({ intent, registrationIntentDigestB64u })`                      |
| `prepareThresholdEd25519RegistrationWithHss` legacy relay sequence                                            | Pure Ed25519 HSS client mechanics called by wallet-registration orchestration                              |
| `prepare/respond/finalizeThresholdEd25519HssServerCeremonyWithRelayRegistration`                              | `walletRegistration.start`, `walletRegistration.hssRespond`, and `walletRegistration.finalize` RPC helpers |
| `createAccountAndRegisterWithRelayServer`                                                                     | `registerWalletViaRelayCeremony` in the wallet-registration RPC caller                                     |
| `provisionThresholdEcdsaAfterRegistration`                                                                    | Delete; initial ECDSA HSS runs inside the registration ceremony                                            |
| `bootstrapEcdsaSession` immediately after continuation-token registration                                     | Warm-session provisioning from persisted wallet-subject signer records after finalize                      |

Client persistence cutover rules:

- Add wallet-subject local store APIs before replacing the registration
  orchestrator.
- `registerWallet` persists wallet subject, authenticator binding, and signer
  records from `/wallets/register/finalize` first.
- `registerNearWallet` and `registerPasskey` route through the same wallet
  registration ceremony and signer-selection builder. With default
  threshold-ECDSA provisioning enabled, they request Ed25519 plus configured
  Tempo/EVM ECDSA targets; callers that need NEAR-only registration pass
  disabled Tempo/EVM `signerOptions`.
  The wrappers may write a NEAR profile projection only after wallet-subject
  persistence succeeds and an Ed25519 signer result is present.
- ECDSA-only registration must not call `atomicStoreRegistrationData`,
  `resolveNearAccountProfileContinuity`, or any NEAR profile continuity helper.
- Warm-session provisioners may create volatile signing-session material after
  finalize, and they should consume existing signer records only.

## Route Auth Policy

Registration route auth should be:

- `/wallets/register/intent`: API-credential route. Accept secret-key,
  bootstrap-token, or managed publishable-key grant flows according to the
  deployment. This route resolves environment binding, origin binding,
  runtime policy scope, and metering context.
- `/wallets/register/start`: public proof route. Requires a valid
  `registrationIntentGrant` and a WebAuthn `create()` credential bound to the
  same intent digest.
- `/wallets/register/hss/respond`: public threshold protocol state route bound
  to an unexpired ceremony id.
- `/wallets/register/finalize`: public threshold protocol state route bound to
  an unexpired ceremony id with complete requested HSS transcripts.
- `/wallets/:walletSubjectId/signers/*`: WebAuthn assertion or app-session
  policy route.
- `/wallets/:walletSubjectId/signers/ecdsa/key-facts/inventory`: WebAuthn
  assertion or app-session policy route for explicit repair/recovery inventory.

Threshold-session auth tokens are signing-session capabilities. They should be
accepted by signing, presign, export, and session refresh routes only.

Metering:

- `/wallets/register/intent` records grant issuance and environment selection.
- `/wallets/register/finalize` records `wallet_created` only after requested
  signer records are persisted.
- Failed start/respond/finalize attempts are observable diagnostics tied to the
  grant or ceremony id. They must not count as wallet creation.

## Refactor 33, 35, And 36 Alignment

This plan targets the current signing-engine layout from `docs/refactor-33.md`, `docs/refactor-35-sealed-recovery.md`, and `docs/refactor-36.md`:

- Registration account lifecycle and registration session helpers live under `client/src/core/signingEngine/flows/registration`.
- Ed25519 threshold protocol mechanics live under `client/src/core/signingEngine/threshold/ed25519`.
- ECDSA threshold protocol mechanics live under `client/src/core/signingEngine/threshold/ecdsa`.
- Passkey-origin PRF cache writes, sealed recovery, and method-specific warm-session provisioning live under `client/src/core/signingEngine/session/passkey`.
- Email OTP recovery and provisioning live under `client/src/core/signingEngine/session/emailOtp`.
- Generic warm-material read models, readiness, transitions, and persistence helpers live under `client/src/core/signingEngine/session/warmCapabilities`.
- Per-operation lane, prepared-operation, trace, and post-sign policy state lives under `client/src/core/signingEngine/session/operationState`.
- Reusable WebAuthn credential collection and PRF extension parsing live under `client/src/core/signingEngine/webauthnAuth`.
- Wallet/account auth policy lives under `client/src/core/signingEngine/stepUpConfirmation/walletAuthModeResolver.ts`.
- Operation code should depend on `stepUpConfirmation/*`, `threshold/*`, and `session/*` by direct owner imports. Do not add `threshold/workflows/*`, `threshold/session/*`, `api/*`, or `orchestration/*` paths.
- Concrete registration prompt routing lives under `uiConfirm/*`.
- Registration-adjacent session work must use discriminated lifecycle plans. Do not pass broad optional bags containing `thresholdSessionAuth?`, `webauthnAuthentication?`, `clientRootShare32B64u?`, `thresholdSessionId?`, or `walletSigningSessionId?` through internal registration, add-signer, warm-capability, or session-provisioning code.
- `tests/unit/signingEngine.refactor33.guard.unit.test.ts` must stay green while registration code moves.
- `tests/unit/signingEngine.refactor36.guard.unit.test.ts` must stay green while registration and signer-provisioning lifecycle types move.

## Current Code Touchpoints

Route replacement order:

1. Add new wallet-registration route definitions and route modules.
2. Implement the new service path against `RegistrationCeremonyStore`.
3. Move client registration orchestration to `/wallets/register/*`.
4. Delete `/registration/bootstrap` and
   `/registration/threshold-ed25519/hss/*` wrappers in the same refactor that
   removes client callers.
5. Keep `/threshold-ecdsa/hss/*` only for signing-session bootstrap, export,
   and other existing-key flows. Initial registration and add-signer creation
   should use wallet registration or wallet signer routes.

Server files to edit:

- `server/src/router/routeDefinitions.ts`
  - Add route definitions for `/wallets/register/intent`,
    `/wallets/register/*`, `/wallets/:walletSubjectId/signers/*`, and
    `/wallets/:walletSubjectId/signers/ecdsa/key-facts/inventory`.
  - Remove initial-registration authority from `/threshold-ecdsa/hss/*`.
  - Delete `/registration/bootstrap` and `/registration/threshold-ed25519/hss/*` in the route replacement phase.
- `server/src/router/express/createRelayRouter.ts`
  - Mount the new Express registration and add-signer route modules.
  - Remove the Express mounts for the obsolete registration bootstrap handlers.
- `server/src/router/express/routes/walletRegistration.ts`
  - Add a new Express route module for `/wallets/register/intent`,
    `/wallets/register/start`, `/wallets/register/hss/respond`, and
    `/wallets/register/finalize`.
  - Route raw request bodies through boundary parsers before calling core
    registration services.
- `server/src/router/cloudflare/createCloudflareRouter.ts`
  - Mount the new Cloudflare registration and add-signer route handlers.
  - Remove the Cloudflare dispatch for the obsolete registration bootstrap handlers.
- `server/src/router/cloudflare/routes/walletRegistration.ts`
  - Add matching Cloudflare handlers for the wallet registration ceremony.
  - Use the Cloudflare `RegistrationCeremonyStore` implementation for ceremony
    state.
- `server/src/router/relayRegistrationBootstrap.ts`
  - Delete the continuation-token response path.
  - Move reusable NEAR account creation pieces behind Ed25519 signer creation helpers.
  - Delete this handler in the same refactor that moves `registerNearWallet` to `/wallets/register/*`.
- `server/src/router/relayRegistrationThresholdEd25519Hss.ts`
  - Fold Ed25519 registration HSS into the new multi-signer ceremony.
  - Remove account provisioning from the Ed25519 HSS finalize path; NEAR
    account provisioning belongs to `/wallets/register/finalize`.
  - Delete this handler in the same refactor that adds Ed25519 support to `/wallets/register/hss/respond`.
- `server/src/router/express/routes/registrationThresholdEd25519Hss.ts`
  - Delete the Express wrapper in the unified registration route refactor.
- `server/src/router/cloudflare/routes/registrationThresholdEd25519Hss.ts`
  - Delete the Cloudflare wrapper in the unified registration route refactor.
- `server/src/router/express/routes/thresholdEcdsa.ts`
  - Remove registration-continuation parsing from ECDSA HSS prepare.
  - Keep ECDSA HSS routes for signing-session bootstrap, export, and other non-registration flows.
- `server/src/router/cloudflare/routes/thresholdEcdsa.ts`
  - Match the Express ECDSA HSS cleanup.
- `server/src/router/commonRouterUtils.ts`
  - Delete `signRegistrationContinuationJwt`.
  - Keep threshold signing-session token signing for signing-session routes.
- `server/src/router/bootstrapGrantBroker.ts`
  - Replace grant targets for `/registration/bootstrap` and `/registration/threshold-ed25519/hss/*` with `/wallets/register/intent`.
  - Keep managed grant issuance scoped to intent allocation only.

Server core files to edit:

- `server/src/core/RegistrationCeremonyStore.ts`
  - Add the `RegistrationCeremonyStore` interface with create, read, update,
    consume-intent, take-finalize, fail, and expire operations.
  - Add memory implementation for tests and local single-process development.
  - Add Postgres and Cloudflare Durable Object implementations before
    production rollout.
- `server/src/core/AuthService.ts`
  - Introduce wallet-subject registration service methods.
  - Add `/wallets/register/intent` allocation and intent-grant consumption
    service methods.
  - Extract NEAR account provisioning as an Ed25519 signer side effect.
  - Extract WebAuthn `create()` verification into a helper that accepts
    normalized `RegistrationIntentV1` and its canonical digest.
  - Extract authenticator binding writes so they target `walletSubjectId`.
  - Extract immediate Ed25519 signing-session minting so it runs after signer
    finalization.
  - Delete `createAccountAndRegisterUser` as the primary registration implementation.
  - Delete the raw `threshold_ecdsa.client_root_share32_b64u` registration path.
- `server/src/core/types.ts`
  - Replace `CreateAccountAndRegisterRequest` and `CreateAccountAndRegisterResult` with wallet registration request/result types.
  - Add explicit registration ceremony state types and signer-selection types.
  - Remove `registrationContinuation` result types.
- `server/src/core/ThresholdService/ThresholdSigningService.ts`
  - Add a verified add-signer policy boundary for WebAuthn `get()` and app-session auth.
  - Add a verified ECDSA key-facts inventory policy boundary for repair/recovery
    reads.
  - Remove object-shape WebAuthn checks from ECDSA registration bootstrap.
  - Move ECDSA registration HSS state behind the new registration ceremony.
  - Move Ed25519 registration HSS state out of the in-memory `ed25519HssCeremonyStore`
    for production registration. Memory state remains acceptable for focused
    tests and local single-process development.
  - Preserve the role-separated Ed25519 HSS boundary when moving registration:
    server routes receive server-visible client request messages, respond with
    server input delivery, and finalize from client-owned staged artifacts.
  - Delete registration-continuation authorization branches.
- `server/src/core/ThresholdService/ed25519HssWasm.ts`
  - Reuse `prepareThresholdEd25519HssRoleSeparatedServerInputDelivery` for
    Ed25519 registration respond.
  - Keep `prepareThresholdEd25519HssServerCeremony` out of production
    registration routes because it consumes evaluator OT state at the server
    boundary.
  - Keep `finalizeThresholdEd25519HssServerCeremony` for client-owned staged
    artifact finalization.
- `server/src/core/thresholdEd25519HssRoleSeparated.typecheck.ts`
  - Extend fixtures for wallet registration request and response types.
  - Assert registration routes reject evaluator OT state, client input shares,
    PRF material, client output masks, raw opened client output, and seed output.
- `server/src/core/ThresholdService/validation.ts`
  - Delete registration continuation claim parsing and validation.
  - Add parsers for wallet-subject signer records and add-signer auth claims if they live in threshold validation.
- `server/src/core/WebAuthnAuthenticatorStore.ts`
  - Change authenticator storage from NEAR `userId` ownership to wallet-subject ownership.
  - Preserve counter update semantics under `(rpId, credentialIdB64u)` uniqueness.
- `server/src/core/WebAuthnCredentialBindingStore.ts`
  - Replace Ed25519-specific binding records with wallet authenticator bindings.
  - Move signer metadata into wallet signer records.
- `server/src/storage/postgres.ts`
  - Add `wallet_subjects`, `wallet_authenticators`, `wallet_signers`,
    `wallet_registration_intents`, and `wallet_registration_ceremonies`.
  - Add unique indexes for authenticator and signer records.
  - Add expiry indexes for intent and ceremony cleanup.
  - Remove obsolete registration-continuation-dependent tables or indexes if any exist by then.

Client files to edit:

- `client/src/core/SeamsPasskey/index.ts`
  - Add `registration.registerWallet(args)` and `registration.addWalletSigner(args)`.
  - Convert `registerPasskey` into the passkey wallet wrapper backed by the
    shared signer-selection builder.
  - Add `near.registerNearWallet(...)` and `evm.registerEvmWallet(...)` wrappers if exposed as modules.
    - Complete: the wrappers route through the existing wallet-registration
      ceremony and do not add a separate registration path.
- `client/src/core/SeamsPasskey/interfaces.ts`
  - Add `RegisterWalletArgs`, `AddWalletSignerArgs`, `RegistrationSignerSelection`, and wallet-subject result types.
  - Replace NEAR-account-only registration capability types.
- `client/src/core/SeamsPasskey/registration.ts`
  - Replace NEAR-first registration orchestration with signer-selection orchestration.
  - Start with `/wallets/register/intent`, then compute WebAuthn challenge from
    the returned intent.
  - Delete `provisionThresholdEcdsaAfterRegistration`.
  - Persist wallet-subject signer records without requiring NEAR profile continuity.
- `client/src/core/SeamsPasskey/login.ts`
  - Replace NEAR-first unlock orchestration with signer-selection unlock
    planning.
  - Split Ed25519 and ECDSA unlock planning so either signer family can unlock
    independently or both can unlock in one flow.
  - Move ECDSA profile metadata and key-facts inventory parsing to boundary
    modules.
  - Delete any ECDSA unlock dependency on Ed25519 signing-session auth.
- `client/src/core/SeamsPasskey/faucets/createAccountRelayServer.ts`
  - Replace `/registration/bootstrap` request construction with `/wallets/register/*` RPC helpers.
  - Delete registration continuation normalization and request fields.
  - Keep only transport utilities that are still used by
    `/wallets/register/intent`; remove per-HSS-step managed grant calls.
- `client/src/core/SeamsPasskey/thresholdWarmSessionBootstrap.ts`
  - Convert Ed25519 registration HSS helpers into per-signer ceremony helpers.
  - Remove per-step managed bootstrap grant calls when the server ceremony takes ownership of route scope.
  - Split pure Ed25519 HSS client mechanics from relay RPC calls. Registration
    relay calls should live in `client/src/core/rpcClients/relayer/walletRegistration.ts`.
- `client/src/core/signingEngine/flows/registration/accountLifecycle.ts`
  - Move NEAR account lifecycle work behind Ed25519 signer creation.
  - Keep wallet-subject registration inputs separate from NEAR account inputs.
  - Replace generic `atomicStoreRegistrationData` usage with wallet-subject
    persistence plus a separate Ed25519 NEAR projection writer. ECDSA-only
    registration should bypass NEAR projection entirely.
- `client/src/core/signingEngine/flows/registration/session.ts`
  - Return optional immediate signing-session auth material only after requested signer finalization.
  - Keep registration session state typed by signer-selection mode.
- `client/src/core/signingEngine/threshold/ed25519/hssLifecycle.ts`
  - Keep Ed25519 HSS protocol mechanics reusable for unified registration.
  - Receive resolved registration protocol material from the caller boundary.
  - Preserve the role-separated sequence: prepare client request, receive server
    input delivery, build client-owned staged evaluator artifact, then complete
    from finalized delivery.
- `client/src/core/signingEngine/threshold/ed25519/hssClientBase.ts`
  - Resolve Ed25519 client-base protocol inputs from registration-domain PRF material.
  - Avoid NEAR profile lookups in protocol helpers.
- `client/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.ts`
  - Keep client-owned evaluator state and output mask material on the client
    side of wallet registration.
  - Expose wallet-registration orchestration only to the server-visible
    `clientRequestMessageB64u` and staged artifact envelope.
- `client/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.typecheck.ts`
  - Keep fixtures proving client-owned staged artifact construction requires
    `evaluatorOtStateB64u`, `serverInputDeliveryB64u`, and
    `clientOutputMaskB64u` inside the client worker boundary.
- `client/src/core/signingEngine/threshold/ecdsa/bootstrapSession.ts`
  - Keep ECDSA signing-session bootstrap for existing ECDSA key refs.
  - Move initial ECDSA registration HSS into the new registration ceremony caller.
- `client/src/core/signingEngine/threshold/ecdsa/keygen.ts`
  - Accept registration-domain ECDSA root-share material through typed protocol inputs.
  - Delete raw relay-bound root-share request shapes.
- `client/src/core/rpcClients/relayer/walletRegistration.ts`
  - Add registration intent, start, HSS respond, and finalize RPC helpers.
  - Keep ECDSA HSS transport details behind wallet registration RPC calls.
  - Remove `registration_continuation` route auth from registration traffic.
- `client/src/core/signingEngine/threshold/ecdsa/clientSecretSource.ts`
  - Split signing-session client-secret lookup from registration-domain PRF derivation.
  - Return narrow typed secret sources instead of optional lifecycle fields.
- `client/src/core/signingEngine/threshold/ecdsa/activation.ts`
  - Route activation through wallet-subject signer records instead of NEAR-account defaults.
- `client/src/core/signingEngine/threshold/sessionPolicy.ts`
  - Keep threshold signing-session policy construction scoped to signing/session routes.
  - Exclude signer-provisioning authority from threshold-session policy material.
- `client/src/core/signingEngine/session/passkey/ecdsaBootstrap.ts`
  - Keep warm-material cache writes for ECDSA signing-session bootstrap.
  - Keep `EcdsaBootstrapRequest` as a discriminated request union.
  - Remove initial-registration continuation-token assumptions.
- `client/src/core/signingEngine/session/passkey/ecdsaSessionProvision.ts`
  - Build signing-session bootstrap requests from wallet signer refs through branch-specific request types.
  - Keep registration ceremony requests in wallet registration RPC helpers.
- `client/src/core/signingEngine/session/warmCapabilities/ecdsaProvisionPlan.ts`
  - Keep ECDSA signing-session provision plans discriminated by passkey, Email OTP, threshold-session auth reconnect, or cookie reconnect.
  - Add registration/add-signer-facing builders only when they return exact branch types with required lifecycle fields.
- `client/src/core/signingEngine/session/warmCapabilities/ecdsaBootstrapPersistence.ts`
  - Persist ECDSA warm-session material against wallet-subject signer refs.
- `client/src/core/signingEngine/session/passkey/ecdsaProvisioner.ts`
  - Provision ECDSA warm sessions from existing signer records after registration.
  - Avoid creating signer records from warm-session provisioning.
  - Consume exact ECDSA activation records that carry
    `EvmFamilyEcdsaWalletKey`; do not accept target-only registration intent
    in exact-session activation code.
- `client/src/core/signingEngine/session/passkey/unlockEcdsaWarmupPlanner.ts`
  - Add a pure ECDSA unlock planner that accepts normalized signer records,
    configured targets, local records, current session facts, and runtime config.
  - Return closed lifecycle states for no configured targets, ready plans,
    authenticated inventory fetches, and blocked plans.
- `client/src/core/signingEngine/session/passkey/ecdsaKeyFactsInventory.ts`
  - Add wallet-subject repair inventory RPC and parser helpers.
  - Require WebAuthn assertion or app-session inventory policy inputs.
  - Return `EvmFamilyEcdsaWalletKey` records keyed by concrete chain target.
- `client/src/core/signingEngine/session/passkey/ed25519Provisioner.ts`
  - Provision Ed25519 warm sessions from existing signer records after registration.
- `client/src/core/signingEngine/session/passkey/ed25519SessionProvision.ts`
  - Keep Ed25519 signing-session provisioning separate from Ed25519 signer creation.
- `client/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity.ts`
  - Build `EvmFamilyEcdsaWalletKey` only from a valid `keyHandle` plus
    `EcdsaKeyFacts`.
  - Keep direct `keyHandle` projection at transport boundaries.
  - Add a guard that prevents `ecdsaThresholdKeyId`, `signingRootId`, or
    `signingRootVersion` construction from `keyHandle`.
- `client/src/core/signingEngine/webauthnAuth/credentials/credentialExtensions.ts`
  - Parse WebAuthn PRF extension output once at the boundary.
  - Return precise registration PRF root types to registration orchestration.
- `client/src/core/signingEngine/stepUpConfirmation/intentDigestPreparation.ts`
  - Add canonical registration and add-signer intent digest preparation.
  - Share digest preparation with passkey confirmation flows.
- `client/src/core/WalletIframe/client/router.ts`
  - Add iframe route messages for `registerWallet` and `addWalletSigner`.
  - Keep `registerPasskey` as a passkey wallet wrapper route and let
    per-call/default signer options decide Ed25519-only versus combined
    Ed25519+ECDSA registration.
- `client/src/core/WalletIframe/shared/messages.ts`
  - Add wallet-subject registration and add-signer message contracts.
- `client/src/core/WalletIframe/host/wallet-iframe-handlers.ts`
  - Wire wallet iframe handlers to the new SDK registration methods.
- `client/src/core/rpcClients/relayer/thresholdEcdsa.ts`
  - Remove `{ kind: 'registration_continuation' }` from `ThresholdEcdsaHssRouteAuth`.
  - Add wallet registration RPC helpers or move them into a new `walletRegistration.ts` client.
- `client/src/core/signingEngine/uiConfirm/handlers/flows/requestRegistrationCredentialConfirmation.ts`
  - Accept a canonical registration intent instead of only `nearAccountId` and `signerSlot`.
  - Remove NEAR RPC URL, NEAR account nonce reservation, and mutable signer-slot
    retry data from the core registration confirmation request.
- `client/src/core/signingEngine/uiConfirm/handlers/flows/registration.ts`
  - Compute the WebAuthn `create()` challenge from `RegistrationIntentV1`.
  - Preserve duplicate-credential retry only for signer selections where a
    retry is valid, and require a fresh `/wallets/register/intent` response
    before a retry prompt.
- `client/src/utils/intentDigest.ts`
  - Add canonical digest helpers for `RegistrationIntentV1` and add-signer intents.
- `client/src/core/signingEngine/interfaces/ecdsaChainTarget.ts`
  - Keep `WalletSubjectId` as the protocol-neutral subject id type.
  - Remove helper usage that derives the subject id from a NEAR account during ECDSA-only registration.
- `client/src/index.ts` and `client/src/react/index.ts`
  - Export the new registration types and APIs.
- `client/src/react/types.ts`
  - Add React-facing registration types for wallet-subject registration.
- `client/src/react/context/useSeamsContextValue.ts`
  - Wire the new registration methods through the React context.
- `client/src/react/context/useSeamsWithSdkFlow.ts`
  - Start SDK flow tracking from wallet subject id or requested NEAR account id depending on signer selection.

Tests to edit or add:

- `tests/unit/thresholdEcdsa.hssBootstrapPolicy.unit.test.ts`
  - Replace fake object-shaped WebAuthn acceptance with verified add-signer auth tests.
- `tests/relayer/threshold-ecdsa.signature-harness.test.ts`
  - Remove fake registration WebAuthn proof usage from registration bootstrap tests.
- `tests/relayer/relay-api-keys.test.ts`
  - Update registration route scope and metering coverage for `/wallets/register/*`.
- `tests/relayer/bootstrap-grants.test.ts`
  - Update grant targets and allowed route paths.
- `tests/unit/relayApiKeyRegistration.unit.test.ts`
  - Update client transport tests for the new registration endpoints.
- `tests/unit/configs.registrationTransport.test.ts`
  - Rename config expectations away from `/registration/bootstrap`.
- `tests/e2e/thresholdEd25519.bootstrapIntegrity.test.ts`
  - Move tamper checks to the new registration ceremony response.
- `server/src/core/thresholdEd25519HssRoleSeparated.typecheck.ts`
  - Add wallet-registration fixtures proving server request types reject
    client-retained HSS state and secret material.
- `client/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.typecheck.ts`
  - Add wallet-registration fixtures proving client-owned evaluation requires
    evaluator OT state, server input delivery, and client output mask locally.
- `tests/unit/thresholdEcdsa.registrationBootstrapParity.unit.test.ts`
  - Replace registration continuation parity assertions with wallet registration ceremony parity.
- `tests/unit/thresholdEcdsa.bootstrapPersistence.unit.test.ts`
  - Update ECDSA bootstrap persistence around wallet-subject signer refs.
- `tests/unit/warmSessionEcdsaProvisioning.unit.test.ts`
  - Ensure warm-session provisioning consumes existing ECDSA signer records.
- `tests/unit/passkeyLoginMenu.thresholdProvision.unit.test.ts`
  - Update login provisioning expectations for wallet-subject signer records.
- `tests/unit/seamsPasskey.loginThresholdWarm.unit.test.ts`
  - Add independent unlock coverage for Ed25519-only, ECDSA-only, and combined
    unlock.
  - Add ECDSA key-facts inventory parser rejection tests.
  - Add mutation-ordering tests that blocked ECDSA plans do not clear volatile
    warm material.
  - Add coverage that active ECDSA signer records require
    `EvmFamilyEcdsaWalletKey`.
- `client/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity.typecheck.ts`
  - Add type fixtures that reject `keyHandle` as `ecdsaThresholdKeyId`,
    `signingRootId`, or `signingRootVersion`.
  - Add fixtures that reject exact activation without
    `EvmFamilyEcdsaWalletKey`.
- `tests/unit/signingEngine.refactor33.guard.unit.test.ts`
  - Keep deleted import paths and import-direction checks aligned with the new registration modules.
- `tests/unit/signingEngine.refactor36.guard.unit.test.ts`
  - Add registration and add-signer lifecycle plan coverage if new signer-provisioning builders are introduced.
- `tests/unit/sealedRecovery.methodAdapters.unit.test.ts`
  - Keep passkey and Email OTP sealed recovery method adapters separate after registration starts persisting wallet-subject signer records.
- Add new registration mode tests covering `ed25519_only`, `ecdsa_only`, and `ed25519_and_ecdsa`.

## Implementation Phases

Next high-impact implementation sequence:

- [x] Add ECDSA ceremony state to `RegistrationCeremonyStore` and
      `WalletRegistrationStartResponse`.
- [x] Wire server ECDSA registration start/respond/finalize through the existing
      role-local ECDSA HSS primitives.
  - [x] ECDSA-only server ceremonies prepare role-local bootstrap identity,
        respond through `ecdsaHssRoleLocalBootstrap`, and finalize complete
        wallet-key facts for every requested EVM-family chain target.
  - [x] Combined Ed25519+ECDSA server ceremonies hold both signer-family
        lifecycle branches, respond to both HSS transcripts, and finalize both
        Ed25519 material and complete per-target ECDSA wallet-key facts.
- [x] Return complete `EvmFamilyEcdsaWalletKey` facts from finalize and persist
      them as wallet-subject signer records before marking ECDSA signers active.
- [x] Route client ECDSA-only and combined registration through
      `threshold/ecdsa/*` from `registerWallet`.
  - [x] ECDSA-only `registerWallet` uses the wallet-registration ECDSA HSS
        branch and persists finalized wallet-key facts.
  - [x] Combined `registerWallet` uses one wallet-registration ceremony,
        responds with both Ed25519 and ECDSA HSS messages, finalizes both
        families, and persists returned ECDSA signer records after the
        Ed25519 wallet-subject registration write.
- [x] Delete continuation-token registration paths once ECDSA registration and
      add-signer creation no longer depend on them.

Current next steps:

1. Define and wire the replacement role-local ECDSA ceremony for Email Recovery.
   Link Device now has role-local prepare/respond wiring and local wallet-key
   persistence. Email Recovery still needs a staged owner-binding contract so
   the recovery email is built only after ECDSA finalization returns the new
   EVM owner address.
2. Delete `/registration/bootstrap` and `/registration/threshold-ed25519/hss/*`
   after the remaining wrapper/harness callers use `/wallets/register/*`.
3. Add SDK app-session add-signer orchestration after a non-passkey ECDSA
   client-root source is defined; the current ECDSA add-signer SDK path
   intentionally requires WebAuthn PRF output.
4. Add an SDK helper for constructing `NearAccountOwnershipProof` if product
   wants the SDK to own existing-account proof creation rather than requiring a
   caller-supplied proof object.
5. Keep authenticated ECDSA key-facts inventory in the explicit
   repair/recovery lane only. It is the strict API for exceptional recovery of
   missing local key facts; normal registration/add-signer finalization must
   write complete `EvmFamilyEcdsaWalletKey` facts and normal unlock must consume
   local complete records.

### Phase 0: Current Flow Cutover Prep

- [x] Add explicit route and RPC replacement notes to the implementation PR so
      reviewers can verify every old registration caller has a new
      `/wallets/register/*` caller.
  - [x] Replacement map for review:
        `client/src/core/rpcClients/relayer/walletRegistration.ts` owns
        `POST /wallets/register/intent`, `POST /wallets/register/start`,
        `POST /wallets/register/hss/respond`, and
        `POST /wallets/register/finalize`.
  - [x] Express and Cloudflare registration route modules are
        `server/src/router/express/routes/walletRegistration.ts` and
        `server/src/router/cloudflare/routes/walletRegistration.ts`; they are
        wired from `createRelayRouter.ts`, `createCloudflareRouter.ts`, and
        `server/src/router/routeDefinitions.ts`.
  - [x] Cutover scope: replace normal `registerPasskeyInternal` registration
        traffic in `client/src/core/SeamsPasskey/registration.ts` with the
        wallet-registration RPC helper. Then delete the legacy initial
        registration use of `/registration/bootstrap`,
        `registrationContinuation`, and `registration_continuation` from
        production code. Remaining uses after cutover should be explicit
        compatibility tests or removed harness fixtures.
- [x] Create the new Express and Cloudflare wallet-registration route modules
      before editing the old registration wrappers.
- [x] Create `client/src/core/rpcClients/relayer/walletRegistration.ts` before
      changing `registerPasskeyInternal`.
- [x] Extract reusable server helpers from `AuthService.createAccountAndRegisterUser`
      behind wallet-subject service methods:
      WebAuthn `create()` verification, NEAR account provisioning,
      authenticator binding writes, and immediate Ed25519 session minting.
- [x] Extract reusable Ed25519 HSS protocol mechanics without preserving the
      legacy registration HSS public routes.
- [x] Split client Ed25519 HSS protocol mechanics from legacy relay calls in
      `thresholdWarmSessionBootstrap.ts`.
  - [x] Extract relay-neutral client helpers:
        `prepareThresholdEd25519RegistrationHssClientMaterial()`,
        `prepareThresholdEd25519RegistrationHssClientRequest()`, and
        `buildThresholdEd25519RegistrationHssClientOwnedArtifact()`. Legacy
        registration and wallet registration now share those helpers, while
        `/registration/*` relay calls and `/wallets/register/*` RPC calls stay
        at their respective orchestration boundaries.
- [x] Add type fixtures for invalid registration intent construction before
      broad registration orchestration edits begin.
- [x] Add role-separated Ed25519 HSS fixtures before moving registration routes:
      server-visible request messages, client-owned staged artifacts, and
      rejected evaluator OT/client-secret fields.
- [x] Confirm the implementation branch contains no feature flag, fallback
      route, or compatibility shim that keeps continuation-token registration
      as a second initial-registration path.
  - Production `client/src`, `server/src`, and `shared/src` no longer contain
    `registrationContinuation`, `registration_continuation`,
    `parseRegistrationContinuationClaims`, or `signRegistrationContinuationJwt`
    outside type fixtures and tests. Remaining generic threshold
    "continuation" route text refers to signing/cosign protocol continuations,
    not registration continuation tokens.

### Phase 1: Types And Boundaries

- [x] Add wallet subject, authenticator binding, signer selection, and ceremony state types in `server/src/core/types.ts` and `client/src/core/SeamsPasskey/interfaces.ts`.
- [x] Add `CreateRegistrationIntentRequest`,
      `CreateRegistrationIntentResponse`, `RegistrationIntentGrant`, and
      grant-claim types.
- [x] Add explicit `EcdsaKeyFacts`, `EvmFamilyEcdsaWalletKey`, and
      `EcdsaWalletSignerRecord` types.
  - [x] `evmFamilyEcdsaIdentity.ts` now exports the named wallet-key facts,
        complete wallet-key, and wallet-signer-record domain shapes. The
        typecheck fixture rejects signer records that try to carry loose
        `keyHandle` fields outside the complete wallet key.
- [x] Add `RegistrationCeremonyStore` state unions for intent allocation,
      started ceremonies, HSS-responded ceremonies, finalizing ceremonies,
      completed ceremonies, and failed ceremonies.
  - [x] `RegistrationCeremonyStore.ts` now models intent allocation,
        consumed-intent handoff, failed intents, Ed25519 prepared/responded,
        Ed25519 finalizing/completed, and failed registration ceremony states
        as explicit discriminated branches.
  - [x] Add Ed25519 prepared/responded ceremony states and type fixtures that
        reject prepared states carrying response data or responded states
        missing response delivery.
  - [x] Extend the type fixture to reject consumed timestamps on allocated
        intents, failed intents without structured failure data, finalizing
        Ed25519 states without `finalizingAtMs`, completed Ed25519 states
        without `walletSubjectId`, and failed ceremony states that still carry
        server HSS ceremony handles.
  - [x] Add ECDSA prepared/responded/completed ceremony branches and type
        fixtures that require complete wallet-key facts before an ECDSA
        ceremony can be represented as completed.
- [x] Add `WalletKeyFactsInventoryAuth` and
      `EcdsaKeyFactsInventoryPolicy` types.
- [x] Remove ECDSA subject fields from registration, signer-record, unlock,
      warm-up, and persistence-domain types; use `walletSubjectId` as the
      single subject identifier.
  - [x] `EvmFamilyEcdsaWalletKey`, `EcdsaWalletSignerRecord`, unlock planner
        records, and activation requests carry wallet identity and canonical
        key facts through `walletKey`; raw threshold `subjectId` remains only
        at the threshold-protocol/server-key boundary where the ECDSA HSS
        record requires it.
- [x] Split raw `keyHandle` boundary parsing from ECDSA `keyFacts` parsing.
  - [x] Profile-continuity and authenticated inventory parsers treat bare
        `keyHandle` as boundary input only. Complete records become
        `EvmFamilyEcdsaWalletKey`; key-handle-only rows become explicit
        `repair_required`; synthetic or ambiguous handles are blocked before
        core warm-up planning.
- [x] Make core resolved active-key flows consume `EvmFamilyEcdsaWalletKey`;
      delete loose `keyHandle` and peer-field `keyFacts` inputs.
  - [x] Unlock warm-up, active signer parsing, provision planning, and ECDSA
        activation now consume `walletKey`/lane-policy inputs. Type fixtures
        reject loose `keyHandle`, direct `ecdsaThresholdKeyId`, and broad
        identity projections in core state.
- [x] Add raw request normalizers for registration intent, wallet registration,
      add-signer, and ECDSA key-facts inventory flows.
  - [x] Registration intent and Ed25519 wallet-registration request boundaries.
  - [x] Route-level Ed25519 wallet-registration HSS respond/finalize parsers
        construct narrow server-visible request objects before calling
        `AuthService`.
  - [x] Route-level ECDSA wallet-registration HSS respond/finalize parsers
        allow ECDSA-only and combined ceremony messages, reject
        root-proof/passkey-bootstrap authorization fields, and forward only
        normalized ceremony-owned bootstrap/finalize inputs.
  - [x] Route-level ECDSA key-facts inventory parser requires app-session
        inventory policy, rejects threshold-session auth, and forwards only
        normalized wallet subject, RP ID, and key target inputs.
  - [x] Route-level add-signer start/respond/finalize parsers verify
        intent-digest binding, app-session/WebAuthn authorization shape, HSS
        branch shape, and expected ECDSA key handles before calling
        `AuthService`.
- [x] Add wallet-registration Ed25519 HSS request unions that distinguish
      `server_visible_client_request`, `server_input_delivery`, and
      `client_owned_staged_artifact`.
- [x] Add `never` exclusions to those unions for evaluator OT state, client
      input shares, PRF fields, output masks, raw client output, seed output,
      and client-secret fields at server boundaries.
- [x] Add canonical `RegistrationIntentV1` and add-signer digest helpers in `client/src/utils/intentDigest.ts`.
  - [x] `RegistrationIntentV1` digest helper.
  - [x] `AddSignerIntentV1` digest helper.
  - [x] Shared add-signer intent types distinguish Ed25519 account creation,
        Ed25519 existing-account linking, and ECDSA signer creation. Type
        fixtures reject Ed25519/ECDSA branch mixing and require an account-proof
        digest for existing-account Ed25519 attachment.
  - [x] Digest tests verify shared/client helper parity and bind signer family,
        participant order, target account, and runtime policy scope.
- [x] Add server-side digest verification helpers for the same intent encodings.
- [x] Add architecture guards against optional lifecycle signer fields in registration core types.
  - [x] Compile-time fixtures cover invalid intent, ceremony, and signer-state
        combinations without adding repo-wide string-scan guard bloat.
- [x] Add architecture guards that reject `ecdsaThresholdKeyId`,
      `signingRootId`, or `signingRootVersion` derivation from `keyHandle`.
  - [x] Compile-time fixtures and focused parser tests require complete key
        facts for canonical wallet keys, reject broad key-handle projections in
        core identity/session state, and block synthetic legacy handles at the
        inventory/profile boundary.
- [x] Add client lifecycle-plan builders for any registration/add-signer path that creates warm-session or signer-provisioning material.
  - [x] ECDSA activation paths now use branch-specific builders for passkey
        enrollment/reconnect, Email OTP session/per-operation auth,
        threshold-session reconnect, cookie reconnect, and export. Type
        fixtures reject activation without `EvmFamilyEcdsaWalletKey`, exact
        activation with wallet/profile identity fields, and mixed auth
        branches.
- [x] Keep registration client imports aligned with `docs/refactor-33.md`; avoid resurrecting deleted `threshold/workflows/*`, `threshold/session/*`, `api/*`, or `orchestration/*` paths.
  - [x] Covered by existing refactor-33 deleted-path guardrails; no new
        registration-specific string scan added.
- [x] Keep session ownership aligned with `docs/refactor-35-sealed-recovery.md`; use `session/passkey/*`, `session/emailOtp/*`, `session/warmCapabilities/*`, and `session/operationState/*` according to owner.
  - [x] Existing session ownership guardrails cover the deleted path families.
- [x] Keep lifecycle input types aligned with `docs/refactor-36.md`; use branch-specific required fields and `never` exclusions for invalid auth combinations.
  - [x] Compile-time fixtures reject invalid registration and add-signer branch
        combinations.
- [x] Update exports in `client/src/index.ts`, `client/src/react/index.ts`, and `client/src/react/types.ts`.

### Phase 2: Server Ceremony

Current status: Ed25519-only, ECDSA-only, and combined Ed25519+ECDSA
registration use the unified server ceremony. Intent/ceremony state has memory,
Postgres, and Cloudflare Durable Object-backed persistence. ECDSA finalization
returns complete per-target wallet-key facts. Durable wallet subject,
authenticator, and signer-record tables now exist. Finalize now commits
WebAuthn authenticator rows, credential bindings, wallet-subject rows,
wallet-authenticator rows, and signer rows in the same Postgres transaction
that consumes the registration or add-signer ceremony.

- [x] Add `/wallets/register/intent`, `/wallets/register/start`,
      `/wallets/register/hss/respond`, and `/wallets/register/finalize` route
      definitions in `server/src/router/routeDefinitions.ts`.
- [x] Add Express and Cloudflare route modules for the new registration ceremony.
- [x] Add `RegistrationCeremonyStore` implementations.
  - [x] Memory store for tests and local single-process development.
  - [x] Postgres store for Express production.
  - [x] Wire `AuthService` to select the durable Postgres store through the
        registration ceremony store factory when `thresholdStore` is backed by
        Postgres.
  - [x] Cloudflare Durable Object store for Worker production.
- [x] Add wallet-subject registration service methods in `server/src/core/AuthService.ts`.
- [x] Replace server registration bootstrap composition with wallet-subject
      services; keep NEAR account creation as an Ed25519 finalization side
      effect.
  - [x] New Ed25519 wallet-subject service path with NEAR account creation at finalize.
- [x] Add `/wallets/register/intent` service method.
  - [x] Resolve runtime policy scope from API key, bootstrap token, or managed
        grant context.
  - [x] Allocate or reserve `walletSubjectId`.
  - [x] Create and persist a one-use registration intent grant.
  - [x] Return `RegistrationIntentV1` and its canonical digest.
- [x] Make `/wallets/register/start` verify and consume the
      `registrationIntentGrant` before ceremony creation.
- [x] Keep unsupported signer modes from consuming the one-use intent grant
      before the corresponding ceremony support is wired.
- [x] Verify WebAuthn `create()` once, then store normalized signer selection on the ceremony record.
- [x] Prepare Ed25519 and ECDSA HSS state from the same verified registration context.
  - [x] Add server and client response/request types for the ECDSA role-local
        registration ceremony prepare/respond/finalize shape.
  - [x] Add ECDSA registration HSS route boundaries before wiring the
        `AuthService` ceremony state transitions.
  - [x] Add ECDSA-only `AuthService.startWalletRegistration` preparation that
        stores normalized chain targets and role-local HSS bootstrap identity
        in `RegistrationCeremonyStore`.
  - [x] Add combined `AuthService.startWalletRegistration` preparation that
        stores Ed25519 and ECDSA prepared branches under one ceremony id after
        one WebAuthn `create()` verification.
- [x] For Ed25519, store the wallet ceremony handle, intent, signer spec, and
      WebAuthn binding in `RegistrationCeremonyStore`; keep prepared server
      session handles, garbler driver state, relayer input shares, operation,
      and expected context binding behind the threshold-service HSS
      `ceremonyHandle`.
- [x] For Ed25519, return only client prepare material from `/wallets/register/start`:
      `preparedSession.contextBindingB64u`,
      `preparedSession.evaluatorDriverStateB64u`, and
      `clientOtOfferMessageB64u`.
- [x] Run independent Ed25519 and ECDSA HSS preparation concurrently where the runtime allows it.
  - [x] Combined registration starts server-side Ed25519 and ECDSA prepare
        work together after WebAuthn verification. The SDK also prepares the
        ECDSA client bootstrap and Ed25519 client request concurrently after
        `/wallets/register/start` returns both prepare branches.
- [x] Make `/wallets/register/hss/respond` use role-separated Ed25519 server
      input delivery and reject evaluator OT state at the request parser.
- [x] Clear raw Ed25519 relayer input shares from the ceremony record after
      server input delivery is prepared.
- [x] Finalize requested signer material and persist wallet subject, authenticator binding, and signer records.
  - [x] Ed25519 finalize path persists wallet subject authenticator and Ed25519 signer binding.
  - [x] Combined finalize returns Ed25519 key material and complete ECDSA
        wallet-key facts from one ceremony.
  - [x] Server finalize writes wallet-subject records through
        `WalletSubjectStore`: `wallet_subjects`, `wallet_authenticators`, and
        `wallet_signers` for registration; add-signer finalize writes the new
        Ed25519 or ECDSA signer rows without re-registering an authenticator.
- [x] Ensure Ed25519 HSS registration material is finalized inside
      `/wallets/register/finalize`; avoid pre-bootstrap persisted registration
      material.
- [x] Make Ed25519 finalize consume only the client-owned staged evaluator
      artifact and derive registration material from the role-separated
      finalized report plus server output.
- [x] Gate NEAR account creation behind Ed25519 signer finalization.
- [x] Persist ECDSA signer metadata without requiring a NEAR account or NEAR profile continuity.
  - ECDSA-only registration and ECDSA add-signer finalization now write
    per-target wallet-subject ECDSA signer rows keyed by concrete chain target.
- [x] Run exactly one ECDSA HSS keygen per `EcdsaRegistrationSpec`, then create
      one active signer record per requested `chainTarget` carrying the shared
      `EvmFamilyEcdsaWalletKey`.
  - [x] ECDSA-only server finalize derives one shared wallet-key fact set from
        the role-local bootstrap response and fans it out to every requested
        chain target.
  - [x] Combined server finalize derives one shared ECDSA wallet-key fact set
        and fans it out to every requested chain target while finalizing
        Ed25519 in the same ceremony.
  - [x] Persist the returned per-target ECDSA signer records in the
        wallet-subject signer store once that server-side store exists.
- [x] Make ECDSA registration/add-signer finalization produce a complete
      `EvmFamilyEcdsaWalletKey` for every requested chain target before any
      signer record is marked active.
  - [x] ECDSA-only wallet-registration finalize returns the exact `keyHandle`
        returned by the ECDSA key server.
  - [x] ECDSA-only wallet-registration finalize returns canonical
        `ecdsaThresholdKeyId`, `signingRootId`,
        `signingRootVersion`, threshold public key, owner address, and
        participant ids in each returned wallet-key fact object.
  - [x] Reject finalize if `keyHandle` or `keyFacts` are incomplete; return no
        wallet-key facts and do not write the authenticator or an active signer.
  - [x] Return the same complete wallet-key facts in the ECDSA-only finalize
        response.
  - [x] Return the same complete wallet-key facts in the combined registration
        finalize response.
- [x] Add Postgres schema changes in `server/src/storage/postgres.ts`.
  - [x] Add registration intent and registration ceremony tables.
  - [x] Add expiry indexes for registration intent and ceremony records.
  - [x] Add wallet subject, authenticator, and signer tables plus unique signer
        indexes.
    - `wallet_subjects`, `wallet_authenticators`, and `wallet_signers` now
      exist in the Postgres schema. `wallet_signers` has a unique
      wallet-subject signer target index for concrete chain-target signer rows.
  - [x] Ensure ceremony finalize consumes the ceremony atomically.
    - Registration and add-signer finalize now use one Postgres transaction to
      delete the ceremony row and write WebAuthn authenticator rows, credential
      bindings, wallet-subject records, wallet authenticators, and signer
      records. Non-Postgres stores keep their existing store-level writes.

### Phase 3: Client Flow

Current status: Ed25519-only, ECDSA-only, and combined Ed25519+ECDSA wallet
registration are wired through the new ceremony.

- [x] Add `registerWallet(args)` in `client/src/core/SeamsPasskey/index.ts`.
- [x] Replace NEAR-first orchestration in `client/src/core/SeamsPasskey/registration.ts`.
- [x] Replace `createAccountAndRegisterWithRelayServer` usage with
      wallet-registration RPC helpers.
- [x] Build signer selection from explicit user options.
- [x] Resolve `RegisterWalletSubjectInput` through `/wallets/register/intent`
      before collecting a WebAuthn credential.
- [x] Update WebAuthn confirmation to accept canonical registration intent inputs.
- [x] Remove NEAR RPC context, nonce reservation, and signer-slot mutation from
      registration WebAuthn confirmation.
  - [x] Add a registration prompt type fixture rejecting `rpcCall` on
        `RegisterAccountPayload`.
- [x] Compute WebAuthn `create()` challenge from the returned
      `RegistrationIntentV1` and verify local digest parity before prompting.
- [x] Allocate a fresh registration intent before any duplicate-credential
      retry that changes challenge-bound data.
  - Intent-bound wallet registration now fails fast on duplicate credential
        creation instead of retrying under the consumed
        `RegistrationIntentV1` digest. The lower-level signer-slot retry is
        limited to non-intent local prompts where the challenge is recomputed
        from the updated UI intent.
- [x] Derive Ed25519 and ECDSA PRF inputs with domain-separated labels.
  - Passkey-origin ECDSA HSS client roots now use HKDF-SHA256 over the
        passkey PRF output with
        `seams/passkey/threshold-ecdsa-client-root/v1`; registration,
        add-signer, Link Device, Email Recovery, login warm-up, and passkey
        ECDSA reconnect planning all route through the same helper. Ed25519 HSS
        continues to consume the existing Ed25519 PRF material at the
        Ed25519-specific protocol boundary.
- [x] Run selected Ed25519 signer HSS work inside the wallet registration
      ceremony.
- [x] Add ECDSA and combined signer HSS work to the wallet registration
      ceremony.
  - [x] ECDSA-only client registration runs start/respond/finalize through the
        wallet-registration ECDSA HSS branch.
  - [x] Combined client registration runs one WebAuthn `create()`, one
        `/wallets/register/start`, one combined HSS respond, and one finalize
        that includes both signer families.
- [x] Remove per-HSS-step managed grant calls from registration HSS helpers.
- [x] Keep Ed25519 `evaluatorOtStateB64u`, client input shares,
      `clientOutputMaskB64u`, PRF material, and opened client output inside
      the client worker/signing-engine boundary.
- [x] Send only `clientRequestMessageB64u` to `/wallets/register/hss/respond`
      for Ed25519.
- [x] Send only the client-owned staged evaluator artifact envelope to
      `/wallets/register/finalize` for Ed25519.
- [x] Route Ed25519 protocol work through `threshold/ed25519/*`.
- [x] Route ECDSA registration protocol work through `threshold/ecdsa/*`.
- [x] Keep Ed25519 warm-session persistence in `session/warmCapabilities/*`
      after signer records exist.
- [x] Keep passkey PRF handling and passkey-origin ECDSA registration
      provisioning in `session/passkey/*`.
  - [x] Generic WebAuthn extension parsing stays under `webauthnAuth`, while
        passkey-origin ECDSA root derivation is owned by
        `session/passkey/ecdsaClientRoot.ts`. Registration, add-signer, Link
        Device, Email Recovery, login warm-up, and passkey ECDSA reconnect
        planning all route through that helper.
- [x] Keep generic warm-capability read/status transitions in `session/warmCapabilities/*`.
- [x] Emit progress events for per-signer prepare/finalize states.
- [x] Persist returned signer refs under wallet subject identity.
  - [x] Ed25519 `registerWallet` persists a wallet-subject signer record and
        authenticator before writing the NEAR account projection.
  - [x] ECDSA registration finalization persists wallet-subject ECDSA
        signer records with complete wallet-key facts.
- [x] Persist NEAR profile projection only after wallet-subject records exist
      and an Ed25519 registration result is present.
  - [x] Ed25519 `registerWallet` writes the NEAR projection after
        wallet-subject persistence succeeds.
  - [x] Combined `registerWallet` writes Ed25519 wallet-subject registration
        data first, then persists ECDSA wallet-subject signer records without
        re-registering the authenticator.
- [x] Ensure ECDSA-only registration never reads or writes NEAR profile
      continuity.
- [x] Persist complete returned `EvmFamilyEcdsaWalletKey` objects into
      wallet-subject signer records and any profile projection consumed by
      unlock.
- [x] Add client write-time invariants that reject active ECDSA signer records
      missing `keyHandle`, required `keyFacts`, public facts, owner address,
      participant ids, or concrete `chainTarget`.
  - `storeWalletSubjectEcdsaSignerRecords()` now requires finalized
        server-returned `walletKeys`, rejects empty key handles, signer ids,
        signing-root facts, public keys, relayer shares, owner addresses,
        participant ids, and concrete chain targets before activating any local
        signer row.
- [x] Remove registration/finalize client code that writes only target intent,
      `ecdsaThresholdKeyId`, signing root facts, or key refs without the
      resolved server selector.
  - ECDSA-only, combined registration, and later ECDSA add-signer all persist
        only `finalized.ecdsa.walletKeys`; expected key handles are used solely
        as finalize assertions and are no longer sufficient for local active
        signer writes.
- [x] Wire React context and SDK flow tracking to the new registration API.
- [x] Wire WalletIframe message contracts and handlers to `registerWallet` and `addWalletSigner`.
  - [x] `registerWallet` message contract, router method, and host handler.
  - [x] `addWalletSigner` message contract, router method, iframe facade, and
        host handler.

### Phase 4: Independent Wallet Unlock

- [x] Add signer-selection unlock input types for Ed25519-only, ECDSA-only, and
      combined unlock.
- [x] Let ECDSA-only unlock proceed without a NEAR/Ed25519 operational key.
  - Account lookup now normalizes the login subject into either
    `near_operational_signer` or `ecdsa_wallet_only`.
  - Ed25519 and combined unlock still fail before warm-up when the NEAR
    operational key is absent; ECDSA-only unlock returns
    `operationalPublicKey: null`.
- [x] Extract wallet-unlock ECDSA planning from `login.ts` into a pure planner
      module.
  - [x] Create an `unlockEcdsaWarmupPlanner.ts` boundary that accepts only
        normalized ECDSA signer records, configured ECDSA targets, local ECDSA
        session records, current session facts, and runtime config.
  - [x] Make the planner return a closed discriminated union:
        `no_configured_ecdsa_targets`, `ready`,
        `awaiting_authenticated_key_facts_inventory`, `repair_required`, and
        `blocked`.
  - [x] Delete Ed25519-specific inventory-state naming. The state is about
        missing authenticated ECDSA key facts, so active docs use
        `awaiting_authenticated_key_facts_inventory`.
  - [x] Keep `blocked` branch reasons explicit:
        `missing_key_handle`, `ambiguous_key_handle`,
        `missing_chain_target`, `synthetic_legacy_key_id`,
        `missing_key_facts`, and `invalid_signer_record`.
  - [x] Keep the normal active-signer unlock path local-only. If all active
        signer records contain complete `EvmFamilyEcdsaWalletKey` facts, the
        planner must return `ready` without calling
        `/threshold-ecdsa/key-identities`.
  - [x] Use `awaiting_authenticated_key_facts_inventory` only when the user
        selected an explicit repair/recovery mode or the caller supplied a
        policy that permits ECDSA key-facts inventory reads.
  - [x] Move configured-target shared-key completion into the planner module so
        `login.ts` consumes a closed completion result instead of owning target
        planning.
- [x] Normalize active ECDSA signer metadata once at the signer-record/profile
      boundary.
  - [x] Add a parser that converts raw profile signer metadata into
        `ActiveEcdsaSignerRecord` or a blocked signer-record reason.
  - [x] Require active ECDSA signers to carry exact
        `EvmFamilyEcdsaWalletKey` and concrete `chainTarget`.
  - [x] Treat missing direct `keyHandle` as invalid after registration/add-signer
        finalize writes complete wallet keys.
  - [x] Accept `EcdsaKeyFacts` only when all required facts are present;
        otherwise emit a closed repair-required or blocked reason without
        partial objects.
  - [x] Reject active signer records that require deriving `keyHandle` from
        `keyFacts`. Use explicit data pruning or one-shot
        maintenance outside login for current development rows.
  - [x] Remove direct reads of raw `metadata` bags from the unlock hot path.
- [x] Split unlock/login execution into typed phases.
  - [x] Phase 1: read and normalize wallet subject, authenticator, and signer
        records.
    - [x] Wallet-subject normalization distinguishes NEAR operational signer
          unlock from ECDSA-wallet-only unlock.
    - Account/authenticator lookup now returns a typed
      `LoginUnlockAccountPhase` before passkey prompting or warm-session
      mutation.
  - [x] Phase 2: build independent Ed25519 and ECDSA unlock plans from
        `WalletUnlockSelection`.
    - `LoginHooksOptions.unlockSelection` now accepts Ed25519-only, ECDSA-only,
      and combined unlock selection. The warm-up path maps that selection into
      requested signer-family work before reading Ed25519 key material or
      planning ECDSA targets.
  - [x] Phase 3: preflight ECDSA blocked states before mutating volatile
        session material.
    - Blocked, ambiguous, and missing-key-facts states are resolved before
      `clearVolatileWarmSigningMaterial` runs.
  - [x] Phase 4: acquire wallet/authenticator auth only for plans that require
        authenticated key-facts inventory.
    - Explicit WebAuthn repair now derives the inventory challenge from the
      planner's preflighted `keyTargets`, prompts only after
      `awaiting_authenticated_key_facts_inventory`, and reuses that assertion's
      PRF result for ECDSA warm-up.
  - [x] Phase 5: resolve deferred ECDSA inventory only for explicit
        repair/recovery plans using the preflighted key-target request list.
    - Explicit app-session repair now calls
      `/wallets/:walletSubjectId/signers/ecdsa/key-facts/inventory` only after
      the planner returns `awaiting_authenticated_key_facts_inventory`, using
      the planner's preflighted `keyTargets` and a bounded
      `ecdsa_key_facts_inventory` policy.
  - [x] Phase 6: clear volatile warm material only after requested signer-family
        plans are ready or conclusively absent.
    - The unlock path now selects requested signer families and validates the
      ECDSA completion state before clearing volatile warm material.
  - [x] Phase 7: provision requested Ed25519 and ECDSA signing sessions from
        their independent ready plans.
    - Ed25519-only unlock skips ECDSA bootstrap even when ECDSA chains are
      configured.
    - ECDSA-only unlock can warm exact ECDSA sessions from complete local
      `EvmFamilyEcdsaWalletKey` facts using a fresh passkey PRF, without
      connecting an Ed25519 signing session.
  - [x] Make each phase consume the prior phase's narrow union instead of the
        broad login context.
    - Warm-session provisioning now consumes a typed
      `ThresholdLoginWarmupPlan` with closed ECDSA completion and signer-family
      selection fields.
    - Warm-session execution now returns `ThresholdLoginWarmupPhaseResult`, so
      the unlock result consumes an explicit active signing-session outcome
      rather than relying only on ambient login-context mutation.
    - Warm-session execution now starts from `ThresholdLoginWarmupPhaseInput`,
      which owns relayer URL, rpId, signer-family selection, configured ECDSA
      targets, repair authority, and session-exchange authorization before the
      phase reads key material or mutates warm-session state.
- [x] Move the ECDSA key-facts inventory parser out of `login.ts`.
  - [x] Parser now lives in
        `client/src/core/signingEngine/session/passkey/ecdsaKeyFactsInventory.ts`;
        `login.ts` consumes parsed entries only for inventory responses.
  - [x] Create a boundary parser for
        `/wallets/:walletSubjectId/signers/ecdsa/key-facts/inventory`
        responses.
  - [x] Require `keyHandle`, concrete `chainTarget`,
        `ecdsaThresholdKeyId`, `signingRootId`, `signingRootVersion`,
        participant ids, and owner address.
  - [x] Require public facts on parsed inventory entries before the planner
        consumes them as active wallet keys.
  - [x] Reject synthetic legacy ids at the parser boundary.
  - [x] Reject missing key handles, mismatched wallet ids, mismatched rp ids, and
        owner-address drift at the parser boundary.
  - [x] Return exact `EvmFamilyEcdsaWalletKey` entries keyed by concrete
        target; downstream unlock logic must not inspect raw response records.
  - [x] Move profile-continuity ECDSA signer metadata parsing into the same
        key-facts boundary module so `login.ts` consumes normalized warm-key
        parse results.
- [x] Tighten lifecycle request state around ECDSA signing-session operation
      selection.
  - [x] Split ECDSA registration/add-signer requests from ECDSA exact-session
        warm-up requests at the type level.
    - [x] Existing-key activation builders now require the exact wallet-key
          branch instead of separate key-handle and key-identity projections.
    - [x] New-key ECDSA enrollment now projects to
          `key_enrollment_bootstrap`; exact wallet-key warm-up remains the only
          branch that projects to `session_bootstrap`.
  - [x] Make exact-session warm-up consume a branch with
        `EvmFamilyEcdsaWalletKey` and lane policy already resolved.
  - [x] Encode server operation from lifecycle state:
        registration/add-signer branches emit registration ceremony operations;
        existing-key activation and recovery branches emit `session_bootstrap`.
    - [x] Existing-key activation and reconnect builders project to
          `session_bootstrap` at the bootstrap boundary.
    - [x] New-key registration, add-signer, and first-bootstrap preparation no
          longer emit the generic `registration_bootstrap` operation label.
  - [x] Keep auth proof envelopes inside the selected lifecycle branch.
  - [x] Remove optional fields that permit exact activation to degrade into
        target-based registration.

### Phase 5: Add-Signer Flow

Current status: Phase 5 now has route contracts, transport dispatch, low-level
client RPC helpers, add-signer auth-boundary normalization, stored add-signer
ceremony state, ECDSA add-signer AuthService start/respond/finalize wiring, and
Ed25519 `create_near_account` add-signer AuthService start/respond/finalize
wiring through the role-separated registration HSS mechanics. Client IndexedDB
persistence is in place for finalized ECDSA add-signer wallet-key facts. The
server now issues add-signer intents with grants; start consumes the grant
before preparing HSS so WebAuthn challenges use server-issued nonces. The SDK
`addWalletSigner(args)` orchestration supports ECDSA and Ed25519 WebAuthn
add-signer paths and persists finalized signer material without writing a new
authenticator. Ed25519 existing-account linking now carries a full
`NearAccountOwnershipProof` in the add-signer intent; the server verifies that
proof against the active NEAR access key before consuming the add-signer grant.
Focused SDK orchestration tests cover later ECDSA from an Ed25519 wallet and
later Ed25519 from an ECDSA wallet over the `addWalletSigner(args)` WebAuthn
paths.

Deferred follow-ups:

1. Add SDK app-session add-signer orchestration after a non-passkey ECDSA
   client-root source is defined; the current ECDSA add-signer SDK path
   intentionally requires WebAuthn PRF output.
2. Add an SDK helper for constructing `NearAccountOwnershipProof` if product
   wants the SDK to own existing-account proof creation rather than requiring a
   caller-supplied proof object.
3. Continue Phase 6 cleanup only after the remaining registration-continuation
   callers have been replaced by wallet-registration or add-signer ceremonies.

- [x] Add `/wallets/:walletSubjectId/signers/start`, `/wallets/:walletSubjectId/signers/hss/respond`, and `/wallets/:walletSubjectId/signers/finalize`.
  - [x] Add route definitions and Express/Cloudflare dispatch for all three
        routes.
  - [x] Add low-level relayer RPC helpers:
        `startWalletAddSigner`, `respondWalletAddSignerHss`, and
        `finalizeWalletAddSigner`.
  - [x] Implement stored add-signer ceremony state behind the routes.
  - [x] Wire ECDSA add-signer HSS preparation, response, and finalization through
        `AuthService` using the existing role-local ECDSA HSS primitive.
  - [x] Extend the Ed25519 add-signer spec with required key-purpose,
        key-version, and derivation-version fields.
  - [x] Wire Ed25519 `create_near_account` add-signer HSS preparation, response,
        and finalization through `AuthService` using the role-separated
        registration HSS primitive.
  - [x] Wire Ed25519 `link_existing_near_account` through a required
        `NearAccountOwnershipProof` object; start verifies the proof against the
        active NEAR access key before grant consumption.
- [x] Add verified add-signer auth boundary before add-signer service dispatch.
  - [x] Route boundary normalizes `webauthn_assertion` and `app_session`
        add-signer auth into closed `AddSignerAuth` branches before service
        dispatch.
- [x] Verify WebAuthn `get()` against a server-issued add-signer challenge.
  - [x] Route boundary verifies WebAuthn `get()` against the canonical
        `AddSignerIntentV1` digest and rejects digest mismatch before verifier
        use.
  - [x] Add the server-side add-signer intent/nonce issuer so the challenge nonce
        is server-issued before WebAuthn collection.
    - `/wallets/:walletSubjectId/signers/intent` returns `AddSignerIntentV1`,
      `addSignerIntentDigestB64u`, `addSignerIntentGrant`, and expiry.
    - `/wallets/:walletSubjectId/signers/start` requires
      `addSignerIntentGrant` and consumes the stored grant before preparing the
      add-signer HSS ceremony.
- [x] Enforce app-session signer-provisioning policy for app-session add-signer flows.
  - The route boundary requires `wallet_signer_provision`, matching
    wallet-subject id, exact signer selection, and unexpired app-session claims
    before service dispatch.
- [x] Reject threshold-session auth tokens for signer creation.
- [x] Complete client `addWalletSigner(args)` coverage for the supported
      passkey/WebAuthn client-root paths.
  - [x] Add low-level client RPC helpers for the three add-signer endpoints.
  - [x] Add SDK orchestration for the ECDSA WebAuthn path: call
        `/wallets/:walletSubjectId/signers/intent`, collect WebAuthn assertion
        with the returned digest, derive the ECDSA HSS client bootstrap from
        assertion PRF output, respond, finalize, and persist returned signer
        records.
  - [x] Add SDK orchestration for the Ed25519 WebAuthn path: call
        `/wallets/:walletSubjectId/signers/intent`, collect WebAuthn assertion
        with the returned digest, derive Ed25519 HSS client material from the
        assertion PRF output, respond, finalize, persist returned signer
        material, and warm the returned Ed25519 session.
  - [x] Allow the Ed25519 WebAuthn path to use `link_existing_near_account`
        when the caller supplies the required ownership proof in
        `signerSelection.ed25519.accountOwnershipProof`.
  - [x] Defer SDK app-session orchestration until a non-passkey ECDSA
        client-root source is defined; current ECDSA add-signer intentionally
        needs WebAuthn PRF output.
- [x] Persist newly attached signer records without re-registering the authenticator.
  - [x] ECDSA add-signer finalization returns complete wallet-key facts without
        writing a new WebAuthn authenticator record.
  - [x] Ed25519 WebAuthn add-signer finalization binds the existing credential to
        the new Ed25519 key without writing a new authenticator record.
  - [x] Client SDK persistence stores finalized ECDSA wallet-key facts as
        threshold-ECDSA account signer rows under the wallet-subject profile,
        without writing a new profile authenticator.
  - [x] Call the ECDSA persistence helper from `addWalletSigner(args)` after
        finalize.
  - [x] Add client SDK persistence for finalized Ed25519 signer material without
        writing a new profile authenticator.
- [x] Add `/wallets/:walletSubjectId/signers/ecdsa/key-facts/inventory` after
      add-signer auth policy helpers are in place.
  - Current slice supports app-session policy authorization and rejects
    Ed25519 threshold-session auth at the route boundary.
- [x] Verify inventory WebAuthn `get()` against a challenge digest that includes
      wallet subject id, RP ID, chain targets, known key handles, runtime policy
      scope, and server nonce.
  - `computeWalletSubjectEcdsaKeyFactsInventoryChallengeDigestB64u` canonicalizes
    wallet subject id, RP ID, sorted `{ keyHandle, chainTarget }` targets,
    optional runtime policy scope, and `serverNonceB64u`.
  - The wallet-subject inventory route rejects mismatched WebAuthn challenge
    digests before verifier use, then verifies `webauthn_assertion` auth with
    `verifyWebAuthnAuthenticationLite`.
- [x] Enforce `ecdsa_key_facts_inventory` app-session policy for app-session
      repair inventory flows.

### Phase 6: Cleanup

Current status: production continuation-token generation, ECDSA bootstrap
acceptance, Ed25519-session authority for ECDSA bootstrap, raw Link
Device/Email Recovery ECDSA prepare payloads, legacy registration bootstrap
routes, and legacy registration HSS sidecar routes have been deleted. Remaining
cleanup is lifecycle naming, optional helper inference, and hardening debt.

- [x] Delete `registrationContinuation` request and response types from `server/src/core/types.ts`.
- [x] Delete `signRegistrationContinuationJwt` from `server/src/router/commonRouterUtils.ts`.
- [x] Delete old managed bootstrap grant targets after `/wallets/register/intent`
      replaces `/registration/bootstrap`.
  - [x] Managed registration grants now allow only `/wallets/register/intent`
        and `/wallets/:walletSubjectId/signers/intent`, mint with
        `/wallets/register/intent` as the canonical path, and consume once.
- [x] Delete all production construction of synthetic
      `legacy-key-handle:*` ECDSA key ids.
- [x] Delete any production fallback that fills `signingRootId` or
      `signingRootVersion` from `keyHandle`.
- [x] Delete login/profile-boundary derivation of `keyHandle` from
      `ecdsaThresholdKeyId + signingRootId + signingRootVersion`.
- [x] Delete normal-unlock inventory fetches. `/threshold-ecdsa/key-identities`
      remains only on the legacy route surface; `unlock()` no longer calls it.
      Explicit repair/recovery flows use the wallet-subject inventory endpoint.
- [x] Keep request/persistence boundary parsing strict for active ECDSA wallet
      keys: direct `keyHandle` is required, synthetic legacy selectors are
      rejected, and incomplete active rows are invalid.
- [x] Delete registration-continuation claim parsing from threshold validation.
      Express and Cloudflare ECDSA role-local bootstrap authorization no longer
      accepts registration-continuation session claims.
- [x] Delete continuation-token generation from `server/src/router/relayRegistrationBootstrap.ts`.
- [x] Delete `provisionThresholdEcdsaAfterRegistration` from `client/src/core/SeamsPasskey/registration.ts`.
- [x] Delete `{ kind: 'registration_continuation' }` from `client/src/core/rpcClients/relayer/thresholdEcdsa.ts`.
      `client/src/core/signingEngine/session/passkey/ecdsaBootstrap.ts` also
      has no registration-continuation route auth branch.
- [x] Delete raw `threshold_ecdsa.client_root_share32_b64u` support from the
      legacy `/registration/bootstrap` server route, `CreateAccountAndRegister*`
      request/result types, and SDK atomic registration wrapper.
  - [x] Delete raw Link Device and Email Recovery
        `threshold_ecdsa.client_root_share32_b64u` production client/server
        payload handling.
  - [x] Add focused `AuthService` boundary coverage proving Link Device and
        Email Recovery reject raw `threshold_ecdsa` bootstrap payloads before
        setup work.
  - [x] Delete the obsolete SDK-side Link Device manual ECDSA bootstrap helper
        and its tests; Link Device ECDSA material must come from the new
        role-local ceremony path.
  - [x] Delete stale Link Device and Email Recovery prepare-route ECDSA session
        wrapping. Express and Cloudflare prepare routes now sign only
        `thresholdEd25519` session payloads until the replacement role-local
        ECDSA ceremony exists.
  - [x] Keep the unfinished Email Recovery ECDSA owner binding from persisting
        WebAuthn authenticator or binding state; it now fails before persistence
        until the replacement role-local ECDSA ceremony supplies the recovered
        EVM owner material.
  - [x] Add the Link Device server prepare contract for replacement ECDSA:
        `threshold_ecdsa_prepare` requests are normalized at the boundary and
        return an `ecdsa.prepare` role-local HSS context without accepting raw
        client-root material or signing a stale `thresholdEcdsa` session.
  - [x] Add the Link Device server respond contract for replacement ECDSA:
        `/link-device/ecdsa/respond` loads the stored prepare context from the
        opaque link-device session, rejects bootstrap identity mismatches, calls
        the role-local ECDSA HSS primitive, and returns canonical
        `WalletRegistrationEcdsaWalletKey` facts for client persistence.
  - [x] Wire the Link Device client to request configured ECDSA prepare targets,
        derive the role-local client bootstrap from the new passkey PRF output,
        call `/link-device/ecdsa/respond`, and persist returned
        `WalletRegistrationEcdsaWalletKey` records locally.
  - [x] Add the replacement role-local ECDSA Email Recovery ceremony.
        `/email-recovery/prepare` now stores verified WebAuthn, Ed25519, and
        ECDSA prepare context without building the recovery email. The SDK
        derives the role-local ECDSA client bootstrap from the passkey PRF and
        calls `/email-recovery/ecdsa/respond`; the server finalizes ECDSA,
        binds the returned EVM owner into the canonical recovery email payload,
        persists the authenticator/binding/recovery session, and returns
        wallet-key facts for local client persistence.
- [x] Delete `/registration/bootstrap` and `/registration/threshold-ed25519/hss/*` routes in the same refactor that moves wrappers to `/wallets/register/*`.
  - [x] Deleted Express and Cloudflare wrappers, shared relay handlers, route
        definitions, SDK atomic bootstrap helper, and old sessionless
        registration HSS client helper.
  - [x] Updated API-key, bootstrap-grant, route-definition, and rollback tests
        to target `/wallets/register/intent`.
  - [x] Removed the stale Email OTP Ed25519 registration sidecar caller from
        production SDK code. That flow now fails explicitly until it is rebuilt
        on a wallet-subject ceremony instead of calling deleted routes.
- [x] Delete mixed paths that derive ECDSA authority from Ed25519 threshold-session auth tokens.
      ECDSA role-local bootstrap authorization no longer parses Ed25519
      threshold-session claims in Express or Cloudflare handlers; existing-key
      ECDSA bootstrap must use passkey authorization, app-session authority, or
      ECDSA threshold-session authority.
  - Validation: `pnpm -s type-check:relay-server`, `pnpm -s type-check:sdk`,
    `pnpm -C tests exec playwright test -c playwright.relayer.config.ts relayer/threshold-ecdsa-role-local-passkey-bootstrap.test.ts --reporter=line`,
    and `pnpm -C tests exec playwright test -c playwright.relayer.config.ts relayer/relay-api-keys.test.ts --reporter=line`
    passed after this deletion.
- [x] Delete any stale client imports that reference the removed threshold workflows path family.
- [x] Delete any stale client imports that reference removed `session/warmSigning/*`, `session/signingSession/*`, `sessionEmailOtp/*`, or `touchConfirm/*` paths.
- [x] Delete any internal registration or add-signer helper that infers lifecycle route from optional auth fields.
  - [x] ECDSA lifecycle projection now switches on discriminated request
        branches: new-key enrollment emits `key_enrollment_bootstrap`, and
        exact existing-key activation emits `session_bootstrap`. Optional auth
        material no longer chooses the lifecycle route.
- [x] Rename threshold signing-session auth fields to opaque auth-token names as covered by `docs/signing-session-architecture/threshold-session-auth-token.md`.
  - [x] Production threshold-session surfaces use
        `thresholdSessionAuthToken`; deleted names remain only in the completed
        naming-cleanup plan and negative grep fixtures.
- [x] Add a one-shot development maintenance path that prunes active ECDSA
      signer rows missing direct `keyHandle` or complete `keyFacts`; keep it
      outside normal login and unlock.
  - [x] `PasskeyClientDBManager.pruneIncompleteActiveThresholdEcdsaSigners`
        revokes only active `threshold-ecdsa` signer rows with missing direct
        `metadata.keyHandle`, missing `metadata.chainTarget`, or incomplete
        EVM-family ECDSA key facts. The method is explicit maintenance only;
        registration, login, and unlock do not call it.

Remaining deferred or hardening work:

- Rebuild Email OTP Ed25519 registration provisioning on a wallet-subject
  ceremony, or remove the public SDK path if Email OTP Ed25519 registration is
  out of scope for this refactor. The stale production sidecar caller is
  already removed, and the current helper fails explicitly instead of calling
  deleted registration routes.

### Phase 6B: Email OTP Wallet Registration And Enrollment

Status: moved to `docs/rework-registration-flows-2.md`. The Email OTP auth-method expansion is now tracked as the follow-up registration-auth-method refactor, so it is excluded from original passkey wallet-registration test readiness.

The original plan keeps this phase as a pointer only. Source of truth for Email OTP first-class registration, explicit `authMethod`, multiple auth methods per wallet, and related coverage is `docs/rework-registration-flows-2.md`.

### Phase 7: Test And Verification

Remaining unchecked Phase 7 items are hardening or broader coverage. They do
not block the high-impact registration, add-signer, or independent-unlock
runtime paths above.

- [x] Add independent-unlock hardening coverage after the Phase 4 planner
      exists.
  - [x] Type fixtures reject broad object-spread construction of unlock plans,
        raw profile metadata in core planner inputs, activation without
        `EvmFamilyEcdsaWalletKey`, activation with `keyIntent`, and
        registration/add-signer requests with exact-session fields.
    - [x] Unlock planner type fixtures reject invalid branch combinations,
          `ready` plans mixed with repair records, and raw profile metadata
          passed as active signer records.
    - [x] ECDSA bootstrap lifecycle type fixtures reject exact activation
          without `EvmFamilyEcdsaWalletKey` and exact activation with separate
          `key` or `keyHandle` projections.
    - [x] ECDSA bootstrap lifecycle type fixtures reject exact activation with
          `keyIntent` and target registration requests with exact-session key
          handles.
  - [x] Unit tests cover Ed25519-only unlock, ECDSA-only unlock, combined
        unlock, no configured ECDSA targets, ready local ECDSA records,
        authenticated inventory fetch, missing key handle, synthetic legacy id,
        ambiguous key handle, parser rejection, and inventory owner drift.
    - [x] Planner tests cover Ed25519-only selection, ECDSA-only selection
          with no configured ECDSA targets, ready local records, synthetic
          legacy ids, missing direct key handles, and ambiguous active records.
    - [x] Login warm-up tests cover Ed25519-only selection and ECDSA-only
          selection from a passkey PRF without Ed25519 session connection.
    - [x] Login and planner coverage now includes combined Ed25519 plus ECDSA
          warm-up, authenticated inventory restore ordering, parser rejection,
          and inventory owner drift.
  - [x] Mutation-ledger coverage proves blocked and inventory-deferred ECDSA
        plans do not call `clearVolatileWarmSigningMaterial` before all exact
        ECDSA warm-up inputs are resolved.
    - [x] `tests/unit/seamsPasskey.loginThresholdWarm.unit.test.ts` records
          blocked profile metadata and restored-inventory ordering: blocked
          inputs perform no clear/fetch/provision mutation, and restored
          inventory resolves before clear, Ed25519 connect, and ECDSA bootstrap.
  - [x] Guard coverage prevents raw profile `metadata` reads and raw inventory
        response records from re-entering the unlock execution path.
    - [x] `tests/unit/signingEngine.refactor36.guard.unit.test.ts` now asserts
          wallet unlock calls the ECDSA key-facts boundary parsers and rejects
          direct profile metadata field reads plus raw inventory-record aliases
          in `login.ts`.
- [x] Add add-signer matrix coverage after Phase 5 add-signer routes and client
      API exist.
  - [x] Cover later ECDSA from Ed25519-only wallets and later Ed25519 from
        ECDSA-only wallets at the full add-signer orchestration layer.
  - [x] Cover client persistence for later ECDSA from an Ed25519 wallet and
        later Ed25519 from an ECDSA wallet.
  - [x] Add focused `AuthService` coverage that existing-account Ed25519
        add-signer proof failures do not consume grants, and valid proofs allow
        the start path to prepare HSS.
- [x] Add cleanup hardening after Phase 6 removes continuation symbols.
  - [x] Update architecture guards so deleted continuation symbols are absent
        from the production registration and passkey ECDSA bootstrap paths.
- [x] Add unit tests for registration intent digest canonicalization.
- [x] Add unit tests for registration intent allocation and grant replay
      rejection.
  - [x] Cover that unsupported ECDSA-mode starts do not consume the intent
        grant before ECDSA ceremony support exists.
- [x] Add unit tests for registration ceremony store durable consume semantics.
  - [x] Cloudflare Durable Object adapter coverage proves intent grants and
        ceremony handles consume once.
- [x] Add compile-time fixtures for ECDSA registration ceremony lifecycle
      branches.
- [x] Add unit tests for registration signer-selection normalization.
- [x] Add relayer tests for the three initial registration modes.
- [x] Add relayer tests for `/wallets/register/intent` environment binding,
      origin binding, and metering context.
  - [x] Assert the route rejects missing/invalid exact origins before API
        credential auth, forwards normalized origin and environment-derived
        runtime scope into intent creation, and remains explicitly
        non-metered at intent allocation.
- [x] Add relayer tests that ECDSA-only registration creates no NEAR account.
  - [x] Focused `AuthService` coverage asserts the ECDSA-only
        start/respond/finalize path completes without calling NEAR account
        creation.
- [x] Add relayer tests that combined registration verifies WebAuthn `create()` once.
  - [x] Add focused `AuthService` coverage for combined start/respond/finalize
        from one ceremony with both signer-family branches.
  - [x] Focused `AuthService` coverage counts the combined start WebAuthn
        verification and asserts both signer families share the one verified
        registration credential.
- [x] Add relayer tests that Ed25519 registration HSS respond rejects
      `evaluatorOtStateB64u`, client input shares, PRF fields, and output mask
      fields.
  - [x] Focused route-boundary unit coverage for every forbidden respond field
        before `AuthService`.
- [x] Add relayer tests that Ed25519 registration HSS finalize rejects
      evaluator OT state, raw opened client output, seed output, and
      server-owned staged artifact shapes.
  - [x] Focused route-boundary unit coverage for every forbidden finalize field
        before `AuthService`.
- [x] Add relayer route-boundary tests for ECDSA registration HSS
      respond/finalize normalization.
  - [x] ECDSA respond rejects root-proof, passkey-bootstrap authorization, and
        direct session-kind fields before `AuthService`.
  - [x] ECDSA respond/finalize forward normalized ceremony-owned inputs for
        ECDSA-only registration messages.
- [x] Add relayer tests that one ECDSA HSS keygen creates shared wallet-key facts
      across all requested EVM-family chain targets.
  - [x] Add focused `AuthService` unit coverage for ECDSA-only start,
        role-local HSS respond, and finalize fan-out across multiple requested
        chain targets.
  - [x] Assert fan-out preserves one shared key handle, threshold key id,
        signing root, threshold public key, owner address, relayer key id,
        verifying share, and participant set across the returned per-target
        wallet keys.
  - [x] Add focused `AuthService` unit coverage that ECDSA registration and
        add-signer finalize reject incomplete key facts before returning
        wallet-key facts.
- [x] Add tests that fake object-shaped WebAuthn auth fails add-signer preparation.
  - Covered at the current role-local ECDSA signer-preparation boundary:
    `tests/relayer/threshold-ecdsa-role-local-passkey-bootstrap.test.ts`
    proves object-shaped fake WebAuthn is forwarded to
    `verifyWebAuthnAuthenticationLite`, rejected on verifier failure, and does
    not bootstrap relayer state.
- [x] Add tests that ECDSA repair inventory rejects Ed25519 threshold-session
      auth and accepts app-session inventory policy.
  - `tests/unit/relayWalletRegistration.boundary.unit.test.ts` covers
    `/wallets/:walletSubjectId/signers/ecdsa/key-facts/inventory` rejecting
    threshold Ed25519 session claims and accepting `app_session_v1` claims with
    `ecdsa_key_facts_inventory` policy.
- [x] Add tests that ECDSA repair inventory accepts WebAuthn inventory
      authorization.
  - `tests/unit/relayWalletRegistration.boundary.unit.test.ts` covers
    mismatched challenge rejection and verified WebAuthn authorization for
    `/wallets/:walletSubjectId/signers/ecdsa/key-facts/inventory`.
- [x] Add client tests for the current registration SDK surface.
  - Current SDK surface exposes `registerWallet`, the passkey
    `registerPasskey` wrapper, and narrow `near.registerNearWallet` /
    `evm.registerEvmWallet` public aliases.
  - [x] Add focused persistence-order coverage proving Ed25519 wallet
        registration stores the wallet-subject signer before the NEAR
        projection.
  - [x] Add focused SDK orchestration coverage proving ECDSA-only
        `registerWallet` uses `/wallets/register/*`, persists returned
        wallet-key facts, and skips NEAR profile work.
  - [x] Add focused SDK orchestration coverage proving combined
        `registerWallet` uses one `/wallets/register/*` ceremony, sends both
        HSS responses, finalizes both signer families, and persists the
        returned ECDSA wallet-key facts after Ed25519 wallet-subject
        registration persistence.
  - [x] Add focused SDK orchestration coverage proving `near.registerNearWallet`
        and `evm.registerEvmWallet` route through `registerWallet`.
        `near.registerNearWallet` requests combined Ed25519+configured ECDSA
        targets by default and still supports explicit Ed25519-only when
        ECDSA provisioning is disabled; `evm.registerEvmWallet` remains
        ECDSA-only.
- [x] Add client tests for Ed25519-only, ECDSA-only, and combined wallet unlock.
  - Existing coverage includes NEAR-only warm-up skipping ECDSA bootstrap,
    combined Ed25519 plus ECDSA warm-up, and shared ECDSA target completion.
    ECDSA-only warm-up is covered by the passkey PRF path without Ed25519
    session connection.
- [x] Add an unlock regression test proving active ECDSA signer rows with
      complete `EvmFamilyEcdsaWalletKey` do not trigger key-facts inventory
      fetches.
- [x] Add a strict-parser test proving active ECDSA signer rows missing direct
      `keyHandle` are rejected.
- [x] Add ECDSA key-facts inventory parser unit tests.
- [x] Add ECDSA bootstrap lifecycle type fixtures.
- [x] Run `tests/unit/signingEngine.refactor33.guard.unit.test.ts` after client registration moves.
- [x] Run `tests/unit/signingEngine.refactor36.guard.unit.test.ts` after registration/add-signer lifecycle type changes.
- [x] Run unlock/login threshold warm-session tests after independent unlock
      planning moves.
- [x] Run `tests/unit/sealedRecovery.methodAdapters.unit.test.ts` if registration changes sealed recovery or warm-session persistence inputs.
- [x] Run `tests/relayer/threshold-ecdsa-role-local-passkey-bootstrap.test.ts`
      after hardening passkey ECDSA role-local bootstrap authorization.
- [x] Add cleanup tests that production code contains no `registrationContinuation` or `registration_continuation` symbols.
  - `tests/unit/passkeyRegistrationRollback.guard.unit.test.ts` scans the
    production registration wrapper, threshold ECDSA RPC client, passkey ECDSA
    bootstrap helper, server core types, common router utilities, and legacy
    registration bootstrap route for deleted continuation symbols.

### Phase 8: ECDSA Active Wallet Key Cleanup

This phase finishes the remaining Refactor 39 cleanup work under the
`EvmFamilyEcdsaWalletKey` model.

- [x] Retire `ThresholdEcdsaSecp256k1KeyRef` from core signing, unlock,
      warm-capability planning, and operation-dependency surfaces.
  - [x] Keep `ThresholdEcdsaSecp256k1KeyRef` construction and consumption inside
        explicit boundary adapters such as signer transport, persistence
        normalization, worker transport, and external SDK compatibility edges.
    - [x] Guard production imports with an allowlist of boundary adapters:
          signer transport, persistence/session-public compatibility,
          identity adapter construction, passkey/bootstrap transport,
          threshold activation, link-device compatibility, and the
          `SigningEngine` public compatibility edge.
  - [x] Move EVM-family signing flow modules to consume
        `EvmFamilyEcdsaWalletKey` plus branch-specific ready signing material.
    - [x] Move ECDSA material-state construction and ECDSA selection to accept
          session records as the resolved material input. These modules now
          derive `ThresholdEcdsaSecp256k1KeyRef` through
          `buildThresholdEcdsaSecp256k1KeyRefFromRecord()` instead of accepting
          key-ref callbacks or caller-provided key-ref pairs.
    - [x] Move passkey and warm-session reconnect preparation in
          `signingFlowRuntime.ts` to require exact session records and construct
          ready material from those records at the adapter boundary.
  - [x] Move warm-capability provision plans to carry
        `EvmFamilyEcdsaWalletKey` for resolved active keys.
    - [x] Reconnect plans now carry only the persisted
          `ThresholdEcdsaSessionRecord`; `ecdsaProvisionPlan.ts` derives
          transport key refs with `buildThresholdEcdsaSecp256k1KeyRefFromRecord()`
          at the threshold-session auth boundary. EVM-family passkey and
          Email OTP provision planners build signing context from records through
          `buildEcdsaSigningKeyContextFromRecord()` and no longer read
          `args.material.keyRef`.
    - [x] Warm ECDSA readiness now requires the selected
          `ThresholdEcdsaSessionRecord` through
          `EnsureWarmEcdsaProvisionPlanReadyArgs.record`. The provisioner
          validates the record against the reconnect plan identity, derives the
          transport key ref internally with
          `buildThresholdEcdsaSecp256k1KeyRefFromRecord()`, and keeps source
          handling at the reconnect request boundary so source-agnostic sealed
          restores keep their exact session identity.
  - [x] Remove operation-dependency callbacks that return key refs. EVM-family
        signing now reads the resolved session record from operation deps and
        builds the signer transport key ref only through
        `buildThresholdEcdsaSecp256k1KeyRefFromRecord()` at the lane adapter
        boundary.
  - [x] Add guard coverage for the operation-dependency cleanup:
        `signingEngine.refactor37.guard.unit.test.ts` now rejects the removed
        key-ref callbacks in operation deps, EVM-family prepared-signing deps,
        port assembly args, port assembly wiring, and the signing-engine
        composition root.
  - [x] Add guard coverage that blocks direct
        `ThresholdEcdsaSecp256k1KeyRef` imports from core signing, unlock,
        warm-capability, and operation-state modules.
    - [x] `signingEngine.refactor37.guard.unit.test.ts` now scans the
          converted EVM-family signing flow, warm-capability, operation-state,
          and `SeamsPasskey` unlock-facing directories for direct
          `ThresholdEcdsaSecp256k1KeyRef` imports. The only allowed matches are
          explicit boundary adapters and type-level rejection fixtures.
    - [x] Remove the operation-state signing capability key-ref reader surface.
          `session/operationState/lanes.ts` now resolves only session records;
          ECDSA capability results reject caller-provided `keyRef` fields, and
          the guard blocks reintroducing key-ref readers or key-ref error
          branches in operation-state lanes.
    - [x] Move login presign prefill to session records. The public warm
          capability API and `ecdsaLoginPrefill.ts` now accept
          `thresholdEcdsaSessionRecord`, read signer-share material from the
          record, and report malformed input as `invalid_session_record`.
          `SeamsPasskey` prefill lookup now selects the login session record
          instead of fetching a signing key ref.
    - [x] Remove ECDSA key-ref payloads from EVM-family material state. Ready,
          public-identity, and reauth material branches now expose session
          records, verified public facts, signer sessions, and ready material;
          transport key refs stay derived locally for readiness resolution and
          signer boundaries. Guards reject reintroducing `keyRef` fields,
          `hasKeyRef` summaries, and `getEcdsaMaterialKeyRef()`.
    - [x] Move EVM-family reconnect readiness and runtime refresh handoff to
          session records. `ecdsaReadiness.ts` now returns the ready
          `ThresholdEcdsaSessionRecord`; `signingFlowRuntime.ts` accepts
          `getThresholdEcdsaRecord` / `setThresholdEcdsaRecord`; and
          `signEvmFamily.ts` no longer imports `ThresholdEcdsaSecp256k1KeyRef`
          or reads selected lane key refs during reconnect refresh.
    - [x] Remove stale ECDSA key-ref lane helpers from `ecdsaLanes.ts`.
          The lane module no longer imports `ThresholdEcdsaSecp256k1KeyRef` or
          exports selected-lane key-ref readers, shared key-ref finders, or
          key-ref candidate validators. `warmSessionServices.ts` now passes
          session records into the warm provisioner instead of deriving key refs
          for candidate lookup.
    - [x] Remove the Email OTP refresh result key-ref payload. The refresh flow
          still validates the bootstrap key ref against the persisted session
          record at the response boundary, then returns ready material, the
          record, lane, and provision plan to callers.
    - [x] Make `ReadyEvmFamilyEcdsaMaterial` record-only. Ready material now
          rejects `keyRef` payloads, keeps cached export-artifact provenance as
          a separate field, derives signer transport key refs through
          `buildThresholdEcdsaSecp256k1KeyRefFromSessionRecord()` only at
          signer/export boundaries, and reads public facts from the validated
          session record.
    - [x] Make ready EVM-family ECDSA material resolution record-only.
          `resolveReadyEvmFamilyEcdsaMaterial()` now accepts the selected
          `ThresholdEcdsaSessionRecord`, rejects caller-provided `keyRef`
          payloads at the type level, removes `record_only` / `key_ref_only`
          resolution branches, and takes cached export artifacts as an explicit
          boundary payload. `ecdsaMaterialState.ts` no longer imports or calls
          `buildThresholdEcdsaSecp256k1KeyRefFromRecord()` just to prove
          readiness.
    - [x] Make warm ECDSA capability readiness results record-only.
          `EnsureWarmEcdsaCapabilityReadyResult` now returns the ready
          `ThresholdEcdsaSessionRecord`, rejects result `keyRef` payloads, and
          `warmCapabilities/types.ts` has no direct
          `ThresholdEcdsaSecp256k1KeyRef` import.
    - [x] Move warm provisioner candidate lookup from key refs to session
          records. `WarmSessionEcdsaProvisionerDeps` and
          `WarmSessionEcdsaReconnectDeps` now expose
          `listThresholdEcdsaRecordsForWalletTarget`; `ecdsaProvisioner.ts`
          matches reconnect and reusable warm-capability candidates by
          validated `ThresholdEcdsaSessionRecord`; and record-to-key-ref
          conversion stays inside bootstrap/reconnect transport result
          construction.
    - [x] Tighten warm provisioner record-candidate dependencies after review.
          `listThresholdEcdsaRecordsForWalletTarget` is now required on
          `WarmSessionEcdsaProvisionerDeps` and
          `WarmSessionEcdsaReconnectDeps`; source-aware exact-record refresh
          lookup uses `resolveExactEcdsaRecordWithSourceFallback()` instead of
          duplicating optional source fallback calls inline; and the guard
          blocks making the callback optional again.
    - [x] Move signing-flow runtime fallback material handoff to records.
          `signingFlowRuntime.ts` now passes the fallback
          `ThresholdEcdsaSessionRecord` into
          `buildReadySecp256k1SigningMaterialFromRecord()` instead of deriving a
          transport key ref in the runtime module. Record-to-key-ref conversion
          for fallback signing now stays inside the secp256k1 signer boundary,
          and the guard blocks reintroducing the key-ref builder import in the
          runtime.
    - [x] Remove export material key-ref lookup for cached HSS artifacts.
          `ecdsaExportMaterial.ts` now reads `exportArtifactsByLane` directly
          with `deriveThresholdEcdsaRuntimeLaneKey(record)` instead of calling
          `getThresholdEcdsaKeyRefByKey()` only to recover
          `ecdsaHssExportArtifact`. Ready export material remains record-only,
          and the guard blocks reintroducing the key-ref lookup.
    - [x] Remove the generic key-ref lookup from EVM-family operation deps.
          Prepared signing now treats exact hot material as present only when a
          canonical `ThresholdEcdsaSessionRecord` exists for the selected lane.
          `EvmFamilyEcdsaSessionReaderDeps`, port assembly, and
          `SigningEngine` no longer expose `getThresholdEcdsaKeyRefByKey()` to
          EVM-family operation flows; persistence/session-public boundary
          lookups remain the only key-ref-by-key readers.
- [x] Move active ECDSA profile-continuity parsing out of
      `client/src/core/SeamsPasskey/login.ts`.
  - [x] Add a boundary parser for raw profile signer metadata:
        `parseProfileContinuityEcdsaWarmKey()` owns raw signer metadata reads
        and normalizes profile continuity into domain branches.
  - [x] Return a discriminated result:
        `active_wallet_key`, `repair_required`, or `blocked`.
  - [x] Make `active_wallet_key` carry `EvmFamilyEcdsaWalletKey` and concrete
        `ThresholdEcdsaChainTarget`.
  - [x] Keep synthetic `legacy-key-handle:*`, missing key handles, missing
        chain targets, invalid chain targets, and ambiguous key handles as
        blocked parser results.
  - [x] Treat keyHandle-only active signers with missing key facts as
        `repair_required`; normal login now fails closed before mutation unless
        another complete local shared key resolves the configured target set.
  - [x] Delete any branch that derives `keyHandle` from `keyFacts` in login,
        unlock planning, profile parsing, or active signer normalization.
  - [x] Make login consume parser results only; login must not inspect raw
        profile metadata fields directly.
- [x] Move authenticated ECDSA key-facts inventory out of normal login.
  - [x] Introduce an explicit repair/recovery entrypoint for inventory reads:
        `repairWalletSubjectEcdsaKeyFactsInventoryWithAppSession()` posts to
        `/wallets/:walletSubjectId/signers/ecdsa/key-facts/inventory`, parses
        returned records through `parseThresholdEcdsaKeyIdentityTargets()`, and
        returns canonical `EvmFamilyEcdsaWalletKey` entries.
  - [x] Require wallet/authenticator authority or app-session policy for repair
        inventory.
  - [x] Keep normal unlock latency local-only when active signer records are
        complete.
  - [x] Normal unlock with incomplete local ECDSA key facts fails before
        volatile warm material is cleared, before Ed25519 warm-up, and before
        ECDSA bootstrap. Managed first-bootstrap remains the only normal-login
        path that may create missing ECDSA lanes from the current assertion.
  - [x] Guards now reject `/threshold-ecdsa/key-identities` in `unlock()` and
        assert the explicit repair RPC boundary owns authenticated inventory
        parsing.
- [x] Clean Postgres ECDSA key-store shared-key lookup shape.
  - [x] Replace JSON-expression shared-key indexes on
        `threshold_ecdsa_keys.record_json` with current-schema columns or a
        deleted lookup if the invariant is covered by key-handle and key-facts
        uniqueness.
  - [x] Replace shared-key conflict queries that read
        `record_json->>'walletSessionUserId'`, `record_json->>'subjectId'`, and
        `record_json->>'rpId'` with typed indexed columns or explicit boundary
        validation.
  - [x] Keep `record_json` as serialized record payload only. Current lookup,
        uniqueness, and conflict checks should use declared columns.
  - [x] Update Postgres key-store tests so startup still has no prune/backfill
        path and shared-key checks exercise the current schema.
- [x] Update stale Refactor 39 naming and docs.
  - [x] Replace completed-plan references to the old Ed25519-specific inventory
        state with the domain name
        `awaiting_authenticated_key_facts_inventory`.
  - [x] Add a short Refactor 39 completion note pointing remaining active-key
        cleanup to this phase.
- [x] Add focused validation for this cleanup phase.
  - [x] Run the ECDSA key-facts unit tests.
        `pnpm -C tests exec playwright test ./unit/thresholdEcdsaKeyIdentityInventoryParser.unit.test.ts ./unit/seamsPasskey.loginThresholdWarm.unit.test.ts --reporter=line`
        passed 35 tests after the parser move, public-facts hardening, and
        exact wallet-key inventory return shape.
        `pnpm -C tests exec playwright test ./unit/thresholdEcdsaKeyIdentityInventoryParser.unit.test.ts --reporter=line`
        passed 4 tests after synthetic legacy-id rejection.
  - [x] Run login threshold warm-session tests.
        `pnpm -C tests exec playwright test ./unit/seamsPasskey.loginThresholdWarm.unit.test.ts --reporter=line`
        passed 32 tests after adding the blocked/restored-inventory mutation
        ledger.
        `pnpm -C tests exec playwright test ./unit/seamsPasskey.loginThresholdWarm.unit.test.ts ./unit/thresholdEcdsaKeyIdentityInventoryParser.unit.test.ts ./unit/signingEngine.refactor36.guard.unit.test.ts --reporter=line`
        passed 56 tests after moving profile-continuity ECDSA metadata parsing
        to the key-facts boundary module and adding the unlock guard.
        `pnpm -C tests exec playwright test ./unit/thresholdEcdsaKeyIdentityInventoryParser.unit.test.ts ./unit/seamsPasskey.loginThresholdWarm.unit.test.ts ./unit/signingEngine.refactor36.guard.unit.test.ts --reporter=line`
        passed 60 tests after the parser result was narrowed to
        `active_wallet_key | repair_required | blocked`.
  - [x] Run Postgres key-store tests.
        `pnpm -C tests exec playwright test ./unit/thresholdEcdsa.postgresRecords.unit.test.ts ./unit/thresholdEcdsa.postgresKeyStoreBackfill.unit.test.ts --reporter=line`
        passed 8 tests after Postgres shared-key lookup moved from JSON
        expressions to declared identity columns.
  - [x] Run SDK type-check after key-ref surface changes.
        `pnpm -s type-check:sdk` passed after the parser move and wallet-key
        inventory return shape.
        `pnpm -s type-check:sdk` passed after exact ECDSA activation requests
        were narrowed to `EvmFamilyEcdsaWalletKey` plus lane policy.
        `pnpm -s type-check:sdk` passed after profile-continuity ECDSA metadata
        parsing moved behind the key-facts boundary.
        `pnpm -s type-check:sdk` passed after `active_wallet_key` began
        carrying `EvmFamilyEcdsaWalletKey`.
        `pnpm -s type-check:sdk` passed after removing operation-dependency
        key-ref callbacks.
        `pnpm -s type-check:sdk` passed after warm-capability provision plans
        moved reconnect material to session records and derived transport key
        refs at the boundary.
        `pnpm -s type-check:sdk` passed after operation-state signing
        capability readers became record-only.
        `pnpm -s type-check:sdk` passed after login presign prefill moved from
        key refs to ECDSA session records.
        `pnpm -s type-check:sdk` passed after warm ECDSA readiness args moved
        from caller-provided key refs to selected session records.
        `pnpm -s type-check:sdk` passed after EVM-family material state stopped
        exposing key-ref payloads.
        `pnpm -s type-check:sdk` passed after EVM-family reconnect readiness
        and runtime refresh handoff moved from key refs to session records.
        `pnpm -C tests exec playwright test ./unit/ecdsaSelection.restorable.unit.test.ts ./unit/evmSigning.thresholdReconnectEvents.unit.test.ts ./unit/emailOtpOperationSplit.guard.unit.test.ts ./unit/signingEngine.refactor37.guard.unit.test.ts --reporter=line`
        passed 53 tests after EVM-family signing began deriving lane key refs
        from session records at the adapter boundary.
        `pnpm -C tests exec playwright test ./unit/ecdsaMaterialState.unit.test.ts ./unit/ecdsaSelection.restorable.unit.test.ts ./unit/evmSigning.thresholdReconnectEvents.unit.test.ts ./unit/emailOtpOperationSplit.guard.unit.test.ts ./unit/signingEngine.refactor37.guard.unit.test.ts --reporter=line`
        passed 56 tests after material-state, selection, and reconnect runtime
        stopped accepting caller-provided key-ref pairs.
        `pnpm -C tests exec playwright test ./unit/ecdsaMaterialState.unit.test.ts ./unit/ecdsaSelection.restorable.unit.test.ts ./unit/evmSigning.thresholdReconnectEvents.unit.test.ts ./unit/evmFamilyStepUpProvisionPlan.unit.test.ts ./unit/warmSessionStore.reconnect.unit.test.ts ./unit/emailOtpOperationSplit.guard.unit.test.ts ./unit/signingEngine.refactor37.guard.unit.test.ts --reporter=line`
        passed 65 tests after warm-capability provision plans began carrying
        session records and deriving transport key refs at the boundary.
        `pnpm -C tests exec playwright test ./unit/signingEngine.refactor37.guard.unit.test.ts --reporter=line`
        passed 35 tests after the operation-state signing capability reader
        stopped exposing ECDSA key-ref readers and key-ref success payloads.
        `pnpm -C tests exec playwright test ./unit/signingEngine.refactor37.guard.unit.test.ts ./unit/signingEngine.refactor33.guard.unit.test.ts ./unit/seamsPasskey.loginThresholdWarm.unit.test.ts --reporter=line`
        passed 123 tests after login presign prefill moved to session-record
        input and record-backed signer-share resolution.
        `pnpm -C tests exec playwright test ./unit/signingEngine.refactor37.guard.unit.test.ts ./unit/evmSigning.thresholdReconnectEvents.unit.test.ts ./unit/warmSessionStore.reconnect.unit.test.ts ./unit/warmSessionStore.concurrency.unit.test.ts ./unit/warmSessionStore.transitions.unit.test.ts ./unit/warmSessionStore.errorNormalization.unit.test.ts --reporter=line`
        passed 56 tests after warm ECDSA readiness and reconnect callers moved
        to record-only input.
        `pnpm -C tests exec playwright test ./unit/ecdsaMaterialState.unit.test.ts ./unit/ecdsaSelection.restorable.unit.test.ts ./unit/signingEngine.refactor37.guard.unit.test.ts --reporter=line`
        passed 47 tests after material-state key-ref payloads were removed.
        `pnpm -C tests exec playwright test ./unit/evmSigning.thresholdReconnectEvents.unit.test.ts ./unit/emailOtpOperationSplit.guard.unit.test.ts ./unit/signingEngine.refactor37.guard.unit.test.ts --reporter=line`
        passed 47 tests after EVM-family reconnect readiness and runtime refresh
        handoff moved to record-only inputs and outputs.
        `pnpm -s type-check:sdk` passed after removing stale ECDSA key-ref lane
        helpers and moving the warm-session provisioner key-ref derivation into
        `warmSessionServices.ts`.
        `pnpm -C tests exec playwright test ./unit/emailOtpOperationSplit.guard.unit.test.ts ./unit/signingEngine.refactor37.guard.unit.test.ts --reporter=line`
        passed 46 tests after `ecdsaLanes.ts` became free of direct ECDSA
        key-ref imports and helper exports.
        `pnpm -s type-check:sdk` passed after the Email OTP refresh result
        stopped returning `ThresholdEcdsaSecp256k1KeyRef`.
        `pnpm -C tests exec playwright test ./unit/emailOtpOperationSplit.guard.unit.test.ts ./unit/signingEngine.refactor37.guard.unit.test.ts --reporter=line`
        passed 46 tests after the Email OTP refresh result became record-only.
        `pnpm -s type-check:sdk` passed after
        `ReadyEvmFamilyEcdsaMaterial` stopped carrying ECDSA key refs.
        `pnpm -C tests exec playwright test ./unit/evmFamilyEcdsaIdentity.unit.test.ts ./unit/evmFamilyStepUpProvisionPlan.unit.test.ts ./unit/ecdsaMaterialState.unit.test.ts ./unit/emailOtpOperationSplit.guard.unit.test.ts ./unit/signingEngine.refactor37.guard.unit.test.ts --reporter=line`
        passed 87 tests after ready EVM-family ECDSA material became
        record-only and signer sessions derived transport key refs at the
        boundary.
        `pnpm -s type-check:sdk` passed after warm ECDSA readiness results
        stopped returning key refs.
        `pnpm -C tests exec playwright test ./unit/warmSessionStore.concurrency.unit.test.ts ./unit/signingEngine.refactor37.guard.unit.test.ts --reporter=line`
        passed 39 tests after warm ECDSA readiness results became record-only.
        `pnpm -s type-check:sdk` passed after warm provisioner candidate
        lookup moved from key refs to session records.
        `pnpm -C tests exec playwright test ./unit/warmSessionEcdsaProvisioning.unit.test.ts ./unit/warmSessionStore.reconnect.unit.test.ts ./unit/warmSessionStore.concurrency.unit.test.ts ./unit/warmSessionStore.transitions.unit.test.ts ./unit/warmSessionStore.errorNormalization.unit.test.ts ./unit/signingEngine.refactor37.guard.unit.test.ts --reporter=line`
        passed 59 tests after warm provisioner candidate lookup moved from key
        refs to session records and the guard began enforcing record callbacks
        in `warmSessionServices.ts`.
        `pnpm -s type-check:sdk` passed after ready EVM-family ECDSA material
        resolution stopped accepting paired key-ref input.
        `pnpm -C tests exec playwright test ./unit/evmFamilyEcdsaIdentity.unit.test.ts ./unit/evmFamilyStepUpProvisionPlan.unit.test.ts ./unit/ecdsaMaterialState.unit.test.ts ./unit/signingEngine.refactor37.guard.unit.test.ts --reporter=line`
        passed 74 tests after ready material resolution became record-only and
        `ecdsaMaterialState.ts` stopped deriving key refs for readiness checks.
        `pnpm -C tests exec playwright test ./unit/evmFamilyEcdsaIdentity.unit.test.ts ./unit/signingEngine.refactor37.guard.unit.test.ts --reporter=line`
        passed 68 tests after deleting the old paired key-ref readiness helper.
        `pnpm -C tests exec playwright test ./unit/warmSessionEcdsaProvisioning.unit.test.ts ./unit/warmSessionStore.reconnect.unit.test.ts ./unit/warmSessionStore.concurrency.unit.test.ts ./unit/warmSessionStore.transitions.unit.test.ts ./unit/warmSessionStore.errorNormalization.unit.test.ts ./unit/signingEngine.refactor37.guard.unit.test.ts --reporter=line`
        passed 59 tests after the ready-material resolver and warm provisioner
        record-candidate changes were combined.
        `pnpm -C tests exec playwright test ./unit/ecdsaExportMaterial.unit.test.ts ./unit/emailOtpOperationSplit.guard.unit.test.ts ./unit/signingEngine.refactor37.guard.unit.test.ts --reporter=line`
        passed 52 tests after export/email-OTP guards were updated for
        record-share readiness checks.
        `pnpm -s type-check:sdk` passed after making warm provisioner
        record-candidate lookup required.
        `pnpm -C tests exec playwright test ./unit/ecdsaExportMaterial.unit.test.ts ./unit/emailOtpOperationSplit.guard.unit.test.ts ./unit/signingEngine.refactor37.guard.unit.test.ts --reporter=line`
        passed 52 tests after updating the provisioner guard for required
        record-candidate lookup.
        `pnpm -C tests exec playwright test ./unit/warmSessionEcdsaProvisioning.unit.test.ts ./unit/warmSessionStore.reconnect.unit.test.ts ./unit/warmSessionStore.concurrency.unit.test.ts ./unit/warmSessionStore.transitions.unit.test.ts ./unit/warmSessionStore.errorNormalization.unit.test.ts ./unit/signingEngine.refactor37.guard.unit.test.ts --reporter=line`
        passed 59 tests after exact-record refresh lookup moved through the
        named source-fallback helper.
        `pnpm -s type-check:sdk` passed after signing-flow runtime fallback
        material moved from key refs to session records.
        `pnpm -C tests exec playwright test ./unit/signingFlow.readySigner.unit.test.ts ./unit/evmSigning.thresholdReconnectEvents.unit.test.ts ./unit/signingEngine.refactor37.guard.unit.test.ts --reporter=line`
        passed 39 tests after fallback ready secp256k1 material construction
        moved to a record handoff at the runtime boundary.
        `pnpm -s type-check:sdk` passed after export material stopped looking
        up key refs for cached HSS artifacts.
        `pnpm -C tests exec playwright test ./unit/ecdsaExportMaterial.unit.test.ts ./unit/signingEngine.refactor37.guard.unit.test.ts --reporter=line`
        passed 42 tests after ready export material began reading cached HSS
        artifacts directly from `exportArtifactsByLane`.

## Tests

Add unit and integration coverage for:

- WebAuthn registration challenge binds the normalized signer selection,
  including default combined Ed25519+ECDSA provisioning for the passkey/NEAR
  wrappers.
- WebAuthn registration challenge binds explicit `ed25519_only` signer
  selection when ECDSA provisioning is disabled.
- WebAuthn registration challenge binds `ecdsa_only` signer selection.
- WebAuthn registration challenge binds `ed25519_and_ecdsa` signer selection.
- Ed25519-only registration creates no ECDSA records.
- ECDSA-only registration creates no NEAR account.
- Combined registration creates both signer families from one WebAuthn `create()` verification.
- ECDSA initial registration rejects threshold-session auth tokens.
- Ed25519 initial registration rejects threshold-session auth tokens.
- Registration HSS respond/finalize rejects signer kinds absent from the stored ceremony.
- Ed25519 registration HSS respond accepts only server-visible client request
  messages.
- Ed25519 registration HSS finalize accepts only client-owned staged evaluator
  artifacts.
- Later ECDSA add-signer succeeds from an Ed25519-only wallet with WebAuthn `get()`.
- Later Ed25519 add-signer succeeds from an ECDSA-only wallet with WebAuthn `get()`.
- Ed25519-only unlock provisions no ECDSA signing session.
- ECDSA-only unlock provisions no Ed25519 signing session and requires no NEAR
  account.
- Combined unlock provisions both signer families without cross-family auth
  dependencies.
- ECDSA unlock key-facts inventory uses wallet/authenticator authority or an
  explicit app-session policy. Ed25519 threshold-session auth is rejected for
  inventory.
- App-session add-signer requires an explicit signer-provisioning policy.
- Deleted registration continuation token names are absent from production code.

## Decisions Locked For Implementation

- Wallet subject id source: `/wallets/register/intent` allocates or reserves it
  before WebAuthn and returns the exact intent to challenge-bind.
- Ed25519 later behavior: add-signer supports explicit
  `create_near_account` and `link_existing_near_account` sub-modes with
  branch-specific required fields.
- Runtime storage layout: add new wallet subject, wallet authenticator, wallet
  signer, registration intent, and registration ceremony tables.
- ECDSA development data cleanup: prune incomplete active rows through a
  one-shot maintenance path outside login/unlock.
- ECDSA key-facts repair inventory: use the wallet-subject inventory endpoint
  with WebAuthn or app-session policy authority.

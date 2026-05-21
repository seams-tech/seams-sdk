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

`walletSubjectId` is the sole wallet subject identifier in registration,
signer records, unlock, warm-up, and persistence-domain types. Do not add an
ECDSA-specific subject field to core types. If a cryptographic protocol or wire
endpoint still uses subject wording, the boundary adapter should project
`walletSubjectId` into that field and immediately normalize responses back to
wallet-subject types.

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
  and registration metering context. `/wallets/register/start` is a public
  proof route whose authority is the exact `registrationIntentGrant` plus the
  WebAuthn `create()` credential for the matching digest.
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
    }
  | {
      mode: 'link_existing_near_account';
      nearAccountId: string;
      signerSlot: number;
      participantIds: NonEmptyParticipantIds;
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
- `seams.near.registerNearWallet(...)` as a small wrapper around `registerWallet({ signerSelection: { mode: 'ed25519_only', ... } })`
- `seams.evm.registerEvmWallet(...)` as a small wrapper around `registerWallet({ signerSelection: { mode: 'ecdsa_only', ... } })`

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
- `server/src/router/cloudflare/createCloudflareRouter.ts`
  - Mount the new Cloudflare registration and add-signer route handlers.
  - Remove the Cloudflare dispatch for the obsolete registration bootstrap handlers.
- `server/src/router/relayRegistrationBootstrap.ts`
  - Delete the continuation-token response path.
  - Move reusable NEAR account creation pieces behind Ed25519 signer creation helpers.
  - Delete this handler in the same refactor that moves `registerNearWallet` to `/wallets/register/*`.
- `server/src/router/relayRegistrationThresholdEd25519Hss.ts`
  - Fold Ed25519 registration HSS into the new multi-signer ceremony.
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
  - Delete registration-continuation authorization branches.
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
  - Convert `registerPasskey` into the Ed25519 wrapper.
  - Add `near.registerNearWallet(...)` and `evm.registerEvmWallet(...)` wrappers if exposed as modules.
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
  - Keep reusable managed-grant transport helpers if the new route grant flow still needs them.
- `client/src/core/SeamsPasskey/thresholdWarmSessionBootstrap.ts`
  - Convert Ed25519 registration HSS helpers into per-signer ceremony helpers.
  - Remove per-step managed bootstrap grant calls when the server ceremony takes ownership of route scope.
- `client/src/core/signingEngine/flows/registration/accountLifecycle.ts`
  - Move NEAR account lifecycle work behind Ed25519 signer creation.
  - Keep wallet-subject registration inputs separate from NEAR account inputs.
- `client/src/core/signingEngine/flows/registration/session.ts`
  - Return optional immediate signing-session auth material only after requested signer finalization.
  - Keep registration session state typed by signer-selection mode.
- `client/src/core/signingEngine/threshold/ed25519/hssLifecycle.ts`
  - Keep Ed25519 HSS protocol mechanics reusable for unified registration.
  - Receive resolved registration protocol material from the caller boundary.
- `client/src/core/signingEngine/threshold/ed25519/hssClientBase.ts`
  - Resolve Ed25519 client-base protocol inputs from registration-domain PRF material.
  - Avoid NEAR profile lookups in protocol helpers.
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
  - Keep `registerPasskey` as an Ed25519 wrapper route.
- `client/src/core/WalletIframe/shared/messages.ts`
  - Add wallet-subject registration and add-signer message contracts.
- `client/src/core/WalletIframe/host/wallet-iframe-handlers.ts`
  - Wire wallet iframe handlers to the new SDK registration methods.
- `client/src/core/rpcClients/relayer/thresholdEcdsa.ts`
  - Remove `{ kind: 'registration_continuation' }` from `ThresholdEcdsaHssRouteAuth`.
  - Add wallet registration RPC helpers or move them into a new `walletRegistration.ts` client.
- `client/src/core/signingEngine/uiConfirm/handlers/flows/requestRegistrationCredentialConfirmation.ts`
  - Accept a canonical registration intent instead of only `nearAccountId` and `signerSlot`.
- `client/src/core/signingEngine/uiConfirm/handlers/flows/registration.ts`
  - Compute the WebAuthn `create()` challenge from `RegistrationIntentV1`.
  - Preserve duplicate-credential retry only for signer selections where a retry is valid.
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

### Phase 1: Types And Boundaries

- [ ] Add wallet subject, authenticator binding, signer selection, and ceremony state types in `server/src/core/types.ts` and `client/src/core/SeamsPasskey/interfaces.ts`.
- [ ] Add `CreateRegistrationIntentRequest`,
      `CreateRegistrationIntentResponse`, `RegistrationIntentGrant`, and
      grant-claim types.
- [ ] Add explicit `EcdsaKeyFacts`, `EvmFamilyEcdsaWalletKey`, and
      `EcdsaWalletSignerRecord` types.
- [ ] Add `RegistrationCeremonyStore` state unions for intent allocation,
      started ceremonies, HSS-responded ceremonies, finalizing ceremonies,
      completed ceremonies, and failed ceremonies.
- [ ] Add `WalletKeyFactsInventoryAuth` and
      `EcdsaKeyFactsInventoryPolicy` types.
- [ ] Remove ECDSA subject fields from registration, signer-record, unlock,
      warm-up, and persistence-domain types; use `walletSubjectId` as the
      single subject identifier.
- [ ] Split raw `keyHandle` boundary parsing from ECDSA `keyFacts` parsing.
- [ ] Make core resolved active-key flows consume `EvmFamilyEcdsaWalletKey`;
      delete loose `keyHandle` and peer-field `keyFacts` inputs.
- [ ] Add raw request normalizers for registration intent, wallet registration,
      add-signer, and ECDSA key-facts inventory flows.
- [ ] Add canonical `RegistrationIntentV1` and add-signer digest helpers in `client/src/utils/intentDigest.ts`.
- [ ] Add server-side digest verification helpers for the same intent encodings.
- [ ] Add architecture guards against optional lifecycle signer fields in registration core types.
- [ ] Add architecture guards that reject `ecdsaThresholdKeyId`,
      `signingRootId`, or `signingRootVersion` derivation from `keyHandle`.
- [ ] Add client lifecycle-plan builders for any registration/add-signer path that creates warm-session or signer-provisioning material.
- [ ] Keep registration client imports aligned with `docs/refactor-33.md`; avoid resurrecting deleted `threshold/workflows/*`, `threshold/session/*`, `api/*`, or `orchestration/*` paths.
- [ ] Keep session ownership aligned with `docs/refactor-35-sealed-recovery.md`; use `session/passkey/*`, `session/emailOtp/*`, `session/warmCapabilities/*`, and `session/operationState/*` according to owner.
- [ ] Keep lifecycle input types aligned with `docs/refactor-36.md`; use branch-specific required fields and `never` exclusions for invalid auth combinations.
- [ ] Update exports in `client/src/index.ts`, `client/src/react/index.ts`, and `client/src/react/types.ts`.

### Phase 2: Server Ceremony

- [ ] Add `/wallets/register/intent`, `/wallets/register/start`,
      `/wallets/register/hss/respond`, and `/wallets/register/finalize` route
      definitions in `server/src/router/routeDefinitions.ts`.
- [ ] Add Express and Cloudflare route modules for the new registration ceremony.
- [ ] Add `RegistrationCeremonyStore` implementations.
  - [ ] Memory store for tests and local single-process development.
  - [ ] Postgres store for Express production.
  - [ ] Cloudflare Durable Object store for Worker production.
- [ ] Add wallet-subject registration service methods in `server/src/core/AuthService.ts`.
- [ ] Add `/wallets/register/intent` service method.
  - [ ] Resolve runtime policy scope from API key, bootstrap token, or managed
        grant context.
  - [ ] Allocate or reserve `walletSubjectId`.
  - [ ] Create and persist a one-use registration intent grant.
  - [ ] Return `RegistrationIntentV1` and its canonical digest.
- [ ] Make `/wallets/register/start` verify and consume the
      `registrationIntentGrant` before ceremony creation.
- [ ] Verify WebAuthn `create()` once, then store normalized signer selection on the ceremony record.
- [ ] Prepare Ed25519 and ECDSA HSS state from the same verified registration context.
- [ ] Run independent Ed25519 and ECDSA HSS preparation concurrently where the runtime allows it.
- [ ] Finalize requested signer material and persist wallet subject, authenticator binding, and signer records.
- [ ] Gate NEAR account creation behind Ed25519 signer finalization.
- [ ] Persist ECDSA signer metadata without requiring a NEAR account or NEAR profile continuity.
- [ ] Run exactly one ECDSA HSS keygen per `EcdsaRegistrationSpec`, then create
      one active signer record per requested `chainTarget` carrying the shared
      `EvmFamilyEcdsaWalletKey`.
- [ ] Make ECDSA registration/add-signer finalization produce a complete
      `EvmFamilyEcdsaWalletKey` for every requested chain target before any
      signer record is marked active.
  - [ ] Persist the exact `keyHandle` returned by the ECDSA key server.
  - [ ] Persist canonical `ecdsaThresholdKeyId`, `signingRootId`,
        `signingRootVersion`, threshold public key, owner address, and
        participant ids as `walletKey.keyFacts` in the same active signer record.
  - [ ] Reject finalize if `keyHandle` or `keyFacts` are incomplete; leave the
        ceremony failed/pending instead of writing a partial active signer.
  - [ ] Return the same complete wallet-key facts in the finalize response.
- [ ] Add Postgres schema changes in `server/src/storage/postgres.ts`.
  - [ ] Add wallet subject, authenticator, signer, registration intent, and
        registration ceremony tables.
  - [ ] Add unique signer indexes and expiry indexes.
  - [ ] Ensure ceremony finalize consumes the ceremony atomically.

### Phase 3: Client Flow

- [ ] Add `registerWallet(args)` in `client/src/core/SeamsPasskey/index.ts`.
- [ ] Replace NEAR-first orchestration in `client/src/core/SeamsPasskey/registration.ts`.
- [ ] Build signer selection from explicit user options.
- [ ] Resolve `RegisterWalletSubjectInput` through `/wallets/register/intent`
      before collecting a WebAuthn credential.
- [ ] Update WebAuthn confirmation to accept canonical registration intent inputs.
- [ ] Compute WebAuthn `create()` challenge from the returned
      `RegistrationIntentV1` and verify local digest parity before prompting.
- [ ] Derive Ed25519 and ECDSA PRF inputs with domain-separated labels.
- [ ] Run selected signer HSS work inside the combined registration ceremony.
- [ ] Route Ed25519 protocol work through `threshold/ed25519/*` and ECDSA protocol work through `threshold/ecdsa/*`.
- [ ] Keep warm-session persistence in `session/warmCapabilities/*` after signer records exist.
- [ ] Keep passkey PRF handling and passkey-origin session provisioning in `session/passkey/*`.
- [ ] Keep generic warm-capability read/status transitions in `session/warmCapabilities/*`.
- [ ] Emit progress events for per-signer prepare/finalize states.
- [ ] Persist returned signer refs under wallet subject identity.
- [ ] Persist complete returned `EvmFamilyEcdsaWalletKey` objects into
      wallet-subject signer records and any profile projection consumed by
      unlock.
- [ ] Add client write-time invariants that reject active ECDSA signer records
      missing `keyHandle`, required `keyFacts`, public facts, owner address,
      participant ids, or concrete `chainTarget`.
- [ ] Remove registration/finalize client code that writes only target intent,
      `ecdsaThresholdKeyId`, signing root facts, or key refs without the
      resolved server selector.
- [ ] Wire React context and SDK flow tracking to the new registration API.
- [ ] Wire WalletIframe message contracts and handlers to `registerWallet` and `addWalletSigner`.

### Phase 4: Independent Wallet Unlock

- [ ] Add signer-selection unlock input types for Ed25519-only, ECDSA-only, and
      combined unlock.
- [ ] Extract wallet-unlock ECDSA planning from `login.ts` into a pure planner
      module.
  - [ ] Create an `unlockEcdsaWarmupPlanner.ts` boundary that accepts only
        normalized ECDSA signer records, configured ECDSA targets, local ECDSA
        session records, current session facts, and runtime config.
  - [ ] Make the planner return a closed discriminated union:
        `no_configured_ecdsa_targets`, `ready`,
        `awaiting_authenticated_key_facts_inventory`, `repair_required`, and
        `blocked`.
  - [ ] Delete `needs_ed25519_inventory` naming. The state is about missing
        authenticated ECDSA key facts, not about Ed25519.
  - [ ] Keep `blocked` branch reasons explicit:
        `missing_key_handle`, `ambiguous_key_handle`,
        `missing_chain_target`, `synthetic_legacy_key_id`,
        `missing_key_facts`, and `invalid_signer_record`.
  - [ ] Keep the normal active-signer unlock path local-only. If all active
        signer records contain complete `EvmFamilyEcdsaWalletKey` facts, the
        planner must return `ready` without calling
        `/threshold-ecdsa/key-identities`.
  - [ ] Use `awaiting_authenticated_key_facts_inventory` only when the user
        selected an explicit repair/recovery mode or the caller supplied a
        policy that permits ECDSA key-facts inventory reads.
- [ ] Normalize active ECDSA signer metadata once at the signer-record/profile
      boundary.
  - [ ] Add a parser that converts raw profile signer metadata into
        `ActiveEcdsaSignerRecord` or a blocked signer-record reason.
  - [ ] Require active ECDSA signers to carry exact
        `EvmFamilyEcdsaWalletKey` and concrete `chainTarget`.
  - [ ] Treat missing direct `keyHandle` as invalid after registration/add-signer
        finalize writes complete wallet keys.
  - [ ] Accept `EcdsaKeyFacts` only when all required facts are present;
        otherwise emit a blocked reason without partial objects.
  - [ ] Reject active signer records that require deriving `keyHandle` from
        `keyFacts`. Use explicit data pruning or one-shot
        maintenance outside login for current development rows.
  - [ ] Remove direct reads of raw `metadata` bags from the unlock hot path.
- [ ] Split unlock/login execution into typed phases.
  - [ ] Phase 1: read and normalize wallet subject, authenticator, and signer
        records.
  - [ ] Phase 2: build independent Ed25519 and ECDSA unlock plans from
        `WalletUnlockSelection`.
  - [ ] Phase 3: preflight ECDSA blocked states before mutating volatile
        session material.
  - [ ] Phase 4: acquire wallet/authenticator auth only for plans that require
        authenticated key-facts inventory.
  - [ ] Phase 5: resolve deferred ECDSA inventory only for explicit
        repair/recovery plans using the preflighted key-target request list.
  - [ ] Phase 6: clear volatile warm material only after requested signer-family
        plans are ready or conclusively absent.
  - [ ] Phase 7: provision requested Ed25519 and ECDSA signing sessions from
        their independent ready plans.
  - [ ] Make each phase consume the prior phase's narrow union instead of the
        broad login context.
- [ ] Move the ECDSA key-facts inventory parser out of `login.ts`.
  - [ ] Create a boundary parser for
        `/wallets/:walletSubjectId/signers/ecdsa/key-facts/inventory`
        responses.
  - [ ] Require `keyHandle`, concrete `chainTarget`,
        `ecdsaThresholdKeyId`, `signingRootId`, `signingRootVersion`,
        participant ids, owner address, and public facts.
  - [ ] Reject synthetic legacy ids, missing key handles, mismatched wallet ids,
        mismatched rp ids, and owner-address drift at the parser boundary.
  - [ ] Return exact `EvmFamilyEcdsaWalletKey` entries keyed by concrete
        target; downstream unlock logic must not inspect raw response records.
- [ ] Tighten lifecycle request state around ECDSA signing-session operation
      selection.
  - [ ] Split ECDSA registration/add-signer requests from ECDSA exact-session
        warm-up requests at the type level.
  - [ ] Make exact-session warm-up consume a branch with
        `EvmFamilyEcdsaWalletKey` and lane policy already resolved.
  - [ ] Encode server operation from lifecycle state:
        registration/add-signer branches emit registration ceremony operations;
        existing-key activation and recovery branches emit `session_bootstrap`.
  - [ ] Keep auth proof envelopes inside the selected lifecycle branch.
  - [ ] Remove optional fields that permit exact activation to degrade into
        target-based registration.
- [ ] Add static and unit coverage for independent unlock.
  - [ ] Type fixtures reject broad object-spread construction of unlock plans,
        raw profile metadata in core planner inputs, activation without
        `EvmFamilyEcdsaWalletKey`, activation with `keyIntent`, and
        registration/add-signer requests with exact-session fields.
  - [ ] Unit tests cover Ed25519-only unlock, ECDSA-only unlock, combined
        unlock, no configured ECDSA targets, ready local ECDSA records,
        authenticated inventory fetch, missing key handle, synthetic legacy id,
        ambiguous key handle, parser rejection, and inventory owner drift.
  - [ ] Add a mutation-ledger test proving blocked and inventory-deferred ECDSA
        plans do not call `clearVolatileWarmSigningMaterial` before all exact
        ECDSA warm-up inputs are resolved.
  - [ ] Add a guard test that prevents raw profile `metadata` reads and raw
        inventory response records from re-entering the unlock execution path.

### Phase 5: Add-Signer Flow

- [ ] Add `/wallets/:walletSubjectId/signers/start`, `/wallets/:walletSubjectId/signers/hss/respond`, and `/wallets/:walletSubjectId/signers/finalize`.
- [ ] Add verified add-signer auth boundary in `server/src/core/ThresholdService/ThresholdSigningService.ts`.
- [ ] Verify WebAuthn `get()` against a server-issued add-signer challenge.
- [ ] Enforce app-session signer-provisioning policy for app-session add-signer flows.
- [ ] Reject threshold-session auth tokens for signer creation.
- [ ] Add client `addWalletSigner(args)`.
- [ ] Persist newly attached signer records without re-registering the authenticator.
- [ ] Cover later ECDSA from Ed25519-only wallets and later Ed25519 from ECDSA-only wallets.
- [ ] Add `/wallets/:walletSubjectId/signers/ecdsa/key-facts/inventory` after
      add-signer auth policy helpers are in place.
- [ ] Verify inventory WebAuthn `get()` against a challenge digest that includes
      wallet subject id, RP ID, chain targets, known key handles, runtime policy
      scope, and server nonce.
- [ ] Enforce `ecdsa_key_facts_inventory` app-session policy for app-session
      repair inventory flows.

### Phase 6: Cleanup

- [ ] Delete `registrationContinuation` request and response types from `server/src/core/types.ts`.
- [ ] Delete `signRegistrationContinuationJwt` from `server/src/router/commonRouterUtils.ts`.
- [ ] Delete old managed bootstrap grant targets after `/wallets/register/intent`
      replaces `/registration/bootstrap`.
- [ ] Delete all production construction of synthetic
      `legacy-key-handle:*` ECDSA key ids.
- [ ] Delete any production fallback that fills `signingRootId` or
      `signingRootVersion` from `keyHandle`.
- [ ] Delete login/profile-boundary derivation of `keyHandle` from
      `ecdsaThresholdKeyId + signingRootId + signingRootVersion`.
- [ ] Delete normal-unlock inventory fetches. Keep `/threshold-ecdsa/key-identities`
      usage only until the wallet-subject inventory endpoint is live.
      Explicit repair/recovery flows should use the wallet-subject inventory
      endpoint.
- [ ] Keep request/persistence boundary parsing strict for active ECDSA wallet
      keys: direct `keyHandle` is required, synthetic legacy selectors are
      rejected, and incomplete active rows are invalid.
- [ ] Delete registration-continuation claim parsing from threshold validation.
- [ ] Delete continuation-token generation from `server/src/router/relayRegistrationBootstrap.ts`.
- [ ] Delete `provisionThresholdEcdsaAfterRegistration` from `client/src/core/SeamsPasskey/registration.ts`.
- [ ] Delete `{ kind: 'registration_continuation' }` from `client/src/core/rpcClients/relayer/thresholdEcdsa.ts`.
- [ ] Delete raw `threshold_ecdsa.client_root_share32_b64u` registration support from server and client code.
- [ ] Delete `/registration/bootstrap` and `/registration/threshold-ed25519/hss/*` routes in the same refactor that moves wrappers to `/wallets/register/*`.
- [ ] Delete mixed paths that derive ECDSA authority from Ed25519 threshold-session auth tokens.
- [ ] Delete any stale client imports that reference the removed threshold workflows path family.
- [ ] Delete any stale client imports that reference removed `session/warmSigning/*`, `session/signingSession/*`, `sessionEmailOtp/*`, or `touchConfirm/*` paths.
- [ ] Delete any internal registration or add-signer helper that infers lifecycle route from optional auth fields.
- [ ] Rename threshold signing-session auth fields to opaque auth-token names as covered by `docs/signing-session-architecture/threshold-session-auth-token.md`.
- [ ] Update route definitions, architecture guards, and tests so deleted continuation symbols are absent from production code.
- [ ] Add a one-shot development maintenance path that prunes active ECDSA
      signer rows missing direct `keyHandle` or complete `keyFacts`; keep it
      outside normal login and unlock.

### Phase 7: Test And Verification

- [ ] Add unit tests for registration intent digest canonicalization.
- [ ] Add unit tests for registration intent allocation and grant replay
      rejection.
- [ ] Add unit tests for registration signer-selection normalization.
- [ ] Add relayer tests for the three initial registration modes.
- [ ] Add relayer tests for `/wallets/register/intent` environment binding,
      origin binding, and metering context.
- [ ] Add relayer tests that ECDSA-only registration creates no NEAR account.
- [ ] Add relayer tests that combined registration verifies WebAuthn `create()` once.
- [ ] Add relayer tests that one ECDSA HSS keygen creates shared wallet-key facts
      across all requested EVM-family chain targets.
- [ ] Add tests that fake object-shaped WebAuthn auth fails add-signer preparation.
- [ ] Add tests that ECDSA repair inventory rejects Ed25519 threshold-session
      auth and accepts WebAuthn/app-session inventory policy.
- [ ] Add client tests for `registerWallet`, `registerNearWallet`, and `registerEvmWallet`.
- [ ] Add client tests for Ed25519-only, ECDSA-only, and combined wallet unlock.
- [ ] Add an unlock regression test proving active ECDSA signer rows with
      complete `EvmFamilyEcdsaWalletKey` do not trigger key-facts inventory
      fetches.
- [ ] Add a strict-parser test proving active ECDSA signer rows missing direct
      `keyHandle` are rejected.
- [ ] Add ECDSA key-facts inventory parser unit tests.
- [ ] Add ECDSA bootstrap lifecycle type fixtures.
- [ ] Run `tests/unit/signingEngine.refactor33.guard.unit.test.ts` after client registration moves.
- [ ] Run `tests/unit/signingEngine.refactor36.guard.unit.test.ts` after registration/add-signer lifecycle type changes.
- [ ] Run unlock/login threshold warm-session tests after independent unlock
      planning moves.
- [ ] Run `tests/unit/sealedRecovery.methodAdapters.unit.test.ts` if registration changes sealed recovery or warm-session persistence inputs.
- [ ] Add cleanup tests that production code contains no `registrationContinuation` or `registration_continuation` symbols.

### Phase 8: ECDSA Active Wallet Key Cleanup

This phase finishes the remaining Refactor 39 cleanup work under the
`EvmFamilyEcdsaWalletKey` model.

- [ ] Retire `ThresholdEcdsaSecp256k1KeyRef` from core signing, unlock,
      warm-capability planning, and operation-dependency surfaces.
  - [ ] Keep `ThresholdEcdsaSecp256k1KeyRef` construction and consumption inside
        explicit boundary adapters such as signer transport, persistence
        normalization, worker transport, and external SDK compatibility edges.
  - [ ] Move EVM-family signing flow modules to consume
        `EvmFamilyEcdsaWalletKey` plus branch-specific ready signing material.
  - [ ] Move warm-capability provision plans to carry
        `EvmFamilyEcdsaWalletKey` for resolved active keys.
  - [ ] Replace operation-dependency callbacks that return key refs with
        callbacks returning resolved active wallet keys or ready signing
        material.
  - [ ] Add guard coverage that blocks direct
        `ThresholdEcdsaSecp256k1KeyRef` imports from core signing, unlock,
        warm-capability, and operation-state modules.
- [ ] Move active ECDSA profile-continuity parsing out of
      `client/src/core/SeamsPasskey/login.ts`.
  - [ ] Add a boundary parser for raw profile signer metadata.
  - [ ] Return a discriminated result:
        `active_wallet_key`, `repair_required`, or `blocked`.
  - [ ] Make `active_wallet_key` carry `EvmFamilyEcdsaWalletKey` and concrete
        `ThresholdEcdsaChainTarget`.
  - [ ] Keep synthetic `legacy-key-handle:*`, missing key handles, missing
        `keyFacts`, missing chain targets, and ambiguous signer metadata as
        blocked parser results.
  - [ ] Delete any branch that derives `keyHandle` from `keyFacts` in login,
        unlock planning, profile parsing, or active signer normalization.
  - [ ] Make login consume parser results only; login must not inspect raw
        profile metadata fields directly.
- [ ] Move authenticated ECDSA key-facts inventory out of normal login.
  - [ ] Introduce an explicit repair/recovery entrypoint for inventory reads.
  - [ ] Require wallet/authenticator authority or app-session policy for repair
        inventory.
  - [ ] Keep normal unlock latency local-only when active signer records are
        complete.
- [ ] Clean Postgres ECDSA key-store shared-key lookup shape.
  - [ ] Replace JSON-expression shared-key indexes on
        `threshold_ecdsa_keys.record_json` with current-schema columns or a
        deleted lookup if the invariant is covered by key-handle and key-facts
        uniqueness.
  - [ ] Replace shared-key conflict queries that read
        `record_json->>'walletSessionUserId'`, `record_json->>'subjectId'`, and
        `record_json->>'rpId'` with typed indexed columns or explicit boundary
        validation.
  - [ ] Keep `record_json` as serialized record payload only. Current lookup,
        uniqueness, and conflict checks should use declared columns.
  - [ ] Update Postgres key-store tests so startup still has no prune/backfill
        path and shared-key checks exercise the current schema.
- [ ] Update stale Refactor 39 naming and docs.
  - [ ] Replace completed-plan references to `needs_ed25519_inventory` with the
        domain name `awaiting_authenticated_key_facts_inventory`.
  - [ ] Add a short Refactor 39 completion note pointing remaining active-key
        cleanup to this phase.
- [ ] Add focused validation for this cleanup phase.
  - [ ] Run the ECDSA key-facts unit tests.
  - [ ] Run login threshold warm-session tests.
  - [ ] Run Postgres key-store tests.
  - [ ] Run SDK type-check after key-ref surface changes.

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

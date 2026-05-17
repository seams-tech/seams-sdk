# Rework Registration Flows

## Goal

Registration should support three first-class modes with one WebAuthn `create()` credential:

- Ed25519 only.
- ECDSA only.
- Ed25519 and ECDSA together.

Later signer creation should use a fresh WebAuthn `get()` assertion or an explicitly approved app-session policy. Initial registration should not require a threshold-session auth token, an Ed25519 session token, or a registration continuation JWT to create ECDSA key material.

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
- Persists ECDSA signer metadata only when ECDSA is requested.
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
- Unique `(walletSubjectId, kind, chainTarget, ecdsaThresholdKeyId)` for ECDSA
  lane/session records.
- Unique ECDSA public key and owner address indexes within runtime scope.
- Funds-safety invariant: EVM SIGNERS MUST ALL SHARE THE SAME ADDRESS for the
  same wallet subject, RP, signing root, and key version. Registration may write
  separate Tempo/EVM lane records, but those records must carry one shared
  `ecdsaThresholdKeyId`, threshold public key, and owner address.

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
- Wallet/account auth policy lives under `client/src/core/signingEngine/walletAuth`.
- Operation code should depend on `stepUpConfirmation/*`, `threshold/*`, and `session/*` by direct owner imports. Do not add `threshold/workflows/*`, `threshold/session/*`, `api/*`, or `orchestration/*` paths.
- Concrete registration prompt routing lives under `uiConfirm/*`.
- Registration-adjacent session work must use discriminated lifecycle plans. Do not pass broad optional bags containing `thresholdSessionAuth?`, `webauthnAuthentication?`, `clientRootShare32B64u?`, `thresholdSessionId?`, or `walletSigningSessionId?` through internal registration, add-signer, warm-capability, or session-provisioning code.
- `tests/unit/signingEngine.refactor33.guard.unit.test.ts` must stay green while registration code moves.
- `tests/unit/signingEngine.refactor36.guard.unit.test.ts` must stay green while registration and signer-provisioning lifecycle types move.

## Current Code Touchpoints

Server files to edit:

- `server/src/router/routeDefinitions.ts`
  - Add route definitions for `/wallets/register/*` and `/wallets/:walletSubjectId/signers/*`.
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
  - Replace grant targets for `/registration/bootstrap` and `/registration/threshold-ed25519/hss/*` with the new `/wallets/register/*` targets.

Server core files to edit:

- `server/src/core/AuthService.ts`
  - Introduce wallet-subject registration service methods.
  - Extract NEAR account provisioning as an Ed25519 signer side effect.
  - Delete `createAccountAndRegisterUser` as the primary registration implementation.
  - Delete the raw `threshold_ecdsa.client_root_share32_b64u` registration path.
- `server/src/core/types.ts`
  - Replace `CreateAccountAndRegisterRequest` and `CreateAccountAndRegisterResult` with wallet registration request/result types.
  - Add explicit registration ceremony state types and signer-selection types.
  - Remove `registrationContinuation` result types.
- `server/src/core/ThresholdService/ThresholdSigningService.ts`
  - Add a verified add-signer policy boundary for WebAuthn `get()` and app-session auth.
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
  - Add `wallet_subjects`, `wallet_authenticators`, and `wallet_signers`.
  - Add unique indexes for authenticator and signer records.
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
  - Delete `provisionThresholdEcdsaAfterRegistration`.
  - Persist wallet-subject signer records without requiring NEAR profile continuity.
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
- `client/src/core/signingEngine/threshold/ecdsa/hssTransport.ts`
  - Reuse the ECDSA HSS transport for registration and add-signer ceremonies.
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
- `client/src/core/signingEngine/session/passkey/ed25519Provisioner.ts`
  - Provision Ed25519 warm sessions from existing signer records after registration.
- `client/src/core/signingEngine/session/passkey/ed25519SessionProvision.ts`
  - Keep Ed25519 signing-session provisioning separate from Ed25519 signer creation.
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
- [ ] Add raw request normalizers for wallet registration and add-signer flows.
- [ ] Add canonical `RegistrationIntentV1` and add-signer digest helpers in `client/src/utils/intentDigest.ts`.
- [ ] Add server-side digest verification helpers for the same intent encodings.
- [ ] Add architecture guards against optional lifecycle signer fields in registration core types.
- [ ] Add client lifecycle-plan builders for any registration/add-signer path that creates warm-session or signer-provisioning material.
- [ ] Keep registration client imports aligned with `docs/refactor-33.md`; avoid resurrecting deleted `threshold/workflows/*`, `threshold/session/*`, `api/*`, or `orchestration/*` paths.
- [ ] Keep session ownership aligned with `docs/refactor-35-sealed-recovery.md`; use `session/passkey/*`, `session/emailOtp/*`, `session/warmCapabilities/*`, and `session/operationState/*` according to owner.
- [ ] Keep lifecycle input types aligned with `docs/refactor-36.md`; use branch-specific required fields and `never` exclusions for invalid auth combinations.
- [ ] Update exports in `client/src/index.ts`, `client/src/react/index.ts`, and `client/src/react/types.ts`.

### Phase 2: Server Ceremony

- [ ] Add `/wallets/register/start`, `/wallets/register/hss/respond`, and `/wallets/register/finalize` route definitions in `server/src/router/routeDefinitions.ts`.
- [ ] Add Express and Cloudflare route modules for the new registration ceremony.
- [ ] Add wallet-subject registration service methods in `server/src/core/AuthService.ts`.
- [ ] Verify WebAuthn `create()` once, then store normalized signer selection on the ceremony record.
- [ ] Prepare Ed25519 and ECDSA HSS state from the same verified registration context.
- [ ] Run independent Ed25519 and ECDSA HSS preparation concurrently where the runtime allows it.
- [ ] Finalize requested signer material and persist wallet subject, authenticator binding, and signer records.
- [ ] Gate NEAR account creation behind Ed25519 signer finalization.
- [ ] Persist ECDSA signer metadata without requiring a NEAR account or NEAR profile continuity.
- [ ] Add Postgres schema changes in `server/src/storage/postgres.ts`.

### Phase 3: Client Flow

- [ ] Add `registerWallet(args)` in `client/src/core/SeamsPasskey/index.ts`.
- [ ] Replace NEAR-first orchestration in `client/src/core/SeamsPasskey/registration.ts`.
- [ ] Build signer selection from explicit user options.
- [ ] Update WebAuthn confirmation to accept canonical registration intent inputs.
- [ ] Derive Ed25519 and ECDSA PRF inputs with domain-separated labels.
- [ ] Run selected signer HSS work inside the combined registration ceremony.
- [ ] Route Ed25519 protocol work through `threshold/ed25519/*` and ECDSA protocol work through `threshold/ecdsa/*`.
- [ ] Keep warm-session persistence in `session/warmCapabilities/*` after signer records exist.
- [ ] Keep passkey PRF handling and passkey-origin session provisioning in `session/passkey/*`.
- [ ] Keep generic warm-capability read/status transitions in `session/warmCapabilities/*`.
- [ ] Emit progress events for per-signer prepare/finalize states.
- [ ] Persist returned signer refs under wallet subject identity.
- [ ] Wire React context and SDK flow tracking to the new registration API.
- [ ] Wire WalletIframe message contracts and handlers to `registerWallet` and `addWalletSigner`.

### Phase 4: Add-Signer Flow

- [ ] Add `/wallets/:walletSubjectId/signers/start`, `/wallets/:walletSubjectId/signers/hss/respond`, and `/wallets/:walletSubjectId/signers/finalize`.
- [ ] Add verified add-signer auth boundary in `server/src/core/ThresholdService/ThresholdSigningService.ts`.
- [ ] Verify WebAuthn `get()` against a server-issued add-signer challenge.
- [ ] Enforce app-session signer-provisioning policy for app-session add-signer flows.
- [ ] Reject threshold-session auth tokens for signer creation.
- [ ] Add client `addWalletSigner(args)`.
- [ ] Persist newly attached signer records without re-registering the authenticator.
- [ ] Cover later ECDSA from Ed25519-only wallets and later Ed25519 from ECDSA-only wallets.

### Phase 5: Cleanup

- [ ] Delete `registrationContinuation` request and response types from `server/src/core/types.ts`.
- [ ] Delete `signRegistrationContinuationJwt` from `server/src/router/commonRouterUtils.ts`.
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

### Phase 6: Test And Verification

- [ ] Add unit tests for registration intent digest canonicalization.
- [ ] Add unit tests for registration signer-selection normalization.
- [ ] Add relayer tests for the three initial registration modes.
- [ ] Add relayer tests that ECDSA-only registration creates no NEAR account.
- [ ] Add relayer tests that combined registration verifies WebAuthn `create()` once.
- [ ] Add tests that fake object-shaped WebAuthn auth fails add-signer preparation.
- [ ] Add client tests for `registerWallet`, `registerNearWallet`, and `registerEvmWallet`.
- [ ] Run `tests/unit/signingEngine.refactor33.guard.unit.test.ts` after client registration moves.
- [ ] Run `tests/unit/signingEngine.refactor36.guard.unit.test.ts` after registration/add-signer lifecycle type changes.
- [ ] Run `tests/unit/sealedRecovery.methodAdapters.unit.test.ts` if registration changes sealed recovery or warm-session persistence inputs.
- [ ] Add cleanup tests that production code contains no `registrationContinuation` or `registration_continuation` symbols.

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
- Ed25519 later behavior for ECDSA-only wallets: create a new NEAR account, attach to an existing account, or support both as explicit sub-modes.
- Runtime storage layout: new wallet subject tables or normalized records on top of existing identity and signer stores.

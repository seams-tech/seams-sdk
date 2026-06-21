# Refactor 76: Branded Key Version Types

## Goal

Prevent HSS material key versions, ECDSA HSS material key versions, and signing-session seal KEK versions from being interchangeable in TypeScript.

The triggering regression was a `threshold-ed25519-hss-v1` value flowing into a signing-session seal transport that expected the active seal KEK version, such as `kek-s-2026-02-28`. Both values were typed as plain `string` and often named `keyVersion`, so TypeScript could not catch the mistake.

This refactor is intentionally narrow. It only brands the high-risk version fields that cross cryptographic, persistence, or sealing boundaries.

## Version Domains

### Ed25519 HSS Material Version

Meaning: the Ed25519 HSS derivation/material version used by threshold Ed25519 registration, HSS reconstruction, material binding, and worker-material persistence.

Current examples:

- `THRESHOLD_ED25519_SINGLE_KEY_HSS_KEY_VERSION_V1 = 'threshold-ed25519-hss-v1'`
- `EMAIL_OTP_THRESHOLD_ED25519_HSS_KEY_VERSION = 'threshold-ed25519-hss-v1'`
- Registration `thresholdEd25519.keyVersion`
- Ed25519 worker material binding `keyVersion`
- Persisted Ed25519 warm-session record `keyVersion`

Target internal field name:

```ts
ed25519HssKeyVersion: Ed25519HssKeyVersion
```

Boundary wire/persistence field can remain:

```ts
keyVersion: string
```

### ECDSA HSS Material Version

Meaning: the ECDSA HSS signing-root/key-material version used by threshold ECDSA registration/provisioning, role-local material, export, and Router A/B ECDSA metadata.

Current examples:

- `THRESHOLD_ECDSA_HSS_KEY_VERSION_V1 = 'v1'`
- `walletKeyVersion`
- Threshold ECDSA key records and keygen context `keyVersion`

Target internal field names:

```ts
ecdsaHssKeyVersion: EcdsaHssKeyVersion
ecdsaWalletKeyVersion: EcdsaHssKeyVersion
```

Boundary wire/persistence fields can remain:

```ts
keyVersion: string
walletKeyVersion: string
```

### Signing-Session Seal KEK Version

Meaning: the server-side signing-session seal key-encryption-key version used by `/v2/wallet-session/seal/apply-server-seal`, Email OTP unseal, and sealed session transport metadata.

Current examples:

- `SIGNING_SESSION_SEAL_KEY_VERSION`
- `signingSessionSealKeyVersion`
- Shamir3Pass seal adapter `currentKeyVersion`
- Apply/remove server seal response `keyVersion`
- Existing local/test values such as `kek-s-2026-02`

Target internal field name:

```ts
signingSessionSealKeyVersion: SigningSessionSealKeyVersion
```

Boundary wire field can remain:

```ts
keyVersion: string
```

New runtime/config values should use a domain-explicit key ID. Avoid adding new abbreviated values such as `kek-s-*`.

Preferred examples:

```text
signing-session-seal-kek-2026-02-28-r1
signing-session-seal-kek-v1
signing-session-seal-kek-kms-abc123
```

If the backing KMS/HSM exposes a stable key ID, prefer embedding that key ID with the signing-session seal domain prefix:

```text
signing-session-seal-kek-kms-${kmsKeyId}
```

Date-based values are acceptable when the date is the activation or rotation date, but include a rotation suffix (`r1`, `r2`) so same-day rotation is unambiguous.

## Proposed Type Surface

Add a small shared SDK/server type module. Prefer one source used by both packages if dependency direction allows it; otherwise duplicate the tiny definitions with the same names in package-local boundary modules.

```ts
export type Brand<T, Name extends string> = T & { readonly __brand: Name };

export type Ed25519HssKeyVersion = Brand<string, 'Ed25519HssKeyVersion'>;
export type EcdsaHssKeyVersion = Brand<string, 'EcdsaHssKeyVersion'>;
export type SigningSessionSealKeyVersion = Brand<string, 'SigningSessionSealKeyVersion'>;
```

Add second-tier key-material brands where a plain string can cross cryptographic domains:

```ts
export type Ed25519RelayerKeyId = Brand<string, 'Ed25519RelayerKeyId'>;
export type EcdsaRelayerKeyId = Brand<string, 'EcdsaRelayerKeyId'>;

export type Ed25519ClientVerifyingShareB64u = Brand<
  string,
  'Ed25519ClientVerifyingShareB64u'
>;
export type EcdsaClientVerifyingShareB64u = Brand<string, 'EcdsaClientVerifyingShareB64u'>;

export type Ed25519WorkerMaterialKeyId = Brand<string, 'Ed25519WorkerMaterialKeyId'>;
export type Ed25519WorkerMaterialBindingDigest = Brand<
  string,
  'Ed25519WorkerMaterialBindingDigest'
>;
export type Ed25519SealedWorkerMaterialRef = Brand<string, 'Ed25519SealedWorkerMaterialRef'>;
export type Ed25519WorkerMaterialHandle = Brand<string, 'Ed25519WorkerMaterialHandle'>;

export type EcdsaThresholdKeyId = Brand<string, 'EcdsaThresholdKeyId'>;
export type EcdsaKeyHandle = Brand<string, 'EcdsaKeyHandle'>;
export type EcdsaClientAdditiveShareHandle = Brand<string, 'EcdsaClientAdditiveShareHandle'>;

export type SigningSessionSealShamirPrimeB64u = Brand<
  string,
  'SigningSessionSealShamirPrimeB64u'
>;
```

Add parser/builders at system boundaries:

```ts
export function parseEd25519HssKeyVersion(value: unknown): Ed25519HssKeyVersion;
export function parseEcdsaHssKeyVersion(value: unknown): EcdsaHssKeyVersion;
export function parseSigningSessionSealKeyVersion(value: unknown): SigningSessionSealKeyVersion;
```

Parser behavior:

- Trim input.
- Reject empty strings.
- Return branded value only after validation.
- Keep string compatibility only at route, worker, and persistence boundaries.

Do not export unsafe casting helpers from public SDK surfaces.

## Additional Key Material Brands

Version branding fixes the known regression. These adjacent key-material strings should also be branded because they are easy to confuse and appear in material binding, route context, restore records, or worker commands.

### Priority A: Opaque Worker Material Handles

Brand these first after key versions.

- `Ed25519WorkerMaterialHandle`
- `Ed25519SealedWorkerMaterialRef`
- `Ed25519WorkerMaterialKeyId`
- `Ed25519WorkerMaterialBindingDigest`
- `EcdsaClientAdditiveShareHandle`

Why:

- They represent capability-like references to key material.
- A persisted hint, runtime material handle, sealed artifact ref, and binding digest have very different trust properties.
- Several restore bugs become easier to catch if a function cannot accept a `materialHandle` where it needs a `sealedWorkerMaterialRef` or `materialBindingDigest`.

Rule:

- Runtime handles must stay volatile.
- Persisted refs must be parsed from storage.
- Binding digests must only be created by canonical digest builders.
- Core signing code should never accept a raw `string` for these values.

### Priority B: Curve-Specific Public Shares And Relayer Keys

Brand these after opaque handles.

- `Ed25519ClientVerifyingShareB64u`
- `EcdsaClientVerifyingShareB64u`
- `Ed25519RelayerKeyId`
- `EcdsaRelayerKeyId`

Why:

- Ed25519 and ECDSA public/verifying shares have different encodings and lengths.
- `relayerKeyId` currently appears in Ed25519 and ECDSA contexts as a plain string.
- Material binding and Router A/B route context should fail at compile time if an ECDSA relayer key is passed into Ed25519 material binding.

Rule:

- Brand after base64url/format validation.
- Preserve wire field names such as `clientVerifyingShareB64u` and `relayerKeyId`.
- Rename internal fields when useful: `ed25519RelayerKeyId`, `ecdsaRelayerKeyId`.

### Priority C: ECDSA Key Identity Handles

Brand these where they are still plain strings.

- `EcdsaThresholdKeyId`
- `EcdsaKeyHandle`
- `EcdsaWalletKeyFingerprint` if still unbranded in active paths

Why:

- ECDSA has multiple identifiers for the same high-level key domain: key handle, threshold key id, wallet key fingerprint, signing-root binding.
- Passing one of these into another field can select the wrong wallet key or produce misleading restore diagnostics.

Rule:

- Keep route/persistence fields unchanged.
- Parse into branded identifiers before selection, activation, provision, export, or signing.

### Priority D: Signing-Session Seal Parameters

Brand the non-secret seal parameters that move through config and runtime read models.

- `SigningSessionSealShamirPrimeB64u`

Consider branded server-side secret config only at config boundary:

- `SigningSessionSealServerEncryptExponentB64u`
- `SigningSessionSealServerDecryptExponentB64u`

Rule:

- Secret bytes are not made safe by TypeScript brands. If a value is secret and needed in browser signing flows, prefer a Rust/worker-owned handle or one-use authorization capability.
- Brands for server-only secret config are acceptable as config-boundary discipline, but they should not encourage passing raw secrets deeper into application code.

### Values Not In Scope

Do not brand every ID in this slice.

Out of scope unless a concrete bug appears:

- `walletSessionJwt`: use a validated auth material union instead.
- `thresholdSessionId`: this is already being normalized through signing-session identity helpers; improve it with existing session-id brands separately if needed.
- `signingGrantId` as key material: this is not key material and should not be added to the key-material brand set. It is in scope for the shared-budget lifecycle phase below because registration must distinguish "mint a grant" from "reuse the registration grant."
- `signingRootId` and `signingRootVersion`: useful domain IDs, but broader than key material. Treat them as a separate signing-root identity cleanup if they keep causing bugs.
- Raw PRF, recovery-code, mask, HSS share, or additive-share bytes in TypeScript: these should be moved behind worker/WASM boundaries or represented by opaque one-use handles.

## Naming Rules

Core/domain code must not accept a generic `keyVersion` for these three version domains.

Use precise names:

- `ed25519HssKeyVersion`
- `ecdsaHssKeyVersion`
- `ecdsaWalletKeyVersion` when the existing domain concept is wallet-key scoped
- `signingSessionSealKeyVersion`

Allowed `keyVersion` uses:

- Raw route bodies and responses.
- Worker command payloads that mirror generated or Rust wire schemas.
- IndexedDB/server persistence record schemas.
- Compatibility parsers immediately converting raw records into internal branded domain objects.

Disallowed:

- Passing `registered.keyVersion` directly into signing-session seal transport.
- Passing `signingSessionSealKeyVersion` into HSS material binding.
- New internal types named only `{ keyVersion: string }` for Ed25519 HSS, ECDSA HSS, or signing-session seal KEK.
- New signing-session seal KEK config values with abbreviated domain names such as `kek-s-*`.

## Implementation Plan

### 1. Add Branding Types And Boundary Parsers

Create a small key-version type module.

Candidate locations:

- SDK: `packages/sdk-web/src/core/signingEngine/session/keyVersions.ts`
- Server: `packages/sdk-server-ts/src/core/keyVersions.ts`

If there is an existing shared package path that both SDK and server can import without new build churn, use that instead.

Tasks:

- Add `Brand`, `Ed25519HssKeyVersion`, `EcdsaHssKeyVersion`, `SigningSessionSealKeyVersion`.
- Add parser functions for the three brands.
- Add `format*KeyVersionForWire()` only if TypeScript needs explicit string conversion at boundaries. Keep it as a simple identity function returning `string`.
- Add type fixtures proving brands are not assignable to each other.

Acceptance:

- `SigningSessionSealKeyVersion` cannot be passed to a function requiring `Ed25519HssKeyVersion`.
- `Ed25519HssKeyVersion` cannot be passed to a function requiring `SigningSessionSealKeyVersion`.
- Raw `string` cannot be passed into core functions that require any branded key version.

### 2. Brand Ed25519 HSS Internal Paths

Primary files:

- `packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts`
- `packages/sdk-web/src/SeamsWeb/operations/devices/linkDevice.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/provisioning.ts`
- `packages/sdk-web/src/core/types/signer-worker.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/persistence.ts`
- `packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts`

Tasks:

- Change `requireThresholdEd25519WarmSessionKeyVersion()` to return `{ ed25519HssKeyVersion: Ed25519HssKeyVersion }`.
- Change Ed25519 reconstruction args from `keyVersion: string` to `ed25519HssKeyVersion: Ed25519HssKeyVersion`.
- Change Ed25519 material-binding builders to accept `ed25519HssKeyVersion`.
- Convert back to wire `keyVersion` only when calling route/worker/generated command boundaries.
- Keep persisted record field `keyVersion` for IndexedDB compatibility, but normalize it into branded internal values at read boundaries.

Acceptance:

- `refreshDurableThresholdEd25519SealedSessionWithWorkerMaterial()` has no way to receive an Ed25519 HSS key version as a signing-session seal version.
- Ed25519 HSS material binding still serializes the canonical JSON field as `"keyVersion"` so digest compatibility is preserved.
- Existing Ed25519 warm-session and material-restore tests pass.

### 3. Brand Signing-Session Seal KEK Paths

Primary files:

- `packages/sdk-server-ts/src/core/AuthService.ts`
- `packages/sdk-server-ts/src/threshold/session/signingSessionSeal/options.ts`
- `packages/sdk-web/src/core/signingEngine/session/persistence/records.ts`
- `packages/sdk-web/src/core/signingEngine/uiConfirm/UiConfirmManager.ts`
- `packages/sdk-web/src/core/types/secure-confirm-worker.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/capabilityReaderCore.ts`

Tasks:

- Parse `SIGNING_SESSION_SEAL_KEY_VERSION` into `SigningSessionSealKeyVersion` at config boundary.
- Change signing-session seal adapter config from generic `keyVersion`/`currentKeyVersion: string` to `signingSessionSealKeyVersion` internally.
- Keep route response/request field `keyVersion` at HTTP boundary.
- Keep persisted field `signingSessionSealKeyVersion` in records, but parse it into the brand before use.
- Rename local variables named `keyVersion` in seal code to `signingSessionSealKeyVersion`.

Acceptance:

- `createEmailOtpShamirCipher()` cannot accidentally return an Ed25519/ECDSA HSS key version as a seal version.
- SDK `hydrateSigningSession(... transport ...)` cannot accept a generic HSS `keyVersion` where a seal version is expected.
- Existing signing-session seal router tests pass.
- New tests/fixtures use a domain-explicit signing-session seal KEK ID such as `signing-session-seal-kek-test-r1`.

### 4. Brand ECDSA HSS Internal Paths

Primary files:

- `packages/sdk-server-ts/src/core/ThresholdService/ThresholdSigningService.ts`
- `packages/sdk-web/src/core/signingEngine/session/persistence/records.ts`
- `packages/sdk-web/src/core/signingEngine/threshold/ecdsa/activation.ts`
- `packages/sdk-web/src/core/signingEngine/session/passkey/ecdsaRecovery.ts`
- `packages/sdk-web/src/core/signingEngine/routerAb/ecdsaHss/*`

Tasks:

- Change server-side `THRESHOLD_ECDSA_HSS_KEY_VERSION_V1` to `EcdsaHssKeyVersion`.
- Rename internal fields from generic `keyVersion`/`walletKeyVersion` to `ecdsaHssKeyVersion` or `ecdsaWalletKeyVersion`.
- Convert to wire `keyVersion` only at route/store boundaries.
- Keep existing persisted/wire field names where changing them would require storage migration.

Acceptance:

- ECDSA HSS material version cannot be passed as signing-session seal KEK version.
- ECDSA HSS material version cannot be passed as Ed25519 HSS material version.
- ECDSA/Tempo signing and sealed refresh tests pass.

### 5. Preserve ECDSA Provision/Reconnect Lifecycle Separation

Branded key versions do not catch lifecycle bugs by themselves. The ECDSA readiness regression came from applying reconnect identity rules to fresh provision plans.

Keep these branches distinct:

```ts
type EcdsaSessionProvisionPlan =
  | WalletSessionEcdsaReconnect
  | PasskeyEcdsaSessionProvision
  | EmailOtpEcdsaSessionProvision;
```

Rules:

- `wallet_session_ecdsa_reconnect` requires the planned identity to match the existing record identity.
- `passkey_ecdsa_session_provision` and `email_otp_ecdsa_session_provision` use the existing record for key material context and mint a fresh threshold session/signing grant.
- Shared helpers must switch on `plan.kind` and use exhaustive handling.
- Do not infer lifecycle behavior from the presence of an existing record.

Acceptance:

- A type or unit fixture proves fresh ECDSA provision can mint a new session from existing key material.
- A type or unit fixture proves wallet-session reconnect still rejects identity drift.
- Reconnect/provision helpers do not accept a broad plan plus optional identity bag.

### 6. Make ECDSA Lifecycle States Structurally Strict

This phase tightens the ECDSA provision/reconnect model so the old record identity and new session identity cannot be compared by accident.

Current weak pattern:

```ts
function getEcdsaSessionProvisionIdentity(plan: EcdsaSessionProvisionPlan): EcdsaSessionIdentity {
  return 'newSessionIdentity' in plan ? plan.newSessionIdentity : plan.existingSessionIdentity;
}
```

That collapses two different concepts:

- `existingSessionIdentity`: identity already proven by an existing wallet-session JWT/record.
- `newSessionIdentity`: identity minted by fresh step-up provision.

Target model:

```ts
type ExistingEcdsaSessionIdentity = EcdsaSessionIdentity & {
  readonly __brand: 'ExistingEcdsaSessionIdentity';
};

type NewEcdsaSessionIdentity = EcdsaSessionIdentity & {
  readonly __brand: 'NewEcdsaSessionIdentity';
};

type WalletSessionEcdsaReconnect = {
  kind: 'wallet_session_ecdsa_reconnect';
  existingSessionIdentity: ExistingEcdsaSessionIdentity;
  reconnectMaterial: EcdsaReconnectMaterialWithMatchedIdentity;
  walletSessionAuth: VerifiedEcdsaWalletSessionAuth;
  newSessionIdentity?: never;
  provisionSecretSource?: never;
};

type PasskeyEcdsaSessionProvision = {
  kind: 'passkey_ecdsa_session_provision';
  materialSource: EcdsaProvisionMaterialSource;
  newSessionIdentity: NewEcdsaSessionIdentity;
  provisionSecretSource: PasskeyEcdsaProvisionSecretSource;
  existingSessionIdentity?: never;
  walletSessionAuth?: never;
};

type EmailOtpEcdsaSessionProvision = {
  kind: 'email_otp_ecdsa_session_provision';
  materialSource: EcdsaProvisionMaterialSource;
  newSessionIdentity: NewEcdsaSessionIdentity;
  provisionSecretSource: EmailOtpEcdsaProvisionSecretSource;
  existingSessionIdentity?: never;
  walletSessionAuth?: never;
};
```

Provision material source:

```ts
type EcdsaProvisionMaterialSource = {
  kind: 'existing_key_material';
  key: EvmFamilyEcdsaKeyIdentity;
  signingKeyContext: EcdsaSigningKeyContext;
  chainTarget: ThresholdEcdsaChainTarget;
};
```

Rules:

- Reconnect compares record identity against `existingSessionIdentity`.
- Fresh provision uses the old record only for key/material context.
- Fresh provision never compares the old record identity against `newSessionIdentity`.
- Delete or narrow union-wide helpers that erase lifecycle semantics, especially `getEcdsaSessionProvisionIdentity()` and `recordMatchesPlannedIdentity()`.
- Replace boolean lifecycle helpers such as `provisionPlanRequiresExistingRecordIdentity(plan)` with exhaustive `switch (plan.kind)` handling.

Target control flow:

```ts
switch (plan.kind) {
  case 'wallet_session_ecdsa_reconnect':
    return ensureReconnectReady(plan);

  case 'passkey_ecdsa_session_provision':
    return provisionFreshPasskeySession(plan);

  case 'email_otp_ecdsa_session_provision':
    return provisionFreshEmailOtpSession(plan);

  default:
    return assertNever(plan);
}
```

Tasks:

- Add branded `ExistingEcdsaSessionIdentity` and `NewEcdsaSessionIdentity`.
- Add builders that produce these brands only at the correct boundary.
- Change reconnect plan builders to require `ExistingEcdsaSessionIdentity`.
- Change passkey/email provision plan builders to require `NewEcdsaSessionIdentity`.
- Introduce `EcdsaProvisionMaterialSource` so fresh provision does not carry a full reconnect record identity as plan identity.
- Delete or narrow `getEcdsaSessionProvisionIdentity()`.
- Delete union-wide `recordMatchesPlannedIdentity()` and replace it with reconnect-only validation.
- Split shared readiness/provision paths into branch-specific helpers.
- Add exhaustive switches with `assertNever`.

Acceptance:

- `WalletSessionEcdsaReconnect` cannot be built with `newSessionIdentity`.
- `PasskeyEcdsaSessionProvision` and `EmailOtpEcdsaSessionProvision` cannot be built with `existingSessionIdentity`.
- Reconnect identity validation only accepts `WalletSessionEcdsaReconnect`.
- Fresh provision activation only accepts `PasskeyEcdsaSessionProvision | EmailOtpEcdsaSessionProvision`.
- Type fixtures fail if fresh provision plans are passed into reconnect identity validation.
- Unit tests cover:
  - reconnect rejects record/session identity drift.
  - passkey provision mints a new session from existing key material.
  - email OTP provision mints a new session from existing key material.

### 7. Model Shared Signing-Grant Budget Lifecycle

This phase addresses the registration-only budget split where combined Ed25519 + ECDSA registration produced two valid wallet signing budgets:

- ECDSA registration prepared a server-authorized `signingGrantId`.
- Ed25519 warm-session policy later minted a fresh `signingGrantId`.
- Server budget accounting is keyed by `signingGrantId`, so NEAR and ECDSA signers consumed separate `remainingUses` budgets even though product behavior expects one shared wallet signing session.

This is not key material and should not be solved by a simple `SigningGrantId` brand alone. Two different branded `SigningGrantId` values can still be valid. The type needs to encode lifecycle intent: generate a new grant or reuse an existing registration grant.

Target warm-session policy input:

```ts
type ThresholdWarmSessionPolicyDraftInput =
  | {
      kind: 'generated_signing_grant';
      sessionId?: string;
      participantIds?: number[];
      signingGrantId?: never;
      ttlMs?: never;
      remainingUses?: never;
    }
  | {
      kind: 'shared_signing_grant';
      signingGrantId: string;
      ttlMs: number;
      remainingUses: number;
      sessionId?: string;
      participantIds?: number[];
    };
```

Target combined-registration helper:

```ts
type CombinedRegistrationEcdsaBudgetSource = {
  preparedClientBootstrap: WalletRegistrationEcdsaPreparedClientBootstrap;
  bootstrap: WalletRegistrationEcdsaHssRespondBootstrap;
};

function createRegistrationThresholdWarmSessionPolicyDraft(args: {
  context: ThresholdWarmSessionContext;
  participantIds: readonly number[];
  ecdsaSession: CombinedRegistrationEcdsaBudgetSource | null;
}): ThresholdWarmSessionPolicyDraft | null;
```

Concrete implementation shape:

1. Warm-session policy creation gets a discriminated input.

```ts
export type ThresholdWarmSessionPolicyDraftInput =
  | {
      kind: 'generated_signing_grant';
      sessionId?: string;
      participantIds?: number[];
      signingGrantId?: never;
      ttlMs?: never;
      remainingUses?: never;
    }
  | {
      kind: 'shared_signing_grant';
      signingGrantId: string;
      ttlMs: number;
      remainingUses: number;
      sessionId?: string;
      participantIds?: number[];
    };
```

2. The policy builder chooses between minting and reusing the grant.

```ts
const sharedGrant = input.kind === 'shared_signing_grant' ? input : null;
const signingGrantId = sharedGrant
  ? parseSharedSigningGrantId(sharedGrant.signingGrantId)
  : generateSigningGrantId();
```

Implementation notes:

- `shared_signing_grant` must reject empty `signingGrantId`.
- `shared_signing_grant` must reject non-positive `ttlMs`.
- `shared_signing_grant` must reject non-positive `remainingUses`.
- Generated grant call sites should pass `kind: 'generated_signing_grant'` explicitly in the final shape.
- A short transitional slice may keep `kind` optional for existing generated-grant call sites, but the done state requires explicit `kind` on every call.

3. Combined registration converts the ECDSA registration budget into an Ed25519 warm-session policy.

```ts
function createRegistrationThresholdWarmSessionPolicyDraft(args: {
  context: ThresholdWarmSessionContext;
  participantIds: readonly number[];
  ecdsaSession: CombinedRegistrationEcdsaBudgetSource | null;
}): ThresholdWarmSessionPolicyDraft | null {
  const participantIds = [...args.participantIds];
  if (!args.ecdsaSession) {
    return createThresholdWarmSessionPolicyDraft(args.context, {
      kind: 'generated_signing_grant',
      participantIds,
    });
  }

  const clientBootstrap = args.ecdsaSession.preparedClientBootstrap.clientBootstrap;
  const serverBootstrap = args.ecdsaSession.bootstrap;
  if (clientBootstrap.signingGrantId !== serverBootstrap.signingGrantId) {
    throw new Error('combined Ed25519/ECDSA registration has mismatched signing grant');
  }
  if (clientBootstrap.remainingUses !== serverBootstrap.remainingUses) {
    throw new Error('combined Ed25519/ECDSA registration has mismatched signing budget limits');
  }

  return createThresholdWarmSessionPolicyDraft(args.context, {
    kind: 'shared_signing_grant',
    signingGrantId: clientBootstrap.signingGrantId,
    ttlMs: clientBootstrap.ttlMs,
    remainingUses: serverBootstrap.remainingUses,
    participantIds,
  });
}
```

4. The combined registration flow must use the helper at the Ed25519 finalize policy construction point.

```ts
const requestedPolicy = createRegistrationThresholdWarmSessionPolicyDraft({
  context,
  participantIds: hssClientMaterial.hssContext.participantIds,
  ecdsaSession:
    ecdsaPreparedClientBootstrap && ecdsaBootstrap
      ? {
          preparedClientBootstrap: ecdsaPreparedClientBootstrap,
          bootstrap: ecdsaBootstrap,
        }
      : null,
});
```

5. Registration postconditions enforce the invariant after persistence.

```ts
function assertCombinedRegistrationSharedSigningGrant(args: {
  walletId: string;
  inventory: WalletRuntimeInventory;
  expectedEcdsaChainTargets: readonly ThresholdEcdsaChainTarget[];
}): void {
  const ed25519GrantId = requireReadyEd25519SigningGrant(args.inventory);
  for (const chainTarget of args.expectedEcdsaChainTargets) {
    const ecdsaGrantId = requireReadyEcdsaSigningGrant(args.inventory, chainTarget);
    if (ecdsaGrantId !== ed25519GrantId) {
      throw new Error(
        `[Registration][postcondition] combined registration split signing budget for ${args.walletId}`,
      );
    }
  }
}
```

Rules:

- Ed25519-only registration uses `generated_signing_grant`.
- ECDSA-only registration keeps the ECDSA prepare/bootstrap grant.
- Combined Ed25519 + ECDSA registration uses `shared_signing_grant` for the Ed25519 warm-session policy.
- The shared grant must come from the ECDSA registration prepare/bootstrap pair.
- The helper must assert that ECDSA client bootstrap and parsed server bootstrap agree on `signingGrantId`.
- The helper must assert that ECDSA client bootstrap and parsed server bootstrap agree on `remainingUses`.
- Ed25519 and ECDSA keep separate curve-specific `thresholdSessionId` values.
- Ed25519 and ECDSA share the same wallet-level `signingGrantId` when one registration creates both curves.
- Do not infer shared budget from equal TTL, equal account, equal signer slot, or route timing. The shared budget is only established by the explicit `shared_signing_grant` branch.

Registration postcondition:

```ts
function assertCombinedRegistrationSharedSigningGrant(args: {
  walletId: string;
  inventory: WalletRuntimeInventory;
  expectedEcdsaChainTargets: readonly ThresholdEcdsaChainTarget[];
}): void;
```

Postcondition rules:

- Run after combined registration has persisted Ed25519 and ECDSA lanes.
- Read the persisted signing-lane inventory.
- Require the Ed25519 lane to have a `signingGrantId`.
- Require every ECDSA lane created in the same registration to have the same `signingGrantId`.
- Throw a registration postcondition error immediately if the budget is split.
- Do not apply this assertion to ECDSA-only registration.
- Do not apply this assertion to independent add-signer flows unless a product requirement says that add-signer must join an existing wallet budget.

Files:

- `packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts`
- `packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts`
- `packages/sdk-web/src/core/signingEngine/session/postconditions/runtimePostconditions.ts` if the shared-grant check is promoted into a reusable postcondition.
- `tests/unit/thresholdWarmSessionPolicyDraft.unit.test.ts`
- `tests/unit/registrationIntentAllocation.unit.test.ts`

Tasks:

- Change `createThresholdWarmSessionPolicyDraft()` to accept a discriminated input instead of an open optional bag.
- Add the `shared_signing_grant` branch with required `signingGrantId`, `ttlMs`, and `remainingUses`.
- Add the `generated_signing_grant` branch and update generated-grant call sites to pass it explicitly.
- Keep wire/session policy field names unchanged: `thresholdSessionId`, `signingGrantId`, `ttlMs`, `remainingUses`.
- Add `createRegistrationThresholdWarmSessionPolicyDraft()` at the registration orchestration layer.
- Use the ECDSA registration prepare/bootstrap pair as the source for combined-registration Ed25519 `signingGrantId`.
- Add explicit mismatch errors for ECDSA client/server `signingGrantId` and `remainingUses` drift.
- Add a combined-registration postcondition that fails if persisted Ed25519/ECDSA lanes do not share `signingGrantId`.
- Keep `thresholdSessionId` curve-specific. Do not collapse Ed25519 and ECDSA threshold sessions into one ID.
- Keep server budget authority unchanged: server budget reservation/commit/release remains keyed by `signingGrantId`.
- Remove the transitional optional `kind?: 'generated_signing_grant'` once all generated-grant call sites are updated.
- Audit generated-grant call sites:
  - Ed25519-only registration.
  - Ed25519 add-signer.
  - link-device.
  - email recovery.
  - sync-account recovery.

Acceptance:

- A call site cannot pass `signingGrantId`, `ttlMs`, or `remainingUses` into policy creation without selecting `kind: 'shared_signing_grant'`.
- A generated-grant call site cannot omit `kind: 'generated_signing_grant'` in the final state.
- Combined registration finalizes Ed25519 with the same `signingGrantId` returned by ECDSA registration prepare/bootstrap.
- Combined registration persistence fails immediately if Ed25519 and ECDSA lanes have different `signingGrantId` values.
- NEAR, Tempo, and EVM consume the same `remainingUses` budget immediately after combined registration.
- Ed25519-only registration still mints a fresh grant.
- ECDSA-only registration behavior is unchanged.
- Login/wallet-unlock behavior is unchanged.

Tests:

- Unit test: `createThresholdWarmSessionPolicyDraft()` with `shared_signing_grant` preserves `signingGrantId`, `ttlMs`, and `remainingUses` through `buildThresholdWarmSessionRequestEnvelope()`.
- Unit test: combined registration route finalizes Ed25519 with `started.ecdsa.prepare.signingGrantId` and returns an Ed25519 session with that grant.
- Unit or integration test: combined registration postcondition rejects a persisted Ed25519 lane whose `signingGrantId` differs from the ECDSA lane.
- Browser evidence after this phase: fresh registration, then NEAR -> Tempo -> EVM -> NEAR should require step-up on the fourth signing operation globally, not on the fourth NEAR operation.

### 8. Add Static Guards

Add typecheck fixtures near the new key-version module.

Examples:

```ts
declare const ed25519: Ed25519HssKeyVersion;
declare const ecdsa: EcdsaHssKeyVersion;
declare const seal: SigningSessionSealKeyVersion;

acceptEd25519(ed25519);
// @ts-expect-error seal KEK version is not an Ed25519 HSS material version
acceptEd25519(seal);
// @ts-expect-error Ed25519 HSS material version is not a signing-session seal KEK version
acceptSeal(ed25519);
// @ts-expect-error ECDSA HSS material version is not an Ed25519 HSS material version
acceptEd25519(ecdsa);
```

Add source guards:

- Forbid new internal `keyVersion: string` declarations in the three scoped domains.
- Allow `keyVersion` only in files or blocks marked as route/persistence/worker boundary.
- Guard that Ed25519 durable refresh transport does not include HSS `keyVersion`.
- Guard that signing-session seal tests and fixtures use domain-explicit KEK IDs.
- Guard that ECDSA reconnect identity validation is not callable with fresh provision plans.
- Guard that combined registration uses `shared_signing_grant` when both Ed25519 and ECDSA are selected.
- Guard that no combined-registration path calls `createThresholdWarmSessionPolicyDraft()` directly with a generated grant after ECDSA prepare/bootstrap exists.

### 9. Add Second-Tier Key-Material Brands

Do this only after the three key-version brands are in place and green.

Tasks:

- Add brands/parsers for Ed25519 worker material handles, sealed refs, material key IDs, and material binding digests.
- Add curve-specific brands for Ed25519/ECDSA relayer key IDs and client verifying shares.
- Add ECDSA key identity brands where active paths still use plain strings.
- Add a signing-session seal Shamir prime brand at config/read-model boundaries.
- Update function signatures in core signing/session code to require the narrow branded type.
- Keep route, generated worker command, and persistence shapes unchanged.

Acceptance:

- `Ed25519WorkerMaterialHandle` cannot be passed where `Ed25519SealedWorkerMaterialRef` is required.
- `Ed25519WorkerMaterialBindingDigest` cannot be passed where `Ed25519WorkerMaterialKeyId` is required.
- `EcdsaClientVerifyingShareB64u` cannot be passed where `Ed25519ClientVerifyingShareB64u` is required.
- `EcdsaRelayerKeyId` cannot be passed where `Ed25519RelayerKeyId` is required.
- Secret bytes do not gain new raw-string domain paths as a side effect of branding.

### 10. Sequencing

Recommended order:

1. Add brands and parsers with type fixtures.
2. Brand Ed25519 HSS paths first, because this is where the regression occurred.
3. Brand signing-session seal KEK paths next, especially server config and UiConfirm transport.
4. Brand ECDSA HSS paths last.
5. Preserve and test ECDSA reconnect/provision lifecycle separation.
6. Make ECDSA lifecycle states structurally strict.
7. Model shared signing-grant budget lifecycle for combined registration.
8. Add second-tier opaque handle and digest brands.
9. Add curve-specific relayer/verifier brands.
10. Add ECDSA key identity brands.
11. Run focused signing/session tests after each slice.

Avoid broad mechanical renames before the branded parsers exist. The point is to tighten assignability, not to churn every `keyVersion` field in the repo.

## Missing Specs Filled Before Implementation

### Type Module Ownership

Pick the brand module location before changing call sites.

SDK brands should live in a core SDK module used by signing/session code:

```text
packages/sdk-web/src/core/signingEngine/session/keyMaterialBrands.ts
```

Server brands should live in a server core module:

```text
packages/sdk-server-ts/src/core/keyMaterialBrands.ts
```

If a shared package already exists and does not add build churn, move the tiny shared definitions there. Do not create a new package for these brands.

Generated command files stay as wire boundaries. Do not manually edit:

```text
packages/sdk-web/src/core/platform/generated/signerCoreCommands.ts
```

If generated command types need branded wrappers, add adapters next to the handwritten SDK wrapper code. Rust/generator changes can happen later if they reduce boundary code.

### Boundary Parser Policy

Raw strings can enter only through these boundaries:

- Route request/response parsing.
- Worker command/response parsing.
- IndexedDB/server persistence parsing.
- Config/env parsing.
- Test fixtures that explicitly model raw wire or invalid boundary input.

After a boundary parser returns a branded value, core code should pass the brand directly. Repeated local validation helpers are a smell because they create multiple unofficial boundaries.

### Wire And Persistence Compatibility

Existing wire and storage field names stay stable in this refactor:

- `keyVersion`
- `walletKeyVersion`
- `clientVerifyingShareB64u`
- `relayerKeyId`
- `materialHandle`
- `sealedWorkerMaterialRef`
- `materialBindingDigest`
- `materialKeyId`

Canonical digest inputs must remain byte-for-byte compatible unless a separate digest-version migration is explicitly planned. Branded types change TypeScript assignability, not serialization.

### Fixture Naming Policy

Existing fixture values such as `kek-s-*` and `seal-v1` should be renamed when they represent current valid signing-session seal keys.

Allowed leftovers:

- Invalid-boundary tests that prove old or malformed values are rejected.
- Historical docs that describe an incident.
- Compatibility parser tests at persistence/request boundaries.

New valid fixtures should use domain-explicit values:

```text
signing-session-seal-kek-test-r1
ed25519-hss-material-test-v1
ecdsa-hss-material-test-v1
```

### ECDSA Lifecycle Helper Cleanup

The plan should treat these helpers as active refactor targets:

- `getEcdsaSessionProvisionIdentity`
- `recordMatchesPlannedIdentity`
- `provisionPlanRequiresExistingRecordIdentity`

The final design should leave reconnect identity checks in reconnect-only functions and fresh provision activation in provision-only functions. Shared helpers must switch on `plan.kind` exhaustively.

### Completion Guard Policy

Add source guards with allowlists. The goal is to block accidental raw core paths while permitting wire and persistence edges.

The guard should fail on:

- New internal `keyVersion: string` declarations for Ed25519 HSS, ECDSA HSS, or signing-session seal KEK domains.
- `getEcdsaSessionProvisionIdentity` and `recordMatchesPlannedIdentity` in active code after Phase 6.
- New valid `kek-s-*` signing-session seal fixture values.
- Core signing/session functions accepting raw `materialHandle`, `sealedWorkerMaterialRef`, `materialBindingDigest`, `materialKeyId`, `clientVerifyingShareB64u`, or `relayerKeyId` strings after the relevant brand phase lands.

The guard should allow:

- Generated command files.
- Explicit route body/response schemas.
- Persistence record schemas.
- Boundary parsers.
- Tests named or scoped as invalid, wire, persistence, migration, or boundary tests.

## Implementation Inventory

Use this inventory to avoid a half-refactored state. Each phase should either update the listed files or mark the file as a deliberate boundary/leftover in the plan.

### Brand Type And Parser Files

Create or update:

- `packages/sdk-web/src/core/signingEngine/session/keyMaterialBrands.ts`
- `packages/sdk-server-ts/src/core/keyMaterialBrands.ts`
- `packages/sdk-web/src/core/signingEngine/session/keyMaterialBrands.typecheck.ts`
- `tests/unit/refactor76BrandedKeys.guard.unit.test.ts`

Existing type fixture patterns to follow:

- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/types.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ecdsaProvisionPlan.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/persistence.typecheck.ts`

### Ed25519 HSS Version And Worker-Material Paths

Primary files:

- `packages/sdk-web/src/core/types/signer-worker.ts`
- `packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts`
- `packages/sdk-web/src/SeamsWeb/operations/devices/linkDevice.ts`
- `packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/provisioning.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/ed25519LocalMetadata.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/ed25519Warmup.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/ports.ts`
- `packages/sdk-web/src/core/signingEngine/threshold/ed25519/workerMaterialBinding.ts`
- `packages/sdk-web/src/core/signingEngine/threshold/ed25519/workerMaterialHandle.ts`
- `packages/sdk-web/src/core/signingEngine/threshold/ed25519/clientOutputMask.ts`
- `packages/sdk-web/src/core/signingEngine/threshold/ed25519/hssLifecycle.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/persistence.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/readModel.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/capabilityReaderCore.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/capabilityReader.ts`

Boundary/generated file:

- `packages/sdk-web/src/core/platform/generated/signerCoreCommands.ts`

Relevant tests:

- `tests/unit/thresholdEd25519.registrationWarmSession.unit.test.ts`
- `tests/unit/warmSessionEd25519Persistence.unit.test.ts`
- `tests/unit/routerAbEd25519.walletSessionState.unit.test.ts`
- `tests/unit/thresholdEd25519.hssMaterialHandle.unit.test.ts`
- `tests/unit/thresholdEd25519.nearSignerWasm.unit.test.ts`
- `tests/unit/seamsWeb.loginThresholdWarm.unit.test.ts`
- `tests/unit/emailOtpWalletSessionCoordinator.unit.test.ts`
- `tests/unit/refactor74LoginNoHss.guard.unit.test.ts`

### Signing-Session Seal KEK Paths

Server files:

- `packages/sdk-server-ts/src/core/config.ts`
- `packages/sdk-server-ts/src/core/types.ts`
- `packages/sdk-server-ts/src/core/AuthService.ts`
- `packages/sdk-server-ts/src/threshold/session/signingSessionSeal/options.ts`
- `packages/sdk-server-ts/src/threshold/session/signingSessionSeal/service.ts`
- `packages/sdk-server-ts/src/threshold/session/signingSessionSeal/signingSessionSeal.types.ts`
- `packages/sdk-server-ts/src/threshold/session/signingSessionSeal/transport/shared.ts`
- `packages/sdk-server-ts/src/threshold/session/signingSessionSeal/postgresRecords.ts`
- `packages/sdk-server-ts/src/threshold/session/signingSessionSeal/crypto/cipher.ts`

SDK files:

- `packages/sdk-web/src/core/types/secure-confirm-worker.ts`
- `packages/sdk-web/src/core/types/seams.ts`
- `packages/sdk-web/src/core/config/configBuilder.ts`
- `packages/sdk-web/src/core/signingEngine/session/persistence/records.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/persistence.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/readModel.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/capabilityReaderCore.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/capabilityReader.ts`
- `packages/sdk-web/src/core/signingEngine/uiConfirm/UiConfirmManager.ts`

Relevant tests and helpers:

- `tests/relayer/signing-session-seal-router.test.ts`
- `tests/unit/sealedSessionStore.unit.test.ts`
- `tests/unit/warmSessionStore.lifecycle.unit.test.ts`
- `tests/unit/walletIframe.signerModeConfigPropagation.unit.test.ts`
- `tests/unit/sealedRefresh.parity.unit.test.ts`
- `tests/helpers/thresholdEcdsaSealedRefreshHarness.ts`
- `tests/helpers/emailOtpEcdsaTempoFlow.ts`

### ECDSA HSS Version And Key-Material Paths

Server files:

- `packages/sdk-server-ts/src/core/ThresholdService/ThresholdSigningService.ts`
- `packages/sdk-server-ts/src/core/ThresholdService/routerAb/ecdsaHssPoolFillHandlers.ts`
- `packages/sdk-server-ts/src/core/ThresholdService/signingRootRecords.ts`

SDK files:

- `packages/sdk-web/src/core/signingEngine/threshold/ecdsa/activation.ts`
- `packages/sdk-web/src/core/signingEngine/threshold/ecdsa/bootstrapSession.ts`
- `packages/sdk-web/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.ts`
- `packages/sdk-web/src/core/signingEngine/session/passkey/ecdsaRecovery.ts`
- `packages/sdk-web/src/core/signingEngine/session/persistence/records.ts`
- `packages/sdk-web/src/core/signingEngine/routerAb/ecdsaHss/presignaturePool.ts`
- `packages/sdk-web/src/core/signingEngine/routerAb/ecdsaHss/signingMaterialRef.ts`
- `packages/sdk-web/src/core/signingEngine/routerAb/ecdsaHss/clientSigningMaterialBoundary.ts`
- `packages/sdk-web/src/core/signingEngine/routerAb/ecdsaHss/poolFillRoutes.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signingFlowRuntime.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaLanes.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaMaterialState.ts`
- `packages/sdk-web/src/core/signingEngine/flows/registration/services/ecdsaRegistrationBootstrap.ts`
- `packages/sdk-web/src/core/signingEngine/flows/registration/services/ecdsaRegistrationSessions.ts`
- `packages/sdk-web/src/core/platform/signerCoreCommandAdapters.ts`

Boundary/generated file:

- `packages/sdk-web/src/core/platform/generated/signerCoreCommands.ts`

### ECDSA Lifecycle Strictness

Primary files:

- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/types.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ecdsaProvisionPlan.ts`
- `packages/sdk-web/src/core/signingEngine/useCases/provisionEcdsaSession.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/provisionPlan.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaReadiness.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signingFlowRuntime.ts`

Type fixtures:

- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/types.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ecdsaProvisionPlan.typecheck.ts`

Relevant tests:

- `tests/unit/evmFamilyStepUpProvisionPlan.unit.test.ts`
- `tests/unit/warmSessionStore.reconnect.unit.test.ts`
- `tests/unit/evmSigning.thresholdReconnectEvents.unit.test.ts`
- `tests/unit/signingEngineEcdsaIdentity.lifecycle.guard.unit.test.ts`
- `tests/unit/helpers/warmSessionStore.fixtures.ts`

### Shared Signing-Grant Budget Lifecycle

Primary files:

- `packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts`
- `packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts`
- `packages/sdk-web/src/core/signingEngine/session/postconditions/runtimePostconditions.ts`
- `packages/sdk-web/src/core/signingEngine/session/availability/availableSigningLanes.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/statusReader.ts`

Server/route files to audit:

- `packages/sdk-server-ts/src/core/AuthService.ts`
- `packages/sdk-server-ts/src/router/cloudflare/routes/thresholdEd25519.ts`
- `packages/sdk-server-ts/src/router/cloudflare/routes/thresholdEcdsa.ts`
- `packages/sdk-server-ts/src/threshold/session/signingSessionSeal/policy/sessionPolicy.ts`

Relevant tests:

- `tests/unit/thresholdWarmSessionPolicyDraft.unit.test.ts`
- `tests/unit/registrationIntentAllocation.unit.test.ts`
- `tests/unit/thresholdEd25519.registrationWarmSession.unit.test.ts`
- `tests/unit/seamsWeb.chainSigners.integration.test.ts`
- `tests/e2e/routerAb.serverBudgetEvidence.walletIframe.test.ts`

Browser evidence:

- Fresh combined registration with NEAR, Tempo, and EVM enabled.
- Sign sequence: NEAR, Tempo, EVM, NEAR.
- Expected: first three signs consume the shared budget; the fourth sign triggers step-up regardless of curve.
- Repeat after wallet unlock to confirm registration and unlock use the same shared-budget semantics.

## Grep Checklist

Run these before and after each phase. After a phase lands, every remaining hit should be either updated, explicitly allowed, or tracked in this plan.

### Key Version Inventory

```bash
rg -n "keyVersion: string" packages/sdk-web/src packages/sdk-server-ts/src
rg -n "THRESHOLD_ED25519_SINGLE_KEY_HSS_KEY_VERSION_V1|EMAIL_OTP_THRESHOLD_ED25519_HSS_KEY_VERSION|threshold-ed25519-hss-v1" packages tests
rg -n "THRESHOLD_ECDSA_HSS_KEY_VERSION_V1|walletKeyVersion|EcdsaClientBootstrapKeyVersion" packages tests
rg -n "SIGNING_SESSION_SEAL_KEY_VERSION|signingSessionSealKeyVersion|currentKeyVersion|kek-s-|seal-v1" packages tests docs
```

### Opaque Material And Digest Inventory

```bash
rg -n "materialHandle: string|sealedWorkerMaterialRef: string|materialBindingDigest: string|materialKeyId: string" packages/sdk-web/src/core/signingEngine
rg -n "clientVerifyingShareB64u: string|relayerKeyId: string" packages/sdk-web/src/core/signingEngine packages/sdk-server-ts/src/core/ThresholdService
rg -n "ecdsaThresholdKeyId|keyHandle|clientAdditiveShareHandle" packages/sdk-web/src packages/sdk-server-ts/src tests
```

### ECDSA Lifecycle Inventory

```bash
rg -n "getEcdsaSessionProvisionIdentity|recordMatchesPlannedIdentity|provisionPlanRequiresExistingRecordIdentity" packages/sdk-web/src/core/signingEngine tests
rg -n "existingSessionIdentity|newSessionIdentity|wallet_session_ecdsa_reconnect|passkey_ecdsa_session_provision|email_otp_ecdsa_session_provision" packages/sdk-web/src/core/signingEngine tests/unit
rg -n "EcdsaSessionProvisionPlan|BuildEcdsaSessionProvisionPlanArgs" packages/sdk-web/src/core/signingEngine tests/unit
```

### Shared Signing-Grant Inventory

```bash
rg -n "createThresholdWarmSessionPolicyDraft\\(" packages/sdk-web/src/SeamsWeb packages/sdk-web/src/core tests/unit
rg -n "shared_signing_grant|generated_signing_grant|signingGrantId" packages/sdk-web/src/SeamsWeb/operations/registration packages/sdk-web/src/SeamsWeb/operations/session tests/unit
rg -n "assertCombinedRegistrationSharedSigningGrant|requireSharedSigningGrant" packages/sdk-web/src tests/unit
rg -n "remainingUses|remainingSignatureUses" packages/sdk-web/src/SeamsWeb/operations/registration packages/sdk-web/src/core/signingEngine/session/postconditions tests/unit
```

After Phase 7 lands, combined-registration code should have one clear shared-grant construction path. Remaining generated-grant calls should be Ed25519-only, add-signer, recovery, link-device, or another explicitly independent wallet-session flow.

### Allowed Raw Boundary Hits

These areas may continue to expose raw strings, provided they parse immediately before core use:

- `packages/sdk-web/src/core/platform/generated/signerCoreCommands.ts`
- Route schema/request/response modules.
- IndexedDB/server persistence record modules.
- Config/env parsing modules.
- Tests named or scoped as wire, persistence, migration, invalid input, or boundary tests.

## Remaining Implementation TODO

Current status:

- Key-version brands are implemented for the three original high-risk domains.
- ECDSA reconnect/provision lifecycle separation is implemented.
- Combined Ed25519 + ECDSA registration now has an explicit shared-signing-grant path.
- Phase 9 second-tier key-material branding is implemented for the scoped SDK/server core boundaries.

Do not reopen completed key-version, ECDSA lifecycle, shared-budget, or Phase 9 second-tier branding behavior unless a test proves a regression. Raw strings remain intentional at route, worker, generated-command, config, and persistence boundaries; core signing/session code should receive branded values through boundary parsers.

### 9A. Add Second-Tier Brands And Parsers

- [x] Extend the SDK key-material brand module with:
  - `Ed25519WorkerMaterialHandle`
  - `Ed25519SealedWorkerMaterialRef`
  - `Ed25519WorkerMaterialKeyId`
  - `Ed25519WorkerMaterialBindingDigest`
  - `Ed25519ClientVerifyingShareB64u`
  - `EcdsaClientVerifyingShareB64u`
  - `Ed25519RelayerKeyId`
  - `EcdsaRelayerKeyId`
  - `EcdsaThresholdKeyId`
  - `EcdsaKeyHandle`
  - `EcdsaClientAdditiveShareHandle`
  - `SigningSessionSealShamirPrimeB64u`
- [x] Extend the server key-material brand module with the server-side subset:
  - `Ed25519RelayerKeyId`
  - `EcdsaRelayerKeyId`
  - `Ed25519ClientVerifyingShareB64u`
  - `EcdsaClientVerifyingShareB64u`
  - `EcdsaThresholdKeyId`
  - `EcdsaKeyHandle`
  - `SigningSessionSealShamirPrimeB64u`
- [x] Add parser and `format*ForWire()` helpers for each brand.
- [x] Keep parsers minimal: trim strings, reject empty strings, and do format-specific validation only where an existing local validator already exists.
- [x] Add type fixtures proving the new brands cannot be assigned across domains.

Files:

- `packages/sdk-web/src/core/signingEngine/session/keyMaterialBrands.ts`
- `packages/sdk-web/src/core/signingEngine/session/keyMaterialBrands.typecheck.ts`
- `packages/sdk-server-ts/src/core/keyMaterialBrands.ts`
- `packages/sdk-server-ts/src/core/keyMaterialBrands.typecheck.ts`

### 9B. Parse At Boundaries, Then Pass Brands In Core

- [x] Treat route bodies, generated worker commands, worker responses, and persisted records as raw boundary shapes.
- [x] Parse raw strings into brands immediately after reading persistence or route/worker responses.
- [x] Format brands back to strings only when writing persistence or sending route/worker requests.
- [x] Do not brand raw secret bytes. Keep PRF, recovery-code, mask, HSS share, and additive-share bytes behind worker/WASM handles or one-use authorization capabilities.

Acceptance:

- Core signing/session functions accept the narrow branded type.
- Boundary modules still expose the existing wire and persisted string fields.
- No compatibility layer is added outside request, worker, route, or persistence boundaries.

### 9C. Brand Ed25519 Worker-Material Restore And Signing References

- [x] Brand runtime material handles as `Ed25519WorkerMaterialHandle`.
- [x] Brand persisted sealed artifact refs as `Ed25519SealedWorkerMaterialRef`.
- [x] Brand material binding digests as `Ed25519WorkerMaterialBindingDigest`.
- [x] Brand worker material key IDs as `Ed25519WorkerMaterialKeyId`.
- [x] Update restore/readiness code so `materialHandle`, `sealedWorkerMaterialRef`, `materialBindingDigest`, and `materialKeyId` cannot be interchanged.
- [x] Keep generated near-signer worker command shapes raw and convert at the wrapper boundary.

Primary files:

- `packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts`
- `packages/sdk-web/src/core/signingEngine/session/passkey/ed25519Recovery.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/persistence.ts`
- `packages/sdk-web/src/core/signingEngine/threshold/ed25519/workerMaterialBinding.ts`
- `packages/sdk-web/src/core/signingEngine/threshold/ed25519/workerMaterialHandle.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519SigningMaterialReadiness.ts`
- `packages/sdk-web/src/core/signingEngine/chains/near/nearSignerWasm.ts`
- `packages/sdk-web/src/core/signingEngine/workerManager/workers/near-signer.worker.ts`
- `packages/sdk-web/src/core/signingEngine/workerManager/workerTypes.ts`

### 9D. Brand Curve-Specific Relayer Keys And Verifying Shares

- [x] Brand Ed25519 relayer keys as `Ed25519RelayerKeyId`.
- [x] Brand ECDSA relayer keys as `EcdsaRelayerKeyId`.
- [x] Brand Ed25519 client verifying shares as `Ed25519ClientVerifyingShareB64u`.
- [x] Brand ECDSA client verifying shares as `EcdsaClientVerifyingShareB64u`.
- [x] Update Ed25519 material-binding, presign-pool, and restore functions to require Ed25519 brands.
- [x] Update ECDSA keygen/provision/presign/signing functions to require ECDSA brands.
- [x] Keep persistence and route schema field names unchanged: `relayerKeyId` and `clientVerifyingShareB64u`.

Primary files:

- `packages/sdk-web/src/core/signingEngine/threshold/ed25519/workerMaterialBinding.ts`
- `packages/sdk-web/src/core/signingEngine/threshold/ed25519/presignPool.ts`
- `packages/sdk-web/src/core/signingEngine/session/persistence/records.ts`
- `packages/sdk-web/src/core/signingEngine/session/identity/ecdsaHssSigningMaterialHandle.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ecdsaProvisionPlan.ts`
- `packages/sdk-web/src/core/signingEngine/routerAb/ecdsaHss/presignaturePool.ts`
- `packages/sdk-server-ts/src/core/ThresholdService/ThresholdSigningService.ts`
- `packages/sdk-server-ts/src/core/ThresholdService/routerAb/ecdsaHssPoolFillHandlers.ts`
- `packages/sdk-server-ts/src/core/ThresholdService/relayerKeyMaterial.ts`

### 9E. Brand ECDSA Key Identity Handles

- [x] Brand threshold ECDSA key IDs as `EcdsaThresholdKeyId`.
- [x] Brand ECDSA key handles as `EcdsaKeyHandle`.
- [x] Brand ECDSA additive-share handles as `EcdsaClientAdditiveShareHandle`.
- [x] Update ECDSA identity, provision, reconnect, sealed-refresh, and signing code to require the narrow handle type.
- [x] Keep generated worker command and persisted record fields raw at the boundary.

Primary files:

- `packages/sdk-web/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity.ts`
- `packages/sdk-web/src/core/signingEngine/session/identity/ecdsaHssSigningMaterialHandle.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ecdsaProvisionPlan.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaReadiness.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/readySecp256k1Material.ts`
- `packages/sdk-web/src/core/signingEngine/routerAb/ecdsaHss/presignaturePool.ts`
- `packages/sdk-web/src/core/signingEngine/routerAb/ecdsaHss/clientSigningMaterialBoundary.ts`
- `packages/sdk-server-ts/src/core/ThresholdService/stores/EcdsaSigningStore.ts`

### 9F. Brand Signing-Session Seal Non-Secret Parameters

- [x] Brand Shamir prime config as `SigningSessionSealShamirPrimeB64u`.
- [x] Parse it at server/env/config boundaries.
- [x] Format it only when constructing the seal adapter or route-compatible config.
- [x] Do not brand raw server exponents unless the code keeps them at config boundary only.

Primary files:

- `packages/sdk-server-ts/src/threshold/session/signingSessionSeal/options.ts`
- `packages/sdk-server-ts/src/core/AuthService.ts`
- `apps/web-server/scripts/generate-signing-session-seal-keys.mjs`
- `apps/web-server/src/index.ts`

### 9G. Add Guards And Tests For Remaining Brands

- [x] Extend `tests/unit/refactor76BrandedKeys.guard.unit.test.ts` to fail on raw material handle/ref/digest/core declarations outside allowlisted boundary files.
- [x] Add type fixtures that reject:
  - `Ed25519WorkerMaterialHandle` where `Ed25519SealedWorkerMaterialRef` is required.
  - `Ed25519WorkerMaterialBindingDigest` where `Ed25519WorkerMaterialKeyId` is required.
  - `EcdsaClientVerifyingShareB64u` where `Ed25519ClientVerifyingShareB64u` is required.
  - `EcdsaRelayerKeyId` where `Ed25519RelayerKeyId` is required.
  - `EcdsaKeyHandle` where `EcdsaThresholdKeyId` is required.
- [x] Add or update focused unit tests for:
  - Ed25519 material restore from persisted sealed artifact.
  - NEAR material-backed signing after restore.
  - ECDSA sealed refresh and normal signing.
  - Signing-session seal config parsing.

Validation:

- [x] `pnpm --dir packages/sdk-web exec tsc --noEmit --pretty false`
- [x] `pnpm -C packages/sdk-server-ts exec tsc --noEmit --pretty false`
- [x] `pnpm -C tests exec playwright test tests/unit/refactor76BrandedKeys.guard.unit.test.ts`
- [x] `pnpm -C tests exec playwright test tests/unit/thresholdEd25519.registrationWarmSession.unit.test.ts tests/unit/warmSessionEd25519Persistence.unit.test.ts`
- [x] `pnpm -C tests exec playwright test tests/unit/evmFamilyStepUpProvisionPlan.unit.test.ts tests/unit/sealedRefresh.parity.unit.test.ts`
- [x] `pnpm -C tests exec playwright test tests/unit/routerAbEd25519.walletSessionState.unit.test.ts`
- [x] `pnpm -C tests exec playwright test tests/unit/thresholdEcdsa.presignPoolPolicy.unit.test.ts tests/unit/thresholdEcdsa.presignPoolRefill.unit.test.ts`

## Source Guard Inventory

Add or update:

```text
tests/unit/refactor76BrandedKeys.guard.unit.test.ts
```

Guard requirements:

- No active core file declares a scoped key version as `keyVersion: string`.
- No active core file uses `getEcdsaSessionProvisionIdentity` after Phase 6.
- No active core file uses `recordMatchesPlannedIdentity` after Phase 6.
- Valid signing-session seal fixtures do not use `kek-s-*` or `seal-v1`.
- Ed25519 durable refresh transport does not accept an HSS material `keyVersion`.
- ECDSA reconnect identity validation is callable only from reconnect-specific paths.
- Raw opaque material strings appear only in allowlisted boundary files before their brand phase is complete.
- Combined Ed25519 + ECDSA registration uses the `shared_signing_grant` branch.
- Combined registration has a persisted-lane postcondition that compares Ed25519 and ECDSA `signingGrantId`.
- No combined registration helper creates a second wallet budget after ECDSA registration prepare/bootstrap has returned a `signingGrantId`.

## Validation Matrix

Run narrow checks by phase:

- Phase 1: SDK/server type fixtures for brand assignability.
- Phase 2: Ed25519 warm-session persistence and material-restore unit tests.
- Phase 3: signing-session seal router tests and UiConfirm/sealed-store tests.
- Phase 4: ECDSA/Tempo sealed refresh and normal signing tests.
- Phase 5 and 6: ECDSA reconnect/provision lifecycle tests and type fixtures.
- Phase 7: combined registration shared-budget unit tests and browser evidence.
- Phase 8: source guards for branded key versions, lifecycle helpers, and shared-grant registration paths.
- Phase 9: source guards for opaque handle/ref/digest/verifier/relayer brands.

Full SDK/server type-check is required before the branch is called done because this refactor changes shared types and core signing/session surfaces.

## Test Plan

Focused checks:

- `pnpm --dir packages/sdk-web exec tsc --noEmit --pretty false`
- `pnpm -C packages/sdk-server-ts exec tsc --noEmit --pretty false`
- Unit tests covering:
  - Ed25519 registration warm-session persistence.
  - Ed25519 durable sealed material restore.
  - Signing-session seal apply/remove.
  - ECDSA/Tempo sealed refresh.
  - ECDSA/Tempo normal signing.

Suggested targeted tests:

- `tests/unit/thresholdEd25519.registrationWarmSession.unit.test.ts`
- `tests/unit/warmSessionEd25519Persistence.unit.test.ts`
- `tests/unit/refactor74LoginNoHss.guard.unit.test.ts`
- `tests/relayer/signing-session-seal-router.test.ts`
- `tests/e2e/thresholdEcdsa.sealedRefresh.walletIframe.test.ts`
- `tests/unit/evmFamilyStepUpProvisionPlan.unit.test.ts`
- `tests/unit/thresholdWarmSessionPolicyDraft.unit.test.ts`
- `tests/unit/registrationIntentAllocation.unit.test.ts --grep "runs combined Ed25519 and ECDSA registration through one ceremony"`

## Done Criteria

- The three version domains have distinct branded types.
- High-risk opaque key-material handles, material refs, material key IDs, and material binding digests have distinct branded types.
- Ed25519 and ECDSA relayer key IDs and client verifying shares are no longer interchangeable in core code.
- Core/domain functions require branded fields with precise names.
- Raw `keyVersion` remains only at request, worker, generated-command, and persistence boundaries.
- Existing wire formats and persisted record shapes are unchanged unless a boundary parser explicitly handles the migration.
- Type fixtures fail if any branded key version can be assigned to another domain.
- The previous regression is impossible to express in TypeScript without an explicit boundary parse/cast.
- New signing-session seal config/test values use domain-explicit names.
- ECDSA reconnect and fresh provision identity rules are represented as separate lifecycle branches.
- Existing and new ECDSA session identities are not interchangeable in plan builders or validation helpers.
- Combined Ed25519 + ECDSA registration cannot mint separate Ed25519 and ECDSA signing budgets.
- Combined registration fails a postcondition if persisted Ed25519 and ECDSA lanes have different `signingGrantId` values.
- Fresh browser registration evidence proves NEAR, Tempo, and EVM consume one shared `remainingUses` budget before step-up.

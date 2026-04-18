# Refactor Signer Slot Lifecycle

## Problem

Earlier SDK iterations used `deviceNumber` as a local signer slot. That was workable for passkeys, where a signer often maps to a physical device, but it became brittle once threshold, session, recovery, and self-hosted signers were added.

The immediate bug was an active signer slot collision:

- Email OTP Ed25519 registration retried or re-ran.
- The retry produced a new `threshold-ed25519:<relayerKeyId>` signer.
- A previous local `threshold-ed25519:*` signer for the same NEAR account was still marked `active` in IndexedDB at slot `1`.
- The new signer also tried to use slot `1`.
- `PasskeyClientDBManager` correctly rejected the write with `DUPLICATE_ACTIVE_SIGNER_SLOT`.

This was not a crypto failure. It was a local signer lifecycle failure:
registration flows were guessing slot ownership instead of using a centralized,
idempotent allocation policy.

## Goals

- Make signer slot allocation explicit, deterministic, and centralized.
- Preserve the DB invariant that only one active signer may occupy a slot for a given account.
- Treat retries and partial-success registration flows as idempotent retries of
  the same signer, not as ad hoc new signer inserts.
- Separate physical passkey device concepts from generic local signer concepts.
- Separate account auth method selection from curve-specific signing and export flows.
- Route every wallet flow through one auth-mode resolver instead of letting each flow guess passkey versus Email OTP behavior.
- Support current signer kinds, threshold Ed25519 and threshold ECDSA, while
  keeping auth methods, session proofs, recovery flows, delegated flows, and
  self-hosted imports as separate metadata or provisioning concepts.
- Keep historical signer records for debugging and auditability instead of deleting stale local records.
- Avoid compatibility shims or legacy duplicate paths. This codebase is still in development, so breaking local storage migrations are acceptable when the model changes.

## Non-Goals

- This refactor does not change threshold signing cryptography.
- This refactor does not change wallet addresses or on-chain account state.
- This refactor does not implement server-side signer policy enforcement.
- This refactor does not make IndexedDB a source of truth for custody. It remains local client state.

## Current State

`AccountSignerRecord` has:

```ts
type AccountSignerRecord = {
  profileId: string;
  chainIdKey: string;
  accountAddress: string;
  signerId: string;
  signerSlot: number;
  signerType: string;
  signerKind: SignerKind;
  signerAuthMethod: SignerAuthMethod;
  signerSource: SignerSource;
  status: 'active' | 'pending' | 'revoked';
  revocationReason?: string;
  metadata?: Record<string, unknown>;
};
```

`PasskeyClientDBManager` enforces:

- one active signer per `(chainIdKey, accountAddress, signerSlot)`;
- revoked signers must carry `removedAt`;
- `lastProfileState.activeSignerSlot` must point to an existing non-revoked
  signer slot.

`AccountKeyMaterialDB` is keyed by:

```ts
[profileId, signerSlot, chainIdKey, keyKind];
```

Earlier versions used `deviceNumber` as this generic key material slot. Phase 7
resets the key-material IndexedDB store to `signerSlot` rather than
carrying a compatibility alias.

The initial Email OTP fix added a flow-local helper:

```ts
planEmailOtpThresholdEd25519SignerSlot({
  activeSigners,
  signerId,
});
```

That helper was removed. Signer activation now routes through the general
signer lifecycle API.

The same class of lifecycle drift also exists in wallet auth routing:

- Email OTP accounts can still hit WebAuthn prompts or server paths that require `webauthn_authentication`.
- Passkey accounts and Email OTP accounts do not have one shared source of truth for auth method selection.
- ECDSA warm sessions have more complete Email OTP auth context than Ed25519 warm sessions.
- Signing planners currently return narrow auth hints instead of a full executable auth plan.
- Key export policy is not explicit for Email OTP-only accounts.

These are not independent UI bugs. They are caused by the same missing boundary:
local account metadata should decide signer lifecycle and wallet auth mode before
curve-specific signing, login, unlock, or export code runs.

### Writer Inventory

Current production writers that still need to be moved behind the lifecycle
boundary or classified explicitly:

| Writer                                                                                       | Current role                                                  | Target classification                                                                                                                           |
| -------------------------------------------------------------------------------------------- | ------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `client/src/core/signingEngine/SigningEngine.ts`                                             | Email OTP Ed25519 local metadata and key material writes      | `signerKind: 'threshold-ed25519'`, `signerAuthMethod: 'email_otp'`, `signerSource: 'email_otp_registration'`, idempotent same-signer retry only |
| `client/src/core/accountData/near/accountProjection.ts`                                      | Generic NEAR account projection and last-profile state writes | classify passkey versus threshold caller, then route signer writes through lifecycle                                                            |
| `client/src/core/TatchiPasskey/near/linkDevicePreparedEcdsa.ts`                              | Linked passkey-backed threshold signer projection             | threshold `signerKind`, `signerAuthMethod: 'passkey'`, `signerSource: 'passkey_registration'`, allocate next free                               |
| `client/src/core/TatchiPasskey/evm/linkDeviceThresholdEcdsa.ts`                              | Linked ECDSA/Tempo signer projection                          | `signerKind: 'threshold-ecdsa'`, `signerAuthMethod: 'passkey'`, `signerSource: 'passkey_registration'`                                          |
| `client/src/core/TatchiPasskey/thresholdWarmSessionBootstrap.ts`                             | Threshold warm-session key material writes                    | use lifecycle-returned `signerSlot` once activation owns signer slot selection                                                                  |
| `client/src/core/signingEngine/api/thresholdLifecycle/thresholdEcdsaBootstrapPersistence.ts` | ECDSA smart-account bootstrap/profile state writes, not an `AccountSignerRecord` writer | keep outside account signer lifecycle unless this module starts writing local account signer rows                                                |
| `client/src/core/signingEngine/api/registration/registrationAccountLifecycle.ts`             | Passkey-backed threshold registration signer writes           | threshold `signerKind`, `signerAuthMethod: 'passkey'`, `signerSource: 'passkey_registration'`, allocate next free                               |
| `client/src/core/indexedDB/unifiedIndexedDBManager.ts`                                       | Lower-level forwarding and reconciliation status updates      | keep as internal DB surface; lifecycle should be the public writer for new signing flows                                                        |

Test-only writer sites remain in `tests/unit/*` and should be updated as the
production callers move from direct writes to `activateAccountSigner`.

### Signer Slot Boundary

`signerSlot` is the only local account signer slot name. It applies to
passkey-backed threshold signers, Email OTP-backed threshold signers, and
self-hosted threshold signers.

Persisted slot pointer model:

- Persisted IndexedDB schema fields now use `Profile.defaultSignerSlot` and
  `LastProfileState.activeSignerSlot`.
- Last-profile state pointer writes that select the active account signer slot
  for future signing.
- `AccountKeyMaterialDB` no longer uses legacy slot names; it was reset to
  `signerSlot` in the v10 key-material store.

Refactor boundary:

- New signer lifecycle APIs use `signerSlot` for the account signer record and
  `signerSlot` for matching key-material rows.
- Threshold Ed25519 and threshold ECDSA code uses `signerSlot` locally.
- WebAuthn/passkey physical identity remains `credentialId`, `rawId`,
  authenticator transports, and authenticator metadata. Do not use a slot
  number as a proxy for the physical authenticator identity.

## Target Model

### Terminology

- `signerId`: stable identifier for one signer instance, for example `threshold-ed25519:<relayerKeyId>`.
- `signerSlot`: local account signer slot and key-material storage slot. Only
  one active signer may occupy a slot for a given account, and key material
  belongs to that signer slot.
- `signerKind`: cryptographic signer kind. Current supported values are
  `threshold-ed25519` and `threshold-ecdsa`.
- `signerAuthMethod`: account auth method that backs or provisioned the signer:
  `passkey` or `email_otp`.
- `walletAuthProofMethod`: how a specific operation was authorized. This can be
  `passkey`, `email_otp`, or `session`.
- `signerSource`: provisioning source: `passkey_registration`,
  `email_otp_registration`, or `self_hosted_import`.
- `credentialId`: WebAuthn/passkey authenticator identity. Do not use
  `signerSlot` as a generic proxy for this.
- `deviceNumber`: removed legacy slot name. Do not use it in production code or
  public SDK/server request shapes.

### Signer Metadata

Add explicit metadata to every account signer:

```ts
type SignerKind = 'threshold-ed25519' | 'threshold-ecdsa';

type SignerAuthMethod = 'passkey' | 'email_otp';

type WalletAuthProofMethod = 'passkey' | 'email_otp' | 'session';

type SignerSource = 'passkey_registration' | 'email_otp_registration' | 'self_hosted_import';

type AccountSignerRecord = {
  signerKind: SignerKind;
  signerAuthMethod: SignerAuthMethod;
  signerSource: SignerSource;
  revocationReason?: string;
};
```

Do not put `passkey`, `session`, or `recovery` in `SignerKind`.

- `passkey` is an auth method or proof method, not a signer kind.
- `session` is an operation proof method managed by session state, not a signer
  identity.
- `recovery` is a recovery/provisioning flow unless it independently signs
  transactions, so it does not belong in signer identity.

Do not rely on string-prefix matching like `signerId.startsWith('threshold-ed25519:')` in production lifecycle code once this metadata exists.

### Wallet Auth Method Metadata

Persist the account's wallet auth method explicitly. Do not infer it from the
current flow, the current prompt, or whether a WebAuthn credential happens to be
available.

```ts
type WalletAuthMethod = 'passkey' | 'email_otp';

type AccountAuthMetadata = {
  primaryAuthMethod: WalletAuthMethod;
  linkedAuthMethods: WalletAuthMethod[];
  email?: string;
  passkeyCredentialIds?: string[];
};
```

The account auth method is orthogonal to:

- `signerKind`, for example `threshold-ed25519` or `threshold-ecdsa`;
- `signerAuthMethod`, for example `email_otp` or `passkey`;
- `signerSource`, for example `email_otp_registration` or
  `passkey_registration`;
- `signingRootId`;
- chain or curve selection;
- whether a warm session currently exists.

Email OTP account records must be able to say: this wallet is authorized through
Email OTP, and both threshold Ed25519 and threshold ECDSA signing should use the
Email OTP auth lane unless a stronger linked auth method is explicitly required
by policy.

### Wallet Auth Mode Resolver

Introduce one resolver that chooses the auth path for all wallet flows:

```ts
type WalletAuthIntent =
  | 'wallet_unlock'
  | 'transaction_sign'
  | 'ed25519_export'
  | 'ecdsa_export'
  | 'session_mint'
  | 'link_device';

type WalletAuthProof =
  | {
      method: Extract<WalletAuthProofMethod, 'passkey'>;
      webauthnAuthentication: unknown;
      prfOutput?: Uint8Array;
    }
  | {
      method: Extract<WalletAuthProofMethod, 'email_otp'>;
      emailOtpAuthentication: unknown;
    }
  | {
      method: Extract<WalletAuthProofMethod, 'session'>;
      sessionId: string;
      parentAuthMethod: WalletAuthMethod;
    };

interface WalletAuthModeResolver {
  resolveWalletAuthPlan(input: {
    accountId: string;
    accountAuth: AccountAuthMetadata;
    intent: WalletAuthIntent;
    curve?: 'ed25519' | 'ecdsa';
  }): Promise<WalletAuthPlan>;
}
```

The resolver must be driven by stored account/session metadata, not per-flow
guesses. Curve-specific flows should request an auth plan and execute it; they
should not directly decide whether to show Touch ID or a 6-digit Email OTP
prompt.

### Full Auth Plans

Replace narrow `SigningAuthMode` hints with an executable plan:

```ts
type WalletAuthPlan =
  | {
      kind: 'warmSession';
      method: WalletAuthMethod;
      sessionId: string;
    }
  | {
      kind: 'passkeyReauth';
      challenge: () => Promise<unknown>;
      complete: (response: unknown) => Promise<WalletAuthProof>;
    }
  | {
      kind: 'emailOtpReauth';
      challenge: () => Promise<{ challengeId: string; email: string }>;
      complete: (input: { challengeId: string; code: string }) => Promise<WalletAuthProof>;
    };
```

This makes the planner responsible for the whole auth route:

- use an existing warm session when policy allows it;
- otherwise create the correct challenge type;
- complete the correct proof type;
- return normalized auth material to signing/session/export code.

Generic threshold code should validate `WalletAuthProof` for the requested
intent. It should not directly require `webauthn_authentication` unless the
resolved account auth method is `passkey`.

`WalletAuthProofMethod` is not a replacement for `WarmSessionManager`.
`WarmSessionManager` owns session freshness, TTL, remaining-use accounting, and
cached signing material. `WalletAuthProofMethod` is a small normalized label for
the proof mechanism that authorized one operation or server request. A
warm-session plan may skip a new challenge because `WarmSessionManager` says the
session is valid; the resulting operation can still be represented as
`method: 'session'` when a server/client boundary needs to audit or validate how
the operation was authorized.

### Auth Metadata Inventory

Current auth mode state is split across several layers. Until the resolver is
implemented, these are the authoritative places to audit when a flow shows the
wrong prompt:

- IndexedDB account signer rows store signer identity and provisioning source
  through `signerKind`, `signerAuthMethod`, `signerSource`, and signer
  metadata. This is useful for signer lifecycle, but it is not sufficient as the
  wallet auth source of truth because a wallet may have multiple linked auth
  methods.
- Threshold ECDSA session records store `source` and, for Email OTP sessions,
  `emailOtpAuthContext`. This is currently the strongest persisted signal that
  an ECDSA signing lane should use Email OTP.
- Threshold Ed25519 session records now also carry `source` and optional
  `emailOtpAuthContext`. Ed25519 must use the same Email OTP session semantics
  as ECDSA instead of falling back to passkey-only auth.
- Warm-session read models expose `authMethod` and retention state to UI and
  iframe callers. UI should display the prompt selected by this auth state, not
  infer auth from curve or transaction type.
- Relay session and auth routes still contain method-specific proof payloads.
  Passkey lanes use `webauthn_authentication`; Email OTP lanes use grant or
  session material from the Email OTP flow. These need a normalized server-side
  auth proof boundary.
- Demo app state should consume SDK session/readiness output. It should not
  infer auth mode by checking whether a WebAuthn prompt or Email OTP prompt is
  currently mounted.

Direct WebAuthn prompt or WebAuthn-only proof boundaries currently include:

- passkey login, passkey registration, account sync, and step-up routes;
- Ed25519 session mint paths under `connectEd25519Session` and
  `ed25519AuthSession`;
- ECDSA bootstrap, connect, and keygen paths that still ask for passkey PRF
  material;
- WebAuthn P-256 signing implementations;
- key export paths in `SigningEngine` that call `requestUserConfirmation`;
- server routes under auth, sessions, sync account, and threshold signing that
  still require `webauthn_authentication` without first resolving
  `method: 'passkey'`.

Direct Email OTP prompt boundaries currently include:

- the Email OTP worker challenge, verify, enroll, login, and wallet-login
  operations;
- `requestEmailOtpChallengeForSigning` in the signing engine dependency
  factory;
- NEAR, EVM, and Tempo signing flows that pass `emailOtpPrompt` into
  touch-confirm UI;
- touch-confirm adapters and UI components that render a 6-digit OTP prompt
  when `signingAuthMode` is `emailOtp`;
- warm-session and threshold-session persistence paths that mark Email OTP
  sessions as `source: 'email_otp'` and store `emailOtpAuthContext`.

Canonical persisted auth metadata should become:

```ts
type AccountAuthMetadata = {
  primaryAuthMethod: WalletAuthMethod;
  linkedAuthMethods: WalletAuthMethod[];
  email?: string;
  passkeyCredentialIds?: string[];
};
```

Until that record exists, the resolver should use a strict interim derivation:

- prefer an active threshold session whose `source` is `email_otp` and whose
  `emailOtpAuthContext` is present;
- otherwise prefer active account signer metadata that identifies a threshold
  signer with `signerAuthMethod: 'email_otp'`;
- otherwise use passkey only when the profile has a passkey credential or the
  active signer is explicitly a passkey signer;
- never choose WebAuthn just because a curve-specific flow has historically
  used WebAuthn.

### Email OTP As A Real Ed25519 Session Source

Email OTP must be a first-class Ed25519 session source, not an ECDSA-only
shortcut. The Ed25519 session store and session mint path should persist the
same kind of auth context that ECDSA already carries:

```ts
type ThresholdAuthContext = {
  authMethod: WalletAuthMethod;
  authSessionId: string;
  accountId: string;
  signingRootId: string;
  issuedAtMs: number;
  expiresAtMs: number;
  remainingUses?: number;
  policy: 'session' | 'per_operation';
};
```

For Email OTP accounts, Ed25519 NEAR signing after registration should be able
to use an Email OTP-backed warm session or request a fresh Email OTP. It must not
fall back to WebAuthn only because the Ed25519 path historically used passkey
auth.

### Export Policy

Key export must have an explicit policy for Email OTP-only accounts.

Resolved product decision:

- Email OTP-only accounts may export Ed25519 and ECDSA keys with fresh OTP
  step-up.
- Email OTP export must be `per_operation`, export-scoped, short-lived, and
  server-authorized.
- Email OTP export must never silently choose WebAuthn for Email OTP-only
  accounts. That makes the account look broken and hides the real product
  policy decision.

Mixed passkey plus Email OTP accounts default to passkey for sensitive actions.
When project policy allows it, the UI may offer a smaller "use one-time
password" fallback link.

### Activation Policies

Centralize activation around an activation policy. Registration must fail
closed if it would create a different signer for an account that already exists.
That avoids accidentally overwriting an account with a different key/address and
risking loss of funds.

```ts
type SignerActivationPolicy =
  | { mode: 'reuse_existing'; signerId: string; materialFingerprint: string }
  | { mode: 'allocate_next_free' }
  | { mode: 'fail_if_occupied'; signerSlot: number };
```

Example Email OTP Ed25519 policy:

```ts
{
  mode: 'reuse_existing',
  signerId: 'threshold-ed25519:<relayerKeyId>',
  materialFingerprint: '<stable signer material fingerprint>',
}
```

`reuse_existing` only applies when the existing signer has the same `signerId`
and the same signer material fingerprint. It is an idempotent retry path, not a
replacement path.

If an Email OTP registration attempts to create the same account with a
different `signerId`, public key, or account address, it must return a typed
duplicate-account error. It must not revoke or replace the existing signer.

Example link-device policy:

```ts
{
  mode: 'allocate_next_free',
}
```

`allocate_next_free` is for explicit link-device or import flows where adding
another signer is intentional. It is not for re-registering an already-created
account.

Example self-hosted import policy:

```ts
{
  mode: 'allocate_next_free',
}
```

Rotation and migration also use `allocate_next_free`: create a new signer slot,
verify the new signer, then explicitly update the active/default pointer during
a cutover step. They do not replace an existing signer in place.

### Central API

Introduce a single lifecycle primitive:

```ts
interface AccountSignerLifecycleStore {
  activateAccountSigner(input: ActivateAccountSignerInput): Promise<ActivateAccountSignerResult>;
}

type ActivateAccountSignerInput = {
  account: {
    profileId: string;
    chainIdKey: string;
    accountAddress: string;
    accountModel: string;
  };
  signer: {
    signerId: string;
    signerType: string;
    signerKind: SignerKind;
    signerAuthMethod: SignerAuthMethod;
    signerSource: SignerSource;
    metadata?: Record<string, unknown>;
  };
  activationPolicy: SignerActivationPolicy;
  preferredSlot?: number;
  selectAsActive?: boolean;
  mutation?: {
    routeThroughOutbox?: boolean;
    idempotencyKey?: string;
  };
};

type ActivateAccountSignerResult = {
  signer: AccountSignerRecord;
  signerSlot: number;
};
```

This API should own:

- reading active signers;
- deciding the slot;
- rejecting unsafe duplicate account registration attempts;
- activating or updating the target signer;
- setting last profile state when `selectAsActive` is true;
- returning the chosen slot for key material storage.

### Key Material Writes

After the lifecycle API returns a `signerSlot`, signer-specific flows can write key material:

```ts
const activation = await activateAccountSigner(...);

await storeNearThresholdKeyMaterial({
  signerSlot: activation.signerSlot,
  signerId: activation.signer.signerId,
  ...
});
```

`AccountKeyMaterialDB` now stores this as `signerSlot` in the reset v10
key-material store. `deviceNumber` is no longer accepted at this boundary.

### Idempotency

Registration and import flows must use stable idempotency keys:

```ts
email-otp-ed25519-registration:<accountAddress>:<signingRootId>:<keyVersion>
passkey-registration:<accountAddress>:<credentialId>
self-hosted-import:<accountAddress>:<signerKind>:<signerId>
```

Retrying the same operation must not create a second active signer or pick a
different slot. Duplicate account registration with different signer material
must fail closed.

### Historical Records

Signer records are immutable identity/history entries. New signer material must
create a new signer slot. Registration, migration, and rotation must not mutate
an existing signer record to point at different key material.

Revoked signers should be marked:

```ts
{
  status: 'revoked',
  removedAt: Date.now(),
  revocationReason: 'explicit_user_removal'
}
```

This keeps local debugging possible and makes startup reconciliation safer.

Registration retry must not create revoked historical records for a different
signer. A different signer during account creation is a duplicate-account error,
not a local replacement event.

Rotation and migration may later revoke or disable an old signer, but only after
the new signer slot is created, verified, and explicitly selected during
cutover.

## Desired Behavior

### Email OTP Ed25519 Retry

If an old active `threshold-ed25519` signer exists for the same account:

- if it is the same `signerId` and same key material, treat the operation as an
  idempotent retry and reuse its slot;
- if it is a different `signerId`, public key, account address, or key material,
  fail with a typed duplicate-account error;
- do not revoke or replace the old signer during registration retry;
- do not require clearing IndexedDB for an idempotent retry.

### Non-Threshold Signer in Slot 1

If slot `1` is occupied by a passkey or other non-replaced signer:

- do not revoke it;
- allocate the next free slot only for explicit link-device/import flows;
- fail closed for duplicate account registration.

### Rotation And Migration

If rotation or migration introduces new signer material:

- allocate a new `signerSlot`;
- write key material under the new slot;
- verify the new signer can produce the expected account public key/address or
  otherwise satisfies the migration policy;
- explicitly update the active/default pointer during cutover;
- optionally revoke or disable the old signer after cutover.

Do not update an existing signer slot in place with different key material.

### Same Signer Retry

If the same `signerId` is already active:

- reuse its slot;
- update metadata if needed;
- do not enqueue duplicate signer operations;
- do not rewrite key material unless needed.

### Partial Success Recovery

If key material exists but signer activation failed:

- rerun activation and bind to the same slot.

If signer activation exists but key material write failed:

- rerun key material write using the existing signer slot.

If session mint fails after local activation:

- retry should not collide;
- the signer may remain active locally because the cryptographic registration succeeded.

## Implementation Plan

### Phase 0: Inventory and Invariants

- [x] Document every current writer of `upsertAccountSigner`, `setAccountSignerStatus`, `setLastProfileStateForProfile`, and `storeNearThresholdKeyMaterial`.
- [x] Classify every signer writer by signer kind/source, account model, and activation policy.
- [x] Add a short code comment to the DB invariant explaining that duplicate active signer slots are intentionally rejected and must be resolved by lifecycle policy, not by weakening the invariant.
- [x] Identify every place where `deviceNumber` means physical passkey device versus generic key material slot.

### Phase 1: Types and Metadata

- [x] Extend `AccountSignerRecord` and `UpsertAccountSignerInput` with explicit
      signer classification metadata and `revocationReason`.
- [x] Update IndexedDB schema and validation to require signer classification metadata for new account signer writes.
- [x] Update current production signer writes to set explicit signer classification metadata.
- [x] Keep no legacy alias for new writes. If development data breaks, reset local IndexedDB.
- [x] Update invariant checks to validate signer classification metadata is present and non-empty for non-revoked signers.

### Phase 2: Slot Planner

- [x] Replace `planEmailOtpThresholdEd25519SignerSlot` with a generic `planAccountSignerActivation`.
- [x] Support `reuse_existing` for same-signer retry, `allocate_next_free`, and `fail_if_occupied`.
- [x] Make the planner pure and unit tested for the currently supported policies.
- [x] Test duplicate same-kind/different-signer registration fails closed.
- [x] Test rotation/migration allocates a new slot instead of mutating an
      existing signer slot.
- [x] Test non-family slot preservation.
- [x] Test same-signer idempotent retry.
- [x] Test full slot exhaustion.
- [x] Test active signer slot uniqueness remains enforced by DB invariants.

### Phase 3: Lifecycle Store

- [x] Add `activateAccountSigner` to `PasskeyClientDBManager`.
- [x] Add `stageAccountSigner` to `PasskeyClientDBManager` for pending signer staging.
- [x] Implement active signer read, planning, revocation, activation, and last profile state update in one logical operation.
- [x] Use one IndexedDB transaction for account signer mutations where possible.
- [x] Preserve outbox behavior through explicit mutation options.
- [x] Return `signer` and `signerSlot`.
- [x] Add tests for revocation metadata: `removedAt` and `revocationReason`.

### Phase 4: Refactor Email OTP Ed25519

- [x] Remove the Email OTP-specific slot planner.
- [x] Update `persistEmailOtpThresholdEd25519LocalMetadata` to call `activateAccountSigner`.
- [x] Use `reuse_existing` for idempotent same-signer retry for
      `signerKind: 'threshold-ed25519'`;
      duplicate registration with different signer material must fail closed.
- [x] Write key material using the returned `signerSlot`.
- [x] Ensure retry after session mint failure does not collide.
- [x] Ensure retry after key material write failure repairs the missing material.

### Phase 5: Refactor Passkey Registration

- [x] Move passkey registration slot selection into `activateAccountSigner`.
- [x] Model passkey registration as a threshold signer with `signerAuthMethod: 'passkey'`, not as `SignerKind: 'passkey'`.
- [x] Use `signerSource: 'passkey_registration'`.
- [x] Use `activationPolicy: { mode: 'allocate_next_free' }` for explicit
      link-device flows unless a specific credential id is being idempotently
      retried.
- [x] Rename WebAuthn/passkey slot parameters to `signerSlot` while keeping
      physical authenticator identity on `credentialId`, `rawId`, transports,
      and authenticator metadata.

### Phase 6: Refactor Threshold ECDSA

- [x] Classify threshold ECDSA signers with `signerKind: 'threshold-ecdsa'`.
- [x] Remove `session` and `recovery` from signer-kind planning. Session is a
      wallet auth proof method, and recovery is a recovery/provisioning flow
      unless it independently signs transactions.
- [x] Replace active signer writes from signing flows with `activateAccountSigner`.
- [x] Replace pending signer writes from signing flows with `stageAccountSigner`.
- [x] Keep lower-level DB methods available only for migrations/tests/internal lifecycle code.

### Phase 7: Key Material Slot Naming

- [x] Add API-level names `signerSlot`.
- [x] Rename local variables in threshold signer flows to `signerSlot`.
- [x] Remove legacy slot names from passkey, WebAuthn, server, and shared
      production request/record shapes.
- [x] Decide whether to reset IndexedDB schema or migrate
      `AccountKeyMaterialDB.deviceNumber` to `signerSlot`.
      Decision: reset the key-material store because local development data may
      be discarded.
- [x] If resetting schema, remove old schema names rather than carrying
      compatibility paths.
- [x] Rename `AccountKeyMaterialDB` schema, AAD, stored records, helper inputs,
      and reconciliation from `deviceNumber` to `signerSlot`.
- [x] Remove signer saga compatibility fallback from `payload.deviceNumber` to
      `payload.signerSlot`.
- [x] Update key-material fixtures and regression tests to write
      `signerSlot`.

### Phase 8: Startup Reconciliation

- [x] Add a local signer reconciliation pass on SDK startup or account load.
- [x] Detect multiple active signers with the same account slot.
- [x] Detect active signer without key material for signer families that require key material.
- [x] Detect key material without an active signer.
- [x] Detect stale pending signers older than a fixed threshold.
- [x] Repair only safe cases, otherwise surface a typed local state issue.
      Current implementation is intentionally non-destructive: it returns typed
      reconciliation issues and performs no automatic repairs.
- [x] Add telemetry/logging for reconciliation findings.

### Phase 9: Verification

- [x] Unit test the pure planner.
- [x] Unit test `PasskeyClientDBManager.activateAccountSigner`.
- [x] Browser test Email OTP retry with stale threshold Ed25519 signer at slot 1.
- [x] Browser test non-threshold signer at slot 1 causes threshold Ed25519 to use slot 2.
- [x] Browser test same-signer retry is idempotent.
- [x] Browser test pending signer staging preserves metadata and does not change last profile state.
- [x] Browser test partial failure after signer activation and before key material write.
- [x] Browser test partial failure after key material write and before session mint.
- [x] Run SDK build.
- [x] Run relay-server typecheck.
- [x] Run affected Email OTP, threshold Ed25519, and NEAR signing tests.
- [x] Run IndexedDB invariant tests.
- [x] Add guard coverage that production signer lifecycle writes must provide
      explicit signer classification metadata.
- [x] Add IndexedDB-backed coverage for local signer reconciliation findings.

### Phase 10: Auth Metadata Inventory

- [x] Inventory where account auth method is currently stored or inferred:
      IndexedDB profile state, account signer metadata, warm-session state,
      iframe session state, relay session claims, and demo app state.
- [x] Identify all direct calls that trigger WebAuthn prompts from wallet
      unlock, Ed25519 signing, ECDSA signing, Ed25519 export, and ECDSA export.
- [x] Identify all direct calls that trigger Email OTP prompts from login,
      unlock, ECDSA signing, Ed25519 signing, and export flows.
- [x] Identify all server request payloads that still make
      `webauthn_authentication` the only accepted auth proof.
- [x] Document the canonical persisted field for `primaryAuthMethod`.
- [x] Add account fixtures for passkey-only, Email OTP-only, and passkey plus
      Email OTP accounts.

### Phase 11: Wallet Auth Mode Resolver

- [x] Add `WalletAuthMethod`, `WalletAuthIntent`, `WalletAuthProof`,
      `WalletAuthPlan`, and `WalletAuthModeResolver` types.
- [x] Implement a passkey auth adapter that owns WebAuthn challenge and
      completion for wallet intents.
- [x] Implement an Email OTP auth adapter that owns 6-digit OTP challenge and
      completion for wallet intents.
- [x] Add a resolver primitive that resolves auth plans from account metadata,
      with warm-session short-circuit support.
- [x] Make EVM and Tempo `transaction_sign` resolve through
      `WalletAuthModeResolver`, then bridge to the existing touch-confirm auth
      mode until Phase 12 removes the narrow enum.
- [x] Make NEAR `transaction_sign` resolve through `WalletAuthModeResolver`,
      while preserving the existing touch-confirm hook boundary.
- [x] Make passkey Ed25519 `session_mint` resolve through
      `WalletAuthModeResolver` while preserving the existing relay mint
      payload.
- [x] Make passkey `wallet_unlock` session exchange resolve through
      `WalletAuthModeResolver` while preserving the existing
      `passkey_assertion` exchange payload.
- [x] Make Email OTP per-operation `session_mint` for Ed25519 and ECDSA
      transaction signing resolve through `WalletAuthModeResolver`.
- [x] Make passkey `ed25519_export` and `ecdsa_export` authorization use the
      resolver instead of direct WebAuthn UI. Email OTP exports are currently
      blocked by policy before auth UI opens.
- [x] Remove the stale `signer_refresh` intent from the plan. Link-device is
      the concrete wallet flow that needs resolver coverage when it requires
      step-up auth.
- [x] Remove duplicate per-flow auth-mode guessing once each flow has moved to
      the resolver.

### Phase 12: Full Signing Auth Plans

- [x] Replace narrow `SigningAuthMode` return values with full
      `WalletAuthPlan` values.
      Completed: orchestration auth helpers now emit request-ready
      `SigningAuthPlan` payloads only. The shared EVM/Tempo helper errors when
      no concrete plan is available instead of synthesizing legacy
      `warmSession`, and NEAR threshold auth emits an `emailOtpReauth`
      `SigningAuthPlan` instead of `signingAuthMode: 'emailOtp'`.
- [x] Add a serializable `SigningAuthPlan` envelope at the touch-confirm
      boundary so signing UI can consume warm-session, passkey reauth, and
      Email OTP reauth intent without re-guessing from a string mode.
- [x] Pass `SigningAuthPlan` through NEAR transaction, EVM, and Tempo
      transaction confirmation flows while keeping `SigningAuthMode` as a
      derived compatibility field during the transition.
- [x] Add regression coverage proving touch-confirm request handling prefers
      `SigningAuthPlan` over a conflicting legacy `SigningAuthMode`.
- [x] Replace the EVM/Tempo orchestration helper with a touch-confirm auth
      resolver that returns both `SigningAuthPlan` and its derived legacy mode,
      then remove the stale mode-only helper.
- [x] Extend the NEAR Ed25519 warm-session planner with account, method,
      retention, TTL, and remaining-use metadata, then forward warm-session
      `SigningAuthPlan` through transaction, delegate, and NEP-413 confirmation
      flows.
- [x] Make the touch-confirm orchestrator derive the effective UI auth mode from
      `SigningAuthPlan` and omit legacy `SigningAuthMode` from request payloads
      whenever a plan is present.
- [x] Make NEAR Ed25519 passkey fallback emit a concrete
      `passkeyReauth` signing plan instead of only carrying legacy
      `signingAuthMode: 'webauthn'`.
- [x] Stop forwarding redundant legacy `signingAuthMode` from NEAR, EVM, and
      Tempo orchestration when a concrete `SigningAuthPlan` is present.
- [x] Make the shared EVM/Tempo touch-confirm auth resolver emit
      `passkeyReauth` for direct WebAuthn fallback so lower-level signing
      callers also avoid redundant legacy mode payloads.
- [x] Make NEAR threshold signing auth resolution return a request-ready
      touch-confirm auth payload, so transaction, delegate, and NEP-413 flows
      no longer duplicate `SigningAuthPlan` versus legacy `SigningAuthMode`
      forwarding logic.
- [x] Make the shared EVM/Tempo signing auth resolver return the same
      request-ready auth payload shape, so EVM and Tempo no longer duplicate
      the transitional legacy-mode spread rule locally.
- [x] Remove the remaining NEAR transaction Email OTP legacy-mode fallback;
      Email OTP confirmation now travels through a concrete `emailOtpReauth`
      plan whenever the prompt is present.
- [x] Stop returning separate narrow auth-mode values from the shared
      EVM/Tempo resolver; callers now consume only the request-ready
      touch-confirm auth payload.
- [x] Remove obsolete shared resolver inputs that implied it still inspected
      ECDSA key refs or warm-session state directly.
- [x] Replace `WarmSessionManager.resolveEd25519SigningAuthPlan` narrow
      `signingAuthMode` returns with plan-kind decisions:
      `warmSession`, `passkeyReauth`, and `emailOtpReauth`.
- [x] Make signing planners return `warmSession`, `passkeyReauth`, or
      `emailOtpReauth` with challenge and complete hooks. Resolver-backed
      passkey and Email OTP plans own their challenge/complete hooks;
      warm-session plans carry ready session metadata and require no challenge.
- [x] Ensure signing flows consume normalized `WalletAuthProof`, not
      WebAuthn-specific payloads. Transaction signing APIs route through
      `WalletAuthPlan`, and Ed25519 session mint normalizes auth proof before
      passkey-specific verification.
- [x] Ensure warm-session reuse checks include auth method, account id,
      signing root id, curve, policy, TTL, and remaining-use budget.
- [x] Add negative tests proving an Email OTP account cannot fall through to a
      WebAuthn-only planner path.
- [x] Add negative tests proving a passkey account cannot accidentally consume
      an Email OTP proof unless Email OTP is explicitly linked and policy allows
      it.

### Phase 13: Email OTP Ed25519 Session Source

- [x] Add Email OTP as a real Ed25519 session source.
- [x] Persist Email OTP auth context for Ed25519 sessions with the same
      policy, TTL, and remaining-use semantics used for ECDSA.
- [x] Replace the remaining Ed25519 session-mint server auth branching with
      normalized `WalletAuthProof` validation. The current Email OTP path is
      authorized by app-session or ECDSA-session claims, while passkey mint
      still validates `webauthn_authentication` directly.
- [x] Ensure the client Email OTP Ed25519 signing path never calls the
      WebAuthn-only session-mint path after resolving `method: 'email_otp'`.
- [x] Ensure Email OTP registration creates both Ed25519 and ECDSA local
      signer/session metadata.
- [x] Add focused unit coverage: Email OTP Ed25519 sign without WebAuthn
      fallback.
- [x] Add focused unit coverage: Email OTP ECDSA sign without WebAuthn
      fallback.
- [x] Add a browser smoke test: Email OTP registration -> Ed25519 NEAR sign
      without WebAuthn prompt.
- [x] Add a browser smoke test: Email OTP registration -> ECDSA sign without
      WebAuthn prompt.
      Completed in `tests/e2e/emailOtp.thresholdEcdsa.tempoSigning.test.ts`:
      session-mode Email OTP registration signs NEAR Ed25519 after login, and
      session/per-operation Email OTP ECDSA signs without falling through to
      WebAuthn.

### Phase 14: Export Auth Policy

- [x] Decide whether Email OTP-only accounts may export Ed25519 and ECDSA
      keys with fresh OTP step-up.
- [x] Add dedicated Email OTP export lanes for Ed25519 and ECDSA.
- [x] Require fresh export-scoped Email OTP step-up for Email OTP-only export.
- [x] Bind server-side Email OTP challenge/verify records to the `export_key`
      operation so export OTPs cannot be replayed as signing or unlock OTPs.
- [x] Add route-level `export_key` policy approval and export-specific audit
      logging.
- [x] Remove the temporary fail-closed Email OTP export guard once OTP export
      lanes are active.
- [x] Ensure export flows call the wallet auth-mode resolver instead of
      directly opening WebAuthn UI.
- [x] Add tests for passkey Ed25519 export.
- [x] Add tests for passkey ECDSA export.
- [x] Add tests for Email OTP Ed25519 export with OTP step-up.
- [x] Add tests for Email OTP ECDSA export with OTP step-up.
- [x] Replace the old Email OTP export restriction with UI coverage proving
      Email OTP accounts can open the export drawer and are routed to OTP
      step-up, not Touch ID/WebAuthn.
- [x] Replace UI guard copy once OTP export UI exists: "Enter email code to
      export" instead of "passkey required."

### Phase 15: Auth/Signer Matrix Verification

- [x] Add a matrix test for passkey account wallet unlock, Ed25519 sign, ECDSA
      sign, Ed25519 export, and ECDSA export.
- [x] Add a matrix test for Email OTP account wallet unlock, Ed25519 sign,
      ECDSA sign, Ed25519 export, and ECDSA export.
- [x] Extend the Email OTP matrix test to cover Ed25519 export and ECDSA
      export with fresh OTP step-up.
- [x] Add tests for mixed accounts with both passkey and Email OTP linked.
- [x] Verify resolver-covered wallet flows use the same account auth metadata
      source through passkey, Email OTP, and mixed-account matrix tests.
- [x] Verify no generic signing/session/export path requires
      `webauthn_authentication` without first resolving `method: 'passkey'`.
- [x] Run SDK build and focused affected unit tests for the resolver/export
      changes.
- [x] Run relay-server build and focused Ed25519 session-mint relayer tests.
- [x] Run full affected browser smoke tests after the existing
      `threshold-ed25519.scope` fixture failures are cleaned up.
      Completed: broad affected wallet smoke passes across Email OTP ECDSA
      Tempo/EVM signing, wallet iframe NEAR signing, sealed refresh,
      threshold ECDSA manual-bootstrap link-device, and threshold Ed25519
      delegate/NEP-413 signing.

### Phase 16: Universal `signerSlot` Rename

Goal: remove legacy local-slot names. Use `signerSlot` for every local account
signer slot, including passkey-backed signers. Use `credentialId` or explicit
WebAuthn terminology for physical authenticator identity.

- [x] Update the specs in this document so `signerSlot` is the only local slot
      name. Remove transitional key-material slot terminology from examples and
      resolved recommendations.
- [x] Rename `AccountKeyMaterialDB` schema, AAD, stored records, helper inputs,
      indexes, and test fixtures to `signerSlot`.
- [x] Reset the key-material IndexedDB store again rather than carrying
      compatibility aliases. Suggested store: `keyMaterialV4` with key path
      `[profileId, signerSlot, chainIdKey, keyKind]`.
- [x] Rename lifecycle return values to
      `{ signerSlot }`. Key material writers must use `activation.signerSlot`.
- [x] Rename `LastProfileState.deviceNumber` to `activeSignerSlot`.
- [x] Rename `Profile.defaultDeviceNumber` to `defaultSignerSlot`.
- [x] Rename passkey registration, login, link-device, account projection, and
      WebAuthn prompt parameters from `deviceNumber` to `signerSlot` when the
      value selects a local account signer slot.
- [x] Rename account projection helper parameters from `deviceNumber` to
      `signerSlot`.
- [x] Rename touch-confirm registration request payloads, registration
      summaries, and WebAuthn registration helper parameters to `signerSlot`.
- [x] Replace WebAuthn user-handle helpers like
      `generateDeviceSpecificUserId` with signer-slot language, for example
      `generateSignerSlotUserId`.
- [x] Keep `credentialId`, `rawId`, authenticator transports, and authenticator
      metadata as the physical-passkey identity boundary. Do not rename those
      to signer-slot concepts.
- [x] Rename passkey authenticator IndexedDB indexes and records that currently
      use `deviceNumber` to `signerSlot` if they are slot-scoped rather than
      credential-scoped.
- [x] Rename internal export-worker payloads from `deviceNumber` to
      `signerSlot`.
- [x] Rename NEAR signing iframe/request slot hints for transaction signing,
      sign-and-send, delegate signing, execute-action, NEP-413 signing, and
      start-device2 linking to `signerSlot`.
- [x] Remove compatibility fallback reads from old public payload slot fields.
      Local development data may be reset.
- [x] Update UI copy from "device" to "signer" or "passkey" depending on the
      user-facing concept. Avoid exposing `signerSlot` directly unless in debug
      tooling.
- [x] Add guard tests proving no generic signing, key material, lifecycle,
      profile-state, or WebAuthn slot-selection code exports legacy slot names.
- [x] Add regression tests for multiple signers associated with the same
      passkey credential/device to prove the model no longer assumes one signer
      per device.
- [x] Run SDK build, relay-server typecheck, affected unit tests, IndexedDB
      invariant tests, and browser smoke tests after the rename.
      Completed: SDK typecheck, SDK build, production-source no-legacy grep,
      and focused wallet-iframe browser smoke tests pass. Passkey login now
      resolves the managed runtime policy scope before minting a fresh Ed25519
      session, so login does not overwrite registration session state with a
      signing-root-scope-less record. Follow-up: unit fixture cleanup is also
      complete; exact legacy slot-name grep is clean across source, e2e, and
      unit tests; signer-slot guard tests pass; focused Ed25519/ECDSA
      immediate-sign/export/link-device unit coverage passes.

### Phase 17: Signer Kind Metadata Cleanup

Goal: remove the remaining legacy `signerFamily` model. `passkey`, `session`,
and `recovery` must not appear as signer kinds.

- [x] Rename persisted and runtime fields from `signerFamily` to `signerKind`.
- [x] Add `signerAuthMethod` to signer lifecycle records and inputs.
- [x] Restrict `SignerKind` to `threshold-ed25519 | threshold-ecdsa`.
- [x] Restrict `SignerAuthMethod` to `passkey | email_otp`.
- [x] Restrict `SignerSource` to
      `passkey_registration | email_otp_registration | self_hosted_import`.
- [x] Remove `replace_same_family`/`replace_same_kind`; registration supports
      only `reuse_existing` for identical same-signer retry or typed
      duplicate-account failure.
- [x] Ensure rotation and migration always allocate a new signer slot and use an
      explicit cutover step.
- [x] Replace `signerSource: 'email_otp'` with
      `signerSource: 'email_otp_registration'`.
- [x] Remove any production or test writes that use
      `signerKind: 'passkey'`, `signerKind: 'session'`, or
      `signerKind: 'recovery'`.
- [x] Add guard tests proving `SignerKind` does not include auth methods,
      proof methods, or recovery flows.
- [x] Update account-auth fixtures to model passkey-backed and Email
      OTP-backed threshold signers via `signerAuthMethod`.
- [x] Run SDK build, relay-server typecheck, signer lifecycle tests, and account
      auth resolver tests.
      Completed: `pnpm -C sdk build`, `pnpm -C examples/relay-server exec tsc
--noEmit`, focused signer lifecycle and Email OTP bootstrap unit tests,
      account auth resolver tests, and no-legacy signer metadata grep.
- [x] Run affected browser registration smokes for passkey and Email OTP after
      the parallel Email OTP polish/refactor thread stabilizes.
      Completed: focused Email OTP and passkey wallet-iframe browser smokes
      pass. The Email OTP smoke exposed and fixed a route regression where
      `/wallet/email-otp/login/challenge` forwarded an undefined `operation`;
      both Cloudflare and Express routes now bind challenge/verify operations
      consistently.

Rotation/migration note: there are no production rotation or migration flows in
this phase. The completed enforcement is at the signer lifecycle boundary: the
replacement modes are gone, registration cannot replace a different active
signer, and any future flow that introduces different signer material must use
`allocate_next_free` plus an explicit active/default cutover.

## Resolved Decisions And Recommendations

### Last Profile State

Decision: `lastProfileState` points to the most recent active signer for an
account, not only the most recent passkey device.

Implication:

- Use `signerSlot` consistently in local code, SDK request shapes, server
  request shapes, and persisted records.
- Keep physical-device wording only for actual device-linking UX concepts, not
  slot identifiers.

### Threshold Ed25519 And ECDSA Slots

Recommendation: use separate signer slots per signer kind and curve.

Why:

- Ed25519 and ECDSA have different key material, signing sessions, export
  paths, and failure modes.
- Replacing or repairing the ECDSA signer should not accidentally revoke or
  overwrite the Ed25519 signer.
- Separate slots make lifecycle reconciliation simpler because each active
  signer has one clear material owner.

Tradeoff:

- Separate slots create more local signer records and require UI grouping so
  users do not see confusing "two devices" for one Email OTP account.
- A shared slot is simpler for "one wallet signer" mental models, but it
  recreates the collision class this refactor is trying to remove.

Implementation default: separate slots, grouped under one account-level auth
method in UI.

### Key Material Writes

Recommendation: lifecycle owns signer activation and returns `signerSlot`;
signer-specific flows write key material.

Why:

- The lifecycle layer should not own secret formats for Ed25519, ECDSA,
  passkey PRF material, or future signers.
- Signer-specific flows already know when material is generated, worker-owned,
  exportable, or intentionally absent.
- Keeping material writes outside lifecycle reduces accidental secret handling
  in generic account metadata code.

Required guardrail:

- Activation plus key-material write must be treated as a saga. If material
  write fails after signer activation, the flow must repair the same signer or
  mark that same attempted signer failed. It must not replace an existing
  different signer.
- If rotation or migration introduces different key material, it must allocate a
  new signer slot and then cut over the active/default pointer explicitly.

### Replaced Signer Visibility

Recommendation: normal account settings show only active user-actionable
signers. Revoked signers remain available in debug tooling and local
diagnostics.

Why:

- Users need to manage login methods, not internal threshold signer attempts.
- Debug tooling still needs revoked signers to explain reconciliation repairs,
  explicit removals, retries, and stale local state.

### Local Reconciliation

Recommendation: run lightweight reconciliation automatically on startup or
account load, and also run targeted reconciliation after failed signer lookup.

Startup/account-load reconciliation should:

- detect duplicate active slots;
- detect active signers missing required key material;
- detect key material without an active signer;
- detect stale pending signers.

It should only auto-repair safe local cases. Risky cases should emit typed
errors and diagnostics. Heavy or network-dependent repair should stay lazy and
trigger only after lookup/signing failure.

### Primary Auth Method Storage

Recommendation: store `primaryAuthMethod` in a separate account wallet-auth
metadata record, with profile state holding only a cached projection for fast UI
reads.

Why:

- It is account-level auth policy, not curve-specific signer metadata.
- Mixed passkey plus Email OTP accounts need `primaryAuthMethod` plus
  `linkedAuthMethods`, which does not fit cleanly on one signer record.
- A separate record keeps product policy independent from Ed25519/ECDSA signer
  identity and lifecycle.

### Email OTP Export

Decision: Email OTP-only accounts may export Ed25519 and ECDSA keys with fresh
OTP step-up.

Implementation requirements:

- Export must use `per_operation` Email OTP.
- Export challenges must be operation-scoped and server-authorized.
- Export material must be discarded after viewer close.
- Email OTP export must not reuse WebAuthn PRF export paths.

### Mixed Passkey Plus Email OTP Accounts

Decision: offer both auth options in the UI, defaulting to passkey.

Product behavior:

- Sensitive actions use passkey by default.
- If project policy allows Email OTP as an alternate step-up, show a smaller
  "use one-time password" text link.
- Do not silently downgrade passkey accounts to Email OTP.

### Warm-Session Policy

Decision: Ed25519 and ECDSA share one warm-session policy model.

Implication:

- Use the same `session` and `per_operation` retention semantics for both
  curves.
- Curve-specific code may enforce different key handling details, but should not
  invent a separate policy model.

## Recommended Direction

Implement the centralized planner and lifecycle API first, then finish the
Email OTP export step-up path. Email OTP is the flow currently proving the
idempotency, auth-mode, and warm-session abstractions across both Ed25519 and
ECDSA.

Keep the active slot uniqueness invariant. The invariant caught a real lifecycle bug. The fix is better lifecycle ownership, not loosening the database rule.

In parallel, introduce the wallet auth-mode resolver and make it the only
prompt/auth selector for wallet flows. The resolver should use stored
account/session metadata to choose `passkey` versus `email_otp`; individual
Ed25519, ECDSA, unlock, and export flows should stop guessing. Treat Email OTP
as a real session source for both ECDSA and Ed25519, and make export policy an
explicit product decision rather than an accidental WebAuthn fallback.

## Cleanup Follow-Up: Domain Types, Validation, And Route Deduplication

Recommendation:

- Keep private string unions when the value never crosses a module, storage,
  JSON, audit, or SDK boundary.
- Prefer `as const` domain maps/arrays plus derived union types for most shared
  TypeScript domains. Use a real enum only when a runtime enum object is useful:
  generated clients, Rust/WASM binding symmetry, or stable public SDK option
  iteration.
- Wire-level, persisted, audited, and cross-package domains should live in a
  shared domain module with constants, derived types, and parser helpers.
- Reuse validation and normalization helpers from
  `shared/src/utils/validation.ts` and `shared/src/utils/normalize.ts` instead
  of redefining local helpers with equivalent behavior.
- Extract duplicated server-side Email OTP route logic only where it reduces
  drift between Express and Cloudflare. Do not keep compatibility aliases or
  duplicate legacy request shapes.

Todo:

1. [x] Audit string union types for Email OTP, wallet auth, signer lifecycle,
       and export policy domains; decide whether each should stay private,
       become shared `as const` constants plus derived types, or become a real
       enum.
       Completed for the first cleanup slice: Email OTP wire values now use
       shared `as const` constants plus derived types, not enums. The Email OTP
       request parser, export-policy audit payload, Express/Cloudflare
       export-policy routes, client Email OTP helper, AuthService
       challenge/verify path, and Email OTP store normalization now consume
       those shared constants.
2. [x] Move remaining cross-boundary values such as `email_otp`, `wallet_unlock`,
       `transaction_sign`, `export_key`, `registration`,
       `wallet_email_otp_login`, `wallet_email_otp_registration`,
       `threshold-ed25519`, `threshold-ecdsa`, `passkey_registration`,
       `email_otp_registration`, and `self_hosted_import` into shared domain
       modules with parser helpers.
       Completed for wallet/signer metadata domains: shared `signerDomain`
       now owns wallet-auth method, wallet-auth proof method, signer kind,
       signer auth method, signer source, and signing-session retention values.
3. [x] Replace local helper copies such as `toOptionalTrimmedString`,
       `optionalClaimString`, local object/string guards, and equivalent
       normalizers with imports from shared validation/normalization utilities
       where behavior matches.
       First cleanup slice complete: Express/Cloudflare session claim parsing
       now uses shared `toOptionalRecordString`, and relay webhook string
       normalization now uses shared `toOptionalTrimmedString`. Matching
       non-array object guards now use shared `isPlainObject` in router,
       Cloudflare Durable Object, self-hosted worker, Email OTP store, and
       link-device parsing code.
4. [ ] Audit Express and Cloudflare Email OTP route duplication and extract
       shared helpers for body validation, app-session claim extraction,
       export-policy authorization, export audit payloads, and common response
       shaping.
       Completed slices: request parsing lives in
       `emailOtpRequestValidation.ts`; export policy/audit helpers live in
       `emailOtpExportPolicy.ts`; shared session-route helpers for status
       mapping, wallet-id claim extraction, Google OIDC detection, and OIDC
       account-mode parsing live in `emailOtpSessionRouteHelpers.ts`. Email
       OTP challenge response shaping now also lives there.
       Remaining work is larger common response-shaping extraction if the two
       route files keep drifting.
5. [x] Add remaining guard tests that reject duplicated hard-coded domain literals and
       duplicated local validation helpers in router/client/server boundary
       code.
       Completed for wallet-auth resolver, signer lifecycle domain
       redeclarations, and generic Email OTP router claim/string helper
       duplication.
6. [x] Keep the cleanup breaking and direct: remove replaced symbols and do not
       add legacy aliases.

## Review Follow-Up: Lifecycle Correctness And Client Cleanup

This follow-up tracks gaps found after the signer-slot/auth refactor landed.
These are implementation hardening tasks, not new product features.

Todo:

1. [x] Require same-signer retries to prove the same signer material, not just
       the same `signerId`. `reuse_existing` must compare a stable
       signer-material fingerprint so a retry cannot silently overwrite local
       metadata or key material for a different public key, key version, or
       relayer key.
2. [x] Add negative tests for same `signerId` with different signer material.
       The expected behavior is a typed/clear duplicate or material-mismatch
       failure, with the original active signer and key material left intact.
3. [x] Make active/default slot cutover explicit. `activateAccountSigner` is
       correct for registration, but rotation, migration, and import flows must
       be able to stage or activate a signer without automatically changing
       `lastProfileState.activeSignerSlot`, then cut over in a separate
       verified step.
4. [x] Decide whether threshold ECDSA bootstrap owns an `AccountSignerRecord`.
       If yes, move the bootstrap writer through signer lifecycle. If no,
       update the writer inventory and phase checklist so ECDSA bootstrap state
       is not falsely marked as an account-signer writer.
5. [x] Remove the remaining EOA/local-signer lifecycle model. There is no
       local EOA signer in the current wallet architecture; any future EOA-like
       domain must be isolated from account signer lifecycle instead of keeping
       signer-slot constraints named after EOA.
6. [x] Split `WalletAuthMethod` from `SignerAuthMethod` in shared domain code.
       The current value set is the same, but wallet auth policy and signer
       provisioning metadata are separate concepts and should not be type
       aliases.
7. [x] Tighten production write types so signer classification metadata is
       required at compile time. If tests need to exercise malformed records,
       they should cast to an internal/malformed input type explicitly rather
       than making production inputs optional.
8. [x] Refresh stale plan snippets, especially the `Current State`
       `AccountSignerRecord` example, so the document describes the current
       model instead of pre-refactor shapes.
9. [x] Review client-side signer/auth code for duplicated local validation,
       duplicated planner glue, and duplicated auth-mode branching. Prefer
       shared domain constants and shared validation helpers where behavior is
       identical.

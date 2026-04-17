# Refactor Signer Slot Lifecycle

## Problem

The SDK currently uses `signerSlot` as the local account signer slot and also uses `deviceNumber` as the account key material storage slot. This is workable for passkeys, where a signer usually maps to a user device, but it is brittle for threshold signers that are not physical devices.

The immediate bug was an active signer slot collision:

- Email OTP Ed25519 registration retried or re-ran.
- The retry produced a new `threshold-ed25519:<relayerKeyId>` signer.
- A previous local `threshold-ed25519:*` signer for the same NEAR account was still marked `active` in IndexedDB at slot `1`.
- The new signer also tried to use slot `1`.
- `PasskeyClientDBManager` correctly rejected the write with `DUPLICATE_ACTIVE_SIGNER_SLOT`.

This was not a crypto failure. It was a local signer lifecycle failure: registration flows were guessing slot ownership instead of using a centralized, idempotent allocation and replacement policy.

## Goals

- Make signer slot allocation explicit, deterministic, and centralized.
- Preserve the DB invariant that only one active signer may occupy a slot for a given account.
- Treat retries and partial-success registration flows as idempotent or replacement operations, not as ad hoc new signer inserts.
- Separate physical passkey device concepts from generic local signer concepts.
- Separate account auth method selection from curve-specific signing and export flows.
- Route every wallet flow through one auth-mode resolver instead of letting each flow guess passkey versus Email OTP behavior.
- Support future signer types: passkey, threshold Ed25519, threshold ECDSA, session signers, recovery signers, delegated signers, and self-hosted signers.
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
  status: 'active' | 'pending' | 'revoked';
  metadata?: Record<string, unknown>;
};
```

`PasskeyClientDBManager` enforces:

- one active signer per `(chainIdKey, accountAddress, signerSlot)`;
- EOA accounts may have at most one active signer;
- revoked signers must carry `removedAt`;
- `lastProfileState.deviceNumber` must point to an existing non-revoked signer slot.

`AccountKeyMaterialDB` is keyed by:

```ts
[profileId, deviceNumber, chainIdKey, keyKind]
```

This means `deviceNumber` currently doubles as a generic key material slot. That coupling is the main naming and lifecycle mismatch.

The immediate Email OTP fix added a flow-local helper:

```ts
planEmailOtpThresholdEd25519SignerSlot({
  activeSigners,
  signerId,
});
```

That helper is useful as a stopgap, but it should become part of a general signer lifecycle system rather than staying Email OTP-specific.

The same class of lifecycle drift also exists in wallet auth routing:

- Email OTP accounts can still hit WebAuthn prompts or server paths that require `webauthn_authentication`.
- Passkey accounts and Email OTP accounts do not have one shared source of truth for auth method selection.
- ECDSA warm sessions have more complete Email OTP auth context than Ed25519 warm sessions.
- Signing planners currently return narrow auth hints instead of a full executable auth plan.
- Key export policy is not explicit for Email OTP-only accounts.

These are not independent UI bugs. They are caused by the same missing boundary:
local account metadata should decide signer lifecycle and wallet auth mode before
curve-specific signing, login, unlock, or export code runs.

## Target Model

### Terminology

- `signerId`: stable identifier for one signer instance, for example `threshold-ed25519:<relayerKeyId>`.
- `signerSlot`: local account signer slot. Only one active signer may occupy a slot for a given account.
- `signerFamily`: semantic signer family, for example `passkey`, `threshold-ed25519`, `threshold-ecdsa`, `session`, `recovery`.
- `signerSource`: provisioning source, for example `passkey_registration`, `email_otp`, `managed_registration`, `self_hosted_import`.
- `keyMaterialSlot`: storage slot for local key material. Initially this can equal `signerSlot`, but the name should stop implying a physical device.
- `deviceNumber`: passkey-device-specific alias. Use only where the signer is actually a passkey device or where WebAuthn user handles require the existing terminology.

### Signer Family Metadata

Add explicit metadata to every account signer:

```ts
type SignerFamily =
  | 'passkey'
  | 'threshold-ed25519'
  | 'threshold-ecdsa'
  | 'session'
  | 'recovery'
  | string;

type SignerSource =
  | 'passkey_registration'
  | 'email_otp'
  | 'managed_registration'
  | 'self_hosted_import'
  | string;

type AccountSignerRecord = {
  signerFamily: SignerFamily;
  signerSource?: SignerSource;
  replacementSignerId?: string;
  revocationReason?: string;
};
```

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

- `signerFamily`, for example `threshold-ed25519` or `threshold-ecdsa`;
- `signerSource`, for example `email_otp` or `passkey_registration`;
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
  | 'signer_refresh';

type WalletAuthProof =
  | {
      method: 'passkey';
      webauthnAuthentication: unknown;
      prfOutput?: Uint8Array;
    }
  | {
      method: 'email_otp';
      emailOtpAuthentication: unknown;
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

Key export must have an explicit policy for Email OTP-only accounts. There are
two acceptable product choices:

- Email OTP export is allowed: add dedicated Email OTP export lanes for both
  Ed25519 and ECDSA, require fresh OTP step-up, and use short TTL or
  single-use authorization.
- Email OTP export is not allowed: state that Email OTP-only accounts cannot
  export keys until a passkey is linked, and surface a typed product error
  instead of showing a WebAuthn prompt that cannot succeed.

Do not let export flows silently choose WebAuthn for Email OTP-only accounts.
That makes the account look broken and hides the real product policy decision.

### Replacement Policies

Centralize activation around a replacement policy:

```ts
type SignerReplacementPolicy =
  | { mode: 'reuse_existing' }
  | { mode: 'replace_same_family'; signerFamily: string; reason: string }
  | { mode: 'replace_matching'; matcher: SignerMatcher; reason: string }
  | { mode: 'allocate_next_free' }
  | { mode: 'fail_if_occupied'; signerSlot: number };
```

Example Email OTP Ed25519 policy:

```ts
{
  mode: 'replace_same_family',
  signerFamily: 'threshold-ed25519',
  reason: 'email_otp_registration_refresh',
}
```

Example passkey registration policy:

```ts
{
  mode: 'allocate_next_free',
}
```

Example deterministic import policy:

```ts
{
  mode: 'reuse_existing',
}
```

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
    signerFamily: string;
    signerSource?: string;
    metadata?: Record<string, unknown>;
  };
  replacementPolicy: SignerReplacementPolicy;
  preferredSlot?: number;
  mutation?: {
    routeThroughOutbox?: boolean;
    idempotencyKey?: string;
  };
};

type ActivateAccountSignerResult = {
  signer: AccountSignerRecord;
  signerSlot: number;
  keyMaterialSlot: number;
  revokedSignerIds: string[];
};
```

This API should own:

- reading active signers;
- deciding the slot;
- revoking replaced signers;
- activating or updating the target signer;
- setting last profile state when appropriate;
- returning the chosen slot for key material storage.

### Key Material Writes

After the lifecycle API returns a `keyMaterialSlot`, signer-specific flows can write key material:

```ts
const activation = await activateAccountSigner(...);

await storeNearThresholdKeyMaterial({
  deviceNumber: activation.keyMaterialSlot,
  signerId: activation.signer.signerId,
  ...
});
```

Short term, `keyMaterialSlot` maps to `deviceNumber`. Longer term, rename `AccountKeyMaterialDB.deviceNumber` to `keyMaterialSlot` with a clean IndexedDB schema reset or migration.

### Idempotency

Registration and import flows must use stable idempotency keys:

```ts
email-otp-ed25519-registration:<accountAddress>:<signingRootId>:<keyVersion>
passkey-registration:<accountAddress>:<credentialId>
self-hosted-import:<accountAddress>:<signerFamily>:<signerId>
```

Retrying the same operation must not create a second active signer or pick a different slot unless the replacement policy explicitly allows rotation.

### Historical Records

Replaced signers should be marked:

```ts
{
  status: 'revoked',
  removedAt: Date.now(),
  replacementSignerId: newSignerId,
  revocationReason: 'email_otp_registration_refresh'
}
```

This keeps local debugging possible and makes startup reconciliation safer.

## Desired Behavior

### Email OTP Ed25519 Retry

If an old active `threshold-ed25519` signer exists for the same account:

- revoke the old signer locally;
- activate the new signer;
- reuse the old slot when safe;
- write threshold key material to the returned `keyMaterialSlot`;
- do not require clearing IndexedDB.

### Non-Threshold Signer in Slot 1

If slot `1` is occupied by a passkey or other non-replaced signer:

- do not revoke it;
- allocate the next free slot;
- keep both signers active if the account model supports multiple signers.

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

- [ ] Document every current writer of `upsertAccountSigner`, `setAccountSignerStatus`, `setLastProfileStateForProfile`, and `storeNearThresholdKeyMaterial`.
- [ ] Classify every signer writer by `signerFamily`, `signerSource`, account model, and replacement policy.
- [ ] Add a short code comment to the DB invariant explaining that duplicate active signer slots are intentionally rejected and must be resolved by lifecycle policy, not by weakening the invariant.
- [ ] Identify every place where `deviceNumber` means physical passkey device versus generic key material slot.

### Phase 1: Types and Metadata

- [ ] Extend `AccountSignerRecord` and `UpsertAccountSignerInput` with `signerFamily`, `signerSource`, `replacementSignerId`, and `revocationReason`.
- [ ] Update IndexedDB schema and validation to require `signerFamily` for new account signer writes.
- [ ] Update all current signer writes to set explicit `signerFamily`.
- [ ] Keep no legacy alias for new writes. If development data breaks, reset local IndexedDB.
- [ ] Update invariant checks to validate `signerFamily` is present and non-empty for non-revoked signers.

### Phase 2: Slot Planner

- [ ] Replace `planEmailOtpThresholdEd25519SignerSlot` with a generic `planAccountSignerActivation`.
- [ ] Support `reuse_existing`, `replace_same_family`, `replace_matching`, `allocate_next_free`, and `fail_if_occupied`.
- [ ] Make the planner pure and fully unit tested.
- [ ] Test stale same-family replacement.
- [ ] Test non-family slot preservation.
- [ ] Test same-signer idempotent retry.
- [ ] Test full slot exhaustion.
- [ ] Test EOA active signer limit behavior remains enforced by DB invariants.

### Phase 3: Lifecycle Store

- [ ] Add `activateAccountSigner` to `PasskeyClientDBManager`.
- [ ] Implement active signer read, planning, revocation, activation, and last profile state update in one logical operation.
- [ ] Use one IndexedDB transaction for account signer mutations where possible.
- [ ] Preserve outbox behavior through explicit mutation options.
- [ ] Return `signerSlot`, `keyMaterialSlot`, and `revokedSignerIds`.
- [ ] Add tests for replacement metadata: `removedAt`, `replacementSignerId`, and `revocationReason`.

### Phase 4: Refactor Email OTP Ed25519

- [ ] Remove the Email OTP-specific slot planner.
- [ ] Update `persistEmailOtpThresholdEd25519LocalMetadata` to call `activateAccountSigner`.
- [ ] Use `replacementPolicy: { mode: 'replace_same_family', signerFamily: 'threshold-ed25519', reason: 'email_otp_registration_refresh' }`.
- [ ] Write key material using the returned `keyMaterialSlot`.
- [ ] Ensure retry after session mint failure does not collide.
- [ ] Ensure retry after key material write failure repairs the missing material.

### Phase 5: Refactor Passkey Registration

- [ ] Move passkey registration slot selection into `activateAccountSigner`.
- [ ] Use `signerFamily: 'passkey'`.
- [ ] Use `signerSource: 'passkey_registration'`.
- [ ] Use `replacementPolicy: { mode: 'allocate_next_free' }` unless a specific credential id is being idempotently retried.
- [ ] Preserve WebAuthn `deviceNumber` semantics only at WebAuthn prompt/user-handle boundaries.

### Phase 6: Refactor Threshold ECDSA and Other Signers

- [ ] Classify threshold ECDSA local signers with `signerFamily: 'threshold-ecdsa'`.
- [ ] Classify session signers with `signerFamily: 'session'`.
- [ ] Classify recovery signers with `signerFamily: 'recovery'`.
- [ ] Replace all direct `upsertAccountSigner` calls from signing flows with `activateAccountSigner`.
- [ ] Keep lower-level DB methods available only for migrations/tests/internal lifecycle code.

### Phase 7: Key Material Slot Naming

- [ ] Add API-level names `keyMaterialSlot` while still writing to existing `deviceNumber` fields.
- [ ] Rename local variables in threshold signer flows from `deviceNumber` to `keyMaterialSlot` or `signerSlot`.
- [ ] Keep `deviceNumber` only in passkey-specific flows and persisted schema fields until the schema rename.
- [ ] Decide whether to reset IndexedDB schema or migrate `AccountKeyMaterialDB.deviceNumber` to `keyMaterialSlot`.
- [ ] If resetting schema, remove old schema names rather than carrying compatibility paths.

### Phase 8: Startup Reconciliation

- [ ] Add a local signer reconciliation pass on SDK startup or account load.
- [ ] Detect multiple active signers with the same account slot.
- [ ] Detect active signer without key material for signer families that require key material.
- [ ] Detect key material without an active signer.
- [ ] Detect stale pending signers older than a fixed threshold.
- [ ] Repair only safe cases, otherwise surface a typed local state error.
- [ ] Add telemetry/logging for reconciliation repairs.

### Phase 9: Verification

- [ ] Unit test the pure planner.
- [ ] Unit test `PasskeyClientDBManager.activateAccountSigner`.
- [ ] Browser test Email OTP retry with stale threshold Ed25519 signer at slot 1.
- [ ] Browser test non-threshold signer at slot 1 causes threshold Ed25519 to use slot 2.
- [ ] Browser test same-signer retry is idempotent.
- [ ] Browser test partial failure after signer activation and before key material write.
- [ ] Browser test partial failure after key material write and before session mint.
- [ ] Run SDK build.
- [ ] Run relay-server typecheck.
- [ ] Run affected Email OTP, threshold Ed25519, and NEAR signing tests.
- [ ] Run IndexedDB invariant tests.

### Phase 10: Auth Metadata Inventory

- [ ] Inventory where account auth method is currently stored or inferred:
      IndexedDB profile state, account signer metadata, warm-session state,
      iframe session state, relay session claims, and demo app state.
- [ ] Identify all direct calls that trigger WebAuthn prompts from wallet
      unlock, Ed25519 signing, ECDSA signing, Ed25519 export, and ECDSA export.
- [ ] Identify all direct calls that trigger Email OTP prompts from login,
      unlock, ECDSA signing, Ed25519 signing, and export flows.
- [ ] Identify all server request payloads that still make
      `webauthn_authentication` the only accepted auth proof.
- [ ] Document the canonical persisted field for `primaryAuthMethod`.
- [ ] Add account fixtures for passkey-only, Email OTP-only, and passkey plus
      Email OTP accounts.

### Phase 11: Wallet Auth Mode Resolver

- [ ] Add `WalletAuthMethod`, `WalletAuthIntent`, `WalletAuthProof`,
      `WalletAuthPlan`, and `WalletAuthModeResolver` types.
- [ ] Implement a passkey auth adapter that owns WebAuthn challenge and
      completion for wallet intents.
- [ ] Implement an Email OTP auth adapter that owns 6-digit OTP challenge and
      completion for wallet intents.
- [ ] Resolve auth plans from stored account/session metadata, not from
      flow-local guesses.
- [ ] Make `wallet_unlock`, `transaction_sign`, `ed25519_export`,
      `ecdsa_export`, `session_mint`, and `signer_refresh` use the resolver.
- [ ] Remove duplicate per-flow auth-mode guessing once each flow has moved to
      the resolver.

### Phase 12: Full Signing Auth Plans

- [ ] Replace narrow `SigningAuthMode` return values with full
      `WalletAuthPlan` values.
- [ ] Make signing planners return `warmSession`, `passkeyReauth`, or
      `emailOtpReauth` with challenge and complete hooks.
- [ ] Ensure signing flows consume normalized `WalletAuthProof`, not
      WebAuthn-specific payloads.
- [ ] Ensure warm-session reuse checks include auth method, account id,
      signing root id, curve, policy, TTL, and remaining-use budget.
- [ ] Add negative tests proving an Email OTP account cannot fall through to a
      WebAuthn-only planner path.
- [ ] Add negative tests proving a passkey account cannot accidentally consume
      an Email OTP proof unless Email OTP is explicitly linked and policy allows
      it.

### Phase 13: Email OTP Ed25519 Session Source

- [ ] Add Email OTP as a real Ed25519 session source.
- [ ] Persist Email OTP auth context for Ed25519 sessions with the same
      policy, TTL, and remaining-use semantics used for ECDSA.
- [ ] Update Ed25519 session mint server validation to accept normalized
      Email OTP auth proofs when the account auth method is `email_otp`.
- [ ] Remove generic Ed25519 errors that say `webauthn_authentication` is
      required when the resolved auth method is Email OTP.
- [ ] Ensure Email OTP registration creates both Ed25519 and ECDSA local
      signer/session metadata.
- [ ] Add a smoke test: Email OTP registration -> Ed25519 NEAR sign without
      WebAuthn prompt.
- [ ] Add a smoke test: Email OTP registration -> ECDSA sign without WebAuthn
      prompt.

### Phase 14: Export Auth Policy

- [ ] Decide whether Email OTP-only accounts may export Ed25519 and ECDSA
      keys with fresh OTP step-up.
- [ ] If allowed, add dedicated Email OTP export lanes for Ed25519 and ECDSA.
- [ ] If disallowed, add a typed error requiring passkey linking before export
      and update product copy.
- [ ] Ensure export flows call the wallet auth-mode resolver instead of
      directly opening WebAuthn UI.
- [ ] Add tests for passkey Ed25519 export, passkey ECDSA export, Email OTP
      Ed25519 export policy, and Email OTP ECDSA export policy.
- [ ] Add UI tests proving Email OTP-only export never shows an impossible
      Touch ID/WebAuthn prompt.

### Phase 15: Auth/Signer Matrix Verification

- [ ] Add a matrix test for passkey account wallet unlock, Ed25519 sign, ECDSA
      sign, Ed25519 export, and ECDSA export.
- [ ] Add a matrix test for Email OTP account wallet unlock, Ed25519 sign,
      ECDSA sign, Ed25519 export, and ECDSA export.
- [ ] Add tests for mixed accounts with both passkey and Email OTP linked.
- [ ] Verify all wallet flows use the same account auth metadata source.
- [ ] Verify no generic signing/session/export path requires
      `webauthn_authentication` without first resolving `method: 'passkey'`.
- [ ] Run SDK build, affected unit tests, affected browser tests, and relay
      route tests.

## Open Decisions

- Should `lastProfileState` point to the most recent active signer for an account, or only to the most recent passkey device?
- Should threshold Ed25519 and threshold ECDSA share one account signer slot or use separate slots per curve?
- Should key material writes be performed inside the lifecycle API, or should lifecycle return `keyMaterialSlot` and leave material writes to signer-specific flows?
- Should replaced threshold signers stay visible in local account settings, or only appear in debug tooling?
- Should local reconciliation run automatically on startup, or only after a failed signer lookup?
- Should `primaryAuthMethod` live on account profile state, signer metadata, or a separate wallet-auth record?
- Should Email OTP-only accounts be allowed to export Ed25519 and ECDSA keys with OTP step-up, or must they link a passkey first?
- Should mixed passkey plus Email OTP accounts default to passkey for sensitive actions and Email OTP only as recovery, or should product policy be per-project configurable?
- Should Ed25519 and ECDSA share one warm-session policy model exactly, or should Ed25519 keep stricter defaults because it controls NEAR account keys directly?

## Recommended Direction

Implement the centralized planner and lifecycle API first, then refactor Email OTP Ed25519 onto it before touching passkey registration. Email OTP is the flow currently exhibiting collisions, and it is the best proving ground for replacement semantics.

Keep the active slot uniqueness invariant. The invariant caught a real lifecycle bug. The fix is better lifecycle ownership, not loosening the database rule.

In parallel, introduce the wallet auth-mode resolver and make it the only
prompt/auth selector for wallet flows. The resolver should use stored
account/session metadata to choose `passkey` versus `email_otp`; individual
Ed25519, ECDSA, unlock, and export flows should stop guessing. Treat Email OTP
as a real session source for both ECDSA and Ed25519, and make export policy an
explicit product decision rather than an accidental WebAuthn fallback.

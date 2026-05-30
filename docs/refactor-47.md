# Refactor 47: Wallet-Scoped IndexedDB Lookups

Date created: 2026-05-29

Status: planned.

## Progress

- [ ] Add guard coverage that rejects wallet-scoped code paths using
  `buildNearAccountRefs(walletId)` or `toAccountId(args.walletId)`.
- [ ] Introduce wallet-scoped repository/read helpers for passkey auth methods,
  wallet signers, wallet preferences, and wallet chain targets.
- [ ] Refactor WebAuthn P-256 wallet key resolution to use `walletId` directly.
- [ ] Refactor EVM-family auth-method resolution to read wallet-scoped signer
  and auth-method state directly.
- [ ] Refactor managed nonce sender resolution to use wallet-scoped chain target
  data directly.
- [ ] Refactor ECDSA bootstrap persistence to write wallet profile/target state
  without creating fake NEAR profile mappings for wallet IDs.
- [ ] Refactor user preferences to load and save by canonical `walletId`.
- [ ] Rename or split public/internal APIs whose names still imply
  `nearAccountId` for wallet-scoped auth-method queries.
- [ ] Prefix true NEAR-account scoped query APIs with `near`.
- [ ] Add focused regression tests for passkey unlock, EVM/Tempo signing,
  key export, Email OTP ECDSA-only registration, and wallet preferences.

## Goal

Remove the remaining IndexedDB lookup paths that accept or derive a
`nearAccountId` when the data is actually wallet-scoped.

After this refactor:

- `walletId` is the only key used to read wallet auth methods, wallet passkeys,
  wallet signers, ECDSA wallet keys, and wallet preferences.
- `nearAccountId` is used only for NEAR account projections, NEAR Ed25519
  operational keys, NEAR nonce/access-key state, and NEAR threshold Ed25519
  warm sessions.
- true NEAR-account scoped read/write APIs are named with a `near` prefix.
- Wallet/EVM/Email OTP paths do not call `buildNearAccountRefs(walletId)`.
- Wallet/EVM/Email OTP paths do not coerce wallet IDs through `toAccountId`.

This is a breaking cleanup. Do not add compatibility aliases or fallback lookup
paths in core code.

## Problem Addressed

Refactors 45 and 46 made `walletId` the canonical durable wallet identity and
merged passkey auth material into wallet auth-method rows. Some IndexedDB
readers still use older NEAR-profile lookup patterns:

1. A function accepts `walletId`, coerces it with `toAccountId`, then calls
   `buildNearAccountRefs(walletId)`.
2. A function accepts `nearAccountId` only to find wallet-scoped passkey or
   auth-method state.
3. A function creates a synthetic NEAR profile mapping for a wallet ID to make
   older read paths work.

These paths caused bugs like wallet unlock reporting:

```text
No authenticators found for account <near account>. Please register an account.
```

while the UI-side wallet session still unlocked, because the canonical passkey
auth method existed under the wallet row, not under the NEAR projection.

## Classification Rule

Use this rule before changing a callsite:

| Data | Canonical key |
| --- | --- |
| Wallet auth methods | `walletId` |
| Wallet passkey credential material | `walletId` |
| Wallet Email OTP auth method | `walletId` |
| Wallet signers | `walletId`, signer family, signer id/target |
| ECDSA wallet key facts | `walletId`, chain target |
| Wallet preferences | `walletId` |
| NEAR account projection | `nearAccountId` |
| NEAR operational public key | `nearAccountId`, signer slot |
| NEAR threshold Ed25519 key material | `nearAccountId`, signer slot |
| NEAR threshold Ed25519 warm session | `nearAccountId` |
| NEAR nonce/access-key state | `nearAccountId` |

If a reader needs wallet auth or ECDSA wallet state, it must start from
`walletId`. If a reader needs a NEAR operational key, it may start from
`nearAccountId` and resolve the NEAR projection.

## Naming Rule

Function names must reveal the identity scope they query:

| Scope | Prefix | Examples |
| --- | --- | --- |
| Wallet identity | `wallet` | `walletPasskeyAuthenticators`, `getWalletPreferences`, `listActiveWalletSigners` |
| NEAR account projection | `near` | `nearAccountProjection`, `getNearUserBySignerSlot`, `setNearLastUser` |
| Chain target | `chain` or wallet + chain | `getWalletChainTargetSigner`, `resolveChainNonceSender` |

Use `near...` for every function that takes `nearAccountId` to query IndexedDB.
This includes valid NEAR-account scoped APIs such as projection reads,
operational signer reads, NEAR Ed25519 key material, NEAR threshold Ed25519 warm
sessions, and NEAR nonce/access-key state.

Use `wallet...` for every function that takes `walletId` to query IndexedDB.
Do not use generic names like `getAuthenticatorsByUser` for core persistence
queries. Public SDK convenience wrappers may keep user-facing names only at the
boundary, and should forward into precisely named core functions.

## Current Inventory

### Already corrected

`getAuthenticatorsByUser(nearAccountId)` now resolves the active NEAR signer,
reads the signer metadata `walletId` and `passkeyCredentialRawId`, then reads
the canonical wallet passkey auth-method row. This keeps the existing public
NEAR-account convenience API while moving the persistence lookup to the wallet
row.

Target follow-up: rename/split this API so core callers use a wallet-scoped
name where they already have `walletId`.

### Must refactor

1. `client/src/core/signingEngine/flows/signEvmFamily/webauthnP256KeyRef.ts`

   Current issue:
   - `resolveWebAuthnP256KeyRefForWallet({ walletId })` coerces `walletId`
     through `toAccountId`.
   - It resolves a NEAR profile with `buildNearAccountRefs(walletId)`.
   - It reads authenticators from the resolved profile.

   Target:
   - Normalize `walletId` as a wallet identity string.
   - Read passkey auth methods via `listProfileAuthenticators(walletId)` or a
     dedicated wallet passkey helper.
   - Use `selectProfileAuthenticatorsForPrompt({ profileId: walletId, ... })`.

2. `client/src/core/signingEngine/flows/signEvmFamily/accountAuth.ts`

   Current issue:
   - `resolveEvmFamilyTransactionWalletAuth({ walletId })` resolves
     `buildNearAccountRefs(walletId)` and selects a signer from a NEAR-style
     profile/account projection.

   Target:
   - Read active wallet signers directly for the requested wallet and chain
     target or signer family.
   - Resolve auth method from wallet signer metadata and/or wallet auth-method
     rows.
   - Keep `isEmailOtpThresholdContext` only as a boundary hint when no durable
     local wallet signer exists yet.

3. `client/src/core/signingEngine/flows/signEvmFamily/nonceResolution.ts`

   Current issue:
   - `resolveProfileChainAccountNonceSenderIdentity({ walletId })` resolves
     `buildNearAccountRefs(walletId)`.
   - It asks for chain accounts under the resolved profile.

   Target:
   - Resolve the sender from wallet-scoped ECDSA signer metadata for the
     requested chain target.
   - Prefer `metadata.thresholdOwnerAddress` / `metadata.accountAddress` from
     the wallet signer row.
   - Keep NEAR projection fallback out of core EVM/Tempo nonce resolution.

4. `client/src/core/signingEngine/session/warmCapabilities/ecdsaBootstrapPersistence.ts`

   Current issue:
   - Email OTP ECDSA bootstrap persistence creates a synthetic NEAR profile and
     account mapping for a wallet ID.
   - It then stores ECDSA target state under that NEAR-shaped profile.

   Target:
   - Ensure the wallet profile row exists by `walletId`.
   - Write ECDSA signer/target state under wallet-scoped signer rows.
   - Remove `ensureEmailOtpNearAccountMapping` once callers write the wallet
     profile directly.

5. `client/src/core/signingEngine/session/userPreferences.ts`

   Current issue:
   - `loadSettingsForWallet(walletId)` converts `walletId` to a NEAR account
     and resolves a NEAR profile.
   - `saveUserSettings()` writes preferences through
     `updateNearAccountPreferences`.

   Target:
   - Load preferences with `IndexedDBManager.getProfile(walletId)`.
   - Save preferences with `IndexedDBManager.updatePreferences({ profileId:
     walletId, ... })`.
   - Keep NEAR-account preference helpers only for NEAR projection callers.

6. `storeAuthenticator(...)` in registration account lifecycle

   Current issue:
   - The API accepts `nearAccountId` and writes an authenticator to the resolved
     NEAR profile.
   - Registration now persists initial passkeys through wallet auth-method rows.

   Target:
   - Keep only if needed by true legacy device-link/sync/recovery paths that are
     still NEAR-projection operations.
   - Prefer wallet-scoped `storeWalletPasskeyAuthMethod(...)` for new
     auth-method writes.
   - Delete or rename this API if no true NEAR projection caller remains.

## Target Repository Helpers

Add small repository/read helpers instead of repeating lookup logic:

```ts
type WalletPasskeyAuthenticatorLookup = {
  walletId: string;
  credentialId?: string;
};

type WalletSignerLookup = {
  walletId: string;
  signerFamily: 'ed25519' | 'ecdsa';
  chainTargetKey?: string;
  status: 'active';
};
```

Suggested helper surface:

- `listWalletPasskeyAuthenticators(walletId)`
- `getWalletPasskeyAuthenticator({ walletId, credentialId })`
- `listActiveWalletSigners({ walletId, signerFamily })`
- `getActiveWalletSignerForChainTarget({ walletId, chainTarget })`
- `getWalletPreferences(walletId)`
- `updateWalletPreferences({ walletId, preferences })`

Use existing store/index names where possible. Add indexes only if a real query
needs them.

## Guard Rules

Add focused static tests that reject these patterns outside NEAR-only modules:

- `buildNearAccountRefs(walletId)`
- `buildNearAccountRefs(toAccountId(args.walletId))`
- `toAccountId(args.walletId)` in wallet/EVM/auth-method modules
- `resolveProfileAccountContextFromCandidates(..., buildNearAccountRefs(walletId))`
- synthetic NEAR profile creation for wallet identity, for example
  `buildNearProfileId(walletId)` in ECDSA wallet persistence

Allowed modules:

- `client/src/core/accountData/near/*`
- NEAR signing flows
- NEAR Ed25519 key material/session code
- request/compatibility boundaries that explicitly translate a NEAR account
  into a wallet ID

## Implementation Phases

### Phase 1: Guard and Shared Helpers

- Add a guard test for the banned wallet-as-NEAR patterns.
- Add wallet-scoped helper functions in the IndexedDB repository/facade.
- Cover helpers with small unit tests using wallet auth-method and wallet signer
  rows.

### Phase 2: Passkey Auth and WebAuthn P-256

- Refactor `resolveWebAuthnP256KeyRefForWallet` to read wallet passkeys by
  `walletId`.
- Keep prompt selection scoped to `profileId: walletId`.
- Add regression coverage that a wallet passkey is found even when no NEAR
  profile authenticator row exists.

### Phase 3: EVM/Tempo Auth and Nonce Sender

- Refactor `resolveEvmFamilyTransactionWalletAuth` to inspect active wallet
  signer rows or wallet auth methods.
- Refactor `resolveProfileChainAccountNonceSenderIdentity` to inspect
  wallet-scoped ECDSA signer metadata for the requested chain target.
- Add tests for passkey ECDSA, Email OTP ECDSA, Tempo, and EVM chain targets.

### Phase 4: ECDSA Bootstrap Persistence

- Remove fake NEAR-profile creation for Email OTP wallet IDs.
- Persist wallet profile and ECDSA target signer rows directly under
  `walletId`.
- Update ECDSA-only Email OTP registration tests so no NEAR projection is
  required for wallet-only targets.

### Phase 5: Wallet Preferences

- Load and save confirmation preferences by `walletId`.
- Keep NEAR account preference helpers only for NEAR account projection flows.
- Add tests proving wallet preferences work without a NEAR profile mapping.

### Phase 6: API Cleanup

- Rename wallet-scoped APIs that currently say `nearAccountId`.
- Rename true NEAR-account scoped APIs to use a `near` prefix if they do not
  already.
- Keep public convenience wrappers only at SDK/user-facing boundaries.
- Delete wrappers that only preserve old internal vocabulary.
- Update type fixtures to reject wallet auth-method lookups that take
  `nearAccountId`.

## Validation

Run targeted checks after each phase:

```bash
pnpm -C tests exec playwright test ./unit/registrationWalletPersistence.unit.test.ts --reporter=line
pnpm -C tests exec playwright test ./unit/webauthnPromptCredentialSelection.unit.test.ts --reporter=line
pnpm -C tests exec playwright test ./unit/confirmTxFlow.successPaths.test.ts ./unit/confirmTxFlow.defensivePaths.test.ts --reporter=line
pnpm -C sdk type-check
git diff --check
```

Run broader validation before marking complete:

```bash
pnpm build:sdk
pnpm -C tests test:unit
```

Manual verification:

- Fresh passkey registration, unlock, NEAR signing, Tempo signing, EVM signing.
- Step-up passkey prompt after session exhaustion uses the selected credential
  directly.
- Key export passkey prompt uses the selected credential directly.
- Email OTP Ed25519-only, ECDSA-only, and combined registration.
- Wallet preferences persist across reload without depending on a NEAR profile
  lookup.

## Completion Criteria

- No wallet/EVM/auth-method core module resolves `walletId` through
  `buildNearAccountRefs`.
- No wallet/EVM/auth-method core module coerces wallet identity through
  `toAccountId` except at explicit public request boundaries.
- Every IndexedDB query function that accepts `nearAccountId` has a `near`
  prefix unless it is a public SDK boundary wrapper.
- Wallet passkey/auth-method reads are keyed by `walletId`.
- ECDSA wallet target/signing reads are keyed by `walletId` and chain target.
- NEAR projection helpers remain available only for NEAR account state.
- Guard tests fail on reintroducing wallet-as-NEAR IndexedDB lookups.

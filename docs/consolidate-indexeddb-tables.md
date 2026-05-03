# IndexedDB Consolidation Plan

Date created: 2026-05-03

## Objective

Consolidate local IndexedDB storage into one consistent Seams-owned schema:

1. Every IndexedDB database and object store name uses `snake_case`.
2. Every Seams-owned database and object store name starts with `seams_`.
3. Wallet-iframe mode keeps IndexedDB owned by the wallet origin; app-origin
   IndexedDB remains disabled when persistence is routed through the iframe.
4. Legacy CamelCase database names and mixed-case object stores are deleted, not
   migrated or kept behind compatibility paths.
5. The storage layout should be boring to inspect in DevTools: one wallet database
   per origin, with clearly named Seams object stores inside it.

This is a breaking development cleanup. If existing local accounts depend on old
IndexedDB records, reset local browser state and create a fresh account/session.

## Current Problems

Current IndexedDB state is split across several names and naming styles:

| Current database | Current role | Problem |
| --- | --- | --- |
| `PasskeyClientDB` | profiles, authenticators, account signers, recovery email hints, nonce leases | CamelCase, old product term, broad mixed responsibilities |
| `PasskeyAccountKeyMaterial` | local account key material | CamelCase, old product term, separate DB where one transaction surface would be simpler |
| `seams_wallet_v1` | durable signing-session sealed records and restore leases | Seams-prefixed, but separate from profile/key material state |
| `seams_email_otp_device_enrollment_escrows_v1` | Email OTP device enrollment escrow | Seams-prefixed, but separate DB and version suffix in DB/store names |

Object store names are also mixed: `appState`, `profileAuthenticators`,
`chainAccounts`, `accountSigners`, `signerOpsOutbox`, `recoveryEmailsV2`,
`nonceLaneLeasesV1`, `keyMaterial`, `signing_session_seals_v1`, and others.

DevTools can still show repeated DB names when multiple origins or frames are
present. This plan cannot make Chrome collapse origins into one row, but it
should make each Seams origin use the same small set of canonical names.

## Target Model

Use one canonical wallet-origin database:

```ts
export const SEAMS_WALLET_DB_NAME = 'seams_wallet' as const;
export const SEAMS_WALLET_DB_VERSION = 1 as const;
```

Do not encode schema version in object-store names. IndexedDB already has a
numeric schema version. Record-level versions remain inside records where they
are cryptographically or semantically meaningful.

Canonical object stores:

| Store | Replaces |
| --- | --- |
| `seams_app_state` | `appState` |
| `seams_profiles` | `profiles` |
| `seams_profile_authenticators` | `profileAuthenticators` |
| `seams_chain_accounts` | `chainAccounts` |
| `seams_account_signers` | `accountSigners` |
| `seams_signer_ops_outbox` | `signerOpsOutbox` |
| `seams_recovery_emails` | `recoveryEmailsV2` |
| `seams_nonce_lane_leases` | `nonceLaneLeasesV1` |
| `seams_nonce_lane_locks` | `nonceLaneLocksV1` |
| `seams_key_material` | `keyMaterial` in `PasskeyAccountKeyMaterial` |
| `seams_signing_session_seals` | `signing_session_seals_v1` |
| `seams_signing_session_restore_leases` | `signing_session_restore_leases_v1` |
| `seams_email_otp_device_enrollment_escrows` | `email_otp_device_enrollment_escrows_v1` |

Index names should also be snake_case. They do not need the `seams_` prefix
because they are scoped under a Seams-prefixed object store:

```ts
'profile_id'
'credential_id'
'profile_id_credential_id'
'profile_id_signer_slot'
'chain_id_key_account_address'
'status_next_attempt_at'
'wallet_auth_subject'
'wallet_auth_subject_enrollment'
```

## Non-Negotiable Rules

1. Do not read from legacy IndexedDB database names in production code.
2. Do not migrate legacy CamelCase databases.
3. Do not keep compatibility aliases for old database or object-store names.
4. Do not create one-off IndexedDB databases for new local state.
5. Do not add version suffixes to object-store names.
6. Tests may use unique database names, but test database names must also be
   snake_case and start with `seams_`, for example
   `seams_test_wallet_<uuid>`.
7. All IndexedDB names must come from one constants module. No inline database or
   object-store string literals in runtime code.
8. If local dev data breaks, delete old databases and recreate the account. Do
   not add legacy rescue paths.

## Proposed Code Shape

Add one schema-name module:

```ts
// client/src/core/indexedDB/schemaNames.ts
export const SEAMS_WALLET_DB_NAME = 'seams_wallet' as const;

export const SEAMS_WALLET_STORES = {
  appState: 'seams_app_state',
  profiles: 'seams_profiles',
  profileAuthenticators: 'seams_profile_authenticators',
  chainAccounts: 'seams_chain_accounts',
  accountSigners: 'seams_account_signers',
  signerOpsOutbox: 'seams_signer_ops_outbox',
  recoveryEmails: 'seams_recovery_emails',
  nonceLaneLeases: 'seams_nonce_lane_leases',
  nonceLaneLocks: 'seams_nonce_lane_locks',
  keyMaterial: 'seams_key_material',
  signingSessionSeals: 'seams_signing_session_seals',
  signingSessionRestoreLeases: 'seams_signing_session_restore_leases',
  emailOtpDeviceEnrollmentEscrows: 'seams_email_otp_device_enrollment_escrows',
} as const;
```

Replace separate DB managers with one wallet DB manager plus narrow repositories:

```ts
type SeamsWalletDbManager = {
  getDbName(): typeof SEAMS_WALLET_DB_NAME | `seams_test_wallet_${string}`;
  getDB(): Promise<IDBPDatabase>;
};

type SeamsWalletRepositories = {
  profiles: ProfileRepository;
  profileAuthenticators: ProfileAuthenticatorRepository;
  chainAccounts: ChainAccountRepository;
  accountSigners: AccountSignerRepository;
  keyMaterial: KeyMaterialRepository;
  signingSessionSeals: SigningSessionSealRepository;
  emailOtpDeviceEnrollmentEscrows: EmailOtpDeviceEnrollmentEscrowRepository;
  nonceLaneCoordination: NonceLaneCoordinationRepository;
};
```

Keep repository APIs narrow. The manager owns opening, version upgrades, and
legacy database deletion. Repositories own object-store reads and writes.

## Implementation Plan

### Phase 1. Inventory and Guard

1. Add `client/src/core/indexedDB/schemaNames.ts`.
2. Add an architecture guard that fails if runtime code contains:
   - `PasskeyClientDB`
   - `PasskeyAccountKeyMaterial`
   - `seams_wallet_v1`
   - `seams_email_otp_device_enrollment_escrows_v1`
   - inline `indexedDB.open('<literal>')` outside the one DB manager
3. Add a guard that all configured database and object-store names match:

```ts
/^seams_[a-z0-9]+(?:_[a-z0-9]+)*$/
```

4. Update test helpers so unique DB names are generated as
   `seams_test_wallet_<suffix>`.

### Phase 2. Create the Unified Schema

1. Introduce `SeamsWalletDBManager` with `SEAMS_WALLET_DB_NAME`.
2. Move the existing `PasskeyClientDB` object stores into the unified schema
   under their `seams_*` store names.
3. Move `PasskeyAccountKeyMaterial` into the unified schema as
   `seams_key_material`.
4. Move signing-session sealed records into the unified schema as:
   - `seams_signing_session_seals`
   - `seams_signing_session_restore_leases`
5. Move Email OTP device enrollment escrow records into the unified schema as:
   - `seams_email_otp_device_enrollment_escrows`
6. Keep all record schemas strict. Do not add compatibility reads for old object
   store names.

### Phase 3. Replace Managers and Imports

1. Replace `PasskeyClientDBManager` with `SeamsWalletDBManager` and repository
   ports.
2. Delete `AccountKeyMaterialDBManager`; key material becomes a repository on
   the unified wallet DB.
3. Update `UnifiedIndexedDBManager` or replace it with a smaller assembly that
   exposes repositories, not separate database managers.
4. Update signing, registration, profile, account projection, nonce, recovery,
   and key-material callsites to use the new repositories.
5. Delete old manager files once no production import remains.

### Phase 4. Delete Legacy Local Databases

Add a dev-state cleanup command behind the new DB manager startup:

```ts
const LEGACY_INDEXED_DB_NAMES = [
  'PasskeyClientDB',
  'PasskeyAccountKeyMaterial',
  'seams_wallet_v1',
  'seams_email_otp_device_enrollment_escrows_v1',
] as const;
```

Rules:

1. Delete these databases after the new `seams_wallet` manager is configured and
   before new stores are opened.
2. Do not parse or migrate records from these databases.
3. If deletion is blocked by another open tab, log a development warning and
   continue with the new database.
4. Do not expose legacy database contents through status, snapshot, restore,
   transaction, or export paths.

### Phase 5. Tests

Add or update tests for:

1. New installs create only `seams_wallet` for wallet-origin persistence.
2. App-origin iframe mode creates no app-origin IndexedDB database.
3. All object stores in `seams_wallet` are `seams_*` and snake_case.
4. Legacy databases are deleted when present.
5. Legacy databases are not read during:
   - wallet-session status
   - transaction signing
   - key export
   - sealed-session restore
   - Email OTP device enrollment restore
6. Test database names are generated as `seams_test_wallet_*`.
7. Architecture guards reject new IndexedDB database names or stores that are not
   `seams_*` snake_case.

### Phase 6. Manual Verification

1. Clear site data for all local wallet/app origins.
2. Create a fresh passkey account.
3. Create a fresh Email OTP account.
4. Confirm DevTools IndexedDB shows only Seams-prefixed DBs for each origin.
5. Verify:
   - wallet unlock
   - page refresh restore
   - ED25519 transaction signing
   - ECDSA transaction signing
   - session exhaustion step-up
   - ED25519 key export
   - ECDSA key export
6. Repeat in wallet-iframe mode and confirm the app origin does not create local
   IndexedDB state.

## Completion Criteria

- Runtime code has one canonical IndexedDB database name: `seams_wallet`.
- Every Seams object store is `seams_*` snake_case.
- No production runtime code references old database names.
- No production runtime code reads or migrates old IndexedDB databases.
- Key material, profile/account state, nonce coordination, signing-session seals,
  and Email OTP enrollment escrow records live under the unified wallet DB.
- Status, transaction signing, restore, and export paths do not create extra
  IndexedDB databases.
- Guard tests prevent reintroducing mixed-case or non-Seams storage names.
- Fresh local manual testing works for both passkey and Email OTP accounts after
  clearing old site data.

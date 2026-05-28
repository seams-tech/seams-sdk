# IndexedDB Consolidation Plan

Date created: 2026-05-03

Status: implementation complete; manual end-to-end verification remains. The
legacy `PasskeyClientDB` and `PasskeyAccountKeyMaterial` manager surfaces have
been removed, first-class auth-method rows live in `seams_wallet`, and
registration/add-signer finalize now use atomic repository batches. Keep this
document as the active IndexedDB cleanup plan until the manual verification
section passes.
Start implementation after `docs/rework-registration-flows-2.md` stabilizes the
registration auth-method and wallet-subject repository shape. The collapsed
`docs/rework-registration-flows.md` is a completed historical note.

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
| `PasskeyClientDB` | profiles, authenticators, account signers, signer mutation outbox, recovery email hints, durable nonce leases and locks | CamelCase, old product term, broad mixed responsibilities |
| `PasskeyAccountKeyMaterial` | local account key material envelopes | CamelCase, old product term, separate DB where one transaction surface would be simpler |
| `seams_wallet_v1` | durable signing-session sealed records and restore leases | Seams-prefixed, but separate from profile/key material state and still has a version suffix in the DB name |

Object store names are also mixed: `appState`, `profiles`,
`profileAuthenticators`, `chainAccounts`, `accountSigners`, `signerOpsOutbox`,
`recoveryEmailsV2`, `nonceLaneLeasesV1`, `nonceLaneLocksV1`, `keyMaterial`,
`signing_session_seals_v1`, `signing_session_restore_leases_v1`, and
`email_otp_device_enrollment_escrows_v1`.

DevTools can still show repeated DB names when multiple origins or frames are
present. This plan cannot make Chrome collapse origins into one row. It should
make each Seams origin use the same small set of canonical names.

Current implementation snapshot:

1. The old `client/src/core/indexedDB/passkeyClientDB/*` manager and repository
   modules have been deleted. `PasskeyClientDB` remains only as a legacy
   database name scheduled for deletion/no-read guards.
2. The deleted `PasskeyClientDB` schema formerly owned:
   - `appState`
   - `profiles`
   - `profileAuthenticators`
   - `chainAccounts`
   - `accountSigners`
   - `signerOpsOutbox`
   - `recoveryEmailsV2`
   - `nonceLaneLeasesV1`
   - `nonceLaneLocksV1`
3. The standalone `PasskeyAccountKeyMaterial` manager has been removed; the
   remaining `accountKeyMaterial` helper surface is a compatibility wrapper over
   unified key-material repository methods.
4. Signing-session seal constants now point at `seams_wallet`; raw IndexedDB
   opens, cursor scans, writes, and restore-lease transactions live in the
   `seams_signing_session_seals` repository.
5. Email OTP device enrollment escrow reads/writes now delegate to the
   `seams_email_otp_escrows` repository.
6. `client/src/core/indexedDB/index.ts` configures `seams_wallet` for `app` and
   `wallet` modes and disables IndexedDB in `disabled` mode. It no longer
   exports or constructs `PasskeyClientDBManager`.
7. `UnifiedIndexedDBManager` now wraps `SeamsWalletRepositories` directly as a
   compatibility facade over repository-shaped ports.
8. Refactor 33 has moved most signing-engine callsites out of `api/`,
   `orchestration/`, `chainAdaptors/`, and `signers/`. Use the Refactor 33
   "Folder And Filename Change Reference" as the naming source of truth:
   operation modules are `flows/*`, reusable wallet auth is `walletAuth/*`, and
   construction/runtime wiring is `assembly/*`. Some intermediate working-tree
   paths may still be named `operations/*`, `auth/*`, or `bootstrap/*` until
   Refactor 33 fully lands.
9. Refactor 35/36 has moved sealed recovery into `session/sealedRecovery/*`,
   method recovery into `session/passkey/*` and `session/emailOtp/*`, and strict
   recovery-record normalization into `session/sealedRecovery/recoveryRecord.ts`.
   Treat `session/persistence/*` and the recovery-record normalizer as the
   raw sealed-record boundary during this plan.
10. Refactor 39 has tightened ECDSA identity around exact lane identity,
    `keyHandle`, and complete ECDSA public facts. IndexedDB records that store
    active ECDSA signers or sealed ECDSA sessions must persist those exact
    scalar identities instead of re-deriving them from broad profile metadata.
11. The completed registration rework made wallet-subject records the local
    source of truth. `docs/rework-registration-flows-2.md` is the active
    follow-up for first-class auth-method bindings. NEAR profile/account state
    remains a projection written after wallet-subject persistence succeeds.
12. Refactor 41 makes prompt policy, step-up freshness, reservation identity,
    exhausted-session reauth anchors, and Email OTP refresh rejection explicit
    domain state. IndexedDB repositories must not expose raw persistence records
    into those session flows.
13. Historical unit tests created CamelCase test databases such as
   `PasskeyClientDB-*` and `PasskeyAccountKeyMaterial-*`. The active guard now
   requires `seams_test_wallet_*` fixtures; keep any remaining legacy test-name
   references confined to historical docs or explicit deletion tests.

Post-refactor 33/35/36/39/40/41/42/43 and registration-auth-method paths to
revisit during the consolidation:

1. `client/src/core/signingEngine/session/persistence/sealedSessionStore.ts`
   now delegates storage operations to unified signing-session repositories.
   Keep raw sealed-record classification and public sealed-store APIs in
   `session/persistence/*`.
2. `client/src/core/signingEngine/workerManager/workers/email-otp/deviceEnrollmentEscrowStore.ts`
   now delegates raw storage to the unified Email OTP escrow repository. Keep
   worker-support normalization at that boundary.
3. `client/src/core/signingEngine/session/userPreferences.ts` reads and writes
   profile state through the unified IndexedDB manager; disabled iframe/app
   origin mode is covered by focused tests.
4. `client/src/core/SeamsPasskey/registration.ts`,
   `client/src/core/SeamsPasskey/login.ts`,
   `client/src/core/signingEngine/flows/registration/*`,
   and `client/src/core/rpcClients/relayer/walletRegistration.ts` need
   wallet-subject repository ports once the registration rework lands.
5. `client/src/core/accountData/near/*`,
   `client/src/core/indexedDB/accountKeyMaterial.ts`,
   `client/src/core/indexedDB/profileAccountProjection.ts`, and
   `client/src/core/signingEngine/webauthnAuth/device/signerSlot.ts` now use
   method-specific persistence ports instead of `PasskeyClientDBManager`-shaped
   ports. Old client DB error text remains to rename as callsites settle.
6. `client/src/core/signingEngine/flows/registration/accountLifecycle.ts`,
   `flows/signEvmFamily/*`, `flows/signNear/*`, `flows/recovery/*`,
   `session/persistence/*`, `session/sealedRecovery/*`, `session/passkey/*`,
   `session/emailOtp/*`, `session/availability/*`, `session/budget/*`,
   `session/identity/*`, `session/operationState/*`,
   `session/warmCapabilities/*`, `threshold/*`, and `walletAuth/webauthn/*`
   need port-shape review as the persistence assembly changes.
7. `sdk/rolldown.config.ts` exposes the unified Seams wallet repositories and
   the Email OTP escrow worker-support store as stable deep-import entries for
   tests/tools.

The storage ownership rule from Refactor 35/36 is: direct sealed-session storage
changes belong in `session/persistence/*`; restore orchestration and method
folders consume normalized recovery records.

The registration ownership rule is: wallet-subject, authenticator, and signer
records are the source of truth. NEAR profile/account state and display caches
are projections that can be rebuilt from those records.

## Target Model

Consolidate all current local wallet-origin IndexedDB persistence into one
canonical database:

```ts
export const SEAMS_WALLET_DB_NAME = 'seams_wallet' as const;
export const SEAMS_WALLET_DB_VERSION = 1 as const;
```

The unified database replaces all current runtime databases:

1. `PasskeyClientDB` v32.
2. `PasskeyAccountKeyMaterial` v11.
3. `seams_wallet_v1` v4.

The implementation should delete the old database managers and direct
`indexedDB.open(...)` modules as each store moves under `seams_wallet`. Runtime
code should open one database per persistence origin.

Do not encode schema version in object-store names. IndexedDB already has a
numeric schema version. Record-level versions remain inside records where they
are cryptographically or semantically meaningful.

Raw IndexedDB rows use `snake_case` field names for key paths, index key paths,
and scalar mirror fields. Repository APIs return camelCase domain types,
discriminated unions, and existing protocol record types as appropriate. Code
outside IndexedDB repositories, the wallet DB manager, focused repository tests,
and `session/persistence/*` must not receive raw snake_case storage rows.

Repository normalizers are the casing and validation boundary. They must verify
that scalar index mirrors match the nested domain object they summarize, for
example `chain_target_key`, `exact_signing_lane_identity_key`, and
`wallet_subject_kind_chain_target_key_handle`.

Identity vocabulary:

| Field | Meaning | Source-of-truth rule |
| --- | --- | --- |
| `wallet_subject_id` | Canonical local wallet identity produced by wallet-subject registration. | Source-of-truth registration, authenticator, signer, and projection stores key by this field. |
| `wallet_id` | Protocol/session wallet identifier used by ECDSA, Email OTP, signing-session, and relayer-facing records. | For wallet-subject-backed rows it must derive from or equal `wallet_subject_id` at the repository boundary. |
| `near_account_id` | NEAR account projection for Ed25519 wallets. | Projection only; never creates source-of-truth wallet, authenticator, signer, or key-material rows. |
| `auth_subject_id` | External auth subject for Email OTP/OIDC-style auth methods. | Selects an auth-method binding only together with `wallet_subject_id` and auth-method kind. |
| `user_id` | Legacy/protocol field still present in some shared sealed/session payloads. | New unified rows should prefer `wallet_subject_id` or `wallet_id`; include `user_id` only when an existing protocol record requires it. |
| `profile_id` | Legacy `PasskeyClientDB` profile vocabulary. | Banned from source-of-truth rows; allowed only as a derived projection field while old profile-facing APIs still exist. |

IndexedDB mode behavior after consolidation:

| Mode | Database behavior |
| --- | --- |
| `wallet` | Open `seams_wallet` in the wallet origin. This is the normal wallet-iframe host persistence mode. |
| `app` | Open `seams_wallet` in the app origin only for non-iframe SDK usage where the app owns persistence. |
| `disabled` | Open no IndexedDB database and run no legacy deletion. Use this when wallet-iframe mode routes persistence to the wallet origin. |

Canonical object stores after the registration auth-method follow-up:

| Store | Role | Replaces or absorbs |
| --- | --- | --- |
| `seams_app_state` | local UI/session preferences such as the last selected wallet | `appState` |
| `seams_wallet_subjects` | wallet-subject records keyed by `walletSubjectId` | new source of truth from registration rework |
| `seams_wallet_auth_methods` | branch-specific passkey, Email OTP, and future auth-method rows keyed by wallet subject and branch identifier; passkey rows include WebAuthn credential material | `profileAuthenticators`, WebAuthn binding projections, and `WalletAuthMethodBinding` rows |
| `seams_wallet_signers` | Ed25519 and ECDSA active signer records keyed by wallet subject | `chainAccounts`, `accountSigners`, and ECDSA profile metadata |
| `seams_near_accounts` | derived NEAR profile/account projection for Ed25519 wallets | `profiles` and `chainAccounts` read models |
| `seams_signer_ops_outbox` | durable signer mutation outbox | `signerOpsOutbox` |
| `seams_recovery_emails` | recovery email hints keyed by wallet subject | `recoveryEmailsV2` |
| `seams_nonce_lane_leases` | durable nonce lane leases | `nonceLaneLeasesV1` |
| `seams_nonce_lane_locks` | durable nonce lane locks | `nonceLaneLocksV1` |
| `seams_key_material` | encrypted local key-material envelopes keyed by wallet signer identity | `keyMaterial` in `PasskeyAccountKeyMaterial` |
| `seams_signing_session_seals` | durable sealed signing-session records | `signing_session_seals_v1` |
| `seams_signing_session_restore_leases` | restore-attempt leases for sealed sessions | `signing_session_restore_leases_v1` |
| `seams_email_otp_escrows` | Email OTP device enrollment escrow records | `email_otp_device_enrollment_escrows_v1` |

Index names should also be snake_case. They do not need the `seams_` prefix
because they are scoped under a Seams-prefixed object store. The canonical index
inventory is:

```ts
'profile_id'
'credential_id'
'credential_id_b64u'
'wallet_auth_method_id'
'auth_identifier_key'
'kind_rp_id_auth_identifier'
'profile_id_credential_id'
'profile_id_signer_slot'
'updated_at'
'wallet_subject_id'
'wallet_subject_id_rp_id'
'wallet_subject_id_kind'
'wallet_subject_kind_near_signer_slot'
'wallet_subject_kind_chain_target_key_handle'
'wallet_subject_kind_chain_target_key_facts'
'near_account_id'
'rp_id'
'rp_id_credential_id'
'chain_id_key'
'chain_id_key_account_address'
'profile_id_chain_id_key'
'chain_id_key_account_address_status'
'chain_target_key'
'key_handle'
'threshold_owner_address'
'ecdsa_threshold_key_id'
'status'
'next_attempt_at'
'status_next_attempt_at'
'idempotency_key'
'lane_key'
'account_id'
'state'
'expires_at_ms'
'lane_state'
'account_expires_at'
'owner_id'
'chain_id_key_key_kind'
'public_key'
'wallet_id'
'user_id'
'auth_method'
'curve'
'signing_root_id'
'signing_root_version'
'wallet_signing_root_auth_method'
'ed25519_threshold_session_id'
'ecdsa_threshold_session_id'
'wallet_signing_session_id'
'threshold_session_id'
'exact_signing_lane_identity_key'
'budget_reservation_key'
'auth_subject_id'
'enrollment_id'
'wallet_id_auth_subject_id'
'wallet_id_auth_subject_id_enrollment_id'
```

## Non-Negotiable Rules

1. Do not read from legacy IndexedDB database names in production code.
2. Do not migrate legacy CamelCase databases.
3. Do not keep compatibility aliases for old database or object-store names.
4. Do not create one-off IndexedDB databases for new local state.
5. Do not add version suffixes to object-store names.
6. Tests may use unique database names, but test database names must also be
   snake_case and start with `seams_`, for example
   `seams_test_wallet_<safe_suffix>`. Test helpers must normalize UUIDs by
   replacing hyphens with underscores.
7. All IndexedDB names must come from one constants module. No inline database or
   object-store string literals in runtime code.
8. If local dev data breaks, delete old databases and recreate the account. Do
   not add legacy rescue paths.
9. Raw sealed-session persistence records may exist only in IndexedDB
   repositories, `session/persistence/*`, and
   `session/sealedRecovery/recoveryRecord.ts`. Restore, flow, budget,
   availability, identity, and operation-state code consumes normalized
   discriminated records.
10. Wallet-subject signer records are the source of truth for active signers.
    NEAR profile/account rows are projections and must be written only after the
    wallet-subject records are committed.
11. Wallet auth-method rows are the source of truth for local passkey,
    Email OTP, and future authentication methods. Passkey rows store the
    WebAuthn credential material on the same branch-specific record.
12. ECDSA active signer records must store the complete
    `EvmFamilyEcdsaWalletKey`: direct `keyHandle`, required key facts, owner
    address, participant ids, and concrete `chainTarget`.
13. Store every indexed complex identity as a canonical scalar field on the
    record. Examples: `chain_target_key`, `exact_signing_lane_identity_key`,
    and `wallet_subject_kind_chain_target_key_handle`.
14. Repository normalizers must validate that scalar index fields match the
    nested domain object they summarize.
15. Raw IndexedDB row fields, key paths, and index key paths use `snake_case`.
    Repositories convert to camelCase domain types at the boundary.
16. `disabled` IndexedDB mode must not open `seams_wallet`, delete legacy
    databases, or create app-origin persistence state.

## Proposed Code Shape

Add one schema-name module:

```ts
// client/src/core/indexedDB/schemaNames.ts
export const SEAMS_WALLET_DB_NAME = 'seams_wallet' as const;

export const SEAMS_WALLET_STORES = {
  appState: 'seams_app_state',
  walletSubjects: 'seams_wallet_subjects',
  walletAuthMethods: 'seams_wallet_auth_methods',
  walletSigners: 'seams_wallet_signers',
  nearAccountProjections: 'seams_near_accounts',
  signerOpsOutbox: 'seams_signer_ops_outbox',
  recoveryEmails: 'seams_recovery_emails',
  nonceLaneLeases: 'seams_nonce_lane_leases',
  nonceLaneLocks: 'seams_nonce_lane_locks',
  keyMaterial: 'seams_key_material',
  signingSessionSeals: 'seams_signing_session_seals',
  signingSessionRestoreLeases: 'seams_signing_session_restore_leases',
  emailOtpDeviceEnrollmentEscrows: 'seams_email_otp_escrows',
} as const;
```

Replace separate DB managers with one wallet DB manager plus narrow repositories:

```ts
type SeamsWalletStoreName = (typeof SEAMS_WALLET_STORES)[keyof typeof SEAMS_WALLET_STORES];

type SeamsWalletTransactionContext = {
  db: IDBPDatabase;
  tx: unknown;
  stores: Record<SeamsWalletStoreName, unknown>;
};

type SeamsWalletDbManager = {
  getDbName(): typeof SEAMS_WALLET_DB_NAME | `seams_test_wallet_${string}`;
  getDB(): Promise<IDBPDatabase>;
  runTransaction<T>(
    stores: readonly SeamsWalletStoreName[],
    mode: 'readonly' | 'readwrite',
    task: (tx: SeamsWalletTransactionContext) => Promise<T> | T,
  ): Promise<T>;
};

type SeamsWalletRepositories = {
  appState: AppStateRepository;
  walletSubjects: WalletSubjectRepository;
  walletAuthMethods: WalletAuthMethodRepository;
  walletSigners: WalletSignerRepository;
  nearAccountProjections: NearAccountProjectionRepository;
  signerOpsOutbox: SignerOpsOutboxRepository;
  recoveryEmails: RecoveryEmailRepository;
  keyMaterial: KeyMaterialRepository;
  signingSessionSeals: SigningSessionSealRepository;
  signingSessionRestoreLeases: SigningSessionRestoreLeaseRepository;
  emailOtpDeviceEnrollmentEscrows: EmailOtpDeviceEnrollmentEscrowRepository;
  nonceLaneCoordination: NonceLaneCoordinationRepository;
};
```

Keep repository APIs narrow. The manager owns opening, version upgrades, and
legacy database deletion. Repositories own object-store reads and writes.
Repository methods that participate in atomic flows must accept a transaction
context, or the repository must expose a branch-specific batch method that uses
`runTransaction(...)` internally. Implementation must not satisfy the atomic
write boundaries below by awaiting several independent repository calls.

For signing sessions, keep `session/persistence/*` as the owner of sealed-store
read/write functions. Its IndexedDB access should go through the
`signingSessionSeals` and `signingSessionRestoreLeases` repositories backed by
`seams_wallet`; `session/sealedRecovery/*`, `session/passkey/*`, and
`session/emailOtp/*` should continue to receive `SealedRecoveryRecord` branches
from `session/sealedRecovery/recoveryRecord.ts`.

## Target Schema Manifest

Add a typed schema manifest next to the schema-name constants before creating
stores. The manifest is the implementation source of truth for key paths,
indexes, uniqueness, record owners, and repository ownership.

| Store | Key path | Required indexes | Repository owner |
| --- | --- | --- | --- |
| `seams_app_state` | `key` | none beyond key path | `AppStateRepository` |
| `seams_wallet_subjects` | `wallet_subject_id` | `rp_id`, `status`, `updated_at` | `WalletSubjectRepository` |
| `seams_wallet_auth_methods` | `wallet_auth_method_id` | `wallet_subject_id`, `wallet_subject_id_kind`, `auth_method`, `rp_id`, `auth_identifier_key`, `kind_rp_id_auth_identifier`, `passkey_rp_id_credential_id`, `status`, `updated_at`; unique `kind_rp_id_auth_identifier` prevents duplicate branch identifiers per RP, and unique `passkey_rp_id_credential_id` keeps WebAuthn credential lookup direct | `WalletAuthMethodRepository` |
| `seams_wallet_signers` | `wallet_signer_id` | `wallet_subject_id`, `wallet_subject_id_kind`, `wallet_subject_kind_near_signer_slot`, `wallet_subject_kind_chain_target_key_handle`, `wallet_subject_kind_chain_target_key_facts`, `chain_target_key`, `key_handle`, `threshold_owner_address`, `status`, `updated_at` | `WalletSignerRepository` |
| `seams_near_accounts` | `['wallet_subject_id', 'near_account_id', 'signer_slot']` | `near_account_id`, `profile_id`, `public_key`, `updated_at` | `NearAccountProjectionRepository` |
| `seams_signer_ops_outbox` | `op_id` | `status`, `next_attempt_at`, `status_next_attempt_at`, `idempotency_key`, `wallet_subject_id`, `chain_target_key` | `SignerOpsOutboxRepository` |
| `seams_recovery_emails` | `['wallet_subject_id', 'hash_hex']` | `wallet_subject_id`, `updated_at` | `RecoveryEmailRepository` |
| `seams_nonce_lane_leases` | `lease_id` | `lane_key`, `account_id`, `state`, `expires_at_ms`, `lane_state`, `account_expires_at` | `NonceLaneCoordinationRepository` |
| `seams_nonce_lane_locks` | `lock_key` | `expires_at_ms`, `owner_id` | `NonceLaneCoordinationRepository` |
| `seams_key_material` | `key_material_id` | `wallet_subject_id`, `wallet_signer_id`, `chain_target_key`, `key_handle`, `public_key`, `updated_at` | `KeyMaterialRepository` |
| `seams_signing_session_seals` | `store_key` | `wallet_id`, `wallet_subject_id`, `auth_method`, `curve`, `wallet_signing_session_id`, `ed25519_threshold_session_id`, `ecdsa_threshold_session_id`, `threshold_session_id`, `key_handle`, `chain_target_key`, `exact_signing_lane_identity_key`, `expires_at_ms`, `updated_at` | `SigningSessionSealRepository` through `session/persistence/*` |
| `seams_signing_session_restore_leases` | `lease_key` | `wallet_signing_session_id`, `threshold_session_id`, `owner_id`, `expires_at_ms` | `SigningSessionRestoreLeaseRepository` through `session/persistence/*` |
| `seams_email_otp_escrows` | `['wallet_id', 'auth_subject_id', 'enrollment_id']` | `wallet_id`, `auth_subject_id`, `enrollment_id`, `wallet_id_auth_subject_id`, `wallet_id_auth_subject_id_enrollment_id`, `signing_root_id` | `EmailOtpDeviceEnrollmentEscrowRepository` |

Schema manifest rules:

1. Every store row must define key path, index list, and unique-index list in
   TypeScript data, then schema creation must iterate that manifest.
2. For union records such as wallet signers, use a synthetic key path
   (`wallet_signer_id`) plus scalar indexed fields. Repositories validate the
   scalar fields against the discriminated record branch.
3. Avoid indexing raw objects such as `ThresholdEcdsaChainTarget`. Persist
   `chain_target_key` from the canonical chain-target encoder and validate it at
   the repository boundary.
4. Unique wallet-signer constraints:
   - Ed25519: `wallet_subject_kind_near_signer_slot`.
   - ECDSA selector: `wallet_subject_kind_chain_target_key_handle`.
   - ECDSA key-facts lookup:
     `wallet_subject_kind_chain_target_key_facts`.
5. Unique auth-method constraints:
   `kind_rp_id_auth_identifier`, where `auth_identifier_key` is the passkey
   `credentialIdB64u`, Email OTP `emailHashHex`, or future branch-specific
   stable identifier. Passkey rows also use `passkey_rp_id_credential_id` for
   direct WebAuthn credential lookup. The stored row must contain the normalized
   branch-specific auth-method data, and the repository normalizer must reject
   mixed passkey/Email OTP fields.
6. WebAuthn credential material is stored on the passkey branch of
   `seams_wallet_auth_methods`.
7. Unique Email OTP escrow constraint:
   `wallet_id_auth_subject_id_enrollment_id`.
8. Repository tests should snapshot the manifest so store names, key paths,
   index names, and uniqueness cannot drift silently.

## Atomic Write Boundaries

Use one `seams_wallet` readwrite transaction for changes that must become
visible together. These flows must go through `SeamsWalletDbManager.runTransaction(...)`
or a repository batch method that uses it internally:

1. Wallet registration finalize writes `seams_wallet_subjects`,
   branch-specific `seams_wallet_auth_methods`, `seams_wallet_signers`, `seams_key_material`,
   and then `seams_near_accounts` when an Ed25519 result exists.
2. ECDSA-only registration writes no NEAR projection rows and skips NEAR profile
   continuity helpers.
3. Add-signer finalize writes the wallet signer and key-material envelope in the
   same transaction.
4. Signer mutation outbox writes should include the wallet-subject identity and
   idempotency key in the same transaction as any local projection update they
   schedule.
5. Signing-session seal and restore-lease updates should share a transaction
   when a restore attempt reserves, consumes, deletes, or clears records.
6. Projection writers never create source-of-truth wallet-subject, authenticator,
   signer, or key-material records.

All relayer responses, worker outputs, and wallet registration bootstrap material
must be validated and normalized before opening the transaction. A failed parser
must leave no wallet-subject, projection, key-material, warm-session, or
signing-session side effect behind.

Registration finalize must use one named repository batch instead of a sequence
of independent repository calls. The concrete name can change during
implementation, but the plan assumes an API with this ownership:

```ts
type PersistWalletRegistrationFinalizeInput = {
  walletSubject: NormalizedWalletSubjectRecord;
  initialAuthMethodBinding: WalletAuthMethodBinding;
  passkeyAuthenticator?: NormalizedWebAuthnAuthenticatorRecord;
  walletSigners: readonly NormalizedWalletSignerRecord[];
  keyMaterials: readonly NormalizedKeyMaterialRecord[];
  nearAccountProjections: readonly NormalizedNearAccountProjectionRecord[];
};

async function persistWalletRegistrationFinalize(
  input: PersistWalletRegistrationFinalizeInput,
): Promise<void>;
```

The batch owns the transaction over all listed stores. It must reject invalid
auth-method branches, missing signer/key-material pairs, ECDSA-only NEAR
projections, and scalar mirror mismatches before any write is committed.

## Implementation Plan

### Phase 0. Final Domain Rescan

Run this phase after `docs/rework-registration-flows-2.md`,
`docs/refactor-40.md`, `docs/refactor-41.md`,
`docs/refactor-42-stricter-union-types.md`, and `docs/refactor-43-cleanup.md`
are complete enough that their public types and repository ports have
stabilized.

1. Rescan current wallet-subject, authenticator, signer, key-material,
   signing-session, Email OTP escrow, nonce, and outbox persistence callers.
2. Update `SEAMS_WALLET_SCHEMA_MANIFEST` to match the final wallet-subject,
   registration auth-method, Refactor 40 HSS v2, Refactor 41 identity, and
   Refactor 42 strict-union types.
3. Confirm whether `seams_near_accounts` needs one store or separate
   NEAR profile/account projection stores. Keep projection stores derived from
   wallet-subject source records.
4. Confirm the canonical scalar encoders for:
   - `chain_target_key`
   - `exact_signing_lane_identity_key`
   - `auth_identifier_key`
   - `wallet_signer_id`
   - `wallet_auth_method_id`
   - `key_material_id`
   - `budget_reservation_key`
5. Freeze the repository ownership list before creating stores.

### Phase 1. Rescan, Constants, and Early Guards

1. [x] Add `client/src/core/indexedDB/schemaNames.ts`.
2. [x] Add schema constants for:
   - `SEAMS_WALLET_DB_NAME`
   - `SEAMS_WALLET_DB_VERSION`
   - `SEAMS_WALLET_STORES`
   - `SEAMS_WALLET_INDEXES`
   - `SEAMS_WALLET_SCHEMA_MANIFEST`
   - `LEGACY_INDEXED_DB_NAMES`
   - `createSeamsTestWalletDbName(...)`
3. [x] Add an architecture guard with an explicit temporary allowlist for legacy
   modules that have not moved yet. The final guard must fail if runtime code
   contains:
   - `PasskeyClientDB`
   - `PasskeyAccountKeyMaterial`
   - `seams_wallet_v1`
   - `signing_session_seals_v1`
   - `signing_session_restore_leases_v1`
   - `email_otp_device_enrollment_escrows_v1`
   - inline `indexedDB.open('<literal>')` outside the one DB manager
4. [x] Add a guard that all configured database, object-store, and index names match:

```ts
/^seams_[a-z0-9]+(?:_[a-z0-9]+)*$/
```

5. [x] Update all test helpers so unique DB names are generated as
   `seams_test_wallet_<safe_suffix>`.
   - [x] Moved the generic account-key-material, NEAR threshold key-material,
     local signer reconciliation, and signer mutation saga fixtures to
     `createSeamsTestWalletDbName(...)`.
   - [x] Moved the remaining Email OTP retry and profile/account projection
     browser fixtures off `PasskeyClientDB-*` /
     `PasskeyAccountKeyMaterial-*` test database names.
6. [x] Add a manifest guard that opens a fresh test DB and verifies every store,
   keyPath, index name, and unique flag exactly matches
   `SEAMS_WALLET_SCHEMA_MANIFEST`.
7. [x] Add an import-boundary guard that keeps `IDBDatabase`, `IDBTransaction`,
   `IDBObjectStore`, and `IDBRequest` usage inside IndexedDB repository modules,
   the wallet DB manager, and focused repository tests.
8. [x] Add a registration persistence guard proving source-of-truth wallet-subject
   writes happen before NEAR projection writes in registration code.
9. [x] Record the current post-refactor 33/35/36/39/40 IndexedDB callsite inventory
   before moving repositories. Use the canonical `flows/`, `session/`,
   `threshold/`, `walletAuth/`, and worker-support paths from
   `docs/refactor-33.md` as the starting inventory, accounting for any
   intermediate folder names still in the working tree. Include the current
   `session/persistence/*`, `session/sealedRecovery/*`, `session/passkey/*`,
   `session/emailOtp/*`, `session/availability/*`, `session/budget/*`,
   `session/identity/*`, `session/operationState/*`,
   `session/warmCapabilities/*`, `accountData/near/*`, `webauthnAuth/device/*`,
   `SeamsPasskey/registration.ts`, `SeamsPasskey/login.ts`, and
   `rpcClients/relayer/walletRegistration.ts` callers.

### Phase 2. Create the Unified Schema

1. [x] Introduce `SeamsWalletDBManager` with `SEAMS_WALLET_DB_NAME`.
2. [x] Create current wallet-subject source-of-truth stores first:
   - `seams_wallet_subjects`
   - `seams_wallet_auth_methods`
   - `seams_wallet_signers`
   - `seams_near_accounts`
3. [x] Add the first-class branch-specific auth-method store:
   - `seams_wallet_auth_methods`
   This store carries passkey, Email OTP, and future auth-method branches.
4. [x] Replace the existing `PasskeyClientDB` responsibilities with unified-schema
   wallet-subject repositories and NEAR projection repositories.
   - [x] Moved app-state rows, recovery-email hints, nonce-lane leases, and
     nonce-lane locks behind `SeamsWalletRepositories` backed by
     `seams_wallet`.
   - [x] Added strict `seams_wallet` repository methods for profile records in
     `seams_wallet_subjects` and chain-account projection rows in
     `seams_near_accounts`.
   - [x] Added wallet-subject repository methods for signer lifecycle rows in
     `seams_wallet_signers` and signer mutation rows in
     `seams_signer_ops_outbox`, with snake_case scalar mirrors validated
     against the nested signer/outbox records.
   - [x] Moved authenticator reads/writes and prompt selection to the passkey
     branch of `seams_wallet_auth_methods` through `SeamsWalletRepositories`.
   - [x] Moved preference updates and profile deletion cleanup to
     `SeamsWalletRepositories`, including wallet-subject, projection,
     authenticator, signer, outbox, recovery-email, and key-material rows.
   - [x] Add `seams_wallet_auth_methods` repository methods for passkey and
     Email OTP rows, with scalar mirrors validated against the discriminated
     auth-method branch.
5. [x] Replace `PasskeyAccountKeyMaterial` with the unified schema as
   `seams_key_material`, keyed by wallet signer identity instead of profile id
   and signer slot.
   - [x] Added `seams_key_material` repository methods for store, read, list,
     and delete, with snake_case scalar mirrors validated against the nested
     key-material record.
   - [x] Routed `UnifiedIndexedDBManager` key-material convenience methods and
     local signer reconciliation through `SeamsWalletRepositories`.
   - [x] Repointed NEAR/signing key-material ports to the unified manager so
     those paths use `seams_key_material` through the repository surface.
   - [x] Migrated focused key-material, local signer reconciliation, and signer
     mutation saga browser tests off `PasskeyAccountKeyMaterial-*` databases.
   - [x] Replaced remaining direct `accountKeyMaterialDB` dependency-property
     names with `keyMaterialStore`.
   - [x] Re-keyed key-material rows by wallet signer identity plus key kind;
     key-material records now require `accountAddress` and `signerId` at the
     repository boundary.
   - [x] Tightened explicit key-material target inputs so `profileId`,
     `chainIdKey`, and `accountAddress` are required together, and replaced
     conditional spread construction with explicit record builders.
6. [x] Replace signing-session sealed records with unified-schema stores:
   - `seams_signing_session_seals`
   - `seams_signing_session_restore_leases`
7. [x] Replace Email OTP device enrollment escrow records with a unified-schema store:
   - `seams_email_otp_escrows`
8. [x] This is a code responsibility move only. Existing browser data in old
   databases is discarded; do not read legacy databases to seed `seams_wallet`.
9. [x] Keep all record schemas strict. Do not add compatibility reads for old object
   store names.
10. [x] Keep this phase focused on schema creation and repository construction. The
   runtime will still open legacy databases until Phase 3 replaces the manager
   assembly and direct stores.
   - [x] Added first unified repository construction slice for app state,
     recovery-email hints, nonce-lane leases, and nonce-lane locks.

### Phase 3. Replace Managers and Imports

1. Replace `PasskeyClientDBManager` with `SeamsWalletDBManager` and repository
   ports.
   - [x] Routed `UnifiedIndexedDBManager` app-state, recovery-email, and
     nonce-lane methods through `SeamsWalletRepositories`.
   - [x] Routed last-profile selection state through `seams_app_state` via
     `SeamsWalletRepositories` and `UnifiedIndexedDBManager`.
   - [x] Repointed runtime callsites from direct `clientDB` access to the
     `UnifiedIndexedDBManager` projection, profile, authenticator, and signer
     port surface.
   - [x] Routed `UnifiedIndexedDBManager` profile, NEAR projection, signer
     lifecycle, signer lookup, signer reconciliation, and signer outbox methods
     through `SeamsWalletRepositories`.
   - [x] Routed `UnifiedIndexedDBManager` authenticator methods through
     `SeamsWalletRepositories`.
   - [x] Removed the legacy `atomicOperation` escape hatch from registration
     account lifecycle code and `UnifiedIndexedDBManager`.
   - [x] Removed the runtime `PasskeyClientDBManager` singleton dependency from
     `UnifiedIndexedDBManager`, wallet-host message scoping, and disabled-mode
     configuration.
   - [x] Removed production `PasskeyClientDBManager` type dependencies from
     NEAR projection, key-material, profile projection, and WebAuthn signer-slot
     helpers; these helpers now accept method-specific ports.
   - [x] Removed the public `PasskeyClientDBManager` / `DBConstraintError`
     export from `client/src/core/indexedDB/index.ts`.
   - [x] Migrated the old `passkeyClientDB.deviceSelection` and
     `passkeyClientDB.repositories` browser tests to `UnifiedIndexedDBManager`
     / `SeamsWalletDBManager` backed by `seams_test_wallet_*` databases.
   - [x] Removed the `passkeyClientDB/manager.ts` SDK deep-import build entry.
   - [x] Deleted the old `client/src/core/indexedDB/passkeyClientDB/*`
     manager, schema, and repository modules after migrating tests to the
     unified repository surface.
2. Delete `AccountKeyMaterialDBManager`; key material becomes a repository on
   the unified wallet DB.
   - [x] `UnifiedIndexedDBManager` no longer initializes or uses
     `AccountKeyMaterialDBManager` for key-material convenience methods.
   - [x] SeamsPasskey warmup/login, signing warmup, recovery export, and NEAR
     signing material callsites pass the unified key-material port.
   - [x] Removed `accountKeyMaterialDB` from `UnifiedIndexedDBManager`
     construction and public fields.
   - [x] Removed remaining `IndexedDBManager.accountKeyMaterialDB` test/helper
     callsites; tests now mock or pass the unified key-material port directly.
   - [x] Removed the runtime `accountKeyMaterialDB` singleton, public index
     export, and `configureIndexedDB(...)`/`getIndexedDBNames()` split-DB
     configuration fields.
   - [x] Removed the standalone `accountKeyMaterialDB/manager.ts` SDK deep
     import build entry after focused browser tests moved to the unified wallet
     DB.
   - [x] Deleted the old `AccountKeyMaterialDBManager` and old standalone
     schema module.
   - [x] Renamed the shared key-material type and envelope modules to neutral
     `keyMaterial.*` names.
3. Replace direct IndexedDB logic inside
   `client/src/core/signingEngine/session/persistence/sealedSessionStore.ts`
   with calls to the `seams_signing_session_seals` and
   `seams_signing_session_restore_leases` repositories on the unified wallet DB.
   Keep sealed-store APIs and raw-record classification in `session/persistence/*`.
   - [x] Moved raw sealed-session IndexedDB opens, cursors, record writes, and
     restore-lease transactions into
     `indexedDB/seamsWalletDB/signingSessionSeals.ts`.
   - [x] `sealedSessionStore.ts` now keeps sealed-record classification,
     filtering, logging, and public session persistence APIs while delegating
     storage operations to the repository.
4. Keep strict restore-record construction in
   `client/src/core/signingEngine/session/sealedRecovery/recoveryRecord.ts`.
5. Move Email OTP device enrollment escrow reads/writes from
   `client/src/core/signingEngine/workerManager/workers/email-otp/deviceEnrollmentEscrowStore.ts`
   into a
   `seams_email_otp_escrows` repository on the unified wallet
   DB.
   - [x] Moved the Email OTP device-enrollment escrow raw IndexedDB code into
     `indexedDB/seamsWalletDB/emailOtpDeviceEnrollmentEscrows.ts`; the worker
     support module now delegates to that repository surface.
   - [x] Routed the Email OTP device-enrollment escrow repository through
     `SeamsWalletDBManager` so disabled mode does not open or create
     `seams_wallet`.
6. Keep Email OTP session lifecycle code under `session/emailOtp/*`; the
   device-enrollment escrow repository is the worker-support persistence boundary
   for those escrow records.
7. [x] Reduce `UnifiedIndexedDBManager` to a compatibility facade over
   `SeamsWalletRepositories` and repository-shaped ports.
8. [x] Add `persistWalletRegistrationFinalize(...)` or an equivalent batch method
   over wallet subject, branch-specific auth method,
   wallet signer, key-material, and NEAR projection stores. Registration
   finalize paths must call this batch instead of awaiting several independent
   persistence methods.
   - [x] Split registration finalize from later signer finalize:
     `persistWalletRegistrationFinalize(...)` requires one
     `initialAuthMethodBinding`, while `persistWalletSignerFinalize(...)` has no
     auth-method binding path.
9. [x] Update post-refactor 33/35/36/39/40 callsites to use the new repositories:
   - `SeamsPasskey/registration.ts`
   - `SeamsPasskey/login.ts`
   - `rpcClients/relayer/walletRegistration.ts`
   - `session/userPreferences.ts`
   - `session/persistence/sealedSessionStore.ts`
   - `session/sealedRecovery/*`
   - `session/passkey/*`
   - `session/emailOtp/*`
   - `session/availability/*`
   - `session/budget/*`
   - `session/identity/*`
   - `session/operationState/*`
   - `session/warmCapabilities/*`
   - `accountData/near/*`
   - `flows/registration/*`
   - `flows/recovery/*`
   - `flows/signEvmFamily/*`
   - `flows/signNear/*`
   - any remaining Email OTP flow helpers
   - `threshold/*`
   - `webauthnAuth/device/*`
   - `walletAuth/webauthn/*`
   - `workerManager/workers/email-otp/*`
10. [x] Replace profile/account/signer source-of-truth calls with wallet-subject
   repository calls. Keep NEAR profile access behind projection repositories.
11. [x] Delete old manager files once no production import remains.
12. [x] Confirm `seams_wallet` is the only runtime database opened by the wallet
   persistence path after this phase.

### Phase 4. Delete Legacy Local Databases

Add a dev-state cleanup command behind the new DB manager startup:

```ts
const LEGACY_INDEXED_DB_NAMES = [
  'PasskeyClientDB',
  'PasskeyAccountKeyMaterial',
  'seams_wallet_v1',
] as const;
```

Rules:

1. [x] This deletion is runtime cleanup, not migration. It is enabled in `app` and
   `wallet` modes after Phase 3, and disabled in `disabled` mode.
2. [x] Enable deletion only after runtime no longer opens the old managers or direct
   one-off IndexedDB stores.
3. [x] Delete these databases after the new `seams_wallet` manager is configured and
   before new stores are opened.
4. [x] Use `indexedDB.deleteDatabase(...)` only. Do not open, parse, inspect, or
   migrate records from these databases.
5. [x] If deletion is blocked by another open tab, log a development warning and
   continue with the new database.
6. [x] If IndexedDB is unavailable, cleanup is a no-op.
7. [x] Do not expose legacy database contents through status, snapshot, restore,
   transaction, or export paths.

### Phase 5. Tests

Add or update tests for:

1. [x] New installs create only `seams_wallet` for wallet-origin persistence.
2. [x] App-origin iframe mode creates no app-origin IndexedDB database.
3. [x] All object stores in `seams_wallet` are `seams_*` and snake_case.
4. [x] Store key paths, index names, and unique flags match
   `SEAMS_WALLET_SCHEMA_MANIFEST`.
5. [x] Legacy databases are deleted when present.
6. [x] `disabled` mode opens no `seams_wallet` database and does not run legacy
   deletion.
7. [x] Legacy databases are not read during:
   - wallet-session status
   - transaction signing
   - key export
   - sealed-session restore
   - Email OTP device enrollment restore
8. [x] Test database names are generated as `seams_test_wallet_*`.
   - [x] Focused account-key-material, NEAR key-material, local signer
     reconciliation, and signer mutation saga tests use `seams_test_wallet_*`.
   - [x] Remaining legacy unique test DB names in unit helpers were removed.
9. [x] Architecture guards reject new IndexedDB database names or stores that are not
   `seams_*` snake_case.
10. [x] Architecture guards reject direct `indexedDB.open(...)` and raw IndexedDB
    object types outside the wallet DB manager, repositories, and focused tests.
    - [x] Added a runtime-callsite guard rejecting direct
      `IndexedDBManager.clientDB` / `*.indexedDB.clientDB` access outside the
      unified IndexedDB manager.
11. [x] Wallet registration finalize writes wallet-subject records before NEAR
    projection rows and leaves no projection rows for ECDSA-only registration.
12. [x] Wallet registration finalize uses the named atomic batch and persists exactly
    one initial auth-method binding. A failed batch leaves no wallet-subject,
    auth-method binding, signer, key-material, or projection rows behind.
13. [x] Auth-method binding repositories reject invalid passkey/Email OTP branch
    combinations, duplicate branch identifiers for the same RP, and scalar
    `auth_identifier_key` mismatches.
14. [x] ECDSA wallet-signer writes reject records missing direct `keyHandle`,
    required key facts, owner address, participant ids, or concrete
    `chainTarget`.
    - [x] ECDSA signer rows now mirror `key_handle`,
      `ecdsa_threshold_key_id`, `threshold_owner_address`, and
      `chain_target_key`; Ed25519 signer rows mirror `near_signer_slot`.
    - [x] Duplicate ECDSA key-handle/key-fact indexes are covered by focused
      IndexedDB guard tests.
15. [x] Repository normalizers reject records whose scalar index fields disagree
    with nested domain fields.
    Initial coverage exists for app-state, recovery-email, key-material, and
    nonce-lease unified repositories; signer scalar mirrors are now covered as
    well.
16. [x] Sealed recovery paths accept only normalized `SealedRecoveryRecord` branches
    after persistence reads.
17. [x] Raw sealed-record fixtures remain scoped to `session/persistence/*` and
   `session/sealedRecovery/recoveryRecord.*` tests.
18. [x] Method-specific passkey and Email OTP recovery type fixtures reject raw
    persisted records and broad optional bags.
19. [x] Refactor 41 step-up freshness, reservation identity, and Email OTP refresh
    rejection tests keep raw storage rows out of flow/session code.

Existing tests to revisit during implementation:

1. [x] `passkeyClientDB.*` tests should become repository tests over
   `SeamsWalletDBManager`.
2. [x] Account key material, signer saga, link-device, profile projection, and local
   signer reconciliation tests should keep using `seams_test_wallet_*` fixtures
   and should drop old `clientDB`/`accountKeyMaterialDB` naming as repository
   ports replace compatibility adapters.
3. [x] `sealedSessionStore.unit.test.ts` should keep raw sealed-record fixtures
   scoped to `session/persistence/*` while asserting unified
   `seams_signing_session_seals` repository behavior. Legacy `seams_wallet_v1`
   coverage should exist only as an explicit deletion/no-read guard.
4. [x] `emailOtpDeviceEnrollmentEscrowStore.unit.test.ts` should assert unified
   `seams_email_otp_escrows` repository behavior.
5. [x] `availableSigningLanes.*`, `touchConfirm.workerRouter.*`,
   `thresholdEd25519.registrationWarmSession.*`, and post-refactor 33 operation
   tests should use the repository assembly rather than the old
   `clientDB`/`accountKeyMaterialDB` split.
6. [x] `session/sealedRecovery/recoveryRecord.*`, `session/passkey/*Recovery.*`,
   and `session/emailOtp/*Recovery.*` tests should keep fixtures on the
   normalized recovery-record builders from Refactor 36.
7. [x] `accountData/near/*` and `webauthnAuth/device/*` tests should update
   `PasskeyClientDBManager`-shaped ports to the new repository-shaped ports.
8. [x] Registration tests should write through wallet-subject repositories and treat
   NEAR profile rows as projections.
9. [x] Refactor 41 budget and freshness tests should use repository fixtures that
   provide exact lane identity and canonical scalar identity keys.

### Phase 6. Manual Verification

1. Clear site data for all local wallet/app origins.
2. Create a fresh passkey account.
3. Create a fresh Email OTP account.
4. Confirm DevTools IndexedDB shows only Seams-prefixed DBs for each origin.
5. Verify:
   - wallet unlock
   - passkey sealed-session restore after page refresh
   - Email OTP sealed-session restore after page refresh
   - ED25519 transaction signing
   - ECDSA transaction signing
   - session exhaustion step-up
   - Email OTP companion session reuse
   - ED25519 key export
   - ECDSA key export
   - Email OTP export recovery
6. Repeat in wallet-iframe mode and confirm the app origin does not create local
   IndexedDB state.

## Completion Criteria

- Runtime code has one canonical IndexedDB database name: `seams_wallet`.
- Every Seams object store is `seams_*` snake_case.
- Raw IndexedDB row key paths, index key paths, and scalar mirror fields are
  `snake_case`; repository APIs return normalized domain types.
- No production runtime code references old database names.
- No production runtime code reads or migrates old IndexedDB databases.
- `disabled` mode opens no wallet database and runs no legacy database deletion.
- Wallet-subject records, branch-specific auth methods,
  signer records, key material, NEAR projections, nonce coordination,
  signing-session seals, and Email OTP enrollment escrow records live under the
  unified wallet DB.
- Wallet auth-methods are first-class local rows under
  `seams_wallet_auth_methods`; passkey rows carry WebAuthn credential material.
- Wallet registration finalize uses one repository batch for wallet subject,
  initial auth-method branch, signer records,
  key material, and optional NEAR projections.
- Wallet-subject signer records are the active-signer source of truth; NEAR
  profile/account rows are derived projections.
- ECDSA active signer records contain direct `keyHandle`, required key facts,
  owner address, participant ids, and concrete `chainTarget`.
- The schema manifest test proves store names, key paths, indexes, and unique
  flags match the declared manifest.
- Raw sealed-session records are normalized inside `session/persistence/*` and
  `session/sealedRecovery/recoveryRecord.ts`; method recovery code consumes
  strict branch types only.
- Status, transaction signing, restore, and export paths do not create extra
  IndexedDB databases.
- Guard tests prevent reintroducing mixed-case or non-Seams storage names, direct
  IndexedDB opens, raw IndexedDB object usage outside repositories, and
  profile-first registration persistence.
- Fresh local manual testing works for both passkey and Email OTP accounts after
  clearing old site data.

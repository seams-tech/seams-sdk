# Refactor 46: Canonical Wallet ID

Date created: 2026-05-28

Status: completed.

## Progress

- [x] Rename active domain/request/persistence fields from wallet-subject terms to
  canonical `walletId` / `wallet_id` / `WalletId`.
- [x] Rename browser wallet store to `wallets` and bump `seams_wallet`
  schema version.
- [x] Merge server passkey authenticator persistence into
  `wallet_auth_methods` rows.
- [x] Update server Postgres schema setup to create `wallets`,
  `wallet_auth_methods`, and `wallet_signers` with `wallet_id`.
- [x] Rename server wallet auth-method store APIs away from binding language.
- [x] Update focused IndexedDB, registration persistence, auth-method store, and
  wallet-registration boundary tests.
- [x] Add a dedicated Postgres migration script for deployed/self-hosted
  databases.
- [x] Complete final active-code stale-term guard cleanup after registration
  Phase 5-7 lands.

## Goal

Make `wallet_id` / `walletId` / `WalletId` the canonical durable wallet identity
term everywhere. Remove the current ambiguity between wallet-subject identity,
runtime wallet/session ids, and persistence ownership fields.

After this refactor:

- `wallet_id` means the durable wallet identity.
- `wallet_signing_session_id` means a signing-session lifecycle id.
- `threshold_session_id` means a threshold/HSS session id.
- `auth_subject_id` means an auth principal such as an Email OTP subject.
- `near_account_id` means a NEAR account projection.

Do not keep compatibility aliases such as `walletSubjectId` in core code. This is
a breaking rename.

## Problem Addressed

The codebase previously used several overlapping terms:

- `walletSubjectId`
- `wallet_subject_id`
- `WalletSubjectId`
- `walletId`
- `wallet_id`

`walletSubjectId` is precise in registration/auth-authority language, but it is
awkward as the main wallet identity term. `walletId` is easier to understand, but
it is currently also used in signing-session and Email OTP paths. The result is a
schema where persistence ownership and runtime/session ids can be confused.

The cleanup made the durable wallet identity term short and canonical, then
renamed non-identity wallet-like values to more specific names.

## Target Vocabulary

| Term | Meaning |
| --- | --- |
| `wallet_id` / `walletId` / `WalletId` | Durable wallet identity. Parent id for auth methods, signers, key material, projections, escrow ownership, and signing-session ownership. |
| `wallet_signing_session_id` / `walletSigningSessionId` | Logical signing-session lifecycle id. Never the durable wallet identity. |
| `threshold_session_id` / `thresholdSessionId` | Threshold/HSS session id from signing or registration ceremonies. |
| `auth_subject_id` / `authSubjectId` | Authentication principal id, for example Email OTP subject/user. |
| `near_account_id` / `nearAccountId` | NEAR account projection id. |
| `chain_account_id` / `chainAccountId` | Optional generic chain-account projection id if needed later. |

Remove these terms from active code:

- `walletSubjectId`
- `wallet_subject_id`
- `WalletSubjectId`
- `seams_wallet_subjects`

This completed plan mentions the old names only as historical source terms for
the rename.

## Target Postgres Schema

The server Postgres schema must use the same canonical vocabulary as IndexedDB.
Do not leave server tables on wallet-subject terminology while browser
persistence uses `wallet_id`.

Rename the wallet-subject tables and columns:

| Current | Target |
| --- | --- |
| `wallet_subjects` | `wallets` |
| `wallet_subjects.wallet_subject_id` | `wallets.wallet_id` |
| `wallet_authenticators` | absorbed into `wallet_auth_methods` passkey rows |
| `wallet_auth_method_bindings` | `wallet_auth_methods` |
| `wallet_auth_method_bindings.wallet_subject_id` | `wallet_auth_methods.wallet_id` |
| `wallet_signers.wallet_subject_id` | `wallet_signers.wallet_id` |

Target core server tables:

```sql
CREATE TABLE wallets (
  namespace TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  rp_id TEXT NOT NULL,
  record_json JSONB NOT NULL,
  created_at_ms BIGINT NOT NULL,
  updated_at_ms BIGINT NOT NULL,
  PRIMARY KEY (namespace, wallet_id)
);

CREATE TABLE wallet_auth_methods (
  namespace TEXT NOT NULL,
  wallet_auth_method_id TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  rp_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  status TEXT NOT NULL,
  auth_identifier_key TEXT NOT NULL,
  credential_id_b64u TEXT,
  credential_public_key_b64u TEXT,
  signer_slot INTEGER,
  email_hash_hex TEXT,
  challenge_id TEXT,
  record_json JSONB NOT NULL,
  created_at_ms BIGINT NOT NULL,
  updated_at_ms BIGINT NOT NULL,
  PRIMARY KEY (namespace, wallet_auth_method_id),
  CHECK (kind IN ('passkey', 'email_otp')),
  CHECK (status IN ('active', 'revoked'))
);

CREATE TABLE wallet_signers (
  namespace TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  signer_family TEXT NOT NULL,
  signer_id TEXT NOT NULL,
  chain_target_key TEXT,
  record_json JSONB NOT NULL,
  created_at_ms BIGINT NOT NULL,
  updated_at_ms BIGINT NOT NULL,
  PRIMARY KEY (namespace, wallet_id, signer_family, signer_id),
  CHECK (signer_family IN ('ed25519', 'ecdsa'))
);
```

Target indexes:

```sql
CREATE INDEX wallets_rp_idx
ON wallets (namespace, rp_id, created_at_ms);

CREATE INDEX wallet_auth_methods_wallet_idx
ON wallet_auth_methods (namespace, wallet_id, rp_id, status);

CREATE UNIQUE INDEX wallet_auth_methods_identifier_uidx
ON wallet_auth_methods (namespace, kind, rp_id, auth_identifier_key);

CREATE UNIQUE INDEX wallet_auth_methods_passkey_uidx
ON wallet_auth_methods (namespace, rp_id, credential_id_b64u)
WHERE kind = 'passkey' AND credential_id_b64u IS NOT NULL;

CREATE UNIQUE INDEX wallet_auth_methods_email_uidx
ON wallet_auth_methods (namespace, wallet_id, rp_id, email_hash_hex)
WHERE kind = 'email_otp' AND email_hash_hex IS NOT NULL;

CREATE UNIQUE INDEX wallet_signers_chain_target_uidx
ON wallet_signers (namespace, wallet_id, signer_family, chain_target_key)
WHERE chain_target_key IS NOT NULL;
```

Tables that already use `wallet_id` must be audited, not blindly renamed:

- `email_otp_wallet_enrollments`
- `email_otp_recovery_wrapped_enrollment_escrows`
- `email_otp_auth_states`
- `email_otp_registration_attempts`
- `threshold_ecdsa_keys`
- console usage/billing/sponsored-call tables

Keep `wallet_id` in those tables only when it means the durable wallet identity.
Rename any session/runtime concept to a specific field such as
`wallet_signing_session_id` or `wallet_session_user_id`.

## Target IndexedDB Schema

Rename wallet-subject persistence to wallet persistence:

| Current | Target |
| --- | --- |
| `seams_wallet_subjects` | `wallets` |
| `wallet_subject_id` | `wallet_id` |
| `wallet_subject_id_kind` | `wallet_id_kind` |
| `wallet_subject_kind_near_signer_slot` | `wallet_kind_near_signer_slot` |
| `wallet_subject_kind_chain_target_key_handle` | `wallet_kind_chain_target_key_handle` |
| `wallet_subject_kind_chain_target_key_facts` | `wallet_kind_chain_target_key_facts` |

Target object stores:

| Store | Parent identity field |
| --- | --- |
| `wallets` | `wallet_id` |
| `wallet_auth_methods` | `wallet_id` |
| `wallet_signers` | `wallet_id` |
| `key_material` | `wallet_id` |
| `near_accounts` | `wallet_id` |
| `signer_ops_outbox` | `wallet_id` |
| `recovery_emails` | `wallet_id` |
| `signing_session_seals` | `wallet_id` |
| `email_otp_escrows` | `wallet_id` for durable wallet ownership, `auth_subject_id` for the auth principal |

Because this project is in development, bump `seams_wallet` schema version and
delete obsolete stores during upgrade. Do not add broad migration compatibility
paths in core logic.

## Target Domain Types

Create one branded durable wallet identity type:

```ts
export type WalletId = string & {
  readonly __walletIdBrand: unique symbol;
};

export function walletIdFromString(value: unknown): WalletId {
  const normalized = String(value ?? '').trim();
  if (!normalized) throw new Error('walletId is required');
  return normalized as WalletId;
}
```

Delete `WalletSubjectId` instead of aliasing it.

Update registration/auth types:

- `WalletAuthMethodBinding.walletSubjectId` -> `walletId`
- `NearAccountOwnershipProofMessageV1.walletSubjectId` -> `walletId`
- registration intent `walletSubject` branches that carry `walletSubjectId` -> `walletId`
- add-signer and wallet-registration route bodies `walletSubjectId` -> `walletId`

Keep `walletSigningSessionId` and `walletSessionUserId` for session concepts.

## Implementation Phases

### Phase 1. Inventory And Guards

1. Add a temporary inventory test that lists active occurrences of:
   - `walletSubjectId`
   - `wallet_subject_id`
   - `WalletSubjectId`
   - `seams_wallet_subjects`
2. Classify each occurrence as one of:
   - domain type
   - route/request boundary
   - IndexedDB schema/row/index
   - repository API
   - signing-session runtime id
   - docs/test fixture
3. Add a guard that fails new active-code references to old terms outside this
   refactor branch. Keep the guard allowlist narrow and delete it when the
   rename completes.

### Phase 2. Shared Domain Rename

1. Replace `WalletSubjectId` with `WalletId`.
2. Replace `walletSubjectIdFromString(...)` with `walletIdFromString(...)`.
3. Replace `walletSubjectIdFromWalletProfile(...)` with a wallet-id-specific
   helper or delete it if it only wrapped casts.
4. Update shared registration-intent types and type fixtures.
5. Update route/request parsers to require `walletId`.
6. Delete old type names. Do not keep aliases.

### Phase 3. IndexedDB Schema Rename

1. Rename `SEAMS_WALLET_STORES.walletSubjects` to `wallets`.
2. Rename store string `seams_wallet_subjects` to `wallets`.
3. Rename row fields:
   - `wallet_subject_id` -> `wallet_id`
   - `wallet_subject_id_kind` -> `wallet_id_kind`
4. Rename wallet-signer unique indexes:
   - `wallet_subject_kind_near_signer_slot` -> `wallet_kind_near_signer_slot`
   - `wallet_subject_kind_chain_target_key_handle` -> `wallet_kind_chain_target_key_handle`
   - `wallet_subject_kind_chain_target_key_facts` -> `wallet_kind_chain_target_key_facts`
5. Bump `SEAMS_WALLET_DB_VERSION`.
6. Delete obsolete wallet-subject stores/index assumptions during schema upgrade.

### Phase 4. Postgres Schema Rename

1. Update `server/src/storage/postgres.ts` schema setup:
   - `wallet_subjects` -> `wallets`
   - `wallet_auth_method_bindings` -> `wallet_auth_methods`
   - remove `wallet_authenticators` as a separate table
   - `wallet_subject_id` -> `wallet_id`
2. Merge passkey authenticator material into `wallet_auth_methods` passkey rows.
3. Rename indexes:
   - `wallet_subjects_rp_idx` -> `wallets_rp_idx`
   - `wallet_auth_method_bindings_wallet_idx` -> `wallet_auth_methods_wallet_idx`
   - `wallet_auth_method_bindings_passkey_uidx` -> `wallet_auth_methods_passkey_uidx`
   - `wallet_auth_method_bindings_email_uidx` -> `wallet_auth_methods_email_uidx`
4. Update Postgres record parsers/builders so `record_json` stores `walletId`,
   not `walletSubjectId`.
5. For development resets, create only the new tables.
6. For self-hosted/deployed Postgres, provide an explicit one-time migration:
   - rename tables/columns/indexes
   - copy or merge `wallet_authenticators` into `wallet_auth_methods`
   - rewrite `record_json` keys from `walletSubjectId` to `walletId`
   - drop old tables once verification passes
   - run with `pnpm -C examples/relay-server run postgres:migrate:wallet-id`

Example migration shape:

```sql
ALTER TABLE wallet_subjects RENAME TO wallets;
ALTER TABLE wallets RENAME COLUMN wallet_subject_id TO wallet_id;
ALTER INDEX wallet_subjects_rp_idx RENAME TO wallets_rp_idx;

ALTER TABLE wallet_auth_method_bindings RENAME TO wallet_auth_methods;
ALTER TABLE wallet_auth_methods RENAME COLUMN wallet_subject_id TO wallet_id;

ALTER TABLE wallet_signers RENAME COLUMN wallet_subject_id TO wallet_id;
```

Handle JSONB rewrites in the same migration or a typed migration script:

```sql
UPDATE wallets
SET record_json =
  (record_json - 'walletSubjectId') ||
  jsonb_build_object('walletId', record_json->>'walletSubjectId')
WHERE record_json ? 'walletSubjectId';
```

### Phase 5. Repository API Rename

1. Rename row types:
   - `WalletSubjectRow` -> `WalletRow`
   - `wallet_subject_id` scalar mirrors -> `wallet_id`
2. Rename repository methods and inputs:
   - `listWalletAuthMethodBindingsForWalletSubject(...)` -> `listWalletAuthMethodsForWallet(...)`
   - wallet-subject finalize inputs -> wallet finalize inputs
   - wallet-subject signer helpers -> wallet signer helpers
3. Make all repository inputs require `walletId` for durable wallet ownership.
4. Keep branch-specific auth-method access methods direct:
   - `getWalletAuthMethod(...)`
   - `listWalletAuthMethodsForWallet(...)`
   - `getPasskeyAuthMethodByCredentialId(...)`
   - `listProfileAuthenticators(...)` only if still needed as a compatibility
     facade inside the browser adapter; otherwise rename to passkey-specific
     methods.

### Phase 6. Registration And Relayer Boundaries

1. Rename wallet-registration and add-signer route bodies:
   - `walletSubjectId` -> `walletId`
2. Update relayer clients, server handlers, request validators, and tests.
3. Update registration flows:
   - wallet-subject registration helpers -> wallet registration helpers
   - wallet-subject signer activation helpers -> wallet signer activation helpers
4. Ensure parsed route bodies become precise internal types at the boundary.
5. Delete compatibility handling once callsites use `walletId`.

### Phase 7. Signing Session And Email OTP Clarification

1. Audit every existing `walletId` usage.
2. Keep `walletId` only where it is the durable wallet identity.
3. Rename any runtime/session value that is not durable identity:
   - `walletSessionId` / `walletSigningSessionId` for signing-session state
   - `walletSessionUserId` for session user identity
   - `authSubjectId` for Email OTP auth principal
4. Verify `signing_session_seals.wallet_id` points to durable wallet id.
5. Verify `email_otp_escrows.wallet_id` points to durable wallet id and
   `auth_subject_id` remains the auth principal.

### Phase 8. Tests And Static Fixtures

1. Update type fixtures to reject old names:
   - `walletSubjectId`
   - `wallet_subject_id`
   - `WalletSubjectId`
2. Update IndexedDB schema manifest tests for:
   - `wallets`
   - `wallet_id`
   - renamed wallet signer indexes
3. Add repository tests proving:
   - auth methods list by `wallet_id`
   - signers list by `wallet_id`
   - profile deletion/wallet deletion removes rows by `wallet_id`
   - route parsers reject `walletSubjectId`
4. Add Postgres tests proving:
   - schema setup creates `wallets`, `wallet_auth_methods`, and
     `wallet_signers.wallet_id`
   - no active table or index uses wallet-subject names
   - `record_json` contains `walletId`, not `walletSubjectId`
   - passkey auth method rows include WebAuthn credential material
5. Update registration and add-signer tests to use `walletId`.

### Phase 9. Documentation Cleanup

1. Update:
   - `docs/consolidate-indexeddb-tables.md`
   - `docs/rework-registration-flows-2.md`
   - `docs/saas/db-schema.md`
   - deployment/migration docs for Postgres
   - any route/API docs
2. Remove old terms from active docs.
3. Keep old terms only in historical changelog notes if needed.

## Validation

Run the cheapest useful checks after each phase:

1. Shared type rename:
   - `pnpm -s type-check:sdk`
   - registration-intent type fixtures
2. Schema/repository rename:
   - `pnpm -C sdk -s run build:prepare`
   - `pnpm -C tests -s exec playwright test ./unit/indexedDBConsolidation.guard.unit.test.ts --reporter=line`
   - focused repository tests
3. Postgres rename:
   - Postgres schema/unit tests
   - `tests/scripts/run-postgres-migration.mjs` when migration scripts change
   - focused relayer Postgres tests for wallet registration/auth methods/signers
4. Registration/route rename:
   - registration wallet-subject/wallet persistence tests
   - route boundary tests
   - server type checks if server request types change
5. Final sweep:
   - `rg "walletSubjectId|wallet_subject_id|WalletSubjectId|seams_wallet_subjects|wallet_subjects" client/src shared/src server/src tests`
   - docs should use `walletId` vocabulary except where a completed migration
     plan explicitly names historical source terms.
   - `pnpm -s type-check:sdk`
   - affected Playwright unit groups
   - `git diff --check`

## Completion Criteria

- `wallet_id` is the only durable wallet identity field in active persistence
  rows.
- `walletId` is the only durable wallet identity property in active domain and
  route types.
- `WalletId` is the only branded durable wallet identity type.
- Runtime/session concepts use specific names such as `walletSigningSessionId`
  or `walletSessionUserId`.
- Active code contains no `walletSubjectId`, `wallet_subject_id`,
  `WalletSubjectId`, `wallet_subjects`, or `seams_wallet_subjects`.
- IndexedDB schema uses `wallets` and `wallet_id`.
- Postgres schema uses `wallets`, `wallet_auth_methods`, and `wallet_id`.
- Postgres `record_json` payloads use `walletId`, not `walletSubjectId`.
- Boundary parsers reject old request fields.

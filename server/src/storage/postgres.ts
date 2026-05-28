import type { NormalizedLogger } from '../core/logger';
import { toOptionalTrimmedString } from '@shared/utils/validation';

export type PgPoolClient = {
  query: (text: string, values?: unknown[]) => Promise<{ rows: any[]; rowCount?: number }>;
  release: () => void;
};

export type PgQueryExecutor = {
  query: (text: string, values?: unknown[]) => Promise<{ rows: any[]; rowCount?: number }>;
};

type PgPool = {
  query: (text: string, values?: unknown[]) => Promise<{ rows: any[]; rowCount?: number }>;
  connect?: () => Promise<PgPoolClient>;
  end?: () => Promise<void>;
};

type PgModuleLike = {
  Pool?: new (opts: { connectionString: string }) => PgPool;
  default?: { Pool?: new (opts: { connectionString: string }) => PgPool };
};

export type ParsedPostgresRowResult<T> =
  | { kind: 'missing' }
  | { kind: 'malformed' }
  | { kind: 'current'; value: T };

export function parsePostgresRow<T>(input: {
  row: unknown;
  parser: (row: Record<string, unknown>) => T | null;
}): ParsedPostgresRowResult<T> {
  if (input.row === null || input.row === undefined) {
    return { kind: 'missing' };
  }
  if (typeof input.row !== 'object' || Array.isArray(input.row)) {
    return { kind: 'malformed' };
  }
  const parsed = input.parser(input.row as Record<string, unknown>);
  if (!parsed) {
    return { kind: 'malformed' };
  }
  return { kind: 'current', value: parsed };
}

const poolsByUrl = new Map<string, Promise<PgPool>>();

async function loadPgPoolCtor(): Promise<new (opts: { connectionString: string }) => PgPool> {
  let mod: PgModuleLike;
  try {
    mod = (await import('pg')) as unknown as PgModuleLike;
  } catch (err) {
    const msg = String(
      err && typeof err === 'object' && 'message' in err ? (err as any).message : err || '',
    );
    throw new Error(
      `Postgres store selected but 'pg' dependency is not available${msg ? `: ${msg}` : ''}`,
    );
  }
  const ctor = mod.Pool || mod.default?.Pool;
  if (!ctor)
    throw new Error(`Postgres store selected but failed to load Pool constructor from 'pg'`);
  return ctor;
}

export function getPostgresUrlFromConfig(config: Record<string, unknown>): string | null {
  return (
    toOptionalTrimmedString(config.postgresUrl) || toOptionalTrimmedString(config.POSTGRES_URL)
  );
}

export async function getPostgresPool(postgresUrl: string): Promise<PgPool> {
  const url = String(postgresUrl || '').trim();
  if (!url) throw new Error('Missing POSTGRES_URL');
  const existing = poolsByUrl.get(url);
  if (existing) return existing;

  const created = (async () => {
    const Pool = await loadPgPoolCtor();
    return new Pool({ connectionString: url });
  })();
  poolsByUrl.set(url, created);
  return created;
}

const MIGRATION_LOCK_ID = 9452360123581;

async function queryOne(
  executor: PgQueryExecutor,
  text: string,
  values: unknown[] = [],
): Promise<Record<string, unknown> | null> {
  const result = await executor.query(text, values);
  const row = result.rows[0];
  return row && typeof row === 'object' && !Array.isArray(row)
    ? (row as Record<string, unknown>)
    : null;
}

async function tableExists(executor: PgQueryExecutor, tableName: string): Promise<boolean> {
  const row = await queryOne(
    executor,
    `
      SELECT to_regclass($1) AS table_name
    `,
    [`public.${tableName}`],
  );
  return Boolean(row?.table_name);
}

async function columnExists(
  executor: PgQueryExecutor,
  tableName: string,
  columnName: string,
): Promise<boolean> {
  const row = await queryOne(
    executor,
    `
      SELECT 1
      FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = $1
        AND column_name = $2
      LIMIT 1
    `,
    [tableName, columnName],
  );
  return Boolean(row);
}

async function migrateWalletIdTables(executor: PgQueryExecutor): Promise<void> {
  if (await tableExists(executor, 'wallet_subjects')) {
    await executor.query(`
      INSERT INTO wallets
        (namespace, wallet_id, rp_id, record_json, created_at_ms, updated_at_ms)
      SELECT
        namespace,
        wallet_subject_id,
        rp_id,
        jsonb_set(
          jsonb_set(record_json - 'walletSubjectId', '{walletId}', to_jsonb(wallet_subject_id)),
          '{version}',
          to_jsonb('wallet_v1'::text)
        ),
        created_at_ms,
        updated_at_ms
      FROM wallet_subjects
      ON CONFLICT (namespace, wallet_id) DO UPDATE SET
        rp_id = EXCLUDED.rp_id,
        record_json = EXCLUDED.record_json,
        created_at_ms = LEAST(wallets.created_at_ms, EXCLUDED.created_at_ms),
        updated_at_ms = GREATEST(wallets.updated_at_ms, EXCLUDED.updated_at_ms)
    `);
  }

  if (await tableExists(executor, 'wallet_auth_method_bindings')) {
    await executor.query(`
      INSERT INTO wallet_auth_methods
        (
          namespace,
          wallet_auth_method_id,
          wallet_id,
          rp_id,
          kind,
          status,
          auth_identifier_key,
          credential_id_b64u,
          credential_public_key_b64u,
          signer_slot,
          email_hash_hex,
          challenge_id,
          record_json,
          created_at_ms,
          updated_at_ms
        )
      SELECT
        namespace,
        CASE
          WHEN kind = 'passkey' THEN 'passkey:' || rp_id || ':' || credential_id_b64u
          ELSE 'email_otp:' || wallet_subject_id || ':' || rp_id || ':' || email_hash_hex
        END,
        wallet_subject_id,
        rp_id,
        kind,
        status,
        CASE WHEN kind = 'passkey' THEN credential_id_b64u ELSE email_hash_hex END,
        credential_id_b64u,
        record_json->>'credentialPublicKeyB64u',
        NULL,
        email_hash_hex,
        record_json->>'challengeId',
        jsonb_set(
          jsonb_set(
            jsonb_set(record_json - 'walletSubjectId', '{walletId}', to_jsonb(wallet_subject_id)),
            '{version}',
            to_jsonb('wallet_auth_method_v1'::text)
          ),
          '{kind}',
          to_jsonb(kind)
        ),
        created_at_ms,
        updated_at_ms
      FROM wallet_auth_method_bindings
      ON CONFLICT (namespace, wallet_auth_method_id) DO UPDATE SET
        wallet_id = EXCLUDED.wallet_id,
        rp_id = EXCLUDED.rp_id,
        kind = EXCLUDED.kind,
        status = EXCLUDED.status,
        auth_identifier_key = EXCLUDED.auth_identifier_key,
        credential_id_b64u = EXCLUDED.credential_id_b64u,
        credential_public_key_b64u = EXCLUDED.credential_public_key_b64u,
        signer_slot = EXCLUDED.signer_slot,
        email_hash_hex = EXCLUDED.email_hash_hex,
        challenge_id = EXCLUDED.challenge_id,
        record_json = EXCLUDED.record_json,
        created_at_ms = LEAST(wallet_auth_methods.created_at_ms, EXCLUDED.created_at_ms),
        updated_at_ms = GREATEST(wallet_auth_methods.updated_at_ms, EXCLUDED.updated_at_ms)
    `);
  }

  if (await tableExists(executor, 'wallet_authenticators')) {
    await executor.query(`
      INSERT INTO wallet_auth_methods
        (
          namespace,
          wallet_auth_method_id,
          wallet_id,
          rp_id,
          kind,
          status,
          auth_identifier_key,
          credential_id_b64u,
          credential_public_key_b64u,
          signer_slot,
          email_hash_hex,
          challenge_id,
          record_json,
          created_at_ms,
          updated_at_ms
        )
      SELECT
        namespace,
        'passkey:' || rp_id || ':' || credential_id_b64u,
        wallet_subject_id,
        rp_id,
        'passkey',
        'active',
        credential_id_b64u,
        credential_id_b64u,
        record_json->>'credentialPublicKeyB64u',
        NULL,
        NULL,
        NULL,
        jsonb_build_object(
          'version', 'wallet_auth_method_v1',
          'kind', 'passkey',
          'status', 'active',
          'walletId', wallet_subject_id,
          'rpId', rp_id,
          'credentialIdB64u', credential_id_b64u,
          'credentialPublicKeyB64u', record_json->>'credentialPublicKeyB64u',
          'counter', COALESCE((record_json->>'counter')::bigint, 0),
          'createdAtMs', created_at_ms,
          'updatedAtMs', updated_at_ms
        ),
        created_at_ms,
        updated_at_ms
      FROM wallet_authenticators
      ON CONFLICT (namespace, wallet_auth_method_id) DO UPDATE SET
        wallet_id = EXCLUDED.wallet_id,
        rp_id = EXCLUDED.rp_id,
        kind = EXCLUDED.kind,
        status = EXCLUDED.status,
        auth_identifier_key = EXCLUDED.auth_identifier_key,
        credential_id_b64u = EXCLUDED.credential_id_b64u,
        credential_public_key_b64u = EXCLUDED.credential_public_key_b64u,
        record_json = EXCLUDED.record_json,
        created_at_ms = LEAST(wallet_auth_methods.created_at_ms, EXCLUDED.created_at_ms),
        updated_at_ms = GREATEST(wallet_auth_methods.updated_at_ms, EXCLUDED.updated_at_ms)
    `);
  }

  if (
    (await tableExists(executor, 'wallet_signers')) &&
    (await columnExists(executor, 'wallet_signers', 'wallet_subject_id')) &&
    !(await columnExists(executor, 'wallet_signers', 'wallet_id'))
  ) {
    await executor.query('ALTER TABLE wallet_signers RENAME COLUMN wallet_subject_id TO wallet_id');
  }
  if (await tableExists(executor, 'wallet_signers')) {
    await executor.query(`
      UPDATE wallet_signers
      SET record_json = jsonb_set(record_json - 'walletSubjectId', '{walletId}', to_jsonb(wallet_id))
      WHERE record_json ? 'walletSubjectId'
    `);
  }

  await executor.query('DROP TABLE IF EXISTS wallet_authenticators');
  await executor.query('DROP TABLE IF EXISTS wallet_auth_method_bindings');
  await executor.query('DROP TABLE IF EXISTS wallet_subjects');
  await executor.query('DROP TABLE IF EXISTS account_signers');
  await executor.query('DROP TABLE IF EXISTS smart_account_recovery_subjects');
}

export async function ensurePostgresSchema(input: {
  postgresUrl: string;
  logger: NormalizedLogger;
}): Promise<void> {
  const pool = await getPostgresPool(input.postgresUrl);
  await pool.query('SELECT pg_advisory_lock($1)', [MIGRATION_LOCK_ID]);
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS webauthn_authenticators (
        namespace TEXT NOT NULL,
        user_id TEXT NOT NULL,
        credential_id_b64u TEXT NOT NULL,
        credential_public_key_b64u TEXT NOT NULL,
        counter BIGINT NOT NULL,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, user_id, credential_id_b64u)
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS webauthn_credential_bindings (
        namespace TEXT NOT NULL,
        rp_id TEXT NOT NULL,
        credential_id_b64u TEXT NOT NULL,
        record_json JSONB NOT NULL,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, rp_id, credential_id_b64u)
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS webauthn_challenges (
        namespace TEXT NOT NULL,
        challenge_id TEXT NOT NULL,
        record_json JSONB NOT NULL,
        expires_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, challenge_id)
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS webauthn_challenges_expires_idx
      ON webauthn_challenges (expires_at_ms)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS wallet_registration_intents (
        namespace TEXT NOT NULL,
        intent_grant TEXT NOT NULL,
        record_json JSONB NOT NULL,
        expires_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, intent_grant)
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS wallet_registration_intents_expires_idx
      ON wallet_registration_intents (expires_at_ms)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS wallet_registration_ceremonies (
        namespace TEXT NOT NULL,
        registration_ceremony_id TEXT NOT NULL,
        record_json JSONB NOT NULL,
        expires_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, registration_ceremony_id)
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS wallet_registration_ceremonies_expires_idx
      ON wallet_registration_ceremonies (expires_at_ms)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS wallets (
        namespace TEXT NOT NULL,
        wallet_id TEXT NOT NULL,
        rp_id TEXT NOT NULL,
        record_json JSONB NOT NULL,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, wallet_id)
      )
    `);
    await migrateWalletIdTables(pool);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS wallets_rp_idx
      ON wallets (namespace, rp_id, created_at_ms)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS wallet_auth_methods (
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
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS wallet_auth_methods_wallet_idx
      ON wallet_auth_methods (namespace, wallet_id, rp_id, status)
    `);
    await pool.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS wallet_auth_methods_identifier_uidx
      ON wallet_auth_methods (namespace, kind, rp_id, auth_identifier_key)
    `);
    await pool.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS wallet_auth_methods_passkey_uidx
      ON wallet_auth_methods (namespace, rp_id, credential_id_b64u)
      WHERE kind = 'passkey' AND credential_id_b64u IS NOT NULL
    `);
    await pool.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS wallet_auth_methods_email_uidx
      ON wallet_auth_methods (namespace, wallet_id, rp_id, email_hash_hex)
      WHERE kind = 'email_otp' AND email_hash_hex IS NOT NULL
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS wallet_signers (
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
      )
    `);
    await pool.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS wallet_signers_chain_target_uidx
      ON wallet_signers (namespace, wallet_id, signer_family, chain_target_key)
      WHERE chain_target_key IS NOT NULL
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS email_otp_challenges (
        namespace TEXT NOT NULL,
        challenge_id TEXT NOT NULL,
        record_json JSONB NOT NULL,
        expires_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, challenge_id)
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS email_otp_challenges_expires_idx
      ON email_otp_challenges (expires_at_ms)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS email_otp_grants (
        namespace TEXT NOT NULL,
        grant_token TEXT NOT NULL,
        record_json JSONB NOT NULL,
        expires_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, grant_token)
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS email_otp_grants_expires_idx
      ON email_otp_grants (expires_at_ms)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS email_otp_wallet_enrollments (
        namespace TEXT NOT NULL,
        wallet_id TEXT NOT NULL,
        org_id TEXT NOT NULL,
        record_json JSONB NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, wallet_id)
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS email_otp_wallet_enrollments_org_updated_idx
      ON email_otp_wallet_enrollments (namespace, org_id, updated_at_ms)
    `);
    await pool.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS email_otp_wallet_enrollments_provider_user_unique_idx
      ON email_otp_wallet_enrollments (namespace, org_id, ((record_json->>'providerUserId')))
    `);
    await pool.query(`
      DROP INDEX IF EXISTS email_otp_wallet_enrollments_provider_user_idx
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS email_otp_recovery_wrapped_enrollment_escrows (
        namespace TEXT NOT NULL,
        wallet_id TEXT NOT NULL,
        recovery_key_id TEXT NOT NULL,
        recovery_key_status TEXT NOT NULL,
        record_json JSONB NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, wallet_id, recovery_key_id)
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS email_otp_recovery_wrapped_escrows_wallet_status_idx
      ON email_otp_recovery_wrapped_enrollment_escrows (
        namespace,
        wallet_id,
        recovery_key_status,
        updated_at_ms
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS email_otp_auth_states (
        namespace TEXT NOT NULL,
        wallet_id TEXT NOT NULL,
        org_id TEXT NOT NULL,
        record_json JSONB NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, wallet_id)
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS email_otp_auth_states_org_updated_idx
      ON email_otp_auth_states (namespace, org_id, updated_at_ms)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS email_otp_unlock_challenges (
        namespace TEXT NOT NULL,
        challenge_id TEXT NOT NULL,
        record_json JSONB NOT NULL,
        expires_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, challenge_id)
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS email_otp_unlock_challenges_expires_idx
      ON email_otp_unlock_challenges (expires_at_ms)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS email_otp_registration_attempts (
        namespace TEXT NOT NULL,
        attempt_id TEXT NOT NULL,
        provider_subject TEXT NOT NULL,
        email TEXT NOT NULL,
        wallet_id TEXT NOT NULL,
        state TEXT NOT NULL,
        record_json JSONB NOT NULL,
        expires_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, attempt_id)
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS email_otp_registration_attempts_subject_idx
      ON email_otp_registration_attempts (namespace, provider_subject, email, state, expires_at_ms)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS email_otp_registration_attempts_wallet_idx
      ON email_otp_registration_attempts (namespace, wallet_id, state, expires_at_ms)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS threshold_ed25519_keys (
        namespace TEXT NOT NULL,
        relayer_key_id TEXT NOT NULL,
        record_json JSONB NOT NULL,
        PRIMARY KEY (namespace, relayer_key_id)
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS threshold_ecdsa_keys (
        namespace TEXT NOT NULL,
        relayer_key_id TEXT NOT NULL,
        key_handle TEXT,
        threshold_key_id TEXT,
        wallet_id TEXT,
        rp_id TEXT,
        signing_root_id TEXT,
        signing_root_version TEXT,
        owner_address TEXT,
        public_key_b64u TEXT,
        record_json JSONB NOT NULL,
        PRIMARY KEY (namespace, relayer_key_id)
      )
    `);

    await pool.query('ALTER TABLE threshold_ecdsa_keys ADD COLUMN IF NOT EXISTS key_handle TEXT');
    await pool.query(
      'ALTER TABLE threshold_ecdsa_keys ADD COLUMN IF NOT EXISTS threshold_key_id TEXT',
    );
    await pool.query(
      'ALTER TABLE threshold_ecdsa_keys ADD COLUMN IF NOT EXISTS wallet_id TEXT',
    );
    await pool.query('ALTER TABLE threshold_ecdsa_keys ADD COLUMN IF NOT EXISTS rp_id TEXT');
    await pool.query(
      'ALTER TABLE threshold_ecdsa_keys ADD COLUMN IF NOT EXISTS signing_root_id TEXT',
    );
    await pool.query(
      'ALTER TABLE threshold_ecdsa_keys ADD COLUMN IF NOT EXISTS signing_root_version TEXT',
    );
    await pool.query(
      'ALTER TABLE threshold_ecdsa_keys ADD COLUMN IF NOT EXISTS owner_address TEXT',
    );
    await pool.query(
      'ALTER TABLE threshold_ecdsa_keys ADD COLUMN IF NOT EXISTS public_key_b64u TEXT',
    );
    await pool.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS threshold_ecdsa_keys_key_handle_uidx
      ON threshold_ecdsa_keys (namespace, key_handle)
      WHERE key_handle IS NOT NULL
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS threshold_ecdsa_keys_owner_address_idx
      ON threshold_ecdsa_keys (namespace, owner_address)
      WHERE owner_address IS NOT NULL
    `);
    await pool.query('DROP INDEX IF EXISTS threshold_ecdsa_keys_shared_identity_idx');
    await pool.query('DROP INDEX IF EXISTS threshold_ecdsa_keys_shared_identity_uidx');
    await pool.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS threshold_ecdsa_keys_threshold_identity_uidx
      ON threshold_ecdsa_keys (namespace, threshold_key_id, signing_root_id, signing_root_version)
      WHERE
        threshold_key_id IS NOT NULL AND
        signing_root_id IS NOT NULL AND
        signing_root_version IS NOT NULL
    `);
    await pool.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS threshold_ecdsa_keys_shared_identity_uidx
      ON threshold_ecdsa_keys (
        namespace,
        wallet_id,
        rp_id,
        signing_root_id,
        signing_root_version
      )
      WHERE
        wallet_id IS NOT NULL AND
        rp_id IS NOT NULL AND
        signing_root_id IS NOT NULL AND
        signing_root_version IS NOT NULL
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS signing_root_secret_shares (
        namespace TEXT NOT NULL,
        signing_root_id TEXT NOT NULL,
        signing_root_version TEXT NOT NULL,
        share_id INTEGER NOT NULL,
        sealed_share_b64u TEXT NOT NULL,
        storage_id TEXT,
        kek_id TEXT,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, signing_root_id, signing_root_version, share_id),
        CHECK (share_id IN (1, 2, 3))
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS threshold_ed25519_sessions (
        namespace TEXT NOT NULL,
        kind TEXT NOT NULL,
        session_id TEXT NOT NULL,
        record_json JSONB NOT NULL,
        expires_at_ms BIGINT NOT NULL,
        remaining_uses INTEGER,
        PRIMARY KEY (namespace, kind, session_id),
        CHECK (kind IN ('mpc', 'signing', 'coordinator', 'auth'))
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS threshold_ed25519_sessions_expires_idx
      ON threshold_ed25519_sessions (expires_at_ms)
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS threshold_ed25519_auth_consumptions (
        namespace TEXT NOT NULL,
        session_id TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        expires_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, session_id, idempotency_key)
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS threshold_ed25519_auth_consumptions_expires_idx
      ON threshold_ed25519_auth_consumptions (expires_at_ms)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS threshold_ecdsa_signing_sessions (
        namespace TEXT NOT NULL,
        signing_session_id TEXT NOT NULL,
        record_json JSONB NOT NULL,
        expires_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, signing_session_id)
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS threshold_ecdsa_signing_sessions_expires_idx
      ON threshold_ecdsa_signing_sessions (expires_at_ms)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS threshold_ecdsa_presign_sessions (
        namespace TEXT NOT NULL,
        presign_session_id TEXT NOT NULL,
        record_json JSONB NOT NULL,
        stage TEXT NOT NULL,
        version INTEGER NOT NULL,
        expires_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, presign_session_id),
        CHECK (stage IN ('triples', 'triples_done', 'presign', 'done'))
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS threshold_ecdsa_presign_sessions_expires_idx
      ON threshold_ecdsa_presign_sessions (expires_at_ms)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS threshold_ecdsa_presign_sessions_stage_idx
      ON threshold_ecdsa_presign_sessions (namespace, stage, updated_at_ms)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS threshold_ecdsa_presignatures (
        namespace TEXT NOT NULL,
        relayer_key_id TEXT NOT NULL,
        presignature_id TEXT NOT NULL,
        state TEXT NOT NULL,
        record_json JSONB NOT NULL,
        created_at_ms BIGINT NOT NULL,
        reserved_at_ms BIGINT,
        reserve_expires_at_ms BIGINT,
        PRIMARY KEY (namespace, relayer_key_id, presignature_id),
        CHECK (state IN ('available', 'reserved'))
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS threshold_ecdsa_presignatures_state_idx
      ON threshold_ecdsa_presignatures (namespace, relayer_key_id, state, created_at_ms)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS threshold_ecdsa_presignatures_reserved_expires_idx
      ON threshold_ecdsa_presignatures (reserve_expires_at_ms)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS device_linking_sessions (
        namespace TEXT NOT NULL,
        session_id TEXT NOT NULL,
        record_json JSONB NOT NULL,
        expires_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, session_id)
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS device_linking_sessions_expires_idx
      ON device_linking_sessions (expires_at_ms)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS email_recovery_preparations (
        namespace TEXT NOT NULL,
        request_id TEXT NOT NULL,
        record_json JSONB NOT NULL,
        expires_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, request_id)
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS email_recovery_preparations_expires_idx
      ON email_recovery_preparations (expires_at_ms)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS near_public_keys (
        namespace TEXT NOT NULL,
        user_id TEXT NOT NULL,
        public_key TEXT NOT NULL,
        record_json JSONB NOT NULL,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, user_id, public_key)
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS near_public_keys_user_idx
      ON near_public_keys (namespace, user_id)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS identity_links (
        namespace TEXT NOT NULL,
        subject TEXT NOT NULL,
        user_id TEXT NOT NULL,
        record_json JSONB NOT NULL,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, subject)
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS identity_links_user_idx
      ON identity_links (namespace, user_id)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS app_session_versions (
        namespace TEXT NOT NULL,
        user_id TEXT NOT NULL,
        session_version TEXT NOT NULL,
        record_json JSONB NOT NULL,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, user_id)
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS recovery_sessions (
        namespace TEXT NOT NULL,
        session_id TEXT NOT NULL,
        near_account_id TEXT NOT NULL,
        record_json JSONB NOT NULL,
        expires_at_ms BIGINT NOT NULL,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, session_id)
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS recovery_sessions_near_idx
      ON recovery_sessions (namespace, near_account_id, updated_at_ms)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS recovery_sessions_expires_idx
      ON recovery_sessions (expires_at_ms)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS recovery_executions (
        namespace TEXT NOT NULL,
        session_id TEXT NOT NULL,
        chain_id_key TEXT NOT NULL,
        account_address TEXT NOT NULL,
        action TEXT NOT NULL,
        record_json JSONB NOT NULL,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, session_id, chain_id_key, account_address, action)
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS recovery_executions_session_idx
      ON recovery_executions (namespace, session_id, updated_at_ms)
    `);
  } finally {
    try {
      await pool.query('SELECT pg_advisory_unlock($1)', [MIGRATION_LOCK_ID]);
    } catch {
      // ignore unlock failures
    }
  }

  input.logger.info('[postgres] Schema ready');
}

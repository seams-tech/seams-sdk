import type { NormalizedLogger } from '../core/logger';
import { toOptionalTrimmedString } from '@shared/utils/validation';

export type PgPoolClient = {
  query: (text: string, values?: unknown[]) => Promise<{ rows: any[]; rowCount?: number }>;
  release: () => void;
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
        record_json JSONB NOT NULL,
        PRIMARY KEY (namespace, relayer_key_id)
      )
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
      CREATE TABLE IF NOT EXISTS account_signers (
        namespace TEXT NOT NULL,
        user_id TEXT NOT NULL,
        chain_id_key TEXT NOT NULL,
        account_address TEXT NOT NULL,
        signer_id TEXT NOT NULL,
        record_json JSONB NOT NULL,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, user_id, chain_id_key, account_address, signer_id)
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS account_signers_user_idx
      ON account_signers (namespace, user_id, chain_id_key, account_address)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS account_signers_account_idx
      ON account_signers (namespace, chain_id_key, account_address, signer_id)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS smart_account_recovery_subjects (
        namespace TEXT NOT NULL,
        user_id TEXT NOT NULL,
        near_account_id TEXT NOT NULL,
        chain_id_key TEXT NOT NULL,
        account_address TEXT NOT NULL,
        record_json JSONB NOT NULL,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, chain_id_key, account_address)
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS smart_account_recovery_subjects_near_idx
      ON smart_account_recovery_subjects (namespace, near_account_id, chain_id_key, account_address)
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

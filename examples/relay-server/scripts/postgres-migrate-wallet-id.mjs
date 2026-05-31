#!/usr/bin/env node
import dotenv from 'dotenv';
import pg from 'pg';

dotenv.config({ path: '.env' });

const postgresUrl = String(
  process.env.POSTGRES_MIGRATION_URL || process.env.POSTGRES_URL || '',
).trim();

if (!postgresUrl) {
  throw new Error(
    'Missing signer Postgres URL. Set POSTGRES_MIGRATION_URL (preferred) or POSTGRES_URL.',
  );
}

const MIGRATION_LOCK_ID = 9452360123582;

const pool = new pg.Pool({ connectionString: postgresUrl });

async function queryOne(client, text, values = []) {
  const result = await client.query(text, values);
  return result.rows[0] || null;
}

async function tableExists(client, tableName) {
  const row = await queryOne(
    client,
    `
      SELECT to_regclass($1) AS table_name
    `,
    [`public.${tableName}`],
  );
  return Boolean(row?.table_name);
}

async function columnExists(client, tableName, columnName) {
  const row = await queryOne(
    client,
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

async function createCanonicalTables(client) {
  await client.query(`
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
  await client.query(`
    CREATE INDEX IF NOT EXISTS wallets_rp_idx
    ON wallets (namespace, rp_id, created_at_ms)
  `);

  await client.query(`
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
  await client.query(`
    CREATE INDEX IF NOT EXISTS wallet_auth_methods_wallet_idx
    ON wallet_auth_methods (namespace, wallet_id, rp_id, status)
  `);
  await client.query(`
    DROP INDEX IF EXISTS wallet_auth_methods_identifier_uidx
  `);
  await client.query(`
    CREATE INDEX IF NOT EXISTS wallet_auth_methods_identifier_idx
    ON wallet_auth_methods (namespace, kind, rp_id, auth_identifier_key)
  `);
  await client.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS wallet_auth_methods_passkey_uidx
    ON wallet_auth_methods (namespace, rp_id, credential_id_b64u)
    WHERE kind = 'passkey' AND credential_id_b64u IS NOT NULL
  `);
  await client.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS wallet_auth_methods_email_uidx
    ON wallet_auth_methods (namespace, wallet_id, rp_id, email_hash_hex)
    WHERE kind = 'email_otp' AND email_hash_hex IS NOT NULL
  `);

  await client.query(`
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
  await client.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS wallet_signers_chain_target_uidx
    ON wallet_signers (namespace, wallet_id, signer_family, chain_target_key)
    WHERE chain_target_key IS NOT NULL
  `);
}

async function migrateWalletSubjects(client) {
  if (!(await tableExists(client, 'wallet_subjects'))) return 0;
  const result = await client.query(`
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
  return result.rowCount || 0;
}

async function migrateWalletAuthMethodBindings(client) {
  if (!(await tableExists(client, 'wallet_auth_method_bindings'))) return 0;
  const result = await client.query(`
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
  return result.rowCount || 0;
}

async function migrateWalletAuthenticators(client) {
  if (!(await tableExists(client, 'wallet_authenticators'))) return 0;
  const result = await client.query(`
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
      credential_public_key_b64u,
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
        'credentialPublicKeyB64u', credential_public_key_b64u,
        'counter', counter,
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
  return result.rowCount || 0;
}

async function migrateWalletSigners(client) {
  if (!(await tableExists(client, 'wallet_signers'))) return 0;
  if (!(await columnExists(client, 'wallet_signers', 'wallet_subject_id'))) return 0;
  await client.query('ALTER TABLE wallet_signers RENAME COLUMN wallet_subject_id TO wallet_id');
  const result = await client.query(`
    UPDATE wallet_signers
    SET record_json = jsonb_set(record_json - 'walletSubjectId', '{walletId}', to_jsonb(wallet_id))
    WHERE record_json ? 'walletSubjectId'
  `);
  return result.rowCount || 0;
}

async function dropLegacyTables(client) {
  await client.query('DROP TABLE IF EXISTS wallet_authenticators');
  await client.query('DROP TABLE IF EXISTS wallet_auth_method_bindings');
  await client.query('DROP TABLE IF EXISTS wallet_subjects');
  await client.query('DROP TABLE IF EXISTS account_signers');
  await client.query('DROP TABLE IF EXISTS smart_account_recovery_subjects');
}

const client = await pool.connect();
try {
  await client.query('BEGIN');
  await client.query('SELECT pg_advisory_xact_lock($1)', [MIGRATION_LOCK_ID]);
  await createCanonicalTables(client);
  const wallets = await migrateWalletSubjects(client);
  const bindings = await migrateWalletAuthMethodBindings(client);
  const authenticators = await migrateWalletAuthenticators(client);
  const signers = await migrateWalletSigners(client);
  await dropLegacyTables(client);
  await client.query('COMMIT');
  console.log('[postgres-migrate-wallet-id] migration complete', {
    wallets,
    authMethodBindings: bindings,
    authenticators,
    signers,
  });
} catch (error) {
  await client.query('ROLLBACK').catch(() => undefined);
  throw error;
} finally {
  client.release();
  await pool.end();
}

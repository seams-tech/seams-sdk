#!/usr/bin/env node
import dotenv from 'dotenv';
import { Pool } from 'pg';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const relayRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function parseArgs(argv) {
  const out = {
    execute: false,
    allowNonLocal: false,
    envFile: path.join(relayRoot, '.env'),
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--execute') {
      out.execute = true;
      continue;
    }
    if (arg === '--allow-non-local') {
      out.allowNonLocal = true;
      continue;
    }
    if (arg === '--env-file') {
      const next = argv[i + 1];
      if (!next) throw new Error('--env-file requires a path');
      out.envFile = path.resolve(next);
      i += 1;
      continue;
    }
    throw new Error(`Unknown argument: ${arg}`);
  }
  return out;
}

const TARGET_TABLES = [
  'threshold_signing_session_seal_idempotency',
  'threshold_ecdsa_presignatures',
  'threshold_ecdsa_presign_sessions',
  'threshold_ecdsa_signing_sessions',
  'threshold_ecdsa_keys',
  'signing_root_secret_shares',
  'wallet_signers',
  'wallet_authenticators',
  'wallet_subjects',
  'wallet_registration_ceremonies',
  'wallet_registration_intents',
  'webauthn_authenticators',
  'webauthn_credential_bindings',
  'webauthn_challenges',
  'email_otp_registration_attempts',
  'email_otp_unlock_challenges',
  'email_otp_auth_states',
  'email_otp_recovery_wrapped_enrollment_escrows',
  'email_otp_wallet_enrollments',
  'email_otp_grants',
  'email_otp_challenges',
  'identity_links',
  'near_public_keys',
  'app_session_versions',
];

function quoteIdentifier(identifier) {
  if (!/^[a-z_][a-z0-9_]*$/u.test(identifier)) {
    throw new Error(`Unsafe SQL identifier: ${identifier}`);
  }
  return `"${identifier}"`;
}

function isLocalPostgresUrl(rawUrl) {
  try {
    const url = new URL(rawUrl);
    const host = url.hostname.toLowerCase();
    return host === 'localhost' || host === '127.0.0.1' || host === '::1';
  } catch {
    return false;
  }
}

async function tableExists(client, tableName) {
  const result = await client.query('SELECT to_regclass($1) AS table_name', [tableName]);
  return Boolean(result.rows[0]?.table_name);
}

async function countRows(client, tableName) {
  const result = await client.query(
    `SELECT count(*)::int AS count FROM ${quoteIdentifier(tableName)}`,
  );
  return Number(result.rows[0]?.count || 0);
}

function formatCounts(counts) {
  const width = Math.max(...counts.map((entry) => entry.table.length), 5);
  return counts
    .map((entry) => `${entry.table.padEnd(width)}  ${String(entry.count).padStart(6)}`)
    .join('\n');
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  dotenv.config({ path: args.envFile });

  const postgresUrl = String(
    process.env.POSTGRES_MIGRATION_URL || process.env.POSTGRES_URL || '',
  ).trim();
  if (!postgresUrl) {
    throw new Error(`Missing POSTGRES_MIGRATION_URL or POSTGRES_URL (loaded ${args.envFile})`);
  }
  if (args.execute && !args.allowNonLocal && !isLocalPostgresUrl(postgresUrl)) {
    throw new Error('Refusing to wipe a non-local Postgres URL without --allow-non-local');
  }

  const pool = new Pool({ connectionString: postgresUrl });
  const client = await pool.connect();
  try {
    const existingTables = [];
    for (const table of TARGET_TABLES) {
      if (await tableExists(client, table)) existingTables.push(table);
    }
    if (existingTables.length === 0) {
      console.log('[postgres-wipe-legacy-accounts] no target tables exist');
      return;
    }

    const before = [];
    for (const table of existingTables) {
      before.push({ table, count: await countRows(client, table) });
    }
    console.log('[postgres-wipe-legacy-accounts] rows before wipe:');
    console.log(formatCounts(before));

    if (!args.execute) {
      console.log('[postgres-wipe-legacy-accounts] dry run only; pass --execute to wipe');
      return;
    }

    await client.query('BEGIN');
    try {
      await client.query(`TRUNCATE TABLE ${existingTables.map(quoteIdentifier).join(', ')}`);
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    }

    const after = [];
    for (const table of existingTables) {
      after.push({ table, count: await countRows(client, table) });
    }
    console.log('[postgres-wipe-legacy-accounts] rows after wipe:');
    console.log(formatCounts(after));
  } finally {
    client.release();
    await pool.end();
  }
}

main().catch((error) => {
  console.error('[postgres-wipe-legacy-accounts] fatal:', error);
  process.exit(1);
});

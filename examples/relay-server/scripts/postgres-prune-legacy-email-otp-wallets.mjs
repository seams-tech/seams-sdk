#!/usr/bin/env node
import dotenv from 'dotenv';
import { Pool } from 'pg';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const relayRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const DELETE_TABLES = [
  'email_otp_registration_attempts',
  'email_otp_challenges',
  'email_otp_unlock_challenges',
  'email_otp_grants',
  'email_otp_auth_states',
  'email_otp_recovery_wrapped_enrollment_escrows',
  'email_otp_wallet_enrollments',
  'threshold_ed25519_auth_consumptions',
  'threshold_ed25519_sessions',
  'threshold_ecdsa_presignatures',
  'threshold_ecdsa_presign_sessions',
  'threshold_ecdsa_signing_sessions',
  'threshold_ecdsa_keys',
  'signing_root_secret_shares',
  'near_public_keys',
  'wallet_signers',
  'wallet_registration_ceremonies',
  'wallet_registration_intents',
  'recovery_executions',
  'recovery_sessions',
  'email_recovery_preparations',
  'wallet_auth_methods',
  'wallets',
];

function parseArgs(argv) {
  const out = {
    execute: false,
    allowNonLocal: false,
    envFile: path.join(relayRoot, '.env'),
    walletIds: [],
    createdAfterMs: null,
    createdBeforeMs: null,
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
    if (arg === '--wallet-id') {
      const next = argv[i + 1];
      if (!next) throw new Error('--wallet-id requires a value');
      out.walletIds.push(
        ...next
          .split(',')
          .map((value) => value.trim())
          .filter(Boolean),
      );
      i += 1;
      continue;
    }
    if (arg === '--created-after-ms') {
      const next = Number(argv[i + 1]);
      if (!Number.isSafeInteger(next) || next < 0) {
        throw new Error('--created-after-ms requires a non-negative integer');
      }
      out.createdAfterMs = next;
      i += 1;
      continue;
    }
    if (arg === '--created-before-ms') {
      const next = Number(argv[i + 1]);
      if (!Number.isSafeInteger(next) || next < 0) {
        throw new Error('--created-before-ms requires a non-negative integer');
      }
      out.createdBeforeMs = next;
      i += 1;
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
  out.walletIds = [...new Set(out.walletIds)];
  if (out.walletIds.length === 0 && out.createdAfterMs == null && out.createdBeforeMs == null) {
    throw new Error(
      'Provide --wallet-id or a created-at window with --created-after-ms/--created-before-ms',
    );
  }
  return out;
}

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

async function queryOne(client, text, values = []) {
  const result = await client.query(text, values);
  return result.rows[0] || null;
}

async function tableExists(client, tableName) {
  const row = await queryOne(client, 'SELECT to_regclass($1) AS table_name', [
    `public.${tableName}`,
  ]);
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

async function tableShape(client, tableName) {
  if (!(await tableExists(client, tableName))) return null;
  return {
    tableName,
    walletId: await columnExists(client, tableName, 'wallet_id'),
    providerUserId: await columnExists(client, tableName, 'provider_user_id'),
    authSubjectId: await columnExists(client, tableName, 'auth_subject_id'),
    recordJson: await columnExists(client, tableName, 'record_json'),
    createdAtMs: await columnExists(client, tableName, 'created_at_ms'),
  };
}

function deletePredicatesForShape(shape, parameterOffset) {
  const predicates = [];
  const walletParam = `$${parameterOffset}`;
  const subjectParam = `$${parameterOffset + 1}`;
  if (shape.walletId) predicates.push(`wallet_id = ${walletParam}`);
  if (shape.recordJson) {
    predicates.push(`record_json->>'walletId' = ${walletParam}`);
    predicates.push(`record_json->>'wallet_id' = ${walletParam}`);
  }
  if (shape.providerUserId) predicates.push(`provider_user_id = ANY(${subjectParam}::text[])`);
  if (shape.authSubjectId) predicates.push(`auth_subject_id = ANY(${subjectParam}::text[])`);
  if (shape.recordJson) {
    predicates.push(`record_json->>'providerSubject' = ANY(${subjectParam}::text[])`);
    predicates.push(`record_json->>'challengeSubjectId' = ANY(${subjectParam}::text[])`);
    predicates.push(`record_json->>'providerUserId' = ANY(${subjectParam}::text[])`);
    predicates.push(`record_json->>'authSubjectId' = ANY(${subjectParam}::text[])`);
  }
  return predicates;
}

async function findCandidateWallets(client, args) {
  if (!(await tableExists(client, 'wallet_auth_methods'))) return [];
  const values = [];
  const predicates = ["kind = 'email_otp'"];
  if (args.walletIds.length > 0) {
    values.push(args.walletIds);
    predicates.push(`wallet_id = ANY($${values.length})`);
  }
  if (args.createdAfterMs != null) {
    values.push(args.createdAfterMs);
    predicates.push(`created_at_ms >= $${values.length}`);
  }
  if (args.createdBeforeMs != null) {
    values.push(args.createdBeforeMs);
    predicates.push(`created_at_ms <= $${values.length}`);
  }
  const result = await client.query(
    `
      SELECT DISTINCT
        wallet_id,
        min(created_at_ms)::bigint AS first_auth_method_created_at_ms,
        count(*)::int AS email_otp_auth_method_count
      FROM wallet_auth_methods
      WHERE ${predicates.join(' AND ')}
      GROUP BY wallet_id
      ORDER BY wallet_id
    `,
    values,
  );
  return result.rows.map((row) => ({
    walletId: String(row.wallet_id),
    firstAuthMethodCreatedAtMs: Number(row.first_auth_method_created_at_ms || 0),
    emailOtpAuthMethodCount: Number(row.email_otp_auth_method_count || 0),
  }));
}

async function readWalletSubjects(client, walletId) {
  const subjects = new Set();
  for (const table of ['wallet_auth_methods', 'email_otp_wallet_enrollments']) {
    const shape = await tableShape(client, table);
    if (!shape) continue;
    const selectParts = [];
    if (shape.providerUserId) selectParts.push('provider_user_id');
    if (shape.authSubjectId) selectParts.push('auth_subject_id');
    if (shape.recordJson) {
      selectParts.push("record_json->>'providerSubject' AS record_provider_subject");
      selectParts.push("record_json->>'challengeSubjectId' AS record_challenge_subject_id");
      selectParts.push("record_json->>'providerUserId' AS record_provider_user_id");
      selectParts.push("record_json->>'authSubjectId' AS record_auth_subject_id");
    }
    if (selectParts.length === 0) continue;
    const walletPredicate = shape.walletId
      ? 'wallet_id = $1'
      : shape.recordJson
        ? "record_json->>'walletId' = $1"
        : '';
    if (!walletPredicate) continue;
    const result = await client.query(
      `
        SELECT ${selectParts.join(', ')}
        FROM ${quoteIdentifier(table)}
        WHERE ${walletPredicate}
      `,
      [walletId],
    );
    for (const row of result.rows) {
      for (const value of Object.values(row)) {
        const subject = String(value || '').trim();
        if (subject) subjects.add(subject);
      }
    }
  }
  return [...subjects];
}

async function countRowsForWallet(client, tableName, walletId, providerSubjects) {
  const shape = await tableShape(client, tableName);
  if (!shape) return null;
  const predicates = deletePredicatesForShape(shape, 1);
  if (predicates.length === 0) return { table: tableName, count: 0 };
  const result = await client.query(
    `
      SELECT count(*)::int AS count
      FROM ${quoteIdentifier(tableName)}
      WHERE ${predicates.join(' OR ')}
    `,
    [walletId, providerSubjects],
  );
  return { table: tableName, count: Number(result.rows[0]?.count || 0) };
}

async function readBrokenInvariants(client, walletId) {
  const broken = [];
  if (await tableExists(client, 'wallets')) {
    const wallet = await queryOne(client, 'SELECT 1 FROM wallets WHERE wallet_id = $1 LIMIT 1', [
      walletId,
    ]);
    if (!wallet) broken.push('wallet_missing');
  }
  if (await tableExists(client, 'wallet_auth_methods')) {
    const authMethods = await queryOne(
      client,
      `
        SELECT count(*)::int AS count
        FROM wallet_auth_methods
        WHERE wallet_id = $1 AND kind = 'email_otp' AND status = 'active'
      `,
      [walletId],
    );
    if (Number(authMethods?.count || 0) <= 0) broken.push('active_email_otp_auth_method_missing');
  }
  if (await tableExists(client, 'wallet_signers')) {
    const signers = await queryOne(
      client,
      `
        SELECT count(*)::int AS count
        FROM wallet_signers
        WHERE wallet_id = $1
      `,
      [walletId],
    );
    if (Number(signers?.count || 0) <= 0) broken.push('signer_missing');
  }
  return broken;
}

async function hasPasskeyAuthMethod(client, walletId) {
  if (!(await tableExists(client, 'wallet_auth_methods'))) return false;
  const row = await queryOne(
    client,
    `
      SELECT 1
      FROM wallet_auth_methods
      WHERE wallet_id = $1 AND kind = 'passkey'
      LIMIT 1
    `,
    [walletId],
  );
  return Boolean(row);
}

async function deleteRowsForWallet(client, tableName, walletId, providerSubjects) {
  const shape = await tableShape(client, tableName);
  if (!shape) return { table: tableName, deleted: 0 };
  const predicates = deletePredicatesForShape(shape, 1);
  if (predicates.length === 0) return { table: tableName, deleted: 0 };
  const result = await client.query(
    `
      DELETE FROM ${quoteIdentifier(tableName)}
      WHERE ${predicates.join(' OR ')}
    `,
    [walletId, providerSubjects],
  );
  return { table: tableName, deleted: result.rowCount || 0 };
}

async function assertWalletRowsDeleted(client, walletId, providerSubjects) {
  const remaining = [];
  for (const table of DELETE_TABLES) {
    const count = await countRowsForWallet(client, table, walletId, providerSubjects);
    if (count && count.count > 0) remaining.push(count);
  }
  if (remaining.length === 0) return;
  const details = remaining.map((item) => `${item.table}:${item.count}`).join(', ');
  throw new Error(`Post-delete verification failed for ${walletId}; remaining rows: ${details}`);
}

function printWalletReport(report) {
  console.log(`\n[postgres-prune-legacy-email-otp-wallets] wallet ${report.walletId}`);
  console.log(`  providerSubjects: ${report.providerSubjects.join(', ') || '(none)'}`);
  console.log(`  hasPasskeyAuthMethod: ${report.hasPasskeyAuthMethod ? 'yes' : 'no'}`);
  console.log(`  brokenInvariants: ${report.brokenInvariants.join(', ') || '(none)'}`);
  for (const count of report.counts) {
    if (count.count > 0) console.log(`  ${count.table}: ${count.count}`);
  }
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
    throw new Error('Refusing to prune a non-local Postgres URL without --allow-non-local');
  }

  const pool = new Pool({ connectionString: postgresUrl });
  const client = await pool.connect();
  try {
    const candidates = await findCandidateWallets(client, args);
    if (candidates.length === 0) {
      console.log('[postgres-prune-legacy-email-otp-wallets] no candidate wallets');
      return;
    }
    const reports = [];
    for (const candidate of candidates) {
      const providerSubjects = await readWalletSubjects(client, candidate.walletId);
      const counts = [];
      for (const table of DELETE_TABLES) {
        const count = await countRowsForWallet(client, table, candidate.walletId, providerSubjects);
        if (count) counts.push(count);
      }
      const report = {
        ...candidate,
        providerSubjects,
        counts,
        brokenInvariants: await readBrokenInvariants(client, candidate.walletId),
        hasPasskeyAuthMethod: await hasPasskeyAuthMethod(client, candidate.walletId),
      };
      reports.push(report);
      printWalletReport(report);
    }

    if (!args.execute) {
      console.log('\n[postgres-prune-legacy-email-otp-wallets] dry run only; pass --execute to delete');
      return;
    }

    for (const report of reports) {
      const explicitlyAllowed = args.walletIds.includes(report.walletId);
      if (report.hasPasskeyAuthMethod && !explicitlyAllowed) {
        throw new Error(
          `Refusing to delete ${report.walletId}: wallet has a passkey auth method and was not explicitly allowlisted`,
        );
      }
      await client.query('BEGIN');
      try {
        const deleted = [];
        for (const table of DELETE_TABLES) {
          deleted.push(
            await deleteRowsForWallet(client, table, report.walletId, report.providerSubjects),
          );
        }
        await client.query('COMMIT');
        await assertWalletRowsDeleted(client, report.walletId, report.providerSubjects);
        console.log(`\n[postgres-prune-legacy-email-otp-wallets] deleted ${report.walletId}`);
        for (const item of deleted) {
          if (item.deleted > 0) console.log(`  ${item.table}: ${item.deleted}`);
        }
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      }
    }
  } finally {
    client.release();
    await pool.end();
  }
}

main().catch((error) => {
  console.error('[postgres-prune-legacy-email-otp-wallets] fatal:', error);
  process.exit(1);
});

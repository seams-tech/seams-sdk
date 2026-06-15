#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

function readEnv(name, fallback = '') {
  const value = process.env[name];
  if (typeof value !== 'string') return fallback;
  const trimmed = value.trim();
  return trimmed || fallback;
}

function readRequiredEnv(name) {
  const value = readEnv(name);
  if (!value) {
    throw new Error(`Missing required environment variable ${name}`);
  }
  return value;
}

function readDomainIdentityConfig(prefix) {
  return {
    dbName: readRequiredEnv(`${prefix}_DB_NAME`),
    runtimeUser: readRequiredEnv(`${prefix}_RUNTIME_USER`),
    migratorUser: readRequiredEnv(`${prefix}_MIGRATOR_USER`),
  };
}

function sqlIdent(value) {
  const normalized = String(value || '').trim();
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(normalized)) {
    throw new Error(
      `Invalid SQL identifier "${normalized}". Use letters/numbers/underscore and start with a letter/underscore.`,
    );
  }
  return `"${normalized}"`;
}

function run(cmd, args, { cwd, capture = false } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, {
      cwd,
      stdio: capture ? ['ignore', 'pipe', 'pipe'] : 'inherit',
    });
    let stdout = '';
    let stderr = '';
    if (capture) {
      child.stdout.on('data', (chunk) => {
        stdout += String(chunk || '');
      });
      child.stderr.on('data', (chunk) => {
        stderr += String(chunk || '');
      });
    }
    child.on('error', reject);
    child.on('exit', (code) => {
      if (code === 0) {
        resolve({ stdout, stderr });
      } else {
        reject(
          new Error(
            `${cmd} ${args.join(' ')} exited with code ${code ?? 'unknown'}${
              capture && stderr ? `\n${stderr}` : ''
            }`,
          ),
        );
      }
    });
  });
}

async function dockerCompose(relayCwd, args, options = {}) {
  return await run('docker', ['compose', '-f', 'docker-compose.postgres.yml', ...args], {
    cwd: relayCwd,
    ...options,
  });
}

async function runPsql(relayCwd, input) {
  const { adminUser, database, sql, capture = false } = input;
  return await dockerCompose(
    relayCwd,
    [
      'exec',
      '-T',
      'postgres',
      'psql',
      '-X',
      '-A',
      '-t',
      '-v',
      'ON_ERROR_STOP=1',
      '-U',
      adminUser,
      '-d',
      database,
      '-c',
      sql,
    ],
    { capture },
  );
}

async function assertRuntimeCannotCreateTable(relayCwd, input) {
  const { adminUser, dbName, runtimeUser, tableName } = input;
  const sql = `
SET ROLE ${sqlIdent(runtimeUser)};
CREATE TABLE public.${sqlIdent(tableName)} (id integer);
RESET ROLE;
`;
  try {
    await runPsql(relayCwd, { adminUser, database: dbName, sql, capture: true });
  } catch (error) {
    const message = String(error?.message || '');
    if (
      message.includes('permission denied') ||
      message.includes('must be owner of schema') ||
      message.includes('not have privileges')
    ) {
      return;
    }
    throw new Error(
      `[postgres-verify-split] runtime role ${runtimeUser} failed CREATE TABLE with unexpected error: ${message}`,
    );
  }
  throw new Error(
    `[postgres-verify-split] runtime role ${runtimeUser} unexpectedly created table public.${tableName}`,
  );
}

async function assertMigratorCanCreateAndDropTable(relayCwd, input) {
  const { adminUser, dbName, migratorUser, tableName } = input;
  const sql = `
SET ROLE ${sqlIdent(migratorUser)};
CREATE TABLE public.${sqlIdent(tableName)} (id integer);
DROP TABLE public.${sqlIdent(tableName)};
RESET ROLE;
`;
  await runPsql(relayCwd, { adminUser, database: dbName, sql, capture: true });
}

async function assertRuntimeCanSelectTable(relayCwd, input) {
  const { adminUser, dbName, runtimeUser, tableName } = input;
  const sql = `
SET ROLE ${sqlIdent(runtimeUser)};
SELECT COUNT(*)::text FROM public.${sqlIdent(tableName)};
RESET ROLE;
`;
  await runPsql(relayCwd, { adminUser, database: dbName, sql, capture: true });
}

async function verifyDomain(relayCwd, input) {
  const { adminUser, domain, dbName, runtimeUser, migratorUser, requiredTables } = input;
  const suffix = `${Date.now()}`.slice(-6);
  const runtimeTable = `verify_runtime_${domain}_${suffix}`;
  const migratorTable = `verify_migrator_${domain}_${suffix}`;

  await assertRuntimeCannotCreateTable(relayCwd, {
    adminUser,
    dbName,
    runtimeUser,
    tableName: runtimeTable,
  });
  await assertMigratorCanCreateAndDropTable(relayCwd, {
    adminUser,
    dbName,
    migratorUser,
    tableName: migratorTable,
  });

  for (const tableName of requiredTables) {
    await assertRuntimeCanSelectTable(relayCwd, {
      adminUser,
      dbName,
      runtimeUser,
      tableName,
    });
  }
}

async function main() {
  const relayScriptsDir = path.dirname(fileURLToPath(import.meta.url));
  const relayCwd = path.resolve(relayScriptsDir, '..');

  const adminUser = readEnv('POSTGRES_BOOTSTRAP_ADMIN_USER', 'seams');

  const signer = readDomainIdentityConfig('SIGNER');
  const consoleDomain = readDomainIdentityConfig('CONSOLE');

  // Validate all role identifiers before issuing any external commands so
  // misconfiguration fails fast and deterministically.
  sqlIdent(signer.runtimeUser);
  sqlIdent(signer.migratorUser);
  sqlIdent(consoleDomain.runtimeUser);
  sqlIdent(consoleDomain.migratorUser);

  await verifyDomain(relayCwd, {
    adminUser,
    domain: 'signer',
    dbName: signer.dbName,
    runtimeUser: signer.runtimeUser,
    migratorUser: signer.migratorUser,
    requiredTables: ['threshold_ed25519_keys', 'webauthn_authenticators'],
  });

  await verifyDomain(relayCwd, {
    adminUser,
    domain: 'console',
    dbName: consoleDomain.dbName,
    runtimeUser: consoleDomain.runtimeUser,
    migratorUser: consoleDomain.migratorUser,
    requiredTables: ['console_billing_accounts', 'console_webhook_endpoints'],
  });

  console.log('[postgres-verify-split] success');
  console.log(
    '[postgres-verify-split] runtime roles cannot run DDL, migrator roles can run DDL, and runtime roles can query required migrated tables.',
  );
}

main().catch((err) => {
  console.error('[postgres-verify-split] fatal:', err);
  process.exit(1);
});

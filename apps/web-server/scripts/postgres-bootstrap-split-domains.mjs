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

function readDomainConfig(prefix) {
  return {
    dbName: readRequiredEnv(`${prefix}_DB_NAME`),
    runtimeUser: readRequiredEnv(`${prefix}_RUNTIME_USER`),
    runtimePassword: readRequiredEnv(`${prefix}_RUNTIME_PASSWORD`),
    migratorUser: readRequiredEnv(`${prefix}_MIGRATOR_USER`),
    migratorPassword: readRequiredEnv(`${prefix}_MIGRATOR_PASSWORD`),
  };
}

function sqlLiteral(value) {
  return `'${String(value).replace(/'/g, "''")}'`;
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

async function waitForPsql(relayCwd, adminUser, database) {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    try {
      await runPsql(relayCwd, {
        adminUser,
        database,
        sql: 'SELECT 1;',
      });
      return;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 300));
    }
  }
  throw new Error('Timed out waiting for Postgres to accept psql commands');
}

async function databaseExists(relayCwd, adminUser, dbName) {
  const res = await runPsql(relayCwd, {
    adminUser,
    database: 'postgres',
    sql: `SELECT 1 FROM pg_database WHERE datname = ${sqlLiteral(dbName)};`,
    capture: true,
  });
  return String(res.stdout || '')
    .trim()
    .split('\n')
    .some((line) => line.trim() === '1');
}

async function ensureRole(relayCwd, adminUser, roleName, password) {
  const role = sqlIdent(roleName);
  const sql = `
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = ${sqlLiteral(roleName)}) THEN
    CREATE ROLE ${role} LOGIN PASSWORD ${sqlLiteral(password)};
  ELSE
    ALTER ROLE ${role} LOGIN PASSWORD ${sqlLiteral(password)};
  END IF;
END
$$;`;
  await runPsql(relayCwd, {
    adminUser,
    database: 'postgres',
    sql,
  });
}

async function ensureDatabase(relayCwd, adminUser, dbName, ownerRole) {
  const exists = await databaseExists(relayCwd, adminUser, dbName);
  if (!exists) {
    await runPsql(relayCwd, {
      adminUser,
      database: 'postgres',
      sql: `CREATE DATABASE ${sqlIdent(dbName)} OWNER ${sqlIdent(ownerRole)};`,
    });
  } else {
    await runPsql(relayCwd, {
      adminUser,
      database: 'postgres',
      sql: `ALTER DATABASE ${sqlIdent(dbName)} OWNER TO ${sqlIdent(ownerRole)};`,
    });
  }
}

async function applyDomainGrants(relayCwd, adminUser, input) {
  const { dbName, runtimeUser, migratorUser } = input;
  const dbIdent = sqlIdent(dbName);
  const runtime = sqlIdent(runtimeUser);
  const migrator = sqlIdent(migratorUser);

  await runPsql(relayCwd, {
    adminUser,
    database: 'postgres',
    sql: `
REVOKE ALL ON DATABASE ${dbIdent} FROM PUBLIC;
GRANT CONNECT, TEMP ON DATABASE ${dbIdent} TO ${runtime};
GRANT CONNECT, CREATE, TEMP ON DATABASE ${dbIdent} TO ${migrator};`,
  });

  await runPsql(relayCwd, {
    adminUser,
    database: dbName,
    sql: `
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO ${runtime};
GRANT USAGE, CREATE ON SCHEMA public TO ${migrator};

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ${runtime};
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO ${runtime};
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO ${runtime};

GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO ${migrator};
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO ${migrator};
GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO ${migrator};

ALTER DEFAULT PRIVILEGES FOR USER ${migrator} IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ${runtime};
ALTER DEFAULT PRIVILEGES FOR USER ${migrator} IN SCHEMA public
  GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO ${runtime};
ALTER DEFAULT PRIVILEGES FOR USER ${migrator} IN SCHEMA public
  GRANT EXECUTE ON FUNCTIONS TO ${runtime};`,
  });
}

function toPgUrl(input) {
  const user = encodeURIComponent(input.user);
  const password = encodeURIComponent(input.password);
  const host = input.host || '127.0.0.1';
  const port = String(input.port || 5432);
  return `postgresql://${user}:${password}@${host}:${port}/${input.db}`;
}

async function main() {
  const relayScriptsDir = path.dirname(fileURLToPath(import.meta.url));
  const relayCwd = path.resolve(relayScriptsDir, '..');

  const adminUser = readEnv('POSTGRES_BOOTSTRAP_ADMIN_USER', 'seams');
  const host = readEnv('POSTGRES_BOOTSTRAP_HOST', '127.0.0.1');
  const port = Number(readEnv('POSTGRES_BOOTSTRAP_PORT', '5432')) || 5432;

  const signer = readDomainConfig('SIGNER');
  const consoleDomain = readDomainConfig('CONSOLE');

  await dockerCompose(relayCwd, ['up', '-d', 'postgres']);
  await waitForPsql(relayCwd, adminUser, 'postgres');

  await ensureRole(relayCwd, adminUser, signer.runtimeUser, signer.runtimePassword);
  await ensureRole(relayCwd, adminUser, signer.migratorUser, signer.migratorPassword);
  await ensureRole(
    relayCwd,
    adminUser,
    consoleDomain.runtimeUser,
    consoleDomain.runtimePassword,
  );
  await ensureRole(
    relayCwd,
    adminUser,
    consoleDomain.migratorUser,
    consoleDomain.migratorPassword,
  );

  await ensureDatabase(relayCwd, adminUser, signer.dbName, signer.migratorUser);
  await ensureDatabase(relayCwd, adminUser, consoleDomain.dbName, consoleDomain.migratorUser);

  await applyDomainGrants(relayCwd, adminUser, signer);
  await applyDomainGrants(relayCwd, adminUser, consoleDomain);

  const signerRuntimeUrl = toPgUrl({
    user: signer.runtimeUser,
    password: signer.runtimePassword,
    host,
    port,
    db: signer.dbName,
  });
  const signerMigratorUrl = toPgUrl({
    user: signer.migratorUser,
    password: signer.migratorPassword,
    host,
    port,
    db: signer.dbName,
  });
  const consoleRuntimeUrl = toPgUrl({
    user: consoleDomain.runtimeUser,
    password: consoleDomain.runtimePassword,
    host,
    port,
    db: consoleDomain.dbName,
  });
  const consoleMigratorUrl = toPgUrl({
    user: consoleDomain.migratorUser,
    password: consoleDomain.migratorPassword,
    host,
    port,
    db: consoleDomain.dbName,
  });

  console.log('[postgres-bootstrap-split] complete');
  console.log('[postgres-bootstrap-split] Suggested .env values:');
  console.log(`POSTGRES_URL=${signerRuntimeUrl}`);
  console.log(`POSTGRES_MIGRATION_URL=${signerMigratorUrl}`);
  console.log(`CONSOLE_POSTGRES_URL=${consoleRuntimeUrl}`);
  console.log(`CONSOLE_POSTGRES_MIGRATION_URL=${consoleMigratorUrl}`);
}

main().catch((err) => {
  console.error('[postgres-bootstrap-split] fatal:', err);
  process.exit(1);
});

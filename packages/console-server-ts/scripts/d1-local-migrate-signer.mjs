#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const phase1BridgeMigrationName = '0028_r103f_phase1_additive_schema_bridge.sql';
const workerdIncompatibleChecks = Object.freeze([
  Object.freeze({
    source:
      "schema.sql NOT LIKE '%PRIMARY KEY (namespace, org_id, project_id, env_id, link_session_id)%'",
    replacement:
      "instr(upper(schema.sql), 'PRIMARY KEY (NAMESPACE, ORG_ID, PROJECT_ID, ENV_ID, LINK_SESSION_ID)') = 0",
  }),
  Object.freeze({
    source: "schema.sql NOT LIKE '%UNIQUE (namespace, org_id, project_id, env_id, authority_id)%'",
    replacement:
      "instr(upper(schema.sql), 'UNIQUE (NAMESPACE, ORG_ID, PROJECT_ID, ENV_ID, AUTHORITY_ID)') = 0",
  }),
  Object.freeze({
    source: "schema.sql NOT LIKE '%CHECK (created_at_ms >= 0)%'",
    replacement: "instr(upper(schema.sql), 'CHECK (CREATED_AT_MS >= 0)') = 0",
  }),
]);

export function buildWorkerdCompatiblePhase1Bridge(source) {
  let result = source;
  for (const check of workerdIncompatibleChecks) {
    const first = result.indexOf(check.source);
    if (first === -1 || result.indexOf(check.source, first + check.source.length) !== -1) {
      throw new Error(`Expected exactly one local D1 schema guard: ${check.source}`);
    }
    result = result.replace(check.source, check.replacement);
  }
  return result;
}

export function resolveSignerMigrationsDirectory(configSource, configPath) {
  const blocks = configSource.split(/(?=\[\[d1_databases\]\])/u);
  let signerBlock;
  for (const block of blocks) {
    if (/database_name\s*=\s*"seams-signer"/u.test(block)) signerBlock = block;
  }
  if (!signerBlock) throw new Error('Local D1 config has no seams-signer database binding');

  const match = signerBlock.match(/migrations_dir\s*=\s*"([^"]+)"/u);
  if (!match) throw new Error('Local seams-signer binding has no migrations_dir');
  return path.resolve(path.dirname(configPath), match[1]);
}

export function buildSignerCompatibilityConfig(configSource, migrationsDirectory) {
  const blocks = configSource.split(/(?=\[\[d1_databases\]\])/u);
  let replaced = false;
  const result = [];
  for (const block of blocks) {
    if (!/database_name\s*=\s*"seams-signer"/u.test(block)) {
      result.push(block);
      continue;
    }
    if (replaced) throw new Error('Local D1 config has multiple seams-signer bindings');
    replaced = true;
    result.push(
      block.replace(
        /migrations_dir\s*=\s*"[^"]+"/u,
        `migrations_dir = ${JSON.stringify(migrationsDirectory)}`,
      ),
    );
  }
  if (!replaced) throw new Error('Local D1 config has no seams-signer database binding');
  return result.join('');
}

function runLocalSignerMigrations(env = process.env) {
  const configPath = path.resolve(
    packageRoot,
    env.SEAMS_D1_LOCAL_WRANGLER_CONFIG || 'wrangler.d1-local.toml',
  );
  const persistTo = env.SEAMS_D1_LOCAL_PERSIST_TO || '.wrangler/state/seams-d1';
  const configSource = readFileSync(configPath, 'utf8');
  const sourceMigrationsDirectory = resolveSignerMigrationsDirectory(configSource, configPath);
  const temporaryRoot = mkdtempSync(path.join(tmpdir(), 'seams-d1-local-migrations-'));
  const compatibleMigrationsDirectory = path.join(temporaryRoot, 'd1-signer');
  const compatibilityConfigPath = path.join(
    path.dirname(configPath),
    `.wrangler.d1-local.compat-${process.pid}.toml`,
  );

  try {
    cpSync(sourceMigrationsDirectory, compatibleMigrationsDirectory, { recursive: true });
    const bridgePath = path.join(compatibleMigrationsDirectory, phase1BridgeMigrationName);
    writeFileSync(
      bridgePath,
      buildWorkerdCompatiblePhase1Bridge(readFileSync(bridgePath, 'utf8')),
      'utf8',
    );
    writeFileSync(
      compatibilityConfigPath,
      buildSignerCompatibilityConfig(configSource, compatibleMigrationsDirectory),
      { mode: 0o600 },
    );

    const result = spawnSync(
      'wrangler',
      [
        'd1',
        'migrations',
        'apply',
        'seams-signer',
        '--local',
        '--persist-to',
        persistTo,
        '--config',
        compatibilityConfigPath,
      ],
      { cwd: packageRoot, env, stdio: 'inherit' },
    );
    if (result.error) throw result.error;
    if (result.status !== 0) process.exitCode = result.status ?? 1;
  } finally {
    rmSync(compatibilityConfigPath, { force: true });
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runLocalSignerMigrations();
}

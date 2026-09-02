import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

type LocalSignerMigrationModule = {
  readonly buildSignerCompatibilityConfig: (
    configSource: string,
    migrationsDirectory: string,
  ) => string;
  readonly buildWorkerdCompatiblePhase1Bridge: (source: string) => string;
  readonly resolveSignerMigrationsDirectory: (configSource: string, configPath: string) => string;
};

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const modulePath = path.join(
  root,
  'packages/console-server-ts/scripts/d1-local-migrate-signer.mjs',
);
const migrationPath = path.join(
  root,
  'packages/wallet-server/migrations/d1-signer/0028_r103f_phase1_additive_schema_bridge.sql',
);
const configPath = path.join(root, 'packages/console-server-ts/wrangler.d1-local.toml');

test('local signer migrations replace only the workerd-incompatible schema guard', async () => {
  const module = (await import(pathToFileURL(modulePath).href)) as LocalSignerMigrationModule;
  const source = readFileSync(migrationPath, 'utf8');
  const compatible = module.buildWorkerdCompatiblePhase1Bridge(source);

  expect(compatible).not.toContain('schema.sql NOT LIKE');
  expect(compatible).toContain(
    "instr(upper(schema.sql), 'PRIMARY KEY (NAMESPACE, ORG_ID, PROJECT_ID, ENV_ID, LINK_SESSION_ID)') = 0",
  );
  expect(compatible).toContain(
    "instr(upper(schema.sql), 'UNIQUE (NAMESPACE, ORG_ID, PROJECT_ID, ENV_ID, AUTHORITY_ID)') = 0",
  );
  expect(compatible).toContain("instr(upper(schema.sql), 'CHECK (CREATED_AT_MS >= 0)') = 0");
  expect(readFileSync(migrationPath, 'utf8')).toBe(source);
});

test('local signer compatibility config redirects only signer migrations', async () => {
  const module = (await import(pathToFileURL(modulePath).href)) as LocalSignerMigrationModule;
  const source = readFileSync(configPath, 'utf8');
  const signerMigrations = module.resolveSignerMigrationsDirectory(source, configPath);
  const compatible = module.buildSignerCompatibilityConfig(source, '/tmp/local-d1-signer');

  expect(signerMigrations).toBe(
    path.join(
      root,
      'packages/wallet-console-server-ts/node_modules/@seams/wallet-server/migrations/d1-signer',
    ),
  );
  expect(compatible).toContain('migrations_dir = "/tmp/local-d1-signer"');
  expect(compatible).toContain(
    'migrations_dir = "../wallet-console-server-ts/migrations/d1-console"',
  );
});

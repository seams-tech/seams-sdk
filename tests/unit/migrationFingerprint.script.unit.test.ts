import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { expect, test } from '@playwright/test';
import {
  assertAppliedMigrationSourcesUnchanged,
  digestMigrations,
} from '../../scripts/migration-fingerprint.mjs';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
} from '../helpers/sqliteD1';

type MigrationSet = {
  readonly database?: string;
  readonly fingerprint: string;
  readonly migrations: readonly string[];
};

const repoRoot = path.resolve(import.meta.dirname, '../..');
const helperPath = path.join(repoRoot, 'scripts/migration-fingerprint.mjs');
const applierPath = path.join(
  repoRoot,
  'packages/console-server-ts/scripts/apply-remote-d1-migrations.mjs',
);
const signerMigrationRoot = path.join(repoRoot, 'packages/sdk-server-ts/migrations/d1-signer');

test('migration fingerprint output is stable per database and uses sorted framed records', () => {
  const migrationsDir = writeMigrationDirectory();
  try {
    const helperOutput = runJsonCommand(helperPath, [
      '--database',
      'console',
      '--migrations-dir',
      migrationsDir,
      '--format',
      'json',
    ]);
    const expectedHash = createHash('sha256');
    for (const [name, source] of [
      ['0001_first.sql', 'first\n'],
      ['0002_second.sql', 'second\n'],
    ]) {
      expectedHash.update(name);
      expectedHash.update('\0');
      expectedHash.update(source);
      expectedHash.update('\0');
    }

    expect(helperOutput).toEqual({
      database: 'console',
      fingerprint: expectedHash.digest('hex'),
      migrations: ['0001_first.sql', '0002_second.sql'],
    });
  } finally {
    rmSync(migrationsDir, { recursive: true, force: true });
  }
});

test('remote migration applier rejects an unexpected fingerprint before Wrangler execution', () => {
  const migrationsDir = writeMigrationDirectory();
  try {
    const result = spawnSync(
      process.execPath,
      [
        applierPath,
        '--database',
        'CONSOLE_DB',
        '--config',
        path.join(migrationsDir, 'missing-wrangler.toml'),
        '--migrations-dir',
        migrationsDir,
        '--expected-fingerprint',
        'f'.repeat(64),
      ],
      { encoding: 'utf8' },
    );

    expect(result.status).toBe(1);
    expect(result.stderr).toContain('D1 migration fingerprint mismatch');
    expect(result.stderr).not.toContain('Wrangler D1 command failed');
  } finally {
    rmSync(migrationsDir, { recursive: true, force: true });
  }
});

test('applied migration sources are immutable when a forward migration is added', () => {
  const appliedMigration = { name: '0001_initial.sql', source: 'initial\n' };
  const forwardMigration = { name: '0002_forward.sql', source: 'forward\n' };

  expect(() =>
    assertAppliedMigrationSourcesUnchanged({
      previousFingerprint: digestMigrations([appliedMigration]),
      appliedMigrationNames: new Set([appliedMigration.name]),
      migrations: [{ ...appliedMigration, source: 'rewritten\n' }, forwardMigration],
    }),
  ).toThrow(/add a new forward migration/u);

  expect(() =>
    assertAppliedMigrationSourcesUnchanged({
      previousFingerprint: digestMigrations([appliedMigration]),
      appliedMigrationNames: new Set([appliedMigration.name]),
      migrations: [appliedMigration, forwardMigration],
    }),
  ).not.toThrow();

  expect(() =>
    assertAppliedMigrationSourcesUnchanged({
      previousFingerprint: 'deployed-predecessor',
      appliedMigrationNames: new Set([appliedMigration.name]),
      migrations: [appliedMigration, forwardMigration],
      acceptedPredecessor: {
        fingerprint: 'deployed-predecessor',
        bridgeMigrationName: forwardMigration.name,
      },
    }),
  ).not.toThrow();

  expect(() =>
    assertAppliedMigrationSourcesUnchanged({
      previousFingerprint: 'deployed-predecessor',
      appliedMigrationNames: new Set([appliedMigration.name, forwardMigration.name]),
      migrations: [appliedMigration, forwardMigration],
      acceptedPredecessor: {
        fingerprint: 'deployed-predecessor',
        bridgeMigrationName: forwardMigration.name,
      },
    }),
  ).toThrow(/add a new forward migration/u);
});

test('post-103 signer bridge upgrades the deployed baseline and stays fresh-schema safe', async () => {
  const deployed = createTemporaryD1Database();
  const fresh = createTemporaryD1Database();
  try {
    await deployed.database.exec(deployedSignerBridgeFixtureSql);
    await deployed.database.exec(
      readFileSync(
        path.join(signerMigrationRoot, '0002_signer_post_103_canonical_upgrade.sql'),
        'utf8',
      ),
    );

    const upgraded = await deployed.database
      .prepare(
        `SELECT authorization_grant_kind
           FROM authorized_operations
          WHERE authorized_operation_id = 'operation-1'`,
      )
      .first<{ readonly authorization_grant_kind: string }>();
    expect(upgraded?.authorization_grant_kind).toBe('wallet_session_authorization');
    for (const table of [
      'lane_enrollments',
      'linked_device_wallet_session_authorizations',
      'linked_device_target_deployment_descriptors',
    ]) {
      const row = await deployed.database
        .prepare(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`)
        .bind(table)
        .first<{ readonly name: string }>();
      expect(row?.name).toBe(table);
    }

    await applyD1MigrationFiles(fresh.database, listD1MigrationFiles('d1-signer'));
    const schemaRows = await fresh.database
      .prepare(`SELECT name FROM sqlite_master WHERE type = 'table'`)
      .all<{ readonly name: string }>();
    const tableNames = new Set(schemaRows.results.map((row) => row.name));
    for (const table of [
      'linked_device_target_deployment_descriptors',
      'verified_wallet_operation_evidence_sets',
      'verified_owner_proof_consumptions',
      'opaque_wallet_session_tokens',
      'hosted_wallet_session_exchange_codes',
    ]) {
      expect(tableNames.has(table), `${table} should exist`).toBe(true);
    }
    for (const table of [
      'authorization_sessions',
      'verified_grant_evidence_sets',
      'ecdsa_authorization_atomic_guards',
      'email_otp_recovery_wrapped_enrollment_escrows',
    ]) {
      expect(tableNames.has(table), `${table} should be removed`).toBe(false);
    }
  } finally {
    cleanupTemporaryD1Database(deployed.tempDir);
    cleanupTemporaryD1Database(fresh.tempDir);
  }
});

const deployedSignerBridgeFixtureSql = `
CREATE TABLE authorized_operation_audit_events (
  namespace TEXT,
  tenant_id TEXT,
  audit_event_id TEXT,
  authorized_operation_id TEXT,
  operation_fingerprint_digest TEXT,
  authorization_source_kind TEXT,
  authorization_id TEXT,
  evidence_set_digest TEXT,
  quota_id TEXT,
  material_activation_id TEXT,
  result_kind TEXT,
  claimed_at_ms INTEGER,
  completed_at_ms INTEGER
);
CREATE TABLE authorized_operations (
  namespace TEXT,
  tenant_id TEXT,
  authorized_operation_id TEXT,
  audit_event_id TEXT,
  principal_id TEXT,
  capability_id TEXT,
  capability_kind TEXT,
  operation_kind TEXT,
  operation_id TEXT,
  operation_fingerprint_digest TEXT,
  lane_digest TEXT,
  intent_digest TEXT,
  display_digest TEXT,
  authorization_source_kind TEXT,
  authorization_id TEXT,
  evidence_set_digest TEXT,
  quota_id TEXT,
  quota_kind TEXT,
  lifecycle_kind TEXT,
  result_kind TEXT,
  result_digest TEXT,
  result_status INTEGER,
  result_content_type TEXT,
  result_body_text TEXT,
  claimed_at_ms INTEGER,
  completed_at_ms INTEGER,
  material_activation_id TEXT
);
CREATE TABLE webauthn_challenges (
  namespace TEXT,
  org_id TEXT,
  project_id TEXT,
  env_id TEXT,
  challenge_id TEXT,
  challenge_kind TEXT,
  record_json TEXT,
  created_at_ms INTEGER,
  expires_at_ms INTEGER
);
INSERT INTO authorized_operations (
  namespace,
  tenant_id,
  authorized_operation_id,
  audit_event_id,
  principal_id,
  capability_id,
  capability_kind,
  operation_kind,
  operation_id,
  operation_fingerprint_digest,
  lane_digest,
  intent_digest,
  display_digest,
  authorization_source_kind,
  authorization_id,
  evidence_set_digest,
  quota_id,
  quota_kind,
  lifecycle_kind,
  result_kind,
  claimed_at_ms
) VALUES (
  'namespace',
  'tenant',
  'operation-1',
  'audit-1',
  'principal',
  'capability',
  'near_ed25519_mpc_signing',
  'near.sign_transaction',
  'request-1',
  'fingerprint',
  'lane',
  'intent',
  'display',
  'authorization_grant',
  'authorization-1',
  NULL,
  'quota-1',
  'consume_reusable_wallet_session',
  'claimed',
  'pending',
  1
);
`;

function writeMigrationDirectory() {
  const directory = mkdtempSync(path.join(tmpdir(), 'seams-migration-fingerprint-'));
  mkdirSync(path.join(directory, 'ignored'), { recursive: true });
  writeFileSync(path.join(directory, '0002_second.sql'), 'second\n');
  writeFileSync(path.join(directory, '0001_first.sql'), 'first\n');
  writeFileSync(path.join(directory, 'README.md'), 'ignored\n');
  return directory;
}

function runJsonCommand(command, args) {
  const output: MigrationSet = JSON.parse(
    execFileSync(process.execPath, [command, ...args], { encoding: 'utf8' }),
  );
  return output;
}

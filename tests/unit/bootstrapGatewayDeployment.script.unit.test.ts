import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { expect, test } from '@playwright/test';
import { publishableKeyUpsertSql } from '../../packages/console-server-ts/scripts/bootstrap-gateway-deployment.mjs';

type PublishableKeyInput = Parameters<typeof publishableKeyUpsertSql>[0];

const BASE_INPUT: PublishableKeyInput = {
  namespace: 'seams-production',
  orgId: 'org_production',
  id: 'ak_bootstrap_test',
  environmentId: 'production',
  keyPrefix: 'pk_original',
  allowedOriginsJson: '["https://seams.sh"]',
  secretHash: 'sha256:original',
  secretPreview: 'pk_origina...',
  nowMs: 1_000,
};

function createApiKeyDatabase(): DatabaseSync {
  const database = new DatabaseSync(':memory:');
  const migration = readFileSync(
    new URL(
      '../../packages/console-server-ts/migrations/d1-console/0008_console_api_keys.sql',
      import.meta.url,
    ),
    'utf8',
  );
  database.exec(migration);
  return database;
}

function readDeploymentKey(database: DatabaseSync): Record<string, unknown> {
  const row = database
    .prepare(
      `SELECT key_prefix, allowed_origins_json, secret_hash, secret_version,
              secret_preview, last_used_at_ms, endpoint_usage_counts_json,
              anomaly_flags_json, created_at_ms, updated_at_ms
         FROM api_keys
        WHERE namespace = ? AND org_id = ? AND id = ?`,
    )
    .get(BASE_INPUT.namespace, BASE_INPUT.orgId, BASE_INPUT.id);
  if (!row) throw new Error('deployment publishable key was not written');
  return row;
}

test('Gateway bootstrap rotates its deterministic publishable key idempotently', () => {
  const database = createApiKeyDatabase();
  try {
    database.exec(publishableKeyUpsertSql(BASE_INPUT));
    database
      .prepare(
        `UPDATE api_keys
            SET last_used_at_ms = ?,
                endpoint_usage_counts_json = ?,
                anomaly_flags_json = ?
          WHERE namespace = ? AND org_id = ? AND id = ?`,
      )
      .run(
        1_100,
        '{"wallets":3}',
        '["observed"]',
        BASE_INPUT.namespace,
        BASE_INPUT.orgId,
        BASE_INPUT.id,
      );

    database.exec(
      publishableKeyUpsertSql({
        ...BASE_INPUT,
        nowMs: 1_200,
      }),
    );
    expect(readDeploymentKey(database)).toMatchObject({
      secret_hash: BASE_INPUT.secretHash,
      secret_version: 1,
      created_at_ms: BASE_INPUT.nowMs,
      updated_at_ms: 1_200,
    });

    database.exec(
      publishableKeyUpsertSql({
        ...BASE_INPUT,
        keyPrefix: 'pk_rotated',
        allowedOriginsJson: '["https://seams.sh","https://sign.seams.sh"]',
        secretHash: 'sha256:rotated',
        secretPreview: 'pk_rotated...',
        nowMs: 1_300,
      }),
    );

    expect(readDeploymentKey(database)).toEqual({
      key_prefix: 'pk_rotated',
      allowed_origins_json: '["https://seams.sh","https://sign.seams.sh"]',
      secret_hash: 'sha256:rotated',
      secret_version: 2,
      secret_preview: 'pk_rotated...',
      last_used_at_ms: 1_100,
      endpoint_usage_counts_json: '{"wallets":3}',
      anomaly_flags_json: '["observed"]',
      created_at_ms: BASE_INPUT.nowMs,
      updated_at_ms: 1_300,
    });
  } finally {
    database.close();
  }
});

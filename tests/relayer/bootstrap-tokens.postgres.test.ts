import { test, expect } from '@playwright/test';
import {
  createPostgresConsoleBootstrapTokenService,
  type ConsoleBootstrapTokenService,
} from '@server/router/express-adaptor';
import { getPostgresPool } from '../../server/src/storage/postgres';
import { withConsoleTenantContextTx } from '../../server/src/console/shared/postgresTenantContext';

function randomNamespace(prefix: string): string {
  return `${prefix}:${Date.now()}:${Math.random().toString(16).slice(2)}`;
}

test.describe('console bootstrap tokens postgres service', () => {
  const postgresUrl = String(process.env.POSTGRES_URL || '').trim();
  const enabled = Boolean(postgresUrl);
  const namespace = randomNamespace('test:console-bootstrap-tokens:postgres');
  const orgId = 'org-bootstrap-tokens-postgres';
  let service: ConsoleBootstrapTokenService | null = null;

  test.beforeAll(async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    service = await createPostgresConsoleBootstrapTokenService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
    });
  });

  test.afterAll(async () => {
    if (!enabled) return;
    const pool = await getPostgresPool(postgresUrl);
    await withConsoleTenantContextTx(pool, { namespace, orgId }, async (q) => {
      await q.query('DELETE FROM console_bootstrap_tokens WHERE namespace = $1', [namespace]);
    });
  });

  test('issues, counts, and redeems bootstrap tokens transactionally', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ctx = {
      orgId,
      actorUserId: 'postgres-bootstrap-broker',
      roles: ['system'],
    };

    const created = await service!.createToken(ctx, {
      publishableKeyId: 'key_publishable_postgres',
      projectId: 'project-bootstrap-postgres',
      environmentId: 'env-bootstrap-postgres',
      newAccountId: 'wallet-bootstrap-postgres.testnet',
      rpId: 'app.example.com',
      origin: 'https://app.example.com',
      method: 'POST',
      path: '/registration/bootstrap',
      requestHashSha256: 'ZmFrZV9oYXNo',
      ttlMs: 60_000,
      riskDecision: 'allow',
    });
    expect(created.token).toContain('tbt_v1_');
    expect(created.record.status).toBe('issued');

    const count = await service!.countIssued(ctx, {
      publishableKeyId: 'key_publishable_postgres',
    });
    expect(count).toBe(1);

    const redeemed = await service!.redeemToken({
      token: created.token,
      origin: 'https://app.example.com',
      method: 'POST',
      path: '/registration/bootstrap',
      requestHashSha256: 'ZmFrZV9oYXNo',
    });
    expect(redeemed.ok).toBe(true);
    if (!redeemed.ok) return;
    expect(redeemed.record.status).toBe('redeemed');
    expect(redeemed.record.redeemedAt).toBeTruthy();

    const replay = await service!.redeemToken({
      token: created.token,
      origin: 'https://app.example.com',
      method: 'POST',
      path: '/registration/bootstrap',
      requestHashSha256: 'ZmFrZV9oYXNo',
    });
    expect(replay.ok).toBe(false);
    if (replay.ok) return;
    expect(replay.code).toBe('bootstrap_token_already_used');
  });
});

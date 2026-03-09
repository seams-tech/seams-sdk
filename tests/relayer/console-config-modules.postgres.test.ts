import { expect, test } from '@playwright/test';
import {
  createPostgresConsoleGasSponsorshipService,
  createPostgresConsoleKeyExportService,
  createPostgresConsoleRuntimeSnapshotService,
  createPostgresConsoleSmartWalletService,
  runPostgresConsoleRuntimeSnapshotOutboxDispatch,
} from '@server/router/express-adaptor';
import { withConsoleTenantContextTx } from '../../server/src/console/shared/postgresTenantContext';
import { getPostgresPool } from '../../server/src/storage/postgres';

function randomNamespace(prefix: string): string {
  return `${prefix}:${Date.now()}:${Math.random().toString(16).slice(2)}`;
}

async function expectConsoleError(fn: () => Promise<unknown>, code: string): Promise<void> {
  let caught: any;
  try {
    await fn();
  } catch (error: unknown) {
    caught = error;
  }
  expect(caught).toBeTruthy();
  expect(String(caught?.code || '')).toBe(code);
}

test.describe('console config modules postgres services', () => {
  const postgresUrl = String(process.env.POSTGRES_URL || '').trim();
  const enabled = Boolean(postgresUrl);
  const namespace = randomNamespace('test:console-config-modules:postgres');
  const orgId = 'org-postgres-console-config-modules';
  const ownerOrgId = `${orgId}:owner`;
  const attackerOrgId = `${orgId}:attacker`;

  const adminCtx = {
    orgId,
    actorUserId: 'admin-config-modules',
    roles: ['admin'],
  };
  const approverCtx = {
    orgId,
    actorUserId: 'approver-config-modules',
    roles: ['admin'],
  };

  test.afterAll(async () => {
    if (!enabled) return;
    const pool = await getPostgresPool(postgresUrl);
    for (const scopedOrgId of [orgId, ownerOrgId, attackerOrgId]) {
      await withConsoleTenantContextTx(pool, { namespace, orgId: scopedOrgId }, async (q) => {
        await q.query('DELETE FROM console_key_exports WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_runtime_snapshot_outbox WHERE namespace = $1', [
          namespace,
        ]);
        await q.query('DELETE FROM console_runtime_snapshots WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_smart_wallet_configs WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_gas_sponsorship_configs WHERE namespace = $1', [
          namespace,
        ]);
      });
    }
  });

  test('gas sponsorship postgres service supports create/list/update + scope validation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const service = await createPostgresConsoleGasSponsorshipService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
    });

    await expectConsoleError(async () => {
      await service.createConfig(adminCtx, {
        scopeType: 'PROJECT',
        enabled: true,
      });
    }, 'invalid_scope');

    const created = await service.createConfig(adminCtx, {
      id: 'gs-postgres-1',
      scopeType: 'ENVIRONMENT',
      environmentId: 'prod',
      enabled: true,
      paymasterMode: 'AUTO',
      fallbackBehavior: 'ALLOW_UNSPONSORED',
      chainBudgets: [
        {
          chain: 'Ethereum',
          period: 'MONTHLY',
          budgetMinor: 400_000,
          quotaTransactions: 2_000,
        },
      ],
    });
    expect(created.id).toBe('gs-postgres-1');
    expect(created.scopeType).toBe('ENVIRONMENT');
    expect(created.environmentId).toBe('prod');
    expect(created.chainBudgets.length).toBe(1);

    const listAll = await service.listConfigs(adminCtx);
    expect(listAll.some((entry) => entry.id === 'gs-postgres-1')).toBe(true);

    const listScoped = await service.listConfigs(adminCtx, { environmentId: 'prod' });
    expect(listScoped.length).toBeGreaterThanOrEqual(1);
    expect(listScoped.every((entry) => entry.environmentId === 'prod')).toBe(true);

    const updated = await service.updateConfig(adminCtx, 'gs-postgres-1', {
      enabled: false,
      chainBudgets: [
        {
          chain: 'Base',
          period: 'MONTHLY',
          budgetMinor: 250_000,
          quotaTransactions: 1_200,
        },
      ],
    });
    expect(updated).toBeTruthy();
    expect(updated?.enabled).toBe(false);
    expect(updated?.chainBudgets.length).toBe(1);
    expect(updated?.chainBudgets[0].chain).toBe('Base');
  });

  test('smart wallets postgres service supports create/list/update + scope validation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const service = await createPostgresConsoleSmartWalletService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
    });

    await expectConsoleError(async () => {
      await service.createConfig(adminCtx, {
        scopeType: 'POLICY',
        mode: 'OPTIONAL',
      });
    }, 'invalid_scope');

    const created = await service.createConfig(adminCtx, {
      id: 'sw-postgres-1',
      scopeType: 'ENVIRONMENT',
      environmentId: 'prod',
      enabled: true,
      mode: 'REQUIRED',
      accountType: 'SMART_ACCOUNT',
      paymasterMode: 'AUTO',
      fallbackBehavior: 'FALLBACK_TO_EOA',
      bundler: {
        provider: 'pimlico',
        entryPointVersion: 'v0.7',
        maxFeePerGasGwei: 60,
        maxPriorityFeePerGasGwei: 2,
      },
    });
    expect(created.id).toBe('sw-postgres-1');
    expect(created.mode).toBe('REQUIRED');
    expect(created.environmentId).toBe('prod');
    expect(created.bundler?.provider).toBe('pimlico');

    const listScoped = await service.listConfigs(adminCtx, { environmentId: 'prod' });
    expect(listScoped.length).toBeGreaterThanOrEqual(1);
    expect(listScoped.every((entry) => entry.environmentId === 'prod')).toBe(true);

    const updated = await service.updateConfig(adminCtx, 'sw-postgres-1', {
      enabled: false,
      mode: 'OPTIONAL',
      bundler: null,
    });
    expect(updated).toBeTruthy();
    expect(updated?.enabled).toBe(false);
    expect(updated?.mode).toBe('OPTIONAL');
    expect(updated?.bundler).toBeNull();
  });

  test('key exports postgres service enforces approval flow constraints', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const service = await createPostgresConsoleKeyExportService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
    });

    const created = await service.createKeyExport(adminCtx, {
      id: 'ke-postgres-1',
      environmentId: 'prod',
      reason: 'Emergency key rotation',
      requiredApprovals: 2,
      constraints: {
        roles: ['admin'],
        chains: ['Ethereum', 'Base'],
      },
    });
    expect(created.id).toBe('ke-postgres-1');
    expect(created.status).toBe('PENDING_APPROVAL');
    expect(created.requiredApprovals).toBe(2);

    await expectConsoleError(async () => {
      await service.approveKeyExport(adminCtx, created.id, {
        reason: 'no mfa',
        mfaVerified: false,
      });
    }, 'mfa_required');

    const first = await service.approveKeyExport(adminCtx, created.id, {
      reason: 'approved 1',
      mfaVerified: true,
    });
    expect(first?.status).toBe('PENDING_APPROVAL');
    expect(first?.approvals.length).toBe(1);

    await expectConsoleError(async () => {
      await service.approveKeyExport(adminCtx, created.id, {
        reason: 'duplicate approver',
        mfaVerified: true,
      });
    }, 'already_approved');

    const second = await service.approveKeyExport(approverCtx, created.id, {
      reason: 'approved 2',
      mfaVerified: true,
    });
    expect(second?.status).toBe('APPROVED');
    expect(second?.approvals.length).toBe(2);

    const listApproved = await service.listKeyExports(adminCtx, {
      status: 'APPROVED',
    });
    expect(listApproved.some((entry) => entry.id === created.id)).toBe(true);
  });

  test('runtime snapshots postgres service supports publish/list/latest semantics', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const service = await createPostgresConsoleRuntimeSnapshotService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
    });

    const publishedOne = await service.publishSnapshot(adminCtx, {
      environmentId: 'prod',
      payload: {
        policy: {
          defaultPolicyId: 'policy-1',
        },
        gasSponsorship: {
          enabled: true,
        },
        smartWallets: {
          mode: 'REQUIRED',
        },
      },
    });
    expect(publishedOne.environmentId).toBe('prod');
    expect(publishedOne.version).toBe(1);
    expect(publishedOne.checksum).toContain('fnv1a32:');

    const publishedTwo = await service.publishSnapshot(adminCtx, {
      environmentId: 'prod',
      payload: {
        policy: {
          defaultPolicyId: 'policy-2',
        },
        gasSponsorship: {
          enabled: false,
        },
        smartWallets: {
          mode: 'OPTIONAL',
        },
      },
    });
    expect(publishedTwo.version).toBe(2);

    const latest = await service.getLatestSnapshot(adminCtx, { environmentId: 'prod' });
    expect(latest?.version).toBe(2);
    expect(latest?.payload.policy.defaultPolicyId).toBe('policy-2');

    const listed = await service.listSnapshots(adminCtx, { environmentId: 'prod', limit: 10 });
    expect(listed.length).toBeGreaterThanOrEqual(2);
    expect(listed[0].version).toBeGreaterThanOrEqual(listed[1].version);
  });

  test('runtime snapshots table enforces DB-level tenant RLS policies', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const service = await createPostgresConsoleRuntimeSnapshotService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
    });

    const environmentId = 'prod-rls';
    const ownerCtx = {
      orgId: ownerOrgId,
      actorUserId: 'owner-runtime-rls',
      roles: ['admin'],
    };
    const attackerCtx = {
      orgId: attackerOrgId,
      actorUserId: 'attacker-runtime-rls',
      roles: ['admin'],
    };

    await service.publishSnapshot(ownerCtx, {
      environmentId,
      payload: {
        policy: { defaultPolicyId: 'owner-policy' },
        gasSponsorship: { enabled: true },
        smartWallets: { mode: 'REQUIRED' },
      },
    });
    await service.publishSnapshot(attackerCtx, {
      environmentId,
      payload: {
        policy: { defaultPolicyId: 'attacker-policy' },
        gasSponsorship: { enabled: false },
        smartWallets: { mode: 'OPTIONAL' },
      },
    });

    const pool = await getPostgresPool(postgresUrl);

    const ownerRows = await withConsoleTenantContextTx(
      pool,
      { namespace, orgId: ownerCtx.orgId },
      async (q) =>
        q.query(
          `SELECT org_id, snapshot_id
             FROM console_runtime_snapshots
            WHERE environment_id = $1
            ORDER BY created_at_ms DESC`,
          [environmentId],
        ),
    );
    expect(ownerRows.rows.length).toBe(1);
    expect(String(ownerRows.rows[0]?.org_id || '')).toBe(ownerCtx.orgId);

    const attackerRows = await withConsoleTenantContextTx(
      pool,
      { namespace, orgId: attackerCtx.orgId },
      async (q) =>
        q.query(
          `SELECT org_id, snapshot_id
             FROM console_runtime_snapshots
            WHERE environment_id = $1
            ORDER BY created_at_ms DESC`,
          [environmentId],
        ),
    );
    expect(attackerRows.rows.length).toBe(1);
    expect(String(attackerRows.rows[0]?.org_id || '')).toBe(attackerCtx.orgId);

    const rowsWithoutTenantContext = await pool.query(
      `SELECT org_id, snapshot_id
         FROM console_runtime_snapshots
        WHERE namespace = $1
          AND environment_id = $2`,
      [namespace, environmentId],
    );
    expect(rowsWithoutTenantContext.rows.length).toBe(0);

    const ownerOutboxRows = await withConsoleTenantContextTx(
      pool,
      { namespace, orgId: ownerCtx.orgId },
      async (q) =>
        q.query(
          `SELECT org_id, event_id, snapshot_id
             FROM console_runtime_snapshot_outbox
            WHERE namespace = $1
            ORDER BY created_at_ms DESC`,
          [namespace],
        ),
    );
    expect(ownerOutboxRows.rows.length).toBeGreaterThan(0);
    expect(String(ownerOutboxRows.rows[0]?.org_id || '')).toBe(ownerCtx.orgId);

    const attackerOutboxRows = await withConsoleTenantContextTx(
      pool,
      { namespace, orgId: attackerCtx.orgId },
      async (q) =>
        q.query(
          `SELECT org_id, event_id, snapshot_id
             FROM console_runtime_snapshot_outbox
            WHERE namespace = $1
            ORDER BY created_at_ms DESC`,
          [namespace],
        ),
    );
    expect(attackerOutboxRows.rows.length).toBeGreaterThan(0);
    expect(String(attackerOutboxRows.rows[0]?.org_id || '')).toBe(attackerCtx.orgId);

    const outboxRowsWithoutTenantContext = await pool.query(
      `SELECT org_id, event_id
         FROM console_runtime_snapshot_outbox
        WHERE namespace = $1`,
      [namespace],
    );
    expect(outboxRowsWithoutTenantContext.rows.length).toBe(0);
  });

  test('runtime snapshot outbox dispatch is ordered and retry-safe', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    let current = new Date('2026-03-01T00:00:00.000Z');
    const service = await createPostgresConsoleRuntimeSnapshotService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
      now: () => current,
    });
    const environmentId = 'prod-outbox-dispatch';

    const one = await service.publishSnapshot(adminCtx, {
      environmentId,
      payload: {
        policy: { defaultPolicyId: 'p1' },
        gasSponsorship: { enabled: true },
        smartWallets: { mode: 'OPTIONAL' },
      },
    });
    current = new Date(current.getTime() + 1000);
    const two = await service.publishSnapshot(adminCtx, {
      environmentId,
      payload: {
        policy: { defaultPolicyId: 'p2' },
        gasSponsorship: { enabled: true },
        smartWallets: { mode: 'OPTIONAL' },
      },
    });
    current = new Date(current.getTime() + 1000);
    const three = await service.publishSnapshot(adminCtx, {
      environmentId,
      payload: {
        policy: { defaultPolicyId: 'p3' },
        gasSponsorship: { enabled: false },
        smartWallets: { mode: 'REQUIRED' },
      },
    });

    const firstRunVersions: number[] = [];
    const first = await runPostgresConsoleRuntimeSnapshotOutboxDispatch({
      postgresUrl,
      namespace,
      orgIds: [orgId],
      ensureSchema: false,
      limit: 2,
      dispatch: async (event) => {
        firstRunVersions.push(event.snapshotVersion);
      },
      logger: console as any,
    });
    expect(first.orgCount).toBe(1);
    expect(first.dispatchedCount).toBe(2);
    expect(first.failureCount).toBe(0);
    expect(firstRunVersions).toEqual([one.version, two.version]);

    let failOnce = true;
    const secondRunVersions: number[] = [];
    const second = await runPostgresConsoleRuntimeSnapshotOutboxDispatch({
      postgresUrl,
      namespace,
      orgIds: [orgId],
      ensureSchema: false,
      limit: 10,
      dispatch: async (event) => {
        secondRunVersions.push(event.snapshotVersion);
        if (event.snapshotVersion === three.version && failOnce) {
          failOnce = false;
          throw new Error('simulated_dispatch_failure');
        }
      },
      logger: console as any,
    });
    expect(second.dispatchedCount).toBe(0);
    expect(second.failureCount).toBe(1);
    expect(secondRunVersions).toEqual([three.version]);

    const thirdRunVersions: number[] = [];
    const third = await runPostgresConsoleRuntimeSnapshotOutboxDispatch({
      postgresUrl,
      namespace,
      orgIds: [orgId],
      ensureSchema: false,
      limit: 10,
      dispatch: async (event) => {
        thirdRunVersions.push(event.snapshotVersion);
      },
      logger: console as any,
    });
    expect(third.dispatchedCount).toBe(1);
    expect(third.failureCount).toBe(0);
    expect(thirdRunVersions).toEqual([three.version]);

    const fourth = await runPostgresConsoleRuntimeSnapshotOutboxDispatch({
      postgresUrl,
      namespace,
      orgIds: [orgId],
      ensureSchema: false,
      limit: 10,
      dispatch: async () => {},
      logger: console as any,
    });
    expect(fourth.dispatchedCount).toBe(0);
    expect(fourth.failureCount).toBe(0);

    const pool = await getPostgresPool(postgresUrl);
    const summaryRows = await withConsoleTenantContextTx(pool, { namespace, orgId }, async (q) =>
      q.query(
        `SELECT
            COUNT(*)::BIGINT AS total_count,
            COUNT(*) FILTER (WHERE dispatched_at_ms IS NOT NULL)::BIGINT AS dispatched_count
           FROM console_runtime_snapshot_outbox
          WHERE namespace = $1 AND environment_id = $2`,
        [namespace, environmentId],
      ),
    );
    expect(Number(summaryRows.rows[0]?.total_count || 0)).toBeGreaterThanOrEqual(3);
    expect(Number(summaryRows.rows[0]?.dispatched_count || 0)).toBeGreaterThanOrEqual(3);
  });

  test('gas/smart-wallet tables enforce DB-level tenant RLS policies', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const gasService = await createPostgresConsoleGasSponsorshipService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
    });
    const smartWalletService = await createPostgresConsoleSmartWalletService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
    });

    const ownerCtx = {
      orgId: ownerOrgId,
      actorUserId: 'owner-config-rls',
      roles: ['admin'],
    };
    const attackerCtx = {
      orgId: attackerOrgId,
      actorUserId: 'attacker-config-rls',
      roles: ['admin'],
    };

    await gasService.createConfig(ownerCtx, {
      id: 'gs-postgres-rls-owner',
      scopeType: 'ENVIRONMENT',
      environmentId: 'prod-rls',
      enabled: true,
      paymasterMode: 'AUTO',
      fallbackBehavior: 'ALLOW_UNSPONSORED',
    });
    await gasService.createConfig(attackerCtx, {
      id: 'gs-postgres-rls-attacker',
      scopeType: 'ENVIRONMENT',
      environmentId: 'prod-rls',
      enabled: true,
      paymasterMode: 'AUTO',
      fallbackBehavior: 'ALLOW_UNSPONSORED',
    });

    await smartWalletService.createConfig(ownerCtx, {
      id: 'sw-postgres-rls-owner',
      scopeType: 'ENVIRONMENT',
      environmentId: 'prod-rls',
      enabled: true,
      mode: 'REQUIRED',
      accountType: 'SMART_ACCOUNT',
      paymasterMode: 'AUTO',
      fallbackBehavior: 'FALLBACK_TO_EOA',
    });
    await smartWalletService.createConfig(attackerCtx, {
      id: 'sw-postgres-rls-attacker',
      scopeType: 'ENVIRONMENT',
      environmentId: 'prod-rls',
      enabled: true,
      mode: 'OPTIONAL',
      accountType: 'SMART_ACCOUNT',
      paymasterMode: 'AUTO',
      fallbackBehavior: 'FALLBACK_TO_EOA',
    });

    const pool = await getPostgresPool(postgresUrl);

    const ownerGasRows = await withConsoleTenantContextTx(
      pool,
      { namespace, orgId: ownerOrgId },
      async (q) =>
        q.query(
          `SELECT org_id, id
             FROM console_gas_sponsorship_configs
            WHERE namespace = $1`,
          [namespace],
        ),
    );
    expect(ownerGasRows.rows.length).toBeGreaterThan(0);
    expect(
      ownerGasRows.rows.every(
        (row) => String((row as Record<string, unknown>).org_id || '') === ownerOrgId,
      ),
    ).toBe(true);

    const ownerSmartRows = await withConsoleTenantContextTx(
      pool,
      { namespace, orgId: ownerOrgId },
      async (q) =>
        q.query(
          `SELECT org_id, id
             FROM console_smart_wallet_configs
            WHERE namespace = $1`,
          [namespace],
        ),
    );
    expect(ownerSmartRows.rows.length).toBeGreaterThan(0);
    expect(
      ownerSmartRows.rows.every(
        (row) => String((row as Record<string, unknown>).org_id || '') === ownerOrgId,
      ),
    ).toBe(true);

    const rowsWithoutTenantContext = await pool.query(
      `SELECT org_id, id FROM console_gas_sponsorship_configs WHERE namespace = $1`,
      [namespace],
    );
    expect(rowsWithoutTenantContext.rows.length).toBe(0);
  });

  test('key-export tables enforce DB-level tenant RLS policies', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const keyExportService = await createPostgresConsoleKeyExportService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
    });

    const ownerCtx = {
      orgId: ownerOrgId,
      actorUserId: 'owner-keyexport-rls',
      roles: ['admin'],
    };
    const attackerCtx = {
      orgId: attackerOrgId,
      actorUserId: 'attacker-keyexport-rls',
      roles: ['admin'],
    };

    await keyExportService.createKeyExport(ownerCtx, {
      id: 'ke-postgres-rls-owner',
      environmentId: 'prod-rls',
      reason: 'Owner export',
      requiredApprovals: 1,
    });
    await keyExportService.createKeyExport(attackerCtx, {
      id: 'ke-postgres-rls-attacker',
      environmentId: 'prod-rls',
      reason: 'Attacker export',
      requiredApprovals: 1,
    });

    const pool = await getPostgresPool(postgresUrl);

    const ownerKeyExportRows = await withConsoleTenantContextTx(
      pool,
      { namespace, orgId: ownerOrgId },
      async (q) =>
        q.query(
          `SELECT org_id, id
             FROM console_key_exports
            WHERE namespace = $1`,
          [namespace],
        ),
    );
    expect(ownerKeyExportRows.rows.length).toBeGreaterThan(0);
    expect(
      ownerKeyExportRows.rows.every(
        (row) => String((row as Record<string, unknown>).org_id || '') === ownerOrgId,
      ),
    ).toBe(true);

    const noTenantKeyExports = await pool.query(
      `SELECT org_id, id FROM console_key_exports WHERE namespace = $1`,
      [namespace],
    );
    expect(noTenantKeyExports.rows.length).toBe(0);
  });

  test('postgres config module services enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');

    const gasService = await createPostgresConsoleGasSponsorshipService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
    });
    const smartWalletService = await createPostgresConsoleSmartWalletService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
    });
    const keyExportService = await createPostgresConsoleKeyExportService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
    });
    const runtimeSnapshotService = await createPostgresConsoleRuntimeSnapshotService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
    });

    const ownerCtx = {
      orgId: ownerOrgId,
      actorUserId: 'owner-config-modules',
      roles: ['admin'],
    };
    const attackerCtx = {
      orgId: attackerOrgId,
      actorUserId: 'attacker-config-modules',
      roles: ['admin'],
    };
    const ownerEnvironmentId = 'prod-org-isolation';

    const createdGas = await gasService.createConfig(ownerCtx, {
      id: 'gs-postgres-isolation-1',
      scopeType: 'ENVIRONMENT',
      environmentId: ownerEnvironmentId,
      enabled: true,
      paymasterMode: 'AUTO',
      fallbackBehavior: 'ALLOW_UNSPONSORED',
    });
    expect(createdGas.id).toBe('gs-postgres-isolation-1');

    const createdSmartWallet = await smartWalletService.createConfig(ownerCtx, {
      id: 'sw-postgres-isolation-1',
      scopeType: 'ENVIRONMENT',
      environmentId: ownerEnvironmentId,
      enabled: true,
      mode: 'REQUIRED',
      accountType: 'SMART_ACCOUNT',
      paymasterMode: 'AUTO',
      fallbackBehavior: 'FALLBACK_TO_EOA',
    });
    expect(createdSmartWallet.id).toBe('sw-postgres-isolation-1');

    const ownerKeyExport = await keyExportService.createKeyExport(ownerCtx, {
      id: 'ke-postgres-isolation-1',
      environmentId: ownerEnvironmentId,
      reason: 'Owner key export',
      requiredApprovals: 1,
    });
    expect(ownerKeyExport.id).toBe('ke-postgres-isolation-1');

    const ownerSnapshot = await runtimeSnapshotService.publishSnapshot(ownerCtx, {
      environmentId: ownerEnvironmentId,
      payload: {
        policy: { defaultPolicyId: 'owner-policy' },
        gasSponsorship: { enabled: true },
        smartWallets: { mode: 'REQUIRED' },
      },
    });
    expect(ownerSnapshot.version).toBe(1);

    const attackerGasList = await gasService.listConfigs(attackerCtx, {
      environmentId: ownerEnvironmentId,
    });
    expect(attackerGasList.length).toBe(0);

    const attackerGasPatch = await gasService.updateConfig(attackerCtx, createdGas.id, {
      enabled: false,
    });
    expect(attackerGasPatch).toBeNull();

    const attackerSmartWalletList = await smartWalletService.listConfigs(attackerCtx, {
      environmentId: ownerEnvironmentId,
    });
    expect(attackerSmartWalletList.length).toBe(0);

    const attackerSmartWalletPatch = await smartWalletService.updateConfig(
      attackerCtx,
      createdSmartWallet.id,
      {
        enabled: false,
      },
    );
    expect(attackerSmartWalletPatch).toBeNull();

    const attackerKeyExportList = await keyExportService.listKeyExports(attackerCtx, {
      environmentId: ownerEnvironmentId,
    });
    expect(attackerKeyExportList.length).toBe(0);

    const attackerApproveOwner = await keyExportService.approveKeyExport(
      attackerCtx,
      ownerKeyExport.id,
      {
        reason: 'attacker approval attempt',
        mfaVerified: true,
      },
    );
    expect(attackerApproveOwner).toBeNull();

    const attackerSnapshots = await runtimeSnapshotService.listSnapshots(attackerCtx, {
      environmentId: ownerEnvironmentId,
    });
    expect(attackerSnapshots.length).toBe(0);

    const attackerLatestSnapshot = await runtimeSnapshotService.getLatestSnapshot(attackerCtx, {
      environmentId: ownerEnvironmentId,
    });
    expect(attackerLatestSnapshot).toBeNull();

    const ownerLatestSnapshot = await runtimeSnapshotService.getLatestSnapshot(ownerCtx, {
      environmentId: ownerEnvironmentId,
    });
    expect(ownerLatestSnapshot?.snapshotId).toBe(ownerSnapshot.snapshotId);

    const ownerKeyExportAfter = await keyExportService.listKeyExports(ownerCtx, {
      environmentId: ownerEnvironmentId,
    });
    expect(ownerKeyExportAfter.some((entry) => entry.id === ownerKeyExport.id)).toBe(true);
    expect(ownerKeyExportAfter.find((entry) => entry.id === ownerKeyExport.id)?.status).toBe(
      'PENDING_APPROVAL',
    );
  });
});

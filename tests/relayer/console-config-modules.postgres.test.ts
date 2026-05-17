import { expect, test } from '@playwright/test';
import {
  createPostgresConsolePolicyService,
  createPostgresConsoleKeyExportService,
  createPostgresConsoleRuntimeSnapshotService,
  runPostgresConsoleRuntimeSnapshotOutboxDispatch,
  runPostgresConsoleRuntimeSnapshotRetentionCleanup,
} from '@server/router/express-adaptor';
import {
  projectConsoleGasSponsorshipPolicyProjection,
  sortConsoleGasSponsorshipPolicyProjections,
  type ConsoleGasSponsorshipPolicyProjection,
} from '../../server/src/console/gasSponsorship';
import {
  isConsoleGasSponsorshipPolicyRules,
  type ConsoleGasSponsorshipPolicyRulesInput,
  type ConsolePoliciesContext,
  type ConsolePolicyService,
} from '../../server/src/console/policies';
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

async function listProjectedGasPolicies(
  policies: ConsolePolicyService,
  ctx: ConsolePoliciesContext,
  filters: {
    environmentId?: string;
    projectId?: string;
  } = {},
): Promise<ConsoleGasSponsorshipPolicyProjection[]> {
  const projections = (
    await Promise.all(
      (await policies.listPolicies(ctx, { kind: 'GAS_SPONSORSHIP' })).map(
        async (policy) => await projectConsoleGasSponsorshipPolicyProjection(policies, ctx, policy),
      ),
    )
  ).filter(
    (projection): projection is ConsoleGasSponsorshipPolicyProjection => projection !== null,
  );
  return sortConsoleGasSponsorshipPolicyProjections(
    projections.filter((projection) => {
      if (filters.environmentId && projection.environmentId !== filters.environmentId) return false;
      if (filters.projectId && projection.projectId !== filters.projectId) return false;
      return true;
    }),
  );
}

async function createPublishedGasPolicy(
  policies: ConsolePolicyService,
  ctx: ConsolePoliciesContext,
  input: {
    name?: string;
    rules: ConsoleGasSponsorshipPolicyRulesInput;
  },
): Promise<ConsoleGasSponsorshipPolicyProjection> {
  const created = await policies.createPolicy(ctx, {
    kind: 'GAS_SPONSORSHIP',
    name: input.name || 'Gas Sponsorship Policy',
    rules: input.rules,
  });
  const published = await policies.publishPolicy(ctx, created.id);
  if (!published) {
    throw new Error(`Policy ${created.id} was not found after create`);
  }
  const projection = await projectConsoleGasSponsorshipPolicyProjection(
    policies,
    ctx,
    published.policy,
  );
  if (!projection) {
    throw new Error(`Policy ${published.policy.id} did not project as gas policy`);
  }
  return projection;
}

async function updatePublishedGasPolicy(
  policies: ConsolePolicyService,
  ctx: ConsolePoliciesContext,
  policyId: string,
  input: {
    name?: string;
    rules?: Partial<ConsoleGasSponsorshipPolicyRulesInput>;
  },
): Promise<ConsoleGasSponsorshipPolicyProjection | null> {
  const current = await policies.getPolicy(ctx, policyId);
  if (!current || current.kind !== 'GAS_SPONSORSHIP' || !isConsoleGasSponsorshipPolicyRules(current.rules)) {
    return null;
  }
  const updated = await policies.updatePolicy(ctx, policyId, {
    ...(input.name !== undefined ? { name: input.name || current.name } : {}),
    ...(input.rules ? { rules: { ...current.rules, ...input.rules } } : {}),
  });
  if (!updated) return null;
  const published = await policies.publishPolicy(ctx, updated.id);
  if (!published) return null;
  return await projectConsoleGasSponsorshipPolicyProjection(policies, ctx, published.policy);
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
        await q.query('DELETE FROM console_policy_versions WHERE namespace = $1', [namespace]);
        await q.query(
          `DELETE FROM console_policies
            WHERE namespace = $1
              AND kind = 'GAS_SPONSORSHIP'`,
          [namespace],
        );
      });
    }
  });

  test('gas sponsorship postgres service supports create/list/update + scope validation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const policies = await createPostgresConsolePolicyService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
    });

    await expectConsoleError(async () => {
      await createPublishedGasPolicy(policies, adminCtx, {
        rules: {
          scopeType: 'PROJECT',
          enabled: true,
          kind: 'evm_call',
          allowedCalls: [
            {
              chainId: 1,
              to: '0x1111111111111111111111111111111111111111',
              functionSignature: 'transfer(address,uint256)',
              maxGasLimit: '21000',
              maxValueWei: '0',
            },
          ],
        },
      });
    }, 'invalid_body');

    const created = await createPublishedGasPolicy(policies, adminCtx, {
      rules: {
        scopeType: 'ENVIRONMENT',
        environmentId: 'prod',
        enabled: true,
        kind: 'evm_call',
        allowedCalls: [
          {
            chainId: 1,
            to: '0x1111111111111111111111111111111111111111',
            functionSignature: 'transfer(address,uint256)',
            maxGasLimit: '21000',
            maxValueWei: '0',
          },
        ],
        spendCap: {
          mode: 'CHAIN_TOTAL',
          period: 'MONTHLY',
          capsByChain: [{ chainId: 1, capMinor: 400_000 }],
        },
      },
    });
    expect(created.id.startsWith('policy_')).toBe(true);
    expect(created.scopeType).toBe('ENVIRONMENT');
    expect(created.environmentId).toBe('prod');
    expect(created.spendCap).toEqual({
      mode: 'CHAIN_TOTAL',
      period: 'MONTHLY',
      capsByChain: [{ chainId: 1, capMinor: 400_000 }],
    });

    const listAll = await listProjectedGasPolicies(policies, adminCtx);
    expect(listAll.some((entry) => entry.id === created.id)).toBe(true);

    const listScoped = await listProjectedGasPolicies(policies, adminCtx, {
      environmentId: 'prod',
    });
    expect(listScoped.length).toBeGreaterThanOrEqual(1);
    expect(listScoped.every((entry) => entry.environmentId === 'prod')).toBe(true);

    const updated = await updatePublishedGasPolicy(policies, adminCtx, created.id, {
      rules: {
        enabled: false,
        kind: 'evm_call',
        allowedCalls: [
          {
            chainId: 8_453,
            to: '0x1111111111111111111111111111111111111111',
            functionSignature: 'transfer(address,uint256)',
            maxGasLimit: '21000',
            maxValueWei: '0',
          },
        ],
        spendCap: {
          mode: 'WALLET_CHAIN_TOTAL',
          period: 'WEEKLY',
          capsByChain: [{ chainId: 8_453, capMinor: 250_000 }],
        },
      },
    });
    expect(updated).toBeTruthy();
    expect(updated?.enabled).toBe(false);
    expect(updated?.spendCap).toEqual({
      mode: 'WALLET_CHAIN_TOTAL',
      period: 'WEEKLY',
      capsByChain: [{ chainId: 8_453, capMinor: 250_000 }],
    });
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

  test('runtime snapshots postgres service resolves project-scoped snapshots without an explicit projectId filter', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const service = await createPostgresConsoleRuntimeSnapshotService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
    });

    const environmentId = 'env-project-scoped-latest';
    const projectId = 'project-scoped-latest';

    const published = await service.publishSnapshot(adminCtx, {
      projectId,
      environmentId,
      payload: {
        policy: {
          defaultPolicyId: 'policy-project-scoped',
        },
        gasSponsorship: {
          enabled: true,
        },
      },
    });

    const latest = await service.getLatestSnapshot(adminCtx, { environmentId });
    expect(latest?.snapshotId).toBe(published.snapshotId);
    expect(latest?.projectId).toBe(projectId);

    const listed = await service.listSnapshots(adminCtx, { environmentId, limit: 10 });
    expect(listed[0]?.snapshotId).toBe(published.snapshotId);
    expect(listed[0]?.projectId).toBe(projectId);
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
      },
    });
    await service.publishSnapshot(attackerCtx, {
      environmentId,
      payload: {
        policy: { defaultPolicyId: 'attacker-policy' },
        gasSponsorship: { enabled: false },
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
      },
    });
    current = new Date(current.getTime() + 1000);
    const two = await service.publishSnapshot(adminCtx, {
      environmentId,
      payload: {
        policy: { defaultPolicyId: 'p2' },
        gasSponsorship: { enabled: true },
      },
    });
    current = new Date(current.getTime() + 1000);
    const three = await service.publishSnapshot(adminCtx, {
      environmentId,
      payload: {
        policy: { defaultPolicyId: 'p3' },
        gasSponsorship: { enabled: false },
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

  test('runtime snapshot retention prunes old outbox rows and keeps latest snapshot per scope', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    let current = new Date('2026-03-01T00:00:00.000Z');
    const service = await createPostgresConsoleRuntimeSnapshotService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
      now: () => current,
      retentionTtlMs: 1000 * 60 * 60 * 24 * 7,
      retentionPruneIntervalMs: 1,
      retentionBatchSize: 100,
    });
    const environmentId = 'prod-retention';

    await service.publishSnapshot(adminCtx, {
      environmentId,
      payload: {
        policy: { defaultPolicyId: 'old-1' },
        gasSponsorship: { enabled: true },
      },
    });
    current = new Date('2026-03-02T00:00:00.000Z');
    await service.publishSnapshot(adminCtx, {
      environmentId,
      payload: {
        policy: { defaultPolicyId: 'old-2' },
        gasSponsorship: { enabled: true },
      },
    });
    current = new Date('2026-03-10T00:00:00.000Z');
    await service.publishSnapshot(adminCtx, {
      environmentId,
      payload: {
        policy: { defaultPolicyId: 'latest' },
        gasSponsorship: { enabled: false },
      },
    });

    const retained = await service.listSnapshots(adminCtx, {
      environmentId,
      limit: 10,
    });
    expect(retained.map((snapshot) => snapshot.version)).toEqual([3]);
    expect(retained[0]?.payload.policy).toEqual({ defaultPolicyId: 'latest' });

    const pool = await getPostgresPool(postgresUrl);
    const outboxRows = await withConsoleTenantContextTx(pool, { namespace, orgId }, async (q) =>
      q.query(
        `SELECT snapshot_version
           FROM console_runtime_snapshot_outbox
          WHERE namespace = $1
            AND org_id = $2
            AND environment_id = $3
          ORDER BY snapshot_version ASC`,
        [namespace, orgId, environmentId],
      ),
    );
    expect(outboxRows.rows.map((row) => Number(row.snapshot_version))).toEqual([3]);

    const singleScopeEnvironmentId = 'prod-retention-single';
    current = new Date('2026-03-01T00:00:00.000Z');
    await service.publishSnapshot(adminCtx, {
      environmentId: singleScopeEnvironmentId,
      payload: {
        policy: { defaultPolicyId: 'only' },
        gasSponsorship: { enabled: true },
      },
    });
    const cleanup = await runPostgresConsoleRuntimeSnapshotRetentionCleanup({
      postgresUrl,
      namespace,
      orgId,
      logger: console as any,
      ensureSchema: false,
      now: () => new Date('2026-03-20T00:00:00.000Z'),
      ttlMs: 1000 * 60 * 60 * 24 * 7,
      batchSize: 100,
    });
    expect(cleanup.deletedOutbox).toBeGreaterThanOrEqual(1);

    const singleRetained = await service.listSnapshots(adminCtx, {
      environmentId: singleScopeEnvironmentId,
      limit: 10,
    });
    expect(singleRetained).toHaveLength(1);
    expect(singleRetained[0]?.payload.policy).toEqual({ defaultPolicyId: 'only' });
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

    const policies = await createPostgresConsolePolicyService({
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

    const createdGas = await createPublishedGasPolicy(policies, ownerCtx, {
      rules: {
        scopeType: 'ENVIRONMENT',
        environmentId: ownerEnvironmentId,
        enabled: true,
        kind: 'evm_call',
        allowedCalls: [
          {
            chainId: 1,
            to: '0x1111111111111111111111111111111111111111',
            functionSignature: 'transfer(address,uint256)',
            maxGasLimit: '21000',
            maxValueWei: '0',
          },
        ],
      },
    });
    expect(createdGas.id.startsWith('policy_')).toBe(true);

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
      },
    });
    expect(ownerSnapshot.version).toBe(1);

    const attackerGasList = await listProjectedGasPolicies(policies, attackerCtx, {
      environmentId: ownerEnvironmentId,
    });
    expect(attackerGasList.length).toBe(0);

    const attackerGasPatch = await updatePublishedGasPolicy(
      policies,
      attackerCtx,
      createdGas.id,
      {
        rules: {
          enabled: false,
        },
      },
    );
    expect(attackerGasPatch).toBeNull();

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

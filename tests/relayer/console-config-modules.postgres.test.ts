import { expect, test } from '@playwright/test';
import {
  createPostgresConsoleGasSponsorshipService,
  createPostgresConsoleKeyExportService,
  createPostgresConsoleRuntimeSnapshotService,
  createPostgresConsoleSettingsService,
  createPostgresConsoleSmartWalletService,
} from '@server/router/express-adaptor';
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
    await pool.query('DELETE FROM console_key_exports WHERE namespace = $1', [namespace]);
    await pool.query('DELETE FROM console_environment_settings WHERE namespace = $1', [namespace]);
    await pool.query('DELETE FROM console_runtime_snapshots WHERE namespace = $1', [namespace]);
    await pool.query('DELETE FROM console_smart_wallet_configs WHERE namespace = $1', [namespace]);
    await pool.query('DELETE FROM console_gas_sponsorship_configs WHERE namespace = $1', [
      namespace,
    ]);
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

  test('settings postgres service persists app + security settings', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const service = await createPostgresConsoleSettingsService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
    });

    const initialApp = await service.getAppSettings(adminCtx, { environmentId: 'prod' });
    expect(initialApp.environmentId).toBe('prod');
    expect(initialApp.cookie.httpOnly).toBe(true);

    const updatedApp = await service.updateAppSettings(adminCtx, {
      environmentId: 'prod',
      allowedOrigins: ['https://dashboard.example.com', 'https://api.example.com'],
      allowedDomains: ['example.com'],
      cookie: {
        sameSite: 'STRICT',
      },
      jwt: {
        issuer: 'https://issuer.example.com',
        audience: ['dashboard', 'api'],
      },
      ssoMetadataUrl: 'https://sso.example.com/metadata.xml',
    });
    expect(updatedApp.allowedOrigins).toEqual([
      'https://dashboard.example.com',
      'https://api.example.com',
    ]);
    expect(updatedApp.cookie.sameSite).toBe('STRICT');
    expect(updatedApp.jwt.issuer).toBe('https://issuer.example.com');

    const updatedSecurity = await service.updateSecuritySettings(adminCtx, {
      environmentId: 'prod',
      ipAllowlist: ['203.0.113.1/32'],
      enforceIpAllowlist: true,
      requireMfaForRiskyChanges: true,
      riskyChangeApproval: {
        approvalsRequired: 2,
        requireAdmin: true,
        requireMfa: true,
      },
    });
    expect(updatedSecurity.enforceIpAllowlist).toBe(true);
    expect(updatedSecurity.ipAllowlist).toEqual(['203.0.113.1/32']);
    expect(updatedSecurity.riskyChangeApproval.approvalsRequired).toBe(2);

    const readSecurity = await service.getSecuritySettings(adminCtx, { environmentId: 'prod' });
    expect(readSecurity.enforceIpAllowlist).toBe(true);
    expect(readSecurity.ipAllowlist).toEqual(['203.0.113.1/32']);
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
        settings: {
          enforceMfa: true,
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
        settings: {
          enforceMfa: false,
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
    const settingsService = await createPostgresConsoleSettingsService({
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
      orgId: `${orgId}:owner`,
      actorUserId: 'owner-config-modules',
      roles: ['admin'],
    };
    const attackerCtx = {
      orgId: `${orgId}:attacker`,
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

    const ownerUpdatedApp = await settingsService.updateAppSettings(ownerCtx, {
      environmentId: ownerEnvironmentId,
      allowedOrigins: ['https://owner.example.com'],
    });
    expect(ownerUpdatedApp.allowedOrigins).toEqual(['https://owner.example.com']);

    const ownerUpdatedSecurity = await settingsService.updateSecuritySettings(ownerCtx, {
      environmentId: ownerEnvironmentId,
      requireMfaForRiskyChanges: false,
    });
    expect(ownerUpdatedSecurity.requireMfaForRiskyChanges).toBe(false);

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
        settings: { enforceMfa: true },
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

    const attackerAppBefore = await settingsService.getAppSettings(attackerCtx, {
      environmentId: ownerEnvironmentId,
    });
    expect(attackerAppBefore.allowedOrigins).toEqual([]);
    expect(attackerAppBefore.jwt.issuer).toContain(attackerCtx.orgId);

    const attackerSecurityBefore = await settingsService.getSecuritySettings(attackerCtx, {
      environmentId: ownerEnvironmentId,
    });
    expect(attackerSecurityBefore.requireMfaForRiskyChanges).toBe(true);

    const attackerUpdatedApp = await settingsService.updateAppSettings(attackerCtx, {
      environmentId: ownerEnvironmentId,
      allowedOrigins: ['https://attacker.example.com'],
    });
    expect(attackerUpdatedApp.allowedOrigins).toEqual(['https://attacker.example.com']);

    const ownerAppAfterAttackerUpdate = await settingsService.getAppSettings(ownerCtx, {
      environmentId: ownerEnvironmentId,
    });
    expect(ownerAppAfterAttackerUpdate.allowedOrigins).toEqual(['https://owner.example.com']);

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

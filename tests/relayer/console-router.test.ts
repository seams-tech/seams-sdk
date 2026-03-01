import { test, expect } from '@playwright/test';
import {
  createConsoleRouter,
  createInMemoryConsoleApiKeyService,
  createInMemoryConsoleBillingService,
  createInMemoryConsoleGasSponsorshipService,
  createInMemoryConsoleKeyExportService,
  createInMemoryConsoleOrgProjectEnvService,
  createInMemoryConsolePolicyService,
  createInMemoryConsoleRuntimeSnapshotService,
  createInMemoryConsoleSettingsService,
  createInMemoryConsoleSmartWalletService,
  createInMemoryConsoleWalletService,
  createInMemoryConsoleWebhookService,
  createPostgresConsoleApiKeyService,
  createPostgresConsoleBillingService,
  createPostgresConsoleOrgProjectEnvService,
  createPostgresConsolePolicyService,
  createPostgresConsoleWalletService,
  createPostgresConsoleWebhookService,
  type ConsoleApiKeyService,
  type ConsoleAuthAdapter,
  type ConsoleBillingService,
  type ConsoleOrgProjectEnvService,
  type ConsolePolicyService,
  type ConsoleWalletService,
  type ConsoleWebhookService,
} from '@server/router/express-adaptor';
import { createCloudflareConsoleRouter } from '@server/router/cloudflare-adaptor';
import { callCf, fetchJson, getPath, startExpressRouter } from './helpers';
import { getPostgresPool } from '../../server/src/storage/postgres';
import { withConsoleTenantContextTx } from '../../server/src/console/shared/postgresTenantContext';

function makeConsoleAuthAdapter(
  roles: string[],
  orgId = 'org-1',
  userId = 'user-1',
): ConsoleAuthAdapter {
  return {
    authenticate: async () => ({
      ok: true,
      claims: {
        userId,
        orgId,
        roles,
      },
    }),
  };
}

function randomNamespace(prefix: string): string {
  return `${prefix}:${Date.now()}:${Math.random().toString(16).slice(2)}`;
}

test.describe('console router (express)', () => {
  test('GET /console/healthz works and relay paths are isolated', async () => {
    const router = createConsoleRouter({ healthz: true });
    const srv = await startExpressRouter(router);
    try {
      const health = await fetchJson(`${srv.baseUrl}/console/healthz`, { method: 'GET' });
      expect(health.status).toBe(200);
      expect(health.json?.service).toBe('console');

      const relayPath = await fetchJson(`${srv.baseUrl}/auth/passkey/options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      expect(relayPath.status).toBe(404);
    } finally {
      await srv.close();
    }
  });

  test('GET /console/webhooks returns webhooks_not_configured without webhook service', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/webhooks`, { method: 'GET' });
      expect(res.status).toBe(501);
      expect(res.json?.code).toBe('webhooks_not_configured');
    } finally {
      await srv.close();
    }
  });

  test('GET /console/api-keys returns api_keys_not_configured without API key service', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/api-keys`, { method: 'GET' });
      expect(res.status).toBe(501);
      expect(res.json?.code).toBe('api_keys_not_configured');
    } finally {
      await srv.close();
    }
  });

  test('GET /console/org returns org_project_env_not_configured without org/project/env service', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/org`, { method: 'GET' });
      expect(res.status).toBe(501);
      expect(res.json?.code).toBe('org_project_env_not_configured');
    } finally {
      await srv.close();
    }
  });

  test('org/project/environment routes return hierarchical metadata', async () => {
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-meta-1', 'user-meta-1'),
      orgProjectEnv,
    });
    const srv = await startExpressRouter(router);
    try {
      const org = await fetchJson(`${srv.baseUrl}/console/org`, { method: 'GET' });
      expect(org.status).toBe(200);
      expect(getPath(org.json, 'org', 'id')).toBe('org-meta-1');

      const projects = await fetchJson(`${srv.baseUrl}/console/projects`, { method: 'GET' });
      expect(projects.status).toBe(200);
      const projectRows = Array.isArray(projects.json?.projects) ? projects.json?.projects : [];
      expect(projectRows.length).toBeGreaterThanOrEqual(1);
      const projectId = String(getPath(projects.json, 'projects', 0, 'id') || '');
      expect(projectId).toBeTruthy();
      expect(Number(getPath(projects.json, 'projects', 0, 'environmentCount') || 0)).toBeGreaterThanOrEqual(
        1,
      );

      const environments = await fetchJson(`${srv.baseUrl}/console/environments`, {
        method: 'GET',
      });
      expect(environments.status).toBe(200);
      const environmentRows = Array.isArray(environments.json?.environments)
        ? environments.json?.environments
        : [];
      expect(environmentRows.length).toBeGreaterThanOrEqual(1);
      expect(String(getPath(environments.json, 'environments', 0, 'projectId') || '')).toBe(
        projectId,
      );

      const scoped = await fetchJson(
        `${srv.baseUrl}/console/environments?projectId=${encodeURIComponent(projectId)}`,
        {
          method: 'GET',
        },
      );
      expect(scoped.status).toBe(200);
      const scopedRows = Array.isArray(scoped.json?.environments) ? scoped.json?.environments : [];
      expect(scopedRows.length).toBeGreaterThanOrEqual(1);
      expect(scopedRows.every((entry: any) => String(entry?.projectId || '') === projectId)).toBe(
        true,
      );
    } finally {
      await srv.close();
    }
  });

  test('org/project/environment mutation routes enforce role and lifecycle rules', async () => {
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    const adminRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-meta-mutate-1', 'user-meta-mutate-1'),
      orgProjectEnv,
    });
    const adminServer = await startExpressRouter(adminRouter);
    try {
      const createdProject = await fetchJson(`${adminServer.baseUrl}/console/projects`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: 'project-mutate-1',
          name: 'Project Mutate',
        }),
      });
      expect(createdProject.status).toBe(201);
      expect(getPath(createdProject.json, 'project', 'id')).toBe('project-mutate-1');
      expect(getPath(createdProject.json, 'project', 'status')).toBe('ACTIVE');
      expect(Number(getPath(createdProject.json, 'project', 'environmentCount') || 0)).toBe(0);

      const createdEnvironment = await fetchJson(`${adminServer.baseUrl}/console/environments`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: 'env-mutate-1',
          projectId: 'project-mutate-1',
          key: 'staging',
        }),
      });
      expect(createdEnvironment.status).toBe(201);
      expect(getPath(createdEnvironment.json, 'environment', 'id')).toBe('env-mutate-1');

      const updatedProject = await fetchJson(
        `${adminServer.baseUrl}/console/projects/project-mutate-1`,
        {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: 'Project Mutate Renamed' }),
        },
      );
      expect(updatedProject.status).toBe(200);
      expect(getPath(updatedProject.json, 'project', 'name')).toBe('Project Mutate Renamed');

      const updatedEnvironment = await fetchJson(
        `${adminServer.baseUrl}/console/environments/env-mutate-1`,
        {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: 'Staging Renamed' }),
        },
      );
      expect(updatedEnvironment.status).toBe(200);
      expect(getPath(updatedEnvironment.json, 'environment', 'name')).toBe('Staging Renamed');

      const archivedProject = await fetchJson(
        `${adminServer.baseUrl}/console/projects/project-mutate-1/archive`,
        {
          method: 'POST',
        },
      );
      expect(archivedProject.status).toBe(200);
      expect(getPath(archivedProject.json, 'project', 'status')).toBe('ARCHIVED');

      const archivedProjects = await fetchJson(
        `${adminServer.baseUrl}/console/projects?status=ARCHIVED`,
        { method: 'GET' },
      );
      expect(archivedProjects.status).toBe(200);
      const archivedProjectRows = Array.isArray(archivedProjects.json?.projects)
        ? archivedProjects.json?.projects
        : [];
      expect(archivedProjectRows.length).toBeGreaterThanOrEqual(1);
      expect(archivedProjectRows.every((entry: any) => String(entry?.status || '') === 'ARCHIVED')).toBe(
        true,
      );

      const activeProjects = await fetchJson(`${adminServer.baseUrl}/console/projects?status=ACTIVE`, {
        method: 'GET',
      });
      expect(activeProjects.status).toBe(200);
      const activeProjectRows = Array.isArray(activeProjects.json?.projects)
        ? activeProjects.json?.projects
        : [];
      expect(activeProjectRows.every((entry: any) => String(entry?.status || '') === 'ACTIVE')).toBe(true);

      const invalidProjectStatus = await fetchJson(
        `${adminServer.baseUrl}/console/projects?status=INVALID`,
        {
          method: 'GET',
        },
      );
      expect(invalidProjectStatus.status).toBe(400);
      expect(invalidProjectStatus.json?.code).toBe('invalid_query');

      const archivedOnly = await fetchJson(
        `${adminServer.baseUrl}/console/environments?projectId=project-mutate-1&status=ARCHIVED`,
        { method: 'GET' },
      );
      expect(archivedOnly.status).toBe(200);
      const archivedRows = Array.isArray(archivedOnly.json?.environments)
        ? archivedOnly.json?.environments
        : [];
      expect(archivedRows.length).toBeGreaterThanOrEqual(1);
      expect(archivedRows.every((entry: any) => String(entry?.status || '') === 'ARCHIVED')).toBe(true);

      const activeOnly = await fetchJson(
        `${adminServer.baseUrl}/console/environments?projectId=project-mutate-1&status=ACTIVE`,
        { method: 'GET' },
      );
      expect(activeOnly.status).toBe(200);
      const activeRows = Array.isArray(activeOnly.json?.environments) ? activeOnly.json?.environments : [];
      expect(activeRows.length).toBe(0);

      const invalidStatus = await fetchJson(`${adminServer.baseUrl}/console/environments?status=INVALID`, {
        method: 'GET',
      });
      expect(invalidStatus.status).toBe(400);
      expect(invalidStatus.json?.code).toBe('invalid_query');

      const createOnArchived = await fetchJson(`${adminServer.baseUrl}/console/environments`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          projectId: 'project-mutate-1',
          key: 'prod',
        }),
      });
      expect(createOnArchived.status).toBe(409);
      expect(createOnArchived.json?.code).toBe('project_archived');
    } finally {
      await adminServer.close();
    }

    const devRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['developer'], 'org-meta-mutate-1', 'user-meta-dev-1'),
      orgProjectEnv,
    });
    const devServer = await startExpressRouter(devRouter);
    try {
      const forbidden = await fetchJson(`${devServer.baseUrl}/console/projects`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'Forbidden Project',
        }),
      });
      expect(forbidden.status).toBe(403);
      expect(forbidden.json?.code).toBe('forbidden');
    } finally {
      await devServer.close();
    }
  });

  test('GET /console/wallets returns wallets_not_configured without wallet service', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/wallets`, { method: 'GET' });
      expect(res.status).toBe(501);
      expect(res.json?.code).toBe('wallets_not_configured');
    } finally {
      await srv.close();
    }
  });

  test('GET /console/policies returns policies_not_configured without policy service', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/policies`, { method: 'GET' });
      expect(res.status).toBe(501);
      expect(res.json?.code).toBe('policies_not_configured');
    } finally {
      await srv.close();
    }
  });

  test('GET /console/policy/coverage returns wallets_not_configured without wallet service', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/policy/coverage`, { method: 'GET' });
      expect(res.status).toBe(501);
      expect(res.json?.code).toBe('wallets_not_configured');
    } finally {
      await srv.close();
    }
  });

  test('GET /console/export/governance returns api_keys_not_configured without API key service', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      wallets: createInMemoryConsoleWalletService(),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/export/governance`, { method: 'GET' });
      expect(res.status).toBe(501);
      expect(res.json?.code).toBe('api_keys_not_configured');
    } finally {
      await srv.close();
    }
  });

  test('new console endpoints return *_not_configured when services are not wired', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const srv = await startExpressRouter(router);
    try {
      const gas = await fetchJson(`${srv.baseUrl}/console/gas-sponsorship`, { method: 'GET' });
      expect(gas.status).toBe(501);
      expect(gas.json?.code).toBe('gas_sponsorship_not_configured');

      const smartWallets = await fetchJson(`${srv.baseUrl}/console/smart-wallets`, { method: 'GET' });
      expect(smartWallets.status).toBe(501);
      expect(smartWallets.json?.code).toBe('smart_wallets_not_configured');

      const settings = await fetchJson(
        `${srv.baseUrl}/console/settings/app?environmentId=${encodeURIComponent('env-test')}`,
        { method: 'GET' },
      );
      expect(settings.status).toBe(501);
      expect(settings.json?.code).toBe('settings_not_configured');

      const keyExports = await fetchJson(`${srv.baseUrl}/console/key-exports`, { method: 'GET' });
      expect(keyExports.status).toBe(501);
      expect(keyExports.json?.code).toBe('key_exports_not_configured');

      const runtimeSnapshots = await fetchJson(
        `${srv.baseUrl}/console/runtime-snapshots?environmentId=${encodeURIComponent('env-test')}`,
        { method: 'GET' },
      );
      expect(runtimeSnapshots.status).toBe(501);
      expect(runtimeSnapshots.json?.code).toBe('runtime_snapshots_not_configured');
    } finally {
      await srv.close();
    }
  });

  test('new console endpoints support scaffold CRUD flows', async () => {
    const gasSponsorship = createInMemoryConsoleGasSponsorshipService();
    const smartWallets = createInMemoryConsoleSmartWalletService();
    const settings = createInMemoryConsoleSettingsService();
    const keyExports = createInMemoryConsoleKeyExportService();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-scaffold-express-1', 'user-scaffold-express-1'),
      gasSponsorship,
      smartWallets,
      settings,
      keyExports,
      runtimeSnapshots,
    });
    const srv = await startExpressRouter(router);
    try {
      const createdGas = await fetchJson(`${srv.baseUrl}/console/gas-sponsorship`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: 'gs-express-1',
          scopeType: 'ENVIRONMENT',
          environmentId: 'prod',
          enabled: true,
          chainBudgets: [
            {
              chain: 'Ethereum',
              period: 'MONTHLY',
              budgetMinor: 500000,
              quotaTransactions: 2000,
            },
          ],
        }),
      });
      expect(createdGas.status).toBe(201);
      expect(getPath(createdGas.json, 'config', 'id')).toBe('gs-express-1');

      const listedGas = await fetchJson(
        `${srv.baseUrl}/console/gas-sponsorship?environmentId=${encodeURIComponent('prod')}`,
        { method: 'GET' },
      );
      expect(listedGas.status).toBe(200);
      const listedGasRows: unknown[] = Array.isArray(listedGas.json?.configs)
        ? (listedGas.json?.configs as unknown[])
        : [];
      expect(listedGasRows.length).toBeGreaterThanOrEqual(1);

      const patchedGas = await fetchJson(`${srv.baseUrl}/console/gas-sponsorship/gs-express-1`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: false }),
      });
      expect(patchedGas.status).toBe(200);
      expect(getPath(patchedGas.json, 'config', 'enabled')).toBe(false);

      const createdSmartWallet = await fetchJson(`${srv.baseUrl}/console/smart-wallets`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: 'sw-express-1',
          scopeType: 'ENVIRONMENT',
          environmentId: 'prod',
          mode: 'REQUIRED',
          accountType: 'SMART_ACCOUNT',
        }),
      });
      expect(createdSmartWallet.status).toBe(201);
      expect(getPath(createdSmartWallet.json, 'config', 'id')).toBe('sw-express-1');

      const listedSmartWallets = await fetchJson(
        `${srv.baseUrl}/console/smart-wallets?environmentId=${encodeURIComponent('prod')}`,
        { method: 'GET' },
      );
      expect(listedSmartWallets.status).toBe(200);
      const listedSmartWalletRows: unknown[] = Array.isArray(listedSmartWallets.json?.configs)
        ? (listedSmartWallets.json?.configs as unknown[])
        : [];
      expect(listedSmartWalletRows.length).toBeGreaterThanOrEqual(1);

      const updatedAppSettings = await fetchJson(`${srv.baseUrl}/console/settings/app`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          environmentId: 'prod',
          allowedOrigins: ['https://dashboard.example.com'],
        }),
      });
      expect(updatedAppSettings.status).toBe(200);
      expect(getPath(updatedAppSettings.json, 'appSettings', 'environmentId')).toBe('prod');
      expect(getPath(updatedAppSettings.json, 'appSettings', 'allowedOrigins', 0)).toBe(
        'https://dashboard.example.com',
      );

      const fetchedSecuritySettings = await fetchJson(
        `${srv.baseUrl}/console/settings/security?environmentId=${encodeURIComponent('prod')}`,
        { method: 'GET' },
      );
      expect(fetchedSecuritySettings.status).toBe(200);
      expect(getPath(fetchedSecuritySettings.json, 'securitySettings', 'environmentId')).toBe('prod');

      const createdKeyExport = await fetchJson(`${srv.baseUrl}/console/key-exports`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: 'ke-express-1',
          environmentId: 'prod',
          reason: 'Emergency rotation',
          requiredApprovals: 1,
        }),
      });
      expect(createdKeyExport.status).toBe(201);
      expect(getPath(createdKeyExport.json, 'keyExport', 'status')).toBe('PENDING_APPROVAL');

      const approvedKeyExport = await fetchJson(
        `${srv.baseUrl}/console/key-exports/ke-express-1/approve`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            reason: 'Approved with MFA',
            mfaVerified: true,
          }),
        },
      );
      expect(approvedKeyExport.status).toBe(200);
      expect(getPath(approvedKeyExport.json, 'keyExport', 'status')).toBe('APPROVED');

      const publishedSnapshot = await fetchJson(
        `${srv.baseUrl}/console/runtime-snapshots/publish-current`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            environmentId: 'prod',
          }),
        },
      );
      expect(publishedSnapshot.status).toBe(201);
      expect(Number(getPath(publishedSnapshot.json, 'snapshot', 'version') || 0)).toBe(1);
      expect(String(getPath(publishedSnapshot.json, 'snapshot', 'checksum') || '')).toContain(
        'fnv1a32:',
      );
      expect(getPath(publishedSnapshot.json, 'snapshot', 'payload', 'settings', 'status')).toBe(
        'resolved',
      );
      expect(getPath(publishedSnapshot.json, 'snapshot', 'payload', 'gasSponsorship', 'status')).toBe(
        'resolved',
      );
      expect(getPath(publishedSnapshot.json, 'snapshot', 'payload', 'smartWallets', 'status')).toBe(
        'resolved',
      );
      expect(
        getPath(
          publishedSnapshot.json,
          'snapshot',
          'payload',
          'settings',
          'appSettings',
          'allowedOrigins',
          0,
        ),
      ).toBe('https://dashboard.example.com');

      const latestSnapshot = await fetchJson(
        `${srv.baseUrl}/console/runtime-snapshots/latest?environmentId=${encodeURIComponent('prod')}`,
        { method: 'GET' },
      );
      expect(latestSnapshot.status).toBe(200);
      expect(getPath(latestSnapshot.json, 'snapshot', 'environmentId')).toBe('prod');
      expect(Number(getPath(latestSnapshot.json, 'snapshot', 'version') || 0)).toBe(1);

      const listedSnapshots = await fetchJson(
        `${srv.baseUrl}/console/runtime-snapshots?environmentId=${encodeURIComponent('prod')}&limit=5`,
        { method: 'GET' },
      );
      expect(listedSnapshots.status).toBe(200);
      const snapshotRows = Array.isArray(listedSnapshots.json?.snapshots)
        ? listedSnapshots.json?.snapshots
        : [];
      expect(snapshotRows.length).toBeGreaterThanOrEqual(1);
    } finally {
      await srv.close();
    }
  });

  test('runtime snapshot publish-current emits not_configured markers and monotonic versions', async () => {
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-runtime-contract-express-1',
        'user-runtime-contract-express-1',
      ),
      runtimeSnapshots,
    });
    const srv = await startExpressRouter(router);
    try {
      const first = await fetchJson(`${srv.baseUrl}/console/runtime-snapshots/publish-current`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          environmentId: 'prod',
          projectId: 'project-alpha',
          snapshotId: 'runtime-contract-v1',
          effectiveAt: '2026-03-01T00:00:00.000Z',
        }),
      });
      expect(first.status).toBe(201);
      expect(getPath(first.json, 'snapshot', 'snapshotId')).toBe('runtime-contract-v1');
      expect(Number(getPath(first.json, 'snapshot', 'version') || 0)).toBe(1);
      expect(getPath(first.json, 'snapshot', 'payload', 'policy', 'status')).toBe('not_configured');
      expect(getPath(first.json, 'snapshot', 'payload', 'settings', 'status')).toBe(
        'not_configured',
      );
      expect(getPath(first.json, 'snapshot', 'payload', 'gasSponsorship', 'status')).toBe(
        'not_configured',
      );
      expect(getPath(first.json, 'snapshot', 'payload', 'smartWallets', 'status')).toBe(
        'not_configured',
      );
      const firstChecksum = String(getPath(first.json, 'snapshot', 'checksum') || '');
      expect(firstChecksum).toContain('fnv1a32:');

      const second = await fetchJson(`${srv.baseUrl}/console/runtime-snapshots/publish-current`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          environmentId: 'prod',
          projectId: 'project-alpha',
          snapshotId: 'runtime-contract-v2',
          effectiveAt: '2026-03-01T01:00:00.000Z',
        }),
      });
      expect(second.status).toBe(201);
      expect(getPath(second.json, 'snapshot', 'snapshotId')).toBe('runtime-contract-v2');
      expect(Number(getPath(second.json, 'snapshot', 'version') || 0)).toBe(2);
      expect(String(getPath(second.json, 'snapshot', 'checksum') || '')).not.toBe(firstChecksum);

      const latest = await fetchJson(
        `${srv.baseUrl}/console/runtime-snapshots/latest?environmentId=${encodeURIComponent('prod')}&projectId=${encodeURIComponent('project-alpha')}`,
        { method: 'GET' },
      );
      expect(latest.status).toBe(200);
      expect(getPath(latest.json, 'snapshot', 'snapshotId')).toBe('runtime-contract-v2');
      expect(Number(getPath(latest.json, 'snapshot', 'version') || 0)).toBe(2);

      const listed = await fetchJson(
        `${srv.baseUrl}/console/runtime-snapshots?environmentId=${encodeURIComponent('prod')}&projectId=${encodeURIComponent('project-alpha')}&limit=2`,
        { method: 'GET' },
      );
      expect(listed.status).toBe(200);
      expect(getPath(listed.json, 'snapshots', 0, 'snapshotId')).toBe('runtime-contract-v2');
      expect(getPath(listed.json, 'snapshots', 1, 'snapshotId')).toBe('runtime-contract-v1');
    } finally {
      await srv.close();
    }
  });

  test('new console endpoint mutations enforce role gates', async () => {
    const gasSponsorship = createInMemoryConsoleGasSponsorshipService();
    const smartWallets = createInMemoryConsoleSmartWalletService();
    const settings = createInMemoryConsoleSettingsService();
    const keyExports = createInMemoryConsoleKeyExportService();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['developer'],
        'org-scaffold-express-rbac-1',
        'user-scaffold-express-rbac-1',
      ),
      gasSponsorship,
      smartWallets,
      settings,
      keyExports,
      runtimeSnapshots,
    });
    const srv = await startExpressRouter(router);
    try {
      const gasCreate = await fetchJson(`${srv.baseUrl}/console/gas-sponsorship`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scopeType: 'ORG',
        }),
      });
      expect(gasCreate.status).toBe(403);
      expect(gasCreate.json?.code).toBe('forbidden');

      const appPatch = await fetchJson(`${srv.baseUrl}/console/settings/app`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          environmentId: 'prod',
          allowedOrigins: ['https://dashboard.example.com'],
        }),
      });
      expect(appPatch.status).toBe(403);
      expect(appPatch.json?.code).toBe('forbidden');

      const approve = await fetchJson(
        `${srv.baseUrl}/console/key-exports/ke-express-rbac-1/approve`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            reason: 'trying as non-admin',
            mfaVerified: true,
          }),
        },
      );
      expect(approve.status).toBe(403);
      expect(approve.json?.code).toBe('forbidden');

      const publishSnapshot = await fetchJson(`${srv.baseUrl}/console/runtime-snapshots/publish`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          environmentId: 'prod',
          payload: {
            policy: {},
            settings: {},
            gasSponsorship: {},
            smartWallets: {},
          },
        }),
      });
      expect(publishSnapshot.status).toBe(403);
      expect(publishSnapshot.json?.code).toBe('forbidden');

      const publishCurrentSnapshot = await fetchJson(
        `${srv.baseUrl}/console/runtime-snapshots/publish-current`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            environmentId: 'prod',
          }),
        },
      );
      expect(publishCurrentSnapshot.status).toBe(403);
      expect(publishCurrentSnapshot.json?.code).toBe('forbidden');
    } finally {
      await srv.close();
    }
  });

  test('new console endpoint validation errors return typed error codes', async () => {
    const gasSponsorship = createInMemoryConsoleGasSponsorshipService();
    const smartWallets = createInMemoryConsoleSmartWalletService();
    const settings = createInMemoryConsoleSettingsService();
    const keyExports = createInMemoryConsoleKeyExportService();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-scaffold-express-validation-1',
        'user-scaffold-express-validation-1',
      ),
      gasSponsorship,
      smartWallets,
      settings,
      keyExports,
      runtimeSnapshots,
    });
    const srv = await startExpressRouter(router);
    try {
      const invalidGasScope = await fetchJson(`${srv.baseUrl}/console/gas-sponsorship`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scopeType: 'ENVIRONMENT',
        }),
      });
      expect(invalidGasScope.status).toBe(400);
      expect(invalidGasScope.json?.code).toBe('invalid_scope');

      const invalidAppPatch = await fetchJson(`${srv.baseUrl}/console/settings/app`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          allowedOrigins: ['https://dashboard.example.com'],
        }),
      });
      expect(invalidAppPatch.status).toBe(400);
      expect(invalidAppPatch.json?.code).toBe('invalid_body');

      const invalidStatusQuery = await fetchJson(
        `${srv.baseUrl}/console/key-exports?status=NOT_A_STATUS`,
        {
          method: 'GET',
        },
      );
      expect(invalidStatusQuery.status).toBe(400);
      expect(invalidStatusQuery.json?.code).toBe('invalid_query');

      const createdKeyExport = await fetchJson(`${srv.baseUrl}/console/key-exports`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: 'ke-express-validation-1',
          environmentId: 'prod',
          reason: 'Validation flow',
          requiredApprovals: 1,
        }),
      });
      expect(createdKeyExport.status).toBe(201);

      const approveWithoutMfa = await fetchJson(
        `${srv.baseUrl}/console/key-exports/ke-express-validation-1/approve`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            reason: 'Missing MFA check',
            mfaVerified: false,
          }),
        },
      );
      expect(approveWithoutMfa.status).toBe(400);
      expect(approveWithoutMfa.json?.code).toBe('mfa_required');

      const invalidSnapshotQuery = await fetchJson(
        `${srv.baseUrl}/console/runtime-snapshots?environmentId=${encodeURIComponent('prod')}&limit=999`,
        { method: 'GET' },
      );
      expect(invalidSnapshotQuery.status).toBe(400);
      expect(invalidSnapshotQuery.json?.code).toBe('invalid_query');

      const invalidSnapshotBody = await fetchJson(`${srv.baseUrl}/console/runtime-snapshots/publish`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          environmentId: 'prod',
          payload: {
            policy: {},
          },
        }),
      });
      expect(invalidSnapshotBody.status).toBe(400);
      expect(invalidSnapshotBody.json?.code).toBe('invalid_body');

      const invalidPublishCurrentBody = await fetchJson(
        `${srv.baseUrl}/console/runtime-snapshots/publish-current`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            projectId: 'project-only',
          }),
        },
      );
      expect(invalidPublishCurrentBody.status).toBe(400);
      expect(invalidPublishCurrentBody.json?.code).toBe('invalid_body');
    } finally {
      await srv.close();
    }
  });

  test('new console endpoints enforce org isolation', async () => {
    const gasSponsorship = createInMemoryConsoleGasSponsorshipService();
    const smartWallets = createInMemoryConsoleSmartWalletService();
    const settings = createInMemoryConsoleSettingsService();
    const keyExports = createInMemoryConsoleKeyExportService();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    const ownerOrgId = 'org-scaffold-express-isolation-owner';
    const attackerOrgId = 'org-scaffold-express-isolation-attacker';
    const ownerEnvironmentId = 'env-isolation-owner';

    const ownerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-scaffold-express-isolation-user'),
      gasSponsorship,
      smartWallets,
      settings,
      keyExports,
      runtimeSnapshots,
    });
    const ownerServer = await startExpressRouter(ownerRouter);
    try {
      const createGas = await fetchJson(`${ownerServer.baseUrl}/console/gas-sponsorship`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: 'gs-express-isolation-1',
          scopeType: 'ENVIRONMENT',
          environmentId: ownerEnvironmentId,
        }),
      });
      expect(createGas.status).toBe(201);

      const createSmartWallet = await fetchJson(`${ownerServer.baseUrl}/console/smart-wallets`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: 'sw-express-isolation-1',
          scopeType: 'ENVIRONMENT',
          environmentId: ownerEnvironmentId,
          mode: 'REQUIRED',
          accountType: 'SMART_ACCOUNT',
        }),
      });
      expect(createSmartWallet.status).toBe(201);

      const patchAppSettings = await fetchJson(`${ownerServer.baseUrl}/console/settings/app`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          environmentId: ownerEnvironmentId,
          allowedOrigins: ['https://owner.example.com'],
        }),
      });
      expect(patchAppSettings.status).toBe(200);

      const patchSecuritySettings = await fetchJson(
        `${ownerServer.baseUrl}/console/settings/security`,
        {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            environmentId: ownerEnvironmentId,
            requireMfaForRiskyChanges: false,
          }),
        },
      );
      expect(patchSecuritySettings.status).toBe(200);

      const createKeyExport = await fetchJson(`${ownerServer.baseUrl}/console/key-exports`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: 'ke-express-isolation-1',
          environmentId: ownerEnvironmentId,
          reason: 'Owner export request',
          requiredApprovals: 1,
        }),
      });
      expect(createKeyExport.status).toBe(201);

      const publishSnapshot = await fetchJson(
        `${ownerServer.baseUrl}/console/runtime-snapshots/publish-current`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            environmentId: ownerEnvironmentId,
          }),
        },
      );
      expect(publishSnapshot.status).toBe(201);
    } finally {
      await ownerServer.close();
    }

    const attackerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        attackerOrgId,
        'attacker-scaffold-express-isolation-user',
      ),
      gasSponsorship,
      smartWallets,
      settings,
      keyExports,
      runtimeSnapshots,
    });
    const attackerServer = await startExpressRouter(attackerRouter);
    try {
      const gasList = await fetchJson(
        `${attackerServer.baseUrl}/console/gas-sponsorship?environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
        { method: 'GET' },
      );
      expect(gasList.status).toBe(200);
      const attackerGasRows = Array.isArray(gasList.json?.configs) ? gasList.json?.configs : [];
      expect(attackerGasRows.length).toBe(0);

      const patchGas = await fetchJson(
        `${attackerServer.baseUrl}/console/gas-sponsorship/gs-express-isolation-1`,
        {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ enabled: false }),
        },
      );
      expect(patchGas.status).toBe(404);
      expect(patchGas.json?.code).toBe('gas_sponsorship_not_found');

      const smartWalletList = await fetchJson(
        `${attackerServer.baseUrl}/console/smart-wallets?environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
        { method: 'GET' },
      );
      expect(smartWalletList.status).toBe(200);
      const attackerSmartWalletRows = Array.isArray(smartWalletList.json?.configs)
        ? smartWalletList.json?.configs
        : [];
      expect(attackerSmartWalletRows.length).toBe(0);

      const patchSmartWallet = await fetchJson(
        `${attackerServer.baseUrl}/console/smart-wallets/sw-express-isolation-1`,
        {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ enabled: false }),
        },
      );
      expect(patchSmartWallet.status).toBe(404);
      expect(patchSmartWallet.json?.code).toBe('smart_wallet_config_not_found');

      const getAppSettings = await fetchJson(
        `${attackerServer.baseUrl}/console/settings/app?environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
        { method: 'GET' },
      );
      expect(getAppSettings.status).toBe(200);
      expect(getPath(getAppSettings.json, 'appSettings', 'allowedOrigins', 0)).toBeUndefined();

      const getSecuritySettings = await fetchJson(
        `${attackerServer.baseUrl}/console/settings/security?environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
        { method: 'GET' },
      );
      expect(getSecuritySettings.status).toBe(200);
      expect(getPath(getSecuritySettings.json, 'securitySettings', 'requireMfaForRiskyChanges')).toBe(
        true,
      );

      const keyExportsList = await fetchJson(
        `${attackerServer.baseUrl}/console/key-exports?environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
        { method: 'GET' },
      );
      expect(keyExportsList.status).toBe(200);
      const attackerKeyExportRows = Array.isArray(keyExportsList.json?.exports)
        ? keyExportsList.json?.exports
        : [];
      expect(attackerKeyExportRows.length).toBe(0);

      const approveKeyExport = await fetchJson(
        `${attackerServer.baseUrl}/console/key-exports/ke-express-isolation-1/approve`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            reason: 'attacker approve attempt',
            mfaVerified: true,
          }),
        },
      );
      expect(approveKeyExport.status).toBe(404);
      expect(approveKeyExport.json?.code).toBe('key_export_not_found');

      const attackerSnapshots = await fetchJson(
        `${attackerServer.baseUrl}/console/runtime-snapshots?environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
        { method: 'GET' },
      );
      expect(attackerSnapshots.status).toBe(200);
      const attackerSnapshotRows = Array.isArray(attackerSnapshots.json?.snapshots)
        ? attackerSnapshots.json?.snapshots
        : [];
      expect(attackerSnapshotRows.length).toBe(0);

      const attackerLatestSnapshot = await fetchJson(
        `${attackerServer.baseUrl}/console/runtime-snapshots/latest?environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
        { method: 'GET' },
      );
      expect(attackerLatestSnapshot.status).toBe(200);
      expect(attackerLatestSnapshot.json?.snapshot).toBeNull();
    } finally {
      await attackerServer.close();
    }
  });

  test('wallet routes support list/search/detail', async () => {
    const wallets = createInMemoryConsoleWalletService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-wallet-express-1', 'user-wallet-express-1'),
      wallets,
    });
    const srv = await startExpressRouter(router);
    try {
      const listed = await fetchJson(`${srv.baseUrl}/console/wallets?limit=5&chain=Ethereum`, {
        method: 'GET',
      });
      expect(listed.status).toBe(200);
      const rows = Array.isArray(listed.json?.wallets) ? listed.json?.wallets : [];
      expect(rows.length).toBeGreaterThanOrEqual(1);
      const walletId = String(getPath(listed.json, 'wallets', 0, 'id') || '');
      expect(walletId).toBeTruthy();

      const searched = await fetchJson(
        `${srv.baseUrl}/console/wallets/search?q=${encodeURIComponent(walletId.slice(0, 10))}`,
        { method: 'GET' },
      );
      expect(searched.status).toBe(200);
      const searchedRows = Array.isArray(searched.json?.wallets) ? searched.json?.wallets : [];
      expect(searchedRows.some((entry: any) => String(entry?.id || '') === walletId)).toBe(true);

      const detail = await fetchJson(
        `${srv.baseUrl}/console/wallets/${encodeURIComponent(walletId)}`,
        { method: 'GET' },
      );
      expect(detail.status).toBe(200);
      expect(String(getPath(detail.json, 'wallet', 'id') || '')).toBe(walletId);

      const missing = await fetchJson(`${srv.baseUrl}/console/wallets/wallet_missing`, {
        method: 'GET',
      });
      expect(missing.status).toBe(404);
      expect(missing.json?.code).toBe('wallet_not_found');
    } finally {
      await srv.close();
    }
  });

  test('policy/gas/export insight routes return aggregated views', async () => {
    const wallets = createInMemoryConsoleWalletService();
    const apiKeys = createInMemoryConsoleApiKeyService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-insights-express-1', 'user-insights-express-1'),
      wallets,
      apiKeys,
    });
    const srv = await startExpressRouter(router);
    try {
      const createdExportKey = await fetchJson(`${srv.baseUrl}/console/api-keys`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'export-key',
          environmentId: 'prod',
          scopes: ['wallets:read', 'keys:export'],
        }),
      });
      expect(createdExportKey.status).toBe(201);

      const createdNonExportKey = await fetchJson(`${srv.baseUrl}/console/api-keys`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'non-export-key',
          environmentId: 'staging',
          scopes: ['wallets:read'],
        }),
      });
      expect(createdNonExportKey.status).toBe(201);

      const coverage = await fetchJson(`${srv.baseUrl}/console/policy/coverage`, { method: 'GET' });
      expect(coverage.status).toBe(200);
      expect(Number(getPath(coverage.json, 'coverage', 'totals', 'walletCount') || 0)).toBeGreaterThanOrEqual(1);
      const policyRows: unknown[] = Array.isArray(getPath(coverage.json, 'coverage', 'policies'))
        ? (getPath(coverage.json, 'coverage', 'policies') as unknown[])
        : [];
      expect(policyRows.length).toBeGreaterThanOrEqual(1);

      const readiness = await fetchJson(`${srv.baseUrl}/console/gas/readiness`, { method: 'GET' });
      expect(readiness.status).toBe(200);
      expect(Number(getPath(readiness.json, 'readiness', 'totals', 'walletCount') || 0)).toBeGreaterThanOrEqual(1);
      const chainRows: unknown[] = Array.isArray(getPath(readiness.json, 'readiness', 'chains'))
        ? (getPath(readiness.json, 'readiness', 'chains') as unknown[])
        : [];
      expect(chainRows.length).toBeGreaterThanOrEqual(1);

      const governance = await fetchJson(
        `${srv.baseUrl}/console/export/governance?environmentId=prod`,
        {
          method: 'GET',
        },
      );
      expect(governance.status).toBe(200);
      expect(Number(getPath(governance.json, 'governance', 'totals', 'apiKeyCount') || 0)).toBe(2);
      expect(
        Number(getPath(governance.json, 'governance', 'totals', 'exportScopedKeyCount') || 0),
      ).toBe(1);
      expect(
        Number(
          getPath(
            governance.json,
            'governance',
            'totals',
            'selectedEnvironmentExportScopedKeyCount',
          ) || 0,
        ),
      ).toBe(1);
    } finally {
      await srv.close();
    }
  });

  test('policy routes support draft/update/simulate/publish lifecycle with role gates', async () => {
    const policies = createInMemoryConsolePolicyService();
    const adminRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-policy-express-1', 'user-policy-admin-1'),
      policies,
    });
    const adminServer = await startExpressRouter(adminRouter);
    try {
      const listed = await fetchJson(`${adminServer.baseUrl}/console/policies`, { method: 'GET' });
      expect(listed.status).toBe(200);
      const policiesBefore = Array.isArray(listed.json?.policies) ? listed.json?.policies : [];
      expect(policiesBefore.length).toBeGreaterThanOrEqual(1);

      const created = await fetchJson(`${adminServer.baseUrl}/console/policies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: 'policy-express-lifecycle-1',
          name: 'Policy Express Lifecycle',
          rules: {
            blockedActions: [],
            allowedChains: ['ethereum'],
            maxAmountMinor: 5000,
          },
        }),
      });
      expect(created.status).toBe(201);
      expect(getPath(created.json, 'policy', 'id')).toBe('policy-express-lifecycle-1');
      expect(getPath(created.json, 'policy', 'status')).toBe('DRAFT');
      expect(Number(getPath(created.json, 'policy', 'version') || 0)).toBe(0);

      const allowedSimulation = await fetchJson(
        `${adminServer.baseUrl}/console/policies/policy-express-lifecycle-1/simulate`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            action: 'transfer',
            chain: 'ethereum',
            amountMinor: 4000,
          }),
        },
      );
      expect(allowedSimulation.status).toBe(200);
      expect(getPath(allowedSimulation.json, 'simulation', 'decision')).toBe('ALLOW');

      const patched = await fetchJson(
        `${adminServer.baseUrl}/console/policies/policy-express-lifecycle-1`,
        {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            rules: {
              blockedActions: ['transfer'],
              allowedChains: ['ethereum'],
            },
          }),
        },
      );
      expect(patched.status).toBe(200);
      expect(getPath(patched.json, 'policy', 'status')).toBe('DRAFT');

      const deniedSimulation = await fetchJson(
        `${adminServer.baseUrl}/console/policies/policy-express-lifecycle-1/simulate`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            action: 'transfer',
            chain: 'ethereum',
            amountMinor: 1,
          }),
        },
      );
      expect(deniedSimulation.status).toBe(200);
      expect(getPath(deniedSimulation.json, 'simulation', 'decision')).toBe('DENY');

      const published = await fetchJson(
        `${adminServer.baseUrl}/console/policies/policy-express-lifecycle-1/publish`,
        {
          method: 'POST',
        },
      );
      expect(published.status).toBe(200);
      expect(getPath(published.json, 'result', 'published')).toBe(true);
      expect(getPath(published.json, 'result', 'policy', 'status')).toBe('PUBLISHED');
      expect(Number(getPath(published.json, 'result', 'policy', 'version') || 0)).toBe(1);
    } finally {
      await adminServer.close();
    }

    const developerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['developer'], 'org-policy-express-1', 'user-policy-dev-1'),
      policies,
    });
    const developerServer = await startExpressRouter(developerRouter);
    try {
      const forbiddenCreate = await fetchJson(`${developerServer.baseUrl}/console/policies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: 'policy-express-forbidden-1',
          name: 'Forbidden policy',
        }),
      });
      expect(forbiddenCreate.status).toBe(403);
      expect(forbiddenCreate.json?.code).toBe('forbidden');
    } finally {
      await developerServer.close();
    }
  });

  test('policy routes enforce org isolation', async () => {
    const policies = createInMemoryConsolePolicyService();
    const ownerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-policy-owner-express', 'owner-policy-user'),
      policies,
    });
    const ownerServer = await startExpressRouter(ownerRouter);
    const ownerPolicyId = 'policy-owner-express-isolation-1';
    try {
      const created = await fetchJson(`${ownerServer.baseUrl}/console/policies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: ownerPolicyId,
          name: 'Owner Policy',
        }),
      });
      expect(created.status).toBe(201);
    } finally {
      await ownerServer.close();
    }

    const attackerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-policy-attacker-express',
        'attacker-policy-user',
      ),
      policies,
    });
    const attackerServer = await startExpressRouter(attackerRouter);
    try {
      const listed = await fetchJson(`${attackerServer.baseUrl}/console/policies`, { method: 'GET' });
      expect(listed.status).toBe(200);
      const attackerPolicies = Array.isArray(listed.json?.policies) ? listed.json?.policies : [];
      expect(
        attackerPolicies.some((entry: any) => String(entry?.id || '') === ownerPolicyId),
      ).toBe(false);

      const patched = await fetchJson(
        `${attackerServer.baseUrl}/console/policies/${encodeURIComponent(ownerPolicyId)}`,
        {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: 'attacker update' }),
        },
      );
      expect(patched.status).toBe(404);
      expect(patched.json?.code).toBe('policy_not_found');

      const simulated = await fetchJson(
        `${attackerServer.baseUrl}/console/policies/${encodeURIComponent(ownerPolicyId)}/simulate`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ action: 'transfer' }),
        },
      );
      expect(simulated.status).toBe(404);
      expect(simulated.json?.code).toBe('policy_not_found');
    } finally {
      await attackerServer.close();
    }
  });

  test('policy assignments support precedence and drive policy coverage', async () => {
    const policies = createInMemoryConsolePolicyService();
    const wallets = createInMemoryConsoleWalletService();
    const adminRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-policy-assign-express', 'policy-assign-admin'),
      policies,
      wallets,
    });
    const adminServer = await startExpressRouter(adminRouter);
    try {
      const listedWallets = await fetchJson(`${adminServer.baseUrl}/console/wallets`, {
        method: 'GET',
      });
      expect(listedWallets.status).toBe(200);
      const walletId = String(getPath(listedWallets.json, 'wallets', 0, 'id') || '');
      const projectId = String(getPath(listedWallets.json, 'wallets', 0, 'projectId') || '');
      const environmentId = String(getPath(listedWallets.json, 'wallets', 0, 'environmentId') || '');
      expect(walletId).toBeTruthy();
      expect(projectId).toBeTruthy();
      expect(environmentId).toBeTruthy();

      const createProjectPolicy = await fetchJson(`${adminServer.baseUrl}/console/policies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: 'policy-project-express-1',
          name: 'Project Policy Express',
        }),
      });
      expect(createProjectPolicy.status).toBe(201);
      const createWalletPolicy = await fetchJson(`${adminServer.baseUrl}/console/policies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: 'policy-wallet-express-1',
          name: 'Wallet Policy Express',
        }),
      });
      expect(createWalletPolicy.status).toBe(201);

      const projectAssignment = await fetchJson(`${adminServer.baseUrl}/console/policies/assignments`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scopeType: 'PROJECT',
          scopeId: projectId,
          policyId: 'policy-project-express-1',
        }),
      });
      expect(projectAssignment.status).toBe(200);

      const walletAssignment = await fetchJson(`${adminServer.baseUrl}/console/policies/assignments`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scopeType: 'WALLET',
          scopeId: walletId,
          policyId: 'policy-wallet-express-1',
        }),
      });
      expect(walletAssignment.status).toBe(200);
      const walletAssignmentId = String(getPath(walletAssignment.json, 'assignment', 'id') || '');
      expect(walletAssignmentId).toBeTruthy();

      const listedAssignments = await fetchJson(
        `${adminServer.baseUrl}/console/policies/assignments?scopeType=WALLET&scopeId=${encodeURIComponent(walletId)}`,
        { method: 'GET' },
      );
      expect(listedAssignments.status).toBe(200);
      const assignmentRows = Array.isArray(listedAssignments.json?.assignments)
        ? listedAssignments.json?.assignments
        : [];
      expect(assignmentRows.length).toBe(1);
      expect(String(getPath(listedAssignments.json, 'assignments', 0, 'policyId') || '')).toBe(
        'policy-wallet-express-1',
      );

      const walletCoverage = await fetchJson(
        `${adminServer.baseUrl}/console/policy/coverage?projectId=${encodeURIComponent(projectId)}&environmentId=${encodeURIComponent(environmentId)}`,
        { method: 'GET' },
      );
      expect(walletCoverage.status).toBe(200);
      const policyRows = Array.isArray(getPath(walletCoverage.json, 'coverage', 'policies'))
        ? (getPath(walletCoverage.json, 'coverage', 'policies') as any[])
        : [];
      expect(policyRows.some((entry) => String(entry?.policyId || '') === 'policy-wallet-express-1')).toBe(
        true,
      );

      const removedWalletAssignment = await fetchJson(
        `${adminServer.baseUrl}/console/policies/assignments/${encodeURIComponent(walletAssignmentId)}`,
        {
          method: 'DELETE',
        },
      );
      expect(removedWalletAssignment.status).toBe(200);
      expect(getPath(removedWalletAssignment.json, 'removed')).toBe(true);

      const projectCoverage = await fetchJson(
        `${adminServer.baseUrl}/console/policy/coverage?projectId=${encodeURIComponent(projectId)}&environmentId=${encodeURIComponent(environmentId)}`,
        { method: 'GET' },
      );
      expect(projectCoverage.status).toBe(200);
      const projectPolicyRows = Array.isArray(getPath(projectCoverage.json, 'coverage', 'policies'))
        ? (getPath(projectCoverage.json, 'coverage', 'policies') as any[])
        : [];
      expect(projectPolicyRows.some((entry) => String(entry?.policyId || '') === 'policy-project-express-1')).toBe(
        true,
      );
    } finally {
      await adminServer.close();
    }

    const developerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['developer'],
        'org-policy-assign-express',
        'policy-assign-developer',
      ),
      policies,
      wallets,
    });
    const developerServer = await startExpressRouter(developerRouter);
    try {
      const forbiddenAssignment = await fetchJson(`${developerServer.baseUrl}/console/policies/assignments`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scopeType: 'ORG',
          scopeId: 'org-policy-assign-express',
          policyId: 'org-policy-assign-express:policy:default',
        }),
      });
      expect(forbiddenAssignment.status).toBe(403);
      expect(forbiddenAssignment.json?.code).toBe('forbidden');
    } finally {
      await developerServer.close();
    }
  });

  test('API key lifecycle works and secrets are reveal-once on create/rotate', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      apiKeys,
    });
    const srv = await startExpressRouter(router);
    try {
      const created = await fetchJson(`${srv.baseUrl}/console/api-keys`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'server-key',
          environmentId: 'prod',
          scopes: ['wallets:read', 'billing:read'],
          ipAllowlist: ['203.0.113.10/32'],
        }),
      });
      expect(created.status).toBe(201);
      const keyId = String(getPath(created.json, 'apiKey', 'id') || '');
      const createdSecret = String(getPath(created.json, 'secret') || '');
      expect(keyId).toBeTruthy();
      expect(createdSecret).toContain('tsk_');
      expect(Number(getPath(created.json, 'apiKey', 'secretVersion') || 0)).toBe(1);

      const listed = await fetchJson(`${srv.baseUrl}/console/api-keys`, { method: 'GET' });
      expect(listed.status).toBe(200);
      expect(Array.isArray(listed.json?.apiKeys)).toBe(true);
      expect(String(getPath(listed.json, 'apiKeys', 0, 'id') || '')).toBe(keyId);
      expect(getPath(listed.json, 'apiKeys', 0, 'secret')).toBeUndefined();

      const rotated = await fetchJson(
        `${srv.baseUrl}/console/api-keys/${encodeURIComponent(keyId)}/rotate`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ reason: 'scheduled rotation' }),
        },
      );
      expect(rotated.status).toBe(200);
      const rotatedSecret = String(getPath(rotated.json, 'secret') || '');
      expect(rotatedSecret).toContain('tsk_');
      expect(rotatedSecret).not.toBe(createdSecret);
      expect(Number(getPath(rotated.json, 'apiKey', 'secretVersion') || 0)).toBe(2);

      const revoked = await fetchJson(
        `${srv.baseUrl}/console/api-keys/${encodeURIComponent(keyId)}`,
        {
          method: 'DELETE',
        },
      );
      expect(revoked.status).toBe(200);
      expect(getPath(revoked.json, 'revoked')).toBe(true);
      expect(getPath(revoked.json, 'apiKey', 'status')).toBe('REVOKED');

      const rotateRevoked = await fetchJson(
        `${srv.baseUrl}/console/api-keys/${encodeURIComponent(keyId)}/rotate`,
        {
          method: 'POST',
        },
      );
      expect(rotateRevoked.status).toBe(409);
      expect(rotateRevoked.json?.code).toBe('api_key_revoked');
    } finally {
      await srv.close();
    }
  });

  test('webhook endpoint CRUD, deliveries, and replay flow works', async () => {
    let dispatchCalls = 0;
    const webhooks = createInMemoryConsoleWebhookService({
      dispatcher: {
        dispatch: async () => {
          dispatchCalls += 1;
          if (dispatchCalls === 1) {
            return {
              ok: false,
              statusCode: 500,
              responseBody: 'temporary failure',
              errorMessage: 'upstream failure',
            };
          }
          return {
            ok: true,
            statusCode: 200,
            responseBody: 'ok',
          };
        },
      },
    });
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      webhooks,
    });
    const srv = await startExpressRouter(router);
    try {
      const created = await fetchJson(`${srv.baseUrl}/console/webhooks`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: 'https://example.com/hook',
          subscriptions: ['billing'],
        }),
      });
      expect(created.status).toBe(201);
      const endpointId = String(getPath(created.json, 'endpoint', 'id') || '');
      expect(endpointId).toBeTruthy();

      const listed = await fetchJson(`${srv.baseUrl}/console/webhooks`, { method: 'GET' });
      expect(listed.status).toBe(200);
      const endpoints = Array.isArray(listed.json?.endpoints) ? listed.json?.endpoints : [];
      expect(endpoints.length).toBe(1);
      expect(String(getPath(listed.json, 'endpoints', 0, 'id') || '')).toBe(endpointId);

      const emitted = await webhooks.emitEvent(
        {
          orgId: 'org-1',
          actorUserId: 'system-webhooks-test',
          roles: ['ops'],
        },
        {
          eventType: 'billing.invoice.paid',
          payload: {
            invoiceId: 'inv_router_1',
          },
        },
      );
      expect(emitted.attempted).toBe(1);
      expect(emitted.delivered).toBe(0);
      expect(emitted.failed).toBe(1);

      const deliveries = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/deliveries`,
        {
          method: 'GET',
        },
      );
      expect(deliveries.status).toBe(200);
      const rows = Array.isArray(deliveries.json?.deliveries) ? deliveries.json?.deliveries : [];
      expect(rows.length).toBe(1);
      expect(String(getPath(deliveries.json, 'deliveries', 0, 'status') || '')).toBe('FAILED');
      expect(Number(getPath(deliveries.json, 'deliveries', 0, 'attemptCount') || 0)).toBe(1);
      const deliveryId = String(getPath(deliveries.json, 'deliveries', 0, 'id') || '');
      expect(deliveryId).toBeTruthy();

      const attemptsBeforeReplay = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/attempts`,
        {
          method: 'GET',
        },
      );
      expect(attemptsBeforeReplay.status).toBe(200);
      expect(Number(getPath(attemptsBeforeReplay.json, 'attempts', 0, 'attemptNo') || 0)).toBe(1);
      expect(getPath(attemptsBeforeReplay.json, 'attempts', 0, 'status')).toBe('FAILED');

      const unresolvedDlq = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/dead-letters`,
        {
          method: 'GET',
        },
      );
      expect(unresolvedDlq.status).toBe(200);
      const unresolvedRows = Array.isArray(unresolvedDlq.json?.deadLetters)
        ? unresolvedDlq.json?.deadLetters
        : [];
      expect(unresolvedRows.length).toBe(1);
      expect(getPath(unresolvedDlq.json, 'deadLetters', 0, 'deliveryId')).toBe(deliveryId);
      expect(getPath(unresolvedDlq.json, 'deadLetters', 0, 'resolvedAt')).toBeNull();

      const replayed = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/replay`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ deliveryId }),
        },
      );
      expect(replayed.status).toBe(200);
      expect(getPath(replayed.json, 'replay', 'replayed')).toBe(true);
      expect(getPath(replayed.json, 'replay', 'delivery', 'status')).toBe('SUCCEEDED');
      expect(Number(getPath(replayed.json, 'replay', 'delivery', 'attemptCount') || 0)).toBe(2);
      expect(Number(getPath(replayed.json, 'replay', 'delivery', 'replayCount') || 0)).toBe(1);

      const attemptsAfterReplay = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/attempts?deliveryId=${encodeURIComponent(deliveryId)}&limit=1`,
        {
          method: 'GET',
        },
      );
      expect(attemptsAfterReplay.status).toBe(200);
      const replayAttempts = Array.isArray(attemptsAfterReplay.json?.attempts)
        ? attemptsAfterReplay.json?.attempts
        : [];
      expect(replayAttempts.length).toBe(1);
      expect(Number(getPath(attemptsAfterReplay.json, 'attempts', 0, 'attemptNo') || 0)).toBe(2);
      expect(getPath(attemptsAfterReplay.json, 'attempts', 0, 'status')).toBe('SUCCEEDED');
      expect(getPath(attemptsAfterReplay.json, 'attempts', 0, 'isReplay')).toBe(true);
      const attemptsNextCursor = String(attemptsAfterReplay.json?.nextCursor || '');
      expect(attemptsNextCursor).toBeTruthy();

      const attemptsSecondPage = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/attempts?deliveryId=${encodeURIComponent(deliveryId)}&limit=1&cursor=${encodeURIComponent(attemptsNextCursor)}`,
        {
          method: 'GET',
        },
      );
      expect(attemptsSecondPage.status).toBe(200);
      const replayAttemptsSecondPage = Array.isArray(attemptsSecondPage.json?.attempts)
        ? attemptsSecondPage.json?.attempts
        : [];
      expect(replayAttemptsSecondPage.length).toBe(1);
      expect(Number(getPath(attemptsSecondPage.json, 'attempts', 0, 'attemptNo') || 0)).toBe(1);
      expect(String(attemptsSecondPage.json?.nextCursor || '')).toBe('');

      const unresolvedAfterReplay = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/dead-letters`,
        {
          method: 'GET',
        },
      );
      expect(unresolvedAfterReplay.status).toBe(200);
      const unresolvedRowsAfterReplay = Array.isArray(unresolvedAfterReplay.json?.deadLetters)
        ? unresolvedAfterReplay.json?.deadLetters
        : [];
      expect(unresolvedRowsAfterReplay.length).toBe(0);

      const resolvedDlq = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/dead-letters?includeResolved=true`,
        {
          method: 'GET',
        },
      );
      expect(resolvedDlq.status).toBe(200);
      const resolvedRows = Array.isArray(resolvedDlq.json?.deadLetters)
        ? resolvedDlq.json?.deadLetters
        : [];
      expect(resolvedRows.length).toBe(1);
      expect(getPath(resolvedDlq.json, 'deadLetters', 0, 'deliveryId')).toBe(deliveryId);
      expect(Boolean(getPath(resolvedDlq.json, 'deadLetters', 0, 'resolvedAt'))).toBe(true);

      const updated = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}`,
        {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            status: 'DISABLED',
            subscriptions: ['wallet', 'policy'],
          }),
        },
      );
      expect(updated.status).toBe(200);
      expect(getPath(updated.json, 'endpoint', 'status')).toBe('DISABLED');

      const emittedDisabled = await webhooks.emitEvent(
        {
          orgId: 'org-1',
          actorUserId: 'system-webhooks-test',
          roles: ['ops'],
        },
        {
          eventType: 'billing.invoice.paid',
          payload: {
            invoiceId: 'inv_router_2',
          },
        },
      );
      expect(emittedDisabled.attempted).toBe(0);
      expect(emittedDisabled.delivered).toBe(0);
      expect(emittedDisabled.failed).toBe(0);

      const deleted = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}`,
        {
          method: 'DELETE',
        },
      );
      expect(deleted.status).toBe(200);
      expect(deleted.json?.removed).toBe(true);
    } finally {
      await srv.close();
    }
  });

  test('webhook list endpoints reject malformed cursor', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      webhooks: createInMemoryConsoleWebhookService(),
    });
    const srv = await startExpressRouter(router);
    try {
      const created = await fetchJson(`${srv.baseUrl}/console/webhooks`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: 'https://example.com/bad-cursor-express',
          subscriptions: ['billing'],
        }),
      });
      expect(created.status).toBe(201);
      const endpointId = String(getPath(created.json, 'endpoint', 'id') || '');
      expect(endpointId).toBeTruthy();

      const deliveries = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/deliveries?cursor=bad_cursor`,
        {
          method: 'GET',
        },
      );
      expect(deliveries.status).toBe(400);
      expect(deliveries.json?.code).toBe('invalid_query');

      const attempts = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/attempts?cursor=bad_cursor`,
        {
          method: 'GET',
        },
      );
      expect(attempts.status).toBe(400);
      expect(attempts.json?.code).toBe('invalid_query');

      const deadLetters = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/dead-letters?cursor=bad_cursor`,
        {
          method: 'GET',
        },
      );
      expect(deadLetters.status).toBe(400);
      expect(deadLetters.json?.code).toBe('invalid_query');

      const oversizedSortKey = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/deliveries?cursor=9007199254740992%3Aoverflow`,
        {
          method: 'GET',
        },
      );
      expect(oversizedSortKey.status).toBe(400);
      expect(oversizedSortKey.json?.code).toBe('invalid_query');
    } finally {
      await srv.close();
    }
  });

  test('GET /console/billing/stablecoins/assets requires console auth adapter', async () => {
    const router = createConsoleRouter({});
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/billing/stablecoins/assets`, {
        method: 'GET',
      });
      expect(res.status).toBe(503);
      expect(res.json?.code).toBe('console_auth_not_configured');
    } finally {
      await srv.close();
    }
  });

  test('GET /console/billing/stablecoins/assets returns supported assets/chains', async () => {
    const router = createConsoleRouter({ auth: makeConsoleAuthAdapter(['admin']) });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/billing/stablecoins/assets`, {
        method: 'GET',
      });
      expect(res.status).toBe(200);
      expect(res.json?.version).toBe('v1');
      const assets = Array.isArray(res.json?.assets) ? res.json?.assets : [];
      expect(assets.length).toBe(2);
      expect(JSON.stringify(assets)).toContain('"asset":"USDC"');
      expect(JSON.stringify(assets)).toContain('"chain":"Ethereum"');
      expect(JSON.stringify(assets)).toContain('"requiredConfirmations":12');
    } finally {
      await srv.close();
    }
  });

  test('POST /console/billing/payment-methods requires admin role', async () => {
    const router = createConsoleRouter({ auth: makeConsoleAuthAdapter(['billing_admin']) });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/billing/payment-methods`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      expect(res.status).toBe(403);
      expect(res.json?.code).toBe('forbidden');
    } finally {
      await srv.close();
    }
  });

  test('POST /console/billing/payment-methods returns billing_not_configured without billing service', async () => {
    const router = createConsoleRouter({ auth: makeConsoleAuthAdapter(['admin']) });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/billing/payment-methods`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      expect(res.status).toBe(501);
      expect(res.json?.code).toBe('billing_not_configured');
    } finally {
      await srv.close();
    }
  });

  test(
    'POST /console/billing/stripe/checkout-session returns billing_not_configured without billing service',
    async () => {
      const router = createConsoleRouter({ auth: makeConsoleAuthAdapter(['admin']) });
      const srv = await startExpressRouter(router);
      try {
        const res = await fetchJson(`${srv.baseUrl}/console/billing/stripe/checkout-session`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            successUrl: 'https://app.example.com/dashboard/billing?checkout=success',
            cancelUrl: 'https://app.example.com/pricing?checkout=cancel',
          }),
        });
        expect(res.status).toBe(501);
        expect(res.json?.code).toBe('billing_not_configured');
      } finally {
        await srv.close();
      }
    },
  );

  test('POST /console/billing/stripe/checkout-session creates checkout session', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing: createInMemoryConsoleBillingService(),
    });
    const srv = await startExpressRouter(router);
    try {
      const created = await fetchJson(`${srv.baseUrl}/console/billing/stripe/checkout-session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          successUrl: 'https://app.example.com/dashboard/billing?checkout=success',
          cancelUrl: 'https://app.example.com/pricing?checkout=cancel',
          planId: 'pro_maw_v1',
        }),
      });
      expect(created.status).toBe(201);
      const checkoutSessionId = String(getPath(created.json, 'checkoutSession', 'id') || '');
      const checkoutSessionUrl = String(getPath(created.json, 'checkoutSession', 'url') || '');
      expect(checkoutSessionId).toBeTruthy();
      expect(checkoutSessionUrl).toContain('https://checkout.stripe.com/pay/');
      expect(String(getPath(created.json, 'checkoutSession', 'customerRef') || '')).toContain('cus_');
      expect(String(getPath(created.json, 'checkoutSession', 'expiresAt') || '')).toMatch(
        /^\d{4}-\d{2}-\d{2}T/,
      );

      const invalid = await fetchJson(`${srv.baseUrl}/console/billing/stripe/checkout-session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          successUrl: '/dashboard/billing',
          cancelUrl: 'https://app.example.com/pricing?checkout=cancel',
        }),
      });
      expect(invalid.status).toBe(400);
      expect(invalid.json?.code).toBe('invalid_body');
    } finally {
      await srv.close();
    }
  });

  test(
    'POST /console/billing/stripe/customer-portal-session returns billing_not_configured without billing service',
    async () => {
      const router = createConsoleRouter({ auth: makeConsoleAuthAdapter(['admin']) });
      const srv = await startExpressRouter(router);
      try {
        const res = await fetchJson(
          `${srv.baseUrl}/console/billing/stripe/customer-portal-session`,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              returnUrl: 'https://app.example.com/dashboard/billing',
            }),
          },
        );
        expect(res.status).toBe(501);
        expect(res.json?.code).toBe('billing_not_configured');
      } finally {
        await srv.close();
      }
    },
  );

  test('POST /console/billing/stripe/customer-portal-session creates portal session', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing: createInMemoryConsoleBillingService(),
    });
    const srv = await startExpressRouter(router);
    try {
      const created = await fetchJson(
        `${srv.baseUrl}/console/billing/stripe/customer-portal-session`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            returnUrl: 'https://app.example.com/dashboard/billing',
          }),
        },
      );
      expect(created.status).toBe(201);
      const sessionId = String(getPath(created.json, 'portalSession', 'id') || '');
      const sessionUrl = String(getPath(created.json, 'portalSession', 'url') || '');
      expect(sessionId).toBeTruthy();
      expect(sessionUrl).toContain('https://billing.stripe.com/p/session/');
      expect(String(getPath(created.json, 'portalSession', 'customerRef') || '')).toContain('cus_');

      const invalid = await fetchJson(
        `${srv.baseUrl}/console/billing/stripe/customer-portal-session`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            returnUrl: '/dashboard/billing',
          }),
        },
      );
      expect(invalid.status).toBe(400);
      expect(invalid.json?.code).toBe('invalid_body');
    } finally {
      await srv.close();
    }
  });

  test('GET /console/billing/subscription returns billing_not_configured without billing service', async () => {
    const router = createConsoleRouter({ auth: makeConsoleAuthAdapter(['admin']) });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/billing/subscription`, {
        method: 'GET',
      });
      expect(res.status).toBe(501);
      expect(res.json?.code).toBe('billing_not_configured');
    } finally {
      await srv.close();
    }
  });

  test('billing subscription lifecycle routes support get/cancel/resume', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing: createInMemoryConsoleBillingService(),
    });
    const srv = await startExpressRouter(router);
    try {
      const initial = await fetchJson(`${srv.baseUrl}/console/billing/subscription`, {
        method: 'GET',
      });
      expect(initial.status).toBe(200);
      expect(getPath(initial.json, 'subscription', 'status')).toBe('ACTIVE');
      expect(getPath(initial.json, 'subscription', 'cancelAtPeriodEnd')).toBe(false);

      const canceled = await fetchJson(`${srv.baseUrl}/console/billing/subscription/cancel`, {
        method: 'POST',
      });
      expect(canceled.status).toBe(200);
      expect(getPath(canceled.json, 'subscription', 'status')).toBe('ACTIVE');
      expect(getPath(canceled.json, 'subscription', 'cancelAtPeriodEnd')).toBe(true);

      const resumed = await fetchJson(`${srv.baseUrl}/console/billing/subscription/resume`, {
        method: 'POST',
      });
      expect(resumed.status).toBe(200);
      expect(getPath(resumed.json, 'subscription', 'status')).toBe('ACTIVE');
      expect(getPath(resumed.json, 'subscription', 'cancelAtPeriodEnd')).toBe(false);
    } finally {
      await srv.close();
    }
  });

  test('POST /console/billing/stripe/webhook requires configured shared secret', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing: createInMemoryConsoleBillingService(),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/billing/stripe/webhook`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          eventId: 'evt_missing_secret',
          providerRef: 'pi_provider_missing',
          providerStatus: 'SUCCEEDED',
        }),
      });
      expect(res.status).toBe(501);
      expect(res.json?.code).toBe('stripe_webhook_not_configured');
    } finally {
      await srv.close();
    }
  });

  test('billing flow: card methods + stablecoin intent + rail lock conflict', async () => {
    const billing = createInMemoryConsoleBillingService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
    });
    const srv = await startExpressRouter(router);
    try {
      const addCard = await fetchJson(`${srv.baseUrl}/console/billing/payment-methods`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          providerRef: 'pm_test_123',
          brand: 'visa',
          last4: '4242',
          expMonth: 12,
          expYear: 2030,
        }),
      });
      expect(addCard.status).toBe(201);
      expect(String(getPath(addCard.json, 'paymentMethod', 'id') || '')).toBeTruthy();

      const invoices = await fetchJson(`${srv.baseUrl}/console/billing/invoices`, {
        method: 'GET',
      });
      expect(invoices.status).toBe(200);
      const invoiceId = Array.isArray(invoices.json?.invoices)
        ? (invoices.json?.invoices?.[0] as any)?.id
        : '';
      expect(invoiceId).toBeTruthy();

      const quote = await fetchJson(`${srv.baseUrl}/console/billing/stablecoins/quotes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          invoiceId,
          asset: 'USDC',
          chain: 'Base',
        }),
      });
      expect(quote.status).toBe(201);
      const quoteId = String(getPath(quote.json, 'quote', 'id') || '');
      expect(quoteId).toBeTruthy();

      const stablecoinIntent = await fetchJson(
        `${srv.baseUrl}/console/billing/stablecoins/payment-intents`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            invoiceId,
            quoteId,
          }),
        },
      );
      expect(stablecoinIntent.status).toBe(201);
      expect(getPath(stablecoinIntent.json, 'paymentIntent', 'rail')).toBe('STABLECOIN');

      const stripeIntent = await fetchJson(`${srv.baseUrl}/console/billing/stripe/payment-intent`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          invoiceId,
        }),
      });
      expect(stripeIntent.status).toBe(409);
      expect(stripeIntent.json?.code).toBe('invoice_rail_locked');
    } finally {
      await srv.close();
    }
  });

  test('stablecoin quote is single-use across payment intents', async () => {
    const billing = createInMemoryConsoleBillingService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
    });
    const srv = await startExpressRouter(router);
    try {
      const invoices = await fetchJson(`${srv.baseUrl}/console/billing/invoices`, {
        method: 'GET',
      });
      expect(invoices.status).toBe(200);
      const invoiceId = Array.isArray(invoices.json?.invoices)
        ? (invoices.json?.invoices?.[0] as any)?.id
        : '';
      expect(invoiceId).toBeTruthy();

      const quote = await fetchJson(`${srv.baseUrl}/console/billing/stablecoins/quotes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          invoiceId,
          asset: 'USDC',
          chain: 'Ethereum',
        }),
      });
      expect(quote.status).toBe(201);
      const quoteId = String(getPath(quote.json, 'quote', 'id') || '');
      expect(quoteId).toBeTruthy();

      const firstIntent = await fetchJson(
        `${srv.baseUrl}/console/billing/stablecoins/payment-intents`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ invoiceId, quoteId }),
        },
      );
      expect(firstIntent.status).toBe(201);
      const paymentIntentId = String(getPath(firstIntent.json, 'paymentIntent', 'id') || '');
      expect(paymentIntentId).toBeTruthy();

      const canceled = await fetchJson(
        `${srv.baseUrl}/console/billing/stablecoins/payment-intents/${paymentIntentId}/cancel`,
        {
          method: 'POST',
        },
      );
      expect(canceled.status).toBe(200);
      expect(getPath(canceled.json, 'paymentIntent', 'state')).toBe('CANCELED');

      const reused = await fetchJson(`${srv.baseUrl}/console/billing/stablecoins/payment-intents`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ invoiceId, quoteId }),
      });
      expect(reused.status).toBe(409);
      expect(reused.json?.code).toBe('quote_already_consumed');
    } finally {
      await srv.close();
    }
  });

  test('Stripe webhook reconciles payment intent by providerRef and dedupes event id', async () => {
    const billing = createInMemoryConsoleBillingService();
    const secret = 'whsec_console_router_test';
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
      billingStripeWebhookSecret: secret,
    });
    const srv = await startExpressRouter(router);
    try {
      const invoices = await fetchJson(`${srv.baseUrl}/console/billing/invoices`, {
        method: 'GET',
      });
      expect(invoices.status).toBe(200);
      const invoiceId = Array.isArray(invoices.json?.invoices)
        ? (invoices.json?.invoices?.[0] as any)?.id
        : '';
      expect(invoiceId).toBeTruthy();

      const created = await fetchJson(`${srv.baseUrl}/console/billing/stripe/payment-intent`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ invoiceId }),
      });
      expect(created.status).toBe(201);
      const providerRef = String(getPath(created.json, 'paymentIntent', 'providerRef') || '');
      const amountMinor = Number(getPath(created.json, 'paymentIntent', 'amountMinor') || 0);
      expect(providerRef).toBeTruthy();
      expect(amountMinor).toBeGreaterThan(0);

      const unauthorized = await fetchJson(`${srv.baseUrl}/console/billing/stripe/webhook`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          eventId: 'evt_express_webhook_unauthorized',
          providerRef,
          providerStatus: 'SUCCEEDED',
          settledAmountMinor: amountMinor,
        }),
      });
      expect(unauthorized.status).toBe(401);
      expect(unauthorized.json?.code).toBe('unauthorized');

      const eventId = `evt_express_webhook_${Date.now()}`;
      const first = await fetchJson(`${srv.baseUrl}/console/billing/stripe/webhook`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-console-stripe-webhook-secret': secret,
        },
        body: JSON.stringify({
          eventId,
          providerRef,
          providerStatus: 'SUCCEEDED',
          settledAmountMinor: amountMinor,
        }),
      });
      expect(first.status).toBe(200);
      expect(first.json?.accepted).toBe(true);
      expect(getPath(first.json, 'paymentIntent', 'state')).toBe('SETTLED');

      const duplicate = await fetchJson(`${srv.baseUrl}/console/billing/stripe/webhook`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-console-stripe-webhook-secret': secret,
        },
        body: JSON.stringify({
          eventId,
          providerRef,
          providerStatus: 'SUCCEEDED',
          settledAmountMinor: amountMinor,
        }),
      });
      expect(duplicate.status).toBe(200);
      expect(duplicate.json?.accepted).toBe(false);
      expect(getPath(duplicate.json, 'paymentIntent', 'state')).toBe('SETTLED');
    } finally {
      await srv.close();
    }
  });

  test('Stripe webhook projects subscription/invoice events idempotently', async () => {
    const billing = createInMemoryConsoleBillingService();
    const secret = 'whsec_console_router_projection_test';
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
      billingStripeWebhookSecret: secret,
    });
    const srv = await startExpressRouter(router);
    try {
      const subscriptionBefore = await fetchJson(`${srv.baseUrl}/console/billing/subscription`, {
        method: 'GET',
      });
      expect(subscriptionBefore.status).toBe(200);
      const providerSubscriptionRef = String(
        getPath(subscriptionBefore.json, 'subscription', 'providerSubscriptionRef') || '',
      );
      const providerCustomerRef = String(
        getPath(subscriptionBefore.json, 'subscription', 'providerCustomerRef') || '',
      );
      expect(providerSubscriptionRef).toBeTruthy();
      expect(providerCustomerRef).toBeTruthy();

      const invoices = await fetchJson(`${srv.baseUrl}/console/billing/invoices`, {
        method: 'GET',
      });
      expect(invoices.status).toBe(200);
      const invoiceId = Array.isArray(invoices.json?.invoices)
        ? String((invoices.json?.invoices?.[0] as any)?.id || '')
        : '';
      const invoiceAmountDueMinor = Array.isArray(invoices.json?.invoices)
        ? Number((invoices.json?.invoices?.[0] as any)?.amountDueMinor || 0)
        : 0;
      expect(invoiceId).toBeTruthy();
      expect(invoiceAmountDueMinor).toBeGreaterThan(0);

      const subscriptionEventId = `evt_express_subscription_projection_${Date.now()}`;
      const projectedSubscription = await fetchJson(`${srv.baseUrl}/console/billing/stripe/webhook`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-console-stripe-webhook-secret': secret,
        },
        body: JSON.stringify({
          eventId: subscriptionEventId,
          eventType: 'customer.subscription.updated',
          orgId: 'org-1',
          providerSubscriptionRef,
          providerCustomerRef,
          subscriptionStatus: 'PAST_DUE',
          cancelAtPeriodEnd: true,
        }),
      });
      expect(projectedSubscription.status).toBe(200);
      expect(projectedSubscription.json?.accepted).toBe(true);
      expect(getPath(projectedSubscription.json, 'subscription', 'status')).toBe('PAST_DUE');
      expect(getPath(projectedSubscription.json, 'subscription', 'cancelAtPeriodEnd')).toBe(true);

      const projectedSubscriptionDuplicate = await fetchJson(
        `${srv.baseUrl}/console/billing/stripe/webhook`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-console-stripe-webhook-secret': secret,
          },
          body: JSON.stringify({
            eventId: subscriptionEventId,
            eventType: 'customer.subscription.updated',
            orgId: 'org-1',
            providerSubscriptionRef,
            providerCustomerRef,
            subscriptionStatus: 'PAST_DUE',
            cancelAtPeriodEnd: true,
          }),
        },
      );
      expect(projectedSubscriptionDuplicate.status).toBe(200);
      expect(projectedSubscriptionDuplicate.json?.accepted).toBe(false);

      const projectedInvoice = await fetchJson(`${srv.baseUrl}/console/billing/stripe/webhook`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-console-stripe-webhook-secret': secret,
        },
        body: JSON.stringify({
          eventId: `evt_express_invoice_projection_${Date.now()}`,
          eventType: 'invoice.paid',
          orgId: 'org-1',
          invoiceId,
          invoiceStatus: 'PAID',
          invoiceAmountPaidMinor: invoiceAmountDueMinor,
        }),
      });
      expect(projectedInvoice.status).toBe(200);
      expect(projectedInvoice.json?.accepted).toBe(true);
      expect(getPath(projectedInvoice.json, 'invoice', 'status')).toBe('PAID');

      const subscriptionAfter = await fetchJson(`${srv.baseUrl}/console/billing/subscription`, {
        method: 'GET',
      });
      expect(subscriptionAfter.status).toBe(200);
      expect(getPath(subscriptionAfter.json, 'subscription', 'status')).toBe('PAST_DUE');

      const invoiceAfter = await fetchJson(
        `${srv.baseUrl}/console/billing/invoices/${encodeURIComponent(invoiceId)}`,
        {
          method: 'GET',
        },
      );
      expect(invoiceAfter.status).toBe(200);
      expect(getPath(invoiceAfter.json, 'invoice', 'status')).toBe('PAID');
    } finally {
      await srv.close();
    }
  });

  test('stripe payment intents reject concurrent active attempts', async () => {
    const billing = createInMemoryConsoleBillingService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
    });
    const srv = await startExpressRouter(router);
    try {
      const invoices = await fetchJson(`${srv.baseUrl}/console/billing/invoices`, {
        method: 'GET',
      });
      expect(invoices.status).toBe(200);
      const invoiceId = Array.isArray(invoices.json?.invoices)
        ? (invoices.json?.invoices?.[0] as any)?.id
        : '';
      expect(invoiceId).toBeTruthy();

      const firstIntent = await fetchJson(`${srv.baseUrl}/console/billing/stripe/payment-intent`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ invoiceId }),
      });
      expect(firstIntent.status).toBe(201);
      expect(getPath(firstIntent.json, 'paymentIntent', 'state')).toBe('CREATED');

      const secondIntent = await fetchJson(`${srv.baseUrl}/console/billing/stripe/payment-intent`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ invoiceId }),
      });
      expect(secondIntent.status).toBe(409);
      expect(secondIntent.json?.code).toBe('active_payment_intent_exists');
    } finally {
      await srv.close();
    }
  });

  test('billing usage endpoints compute MAW with exclusions and idempotency', async () => {
    const billing = createInMemoryConsoleBillingService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
    });
    const srv = await startExpressRouter(router);
    try {
      const e1 = await fetchJson(`${srv.baseUrl}/console/billing/usage/events`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          walletId: 'wallet_1',
          action: 'transfer',
          succeeded: true,
          sourceEventId: 'usage_evt_1',
        }),
      });
      expect(e1.status).toBe(200);
      expect(getPath(e1.json, 'result', 'accepted')).toBe(true);
      expect(getPath(e1.json, 'result', 'counted')).toBe(true);
      expect(Number(getPath(e1.json, 'result', 'monthlyActiveWallets') || 0)).toBe(1);
      const monthUtc = String(getPath(e1.json, 'result', 'monthUtc') || '');
      expect(monthUtc).toMatch(/^\d{4}-\d{2}$/);

      const e2 = await fetchJson(`${srv.baseUrl}/console/billing/usage/events`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          walletId: 'wallet_1',
          action: 'swap',
          succeeded: true,
          sourceEventId: 'usage_evt_2',
        }),
      });
      expect(e2.status).toBe(200);
      expect(Number(getPath(e2.json, 'result', 'monthlyActiveWallets') || 0)).toBe(1);

      const e3 = await fetchJson(`${srv.baseUrl}/console/billing/usage/events`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          walletId: 'wallet_2',
          action: 'approve',
          succeeded: true,
          sourceEventId: 'usage_evt_3',
        }),
      });
      expect(e3.status).toBe(200);
      expect(Number(getPath(e3.json, 'result', 'monthlyActiveWallets') || 0)).toBe(2);

      const excluded = await fetchJson(`${srv.baseUrl}/console/billing/usage/events`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          walletId: 'wallet_3',
          action: 'wallet_created',
          succeeded: true,
          sourceEventId: 'usage_evt_4',
        }),
      });
      expect(excluded.status).toBe(200);
      expect(getPath(excluded.json, 'result', 'counted')).toBe(false);
      expect(Number(getPath(excluded.json, 'result', 'monthlyActiveWallets') || 0)).toBe(2);

      const duplicate = await fetchJson(`${srv.baseUrl}/console/billing/usage/events`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          walletId: 'wallet_2',
          action: 'approve',
          succeeded: true,
          sourceEventId: 'usage_evt_3',
        }),
      });
      expect(duplicate.status).toBe(200);
      expect(getPath(duplicate.json, 'result', 'accepted')).toBe(false);
      expect(getPath(duplicate.json, 'result', 'counted')).toBe(false);
      expect(Number(getPath(duplicate.json, 'result', 'monthlyActiveWallets') || 0)).toBe(2);

      const usage = await fetchJson(
        `${srv.baseUrl}/console/billing/usage/monthly-active-wallets?monthUtc=${encodeURIComponent(monthUtc)}`,
        {
          method: 'GET',
        },
      );
      expect(usage.status).toBe(200);
      expect(getPath(usage.json, 'usage', 'usageMetricVersion')).toBe('maw_v1');
      expect(getPath(usage.json, 'usage', 'monthUtc')).toBe(monthUtc);
      expect(Number(getPath(usage.json, 'usage', 'monthlyActiveWallets') || 0)).toBe(2);
    } finally {
      await srv.close();
    }
  });

  test('POST /console/billing/invoices/generate requires admin or ops role', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['billing_admin']),
      billing: createInMemoryConsoleBillingService(),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/billing/invoices/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          periodMonthUtc: '2026-01',
        }),
      });
      expect(res.status).toBe(403);
      expect(res.json?.code).toBe('forbidden');
    } finally {
      await srv.close();
    }
  });

  test('invoice generation endpoint returns deterministic line items', async () => {
    const billing = createInMemoryConsoleBillingService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['ops']),
      billing,
    });
    const srv = await startExpressRouter(router);
    try {
      await fetchJson(`${srv.baseUrl}/console/billing/usage/events`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          walletId: 'wallet_gen_1',
          action: 'transfer',
          succeeded: true,
          occurredAt: '2026-01-05T01:00:00.000Z',
          sourceEventId: 'router_gen_evt_1',
        }),
      });
      await fetchJson(`${srv.baseUrl}/console/billing/usage/events`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          walletId: 'wallet_gen_2',
          action: 'swap',
          succeeded: true,
          occurredAt: '2026-01-06T01:00:00.000Z',
          sourceEventId: 'router_gen_evt_2',
        }),
      });
      await fetchJson(`${srv.baseUrl}/console/billing/usage/events`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          walletId: 'wallet_gen_3',
          action: 'wallet_created',
          succeeded: true,
          occurredAt: '2026-01-07T01:00:00.000Z',
          sourceEventId: 'router_gen_evt_3',
        }),
      });

      const generated = await fetchJson(`${srv.baseUrl}/console/billing/invoices/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ periodMonthUtc: '2026-01' }),
      });
      expect(generated.status).toBe(200);
      expect(getPath(generated.json, 'generation', 'generated')).toBe(true);
      expect(Number(getPath(generated.json, 'generation', 'invoice', 'amountDueMinor') || 0)).toBe(
        2500,
      );
      const invoiceId = String(getPath(generated.json, 'generation', 'invoice', 'id') || '');
      expect(invoiceId).toBeTruthy();

      const lineItems = await fetchJson(
        `${srv.baseUrl}/console/billing/invoices/${encodeURIComponent(invoiceId)}/line-items`,
        {
          method: 'GET',
        },
      );
      expect(lineItems.status).toBe(200);
      const items = Array.isArray(lineItems.json?.lineItems) ? lineItems.json?.lineItems : [];
      expect(items.length).toBe(2);
      expect(JSON.stringify(items)).toContain('"itemType":"PLAN_BASE_FEE"');
      expect(JSON.stringify(items)).toContain('"itemType":"MAW_USAGE"');
    } finally {
      await srv.close();
    }
  });

  test('POST /console/billing/stablecoins/payment-intents/:id/reconcile requires admin or ops role', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['billing_admin']),
      billing: createInMemoryConsoleBillingService(),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(
        `${srv.baseUrl}/console/billing/stablecoins/payment-intents/scpi_fake/reconcile`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            observedAmountMinor: 1,
            observedConfirmations: 1,
          }),
        },
      );
      expect(res.status).toBe(403);
      expect(res.json?.code).toBe('forbidden');
    } finally {
      await srv.close();
    }
  });

  test('stablecoin reconcile transitions to confirming then settled and updates invoice', async () => {
    const billing = createInMemoryConsoleBillingService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
    });
    const srv = await startExpressRouter(router);
    try {
      const invoices = await fetchJson(`${srv.baseUrl}/console/billing/invoices`, {
        method: 'GET',
      });
      expect(invoices.status).toBe(200);
      const invoiceId = Array.isArray(invoices.json?.invoices)
        ? (invoices.json?.invoices?.[0] as any)?.id
        : '';
      expect(invoiceId).toBeTruthy();

      const quote = await fetchJson(`${srv.baseUrl}/console/billing/stablecoins/quotes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          invoiceId,
          asset: 'USDC',
          chain: 'Ethereum',
        }),
      });
      expect(quote.status).toBe(201);
      const quoteId = String(getPath(quote.json, 'quote', 'id') || '');
      expect(quoteId).toBeTruthy();

      const created = await fetchJson(
        `${srv.baseUrl}/console/billing/stablecoins/payment-intents`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ invoiceId, quoteId }),
        },
      );
      expect(created.status).toBe(201);
      const paymentIntentId = String(getPath(created.json, 'paymentIntent', 'id') || '');
      const expectedAmountMinor = Number(
        getPath(created.json, 'paymentIntent', 'expectedAmountMinor') || 0,
      );
      const requiredConfirmations = Number(
        getPath(created.json, 'paymentIntent', 'requiredConfirmations') || 0,
      );
      expect(paymentIntentId).toBeTruthy();
      expect(expectedAmountMinor).toBeGreaterThan(0);
      expect(requiredConfirmations).toBeGreaterThan(0);

      const confirming = await fetchJson(
        `${srv.baseUrl}/console/billing/stablecoins/payment-intents/${paymentIntentId}/reconcile`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            observedAmountMinor: expectedAmountMinor,
            observedConfirmations: Math.max(requiredConfirmations - 1, 0),
          }),
        },
      );
      expect(confirming.status).toBe(200);
      expect(getPath(confirming.json, 'paymentIntent', 'state')).toBe('CONFIRMING');

      const settled = await fetchJson(
        `${srv.baseUrl}/console/billing/stablecoins/payment-intents/${paymentIntentId}/reconcile`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            observedAmountMinor: expectedAmountMinor,
            observedConfirmations: requiredConfirmations,
          }),
        },
      );
      expect(settled.status).toBe(200);
      expect(getPath(settled.json, 'paymentIntent', 'state')).toBe('SETTLED');
      expect(getPath(settled.json, 'paymentIntent', 'settledAt')).toBeTruthy();
      expect(getPath(settled.json, 'paymentIntent', 'reorgRiskWindowEndsAt')).toBeTruthy();
      expect(getPath(settled.json, 'paymentIntent', 'withinReorgRiskWindow')).toBe(true);

      const invoice = await fetchJson(`${srv.baseUrl}/console/billing/invoices/${invoiceId}`, {
        method: 'GET',
      });
      expect(invoice.status).toBe(200);
      expect(getPath(invoice.json, 'invoice', 'status')).toBe('PAID');
      expect(
        Number(getPath(invoice.json, 'invoice', 'amountPaidMinor') || 0),
      ).toBeGreaterThanOrEqual(expectedAmountMinor);
    } finally {
      await srv.close();
    }
  });

  test('stablecoin reconcile after intent expiry returns EXPIRED and leaves invoice open', async () => {
    let current = new Date('2026-03-01T00:00:00.000Z');
    const billing = createInMemoryConsoleBillingService({
      now: () => current,
    });
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
    });
    const srv = await startExpressRouter(router);
    try {
      const invoices = await fetchJson(`${srv.baseUrl}/console/billing/invoices`, {
        method: 'GET',
      });
      expect(invoices.status).toBe(200);
      const invoiceId = Array.isArray(invoices.json?.invoices)
        ? (invoices.json?.invoices?.[0] as any)?.id
        : '';
      expect(invoiceId).toBeTruthy();

      const quote = await fetchJson(`${srv.baseUrl}/console/billing/stablecoins/quotes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          invoiceId,
          asset: 'USDC',
          chain: 'Ethereum',
        }),
      });
      expect(quote.status).toBe(201);
      const quoteId = String(getPath(quote.json, 'quote', 'id') || '');
      expect(quoteId).toBeTruthy();

      const created = await fetchJson(
        `${srv.baseUrl}/console/billing/stablecoins/payment-intents`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ invoiceId, quoteId }),
        },
      );
      expect(created.status).toBe(201);
      const paymentIntentId = String(getPath(created.json, 'paymentIntent', 'id') || '');
      const expectedAmountMinor = Number(
        getPath(created.json, 'paymentIntent', 'expectedAmountMinor') || 0,
      );
      const requiredConfirmations = Number(
        getPath(created.json, 'paymentIntent', 'requiredConfirmations') || 0,
      );
      expect(paymentIntentId).toBeTruthy();
      expect(requiredConfirmations).toBeGreaterThan(0);

      current = new Date(current.getTime() + 16 * 60 * 1000);

      const reconcile = await fetchJson(
        `${srv.baseUrl}/console/billing/stablecoins/payment-intents/${paymentIntentId}/reconcile`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            observedAmountMinor: expectedAmountMinor,
            observedConfirmations: requiredConfirmations,
          }),
        },
      );
      expect(reconcile.status).toBe(200);
      expect(getPath(reconcile.json, 'paymentIntent', 'state')).toBe('EXPIRED');

      const invoice = await fetchJson(`${srv.baseUrl}/console/billing/invoices/${invoiceId}`, {
        method: 'GET',
      });
      expect(invoice.status).toBe(200);
      expect(getPath(invoice.json, 'invoice', 'status')).toBe('OPEN');
      expect(Number(getPath(invoice.json, 'invoice', 'amountPaidMinor') || 0)).toBe(0);
    } finally {
      await srv.close();
    }
  });

  test('stripe reconcile transitions action_required -> settled and updates invoice', async () => {
    const billing = createInMemoryConsoleBillingService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['ops']),
      billing,
    });
    const srv = await startExpressRouter(router);
    try {
      const invoices = await fetchJson(`${srv.baseUrl}/console/billing/invoices`, {
        method: 'GET',
      });
      expect(invoices.status).toBe(200);
      const invoiceId = Array.isArray(invoices.json?.invoices)
        ? (invoices.json?.invoices?.[0] as any)?.id
        : '';
      expect(invoiceId).toBeTruthy();

      const created = await fetchJson(`${srv.baseUrl}/console/billing/stripe/payment-intent`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ invoiceId }),
      });
      expect(created.status).toBe(201);
      const paymentIntentId = String(getPath(created.json, 'paymentIntent', 'id') || '');
      expect(getPath(created.json, 'paymentIntent', 'state')).toBe('CREATED');
      const amountMinor = Number(getPath(created.json, 'paymentIntent', 'amountMinor') || 0);
      expect(paymentIntentId).toBeTruthy();
      expect(amountMinor).toBeGreaterThan(0);

      const actionRequired = await fetchJson(
        `${srv.baseUrl}/console/billing/stripe/payment-intents/${paymentIntentId}/reconcile`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            providerStatus: 'ACTION_REQUIRED',
            sourceEventId: `evt_${Date.now()}_action_required`,
          }),
        },
      );
      expect(actionRequired.status).toBe(200);
      expect(getPath(actionRequired.json, 'paymentIntent', 'state')).toBe('ACTION_REQUIRED');

      const pending = await fetchJson(
        `${srv.baseUrl}/console/billing/stripe/payment-intents/${paymentIntentId}/reconcile`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            providerStatus: 'PENDING',
            sourceEventId: `evt_${Date.now()}_pending`,
          }),
        },
      );
      expect(pending.status).toBe(200);
      expect(getPath(pending.json, 'paymentIntent', 'state')).toBe('PENDING');

      const settled = await fetchJson(
        `${srv.baseUrl}/console/billing/stripe/payment-intents/${paymentIntentId}/reconcile`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            providerStatus: 'SUCCEEDED',
            settledAmountMinor: amountMinor,
            sourceEventId: `evt_${Date.now()}_succeeded`,
          }),
        },
      );
      expect(settled.status).toBe(200);
      expect(getPath(settled.json, 'paymentIntent', 'state')).toBe('SETTLED');

      const invoice = await fetchJson(`${srv.baseUrl}/console/billing/invoices/${invoiceId}`, {
        method: 'GET',
      });
      expect(invoice.status).toBe(200);
      expect(getPath(invoice.json, 'invoice', 'status')).toBe('PAID');
    } finally {
      await srv.close();
    }
  });

  test('billing transitions emit billing webhook events when webhook endpoint is configured', async () => {
    const billing = createInMemoryConsoleBillingService();
    const webhooks = createInMemoryConsoleWebhookService({
      dispatcher: {
        dispatch: async () => ({
          ok: true,
          statusCode: 200,
          responseBody: 'ok',
        }),
      },
    });
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
      webhooks,
    });
    const srv = await startExpressRouter(router);
    try {
      const endpointCreated = await fetchJson(`${srv.baseUrl}/console/webhooks`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: 'https://example.com/billing-events',
          subscriptions: ['billing'],
        }),
      });
      expect(endpointCreated.status).toBe(201);
      const endpointId = String(getPath(endpointCreated.json, 'endpoint', 'id') || '');
      expect(endpointId).toBeTruthy();

      const invoices = await fetchJson(`${srv.baseUrl}/console/billing/invoices`, {
        method: 'GET',
      });
      expect(invoices.status).toBe(200);
      const invoiceId = Array.isArray(invoices.json?.invoices)
        ? (invoices.json?.invoices?.[0] as any)?.id
        : '';
      expect(invoiceId).toBeTruthy();

      const created = await fetchJson(`${srv.baseUrl}/console/billing/stripe/payment-intent`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ invoiceId }),
      });
      expect(created.status).toBe(201);
      const paymentIntentId = String(getPath(created.json, 'paymentIntent', 'id') || '');
      const amountMinor = Number(getPath(created.json, 'paymentIntent', 'amountMinor') || 0);
      expect(paymentIntentId).toBeTruthy();
      expect(amountMinor).toBeGreaterThan(0);

      const actionRequired = await fetchJson(
        `${srv.baseUrl}/console/billing/stripe/payment-intents/${paymentIntentId}/reconcile`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            providerStatus: 'ACTION_REQUIRED',
          }),
        },
      );
      expect(actionRequired.status).toBe(200);

      const pending = await fetchJson(
        `${srv.baseUrl}/console/billing/stripe/payment-intents/${paymentIntentId}/reconcile`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            providerStatus: 'PENDING',
          }),
        },
      );
      expect(pending.status).toBe(200);

      const settled = await fetchJson(
        `${srv.baseUrl}/console/billing/stripe/payment-intents/${paymentIntentId}/reconcile`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            providerStatus: 'SUCCEEDED',
            settledAmountMinor: amountMinor,
          }),
        },
      );
      expect(settled.status).toBe(200);
      expect(getPath(settled.json, 'paymentIntent', 'state')).toBe('SETTLED');

      const deliveries = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/deliveries`,
        {
          method: 'GET',
        },
      );
      expect(deliveries.status).toBe(200);
      const rows = Array.isArray(deliveries.json?.deliveries) ? deliveries.json?.deliveries : [];
      const eventTypes = rows.map((row: any) => String(row?.eventType || ''));
      expect(eventTypes).toContain('billing.payment_intent.created');
      expect(eventTypes).toContain('billing.payment_intent.updated');
      expect(eventTypes).toContain('billing.invoice.paid');

      const pageOne = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/deliveries?limit=2`,
        {
          method: 'GET',
        },
      );
      expect(pageOne.status).toBe(200);
      const pageOneRows = Array.isArray(pageOne.json?.deliveries) ? pageOne.json?.deliveries : [];
      expect(pageOneRows.length).toBe(2);
      const pageOneCursor = String(pageOne.json?.nextCursor || '');
      expect(pageOneCursor).toBeTruthy();

      const pageTwo = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/deliveries?limit=2&cursor=${encodeURIComponent(pageOneCursor)}`,
        {
          method: 'GET',
        },
      );
      expect(pageTwo.status).toBe(200);
      const pageTwoRows = Array.isArray(pageTwo.json?.deliveries) ? pageTwo.json?.deliveries : [];
      expect(pageTwoRows.length).toBeGreaterThanOrEqual(1);
    } finally {
      await srv.close();
    }
  });
});

test.describe('console router (cloudflare)', () => {
  test('GET /console/healthz works', async () => {
    const handler = createCloudflareConsoleRouter({ healthz: true });
    const res = await callCf(handler, { method: 'GET', path: '/console/healthz' });
    expect(res.status).toBe(200);
    expect(res.json?.service).toBe('console');
  });

  test('GET /console/webhooks returns webhooks_not_configured without webhook service', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const res = await callCf(handler, {
      method: 'GET',
      path: '/console/webhooks',
    });
    expect(res.status).toBe(501);
    expect(res.json?.code).toBe('webhooks_not_configured');
  });

  test('GET /console/api-keys returns api_keys_not_configured without API key service', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const res = await callCf(handler, {
      method: 'GET',
      path: '/console/api-keys',
    });
    expect(res.status).toBe(501);
    expect(res.json?.code).toBe('api_keys_not_configured');
  });

  test('GET /console/org returns org_project_env_not_configured without org/project/env service', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const res = await callCf(handler, {
      method: 'GET',
      path: '/console/org',
    });
    expect(res.status).toBe(501);
    expect(res.json?.code).toBe('org_project_env_not_configured');
  });

  test('cloudflare org/project/environment routes return hierarchical metadata', async () => {
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-meta-cf-1', 'user-meta-cf-1'),
      orgProjectEnv,
    });

    const org = await callCf(handler, {
      method: 'GET',
      path: '/console/org',
    });
    expect(org.status).toBe(200);
    expect(getPath(org.json, 'org', 'id')).toBe('org-meta-cf-1');

    const projects = await callCf(handler, {
      method: 'GET',
      path: '/console/projects',
    });
    expect(projects.status).toBe(200);
    const projectRows = Array.isArray(projects.json?.projects) ? projects.json?.projects : [];
    expect(projectRows.length).toBeGreaterThanOrEqual(1);
    const projectId = String(getPath(projects.json, 'projects', 0, 'id') || '');
    expect(projectId).toBeTruthy();
    expect(Number(getPath(projects.json, 'projects', 0, 'environmentCount') || 0)).toBeGreaterThanOrEqual(
      1,
    );

    const environments = await callCf(handler, {
      method: 'GET',
      path: '/console/environments',
    });
    expect(environments.status).toBe(200);
    const environmentRows = Array.isArray(environments.json?.environments)
      ? environments.json?.environments
      : [];
    expect(environmentRows.length).toBeGreaterThanOrEqual(1);
    expect(String(getPath(environments.json, 'environments', 0, 'projectId') || '')).toBe(
      projectId,
    );

    const scoped = await callCf(handler, {
      method: 'GET',
      path: `/console/environments?projectId=${encodeURIComponent(projectId)}`,
    });
    expect(scoped.status).toBe(200);
    const scopedRows = Array.isArray(scoped.json?.environments) ? scoped.json?.environments : [];
    expect(scopedRows.length).toBeGreaterThanOrEqual(1);
    expect(scopedRows.every((entry: any) => String(entry?.projectId || '') === projectId)).toBe(
      true,
    );
  });

  test('cloudflare org/project/environment mutation routes enforce role and lifecycle rules', async () => {
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    const adminHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-meta-cf-mutate-1', 'user-meta-cf-mutate-1'),
      orgProjectEnv,
    });

    const createdProject = await callCf(adminHandler, {
      method: 'POST',
      path: '/console/projects',
      body: {
        id: 'project-cf-mutate-1',
        name: 'Project CF Mutate',
      },
    });
    expect(createdProject.status).toBe(201);
    expect(getPath(createdProject.json, 'project', 'id')).toBe('project-cf-mutate-1');
    expect(Number(getPath(createdProject.json, 'project', 'environmentCount') || 0)).toBe(0);

    const createdEnvironment = await callCf(adminHandler, {
      method: 'POST',
      path: '/console/environments',
      body: {
        id: 'env-cf-mutate-1',
        projectId: 'project-cf-mutate-1',
        key: 'dev',
      },
    });
    expect(createdEnvironment.status).toBe(201);
    expect(getPath(createdEnvironment.json, 'environment', 'id')).toBe('env-cf-mutate-1');

    const updatedProject = await callCf(adminHandler, {
      method: 'PATCH',
      path: '/console/projects/project-cf-mutate-1',
      body: { name: 'Project CF Mutate Renamed' },
    });
    expect(updatedProject.status).toBe(200);
    expect(getPath(updatedProject.json, 'project', 'name')).toBe('Project CF Mutate Renamed');

    const archivedEnvironment = await callCf(adminHandler, {
      method: 'POST',
      path: '/console/environments/env-cf-mutate-1/archive',
    });
    expect(archivedEnvironment.status).toBe(200);
    expect(getPath(archivedEnvironment.json, 'environment', 'status')).toBe('ARCHIVED');

    const archivedProject = await callCf(adminHandler, {
      method: 'POST',
      path: '/console/projects/project-cf-mutate-1/archive',
    });
    expect(archivedProject.status).toBe(200);
    expect(getPath(archivedProject.json, 'project', 'status')).toBe('ARCHIVED');

    const archivedProjects = await callCf(adminHandler, {
      method: 'GET',
      path: '/console/projects?status=ARCHIVED',
    });
    expect(archivedProjects.status).toBe(200);
    const archivedProjectRows = Array.isArray(archivedProjects.json?.projects)
      ? archivedProjects.json?.projects
      : [];
    expect(archivedProjectRows.length).toBeGreaterThanOrEqual(1);
    expect(archivedProjectRows.every((entry: any) => String(entry?.status || '') === 'ARCHIVED')).toBe(
      true,
    );

    const activeProjects = await callCf(adminHandler, {
      method: 'GET',
      path: '/console/projects?status=ACTIVE',
    });
    expect(activeProjects.status).toBe(200);
    const activeProjectRows = Array.isArray(activeProjects.json?.projects)
      ? activeProjects.json?.projects
      : [];
    expect(activeProjectRows.every((entry: any) => String(entry?.status || '') === 'ACTIVE')).toBe(true);

    const invalidProjectStatus = await callCf(adminHandler, {
      method: 'GET',
      path: '/console/projects?status=INVALID',
    });
    expect(invalidProjectStatus.status).toBe(400);
    expect(invalidProjectStatus.json?.code).toBe('invalid_query');

    const archivedOnly = await callCf(adminHandler, {
      method: 'GET',
      path: '/console/environments?projectId=project-cf-mutate-1&status=ARCHIVED',
    });
    expect(archivedOnly.status).toBe(200);
    const archivedRows = Array.isArray(archivedOnly.json?.environments)
      ? archivedOnly.json?.environments
      : [];
    expect(archivedRows.length).toBeGreaterThanOrEqual(1);
    expect(archivedRows.every((entry: any) => String(entry?.status || '') === 'ARCHIVED')).toBe(true);

    const activeOnly = await callCf(adminHandler, {
      method: 'GET',
      path: '/console/environments?projectId=project-cf-mutate-1&status=ACTIVE',
    });
    expect(activeOnly.status).toBe(200);
    const activeRows = Array.isArray(activeOnly.json?.environments) ? activeOnly.json?.environments : [];
    expect(activeRows.length).toBe(0);

    const invalidStatus = await callCf(adminHandler, {
      method: 'GET',
      path: '/console/environments?status=INVALID',
    });
    expect(invalidStatus.status).toBe(400);
    expect(invalidStatus.json?.code).toBe('invalid_query');

    const createOnArchived = await callCf(adminHandler, {
      method: 'POST',
      path: '/console/environments',
      body: {
        projectId: 'project-cf-mutate-1',
        key: 'prod',
      },
    });
    expect(createOnArchived.status).toBe(409);
    expect(createOnArchived.json?.code).toBe('project_archived');

    const devHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['developer'], 'org-meta-cf-mutate-1', 'user-meta-cf-dev-1'),
      orgProjectEnv,
    });
    const forbidden = await callCf(devHandler, {
      method: 'POST',
      path: '/console/projects',
      body: {
        name: 'Forbidden CF Project',
      },
    });
    expect(forbidden.status).toBe(403);
    expect(forbidden.json?.code).toBe('forbidden');
  });

  test('GET /console/wallets returns wallets_not_configured without wallet service', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const res = await callCf(handler, {
      method: 'GET',
      path: '/console/wallets',
    });
    expect(res.status).toBe(501);
    expect(res.json?.code).toBe('wallets_not_configured');
  });

  test('GET /console/policies returns policies_not_configured without policy service', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const res = await callCf(handler, {
      method: 'GET',
      path: '/console/policies',
    });
    expect(res.status).toBe(501);
    expect(res.json?.code).toBe('policies_not_configured');
  });

  test('GET /console/policy/coverage returns wallets_not_configured without wallet service', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const res = await callCf(handler, {
      method: 'GET',
      path: '/console/policy/coverage',
    });
    expect(res.status).toBe(501);
    expect(res.json?.code).toBe('wallets_not_configured');
  });

  test('GET /console/export/governance returns api_keys_not_configured without API key service', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      wallets: createInMemoryConsoleWalletService(),
    });
    const res = await callCf(handler, {
      method: 'GET',
      path: '/console/export/governance',
    });
    expect(res.status).toBe(501);
    expect(res.json?.code).toBe('api_keys_not_configured');
  });

  test('cloudflare new console endpoints return *_not_configured when services are not wired', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });

    const gas = await callCf(handler, {
      method: 'GET',
      path: '/console/gas-sponsorship',
    });
    expect(gas.status).toBe(501);
    expect(gas.json?.code).toBe('gas_sponsorship_not_configured');

    const smartWallets = await callCf(handler, {
      method: 'GET',
      path: '/console/smart-wallets',
    });
    expect(smartWallets.status).toBe(501);
    expect(smartWallets.json?.code).toBe('smart_wallets_not_configured');

    const settings = await callCf(handler, {
      method: 'GET',
      path: '/console/settings/app?environmentId=env-test',
    });
    expect(settings.status).toBe(501);
    expect(settings.json?.code).toBe('settings_not_configured');

    const keyExports = await callCf(handler, {
      method: 'GET',
      path: '/console/key-exports',
    });
    expect(keyExports.status).toBe(501);
    expect(keyExports.json?.code).toBe('key_exports_not_configured');

    const runtimeSnapshots = await callCf(handler, {
      method: 'GET',
      path: '/console/runtime-snapshots?environmentId=env-test',
    });
    expect(runtimeSnapshots.status).toBe(501);
    expect(runtimeSnapshots.json?.code).toBe('runtime_snapshots_not_configured');
  });

  test('cloudflare new console endpoints support scaffold CRUD flows', async () => {
    const gasSponsorship = createInMemoryConsoleGasSponsorshipService();
    const smartWallets = createInMemoryConsoleSmartWalletService();
    const settings = createInMemoryConsoleSettingsService();
    const keyExports = createInMemoryConsoleKeyExportService();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-scaffold-cf-1', 'user-scaffold-cf-1'),
      gasSponsorship,
      smartWallets,
      settings,
      keyExports,
      runtimeSnapshots,
    });

    const createdGas = await callCf(handler, {
      method: 'POST',
      path: '/console/gas-sponsorship',
      body: {
        id: 'gs-cf-1',
        scopeType: 'ENVIRONMENT',
        environmentId: 'prod',
        enabled: true,
        chainBudgets: [
          {
            chain: 'Ethereum',
            period: 'MONTHLY',
            budgetMinor: 500000,
            quotaTransactions: 2000,
          },
        ],
      },
    });
    expect(createdGas.status).toBe(201);
    expect(getPath(createdGas.json, 'config', 'id')).toBe('gs-cf-1');

    const listedGas = await callCf(handler, {
      method: 'GET',
      path: '/console/gas-sponsorship?environmentId=prod',
    });
    expect(listedGas.status).toBe(200);
    const listedGasRows: unknown[] = Array.isArray(listedGas.json?.configs)
      ? (listedGas.json?.configs as unknown[])
      : [];
    expect(listedGasRows.length).toBeGreaterThanOrEqual(1);

    const patchedGas = await callCf(handler, {
      method: 'PATCH',
      path: '/console/gas-sponsorship/gs-cf-1',
      body: {
        enabled: false,
      },
    });
    expect(patchedGas.status).toBe(200);
    expect(getPath(patchedGas.json, 'config', 'enabled')).toBe(false);

    const createdSmartWallet = await callCf(handler, {
      method: 'POST',
      path: '/console/smart-wallets',
      body: {
        id: 'sw-cf-1',
        scopeType: 'ENVIRONMENT',
        environmentId: 'prod',
        mode: 'REQUIRED',
        accountType: 'SMART_ACCOUNT',
      },
    });
    expect(createdSmartWallet.status).toBe(201);
    expect(getPath(createdSmartWallet.json, 'config', 'id')).toBe('sw-cf-1');

    const listedSmartWallets = await callCf(handler, {
      method: 'GET',
      path: '/console/smart-wallets?environmentId=prod',
    });
    expect(listedSmartWallets.status).toBe(200);
    const listedSmartWalletRows: unknown[] = Array.isArray(listedSmartWallets.json?.configs)
      ? (listedSmartWallets.json?.configs as unknown[])
      : [];
    expect(listedSmartWalletRows.length).toBeGreaterThanOrEqual(1);

    const updatedAppSettings = await callCf(handler, {
      method: 'PATCH',
      path: '/console/settings/app',
      body: {
        environmentId: 'prod',
        allowedOrigins: ['https://dashboard.example.com'],
      },
    });
    expect(updatedAppSettings.status).toBe(200);
    expect(getPath(updatedAppSettings.json, 'appSettings', 'environmentId')).toBe('prod');
    expect(getPath(updatedAppSettings.json, 'appSettings', 'allowedOrigins', 0)).toBe(
      'https://dashboard.example.com',
    );

    const fetchedSecuritySettings = await callCf(handler, {
      method: 'GET',
      path: '/console/settings/security?environmentId=prod',
    });
    expect(fetchedSecuritySettings.status).toBe(200);
    expect(getPath(fetchedSecuritySettings.json, 'securitySettings', 'environmentId')).toBe('prod');

    const createdKeyExport = await callCf(handler, {
      method: 'POST',
      path: '/console/key-exports',
      body: {
        id: 'ke-cf-1',
        environmentId: 'prod',
        reason: 'Emergency rotation',
        requiredApprovals: 1,
      },
    });
    expect(createdKeyExport.status).toBe(201);
    expect(getPath(createdKeyExport.json, 'keyExport', 'status')).toBe('PENDING_APPROVAL');

    const approvedKeyExport = await callCf(handler, {
      method: 'POST',
      path: '/console/key-exports/ke-cf-1/approve',
      body: {
        reason: 'Approved with MFA',
        mfaVerified: true,
      },
    });
    expect(approvedKeyExport.status).toBe(200);
    expect(getPath(approvedKeyExport.json, 'keyExport', 'status')).toBe('APPROVED');

    const publishedSnapshot = await callCf(handler, {
      method: 'POST',
      path: '/console/runtime-snapshots/publish-current',
      body: {
        environmentId: 'prod',
      },
    });
    expect(publishedSnapshot.status).toBe(201);
    expect(Number(getPath(publishedSnapshot.json, 'snapshot', 'version') || 0)).toBe(1);
    expect(String(getPath(publishedSnapshot.json, 'snapshot', 'checksum') || '')).toContain(
      'fnv1a32:',
    );
    expect(getPath(publishedSnapshot.json, 'snapshot', 'payload', 'settings', 'status')).toBe(
      'resolved',
    );
    expect(getPath(publishedSnapshot.json, 'snapshot', 'payload', 'gasSponsorship', 'status')).toBe(
      'resolved',
    );
    expect(getPath(publishedSnapshot.json, 'snapshot', 'payload', 'smartWallets', 'status')).toBe(
      'resolved',
    );
    expect(
      getPath(
        publishedSnapshot.json,
        'snapshot',
        'payload',
        'settings',
        'appSettings',
        'allowedOrigins',
        0,
      ),
    ).toBe('https://dashboard.example.com');

    const latestSnapshot = await callCf(handler, {
      method: 'GET',
      path: '/console/runtime-snapshots/latest?environmentId=prod',
    });
    expect(latestSnapshot.status).toBe(200);
    expect(getPath(latestSnapshot.json, 'snapshot', 'environmentId')).toBe('prod');
    expect(Number(getPath(latestSnapshot.json, 'snapshot', 'version') || 0)).toBe(1);

    const listedSnapshots = await callCf(handler, {
      method: 'GET',
      path: '/console/runtime-snapshots?environmentId=prod&limit=5',
    });
    expect(listedSnapshots.status).toBe(200);
    const snapshotRows = Array.isArray(listedSnapshots.json?.snapshots)
      ? listedSnapshots.json?.snapshots
      : [];
    expect(snapshotRows.length).toBeGreaterThanOrEqual(1);
  });

  test('cloudflare runtime snapshot publish-current emits not_configured markers and monotonic versions', async () => {
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-runtime-contract-cf-1',
        'user-runtime-contract-cf-1',
      ),
      runtimeSnapshots,
    });

    const first = await callCf(handler, {
      method: 'POST',
      path: '/console/runtime-snapshots/publish-current',
      body: {
        environmentId: 'prod',
        projectId: 'project-alpha',
        snapshotId: 'runtime-contract-v1',
        effectiveAt: '2026-03-01T00:00:00.000Z',
      },
    });
    expect(first.status).toBe(201);
    expect(getPath(first.json, 'snapshot', 'snapshotId')).toBe('runtime-contract-v1');
    expect(Number(getPath(first.json, 'snapshot', 'version') || 0)).toBe(1);
    expect(getPath(first.json, 'snapshot', 'payload', 'policy', 'status')).toBe('not_configured');
    expect(getPath(first.json, 'snapshot', 'payload', 'settings', 'status')).toBe('not_configured');
    expect(getPath(first.json, 'snapshot', 'payload', 'gasSponsorship', 'status')).toBe(
      'not_configured',
    );
    expect(getPath(first.json, 'snapshot', 'payload', 'smartWallets', 'status')).toBe(
      'not_configured',
    );
    const firstChecksum = String(getPath(first.json, 'snapshot', 'checksum') || '');
    expect(firstChecksum).toContain('fnv1a32:');

    const second = await callCf(handler, {
      method: 'POST',
      path: '/console/runtime-snapshots/publish-current',
      body: {
        environmentId: 'prod',
        projectId: 'project-alpha',
        snapshotId: 'runtime-contract-v2',
        effectiveAt: '2026-03-01T01:00:00.000Z',
      },
    });
    expect(second.status).toBe(201);
    expect(getPath(second.json, 'snapshot', 'snapshotId')).toBe('runtime-contract-v2');
    expect(Number(getPath(second.json, 'snapshot', 'version') || 0)).toBe(2);
    expect(String(getPath(second.json, 'snapshot', 'checksum') || '')).not.toBe(firstChecksum);

    const latest = await callCf(handler, {
      method: 'GET',
      path: '/console/runtime-snapshots/latest?environmentId=prod&projectId=project-alpha',
    });
    expect(latest.status).toBe(200);
    expect(getPath(latest.json, 'snapshot', 'snapshotId')).toBe('runtime-contract-v2');
    expect(Number(getPath(latest.json, 'snapshot', 'version') || 0)).toBe(2);

    const listed = await callCf(handler, {
      method: 'GET',
      path: '/console/runtime-snapshots?environmentId=prod&projectId=project-alpha&limit=2',
    });
    expect(listed.status).toBe(200);
    expect(getPath(listed.json, 'snapshots', 0, 'snapshotId')).toBe('runtime-contract-v2');
    expect(getPath(listed.json, 'snapshots', 1, 'snapshotId')).toBe('runtime-contract-v1');
  });

  test('cloudflare new console endpoint mutations enforce role gates', async () => {
    const gasSponsorship = createInMemoryConsoleGasSponsorshipService();
    const smartWallets = createInMemoryConsoleSmartWalletService();
    const settings = createInMemoryConsoleSettingsService();
    const keyExports = createInMemoryConsoleKeyExportService();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['developer'],
        'org-scaffold-cf-rbac-1',
        'user-scaffold-cf-rbac-1',
      ),
      gasSponsorship,
      smartWallets,
      settings,
      keyExports,
      runtimeSnapshots,
    });

    const gasCreate = await callCf(handler, {
      method: 'POST',
      path: '/console/gas-sponsorship',
      body: {
        scopeType: 'ORG',
      },
    });
    expect(gasCreate.status).toBe(403);
    expect(gasCreate.json?.code).toBe('forbidden');

    const appPatch = await callCf(handler, {
      method: 'PATCH',
      path: '/console/settings/app',
      body: {
        environmentId: 'prod',
        allowedOrigins: ['https://dashboard.example.com'],
      },
    });
    expect(appPatch.status).toBe(403);
    expect(appPatch.json?.code).toBe('forbidden');

    const approve = await callCf(handler, {
      method: 'POST',
      path: '/console/key-exports/ke-cf-rbac-1/approve',
      body: {
        reason: 'trying as non-admin',
        mfaVerified: true,
      },
    });
    expect(approve.status).toBe(403);
    expect(approve.json?.code).toBe('forbidden');

    const publishSnapshot = await callCf(handler, {
      method: 'POST',
      path: '/console/runtime-snapshots/publish',
      body: {
        environmentId: 'prod',
        payload: {
          policy: {},
          settings: {},
          gasSponsorship: {},
          smartWallets: {},
        },
      },
    });
    expect(publishSnapshot.status).toBe(403);
    expect(publishSnapshot.json?.code).toBe('forbidden');

    const publishCurrentSnapshot = await callCf(handler, {
      method: 'POST',
      path: '/console/runtime-snapshots/publish-current',
      body: {
        environmentId: 'prod',
      },
    });
    expect(publishCurrentSnapshot.status).toBe(403);
    expect(publishCurrentSnapshot.json?.code).toBe('forbidden');
  });

  test('cloudflare new console endpoint validation errors return typed error codes', async () => {
    const gasSponsorship = createInMemoryConsoleGasSponsorshipService();
    const smartWallets = createInMemoryConsoleSmartWalletService();
    const settings = createInMemoryConsoleSettingsService();
    const keyExports = createInMemoryConsoleKeyExportService();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-scaffold-cf-validation-1',
        'user-scaffold-cf-validation-1',
      ),
      gasSponsorship,
      smartWallets,
      settings,
      keyExports,
      runtimeSnapshots,
    });

    const invalidGasScope = await callCf(handler, {
      method: 'POST',
      path: '/console/gas-sponsorship',
      body: {
        scopeType: 'ENVIRONMENT',
      },
    });
    expect(invalidGasScope.status).toBe(400);
    expect(invalidGasScope.json?.code).toBe('invalid_scope');

    const invalidAppPatch = await callCf(handler, {
      method: 'PATCH',
      path: '/console/settings/app',
      body: {
        allowedOrigins: ['https://dashboard.example.com'],
      },
    });
    expect(invalidAppPatch.status).toBe(400);
    expect(invalidAppPatch.json?.code).toBe('invalid_body');

    const invalidStatusQuery = await callCf(handler, {
      method: 'GET',
      path: '/console/key-exports?status=NOT_A_STATUS',
    });
    expect(invalidStatusQuery.status).toBe(400);
    expect(invalidStatusQuery.json?.code).toBe('invalid_query');

    const createdKeyExport = await callCf(handler, {
      method: 'POST',
      path: '/console/key-exports',
      body: {
        id: 'ke-cf-validation-1',
        environmentId: 'prod',
        reason: 'Validation flow',
        requiredApprovals: 1,
      },
    });
    expect(createdKeyExport.status).toBe(201);

    const approveWithoutMfa = await callCf(handler, {
      method: 'POST',
      path: '/console/key-exports/ke-cf-validation-1/approve',
      body: {
        reason: 'Missing MFA check',
        mfaVerified: false,
      },
    });
    expect(approveWithoutMfa.status).toBe(400);
    expect(approveWithoutMfa.json?.code).toBe('mfa_required');

    const invalidSnapshotQuery = await callCf(handler, {
      method: 'GET',
      path: '/console/runtime-snapshots?environmentId=prod&limit=999',
    });
    expect(invalidSnapshotQuery.status).toBe(400);
    expect(invalidSnapshotQuery.json?.code).toBe('invalid_query');

    const invalidSnapshotBody = await callCf(handler, {
      method: 'POST',
      path: '/console/runtime-snapshots/publish',
      body: {
        environmentId: 'prod',
        payload: {
          policy: {},
        },
      },
    });
    expect(invalidSnapshotBody.status).toBe(400);
    expect(invalidSnapshotBody.json?.code).toBe('invalid_body');

    const invalidPublishCurrentBody = await callCf(handler, {
      method: 'POST',
      path: '/console/runtime-snapshots/publish-current',
      body: {
        projectId: 'project-only',
      },
    });
    expect(invalidPublishCurrentBody.status).toBe(400);
    expect(invalidPublishCurrentBody.json?.code).toBe('invalid_body');
  });

  test('cloudflare new console endpoints enforce org isolation', async () => {
    const gasSponsorship = createInMemoryConsoleGasSponsorshipService();
    const smartWallets = createInMemoryConsoleSmartWalletService();
    const settings = createInMemoryConsoleSettingsService();
    const keyExports = createInMemoryConsoleKeyExportService();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    const ownerOrgId = 'org-scaffold-cf-isolation-owner';
    const attackerOrgId = 'org-scaffold-cf-isolation-attacker';
    const ownerEnvironmentId = 'env-isolation-owner-cf';

    const ownerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-scaffold-cf-isolation-user'),
      gasSponsorship,
      smartWallets,
      settings,
      keyExports,
      runtimeSnapshots,
    });
    const createGas = await callCf(ownerHandler, {
      method: 'POST',
      path: '/console/gas-sponsorship',
      body: {
        id: 'gs-cf-isolation-1',
        scopeType: 'ENVIRONMENT',
        environmentId: ownerEnvironmentId,
      },
    });
    expect(createGas.status).toBe(201);

    const createSmartWallet = await callCf(ownerHandler, {
      method: 'POST',
      path: '/console/smart-wallets',
      body: {
        id: 'sw-cf-isolation-1',
        scopeType: 'ENVIRONMENT',
        environmentId: ownerEnvironmentId,
        mode: 'REQUIRED',
        accountType: 'SMART_ACCOUNT',
      },
    });
    expect(createSmartWallet.status).toBe(201);

    const patchAppSettings = await callCf(ownerHandler, {
      method: 'PATCH',
      path: '/console/settings/app',
      body: {
        environmentId: ownerEnvironmentId,
        allowedOrigins: ['https://owner-cf.example.com'],
      },
    });
    expect(patchAppSettings.status).toBe(200);

    const patchSecuritySettings = await callCf(ownerHandler, {
      method: 'PATCH',
      path: '/console/settings/security',
      body: {
        environmentId: ownerEnvironmentId,
        requireMfaForRiskyChanges: false,
      },
    });
    expect(patchSecuritySettings.status).toBe(200);

    const createKeyExport = await callCf(ownerHandler, {
      method: 'POST',
      path: '/console/key-exports',
      body: {
        id: 'ke-cf-isolation-1',
        environmentId: ownerEnvironmentId,
        reason: 'Owner export request',
        requiredApprovals: 1,
      },
    });
    expect(createKeyExport.status).toBe(201);

    const publishSnapshot = await callCf(ownerHandler, {
      method: 'POST',
      path: '/console/runtime-snapshots/publish-current',
      body: {
        environmentId: ownerEnvironmentId,
      },
    });
    expect(publishSnapshot.status).toBe(201);

    const attackerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-scaffold-cf-isolation-user'),
      gasSponsorship,
      smartWallets,
      settings,
      keyExports,
      runtimeSnapshots,
    });
    const gasList = await callCf(attackerHandler, {
      method: 'GET',
      path: `/console/gas-sponsorship?environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
    });
    expect(gasList.status).toBe(200);
    const attackerGasRows = Array.isArray(gasList.json?.configs) ? gasList.json?.configs : [];
    expect(attackerGasRows.length).toBe(0);

    const patchGas = await callCf(attackerHandler, {
      method: 'PATCH',
      path: '/console/gas-sponsorship/gs-cf-isolation-1',
      body: { enabled: false },
    });
    expect(patchGas.status).toBe(404);
    expect(patchGas.json?.code).toBe('gas_sponsorship_not_found');

    const smartWalletList = await callCf(attackerHandler, {
      method: 'GET',
      path: `/console/smart-wallets?environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
    });
    expect(smartWalletList.status).toBe(200);
    const attackerSmartWalletRows = Array.isArray(smartWalletList.json?.configs)
      ? smartWalletList.json?.configs
      : [];
    expect(attackerSmartWalletRows.length).toBe(0);

    const patchSmartWallet = await callCf(attackerHandler, {
      method: 'PATCH',
      path: '/console/smart-wallets/sw-cf-isolation-1',
      body: { enabled: false },
    });
    expect(patchSmartWallet.status).toBe(404);
    expect(patchSmartWallet.json?.code).toBe('smart_wallet_config_not_found');

    const getAppSettings = await callCf(attackerHandler, {
      method: 'GET',
      path: `/console/settings/app?environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
    });
    expect(getAppSettings.status).toBe(200);
    expect(getPath(getAppSettings.json, 'appSettings', 'allowedOrigins', 0)).toBeUndefined();

    const getSecuritySettings = await callCf(attackerHandler, {
      method: 'GET',
      path: `/console/settings/security?environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
    });
    expect(getSecuritySettings.status).toBe(200);
    expect(getPath(getSecuritySettings.json, 'securitySettings', 'requireMfaForRiskyChanges')).toBe(
      true,
    );

    const keyExportsList = await callCf(attackerHandler, {
      method: 'GET',
      path: `/console/key-exports?environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
    });
    expect(keyExportsList.status).toBe(200);
    const attackerKeyExportRows = Array.isArray(keyExportsList.json?.exports)
      ? keyExportsList.json?.exports
      : [];
    expect(attackerKeyExportRows.length).toBe(0);

    const approveKeyExport = await callCf(attackerHandler, {
      method: 'POST',
      path: '/console/key-exports/ke-cf-isolation-1/approve',
      body: {
        reason: 'attacker approve attempt',
        mfaVerified: true,
      },
    });
    expect(approveKeyExport.status).toBe(404);
    expect(approveKeyExport.json?.code).toBe('key_export_not_found');

    const attackerSnapshots = await callCf(attackerHandler, {
      method: 'GET',
      path: `/console/runtime-snapshots?environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
    });
    expect(attackerSnapshots.status).toBe(200);
    const attackerSnapshotRows = Array.isArray(attackerSnapshots.json?.snapshots)
      ? attackerSnapshots.json?.snapshots
      : [];
    expect(attackerSnapshotRows.length).toBe(0);

    const attackerLatestSnapshot = await callCf(attackerHandler, {
      method: 'GET',
      path: `/console/runtime-snapshots/latest?environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
    });
    expect(attackerLatestSnapshot.status).toBe(200);
    expect(attackerLatestSnapshot.json?.snapshot).toBeNull();
  });

  test('cloudflare wallet routes support list/search/detail', async () => {
    const wallets = createInMemoryConsoleWalletService();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-wallet-cf-1', 'user-wallet-cf-1'),
      wallets,
    });

    const listed = await callCf(handler, {
      method: 'GET',
      path: '/console/wallets?limit=5&chain=Ethereum',
    });
    expect(listed.status).toBe(200);
    const rows = Array.isArray(listed.json?.wallets) ? listed.json?.wallets : [];
    expect(rows.length).toBeGreaterThanOrEqual(1);
    const walletId = String(getPath(listed.json, 'wallets', 0, 'id') || '');
    expect(walletId).toBeTruthy();

    const searched = await callCf(handler, {
      method: 'GET',
      path: `/console/wallets/search?q=${encodeURIComponent(walletId.slice(0, 10))}`,
    });
    expect(searched.status).toBe(200);
    const searchedRows = Array.isArray(searched.json?.wallets) ? searched.json?.wallets : [];
    expect(searchedRows.some((entry: any) => String(entry?.id || '') === walletId)).toBe(true);

    const detail = await callCf(handler, {
      method: 'GET',
      path: `/console/wallets/${encodeURIComponent(walletId)}`,
    });
    expect(detail.status).toBe(200);
    expect(String(getPath(detail.json, 'wallet', 'id') || '')).toBe(walletId);

    const missing = await callCf(handler, {
      method: 'GET',
      path: '/console/wallets/wallet_missing',
    });
    expect(missing.status).toBe(404);
    expect(missing.json?.code).toBe('wallet_not_found');
  });

  test('cloudflare policy/gas/export insight routes return aggregated views', async () => {
    const wallets = createInMemoryConsoleWalletService();
    const apiKeys = createInMemoryConsoleApiKeyService();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-insights-cloudflare-1',
        'user-insights-cloudflare-1',
      ),
      wallets,
      apiKeys,
    });

    const createdExportKey = await callCf(handler, {
      method: 'POST',
      path: '/console/api-keys',
      body: {
        name: 'export-key-cf',
        environmentId: 'prod',
        scopes: ['wallets:read', 'keys:export'],
      },
    });
    expect(createdExportKey.status).toBe(201);

    const createdNonExportKey = await callCf(handler, {
      method: 'POST',
      path: '/console/api-keys',
      body: {
        name: 'non-export-key-cf',
        environmentId: 'staging',
        scopes: ['wallets:read'],
      },
    });
    expect(createdNonExportKey.status).toBe(201);

    const coverage = await callCf(handler, {
      method: 'GET',
      path: '/console/policy/coverage',
    });
    expect(coverage.status).toBe(200);
    expect(Number(getPath(coverage.json, 'coverage', 'totals', 'walletCount') || 0)).toBeGreaterThanOrEqual(1);
    const policyRows: unknown[] = Array.isArray(getPath(coverage.json, 'coverage', 'policies'))
      ? (getPath(coverage.json, 'coverage', 'policies') as unknown[])
      : [];
    expect(policyRows.length).toBeGreaterThanOrEqual(1);

    const readiness = await callCf(handler, {
      method: 'GET',
      path: '/console/gas/readiness',
    });
    expect(readiness.status).toBe(200);
    expect(Number(getPath(readiness.json, 'readiness', 'totals', 'walletCount') || 0)).toBeGreaterThanOrEqual(1);
    const chainRows: unknown[] = Array.isArray(getPath(readiness.json, 'readiness', 'chains'))
      ? (getPath(readiness.json, 'readiness', 'chains') as unknown[])
      : [];
    expect(chainRows.length).toBeGreaterThanOrEqual(1);

    const governance = await callCf(handler, {
      method: 'GET',
      path: '/console/export/governance?environmentId=prod',
    });
    expect(governance.status).toBe(200);
    expect(Number(getPath(governance.json, 'governance', 'totals', 'apiKeyCount') || 0)).toBe(2);
    expect(Number(getPath(governance.json, 'governance', 'totals', 'exportScopedKeyCount') || 0)).toBe(1);
    expect(
      Number(
        getPath(
          governance.json,
          'governance',
          'totals',
          'selectedEnvironmentExportScopedKeyCount',
        ) || 0,
      ),
    ).toBe(1);
  });

  test('cloudflare policy routes support draft/update/simulate/publish lifecycle with role gates', async () => {
    const policies = createInMemoryConsolePolicyService();
    const adminHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-policy-cf-1', 'user-policy-admin-cf-1'),
      policies,
    });

    const listed = await callCf(adminHandler, {
      method: 'GET',
      path: '/console/policies',
    });
    expect(listed.status).toBe(200);
    const policiesBefore = Array.isArray(listed.json?.policies) ? listed.json?.policies : [];
    expect(policiesBefore.length).toBeGreaterThanOrEqual(1);

    const created = await callCf(adminHandler, {
      method: 'POST',
      path: '/console/policies',
      body: {
        id: 'policy-cf-lifecycle-1',
        name: 'Policy Cloudflare Lifecycle',
        rules: {
          blockedActions: [],
          allowedChains: ['ethereum'],
          maxAmountMinor: 5000,
        },
      },
    });
    expect(created.status).toBe(201);
    expect(getPath(created.json, 'policy', 'id')).toBe('policy-cf-lifecycle-1');
    expect(getPath(created.json, 'policy', 'status')).toBe('DRAFT');
    expect(Number(getPath(created.json, 'policy', 'version') || 0)).toBe(0);

    const allowedSimulation = await callCf(adminHandler, {
      method: 'POST',
      path: '/console/policies/policy-cf-lifecycle-1/simulate',
      body: {
        action: 'transfer',
        chain: 'ethereum',
        amountMinor: 4000,
      },
    });
    expect(allowedSimulation.status).toBe(200);
    expect(getPath(allowedSimulation.json, 'simulation', 'decision')).toBe('ALLOW');

    const patched = await callCf(adminHandler, {
      method: 'PATCH',
      path: '/console/policies/policy-cf-lifecycle-1',
      body: {
        rules: {
          blockedActions: ['transfer'],
          allowedChains: ['ethereum'],
        },
      },
    });
    expect(patched.status).toBe(200);
    expect(getPath(patched.json, 'policy', 'status')).toBe('DRAFT');

    const deniedSimulation = await callCf(adminHandler, {
      method: 'POST',
      path: '/console/policies/policy-cf-lifecycle-1/simulate',
      body: {
        action: 'transfer',
        chain: 'ethereum',
        amountMinor: 1,
      },
    });
    expect(deniedSimulation.status).toBe(200);
    expect(getPath(deniedSimulation.json, 'simulation', 'decision')).toBe('DENY');

    const published = await callCf(adminHandler, {
      method: 'POST',
      path: '/console/policies/policy-cf-lifecycle-1/publish',
    });
    expect(published.status).toBe(200);
    expect(getPath(published.json, 'result', 'published')).toBe(true);
    expect(getPath(published.json, 'result', 'policy', 'status')).toBe('PUBLISHED');
    expect(Number(getPath(published.json, 'result', 'policy', 'version') || 0)).toBe(1);

    const developerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['developer'], 'org-policy-cf-1', 'user-policy-dev-cf-1'),
      policies,
    });
    const forbiddenCreate = await callCf(developerHandler, {
      method: 'POST',
      path: '/console/policies',
      body: {
        id: 'policy-cf-forbidden-1',
        name: 'Forbidden policy',
      },
    });
    expect(forbiddenCreate.status).toBe(403);
    expect(forbiddenCreate.json?.code).toBe('forbidden');
  });

  test('cloudflare policy routes enforce org isolation', async () => {
    const policies = createInMemoryConsolePolicyService();
    const ownerPolicyId = 'policy-owner-cf-isolation-1';

    const ownerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-policy-owner-cf', 'owner-policy-user-cf'),
      policies,
    });
    const created = await callCf(ownerHandler, {
      method: 'POST',
      path: '/console/policies',
      body: {
        id: ownerPolicyId,
        name: 'Owner Policy CF',
      },
    });
    expect(created.status).toBe(201);

    const attackerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-policy-attacker-cf', 'attacker-policy-user-cf'),
      policies,
    });
    const listed = await callCf(attackerHandler, {
      method: 'GET',
      path: '/console/policies',
    });
    expect(listed.status).toBe(200);
    const attackerPolicies = Array.isArray(listed.json?.policies) ? listed.json?.policies : [];
    expect(attackerPolicies.some((entry: any) => String(entry?.id || '') === ownerPolicyId)).toBe(
      false,
    );

    const patched = await callCf(attackerHandler, {
      method: 'PATCH',
      path: `/console/policies/${encodeURIComponent(ownerPolicyId)}`,
      body: {
        name: 'attacker update cf',
      },
    });
    expect(patched.status).toBe(404);
    expect(patched.json?.code).toBe('policy_not_found');

    const simulated = await callCf(attackerHandler, {
      method: 'POST',
      path: `/console/policies/${encodeURIComponent(ownerPolicyId)}/simulate`,
      body: {
        action: 'transfer',
      },
    });
    expect(simulated.status).toBe(404);
    expect(simulated.json?.code).toBe('policy_not_found');
  });

  test('cloudflare policy assignments support precedence and drive policy coverage', async () => {
    const policies = createInMemoryConsolePolicyService();
    const wallets = createInMemoryConsoleWalletService();
    const adminHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-policy-assign-cloudflare',
        'policy-assign-admin-cf',
      ),
      policies,
      wallets,
    });

    const listedWallets = await callCf(adminHandler, {
      method: 'GET',
      path: '/console/wallets',
    });
    expect(listedWallets.status).toBe(200);
    const walletId = String(getPath(listedWallets.json, 'wallets', 0, 'id') || '');
    const projectId = String(getPath(listedWallets.json, 'wallets', 0, 'projectId') || '');
    const environmentId = String(getPath(listedWallets.json, 'wallets', 0, 'environmentId') || '');
    expect(walletId).toBeTruthy();
    expect(projectId).toBeTruthy();
    expect(environmentId).toBeTruthy();

    const createProjectPolicy = await callCf(adminHandler, {
      method: 'POST',
      path: '/console/policies',
      body: {
        id: 'policy-project-cloudflare-1',
        name: 'Project Policy Cloudflare',
      },
    });
    expect(createProjectPolicy.status).toBe(201);

    const createWalletPolicy = await callCf(adminHandler, {
      method: 'POST',
      path: '/console/policies',
      body: {
        id: 'policy-wallet-cloudflare-1',
        name: 'Wallet Policy Cloudflare',
      },
    });
    expect(createWalletPolicy.status).toBe(201);

    const projectAssignment = await callCf(adminHandler, {
      method: 'PUT',
      path: '/console/policies/assignments',
      body: {
        scopeType: 'PROJECT',
        scopeId: projectId,
        policyId: 'policy-project-cloudflare-1',
      },
    });
    expect(projectAssignment.status).toBe(200);

    const walletAssignment = await callCf(adminHandler, {
      method: 'PUT',
      path: '/console/policies/assignments',
      body: {
        scopeType: 'WALLET',
        scopeId: walletId,
        policyId: 'policy-wallet-cloudflare-1',
      },
    });
    expect(walletAssignment.status).toBe(200);
    const walletAssignmentId = String(getPath(walletAssignment.json, 'assignment', 'id') || '');
    expect(walletAssignmentId).toBeTruthy();

    const listedAssignments = await callCf(adminHandler, {
      method: 'GET',
      path: `/console/policies/assignments?scopeType=WALLET&scopeId=${encodeURIComponent(walletId)}`,
    });
    expect(listedAssignments.status).toBe(200);
    const assignmentRows = Array.isArray(listedAssignments.json?.assignments)
      ? listedAssignments.json?.assignments
      : [];
    expect(assignmentRows.length).toBe(1);
    expect(String(getPath(listedAssignments.json, 'assignments', 0, 'policyId') || '')).toBe(
      'policy-wallet-cloudflare-1',
    );

    const walletCoverage = await callCf(adminHandler, {
      method: 'GET',
      path: `/console/policy/coverage?projectId=${encodeURIComponent(projectId)}&environmentId=${encodeURIComponent(environmentId)}`,
    });
    expect(walletCoverage.status).toBe(200);
    const walletPolicyRows = Array.isArray(getPath(walletCoverage.json, 'coverage', 'policies'))
      ? (getPath(walletCoverage.json, 'coverage', 'policies') as any[])
      : [];
    expect(
      walletPolicyRows.some((entry) => String(entry?.policyId || '') === 'policy-wallet-cloudflare-1'),
    ).toBe(true);

    const removedWalletAssignment = await callCf(adminHandler, {
      method: 'DELETE',
      path: `/console/policies/assignments/${encodeURIComponent(walletAssignmentId)}`,
    });
    expect(removedWalletAssignment.status).toBe(200);
    expect(getPath(removedWalletAssignment.json, 'removed')).toBe(true);

    const projectCoverage = await callCf(adminHandler, {
      method: 'GET',
      path: `/console/policy/coverage?projectId=${encodeURIComponent(projectId)}&environmentId=${encodeURIComponent(environmentId)}`,
    });
    expect(projectCoverage.status).toBe(200);
    const projectPolicyRows = Array.isArray(getPath(projectCoverage.json, 'coverage', 'policies'))
      ? (getPath(projectCoverage.json, 'coverage', 'policies') as any[])
      : [];
    expect(
      projectPolicyRows.some((entry) => String(entry?.policyId || '') === 'policy-project-cloudflare-1'),
    ).toBe(true);

    const developerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['developer'],
        'org-policy-assign-cloudflare',
        'policy-assign-developer-cf',
      ),
      policies,
      wallets,
    });
    const forbiddenAssignment = await callCf(developerHandler, {
      method: 'PUT',
      path: '/console/policies/assignments',
      body: {
        scopeType: 'ORG',
        scopeId: 'org-policy-assign-cloudflare',
        policyId: 'org-policy-assign-cloudflare:policy:default',
      },
    });
    expect(forbiddenAssignment.status).toBe(403);
    expect(forbiddenAssignment.json?.code).toBe('forbidden');
  });

  test('cloudflare API key lifecycle works and secrets are reveal-once on create/rotate', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      apiKeys,
    });

    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/api-keys',
      body: {
        name: 'cloudflare-key',
        environmentId: 'prod',
        scopes: ['wallets:read'],
        ipAllowlist: ['198.51.100.5/32'],
      },
    });
    expect(created.status).toBe(201);
    const keyId = String(getPath(created.json, 'apiKey', 'id') || '');
    const createdSecret = String(getPath(created.json, 'secret') || '');
    expect(keyId).toBeTruthy();
    expect(createdSecret).toContain('tsk_');
    expect(Number(getPath(created.json, 'apiKey', 'secretVersion') || 0)).toBe(1);

    const listed = await callCf(handler, {
      method: 'GET',
      path: '/console/api-keys',
    });
    expect(listed.status).toBe(200);
    expect(String(getPath(listed.json, 'apiKeys', 0, 'id') || '')).toBe(keyId);
    expect(getPath(listed.json, 'apiKeys', 0, 'secret')).toBeUndefined();

    const rotated = await callCf(handler, {
      method: 'POST',
      path: `/console/api-keys/${encodeURIComponent(keyId)}/rotate`,
      body: {
        reason: 'manual rotate',
      },
    });
    expect(rotated.status).toBe(200);
    const rotatedSecret = String(getPath(rotated.json, 'secret') || '');
    expect(rotatedSecret).toContain('tsk_');
    expect(rotatedSecret).not.toBe(createdSecret);
    expect(Number(getPath(rotated.json, 'apiKey', 'secretVersion') || 0)).toBe(2);

    const revoked = await callCf(handler, {
      method: 'DELETE',
      path: `/console/api-keys/${encodeURIComponent(keyId)}`,
    });
    expect(revoked.status).toBe(200);
    expect(getPath(revoked.json, 'revoked')).toBe(true);
    expect(getPath(revoked.json, 'apiKey', 'status')).toBe('REVOKED');

    const rotateRevoked = await callCf(handler, {
      method: 'POST',
      path: `/console/api-keys/${encodeURIComponent(keyId)}/rotate`,
    });
    expect(rotateRevoked.status).toBe(409);
    expect(rotateRevoked.json?.code).toBe('api_key_revoked');
  });

  test('cloudflare webhook routes support delivery attempts, dead letters, and replay', async () => {
    let dispatchCalls = 0;
    const webhooks = createInMemoryConsoleWebhookService({
      dispatcher: {
        dispatch: async () => {
          dispatchCalls += 1;
          if (dispatchCalls === 1) {
            return {
              ok: false,
              statusCode: 500,
              responseBody: 'temporary failure',
              errorMessage: 'upstream failure',
            };
          }
          return {
            ok: true,
            statusCode: 200,
            responseBody: 'ok',
          };
        },
      },
    });
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      webhooks,
    });

    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/webhooks',
      body: {
        url: 'https://example.com/cloudflare-webhook',
        subscriptions: ['billing'],
      },
    });
    expect(created.status).toBe(201);
    const endpointId = String(getPath(created.json, 'endpoint', 'id') || '');
    expect(endpointId).toBeTruthy();

    const listed = await callCf(handler, {
      method: 'GET',
      path: '/console/webhooks',
    });
    expect(listed.status).toBe(200);
    expect(Array.isArray(listed.json?.endpoints)).toBe(true);
    expect(String(getPath(listed.json, 'endpoints', 0, 'id') || '')).toBe(endpointId);

    const emitted = await webhooks.emitEvent(
      {
        orgId: 'org-1',
        actorUserId: 'system-webhooks-test',
        roles: ['ops'],
      },
      {
        eventType: 'billing.invoice.paid',
        payload: {
          invoiceId: 'inv_cf_1',
        },
      },
    );
    expect(emitted.attempted).toBe(1);
    expect(emitted.delivered).toBe(0);
    expect(emitted.failed).toBe(1);

    const deliveries = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/deliveries`,
    });
    expect(deliveries.status).toBe(200);
    const rows = Array.isArray(deliveries.json?.deliveries) ? deliveries.json?.deliveries : [];
    expect(rows.length).toBe(1);
    expect(String(getPath(deliveries.json, 'deliveries', 0, 'status') || '')).toBe('FAILED');
    const deliveryId = String(getPath(deliveries.json, 'deliveries', 0, 'id') || '');
    expect(deliveryId).toBeTruthy();

    const attemptsBeforeReplay = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/attempts`,
    });
    expect(attemptsBeforeReplay.status).toBe(200);
    expect(Number(getPath(attemptsBeforeReplay.json, 'attempts', 0, 'attemptNo') || 0)).toBe(1);
    expect(getPath(attemptsBeforeReplay.json, 'attempts', 0, 'status')).toBe('FAILED');

    const unresolvedDlq = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/dead-letters`,
    });
    expect(unresolvedDlq.status).toBe(200);
    const unresolvedRows = Array.isArray(unresolvedDlq.json?.deadLetters)
      ? unresolvedDlq.json?.deadLetters
      : [];
    expect(unresolvedRows.length).toBe(1);
    expect(getPath(unresolvedDlq.json, 'deadLetters', 0, 'deliveryId')).toBe(deliveryId);
    expect(getPath(unresolvedDlq.json, 'deadLetters', 0, 'resolvedAt')).toBeNull();

    const replayed = await callCf(handler, {
      method: 'POST',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/replay`,
      body: { deliveryId },
    });
    expect(replayed.status).toBe(200);
    expect(getPath(replayed.json, 'replay', 'replayed')).toBe(true);
    expect(getPath(replayed.json, 'replay', 'delivery', 'status')).toBe('SUCCEEDED');

    const attemptsAfterReplay = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/attempts?deliveryId=${encodeURIComponent(deliveryId)}&limit=1`,
    });
    expect(attemptsAfterReplay.status).toBe(200);
    const replayAttempts = Array.isArray(attemptsAfterReplay.json?.attempts)
      ? attemptsAfterReplay.json?.attempts
      : [];
    expect(replayAttempts.length).toBe(1);
    expect(Number(getPath(attemptsAfterReplay.json, 'attempts', 0, 'attemptNo') || 0)).toBe(2);
    expect(getPath(attemptsAfterReplay.json, 'attempts', 0, 'isReplay')).toBe(true);
    const attemptsNextCursor = String(attemptsAfterReplay.json?.nextCursor || '');
    expect(attemptsNextCursor).toBeTruthy();

    const attemptsSecondPage = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/attempts?deliveryId=${encodeURIComponent(deliveryId)}&limit=1&cursor=${encodeURIComponent(attemptsNextCursor)}`,
    });
    expect(attemptsSecondPage.status).toBe(200);
    const replayAttemptsSecondPage = Array.isArray(attemptsSecondPage.json?.attempts)
      ? attemptsSecondPage.json?.attempts
      : [];
    expect(replayAttemptsSecondPage.length).toBe(1);
    expect(Number(getPath(attemptsSecondPage.json, 'attempts', 0, 'attemptNo') || 0)).toBe(1);
    expect(String(attemptsSecondPage.json?.nextCursor || '')).toBe('');

    const unresolvedAfterReplay = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/dead-letters`,
    });
    expect(unresolvedAfterReplay.status).toBe(200);
    const unresolvedRowsAfterReplay = Array.isArray(unresolvedAfterReplay.json?.deadLetters)
      ? unresolvedAfterReplay.json?.deadLetters
      : [];
    expect(unresolvedRowsAfterReplay.length).toBe(0);

    const resolvedDlq = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/dead-letters?includeResolved=true`,
    });
    expect(resolvedDlq.status).toBe(200);
    const resolvedRows = Array.isArray(resolvedDlq.json?.deadLetters)
      ? resolvedDlq.json?.deadLetters
      : [];
    expect(resolvedRows.length).toBe(1);
    expect(getPath(resolvedDlq.json, 'deadLetters', 0, 'deliveryId')).toBe(deliveryId);
    expect(Boolean(getPath(resolvedDlq.json, 'deadLetters', 0, 'resolvedAt'))).toBe(true);

    const updated = await callCf(handler, {
      method: 'PATCH',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}`,
      body: {
        status: 'DISABLED',
      },
    });
    expect(updated.status).toBe(200);
    expect(getPath(updated.json, 'endpoint', 'status')).toBe('DISABLED');

    const deleted = await callCf(handler, {
      method: 'DELETE',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}`,
    });
    expect(deleted.status).toBe(200);
    expect(deleted.json?.removed).toBe(true);
  });

  test('cloudflare webhook list endpoints reject malformed cursor', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      webhooks: createInMemoryConsoleWebhookService(),
    });

    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/webhooks',
      body: {
        url: 'https://example.com/bad-cursor-cloudflare',
        subscriptions: ['billing'],
      },
    });
    expect(created.status).toBe(201);
    const endpointId = String(getPath(created.json, 'endpoint', 'id') || '');
    expect(endpointId).toBeTruthy();

    const deliveries = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/deliveries?cursor=bad_cursor`,
    });
    expect(deliveries.status).toBe(400);
    expect(deliveries.json?.code).toBe('invalid_query');

    const attempts = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/attempts?cursor=bad_cursor`,
    });
    expect(attempts.status).toBe(400);
    expect(attempts.json?.code).toBe('invalid_query');

    const deadLetters = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/dead-letters?cursor=bad_cursor`,
    });
    expect(deadLetters.status).toBe(400);
    expect(deadLetters.json?.code).toBe('invalid_query');

    const oversizedSortKey = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/deliveries?cursor=9007199254740992%3Aoverflow`,
    });
    expect(oversizedSortKey.status).toBe(400);
    expect(oversizedSortKey.json?.code).toBe('invalid_query');
  });

  test('GET /console/billing/stablecoins/assets requires auth adapter', async () => {
    const handler = createCloudflareConsoleRouter({});
    const res = await callCf(handler, {
      method: 'GET',
      path: '/console/billing/stablecoins/assets',
    });
    expect(res.status).toBe(503);
    expect(res.json?.code).toBe('console_auth_not_configured');
  });

  test('GET /console/billing/stablecoins/assets returns supported assets/chains', async () => {
    const handler = createCloudflareConsoleRouter({ auth: makeConsoleAuthAdapter(['admin']) });
    const res = await callCf(handler, {
      method: 'GET',
      path: '/console/billing/stablecoins/assets',
    });
    expect(res.status).toBe(200);
    expect(res.json?.version).toBe('v1');
    expect(JSON.stringify(res.json?.assets || null)).toContain('"asset":"USDT"');
    expect(JSON.stringify(res.json?.assets || null)).toContain('"chain":"NEAR"');
    expect(JSON.stringify(res.json?.assets || null)).toContain('"requiredConfirmations":10');
  });

  test('POST /console/billing/payment-methods requires admin role', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['billing_admin']),
      billing: createInMemoryConsoleBillingService(),
    });
    const res = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/payment-methods',
      body: {},
    });
    expect(res.status).toBe(403);
    expect(res.json?.code).toBe('forbidden');
  });

  test(
    'POST /console/billing/stripe/checkout-session returns billing_not_configured without billing service',
    async () => {
      const handler = createCloudflareConsoleRouter({
        auth: makeConsoleAuthAdapter(['admin']),
      });
      const res = await callCf(handler, {
        method: 'POST',
        path: '/console/billing/stripe/checkout-session',
        body: {
          successUrl: 'https://app.example.com/dashboard/billing?checkout=success',
          cancelUrl: 'https://app.example.com/pricing?checkout=cancel',
        },
      });
      expect(res.status).toBe(501);
      expect(res.json?.code).toBe('billing_not_configured');
    },
  );

  test('POST /console/billing/stripe/checkout-session creates checkout session', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing: createInMemoryConsoleBillingService(),
    });
    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/checkout-session',
      body: {
        successUrl: 'https://app.example.com/dashboard/billing?checkout=success',
        cancelUrl: 'https://app.example.com/pricing?checkout=cancel',
        planId: 'pro_maw_v1',
      },
    });
    expect(created.status).toBe(201);
    const checkoutSessionId = String(getPath(created.json, 'checkoutSession', 'id') || '');
    const checkoutSessionUrl = String(getPath(created.json, 'checkoutSession', 'url') || '');
    expect(checkoutSessionId).toBeTruthy();
    expect(checkoutSessionUrl).toContain('https://checkout.stripe.com/pay/');
    expect(String(getPath(created.json, 'checkoutSession', 'customerRef') || '')).toContain('cus_');
    expect(String(getPath(created.json, 'checkoutSession', 'expiresAt') || '')).toMatch(
      /^\d{4}-\d{2}-\d{2}T/,
    );

    const invalid = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/checkout-session',
      body: {
        successUrl: '/dashboard/billing',
        cancelUrl: 'https://app.example.com/pricing?checkout=cancel',
      },
    });
    expect(invalid.status).toBe(400);
    expect(invalid.json?.code).toBe('invalid_body');
  });

  test(
    'POST /console/billing/stripe/customer-portal-session returns billing_not_configured without billing service',
    async () => {
      const handler = createCloudflareConsoleRouter({
        auth: makeConsoleAuthAdapter(['admin']),
      });
      const res = await callCf(handler, {
        method: 'POST',
        path: '/console/billing/stripe/customer-portal-session',
        body: {
          returnUrl: 'https://app.example.com/dashboard/billing',
        },
      });
      expect(res.status).toBe(501);
      expect(res.json?.code).toBe('billing_not_configured');
    },
  );

  test('POST /console/billing/stripe/customer-portal-session creates portal session', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing: createInMemoryConsoleBillingService(),
    });

    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/customer-portal-session',
      body: {
        returnUrl: 'https://app.example.com/dashboard/billing',
      },
    });
    expect(created.status).toBe(201);
    const sessionId = String(getPath(created.json, 'portalSession', 'id') || '');
    const sessionUrl = String(getPath(created.json, 'portalSession', 'url') || '');
    expect(sessionId).toBeTruthy();
    expect(sessionUrl).toContain('https://billing.stripe.com/p/session/');
    expect(String(getPath(created.json, 'portalSession', 'customerRef') || '')).toContain('cus_');

    const invalid = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/customer-portal-session',
      body: {
        returnUrl: '/dashboard/billing',
      },
    });
    expect(invalid.status).toBe(400);
    expect(invalid.json?.code).toBe('invalid_body');
  });

  test('GET /console/billing/subscription returns billing_not_configured without billing service', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const res = await callCf(handler, {
      method: 'GET',
      path: '/console/billing/subscription',
    });
    expect(res.status).toBe(501);
    expect(res.json?.code).toBe('billing_not_configured');
  });

  test('billing subscription lifecycle routes support get/cancel/resume', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing: createInMemoryConsoleBillingService(),
    });

    const initial = await callCf(handler, {
      method: 'GET',
      path: '/console/billing/subscription',
    });
    expect(initial.status).toBe(200);
    expect(getPath(initial.json, 'subscription', 'status')).toBe('ACTIVE');
    expect(getPath(initial.json, 'subscription', 'cancelAtPeriodEnd')).toBe(false);

    const canceled = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/subscription/cancel',
    });
    expect(canceled.status).toBe(200);
    expect(getPath(canceled.json, 'subscription', 'status')).toBe('ACTIVE');
    expect(getPath(canceled.json, 'subscription', 'cancelAtPeriodEnd')).toBe(true);

    const resumed = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/subscription/resume',
    });
    expect(resumed.status).toBe(200);
    expect(getPath(resumed.json, 'subscription', 'status')).toBe('ACTIVE');
    expect(getPath(resumed.json, 'subscription', 'cancelAtPeriodEnd')).toBe(false);
  });

  test('POST /console/billing/stripe/webhook requires configured shared secret', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing: createInMemoryConsoleBillingService(),
    });
    const res = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/webhook',
      body: {
        eventId: 'evt_cf_missing_secret',
        providerRef: 'pi_provider_missing',
        providerStatus: 'SUCCEEDED',
      },
    });
    expect(res.status).toBe(501);
    expect(res.json?.code).toBe('stripe_webhook_not_configured');
  });

  test('POST /console/billing/invoices/generate requires admin or ops role', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['billing_admin']),
      billing: createInMemoryConsoleBillingService(),
    });
    const res = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/invoices/generate',
      body: {
        periodMonthUtc: '2026-01',
      },
    });
    expect(res.status).toBe(403);
    expect(res.json?.code).toBe('forbidden');
  });

  test('billing flow: stablecoin intent locks rail from stripe card intent', async () => {
    const billing = createInMemoryConsoleBillingService();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
    });

    const invoices = await callCf(handler, {
      method: 'GET',
      path: '/console/billing/invoices',
    });
    expect(invoices.status).toBe(200);
    const invoiceId = Array.isArray(invoices.json?.invoices)
      ? (invoices.json?.invoices?.[0] as any)?.id
      : '';
    expect(invoiceId).toBeTruthy();

    const quote = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stablecoins/quotes',
      body: {
        invoiceId,
        asset: 'USDT',
        chain: 'Ethereum',
      },
    });
    expect(quote.status).toBe(201);
    const quoteId = String(getPath(quote.json, 'quote', 'id') || '');
    expect(quoteId).toBeTruthy();

    const intent = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stablecoins/payment-intents',
      body: {
        invoiceId,
        quoteId,
      },
    });
    expect(intent.status).toBe(201);
    expect(getPath(intent.json, 'paymentIntent', 'rail')).toBe('STABLECOIN');

    const stripeIntent = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/payment-intent',
      body: {
        invoiceId,
      },
    });
    expect(stripeIntent.status).toBe(409);
    expect(stripeIntent.json?.code).toBe('invoice_rail_locked');
  });

  test('stablecoin quote is single-use across payment intents', async () => {
    const billing = createInMemoryConsoleBillingService();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
    });

    const invoices = await callCf(handler, {
      method: 'GET',
      path: '/console/billing/invoices',
    });
    expect(invoices.status).toBe(200);
    const invoiceId = Array.isArray(invoices.json?.invoices)
      ? (invoices.json?.invoices?.[0] as any)?.id
      : '';
    expect(invoiceId).toBeTruthy();

    const quote = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stablecoins/quotes',
      body: {
        invoiceId,
        asset: 'USDT',
        chain: 'Ethereum',
      },
    });
    expect(quote.status).toBe(201);
    const quoteId = String(getPath(quote.json, 'quote', 'id') || '');
    expect(quoteId).toBeTruthy();

    const firstIntent = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stablecoins/payment-intents',
      body: { invoiceId, quoteId },
    });
    expect(firstIntent.status).toBe(201);
    const paymentIntentId = String(getPath(firstIntent.json, 'paymentIntent', 'id') || '');
    expect(paymentIntentId).toBeTruthy();

    const canceled = await callCf(handler, {
      method: 'POST',
      path: `/console/billing/stablecoins/payment-intents/${encodeURIComponent(paymentIntentId)}/cancel`,
    });
    expect(canceled.status).toBe(200);
    expect(getPath(canceled.json, 'paymentIntent', 'state')).toBe('CANCELED');

    const reused = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stablecoins/payment-intents',
      body: { invoiceId, quoteId },
    });
    expect(reused.status).toBe(409);
    expect(reused.json?.code).toBe('quote_already_consumed');
  });

  test('stripe payment intents reject concurrent active attempts', async () => {
    const billing = createInMemoryConsoleBillingService();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
    });

    const invoices = await callCf(handler, {
      method: 'GET',
      path: '/console/billing/invoices',
    });
    expect(invoices.status).toBe(200);
    const invoiceId = Array.isArray(invoices.json?.invoices)
      ? (invoices.json?.invoices?.[0] as any)?.id
      : '';
    expect(invoiceId).toBeTruthy();

    const firstIntent = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/payment-intent',
      body: { invoiceId },
    });
    expect(firstIntent.status).toBe(201);
    expect(getPath(firstIntent.json, 'paymentIntent', 'state')).toBe('CREATED');

    const secondIntent = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/payment-intent',
      body: { invoiceId },
    });
    expect(secondIntent.status).toBe(409);
    expect(secondIntent.json?.code).toBe('active_payment_intent_exists');
  });

  test('Stripe webhook reconciles payment intent by providerRef and dedupes event id', async () => {
    const billing = createInMemoryConsoleBillingService();
    const secret = 'whsec_console_router_cf_test';
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
      billingStripeWebhookSecret: secret,
    });

    const invoices = await callCf(handler, {
      method: 'GET',
      path: '/console/billing/invoices',
    });
    expect(invoices.status).toBe(200);
    const invoiceId = Array.isArray(invoices.json?.invoices)
      ? (invoices.json?.invoices?.[0] as any)?.id
      : '';
    expect(invoiceId).toBeTruthy();

    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/payment-intent',
      body: { invoiceId },
    });
    expect(created.status).toBe(201);
    const providerRef = String(getPath(created.json, 'paymentIntent', 'providerRef') || '');
    const amountMinor = Number(getPath(created.json, 'paymentIntent', 'amountMinor') || 0);
    expect(providerRef).toBeTruthy();
    expect(amountMinor).toBeGreaterThan(0);

    const unauthorized = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/webhook',
      body: {
        eventId: 'evt_cf_webhook_unauthorized',
        providerRef,
        providerStatus: 'SUCCEEDED',
        settledAmountMinor: amountMinor,
      },
    });
    expect(unauthorized.status).toBe(401);
    expect(unauthorized.json?.code).toBe('unauthorized');

    const eventId = `evt_cf_webhook_${Date.now()}`;
    const first = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/webhook',
      headers: {
        'x-console-stripe-webhook-secret': secret,
      },
      body: {
        eventId,
        providerRef,
        providerStatus: 'SUCCEEDED',
        settledAmountMinor: amountMinor,
      },
    });
    expect(first.status).toBe(200);
    expect(first.json?.accepted).toBe(true);
    expect(getPath(first.json, 'paymentIntent', 'state')).toBe('SETTLED');

    const duplicate = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/webhook',
      headers: {
        'x-console-stripe-webhook-secret': secret,
      },
      body: {
        eventId,
        providerRef,
        providerStatus: 'SUCCEEDED',
        settledAmountMinor: amountMinor,
      },
    });
    expect(duplicate.status).toBe(200);
    expect(duplicate.json?.accepted).toBe(false);
    expect(getPath(duplicate.json, 'paymentIntent', 'state')).toBe('SETTLED');
  });

  test('Stripe webhook projects subscription/invoice events idempotently', async () => {
    const billing = createInMemoryConsoleBillingService();
    const secret = 'whsec_console_router_cf_projection_test';
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
      billingStripeWebhookSecret: secret,
    });

    const subscriptionBefore = await callCf(handler, {
      method: 'GET',
      path: '/console/billing/subscription',
    });
    expect(subscriptionBefore.status).toBe(200);
    const providerSubscriptionRef = String(
      getPath(subscriptionBefore.json, 'subscription', 'providerSubscriptionRef') || '',
    );
    const providerCustomerRef = String(
      getPath(subscriptionBefore.json, 'subscription', 'providerCustomerRef') || '',
    );
    expect(providerSubscriptionRef).toBeTruthy();
    expect(providerCustomerRef).toBeTruthy();

    const invoices = await callCf(handler, {
      method: 'GET',
      path: '/console/billing/invoices',
    });
    expect(invoices.status).toBe(200);
    const invoiceId = Array.isArray(invoices.json?.invoices)
      ? String((invoices.json?.invoices?.[0] as any)?.id || '')
      : '';
    const invoiceAmountDueMinor = Array.isArray(invoices.json?.invoices)
      ? Number((invoices.json?.invoices?.[0] as any)?.amountDueMinor || 0)
      : 0;
    expect(invoiceId).toBeTruthy();
    expect(invoiceAmountDueMinor).toBeGreaterThan(0);

    const subscriptionEventId = `evt_cf_subscription_projection_${Date.now()}`;
    const projectedSubscription = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/webhook',
      headers: {
        'x-console-stripe-webhook-secret': secret,
      },
      body: {
        eventId: subscriptionEventId,
        eventType: 'customer.subscription.updated',
        orgId: 'org-1',
        providerSubscriptionRef,
        providerCustomerRef,
        subscriptionStatus: 'PAST_DUE',
        cancelAtPeriodEnd: true,
      },
    });
    expect(projectedSubscription.status).toBe(200);
    expect(projectedSubscription.json?.accepted).toBe(true);
    expect(getPath(projectedSubscription.json, 'subscription', 'status')).toBe('PAST_DUE');
    expect(getPath(projectedSubscription.json, 'subscription', 'cancelAtPeriodEnd')).toBe(true);

    const projectedSubscriptionDuplicate = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/webhook',
      headers: {
        'x-console-stripe-webhook-secret': secret,
      },
      body: {
        eventId: subscriptionEventId,
        eventType: 'customer.subscription.updated',
        orgId: 'org-1',
        providerSubscriptionRef,
        providerCustomerRef,
        subscriptionStatus: 'PAST_DUE',
        cancelAtPeriodEnd: true,
      },
    });
    expect(projectedSubscriptionDuplicate.status).toBe(200);
    expect(projectedSubscriptionDuplicate.json?.accepted).toBe(false);

    const projectedInvoice = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/webhook',
      headers: {
        'x-console-stripe-webhook-secret': secret,
      },
      body: {
        eventId: `evt_cf_invoice_projection_${Date.now()}`,
        eventType: 'invoice.paid',
        orgId: 'org-1',
        invoiceId,
        invoiceStatus: 'PAID',
        invoiceAmountPaidMinor: invoiceAmountDueMinor,
      },
    });
    expect(projectedInvoice.status).toBe(200);
    expect(projectedInvoice.json?.accepted).toBe(true);
    expect(getPath(projectedInvoice.json, 'invoice', 'status')).toBe('PAID');

    const subscriptionAfter = await callCf(handler, {
      method: 'GET',
      path: '/console/billing/subscription',
    });
    expect(subscriptionAfter.status).toBe(200);
    expect(getPath(subscriptionAfter.json, 'subscription', 'status')).toBe('PAST_DUE');

    const invoiceAfter = await callCf(handler, {
      method: 'GET',
      path: `/console/billing/invoices/${encodeURIComponent(invoiceId)}`,
    });
    expect(invoiceAfter.status).toBe(200);
    expect(getPath(invoiceAfter.json, 'invoice', 'status')).toBe('PAID');
  });

  test('billing usage endpoints compute MAW with exclusions and idempotency', async () => {
    const billing = createInMemoryConsoleBillingService();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
    });

    const e1 = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/usage/events',
      body: {
        walletId: 'wallet_cf_1',
        action: 'transfer',
        succeeded: true,
        sourceEventId: 'usage_cf_evt_1',
      },
    });
    expect(e1.status).toBe(200);
    expect(getPath(e1.json, 'result', 'accepted')).toBe(true);
    expect(getPath(e1.json, 'result', 'counted')).toBe(true);
    expect(Number(getPath(e1.json, 'result', 'monthlyActiveWallets') || 0)).toBe(1);
    const monthUtc = String(getPath(e1.json, 'result', 'monthUtc') || '');
    expect(monthUtc).toMatch(/^\d{4}-\d{2}$/);

    const e2 = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/usage/events',
      body: {
        walletId: 'wallet_cf_2',
        action: 'swap',
        succeeded: true,
        sourceEventId: 'usage_cf_evt_2',
      },
    });
    expect(e2.status).toBe(200);
    expect(Number(getPath(e2.json, 'result', 'monthlyActiveWallets') || 0)).toBe(2);

    const excluded = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/usage/events',
      body: {
        walletId: 'wallet_cf_3',
        action: 'wallet_created',
        succeeded: true,
        sourceEventId: 'usage_cf_evt_3',
      },
    });
    expect(excluded.status).toBe(200);
    expect(getPath(excluded.json, 'result', 'counted')).toBe(false);
    expect(Number(getPath(excluded.json, 'result', 'monthlyActiveWallets') || 0)).toBe(2);

    const duplicate = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/usage/events',
      body: {
        walletId: 'wallet_cf_2',
        action: 'swap',
        succeeded: true,
        sourceEventId: 'usage_cf_evt_2',
      },
    });
    expect(duplicate.status).toBe(200);
    expect(getPath(duplicate.json, 'result', 'accepted')).toBe(false);
    expect(Number(getPath(duplicate.json, 'result', 'monthlyActiveWallets') || 0)).toBe(2);

    const usage = await callCf(handler, {
      method: 'GET',
      path: `/console/billing/usage/monthly-active-wallets?monthUtc=${encodeURIComponent(monthUtc)}`,
    });
    expect(usage.status).toBe(200);
    expect(getPath(usage.json, 'usage', 'monthUtc')).toBe(monthUtc);
    expect(Number(getPath(usage.json, 'usage', 'monthlyActiveWallets') || 0)).toBe(2);
  });

  test('invoice generation endpoint returns deterministic line items', async () => {
    const billing = createInMemoryConsoleBillingService();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
    });

    await callCf(handler, {
      method: 'POST',
      path: '/console/billing/usage/events',
      body: {
        walletId: 'wallet_cf_gen_1',
        action: 'transfer',
        succeeded: true,
        occurredAt: '2026-01-05T01:00:00.000Z',
        sourceEventId: 'router_cf_gen_evt_1',
      },
    });
    await callCf(handler, {
      method: 'POST',
      path: '/console/billing/usage/events',
      body: {
        walletId: 'wallet_cf_gen_2',
        action: 'swap',
        succeeded: true,
        occurredAt: '2026-01-06T01:00:00.000Z',
        sourceEventId: 'router_cf_gen_evt_2',
      },
    });

    const generated = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/invoices/generate',
      body: {
        periodMonthUtc: '2026-01',
      },
    });
    expect(generated.status).toBe(200);
    expect(getPath(generated.json, 'generation', 'generated')).toBe(true);
    expect(Number(getPath(generated.json, 'generation', 'invoice', 'amountDueMinor') || 0)).toBe(
      2500,
    );
    const invoiceId = String(getPath(generated.json, 'generation', 'invoice', 'id') || '');
    expect(invoiceId).toBeTruthy();

    const lineItems = await callCf(handler, {
      method: 'GET',
      path: `/console/billing/invoices/${encodeURIComponent(invoiceId)}/line-items`,
    });
    expect(lineItems.status).toBe(200);
    const items = Array.isArray(lineItems.json?.lineItems) ? lineItems.json?.lineItems : [];
    expect(items.length).toBe(2);
    expect(JSON.stringify(items)).toContain('"itemType":"PLAN_BASE_FEE"');
    expect(JSON.stringify(items)).toContain('"itemType":"MAW_USAGE"');
  });

  test('POST /console/billing/stablecoins/payment-intents/:id/reconcile requires admin or ops role', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['billing_admin']),
      billing: createInMemoryConsoleBillingService(),
    });
    const res = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stablecoins/payment-intents/scpi_fake/reconcile',
      body: {
        observedAmountMinor: 1,
        observedConfirmations: 1,
      },
    });
    expect(res.status).toBe(403);
    expect(res.json?.code).toBe('forbidden');
  });

  test('stablecoin reconcile timeout moves intent to failed', async () => {
    const billing = createInMemoryConsoleBillingService();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['ops']),
      billing,
    });

    const invoices = await callCf(handler, {
      method: 'GET',
      path: '/console/billing/invoices',
    });
    expect(invoices.status).toBe(200);
    const invoiceId = Array.isArray(invoices.json?.invoices)
      ? (invoices.json?.invoices?.[0] as any)?.id
      : '';
    expect(invoiceId).toBeTruthy();

    const quote = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stablecoins/quotes',
      body: {
        invoiceId,
        asset: 'USDT',
        chain: 'Base',
      },
    });
    expect(quote.status).toBe(201);
    const quoteId = String(getPath(quote.json, 'quote', 'id') || '');
    expect(quoteId).toBeTruthy();

    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stablecoins/payment-intents',
      body: {
        invoiceId,
        quoteId,
      },
    });
    expect(created.status).toBe(201);
    const paymentIntentId = String(getPath(created.json, 'paymentIntent', 'id') || '');
    expect(paymentIntentId).toBeTruthy();

    const reconciled = await callCf(handler, {
      method: 'POST',
      path: `/console/billing/stablecoins/payment-intents/${encodeURIComponent(paymentIntentId)}/reconcile`,
      body: {
        observedAmountMinor: 0,
        observedConfirmations: 0,
        confirmationTimedOut: true,
      },
    });
    expect(reconciled.status).toBe(200);
    expect(getPath(reconciled.json, 'paymentIntent', 'state')).toBe('FAILED');
  });

  test('stablecoin reconcile after intent expiry returns EXPIRED and leaves invoice open', async () => {
    let current = new Date('2026-03-01T00:00:00.000Z');
    const billing = createInMemoryConsoleBillingService({
      now: () => current,
    });
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['ops']),
      billing,
    });

    const invoices = await callCf(handler, {
      method: 'GET',
      path: '/console/billing/invoices',
    });
    expect(invoices.status).toBe(200);
    const invoiceId = Array.isArray(invoices.json?.invoices)
      ? (invoices.json?.invoices?.[0] as any)?.id
      : '';
    expect(invoiceId).toBeTruthy();

    const quote = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stablecoins/quotes',
      body: {
        invoiceId,
        asset: 'USDC',
        chain: 'Ethereum',
      },
    });
    expect(quote.status).toBe(201);
    const quoteId = String(getPath(quote.json, 'quote', 'id') || '');
    expect(quoteId).toBeTruthy();

    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stablecoins/payment-intents',
      body: {
        invoiceId,
        quoteId,
      },
    });
    expect(created.status).toBe(201);
    const paymentIntentId = String(getPath(created.json, 'paymentIntent', 'id') || '');
    const expectedAmountMinor = Number(
      getPath(created.json, 'paymentIntent', 'expectedAmountMinor') || 0,
    );
    const requiredConfirmations = Number(
      getPath(created.json, 'paymentIntent', 'requiredConfirmations') || 0,
    );
    expect(paymentIntentId).toBeTruthy();
    expect(requiredConfirmations).toBeGreaterThan(0);

    current = new Date(current.getTime() + 16 * 60 * 1000);

    const reconciled = await callCf(handler, {
      method: 'POST',
      path: `/console/billing/stablecoins/payment-intents/${encodeURIComponent(paymentIntentId)}/reconcile`,
      body: {
        observedAmountMinor: expectedAmountMinor,
        observedConfirmations: requiredConfirmations,
      },
    });
    expect(reconciled.status).toBe(200);
    expect(getPath(reconciled.json, 'paymentIntent', 'state')).toBe('EXPIRED');

    const invoice = await callCf(handler, {
      method: 'GET',
      path: `/console/billing/invoices/${encodeURIComponent(invoiceId)}`,
    });
    expect(invoice.status).toBe(200);
    expect(getPath(invoice.json, 'invoice', 'status')).toBe('OPEN');
    expect(Number(getPath(invoice.json, 'invoice', 'amountPaidMinor') || 0)).toBe(0);
  });

  test('stripe reconcile settles payment intent', async () => {
    const billing = createInMemoryConsoleBillingService();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
    });

    const invoices = await callCf(handler, {
      method: 'GET',
      path: '/console/billing/invoices',
    });
    expect(invoices.status).toBe(200);
    const invoiceId = Array.isArray(invoices.json?.invoices)
      ? (invoices.json?.invoices?.[0] as any)?.id
      : '';
    expect(invoiceId).toBeTruthy();

    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/payment-intent',
      body: { invoiceId },
    });
    expect(created.status).toBe(201);
    const paymentIntentId = String(getPath(created.json, 'paymentIntent', 'id') || '');
    expect(getPath(created.json, 'paymentIntent', 'state')).toBe('CREATED');
    const amountMinor = Number(getPath(created.json, 'paymentIntent', 'amountMinor') || 0);
    expect(paymentIntentId).toBeTruthy();
    expect(amountMinor).toBeGreaterThan(0);

    const pending = await callCf(handler, {
      method: 'POST',
      path: `/console/billing/stripe/payment-intents/${encodeURIComponent(paymentIntentId)}/reconcile`,
      body: {
        providerStatus: 'PENDING',
        sourceEventId: `evt_${Date.now()}_cf_pending`,
      },
    });
    expect(pending.status).toBe(200);
    expect(getPath(pending.json, 'paymentIntent', 'state')).toBe('PENDING');

    const settled = await callCf(handler, {
      method: 'POST',
      path: `/console/billing/stripe/payment-intents/${encodeURIComponent(paymentIntentId)}/reconcile`,
      body: {
        providerStatus: 'SUCCEEDED',
        settledAmountMinor: amountMinor,
        sourceEventId: `evt_${Date.now()}_cf_succeeded`,
      },
    });
    expect(settled.status).toBe(200);
    expect(getPath(settled.json, 'paymentIntent', 'state')).toBe('SETTLED');
  });

  test('cloudflare billing transitions emit billing webhook events', async () => {
    const billing = createInMemoryConsoleBillingService();
    const webhooks = createInMemoryConsoleWebhookService({
      dispatcher: {
        dispatch: async () => ({
          ok: true,
          statusCode: 200,
          responseBody: 'ok',
        }),
      },
    });
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
      webhooks,
    });

    const endpointCreated = await callCf(handler, {
      method: 'POST',
      path: '/console/webhooks',
      body: {
        url: 'https://example.com/cloudflare-billing-events',
        subscriptions: ['billing'],
      },
    });
    expect(endpointCreated.status).toBe(201);
    const endpointId = String(getPath(endpointCreated.json, 'endpoint', 'id') || '');
    expect(endpointId).toBeTruthy();

    const invoices = await callCf(handler, {
      method: 'GET',
      path: '/console/billing/invoices',
    });
    expect(invoices.status).toBe(200);
    const invoiceId = Array.isArray(invoices.json?.invoices)
      ? (invoices.json?.invoices?.[0] as any)?.id
      : '';
    expect(invoiceId).toBeTruthy();

    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/payment-intent',
      body: { invoiceId },
    });
    expect(created.status).toBe(201);
    const paymentIntentId = String(getPath(created.json, 'paymentIntent', 'id') || '');
    const amountMinor = Number(getPath(created.json, 'paymentIntent', 'amountMinor') || 0);
    expect(paymentIntentId).toBeTruthy();
    expect(amountMinor).toBeGreaterThan(0);

    const actionRequired = await callCf(handler, {
      method: 'POST',
      path: `/console/billing/stripe/payment-intents/${encodeURIComponent(paymentIntentId)}/reconcile`,
      body: {
        providerStatus: 'ACTION_REQUIRED',
      },
    });
    expect(actionRequired.status).toBe(200);

    const pending = await callCf(handler, {
      method: 'POST',
      path: `/console/billing/stripe/payment-intents/${encodeURIComponent(paymentIntentId)}/reconcile`,
      body: {
        providerStatus: 'PENDING',
      },
    });
    expect(pending.status).toBe(200);

    const settled = await callCf(handler, {
      method: 'POST',
      path: `/console/billing/stripe/payment-intents/${encodeURIComponent(paymentIntentId)}/reconcile`,
      body: {
        providerStatus: 'SUCCEEDED',
        settledAmountMinor: amountMinor,
      },
    });
    expect(settled.status).toBe(200);
    expect(getPath(settled.json, 'paymentIntent', 'state')).toBe('SETTLED');

    const deliveries = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/deliveries`,
    });
    expect(deliveries.status).toBe(200);
    const rows = Array.isArray(deliveries.json?.deliveries) ? deliveries.json?.deliveries : [];
    const eventTypes = rows.map((row: any) => String(row?.eventType || ''));
    expect(eventTypes).toContain('billing.payment_intent.created');
    expect(eventTypes).toContain('billing.payment_intent.updated');
    expect(eventTypes).toContain('billing.invoice.paid');

    const pageOne = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/deliveries?limit=2`,
    });
    expect(pageOne.status).toBe(200);
    const pageOneRows = Array.isArray(pageOne.json?.deliveries) ? pageOne.json?.deliveries : [];
    expect(pageOneRows.length).toBe(2);
    const pageOneCursor = String(pageOne.json?.nextCursor || '');
    expect(pageOneCursor).toBeTruthy();

    const pageTwo = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/deliveries?limit=2&cursor=${encodeURIComponent(pageOneCursor)}`,
    });
    expect(pageTwo.status).toBe(200);
    const pageTwoRows = Array.isArray(pageTwo.json?.deliveries) ? pageTwo.json?.deliveries : [];
    expect(pageTwoRows.length).toBeGreaterThanOrEqual(1);
  });
});

test.describe('console router (postgres org-project-env)', () => {
  const postgresUrl = String(process.env.POSTGRES_URL || '').trim();
  const enabled = Boolean(postgresUrl);
  const namespace = randomNamespace('test:console-router:org-project-env:postgres');
  const authOrgId = 'org-router-postgres-org-project-env';
  let orgProjectEnv: ConsoleOrgProjectEnvService | null = null;

  test.beforeAll(async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    orgProjectEnv = await createPostgresConsoleOrgProjectEnvService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
    });
  });

  test.afterAll(async () => {
    if (!enabled) return;
    const pool = await getPostgresPool(postgresUrl);
    await pool.query('DELETE FROM console_environments WHERE namespace = $1', [namespace]);
    await pool.query('DELETE FROM console_projects WHERE namespace = $1', [namespace]);
    await pool.query('DELETE FROM console_organizations WHERE namespace = $1', [namespace]);
  });

  test('express org/project/environment routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner`;
    const attackerOrgId = `${authOrgId}:attacker`;
    const ownerManagedProjectId = `${ownerOrgId}:managed-project`;
    const ownerManagedEnvironmentId = `${ownerOrgId}:managed-env`;

    const ownerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-org-project-env-user'),
      orgProjectEnv: orgProjectEnv!,
    });
    const ownerServer = await startExpressRouter(ownerRouter);
    let ownerProjectId = '';
    try {
      const projects = await fetchJson(`${ownerServer.baseUrl}/console/projects`, {
        method: 'GET',
      });
      expect(projects.status).toBe(200);
      ownerProjectId = String(getPath(projects.json, 'projects', 0, 'id') || '');
      expect(ownerProjectId).toBeTruthy();
      expect(Number(getPath(projects.json, 'projects', 0, 'environmentCount') || 0)).toBeGreaterThanOrEqual(
        1,
      );

      const createdProject = await fetchJson(`${ownerServer.baseUrl}/console/projects`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: ownerManagedProjectId,
          name: 'Owner Managed Project',
        }),
      });
      expect(createdProject.status).toBe(201);
      expect(Number(getPath(createdProject.json, 'project', 'environmentCount') || 0)).toBe(0);

      const createdEnvironment = await fetchJson(`${ownerServer.baseUrl}/console/environments`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: ownerManagedEnvironmentId,
          projectId: ownerManagedProjectId,
          key: 'staging',
        }),
      });
      expect(createdEnvironment.status).toBe(201);

      const environments = await fetchJson(
        `${ownerServer.baseUrl}/console/environments?projectId=${encodeURIComponent(ownerProjectId)}`,
        { method: 'GET' },
      );
      expect(environments.status).toBe(200);
      const ownerEnvRows = Array.isArray(environments.json?.environments)
        ? environments.json?.environments
        : [];
      expect(ownerEnvRows.length).toBeGreaterThanOrEqual(1);
    } finally {
      await ownerServer.close();
    }

    const attackerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-org-project-env-user'),
      orgProjectEnv: orgProjectEnv!,
    });
    const attackerServer = await startExpressRouter(attackerRouter);
    try {
      const org = await fetchJson(`${attackerServer.baseUrl}/console/org`, {
        method: 'GET',
      });
      expect(org.status).toBe(200);
      expect(String(getPath(org.json, 'org', 'id') || '')).toBe(attackerOrgId);
      expect(String(getPath(org.json, 'org', 'id') || '')).not.toBe(ownerOrgId);

      const projects = await fetchJson(`${attackerServer.baseUrl}/console/projects`, {
        method: 'GET',
      });
      expect(projects.status).toBe(200);
      const attackerProjects = Array.isArray(projects.json?.projects) ? projects.json?.projects : [];
      expect(
        attackerProjects.some((entry: any) => String(entry?.id || '') === ownerProjectId),
      ).toBe(false);
      expect(
        attackerProjects.some((entry: any) => String(entry?.id || '') === ownerManagedProjectId),
      ).toBe(false);

      const scopedEnvironments = await fetchJson(
        `${attackerServer.baseUrl}/console/environments?projectId=${encodeURIComponent(ownerProjectId)}`,
        {
          method: 'GET',
        },
      );
      expect(scopedEnvironments.status).toBe(200);
      const attackerScopedRows = Array.isArray(scopedEnvironments.json?.environments)
        ? scopedEnvironments.json?.environments
        : [];
      expect(attackerScopedRows.length).toBe(0);

      const patchOwnerProject = await fetchJson(
        `${attackerServer.baseUrl}/console/projects/${encodeURIComponent(ownerManagedProjectId)}`,
        {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: 'attacker rename' }),
        },
      );
      expect(patchOwnerProject.status).toBe(404);
      expect(patchOwnerProject.json?.code).toBe('project_not_found');

      const archiveOwnerEnvironment = await fetchJson(
        `${attackerServer.baseUrl}/console/environments/${encodeURIComponent(ownerManagedEnvironmentId)}/archive`,
        {
          method: 'POST',
        },
      );
      expect(archiveOwnerEnvironment.status).toBe(404);
      expect(archiveOwnerEnvironment.json?.code).toBe('environment_not_found');
    } finally {
      await attackerServer.close();
    }
  });

  test('cloudflare org/project/environment routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner-cf`;
    const attackerOrgId = `${authOrgId}:attacker-cf`;
    const ownerManagedProjectId = `${ownerOrgId}:managed-project`;
    const ownerManagedEnvironmentId = `${ownerOrgId}:managed-env`;

    const ownerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-org-project-env-user-cf'),
      orgProjectEnv: orgProjectEnv!,
    });
    const ownerProjects = await callCf(ownerHandler, {
      method: 'GET',
      path: '/console/projects',
    });
    expect(ownerProjects.status).toBe(200);
    const ownerProjectId = String(getPath(ownerProjects.json, 'projects', 0, 'id') || '');
    expect(ownerProjectId).toBeTruthy();
    expect(Number(getPath(ownerProjects.json, 'projects', 0, 'environmentCount') || 0)).toBeGreaterThanOrEqual(
      1,
    );

    const ownerCreatedProject = await callCf(ownerHandler, {
      method: 'POST',
      path: '/console/projects',
      body: {
        id: ownerManagedProjectId,
        name: 'Owner Managed Project CF',
      },
    });
    expect(ownerCreatedProject.status).toBe(201);
    expect(Number(getPath(ownerCreatedProject.json, 'project', 'environmentCount') || 0)).toBe(0);

    const ownerCreatedEnvironment = await callCf(ownerHandler, {
      method: 'POST',
      path: '/console/environments',
      body: {
        id: ownerManagedEnvironmentId,
        projectId: ownerManagedProjectId,
        key: 'staging',
      },
    });
    expect(ownerCreatedEnvironment.status).toBe(201);

    const ownerEnvironments = await callCf(ownerHandler, {
      method: 'GET',
      path: `/console/environments?projectId=${encodeURIComponent(ownerProjectId)}`,
    });
    expect(ownerEnvironments.status).toBe(200);
    const ownerEnvRows = Array.isArray(ownerEnvironments.json?.environments)
      ? ownerEnvironments.json?.environments
      : [];
    expect(ownerEnvRows.length).toBeGreaterThanOrEqual(1);

    const attackerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-org-project-env-user-cf'),
      orgProjectEnv: orgProjectEnv!,
    });
    const org = await callCf(attackerHandler, {
      method: 'GET',
      path: '/console/org',
    });
    expect(org.status).toBe(200);
    expect(String(getPath(org.json, 'org', 'id') || '')).toBe(attackerOrgId);
    expect(String(getPath(org.json, 'org', 'id') || '')).not.toBe(ownerOrgId);

    const projects = await callCf(attackerHandler, {
      method: 'GET',
      path: '/console/projects',
    });
    expect(projects.status).toBe(200);
    const attackerProjects = Array.isArray(projects.json?.projects) ? projects.json?.projects : [];
    expect(
      attackerProjects.some((entry: any) => String(entry?.id || '') === ownerProjectId),
    ).toBe(false);
    expect(
      attackerProjects.some((entry: any) => String(entry?.id || '') === ownerManagedProjectId),
    ).toBe(false);

    const scopedEnvironments = await callCf(attackerHandler, {
      method: 'GET',
      path: `/console/environments?projectId=${encodeURIComponent(ownerProjectId)}`,
    });
    expect(scopedEnvironments.status).toBe(200);
    const attackerScopedRows = Array.isArray(scopedEnvironments.json?.environments)
      ? scopedEnvironments.json?.environments
      : [];
    expect(attackerScopedRows.length).toBe(0);

    const patchOwnerProject = await callCf(attackerHandler, {
      method: 'PATCH',
      path: `/console/projects/${encodeURIComponent(ownerManagedProjectId)}`,
      body: { name: 'attacker rename cf' },
    });
    expect(patchOwnerProject.status).toBe(404);
    expect(patchOwnerProject.json?.code).toBe('project_not_found');

    const archiveOwnerEnvironment = await callCf(attackerHandler, {
      method: 'POST',
      path: `/console/environments/${encodeURIComponent(ownerManagedEnvironmentId)}/archive`,
    });
    expect(archiveOwnerEnvironment.status).toBe(404);
    expect(archiveOwnerEnvironment.json?.code).toBe('environment_not_found');
  });
});

test.describe('console router (postgres wallets)', () => {
  const postgresUrl = String(process.env.POSTGRES_URL || '').trim();
  const enabled = Boolean(postgresUrl);
  const namespace = randomNamespace('test:console-router:wallets:postgres');
  const authOrgId = 'org-router-postgres-wallets';
  let wallets: ConsoleWalletService | null = null;

  test.beforeAll(async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    wallets = await createPostgresConsoleWalletService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
    });
  });

  test.afterAll(async () => {
    if (!enabled) return;
    const pool = await getPostgresPool(postgresUrl);
    await pool.query('DELETE FROM console_wallet_index WHERE namespace = $1', [namespace]);
  });

  test('express wallet routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner`;
    const attackerOrgId = `${authOrgId}:attacker`;

    const ownerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-wallet-user'),
      wallets: wallets!,
    });
    const ownerServer = await startExpressRouter(ownerRouter);
    let ownerWalletId = '';
    try {
      const listed = await fetchJson(`${ownerServer.baseUrl}/console/wallets`, {
        method: 'GET',
      });
      expect(listed.status).toBe(200);
      ownerWalletId = String(getPath(listed.json, 'wallets', 0, 'id') || '');
      expect(ownerWalletId).toBeTruthy();
    } finally {
      await ownerServer.close();
    }

    const attackerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-wallet-user'),
      wallets: wallets!,
    });
    const attackerServer = await startExpressRouter(attackerRouter);
    try {
      const detail = await fetchJson(
        `${attackerServer.baseUrl}/console/wallets/${encodeURIComponent(ownerWalletId)}`,
        {
          method: 'GET',
        },
      );
      expect(detail.status).toBe(404);
      expect(detail.json?.code).toBe('wallet_not_found');

      const searched = await fetchJson(
        `${attackerServer.baseUrl}/console/wallets/search?q=${encodeURIComponent(ownerWalletId)}`,
        { method: 'GET' },
      );
      expect(searched.status).toBe(200);
      const attackerRows = Array.isArray(searched.json?.wallets) ? searched.json?.wallets : [];
      expect(attackerRows.some((entry: any) => String(entry?.id || '') === ownerWalletId)).toBe(
        false,
      );
    } finally {
      await attackerServer.close();
    }
  });

  test('cloudflare wallet routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner-cf`;
    const attackerOrgId = `${authOrgId}:attacker-cf`;

    const ownerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-wallet-user-cf'),
      wallets: wallets!,
    });
    const ownerList = await callCf(ownerHandler, {
      method: 'GET',
      path: '/console/wallets',
    });
    expect(ownerList.status).toBe(200);
    const ownerWalletId = String(getPath(ownerList.json, 'wallets', 0, 'id') || '');
    expect(ownerWalletId).toBeTruthy();

    const attackerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-wallet-user-cf'),
      wallets: wallets!,
    });
    const detail = await callCf(attackerHandler, {
      method: 'GET',
      path: `/console/wallets/${encodeURIComponent(ownerWalletId)}`,
    });
    expect(detail.status).toBe(404);
    expect(detail.json?.code).toBe('wallet_not_found');

    const searched = await callCf(attackerHandler, {
      method: 'GET',
      path: `/console/wallets/search?q=${encodeURIComponent(ownerWalletId)}`,
    });
    expect(searched.status).toBe(200);
    const attackerRows = Array.isArray(searched.json?.wallets) ? searched.json?.wallets : [];
    expect(attackerRows.some((entry: any) => String(entry?.id || '') === ownerWalletId)).toBe(
      false,
    );
  });

  test('express policy/gas insight routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner-insights`;
    const attackerOrgId = `${authOrgId}:attacker-insights`;

    const ownerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-wallet-insights-user'),
      wallets: wallets!,
    });
    const ownerServer = await startExpressRouter(ownerRouter);
    let ownerProjectId = '';
    let ownerEnvironmentId = '';
    try {
      const ownerList = await fetchJson(`${ownerServer.baseUrl}/console/wallets`, { method: 'GET' });
      expect(ownerList.status).toBe(200);
      ownerProjectId = String(getPath(ownerList.json, 'wallets', 0, 'projectId') || '');
      ownerEnvironmentId = String(getPath(ownerList.json, 'wallets', 0, 'environmentId') || '');
      expect(ownerProjectId).toBeTruthy();
      expect(ownerEnvironmentId).toBeTruthy();

      const ownerCoverage = await fetchJson(
        `${ownerServer.baseUrl}/console/policy/coverage?projectId=${encodeURIComponent(ownerProjectId)}&environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
        { method: 'GET' },
      );
      expect(ownerCoverage.status).toBe(200);
      expect(
        Number(getPath(ownerCoverage.json, 'coverage', 'totals', 'walletCount') || 0),
      ).toBeGreaterThanOrEqual(1);
    } finally {
      await ownerServer.close();
    }

    const attackerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-wallet-insights-user'),
      wallets: wallets!,
    });
    const attackerServer = await startExpressRouter(attackerRouter);
    try {
      const coverage = await fetchJson(
        `${attackerServer.baseUrl}/console/policy/coverage?projectId=${encodeURIComponent(ownerProjectId)}&environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
        { method: 'GET' },
      );
      expect(coverage.status).toBe(200);
      expect(Number(getPath(coverage.json, 'coverage', 'totals', 'walletCount') || 0)).toBe(0);

      const readiness = await fetchJson(
        `${attackerServer.baseUrl}/console/gas/readiness?projectId=${encodeURIComponent(ownerProjectId)}&environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
        { method: 'GET' },
      );
      expect(readiness.status).toBe(200);
      expect(Number(getPath(readiness.json, 'readiness', 'totals', 'walletCount') || 0)).toBe(0);
    } finally {
      await attackerServer.close();
    }
  });

  test('cloudflare policy/gas insight routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner-insights-cf`;
    const attackerOrgId = `${authOrgId}:attacker-insights-cf`;

    const ownerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-wallet-insights-user-cf'),
      wallets: wallets!,
    });
    const ownerList = await callCf(ownerHandler, {
      method: 'GET',
      path: '/console/wallets',
    });
    expect(ownerList.status).toBe(200);
    const ownerProjectId = String(getPath(ownerList.json, 'wallets', 0, 'projectId') || '');
    const ownerEnvironmentId = String(
      getPath(ownerList.json, 'wallets', 0, 'environmentId') || '',
    );
    expect(ownerProjectId).toBeTruthy();
    expect(ownerEnvironmentId).toBeTruthy();

    const ownerCoverage = await callCf(ownerHandler, {
      method: 'GET',
      path: `/console/policy/coverage?projectId=${encodeURIComponent(ownerProjectId)}&environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
    });
    expect(ownerCoverage.status).toBe(200);
    expect(Number(getPath(ownerCoverage.json, 'coverage', 'totals', 'walletCount') || 0)).toBeGreaterThanOrEqual(1);

    const attackerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-wallet-insights-user-cf'),
      wallets: wallets!,
    });
    const attackerCoverage = await callCf(attackerHandler, {
      method: 'GET',
      path: `/console/policy/coverage?projectId=${encodeURIComponent(ownerProjectId)}&environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
    });
    expect(attackerCoverage.status).toBe(200);
    expect(Number(getPath(attackerCoverage.json, 'coverage', 'totals', 'walletCount') || 0)).toBe(0);

    const attackerReadiness = await callCf(attackerHandler, {
      method: 'GET',
      path: `/console/gas/readiness?projectId=${encodeURIComponent(ownerProjectId)}&environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
    });
    expect(attackerReadiness.status).toBe(200);
    expect(Number(getPath(attackerReadiness.json, 'readiness', 'totals', 'walletCount') || 0)).toBe(0);
  });
});

test.describe('console router (postgres policies)', () => {
  const postgresUrl = String(process.env.POSTGRES_URL || '').trim();
  const enabled = Boolean(postgresUrl);
  const namespace = randomNamespace('test:console-router:policies:postgres');
  const authOrgId = 'org-router-postgres-policies';
  let policies: ConsolePolicyService | null = null;

  test.beforeAll(async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    policies = await createPostgresConsolePolicyService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
    });
  });

  test.afterAll(async () => {
    if (!enabled) return;
    const pool = await getPostgresPool(postgresUrl);
    await pool.query('DELETE FROM console_policy_assignments WHERE namespace = $1', [namespace]);
    await pool.query('DELETE FROM console_policy_versions WHERE namespace = $1', [namespace]);
    await pool.query('DELETE FROM console_policies WHERE namespace = $1', [namespace]);
  });

  test('express policy routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner`;
    const attackerOrgId = `${authOrgId}:attacker`;
    const ownerPolicyId = `${ownerOrgId}:managed-policy`;
    let ownerAssignmentId = '';

    const ownerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-policy-user'),
      policies: policies!,
    });
    const ownerServer = await startExpressRouter(ownerRouter);
    try {
      const created = await fetchJson(`${ownerServer.baseUrl}/console/policies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: ownerPolicyId,
          name: 'Owner Managed Policy',
        }),
      });
      expect(created.status).toBe(201);

      const published = await fetchJson(
        `${ownerServer.baseUrl}/console/policies/${encodeURIComponent(ownerPolicyId)}/publish`,
        {
          method: 'POST',
        },
      );
      expect(published.status).toBe(200);

      const listed = await fetchJson(`${ownerServer.baseUrl}/console/policies`, { method: 'GET' });
      expect(listed.status).toBe(200);
      const ownerPolicies = Array.isArray(listed.json?.policies) ? listed.json?.policies : [];
      expect(ownerPolicies.some((entry: any) => String(entry?.id || '') === ownerPolicyId)).toBe(true);

      const upsertedAssignment = await fetchJson(
        `${ownerServer.baseUrl}/console/policies/assignments`,
        {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            scopeType: 'ORG',
            scopeId: ownerOrgId,
            policyId: ownerPolicyId,
          }),
        },
      );
      expect(upsertedAssignment.status).toBe(200);
      ownerAssignmentId = String(getPath(upsertedAssignment.json, 'assignment', 'id') || '');
      expect(ownerAssignmentId).toBeTruthy();
    } finally {
      await ownerServer.close();
    }

    const attackerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-policy-user'),
      policies: policies!,
    });
    const attackerServer = await startExpressRouter(attackerRouter);
    try {
      const listed = await fetchJson(`${attackerServer.baseUrl}/console/policies`, { method: 'GET' });
      expect(listed.status).toBe(200);
      const attackerPolicies = Array.isArray(listed.json?.policies) ? listed.json?.policies : [];
      expect(attackerPolicies.some((entry: any) => String(entry?.id || '') === ownerPolicyId)).toBe(
        false,
      );

      const listedAssignments = await fetchJson(
        `${attackerServer.baseUrl}/console/policies/assignments?scopeType=ORG&scopeId=${encodeURIComponent(ownerOrgId)}`,
        { method: 'GET' },
      );
      expect(listedAssignments.status).toBe(200);
      const attackerAssignments = Array.isArray(listedAssignments.json?.assignments)
        ? listedAssignments.json?.assignments
        : [];
      expect(attackerAssignments.length).toBe(0);

      const patched = await fetchJson(
        `${attackerServer.baseUrl}/console/policies/${encodeURIComponent(ownerPolicyId)}`,
        {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: 'attacker rename' }),
        },
      );
      expect(patched.status).toBe(404);
      expect(patched.json?.code).toBe('policy_not_found');

      const published = await fetchJson(
        `${attackerServer.baseUrl}/console/policies/${encodeURIComponent(ownerPolicyId)}/publish`,
        { method: 'POST' },
      );
      expect(published.status).toBe(404);
      expect(published.json?.code).toBe('policy_not_found');

      const simulated = await fetchJson(
        `${attackerServer.baseUrl}/console/policies/${encodeURIComponent(ownerPolicyId)}/simulate`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ action: 'transfer' }),
        },
      );
      expect(simulated.status).toBe(404);
      expect(simulated.json?.code).toBe('policy_not_found');

      const deletedAssignment = await fetchJson(
        `${attackerServer.baseUrl}/console/policies/assignments/${encodeURIComponent(ownerAssignmentId)}`,
        { method: 'DELETE' },
      );
      expect(deletedAssignment.status).toBe(404);
      expect(deletedAssignment.json?.code).toBe('assignment_not_found');
    } finally {
      await attackerServer.close();
    }
  });

  test('cloudflare policy routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner-cf`;
    const attackerOrgId = `${authOrgId}:attacker-cf`;
    const ownerPolicyId = `${ownerOrgId}:managed-policy`;
    let ownerAssignmentId = '';

    const ownerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-policy-user-cf'),
      policies: policies!,
    });
    const created = await callCf(ownerHandler, {
      method: 'POST',
      path: '/console/policies',
      body: {
        id: ownerPolicyId,
        name: 'Owner Managed Policy CF',
      },
    });
    expect(created.status).toBe(201);

    const ownerPublished = await callCf(ownerHandler, {
      method: 'POST',
      path: `/console/policies/${encodeURIComponent(ownerPolicyId)}/publish`,
    });
    expect(ownerPublished.status).toBe(200);

    const ownerAssignment = await callCf(ownerHandler, {
      method: 'PUT',
      path: '/console/policies/assignments',
      body: {
        scopeType: 'ORG',
        scopeId: ownerOrgId,
        policyId: ownerPolicyId,
      },
    });
    expect(ownerAssignment.status).toBe(200);
    ownerAssignmentId = String(getPath(ownerAssignment.json, 'assignment', 'id') || '');
    expect(ownerAssignmentId).toBeTruthy();

    const attackerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-policy-user-cf'),
      policies: policies!,
    });
    const listed = await callCf(attackerHandler, {
      method: 'GET',
      path: '/console/policies',
    });
    expect(listed.status).toBe(200);
    const attackerPolicies = Array.isArray(listed.json?.policies) ? listed.json?.policies : [];
    expect(attackerPolicies.some((entry: any) => String(entry?.id || '') === ownerPolicyId)).toBe(
      false,
    );

    const listedAssignments = await callCf(attackerHandler, {
      method: 'GET',
      path: `/console/policies/assignments?scopeType=ORG&scopeId=${encodeURIComponent(ownerOrgId)}`,
    });
    expect(listedAssignments.status).toBe(200);
    const attackerAssignments = Array.isArray(listedAssignments.json?.assignments)
      ? listedAssignments.json?.assignments
      : [];
    expect(attackerAssignments.length).toBe(0);

    const patched = await callCf(attackerHandler, {
      method: 'PATCH',
      path: `/console/policies/${encodeURIComponent(ownerPolicyId)}`,
      body: {
        name: 'attacker rename cf',
      },
    });
    expect(patched.status).toBe(404);
    expect(patched.json?.code).toBe('policy_not_found');

    const published = await callCf(attackerHandler, {
      method: 'POST',
      path: `/console/policies/${encodeURIComponent(ownerPolicyId)}/publish`,
    });
    expect(published.status).toBe(404);
    expect(published.json?.code).toBe('policy_not_found');

    const simulated = await callCf(attackerHandler, {
      method: 'POST',
      path: `/console/policies/${encodeURIComponent(ownerPolicyId)}/simulate`,
      body: {
        action: 'transfer',
      },
    });
    expect(simulated.status).toBe(404);
    expect(simulated.json?.code).toBe('policy_not_found');

    const deletedAssignment = await callCf(attackerHandler, {
      method: 'DELETE',
      path: `/console/policies/assignments/${encodeURIComponent(ownerAssignmentId)}`,
    });
    expect(deletedAssignment.status).toBe(404);
    expect(deletedAssignment.json?.code).toBe('assignment_not_found');
  });
});

test.describe('console router (postgres api keys)', () => {
  const postgresUrl = String(process.env.POSTGRES_URL || '').trim();
  const enabled = Boolean(postgresUrl);
  const namespace = randomNamespace('test:console-router:api-keys:postgres');
  const authOrgId = 'org-router-postgres-api-keys';
  let apiKeys: ConsoleApiKeyService | null = null;

  test.beforeAll(async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    apiKeys = await createPostgresConsoleApiKeyService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
    });
  });

  test.afterAll(async () => {
    if (!enabled) return;
    const pool = await getPostgresPool(postgresUrl);
    await pool.query('DELETE FROM console_api_keys WHERE namespace = $1', [namespace]);
  });

  test('express API key routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner`;
    const attackerOrgId = `${authOrgId}:attacker`;

    const ownerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-api-key-user'),
      apiKeys: apiKeys!,
    });
    const ownerServer = await startExpressRouter(ownerRouter);
    let keyId = '';
    try {
      const created = await fetchJson(`${ownerServer.baseUrl}/console/api-keys`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'owner-postgres-api-key',
          environmentId: 'prod',
          scopes: ['wallets:read', 'billing:read'],
          ipAllowlist: ['203.0.113.20/32'],
        }),
      });
      expect(created.status).toBe(201);
      keyId = String(getPath(created.json, 'apiKey', 'id') || '');
      expect(keyId).toBeTruthy();
    } finally {
      await ownerServer.close();
    }

    const attackerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-api-key-user'),
      apiKeys: apiKeys!,
    });
    const attackerServer = await startExpressRouter(attackerRouter);
    try {
      const list = await fetchJson(`${attackerServer.baseUrl}/console/api-keys`, {
        method: 'GET',
      });
      expect(list.status).toBe(200);
      const attackerKeys = Array.isArray(list.json?.apiKeys) ? list.json?.apiKeys : [];
      expect(attackerKeys.some((entry: any) => String(entry?.id || '') === keyId)).toBe(false);

      const rotate = await fetchJson(
        `${attackerServer.baseUrl}/console/api-keys/${encodeURIComponent(keyId)}/rotate`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ reason: 'attacker rotate attempt' }),
        },
      );
      expect(rotate.status).toBe(404);
      expect(rotate.json?.code).toBe('api_key_not_found');

      const deleted = await fetchJson(
        `${attackerServer.baseUrl}/console/api-keys/${encodeURIComponent(keyId)}`,
        { method: 'DELETE' },
      );
      expect(deleted.status).toBe(404);
      expect(deleted.json?.code).toBe('api_key_not_found');
    } finally {
      await attackerServer.close();
    }
  });

  test('cloudflare API key routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner-cf`;
    const attackerOrgId = `${authOrgId}:attacker-cf`;

    const ownerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-api-key-user-cf'),
      apiKeys: apiKeys!,
    });
    const created = await callCf(ownerHandler, {
      method: 'POST',
      path: '/console/api-keys',
      body: {
        name: 'owner-postgres-api-key-cf',
        environmentId: 'prod',
        scopes: ['wallets:read'],
        ipAllowlist: ['198.51.100.25/32'],
      },
    });
    expect(created.status).toBe(201);
    const keyId = String(getPath(created.json, 'apiKey', 'id') || '');
    expect(keyId).toBeTruthy();

    const attackerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-api-key-user-cf'),
      apiKeys: apiKeys!,
    });
    const list = await callCf(attackerHandler, {
      method: 'GET',
      path: '/console/api-keys',
    });
    expect(list.status).toBe(200);
    const attackerKeys = Array.isArray(list.json?.apiKeys) ? list.json?.apiKeys : [];
    expect(attackerKeys.some((entry: any) => String(entry?.id || '') === keyId)).toBe(false);

    const rotate = await callCf(attackerHandler, {
      method: 'POST',
      path: `/console/api-keys/${encodeURIComponent(keyId)}/rotate`,
      body: {
        reason: 'attacker rotate attempt',
      },
    });
    expect(rotate.status).toBe(404);
    expect(rotate.json?.code).toBe('api_key_not_found');

    const deleted = await callCf(attackerHandler, {
      method: 'DELETE',
      path: `/console/api-keys/${encodeURIComponent(keyId)}`,
    });
    expect(deleted.status).toBe(404);
    expect(deleted.json?.code).toBe('api_key_not_found');
  });

  test('express export governance route enforces org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner-export`;
    const attackerOrgId = `${authOrgId}:attacker-export`;
    const ownerEnvironmentId = `${ownerOrgId}:prod`;

    const ownerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-export-user'),
      apiKeys: apiKeys!,
    });
    const ownerServer = await startExpressRouter(ownerRouter);
    try {
      const created = await fetchJson(`${ownerServer.baseUrl}/console/api-keys`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'owner-export-governance-key',
          environmentId: ownerEnvironmentId,
          scopes: ['wallets:read', 'keys:export'],
        }),
      });
      expect(created.status).toBe(201);

      const ownerGovernance = await fetchJson(
        `${ownerServer.baseUrl}/console/export/governance?environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
        { method: 'GET' },
      );
      expect(ownerGovernance.status).toBe(200);
      expect(
        Number(
          getPath(
            ownerGovernance.json,
            'governance',
            'totals',
            'selectedEnvironmentExportScopedKeyCount',
          ) || 0,
        ),
      ).toBeGreaterThanOrEqual(1);
    } finally {
      await ownerServer.close();
    }

    const attackerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-export-user'),
      apiKeys: apiKeys!,
    });
    const attackerServer = await startExpressRouter(attackerRouter);
    try {
      const attackerGovernance = await fetchJson(
        `${attackerServer.baseUrl}/console/export/governance?environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
        { method: 'GET' },
      );
      expect(attackerGovernance.status).toBe(200);
      expect(
        Number(
          getPath(
            attackerGovernance.json,
            'governance',
            'totals',
            'selectedEnvironmentExportScopedKeyCount',
          ) || 0,
        ),
      ).toBe(0);
    } finally {
      await attackerServer.close();
    }
  });

  test('cloudflare export governance route enforces org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner-export-cf`;
    const attackerOrgId = `${authOrgId}:attacker-export-cf`;
    const ownerEnvironmentId = `${ownerOrgId}:prod`;

    const ownerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-export-user-cf'),
      apiKeys: apiKeys!,
    });
    const created = await callCf(ownerHandler, {
      method: 'POST',
      path: '/console/api-keys',
      body: {
        name: 'owner-export-governance-key-cf',
        environmentId: ownerEnvironmentId,
        scopes: ['wallets:read', 'keys:export'],
      },
    });
    expect(created.status).toBe(201);

    const ownerGovernance = await callCf(ownerHandler, {
      method: 'GET',
      path: `/console/export/governance?environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
    });
    expect(ownerGovernance.status).toBe(200);
    expect(
      Number(
        getPath(
          ownerGovernance.json,
          'governance',
          'totals',
          'selectedEnvironmentExportScopedKeyCount',
        ) || 0,
      ),
    ).toBeGreaterThanOrEqual(1);

    const attackerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-export-user-cf'),
      apiKeys: apiKeys!,
    });
    const attackerGovernance = await callCf(attackerHandler, {
      method: 'GET',
      path: `/console/export/governance?environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
    });
    expect(attackerGovernance.status).toBe(200);
    expect(
      Number(
        getPath(
          attackerGovernance.json,
          'governance',
          'totals',
          'selectedEnvironmentExportScopedKeyCount',
        ) || 0,
      ),
    ).toBe(0);
  });
});

test.describe('console router (postgres webhooks)', () => {
  const postgresUrl = String(process.env.POSTGRES_URL || '').trim();
  const enabled = Boolean(postgresUrl);
  const namespace = randomNamespace('test:console-router:webhooks:postgres');
  const authOrgId = 'org-router-postgres-webhooks';
  let webhooks: ConsoleWebhookService | null = null;

  test.beforeAll(async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    webhooks = await createPostgresConsoleWebhookService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
    });
  });

  test.afterAll(async () => {
    if (!enabled) return;
    const pool = await getPostgresPool(postgresUrl);
    const cleanupOrgIds = [
      authOrgId,
      `${authOrgId}:owner`,
      `${authOrgId}:attacker`,
      `${authOrgId}:owner-cf`,
      `${authOrgId}:attacker-cf`,
    ];
    for (const orgId of cleanupOrgIds) {
      await withConsoleTenantContextTx(pool, { namespace, orgId }, async (q) => {
        await q.query('DELETE FROM console_webhook_attempts WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_webhook_dead_letters WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_webhook_deliveries WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_webhook_endpoints WHERE namespace = $1', [namespace]);
      });
    }
  });

  test('express attempts list rejects non-numeric attempt cursor id', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], authOrgId, 'ops-router-postgres'),
      webhooks: webhooks!,
    });
    const srv = await startExpressRouter(router);
    try {
      const created = await fetchJson(`${srv.baseUrl}/console/webhooks`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: 'https://example.com/postgres-router-bad-attempt-cursor-express',
          subscriptions: ['billing'],
        }),
      });
      expect(created.status).toBe(201);
      const endpointId = String(getPath(created.json, 'endpoint', 'id') || '');
      expect(endpointId).toBeTruthy();

      const cursor = `${Date.parse('2026-01-03T00:00:00.000Z')}:non_numeric_attempt_id`;
      const attempts = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/attempts?cursor=${encodeURIComponent(cursor)}`,
        {
          method: 'GET',
        },
      );
      expect(attempts.status).toBe(400);
      expect(attempts.json?.code).toBe('invalid_query');

      const oversizedSortCursor = '9007199254740992:attempt_1';
      const oversizedSortKey = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/attempts?cursor=${encodeURIComponent(oversizedSortCursor)}`,
        {
          method: 'GET',
        },
      );
      expect(oversizedSortKey.status).toBe(400);
      expect(oversizedSortKey.json?.code).toBe('invalid_query');
    } finally {
      await srv.close();
    }
  });

  test('cloudflare attempts list rejects non-numeric attempt cursor id', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], authOrgId, 'ops-router-postgres'),
      webhooks: webhooks!,
    });
    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/webhooks',
      body: {
        url: 'https://example.com/postgres-router-bad-attempt-cursor-cloudflare',
        subscriptions: ['billing'],
      },
    });
    expect(created.status).toBe(201);
    const endpointId = String(getPath(created.json, 'endpoint', 'id') || '');
    expect(endpointId).toBeTruthy();

    const cursor = `${Date.parse('2026-01-03T00:00:00.000Z')}:non_numeric_attempt_id`;
    const attempts = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/attempts?cursor=${encodeURIComponent(cursor)}`,
    });
    expect(attempts.status).toBe(400);
    expect(attempts.json?.code).toBe('invalid_query');

    const oversizedSortCursor = '9007199254740992:attempt_1';
    const oversizedSortKey = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/attempts?cursor=${encodeURIComponent(oversizedSortCursor)}`,
    });
    expect(oversizedSortKey.status).toBe(400);
    expect(oversizedSortKey.json?.code).toBe('invalid_query');
  });

  test('express webhook routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner`;
    const attackerOrgId = `${authOrgId}:attacker`;

    const ownerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-user'),
      webhooks: webhooks!,
    });
    const ownerServer = await startExpressRouter(ownerRouter);
    let endpointId = '';
    try {
      const created = await fetchJson(`${ownerServer.baseUrl}/console/webhooks`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: 'https://example.com/postgres-router-org-isolation-express-owner',
          subscriptions: ['billing'],
        }),
      });
      expect(created.status).toBe(201);
      endpointId = String(getPath(created.json, 'endpoint', 'id') || '');
      expect(endpointId).toBeTruthy();
    } finally {
      await ownerServer.close();
    }

    const attackerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-user'),
      webhooks: webhooks!,
    });
    const attackerServer = await startExpressRouter(attackerRouter);
    try {
      const list = await fetchJson(`${attackerServer.baseUrl}/console/webhooks`, { method: 'GET' });
      expect(list.status).toBe(200);
      const attackerEndpoints = Array.isArray(list.json?.endpoints) ? list.json?.endpoints : [];
      expect(attackerEndpoints.some((entry: any) => String(entry?.id || '') === endpointId)).toBe(
        false,
      );

      const deliveries = await fetchJson(
        `${attackerServer.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/deliveries`,
        { method: 'GET' },
      );
      expect(deliveries.status).toBe(404);
      expect(deliveries.json?.code).toBe('webhook_not_found');

      const replay = await fetchJson(
        `${attackerServer.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/replay`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({}),
        },
      );
      expect(replay.status).toBe(404);
      expect(replay.json?.code).toBe('webhook_not_found');

      const deleted = await fetchJson(
        `${attackerServer.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}`,
        { method: 'DELETE' },
      );
      expect(deleted.status).toBe(404);
      expect(deleted.json?.code).toBe('webhook_not_found');
    } finally {
      await attackerServer.close();
    }
  });

  test('cloudflare webhook routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner-cf`;
    const attackerOrgId = `${authOrgId}:attacker-cf`;

    const ownerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-user-cf'),
      webhooks: webhooks!,
    });
    const created = await callCf(ownerHandler, {
      method: 'POST',
      path: '/console/webhooks',
      body: {
        url: 'https://example.com/postgres-router-org-isolation-cloudflare-owner',
        subscriptions: ['billing'],
      },
    });
    expect(created.status).toBe(201);
    const endpointId = String(getPath(created.json, 'endpoint', 'id') || '');
    expect(endpointId).toBeTruthy();

    const attackerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-user-cf'),
      webhooks: webhooks!,
    });
    const list = await callCf(attackerHandler, { method: 'GET', path: '/console/webhooks' });
    expect(list.status).toBe(200);
    const attackerEndpoints = Array.isArray(list.json?.endpoints) ? list.json?.endpoints : [];
    expect(attackerEndpoints.some((entry: any) => String(entry?.id || '') === endpointId)).toBe(
      false,
    );

    const deliveries = await callCf(attackerHandler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/deliveries`,
    });
    expect(deliveries.status).toBe(404);
    expect(deliveries.json?.code).toBe('webhook_not_found');

    const replay = await callCf(attackerHandler, {
      method: 'POST',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/replay`,
      body: {},
    });
    expect(replay.status).toBe(404);
    expect(replay.json?.code).toBe('webhook_not_found');

    const deleted = await callCf(attackerHandler, {
      method: 'DELETE',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}`,
    });
    expect(deleted.status).toBe(404);
    expect(deleted.json?.code).toBe('webhook_not_found');
  });
});

test.describe('console router (postgres billing)', () => {
  const postgresUrl = String(process.env.POSTGRES_URL || '').trim();
  const enabled = Boolean(postgresUrl);
  const namespace = randomNamespace('test:console-router:billing:postgres');
  const authOrgId = 'org-router-postgres-billing';
  let billing: ConsoleBillingService | null = null;

  test.beforeAll(async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    billing = await createPostgresConsoleBillingService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
    });
  });

  test.afterAll(async () => {
    if (!enabled) return;
    const pool = await getPostgresPool(postgresUrl);
    for (const orgId of [`${authOrgId}:owner`, `${authOrgId}:attacker`]) {
      await withConsoleTenantContextTx(pool, { namespace, orgId }, async (q) => {
        await q.query('DELETE FROM console_stripe_webhook_events WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_stablecoin_payment_intents WHERE namespace = $1', [
          namespace,
        ]);
        await q.query('DELETE FROM console_stablecoin_quotes WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_stripe_payment_intents WHERE namespace = $1', [
          namespace,
        ]);
        await q.query('DELETE FROM console_payment_methods WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_invoice_line_items WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_usage_rollups_monthly WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_usage_meter_events WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_invoices WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_billing_accounts WHERE namespace = $1', [namespace]);
      });
    }
    await pool.query('DELETE FROM console_stripe_provider_refs WHERE namespace = $1', [namespace]);
  });

  test('express billing routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner`;
    const attackerOrgId = `${authOrgId}:attacker`;

    const ownerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-billing-user'),
      billing: billing!,
    });
    const ownerServer = await startExpressRouter(ownerRouter);
    let ownerInvoiceId = '';
    try {
      const invoices = await fetchJson(`${ownerServer.baseUrl}/console/billing/invoices`, {
        method: 'GET',
      });
      expect(invoices.status).toBe(200);
      ownerInvoiceId = String(getPath(invoices.json, 'invoices', 0, 'id') || '');
      expect(ownerInvoiceId).toBeTruthy();
    } finally {
      await ownerServer.close();
    }

    const attackerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-billing-user'),
      billing: billing!,
    });
    const attackerServer = await startExpressRouter(attackerRouter);
    try {
      const list = await fetchJson(`${attackerServer.baseUrl}/console/billing/invoices`, {
        method: 'GET',
      });
      expect(list.status).toBe(200);
      const attackerInvoices = Array.isArray(list.json?.invoices) ? list.json?.invoices : [];
      expect(
        attackerInvoices.some((entry: any) => String(entry?.id || '') === ownerInvoiceId),
      ).toBe(false);

      const getInvoice = await fetchJson(
        `${attackerServer.baseUrl}/console/billing/invoices/${encodeURIComponent(ownerInvoiceId)}`,
        { method: 'GET' },
      );
      expect(getInvoice.status).toBe(404);
      expect(getInvoice.json?.code).toBe('invoice_not_found');

      const getLineItems = await fetchJson(
        `${attackerServer.baseUrl}/console/billing/invoices/${encodeURIComponent(ownerInvoiceId)}/line-items`,
        { method: 'GET' },
      );
      expect(getLineItems.status).toBe(404);
      expect(getLineItems.json?.code).toBe('invoice_not_found');

      const stripeIntent = await fetchJson(
        `${attackerServer.baseUrl}/console/billing/stripe/payment-intent`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ invoiceId: ownerInvoiceId }),
        },
      );
      expect(stripeIntent.status).toBe(404);
      expect(stripeIntent.json?.code).toBe('invoice_not_found');

      const quote = await fetchJson(
        `${attackerServer.baseUrl}/console/billing/stablecoins/quotes`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            invoiceId: ownerInvoiceId,
            asset: 'USDC',
            chain: 'Ethereum',
          }),
        },
      );
      expect(quote.status).toBe(404);
      expect(quote.json?.code).toBe('invoice_not_found');
    } finally {
      await attackerServer.close();
    }
  });

  test('cloudflare billing routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner-cf`;
    const attackerOrgId = `${authOrgId}:attacker-cf`;

    const ownerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-billing-user-cf'),
      billing: billing!,
    });
    const ownerInvoices = await callCf(ownerHandler, {
      method: 'GET',
      path: '/console/billing/invoices',
    });
    expect(ownerInvoices.status).toBe(200);
    const ownerInvoiceId = String(getPath(ownerInvoices.json, 'invoices', 0, 'id') || '');
    expect(ownerInvoiceId).toBeTruthy();

    const attackerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-billing-user-cf'),
      billing: billing!,
    });
    const list = await callCf(attackerHandler, {
      method: 'GET',
      path: '/console/billing/invoices',
    });
    expect(list.status).toBe(200);
    const attackerInvoices = Array.isArray(list.json?.invoices) ? list.json?.invoices : [];
    expect(attackerInvoices.some((entry: any) => String(entry?.id || '') === ownerInvoiceId)).toBe(
      false,
    );

    const getInvoice = await callCf(attackerHandler, {
      method: 'GET',
      path: `/console/billing/invoices/${encodeURIComponent(ownerInvoiceId)}`,
    });
    expect(getInvoice.status).toBe(404);
    expect(getInvoice.json?.code).toBe('invoice_not_found');

    const getLineItems = await callCf(attackerHandler, {
      method: 'GET',
      path: `/console/billing/invoices/${encodeURIComponent(ownerInvoiceId)}/line-items`,
    });
    expect(getLineItems.status).toBe(404);
    expect(getLineItems.json?.code).toBe('invoice_not_found');

    const stripeIntent = await callCf(attackerHandler, {
      method: 'POST',
      path: '/console/billing/stripe/payment-intent',
      body: { invoiceId: ownerInvoiceId },
    });
    expect(stripeIntent.status).toBe(404);
    expect(stripeIntent.json?.code).toBe('invoice_not_found');

    const quote = await callCf(attackerHandler, {
      method: 'POST',
      path: '/console/billing/stablecoins/quotes',
      body: {
        invoiceId: ownerInvoiceId,
        asset: 'USDC',
        chain: 'Ethereum',
      },
    });
    expect(quote.status).toBe(404);
    expect(quote.json?.code).toBe('invoice_not_found');
  });

  test('express billing payment-intent routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerCardOrgId = `${authOrgId}:owner-card`;
    const ownerStableOrgId = `${authOrgId}:owner-stable`;
    const attackerOrgId = `${authOrgId}:attacker-intents`;

    let stripeIntentId = '';
    const ownerCardRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerCardOrgId, 'owner-card-user'),
      billing: billing!,
    });
    const ownerCardServer = await startExpressRouter(ownerCardRouter);
    try {
      const invoices = await fetchJson(`${ownerCardServer.baseUrl}/console/billing/invoices`, {
        method: 'GET',
      });
      expect(invoices.status).toBe(200);
      const invoiceId = String(getPath(invoices.json, 'invoices', 0, 'id') || '');
      expect(invoiceId).toBeTruthy();

      const stripeIntent = await fetchJson(
        `${ownerCardServer.baseUrl}/console/billing/stripe/payment-intent`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ invoiceId }),
        },
      );
      expect(stripeIntent.status).toBe(201);
      stripeIntentId = String(getPath(stripeIntent.json, 'paymentIntent', 'id') || '');
      expect(stripeIntentId).toBeTruthy();
    } finally {
      await ownerCardServer.close();
    }

    let stableIntentId = '';
    const ownerStableRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerStableOrgId, 'owner-stable-user'),
      billing: billing!,
    });
    const ownerStableServer = await startExpressRouter(ownerStableRouter);
    try {
      const invoices = await fetchJson(`${ownerStableServer.baseUrl}/console/billing/invoices`, {
        method: 'GET',
      });
      expect(invoices.status).toBe(200);
      const invoiceId = String(getPath(invoices.json, 'invoices', 0, 'id') || '');
      expect(invoiceId).toBeTruthy();

      const quote = await fetchJson(
        `${ownerStableServer.baseUrl}/console/billing/stablecoins/quotes`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            invoiceId,
            asset: 'USDC',
            chain: 'Ethereum',
          }),
        },
      );
      expect(quote.status).toBe(201);
      const quoteId = String(getPath(quote.json, 'quote', 'id') || '');
      expect(quoteId).toBeTruthy();

      const stableIntent = await fetchJson(
        `${ownerStableServer.baseUrl}/console/billing/stablecoins/payment-intents`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            invoiceId,
            quoteId,
          }),
        },
      );
      expect(stableIntent.status).toBe(201);
      stableIntentId = String(getPath(stableIntent.json, 'paymentIntent', 'id') || '');
      expect(stableIntentId).toBeTruthy();
    } finally {
      await ownerStableServer.close();
    }

    const attackerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-intents-user'),
      billing: billing!,
    });
    const attackerServer = await startExpressRouter(attackerRouter);
    try {
      const stripeReconcile = await fetchJson(
        `${attackerServer.baseUrl}/console/billing/stripe/payment-intents/${encodeURIComponent(stripeIntentId)}/reconcile`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ providerStatus: 'PENDING' }),
        },
      );
      expect(stripeReconcile.status).toBe(404);
      expect(stripeReconcile.json?.code).toBe('payment_intent_not_found');

      const stableGet = await fetchJson(
        `${attackerServer.baseUrl}/console/billing/stablecoins/payment-intents/${encodeURIComponent(stableIntentId)}`,
        { method: 'GET' },
      );
      expect(stableGet.status).toBe(404);
      expect(stableGet.json?.code).toBe('payment_intent_not_found');

      const stableCancel = await fetchJson(
        `${attackerServer.baseUrl}/console/billing/stablecoins/payment-intents/${encodeURIComponent(stableIntentId)}/cancel`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({}),
        },
      );
      expect(stableCancel.status).toBe(404);
      expect(stableCancel.json?.code).toBe('payment_intent_not_found');

      const stableReconcile = await fetchJson(
        `${attackerServer.baseUrl}/console/billing/stablecoins/payment-intents/${encodeURIComponent(stableIntentId)}/reconcile`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            observedAmountMinor: 0,
            observedConfirmations: 0,
          }),
        },
      );
      expect(stableReconcile.status).toBe(404);
      expect(stableReconcile.json?.code).toBe('payment_intent_not_found');
    } finally {
      await attackerServer.close();
    }
  });

  test('cloudflare billing payment-intent routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerCardOrgId = `${authOrgId}:owner-card-cf`;
    const ownerStableOrgId = `${authOrgId}:owner-stable-cf`;
    const attackerOrgId = `${authOrgId}:attacker-intents-cf`;

    const ownerCardHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerCardOrgId, 'owner-card-user-cf'),
      billing: billing!,
    });
    const ownerCardInvoices = await callCf(ownerCardHandler, {
      method: 'GET',
      path: '/console/billing/invoices',
    });
    expect(ownerCardInvoices.status).toBe(200);
    const ownerCardInvoiceId = String(getPath(ownerCardInvoices.json, 'invoices', 0, 'id') || '');
    expect(ownerCardInvoiceId).toBeTruthy();

    const ownerStripeIntent = await callCf(ownerCardHandler, {
      method: 'POST',
      path: '/console/billing/stripe/payment-intent',
      body: { invoiceId: ownerCardInvoiceId },
    });
    expect(ownerStripeIntent.status).toBe(201);
    const stripeIntentId = String(getPath(ownerStripeIntent.json, 'paymentIntent', 'id') || '');
    expect(stripeIntentId).toBeTruthy();

    const ownerStableHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerStableOrgId, 'owner-stable-user-cf'),
      billing: billing!,
    });
    const ownerStableInvoices = await callCf(ownerStableHandler, {
      method: 'GET',
      path: '/console/billing/invoices',
    });
    expect(ownerStableInvoices.status).toBe(200);
    const ownerStableInvoiceId = String(
      getPath(ownerStableInvoices.json, 'invoices', 0, 'id') || '',
    );
    expect(ownerStableInvoiceId).toBeTruthy();

    const ownerQuote = await callCf(ownerStableHandler, {
      method: 'POST',
      path: '/console/billing/stablecoins/quotes',
      body: {
        invoiceId: ownerStableInvoiceId,
        asset: 'USDC',
        chain: 'Ethereum',
      },
    });
    expect(ownerQuote.status).toBe(201);
    const quoteId = String(getPath(ownerQuote.json, 'quote', 'id') || '');
    expect(quoteId).toBeTruthy();

    const ownerStableIntent = await callCf(ownerStableHandler, {
      method: 'POST',
      path: '/console/billing/stablecoins/payment-intents',
      body: {
        invoiceId: ownerStableInvoiceId,
        quoteId,
      },
    });
    expect(ownerStableIntent.status).toBe(201);
    const stableIntentId = String(getPath(ownerStableIntent.json, 'paymentIntent', 'id') || '');
    expect(stableIntentId).toBeTruthy();

    const attackerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-intents-user-cf'),
      billing: billing!,
    });
    const stripeReconcile = await callCf(attackerHandler, {
      method: 'POST',
      path: `/console/billing/stripe/payment-intents/${encodeURIComponent(stripeIntentId)}/reconcile`,
      body: {
        providerStatus: 'PENDING',
      },
    });
    expect(stripeReconcile.status).toBe(404);
    expect(stripeReconcile.json?.code).toBe('payment_intent_not_found');

    const stableGet = await callCf(attackerHandler, {
      method: 'GET',
      path: `/console/billing/stablecoins/payment-intents/${encodeURIComponent(stableIntentId)}`,
    });
    expect(stableGet.status).toBe(404);
    expect(stableGet.json?.code).toBe('payment_intent_not_found');

    const stableCancel = await callCf(attackerHandler, {
      method: 'POST',
      path: `/console/billing/stablecoins/payment-intents/${encodeURIComponent(stableIntentId)}/cancel`,
      body: {},
    });
    expect(stableCancel.status).toBe(404);
    expect(stableCancel.json?.code).toBe('payment_intent_not_found');

    const stableReconcile = await callCf(attackerHandler, {
      method: 'POST',
      path: `/console/billing/stablecoins/payment-intents/${encodeURIComponent(stableIntentId)}/reconcile`,
      body: {
        observedAmountMinor: 0,
        observedConfirmations: 0,
      },
    });
    expect(stableReconcile.status).toBe(404);
    expect(stableReconcile.json?.code).toBe('payment_intent_not_found');
  });

  test('express billing overview and MAW usage routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner-usage`;
    const attackerOrgId = `${authOrgId}:attacker-usage`;

    const ownerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-usage-user'),
      billing: billing!,
    });
    const ownerServer = await startExpressRouter(ownerRouter);
    let monthUtc = '';
    try {
      const event = await fetchJson(`${ownerServer.baseUrl}/console/billing/usage/events`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          walletId: 'wallet_owner_usage_1',
          action: 'transfer',
          succeeded: true,
          sourceEventId: `owner_usage_evt_${Date.now()}`,
        }),
      });
      expect(event.status).toBe(200);
      monthUtc = String(getPath(event.json, 'result', 'monthUtc') || '');
      expect(monthUtc).toMatch(/^\d{4}-\d{2}$/);

      const ownerOverview = await fetchJson(`${ownerServer.baseUrl}/console/billing/overview`, {
        method: 'GET',
      });
      expect(ownerOverview.status).toBe(200);
      expect(Number(getPath(ownerOverview.json, 'overview', 'monthlyActiveWallets') || 0)).toBe(1);

      const ownerUsage = await fetchJson(
        `${ownerServer.baseUrl}/console/billing/usage/monthly-active-wallets?monthUtc=${encodeURIComponent(monthUtc)}`,
        { method: 'GET' },
      );
      expect(ownerUsage.status).toBe(200);
      expect(Number(getPath(ownerUsage.json, 'usage', 'monthlyActiveWallets') || 0)).toBe(1);
    } finally {
      await ownerServer.close();
    }

    const attackerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-usage-user'),
      billing: billing!,
    });
    const attackerServer = await startExpressRouter(attackerRouter);
    try {
      const attackerOverview = await fetchJson(
        `${attackerServer.baseUrl}/console/billing/overview`,
        {
          method: 'GET',
        },
      );
      expect(attackerOverview.status).toBe(200);
      expect(Number(getPath(attackerOverview.json, 'overview', 'monthlyActiveWallets') || 0)).toBe(
        0,
      );

      const attackerUsage = await fetchJson(
        `${attackerServer.baseUrl}/console/billing/usage/monthly-active-wallets?monthUtc=${encodeURIComponent(monthUtc)}`,
        { method: 'GET' },
      );
      expect(attackerUsage.status).toBe(200);
      expect(Number(getPath(attackerUsage.json, 'usage', 'monthlyActiveWallets') || 0)).toBe(0);
    } finally {
      await attackerServer.close();
    }
  });

  test('cloudflare billing overview and MAW usage routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner-usage-cf`;
    const attackerOrgId = `${authOrgId}:attacker-usage-cf`;

    const ownerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-usage-user-cf'),
      billing: billing!,
    });
    const event = await callCf(ownerHandler, {
      method: 'POST',
      path: '/console/billing/usage/events',
      body: {
        walletId: 'wallet_owner_usage_cf_1',
        action: 'swap',
        succeeded: true,
        sourceEventId: `owner_usage_cf_evt_${Date.now()}`,
      },
    });
    expect(event.status).toBe(200);
    const monthUtc = String(getPath(event.json, 'result', 'monthUtc') || '');
    expect(monthUtc).toMatch(/^\d{4}-\d{2}$/);

    const ownerOverview = await callCf(ownerHandler, {
      method: 'GET',
      path: '/console/billing/overview',
    });
    expect(ownerOverview.status).toBe(200);
    expect(Number(getPath(ownerOverview.json, 'overview', 'monthlyActiveWallets') || 0)).toBe(1);

    const ownerUsage = await callCf(ownerHandler, {
      method: 'GET',
      path: `/console/billing/usage/monthly-active-wallets?monthUtc=${encodeURIComponent(monthUtc)}`,
    });
    expect(ownerUsage.status).toBe(200);
    expect(Number(getPath(ownerUsage.json, 'usage', 'monthlyActiveWallets') || 0)).toBe(1);

    const attackerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-usage-user-cf'),
      billing: billing!,
    });
    const attackerOverview = await callCf(attackerHandler, {
      method: 'GET',
      path: '/console/billing/overview',
    });
    expect(attackerOverview.status).toBe(200);
    expect(Number(getPath(attackerOverview.json, 'overview', 'monthlyActiveWallets') || 0)).toBe(0);

    const attackerUsage = await callCf(attackerHandler, {
      method: 'GET',
      path: `/console/billing/usage/monthly-active-wallets?monthUtc=${encodeURIComponent(monthUtc)}`,
    });
    expect(attackerUsage.status).toBe(200);
    expect(Number(getPath(attackerUsage.json, 'usage', 'monthlyActiveWallets') || 0)).toBe(0);
  });
});

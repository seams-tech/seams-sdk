import { expect, test } from '@playwright/test';

function iso(ts: string): string {
  return new Date(ts).toISOString();
}

function parseJsonBody(raw: string | null): Record<string, unknown> {
  if (!raw) return {};
  try {
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
  } catch {
    // no-op
  }
  return {};
}

interface MockDashboardContext {
  org: Record<string, unknown>;
  activeProject: Record<string, unknown>;
  activeEnvironment: Record<string, unknown>;
  archivedProject: Record<string, unknown>;
  archivedEnvironment: Record<string, unknown>;
}

function buildMockDashboardContext(): MockDashboardContext {
  return {
    org: {
      id: 'org_dash_console_pages',
      name: 'Dashboard Console Pages Org',
      slug: 'dashboard-console-pages-org',
      status: 'ACTIVE',
      createdAt: iso('2026-01-01T00:00:00.000Z'),
      updatedAt: iso('2026-01-01T00:00:00.000Z'),
    },
    activeProject: {
      id: 'proj_active',
      name: 'Project Active',
      slug: 'project-active',
      status: 'ACTIVE',
      environmentCount: 1,
      createdAt: iso('2026-01-01T00:00:00.000Z'),
      updatedAt: iso('2026-01-02T00:00:00.000Z'),
    },
    archivedProject: {
      id: 'proj_archived',
      name: 'Project Archived',
      slug: 'project-archived',
      status: 'ARCHIVED',
      environmentCount: 1,
      createdAt: iso('2026-01-01T00:00:00.000Z'),
      updatedAt: iso('2026-01-03T00:00:00.000Z'),
    },
    activeEnvironment: {
      id: 'env_active',
      projectId: 'proj_active',
      key: 'prod',
      name: 'Production',
      status: 'ACTIVE',
      createdAt: iso('2026-01-01T00:00:00.000Z'),
      updatedAt: iso('2026-01-02T00:00:00.000Z'),
    },
    archivedEnvironment: {
      id: 'env_archived',
      projectId: 'proj_active',
      key: 'staging',
      name: 'Staging Archived',
      status: 'ARCHIVED',
      createdAt: iso('2026-01-01T00:00:00.000Z'),
      updatedAt: iso('2026-01-03T00:00:00.000Z'),
    },
  };
}

test.describe('dashboard console config page api wiring', () => {
  test('gas-smart-wallets page wires create and validates scope requirements', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:5174')).origin;
    const context = buildMockDashboardContext();
    const gasConfigs: any[] = [
      {
        id: 'gs_existing',
        scopeType: 'ENVIRONMENT',
        projectId: 'proj_active',
        environmentId: 'env_active',
        policyId: null,
        walletSegmentId: null,
        enabled: true,
        paymasterMode: 'AUTO',
        fallbackBehavior: 'ALLOW_UNSPONSORED',
        chainBudgets: [],
        updatedAt: iso('2026-01-10T00:00:00.000Z'),
      },
    ];
    const smartWalletConfigs: any[] = [
      {
        id: 'sw_existing',
        scopeType: 'ENVIRONMENT',
        projectId: 'proj_active',
        environmentId: 'env_active',
        policyId: null,
        walletSegmentId: null,
        enabled: true,
        mode: 'OPTIONAL',
        accountType: 'SMART_ACCOUNT',
        paymasterMode: 'AUTO',
        fallbackBehavior: 'FALLBACK_TO_EOA',
        bundler: null,
        updatedAt: iso('2026-01-10T00:00:00.000Z'),
      },
    ];
    let lastGasCreateBody: Record<string, unknown> | null = null;
    let lastGasPatchConfigId = '';

    await page.route(`${consoleOrigin}/console/**`, async (route) => {
      const req = route.request();
      const method = req.method().toUpperCase();
      const url = new URL(req.url());
      const { pathname } = url;

      if (pathname === '/console/session') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            claims: {
              userId: 'user_dash_console_pages',
              orgId: 'org_dash_console_pages',
              roles: ['admin'],
              projectId: 'proj_active',
              environmentId: 'env_active',
            },
          }),
        });
        return;
      }

      if (pathname === '/console/org') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, org: context.org }),
        });
        return;
      }

      if (pathname === '/console/projects') {
        const status = String(url.searchParams.get('status') || '').toUpperCase();
        const projects = status === 'ACTIVE' ? [context.activeProject] : [context.activeProject, context.archivedProject];
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, projects }),
        });
        return;
      }

      if (pathname === '/console/environments') {
        const projectId = String(url.searchParams.get('projectId') || '').trim();
        const status = String(url.searchParams.get('status') || '').toUpperCase();
        let environments = [context.activeEnvironment, context.archivedEnvironment];
        if (projectId) {
          environments = environments.filter((entry: any) => String(entry.projectId) === projectId);
        }
        if (status === 'ACTIVE') {
          environments = environments.filter((entry: any) => String(entry.status) === 'ACTIVE');
        } else if (status === 'ARCHIVED') {
          environments = environments.filter((entry: any) => String(entry.status) === 'ARCHIVED');
        }
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, environments }),
        });
        return;
      }

      if (pathname === '/console/gas-sponsorship' && method === 'GET') {
        const environmentId = String(url.searchParams.get('environmentId') || '').trim();
        const projectId = String(url.searchParams.get('projectId') || '').trim();
        const rows = gasConfigs.filter((entry) => {
          if (environmentId && String(entry.environmentId || '') !== environmentId) return false;
          if (projectId && String(entry.projectId || '') !== projectId) return false;
          return true;
        });
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, configs: rows }),
        });
        return;
      }

      if (pathname === '/console/gas-sponsorship' && method === 'POST') {
        const body = parseJsonBody(req.postData());
        lastGasCreateBody = body;
        const scopeType = String(body.scopeType || '').toUpperCase();
        const environmentId = String(body.environmentId || '').trim();
        if (scopeType === 'ENVIRONMENT' && !environmentId) {
          await route.fulfill({
            status: 400,
            contentType: 'application/json',
            body: JSON.stringify({
              ok: false,
              code: 'invalid_scope',
              message: 'Scope ENVIRONMENT is missing a required identifier',
            }),
          });
          return;
        }
        const now = iso('2026-02-01T00:00:00.000Z');
        const created = {
          id: String(body.id || `gs_created_${Date.now()}`),
          scopeType,
          projectId: body.projectId ?? null,
          environmentId: body.environmentId ?? null,
          policyId: body.policyId ?? null,
          walletSegmentId: body.walletSegmentId ?? null,
          enabled: body.enabled !== false,
          paymasterMode: String(body.paymasterMode || 'AUTO'),
          fallbackBehavior: String(body.fallbackBehavior || 'ALLOW_UNSPONSORED'),
          chainBudgets: Array.isArray(body.chainBudgets) ? body.chainBudgets : [],
          updatedAt: now,
        };
        gasConfigs.unshift(created);
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, config: created }),
        });
        return;
      }

      const gasPatchMatch = pathname.match(/^\/console\/gas-sponsorship\/([^/]+)$/);
      if (gasPatchMatch && method === 'PATCH') {
        const body = parseJsonBody(req.postData());
        const configId = decodeURIComponent(String(gasPatchMatch[1] || ''));
        lastGasPatchConfigId = configId;
        const target = gasConfigs.find((entry) => String(entry.id || '') === configId);
        if (!target) {
          await route.fulfill({
            status: 404,
            contentType: 'application/json',
            body: JSON.stringify({
              ok: false,
              code: 'gas_sponsorship_not_found',
              message: `Gas sponsorship config ${configId} was not found`,
            }),
          });
          return;
        }
        if (body.enabled !== undefined) {
          target.enabled = body.enabled === true;
        }
        target.updatedAt = iso('2026-02-01T00:00:00.000Z');
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, config: target }),
        });
        return;
      }

      if (pathname === '/console/smart-wallets' && method === 'GET') {
        const environmentId = String(url.searchParams.get('environmentId') || '').trim();
        const projectId = String(url.searchParams.get('projectId') || '').trim();
        const rows = smartWalletConfigs.filter((entry) => {
          if (environmentId && String(entry.environmentId || '') !== environmentId) return false;
          if (projectId && String(entry.projectId || '') !== projectId) return false;
          return true;
        });
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, configs: rows }),
        });
        return;
      }

      await route.fulfill({
        status: 404,
        contentType: 'application/json',
        body: JSON.stringify({
          ok: false,
          code: 'not_found',
          message: `Unhandled mock path ${pathname}`,
        }),
      });
    });

    await page.goto('/dashboard/gas-smart-wallets');
    await expect(page.locator('#dashboard-main-title')).toHaveText(/gas sponsorship and smart wallets/i);
    await expect(page.locator('section[aria-label="Gas sponsorship configs table"]')).toContainText(
      'gs_existing',
    );

    const gasCreateSection = page.locator('section[aria-label="Create gas sponsorship config"]');
    await gasCreateSection.locator('label:has-text("Config ID (optional)") input').fill('gs_new_e2e');
    await gasCreateSection.locator('label:has-text("Budget chain (optional)") input').fill('Ethereum');
    await gasCreateSection.locator('label:has-text("Budget (minor units)") input').fill('50000');
    await gasCreateSection.locator('label:has-text("Quota transactions") input').fill('1200');
    await gasCreateSection
      .locator('button:has-text("Create gas sponsorship config")')
      .click();

    await expect
      .poll(() => String(lastGasCreateBody?.id || ''))
      .toBe('gs_new_e2e');
    await expect(page.locator('section[aria-label="Gas sponsorship configs table"]')).toContainText(
      'gs_new_e2e',
    );

    const gasTable = page.locator('section[aria-label="Gas sponsorship configs table"]');
    const existingGasRow = gasTable.locator('.dashboard-table-row', { hasText: 'gs_existing' });
    await existingGasRow.locator('button:has-text("Disable")').click();
    await expect.poll(() => lastGasPatchConfigId).toBe('gs_existing');
    await expect(existingGasRow).toContainText('false');
  });

  test('export-keys page wires create and approve flows with MFA guard', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:5174')).origin;
    const context = buildMockDashboardContext();
    const keyExports: any[] = [
      {
        id: 'ke_existing',
        environmentId: 'env_active',
        walletId: null,
        mode: 'APPROVAL_REQUIRED',
        status: 'PENDING_APPROVAL',
        reason: 'Existing key export',
        requestedByUserId: 'user_a',
        requiredApprovals: 1,
        approvals: [],
        constraints: { roles: [], chains: [], walletTypes: [], environmentIds: [] },
        createdAt: iso('2026-01-10T00:00:00.000Z'),
        updatedAt: iso('2026-01-10T00:00:00.000Z'),
      },
    ];
    let lastCreateBody: Record<string, unknown> | null = null;
    let lastApproveBody: Record<string, unknown> | null = null;

    await page.route(`${consoleOrigin}/console/**`, async (route) => {
      const req = route.request();
      const method = req.method().toUpperCase();
      const url = new URL(req.url());
      const { pathname } = url;

      if (pathname === '/console/session') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            claims: {
              userId: 'user_dash_console_pages',
              orgId: 'org_dash_console_pages',
              roles: ['admin'],
              projectId: 'proj_active',
              environmentId: 'env_active',
            },
          }),
        });
        return;
      }

      if (pathname === '/console/org') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, org: context.org }),
        });
        return;
      }

      if (pathname === '/console/projects') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, projects: [context.activeProject] }),
        });
        return;
      }

      if (pathname === '/console/environments') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, environments: [context.activeEnvironment] }),
        });
        return;
      }

      if (pathname === '/console/key-exports' && method === 'GET') {
        const status = String(url.searchParams.get('status') || '').trim().toUpperCase();
        const environmentId = String(url.searchParams.get('environmentId') || '').trim();
        const rows = keyExports.filter((entry) => {
          if (status && String(entry.status || '').toUpperCase() !== status) return false;
          if (environmentId && String(entry.environmentId || '') !== environmentId) return false;
          return true;
        });
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, exports: rows }),
        });
        return;
      }

      if (pathname === '/console/key-exports' && method === 'POST') {
        const body = parseJsonBody(req.postData());
        lastCreateBody = body;
        const now = iso('2026-02-01T00:00:00.000Z');
        const created = {
          id: String(body.id || `ke_created_${Date.now()}`),
          environmentId: String(body.environmentId || 'env_active'),
          walletId: body.walletId ?? null,
          mode: String(body.mode || 'APPROVAL_REQUIRED'),
          status: 'PENDING_APPROVAL',
          reason: String(body.reason || ''),
          requestedByUserId: 'user_dash_console_pages',
          requiredApprovals: Number(body.requiredApprovals || 1),
          approvals: [],
          constraints: {
            roles: Array.isArray((body.constraints as any)?.roles) ? (body.constraints as any).roles : [],
            chains: Array.isArray((body.constraints as any)?.chains) ? (body.constraints as any).chains : [],
            walletTypes: Array.isArray((body.constraints as any)?.walletTypes) ? (body.constraints as any).walletTypes : [],
            environmentIds: Array.isArray((body.constraints as any)?.environmentIds)
              ? (body.constraints as any).environmentIds
              : [],
          },
          createdAt: now,
          updatedAt: now,
        };
        keyExports.unshift(created);
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, keyExport: created }),
        });
        return;
      }

      const approveMatch = pathname.match(/^\/console\/key-exports\/([^/]+)\/approve$/);
      if (approveMatch && method === 'POST') {
        const body = parseJsonBody(req.postData());
        lastApproveBody = body;
        const id = decodeURIComponent(String(approveMatch[1] || ''));
        const row = keyExports.find((entry) => String(entry.id) === id);
        if (!row) {
          await route.fulfill({
            status: 404,
            contentType: 'application/json',
            body: JSON.stringify({
              ok: false,
              code: 'key_export_not_found',
              message: `Key export request ${id} was not found`,
            }),
          });
          return;
        }
        if (body.mfaVerified !== true) {
          await route.fulfill({
            status: 400,
            contentType: 'application/json',
            body: JSON.stringify({
              ok: false,
              code: 'mfa_required',
              message: 'MFA is required to approve key export requests',
            }),
          });
          return;
        }
        const now = iso('2026-02-02T00:00:00.000Z');
        row.approvals = [
          {
            approverUserId: 'user_dash_console_pages',
            approvedAt: now,
            reason: String(body.reason || ''),
            mfaVerified: true,
          },
        ];
        row.status = 'APPROVED';
        row.updatedAt = now;
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, keyExport: row }),
        });
        return;
      }

      await route.fulfill({
        status: 404,
        contentType: 'application/json',
        body: JSON.stringify({
          ok: false,
          code: 'not_found',
          message: `Unhandled mock path ${pathname}`,
        }),
      });
    });

    await page.goto('/dashboard/export-keys');
    await expect(page.locator('#dashboard-main-title')).toHaveText(/export keys settings/i);
    await expect(page.locator('section[aria-label="Key export requests table"]')).toContainText(
      'ke_existing',
    );

    const createSection = page.locator('section[aria-label="Create key export request"]');
    await createSection.locator('label:has-text("Request ID (optional)") input').fill('ke_new_e2e');
    await createSection.locator('label:has-text("Reason") input').fill('Need export for audit');
    await createSection.locator('button:has-text("Create export request")').click();

    await expect.poll(() => String(lastCreateBody?.id || '')).toBe('ke_new_e2e');
    await expect(page.locator('section[aria-label="Key export requests table"]')).toContainText(
      'ke_new_e2e',
    );

    const approveSection = page.locator('section[aria-label="Approve key export request"]');
    await approveSection
      .locator('label:has-text("Pending request") select')
      .selectOption('ke_new_e2e');
    await approveSection.locator('label:has-text("MFA verified") input[type="checkbox"]').setChecked(false);
    await approveSection.locator('button:has-text("Approve request")').click();
    await expect(page.locator('section[aria-label="Key export request controls"]')).toContainText(
      'MFA is required to approve key export requests',
    );

    await approveSection.locator('label:has-text("MFA verified") input[type="checkbox"]').setChecked(true);
    await approveSection.locator('button:has-text("Approve request")').click();
    await expect.poll(() => String(lastApproveBody?.reason || '')).not.toBe('');
    await expect(page.locator('section[aria-label="Key export requests table"]')).toContainText(
      'APPROVED',
    );
  });

  test('app-settings page wires app and security settings patch flows', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:5174')).origin;
    const context = buildMockDashboardContext();
    let appSettings = {
      environmentId: 'env_active',
      allowedOrigins: ['https://existing.example.com'],
      allowedDomains: ['example.com'],
      cookie: {
        httpOnly: true,
        secure: true,
        sameSite: 'LAX',
        domain: null,
        path: '/',
        maxAgeSeconds: 86400,
      },
      jwt: {
        issuer: 'https://issuer.example.com',
        audience: ['dashboard'],
        keyIds: ['kid-1'],
        accessTokenTtlSeconds: 900,
        refreshTokenTtlSeconds: 2592000,
      },
      ssoMetadataUrl: null,
      updatedAt: iso('2026-01-05T00:00:00.000Z'),
    };
    let securitySettings = {
      environmentId: 'env_active',
      ipAllowlist: ['203.0.113.1/32'],
      enforceIpAllowlist: false,
      requireMfaForRiskyChanges: true,
      riskyChangeApproval: {
        approvalsRequired: 1,
        requireAdmin: true,
        requireMfa: true,
      },
      updatedAt: iso('2026-01-05T00:00:00.000Z'),
    };
    let runtimeSnapshots: any[] = [
      {
        orgId: 'org_dash_console_pages',
        projectId: 'proj_active',
        environmentId: 'env_active',
        snapshotId: 'snapshot_existing_v2',
        version: 2,
        effectiveAt: iso('2026-02-01T00:00:00.000Z'),
        checksum: 'fnv1a32:11111111',
        payload: {
          policy: { status: 'resolved', policyCount: 2, assignmentCount: 1 },
          settings: { status: 'resolved' },
          gasSponsorship: { status: 'resolved', configCount: 1 },
          smartWallets: { status: 'resolved', configCount: 1 },
          metadata: { source: 'server_publish_current_v1' },
        },
        createdAt: iso('2026-02-01T00:00:00.000Z'),
        createdBy: 'user_dash_console_pages',
      },
      {
        orgId: 'org_dash_console_pages',
        projectId: 'proj_active',
        environmentId: 'env_active',
        snapshotId: 'snapshot_existing_v1',
        version: 1,
        effectiveAt: iso('2026-01-15T00:00:00.000Z'),
        checksum: 'fnv1a32:00000000',
        payload: {
          policy: { status: 'resolved', policyCount: 1, assignmentCount: 1 },
          settings: { status: 'resolved' },
          gasSponsorship: { status: 'not_configured', configCount: 0 },
          smartWallets: { status: 'not_configured', configCount: 0 },
          metadata: { source: 'server_publish_current_v1' },
        },
        createdAt: iso('2026-01-15T00:00:00.000Z'),
        createdBy: 'user_dash_console_pages',
      },
    ];
    let lastAppPatchBody: Record<string, unknown> | null = null;
    let lastSecurityPatchBody: Record<string, unknown> | null = null;
    let lastPublishCurrentBody: Record<string, unknown> | null = null;

    await page.route(`${consoleOrigin}/console/**`, async (route) => {
      const req = route.request();
      const method = req.method().toUpperCase();
      const url = new URL(req.url());
      const { pathname } = url;

      if (pathname === '/console/session') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            claims: {
              userId: 'user_dash_console_pages',
              orgId: 'org_dash_console_pages',
              roles: ['admin'],
              projectId: 'proj_active',
              environmentId: 'env_active',
            },
          }),
        });
        return;
      }

      if (pathname === '/console/org') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, org: context.org }),
        });
        return;
      }

      if (pathname === '/console/projects') {
        const status = String(url.searchParams.get('status') || '').toUpperCase();
        const projects = status === 'ACTIVE' ? [context.activeProject] : [context.activeProject, context.archivedProject];
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, projects }),
        });
        return;
      }

      if (pathname === '/console/environments') {
        const status = String(url.searchParams.get('status') || '').toUpperCase();
        const projectId = String(url.searchParams.get('projectId') || '').trim();
        let environments = [context.activeEnvironment, context.archivedEnvironment];
        if (projectId) {
          environments = environments.filter((entry: any) => String(entry.projectId) === projectId);
        }
        if (status === 'ACTIVE') {
          environments = environments.filter((entry: any) => String(entry.status) === 'ACTIVE');
        } else if (status === 'ARCHIVED') {
          environments = environments.filter((entry: any) => String(entry.status) === 'ARCHIVED');
        }
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, environments }),
        });
        return;
      }

      if (pathname === '/console/settings/app' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, appSettings }),
        });
        return;
      }

      if (pathname === '/console/settings/security' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, securitySettings }),
        });
        return;
      }

      if (pathname === '/console/settings/app' && method === 'PATCH') {
        const body = parseJsonBody(req.postData());
        lastAppPatchBody = body;
        appSettings = {
          ...appSettings,
          environmentId: String(body.environmentId || appSettings.environmentId),
          allowedOrigins: Array.isArray(body.allowedOrigins)
            ? (body.allowedOrigins as string[])
            : appSettings.allowedOrigins,
          allowedDomains: Array.isArray(body.allowedDomains)
            ? (body.allowedDomains as string[])
            : appSettings.allowedDomains,
          cookie:
            body.cookie && typeof body.cookie === 'object'
              ? { ...appSettings.cookie, ...(body.cookie as Record<string, unknown>) }
              : appSettings.cookie,
          jwt:
            body.jwt && typeof body.jwt === 'object'
              ? { ...appSettings.jwt, ...(body.jwt as Record<string, unknown>) }
              : appSettings.jwt,
          ssoMetadataUrl:
            body.ssoMetadataUrl === undefined
              ? appSettings.ssoMetadataUrl
              : (body.ssoMetadataUrl as string | null),
          updatedAt: iso('2026-02-03T00:00:00.000Z'),
        };
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, appSettings }),
        });
        return;
      }

      if (pathname === '/console/settings/security' && method === 'PATCH') {
        const body = parseJsonBody(req.postData());
        lastSecurityPatchBody = body;
        securitySettings = {
          ...securitySettings,
          environmentId: String(body.environmentId || securitySettings.environmentId),
          ipAllowlist: Array.isArray(body.ipAllowlist)
            ? (body.ipAllowlist as string[])
            : securitySettings.ipAllowlist,
          enforceIpAllowlist:
            body.enforceIpAllowlist === undefined
              ? securitySettings.enforceIpAllowlist
              : Boolean(body.enforceIpAllowlist),
          requireMfaForRiskyChanges:
            body.requireMfaForRiskyChanges === undefined
              ? securitySettings.requireMfaForRiskyChanges
              : Boolean(body.requireMfaForRiskyChanges),
          riskyChangeApproval:
            body.riskyChangeApproval && typeof body.riskyChangeApproval === 'object'
              ? {
                  ...securitySettings.riskyChangeApproval,
                  ...(body.riskyChangeApproval as Record<string, unknown>),
                }
              : securitySettings.riskyChangeApproval,
          updatedAt: iso('2026-02-03T00:00:00.000Z'),
        };
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, securitySettings }),
        });
        return;
      }

      if (pathname === '/console/runtime-snapshots/latest' && method === 'GET') {
        const environmentId = String(url.searchParams.get('environmentId') || '').trim();
        const projectId = String(url.searchParams.get('projectId') || '').trim();
        const rows = runtimeSnapshots
          .filter((entry) => {
            if (environmentId && String(entry.environmentId || '') !== environmentId) return false;
            if (projectId && String(entry.projectId || '') !== projectId) return false;
            return true;
          })
          .sort((a, b) => Number(b.version || 0) - Number(a.version || 0));
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, snapshot: rows[0] || null }),
        });
        return;
      }

      if (pathname === '/console/runtime-snapshots' && method === 'GET') {
        const environmentId = String(url.searchParams.get('environmentId') || '').trim();
        const projectId = String(url.searchParams.get('projectId') || '').trim();
        const limitRaw = Number(url.searchParams.get('limit') || 20);
        const limit = Number.isFinite(limitRaw) && limitRaw > 0 ? Math.floor(limitRaw) : 20;
        const rows = runtimeSnapshots
          .filter((entry) => {
            if (environmentId && String(entry.environmentId || '') !== environmentId) return false;
            if (projectId && String(entry.projectId || '') !== projectId) return false;
            return true;
          })
          .sort((a, b) => Number(b.version || 0) - Number(a.version || 0))
          .slice(0, limit);
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, snapshots: rows }),
        });
        return;
      }

      if (pathname === '/console/runtime-snapshots/publish-current' && method === 'POST') {
        const body = parseJsonBody(req.postData());
        lastPublishCurrentBody = body;
        const environmentId = String(body.environmentId || '').trim();
        const projectId = String(body.projectId || '').trim();
        const scoped = runtimeSnapshots.filter((entry) => {
          if (environmentId && String(entry.environmentId || '') !== environmentId) return false;
          if (projectId && String(entry.projectId || '') !== projectId) return false;
          return true;
        });
        const nextVersion = scoped.length + 1;
        const createdAt = iso('2026-02-06T00:00:00.000Z');
        const created = {
          orgId: 'org_dash_console_pages',
          projectId: projectId || null,
          environmentId: environmentId || 'env_active',
          snapshotId:
            String(body.snapshotId || '').trim() || `runtime_snapshot_generated_v${String(nextVersion)}`,
          version: nextVersion,
          effectiveAt: String(body.effectiveAt || '').trim() || createdAt,
          checksum: `fnv1a32:created_${String(nextVersion)}`,
          payload: {
            policy: { status: 'resolved', policyCount: 2, assignmentCount: 1 },
            settings: { status: 'resolved' },
            gasSponsorship: { status: 'resolved', configCount: 1 },
            smartWallets: { status: 'resolved', configCount: 1 },
            metadata: { source: 'server_publish_current_v1' },
          },
          createdAt,
          createdBy: 'user_dash_console_pages',
        };
        runtimeSnapshots = [created, ...runtimeSnapshots];
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, snapshot: created }),
        });
        return;
      }

      await route.fulfill({
        status: 404,
        contentType: 'application/json',
        body: JSON.stringify({
          ok: false,
          code: 'not_found',
          message: `Unhandled mock path ${pathname}`,
        }),
      });
    });

    await page.goto('/dashboard/app-settings');
    await expect(page.locator('#dashboard-main-title')).toHaveText(/app settings/i);
    await expect(page.locator('section[aria-label="App and security settings controls"]')).toBeVisible();
    await expect(page.locator('section[aria-label="Latest runtime snapshot"]')).toContainText(
      'snapshot_existing_v2',
    );

    const appSection = page.locator('section[aria-label="Update app settings"]');
    await appSection
      .locator('label:has-text("Allowed origins (csv)") input')
      .fill('https://dashboard.example.com, https://api.example.com');
    await appSection
      .locator('label:has-text("Cookie max age (seconds)") input')
      .fill('7200');
    await appSection.locator('button:has-text("Update app settings")').click();
    await expect.poll(() => String(lastAppPatchBody?.environmentId || '')).toBe('env_active');
    await expect(page.locator('section[aria-label="Current settings snapshot"]')).toContainText('2');

    const securitySection = page.locator('section[aria-label="Update security settings"]');
    await securitySection
      .locator('label:has-text("Risky change approvals required") input')
      .fill('2');
    await securitySection
      .locator('label:has-text("Require MFA for risky changes") input[type="checkbox"]')
      .setChecked(false);
    await securitySection.locator('button:has-text("Update security settings")').click();
    await expect
      .poll(() =>
        Number(
          ((lastSecurityPatchBody?.riskyChangeApproval as Record<string, unknown> | undefined)
            ?.approvalsRequired as number) || 0,
        ),
      )
      .toBe(2);
    await expect(page.locator('section[aria-label="Current settings snapshot"]')).toContainText('false');

    const runtimeControls = page.locator('section[aria-label="App and security settings controls"]');
    await runtimeControls
      .locator('label:has-text("Snapshot ID (optional)") input')
      .fill('runtime_snapshot_manual_e2e');
    await runtimeControls
      .locator('label:has-text("Effective at (optional ISO-8601)") input')
      .fill('2026-02-07T00:00:00.000Z');
    await runtimeControls.locator('button:has-text("Publish current runtime snapshot")').click();
    await expect.poll(() => String(lastPublishCurrentBody?.environmentId || '')).toBe('env_active');
    await expect(page.locator('section[aria-label="Latest runtime snapshot"]')).toContainText(
      'runtime_snapshot_manual_e2e',
    );
    await expect(page.locator('section[aria-label="Runtime snapshots history"]')).toContainText(
      'runtime_snapshot_manual_e2e',
    );
  });
});

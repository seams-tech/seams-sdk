import { expect, test } from '@playwright/test';

function iso(ts: string): string {
  return new Date(ts).toISOString();
}

test.describe('dashboard credential-policy context hierarchy', () => {
  test('shows auto-provisioned environments without mutation controls', async ({ page, baseURL }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    const projectQueryStrings: string[] = [];
    const environmentQueryStrings: string[] = [];

    const org = {
      id: 'org_dash_1',
      name: 'Dashboard Org',
      slug: 'dashboard-org',
      status: 'ACTIVE',
      createdAt: iso('2026-01-01T00:00:00.000Z'),
      updatedAt: iso('2026-01-01T00:00:00.000Z'),
    };

    const activeProject = {
      id: 'proj_active',
      name: 'Project Active',
      slug: 'project-active',
      status: 'ACTIVE',
      environmentCount: 1,
      createdAt: iso('2026-01-01T00:00:00.000Z'),
      updatedAt: iso('2026-01-02T00:00:00.000Z'),
    };

    const activeEnvironment = {
      id: 'proj_active:dev',
      projectId: 'proj_active',
      key: 'dev',
      name: 'Development',
      status: 'ACTIVE',
      createdAt: iso('2026-01-01T00:00:00.000Z'),
      updatedAt: iso('2026-01-02T00:00:00.000Z'),
    };
    const disabledProductionEnvironment = {
      id: 'proj_active:prod',
      projectId: 'proj_active',
      key: 'prod',
      name: 'Production',
      status: 'DISABLED',
      createdAt: iso('2026-01-01T00:00:00.000Z'),
      updatedAt: iso('2026-01-03T00:00:00.000Z'),
    };
    const archivedEnvironment = {
      id: 'proj_active:staging',
      projectId: 'proj_active',
      key: 'staging',
      name: 'Staging',
      status: 'ARCHIVED',
      createdAt: iso('2026-01-01T00:00:00.000Z'),
      updatedAt: iso('2026-01-03T00:00:00.000Z'),
    };

    const appSettingsByEnvironmentId: Record<string, Record<string, unknown>> = {
      [activeEnvironment.id]: {
        environmentId: activeEnvironment.id,
        allowedOrigins: ['https://app.example.com'],
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
        updatedAt: iso('2026-01-03T00:00:00.000Z'),
      },
      [disabledProductionEnvironment.id]: {
        environmentId: disabledProductionEnvironment.id,
        allowedOrigins: ['https://app.example.com'],
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
        updatedAt: iso('2026-01-03T00:00:00.000Z'),
      },
    };

    const securitySettingsByEnvironmentId: Record<string, Record<string, unknown>> = {
      [activeEnvironment.id]: {
        environmentId: activeEnvironment.id,
        ipAllowlist: [],
        enforceIpAllowlist: false,
        requireMfaForRiskyChanges: true,
        riskyChangeApproval: {
          approvalsRequired: 1,
          requireAdmin: true,
          requireMfa: true,
        },
        updatedAt: iso('2026-01-03T00:00:00.000Z'),
      },
      [disabledProductionEnvironment.id]: {
        environmentId: disabledProductionEnvironment.id,
        ipAllowlist: [],
        enforceIpAllowlist: false,
        requireMfaForRiskyChanges: true,
        riskyChangeApproval: {
          approvalsRequired: 1,
          requireAdmin: true,
          requireMfa: true,
        },
        updatedAt: iso('2026-01-03T00:00:00.000Z'),
      },
    };

    await page.route(`${consoleOrigin}/console/**`, async (route) => {
      const url = new URL(route.request().url());
      const { pathname, search } = url;

      if (pathname === '/console/session') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            claims: {
              userId: 'user_dash_1',
              orgId: 'org_dash_1',
              roles: ['admin'],
              projectId: 'proj_active',
              environmentId: activeEnvironment.id,
            },
          }),
        });
        return;
      }

      if (pathname === '/console/org') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            org,
          }),
        });
        return;
      }

      if (pathname === '/console/projects') {
        projectQueryStrings.push(search);
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            projects: [activeProject],
          }),
        });
        return;
      }

      if (pathname === '/console/environments') {
        environmentQueryStrings.push(search);
        const projectId = url.searchParams.get('projectId');
        const status = url.searchParams.get('status');
        let environments = [activeEnvironment, disabledProductionEnvironment, archivedEnvironment];
        if (projectId) {
          environments = environments.filter((entry) => entry.projectId === projectId);
        }
        if (status && status.toUpperCase() === 'ACTIVE') {
          environments = environments.filter((entry) => entry.status === 'ACTIVE');
        } else if (status && status.toUpperCase() === 'ARCHIVED') {
          environments = environments.filter((entry) => entry.status === 'ARCHIVED');
        }
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            environments,
          }),
        });
        return;
      }

      if (pathname === '/console/settings/app') {
        const environmentId = String(url.searchParams.get('environmentId') || '').trim();
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            appSettings: appSettingsByEnvironmentId[environmentId] || appSettingsByEnvironmentId[activeEnvironment.id],
          }),
        });
        return;
      }

      if (pathname === '/console/settings/security') {
        const environmentId = String(url.searchParams.get('environmentId') || '').trim();
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            securitySettings:
              securitySettingsByEnvironmentId[environmentId] ||
              securitySettingsByEnvironmentId[activeEnvironment.id],
          }),
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

    await page.goto('/dashboard/credential-policy');
    await expect(page.locator('main[aria-label="Dashboard workspace"]')).toBeVisible();
    await expect(page.locator('#dashboard-main-title')).toHaveText(/credential policy/i);
    await expect(page.locator('section[aria-label="Project management"]')).toContainText('proj_active');
    await expect(page.locator('section[aria-label="Environment inventory"]')).toHaveCount(0);
    await expect(page.locator('section[aria-label="Environment management"]')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Create environment' })).toHaveCount(0);

    await expect.poll(() => projectQueryStrings.length).toBeGreaterThan(0);
    await expect.poll(() => environmentQueryStrings.length).toBeGreaterThan(0);
    expect(projectQueryStrings.some((entry) => entry.includes('status=ACTIVE'))).toBe(true);
    expect(environmentQueryStrings.some((entry) => entry.includes('projectId=proj_active'))).toBe(true);
    await expect(page.getByRole('button', { name: 'Create project' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Edit' })).toHaveCount(1);
  });
});

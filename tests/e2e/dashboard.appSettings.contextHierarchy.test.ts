import { expect, test } from '@playwright/test';

function iso(ts: string): string {
  return new Date(ts).toISOString();
}

test.describe('dashboard app-settings context hierarchy', () => {
  test('uses archived toggles and active-project create guard semantics', async ({ page, baseURL }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:5174')).origin;
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
    const archivedProject = {
      id: 'proj_archived',
      name: 'Project Archived',
      slug: 'project-archived',
      status: 'ARCHIVED',
      environmentCount: 1,
      createdAt: iso('2026-01-01T00:00:00.000Z'),
      updatedAt: iso('2026-01-03T00:00:00.000Z'),
    };

    const activeEnvironment = {
      id: 'env_active',
      projectId: 'proj_active',
      key: 'prod',
      name: 'Production',
      status: 'ACTIVE',
      createdAt: iso('2026-01-01T00:00:00.000Z'),
      updatedAt: iso('2026-01-02T00:00:00.000Z'),
    };
    const archivedEnvironment = {
      id: 'env_archived',
      projectId: 'proj_active',
      key: 'staging',
      name: 'Staging Archived',
      status: 'ARCHIVED',
      createdAt: iso('2026-01-01T00:00:00.000Z'),
      updatedAt: iso('2026-01-03T00:00:00.000Z'),
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
          body: JSON.stringify({
            ok: true,
            org,
          }),
        });
        return;
      }

      if (pathname === '/console/projects') {
        projectQueryStrings.push(search);
        const status = url.searchParams.get('status');
        const projects =
          status && status.toUpperCase() === 'ACTIVE'
            ? [activeProject]
            : [activeProject, archivedProject];
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            projects,
          }),
        });
        return;
      }

      if (pathname === '/console/environments') {
        environmentQueryStrings.push(search);
        const projectId = url.searchParams.get('projectId');
        const status = url.searchParams.get('status');
        let environments = [activeEnvironment, archivedEnvironment];
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
    await expect(page.locator('main[aria-label="Dashboard workspace"]')).toBeVisible();
    await expect(page.locator('#dashboard-main-title')).toHaveText(/app settings/i);
    await expect(page.locator('section[aria-label="Project management"]')).toContainText('proj_active');
    await expect(page.locator('section[aria-label="Environment management"]')).toContainText(
      'env_active',
    );

    await expect.poll(() => projectQueryStrings.length).toBeGreaterThan(0);
    await expect.poll(() => environmentQueryStrings.length).toBeGreaterThan(0);
    expect(projectQueryStrings.some((entry) => entry.includes('status=ACTIVE'))).toBe(true);
    expect(environmentQueryStrings.some((entry) => entry.includes('status=ACTIVE'))).toBe(true);

    const projectSection = page.locator('section[aria-label="Project management"]');
    await projectSection
      .locator('label:has-text("Include archived") input[type="checkbox"]')
      .setChecked(true);
    await expect(projectSection).toContainText('proj_archived');
    await expect
      .poll(() => projectQueryStrings[projectQueryStrings.length - 1] || '')
      .not.toContain('status=ACTIVE');

    const environmentSection = page.locator('section[aria-label="Environment management"]');
    await environmentSection
      .locator('label:has-text("Include archived") input[type="checkbox"]')
      .setChecked(true);
    await expect(environmentSection).toContainText('env_archived');
    await expect
      .poll(() => environmentQueryStrings[environmentQueryStrings.length - 1] || '')
      .not.toContain('status=ACTIVE');

    const createEnvironmentProjectOptions = page.locator(
      'form:has-text("New environment ID (optional)") label:has-text("Project") option',
    );
    await expect(createEnvironmentProjectOptions).toHaveCount(1);
    await expect(createEnvironmentProjectOptions.first()).toHaveAttribute('value', 'proj_active');
  });
});

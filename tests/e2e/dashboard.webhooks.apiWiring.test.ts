import { expect, test, type Page, type Route } from '@playwright/test';

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
  } catch {}
  return {};
}

async function fulfillJson(route: Route, body: unknown, status = 200): Promise<void> {
  await route.fulfill({
    status,
    contentType: 'application/json',
    body: JSON.stringify(body),
  });
}

async function routeWorkspaceScaffold(
  page: Page,
  consoleOrigin: string,
  input: {
    userId: string;
    org: Record<string, unknown>;
    project: Record<string, unknown>;
    environment: Record<string, unknown>;
    handleWebhookRequest: (
      route: Route,
      pathname: string,
      method: string,
      url: URL,
    ) => Promise<boolean>;
  },
): Promise<void> {
  await page.route(`${consoleOrigin}/console/**`, async (route) => {
    const req = route.request();
    const method = req.method().toUpperCase();
    const url = new URL(req.url());
    const { pathname } = url;

    if (pathname === '/console/session') {
      await fulfillJson(route, {
        ok: true,
        claims: {
          userId: input.userId,
          orgId: String(input.org.id || ''),
          roles: ['admin'],
          projectId: String(input.project.id || ''),
          environmentId: String(input.environment.id || ''),
        },
      });
      return;
    }

    if (pathname === '/console/onboarding/state') {
      await fulfillJson(route, {
        ok: true,
        state: {
          orgId: String(input.org.id || ''),
          organization: input.org,
          activeProjectCount: 1,
          activeEnvironmentCount: 1,
          activeApiKeyCount: 1,
          hasOrganization: true,
          hasProject: true,
          hasEnvironment: true,
          hasApiKey: true,
          accountReady: true,
          organizationReady: true,
          billingReady: true,
          projectReady: true,
          onboardingComplete: true,
          currentStep: 'complete',
          complete: true,
          selectedProjectId: String(input.project.id || ''),
          selectedEnvironmentId: String(input.environment.id || ''),
        },
      });
      return;
    }

    if (pathname === '/console/org') {
      await fulfillJson(route, { ok: true, org: input.org });
      return;
    }

    if (pathname === '/console/projects') {
      await fulfillJson(route, { ok: true, projects: [input.project] });
      return;
    }

    if (pathname === '/console/environments') {
      await fulfillJson(route, { ok: true, environments: [input.environment] });
      return;
    }

    if (await input.handleWebhookRequest(route, pathname, method, url)) {
      return;
    }

    await fulfillJson(
      route,
      {
        ok: false,
        code: 'not_found',
        message: `Unhandled mock path ${pathname}`,
      },
      404,
    );
  });
}

test.describe('dashboard webhooks console api wiring', () => {
  test('create endpoint posts eventCategories and never legacy subscriptions', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    const createBodies: Record<string, unknown>[] = [];
    const endpoints: Record<string, unknown>[] = [];

    const org = {
      id: 'org_dash_webhooks',
      name: 'Dashboard Webhooks Org',
      slug: 'dashboard-webhooks-org',
      status: 'ACTIVE',
      createdAt: iso('2026-01-01T00:00:00.000Z'),
      updatedAt: iso('2026-01-01T00:00:00.000Z'),
    };
    const project = {
      id: 'proj_dash_webhooks',
      name: 'Webhooks Project',
      slug: 'webhooks-project',
      status: 'ACTIVE',
      environmentCount: 1,
      createdAt: iso('2026-01-01T00:00:00.000Z'),
      updatedAt: iso('2026-01-01T00:00:00.000Z'),
    };
    const environment = {
      id: 'env_dash_webhooks',
      projectId: project.id,
      key: 'prod',
      name: 'Production',
      status: 'ACTIVE',
      createdAt: iso('2026-01-01T00:00:00.000Z'),
      updatedAt: iso('2026-01-01T00:00:00.000Z'),
    };

    await routeWorkspaceScaffold(page, consoleOrigin, {
      userId: 'user_dash_webhooks',
      org,
      project,
      environment,
      handleWebhookRequest: async (route, pathname, method, url) => {
        if (method === 'GET' && pathname === '/console/webhooks') {
          await fulfillJson(route, { ok: true, endpoints });
          return true;
        }

        if (method === 'POST' && pathname === '/console/webhooks') {
          const body = parseJsonBody(route.request().postData());
          createBodies.push(body);
          const eventCategories = Array.isArray(body.eventCategories)
            ? [...body.eventCategories]
            : [];
          const endpoint = {
            id: 'wh_ep_dash_created',
            orgId: String(org.id || ''),
            url: String(body.url || ''),
            eventCategories,
            status: 'ACTIVE',
            secretVersion: 1,
            secretPreview: 'whsec_...cdef',
            createdAt: iso('2026-03-10T12:00:00.000Z'),
            updatedAt: iso('2026-03-10T12:00:00.000Z'),
          };
          endpoints.splice(0, endpoints.length, endpoint);
          await fulfillJson(route, { ok: true, endpoint }, 201);
          return true;
        }

        if (
          method === 'GET' &&
          pathname === '/console/webhooks/wh_ep_dash_created/deliveries' &&
          url.searchParams.get('limit') === '100'
        ) {
          await fulfillJson(route, { ok: true, deliveries: [], nextCursor: null });
          return true;
        }

        return false;
      },
    });

    await page.goto('/dashboard/webhooks');
    await expect(page.locator('main[aria-label="Dashboard workspace"]')).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Create webhook endpoint' })).toBeVisible();

    await page
      .getByPlaceholder('https://example.com/webhooks/tatchi')
      .fill('https://example.com/webhooks/dashboard-test');
    await page.getByLabel('Event categories dropdown').selectOption('wallet');
    await page.getByRole('button', { name: 'Create endpoint' }).click();

    await expect.poll(() => createBodies.length).toBe(1);
    expect(createBodies[0]?.url).toBe('https://example.com/webhooks/dashboard-test');
    expect(createBodies[0]?.eventCategories).toEqual(['billing', 'wallet']);
    expect(Object.prototype.hasOwnProperty.call(createBodies[0] || {}, 'subscriptions')).toBe(
      false,
    );

    await expect(page.getByLabel('Webhook endpoints table')).toContainText(
      'https://example.com/webhooks/dashboard-test',
    );
    await expect(page.getByLabel('Webhook endpoints table')).toContainText('billing, wallet');
  });
});

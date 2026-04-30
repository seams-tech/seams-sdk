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
  test('create endpoint posts eventCategories', async ({ page, baseURL }) => {
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
    await expect(page.getByRole('button', { name: 'Create Webhook' })).toBeVisible();

    await page.getByRole('button', { name: 'Create Webhook' }).click();
    await page
      .getByPlaceholder('https://example.com/webhooks/seams')
      .fill('https://example.com/webhooks/dashboard-test');
    await page.getByLabel('Event categories dropdown').selectOption('wallet');
    await page.locator('button').filter({ hasText: 'Create endpoint' }).click();

    await expect.poll(() => createBodies.length).toBe(1);
    expect(createBodies[0]?.url).toBe('https://example.com/webhooks/dashboard-test');
    expect(createBodies[0]?.eventCategories).toEqual(['billing', 'wallet']);

    await expect(page.getByLabel('Webhook endpoints table')).toContainText(
      'https://example.com/webhooks/dashboard-test',
    );
    await expect(page.getByLabel('Webhook endpoints table')).toContainText('billing, wallet');
  });

  test('query params select the requested endpoint and page the linked delivery into view', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    const deliveryRequests: string[] = [];
    const endpoints = [
      {
        id: 'wh_ep_dash_primary',
        orgId: 'org_dash_webhooks',
        url: 'https://example.com/webhooks/primary',
        eventCategories: ['billing'],
        status: 'ACTIVE',
        secretVersion: 1,
        secretPreview: 'whsec_...1111',
        createdAt: iso('2026-03-01T00:00:00.000Z'),
        updatedAt: iso('2026-03-02T00:00:00.000Z'),
      },
      {
        id: 'wh_ep_dash_secondary',
        orgId: 'org_dash_webhooks',
        url: 'https://example.com/webhooks/secondary',
        eventCategories: ['billing', 'policy'],
        status: 'ACTIVE',
        secretVersion: 2,
        secretPreview: 'whsec_...2222',
        createdAt: iso('2026-03-03T00:00:00.000Z'),
        updatedAt: iso('2026-03-04T00:00:00.000Z'),
      },
    ];
    const deliveriesByEndpoint: Record<string, Record<string, unknown>[]> = {
      wh_ep_dash_primary: [
        {
          id: 'dlv_primary_1',
          orgId: 'org_dash_webhooks',
          endpointId: 'wh_ep_dash_primary',
          eventId: 'evt_primary_1',
          eventType: 'billing.invoice.generated',
          status: 'DELIVERED',
          attemptCount: 1,
          replayCount: 0,
          responseStatus: 200,
          errorMessage: '',
          deliveredAt: iso('2026-03-04T12:00:00.000Z'),
          lastAttemptAt: iso('2026-03-04T12:00:00.000Z'),
          createdAt: iso('2026-03-04T11:59:00.000Z'),
          updatedAt: iso('2026-03-04T12:00:00.000Z'),
        },
      ],
      wh_ep_dash_secondary: Array.from({ length: 14 }, (_, index) => ({
        id: `dlv_secondary_${index + 1}`,
        orgId: 'org_dash_webhooks',
        endpointId: 'wh_ep_dash_secondary',
        eventId: `evt_secondary_${index + 1}`,
        eventType: index % 2 === 0 ? 'billing.credit_purchase.settled' : 'policy.publish',
        status: 'DELIVERED',
        attemptCount: 1,
        replayCount: 0,
        responseStatus: 200,
        errorMessage: '',
        deliveredAt: iso(`2026-03-${String(5 + index).padStart(2, '0')}T12:00:00.000Z`),
        lastAttemptAt: iso(`2026-03-${String(5 + index).padStart(2, '0')}T12:00:00.000Z`),
        createdAt: iso(`2026-03-${String(5 + index).padStart(2, '0')}T11:59:00.000Z`),
        updatedAt: iso(`2026-03-${String(5 + index).padStart(2, '0')}T12:00:00.000Z`),
      })),
    };

    await routeWorkspaceScaffold(page, consoleOrigin, {
      userId: 'user_dash_webhooks',
      org: {
        id: 'org_dash_webhooks',
        name: 'Dashboard Webhooks Org',
        slug: 'dashboard-webhooks-org',
        status: 'ACTIVE',
        createdAt: iso('2026-01-01T00:00:00.000Z'),
        updatedAt: iso('2026-01-01T00:00:00.000Z'),
      },
      project: {
        id: 'proj_dash_webhooks',
        name: 'Webhooks Project',
        slug: 'webhooks-project',
        status: 'ACTIVE',
        environmentCount: 1,
        createdAt: iso('2026-01-01T00:00:00.000Z'),
        updatedAt: iso('2026-01-01T00:00:00.000Z'),
      },
      environment: {
        id: 'env_dash_webhooks',
        projectId: 'proj_dash_webhooks',
        key: 'prod',
        name: 'Production',
        status: 'ACTIVE',
        createdAt: iso('2026-01-01T00:00:00.000Z'),
        updatedAt: iso('2026-01-01T00:00:00.000Z'),
      },
      handleWebhookRequest: async (route, pathname, method, url) => {
        if (method === 'GET' && pathname === '/console/webhooks') {
          await fulfillJson(route, { ok: true, endpoints });
          return true;
        }

        const deliveriesMatch = pathname.match(/^\/console\/webhooks\/([^/]+)\/deliveries$/);
        if (method === 'GET' && deliveriesMatch) {
          const endpointId = decodeURIComponent(String(deliveriesMatch[1] || ''));
          if (url.searchParams.get('limit') === '100') {
            deliveryRequests.push(endpointId);
            await fulfillJson(route, {
              ok: true,
              deliveries: deliveriesByEndpoint[endpointId] || [],
              nextCursor: null,
            });
            return true;
          }
        }

        return false;
      },
    });

    await page.goto(
      '/dashboard/webhooks?endpointId=wh_ep_dash_secondary&deliveryId=dlv_secondary_14',
    );
    await expect(page.locator('main[aria-label="Dashboard workspace"]')).toBeVisible();
    await expect.poll(() => deliveryRequests.join(',')).toContain('wh_ep_dash_secondary');
    await expect(page.getByLabel('Webhook deliveries table')).toContainText('dlv_secondary_14');
    await expect(page.getByLabel('Webhook deliveries table')).toContainText('Opened from audit');
    await expect(page.getByLabel('Webhook deliveries table')).not.toContainText('dlv_primary_1');
  });
});

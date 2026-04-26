import { expect, test } from '@playwright/test';
import { getNearSpendCapChainId } from '@shared/console/gasSponsorshipSpendCapTargets';

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

function isPlainObject(raw: unknown): raw is Record<string, unknown> {
  return Boolean(raw) && typeof raw === 'object' && !Array.isArray(raw);
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
  test('dashboard root routes to login when console session is unavailable', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;

    await page.route(`${consoleOrigin}/console/**`, async (route) => {
      const pathname = new URL(route.request().url()).pathname;
      if (pathname === '/console/session') {
        await route.fulfill({
          status: 503,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: false,
            code: 'session_unavailable',
            message: 'Console session unavailable in test stub',
          }),
        });
        return;
      }
      await route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: JSON.stringify({
          ok: false,
          code: 'service_unavailable',
        }),
      });
    });

    await page.goto('/dashboard');

    await expect.poll(() => new URL(page.url()).pathname).toBe('/dashboard/login');
    await expect(page.locator('h1')).toHaveText(/sign in with google/i);
    await expect(page.locator('main[aria-label="Dashboard login page"]')).toBeVisible();
  });

  test('protected dashboard route redirects to login when console session is unavailable', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;

    await page.route(`${consoleOrigin}/console/**`, async (route) => {
      const pathname = new URL(route.request().url()).pathname;
      if (pathname === '/console/session') {
        await route.fulfill({
          status: 401,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: false,
            code: 'unauthorized',
            message: 'No valid app session',
          }),
        });
        return;
      }
      await route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: JSON.stringify({
          ok: false,
          code: 'service_unavailable',
        }),
      });
    });

    await page.goto('/dashboard/wallets-list');
    await expect.poll(() => new URL(page.url()).pathname).toBe('/dashboard/login');
    await expect(page.locator('h1')).toHaveText(/sign in with google/i);
    await expect(page.locator('main[aria-label="Dashboard login page"]')).toBeVisible();
  });

  test('dashboard root preserves route and shows forbidden state on 403 session response', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;

    await page.route(`${consoleOrigin}/console/**`, async (route) => {
      const pathname = new URL(route.request().url()).pathname;
      if (pathname === '/console/session') {
        await route.fulfill({
          status: 403,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: false,
            code: 'forbidden',
            message: 'No console roles assigned',
          }),
        });
        return;
      }
      await route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: JSON.stringify({
          ok: false,
          code: 'service_unavailable',
        }),
      });
    });

    await page.goto('/dashboard');

    await expect.poll(() => new URL(page.url()).pathname).toBe('/dashboard');
    await expect(page.locator('main[aria-label="Dashboard workspace"]')).toBeVisible();
    await expect(page.locator('p[role="alert"]')).toContainText(
      /access to this dashboard is forbidden/i,
    );
    await expect(page.locator('h1')).not.toHaveText(/sign in with google/i);
  });

  test('login page remains available when console session check fails at network layer', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;

    await page.route(`${consoleOrigin}/console/session`, async (route) => {
      await route.abort('failed');
    });

    await page.goto('/dashboard/login');
    await expect(page.locator('h1')).toHaveText(/sign in with google/i);
    await expect(page.locator('main[aria-label="Dashboard login page"]')).toBeVisible();
  });

  test('dashboard login exchanges mocked Google id token and redirects into dashboard flow', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    let sessionEstablished = false;
    let sessionExchangeCalls = 0;
    let exchangeToken = '';
    let exchangeType = '';
    let exchangeProvider = '';
    let exchangeSessionKind = '';
    let optionsRequestUsedLegacyAuthHeaders = false;
    let exchangeRequestUsedLegacyAuthHeaders = false;

    const hasLegacyDashboardAuthHeaders = (headers: Record<string, string>): boolean => {
      const entries = Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v] as const);
      for (const [key, value] of entries) {
        if (key.startsWith('x-console-')) return true;
        if (key === 'authorization' && String(value || '').trim()) return true;
      }
      return false;
    };

    await page.addInitScript(() => {
      (window as any).__googleInitConfig = null;
      (window as any).google = {
        accounts: {
          id: {
            initialize(config: any) {
              (window as any).__googleInitConfig = config;
            },
            prompt(notification: any) {
              const config = (window as any).__googleInitConfig;
              if (config && typeof config.callback === 'function') {
                config.callback({ credential: 'mock-google-id-token' });
              }
              if (typeof notification === 'function') {
                notification({
                  isNotDisplayed: () => false,
                  isSkippedMoment: () => false,
                  getNotDisplayedReason: () => '',
                  getSkippedReason: () => '',
                });
              }
            },
          },
        },
      };
    });

    await page.route(`${consoleOrigin}/auth/google/options`, async (route) => {
      optionsRequestUsedLegacyAuthHeaders = hasLegacyDashboardAuthHeaders(
        route.request().headers(),
      );
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          ok: true,
          configured: true,
          clientId: 'playwright-google-client-id',
        }),
      });
    });

    await page.route(`${consoleOrigin}/session/exchange`, async (route) => {
      const req = route.request();
      if (req.method().toUpperCase() !== 'POST') {
        await route.fulfill({ status: 405, body: '' });
        return;
      }
      exchangeRequestUsedLegacyAuthHeaders = hasLegacyDashboardAuthHeaders(req.headers());
      const body = parseJsonBody(req.postData());
      const exchange = (body.exchange || {}) as Record<string, unknown>;
      exchangeToken = String(exchange.token || '').trim();
      exchangeType = String(exchange.type || '').trim();
      exchangeProvider = String(exchange.provider || '').trim();
      exchangeSessionKind = String(body.session_kind || '').trim();
      sessionExchangeCalls += 1;
      sessionEstablished = true;
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          ok: true,
          session: {
            kind: 'app_session_v1',
            sub: 'google:dashboard-login-test',
            appSessionVersion: 'v1',
          },
        }),
      });
    });

    await page.route(`${consoleOrigin}/console/**`, async (route) => {
      const req = route.request();
      const method = req.method().toUpperCase();
      const pathname = new URL(req.url()).pathname;

      if (pathname === '/console/session') {
        if (!sessionEstablished) {
          await route.fulfill({
            status: 401,
            contentType: 'application/json',
            body: JSON.stringify({
              ok: false,
              code: 'unauthorized',
              message: 'No valid app session',
            }),
          });
          return;
        }
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            claims: {
              userId: 'google:dashboard-login-test',
              orgId: 'org-dashboard-login-test',
              roles: ['owner', 'admin'],
            },
          }),
        });
        return;
      }

      if (pathname === '/console/onboarding/state' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            state: {
              orgId: 'org-dashboard-login-test',
              organization: null,
              activeProjectCount: 0,
              activeEnvironmentCount: 0,
              activeApiKeyCount: 0,
              hasOrganization: false,
              hasProject: false,
              hasEnvironment: false,
              hasApiKey: false,
              accountReady: true,
              organizationReady: false,
              billingReady: false,
              projectReady: false,
              onboardingComplete: false,
              currentStep: 'organization',
              complete: false,
              selectedProjectId: null,
              selectedEnvironmentId: null,
            },
          }),
        });
        return;
      }

      if (pathname === '/console/org' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            org: {
              id: 'org-dashboard-login-test',
              name: 'Dashboard Login Test Org',
              slug: 'dashboard-login-test-org',
              status: 'ACTIVE',
              createdAt: iso('2026-03-01T00:00:00.000Z'),
              updatedAt: iso('2026-03-01T00:00:00.000Z'),
            },
          }),
        });
        return;
      }

      if (pathname === '/console/projects' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            projects: [],
          }),
        });
        return;
      }

      if (pathname === '/console/environments' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            environments: [],
          }),
        });
        return;
      }

      await route.fulfill({
        status: 404,
        contentType: 'application/json',
        body: JSON.stringify({
          ok: false,
          code: 'not_stubbed',
          path: pathname,
          method,
        }),
      });
    });

    await page.goto('/dashboard/login');
    await expect(page.locator('h1')).toHaveText(/sign in with google/i);

    const continueButton = page.getByRole('button', { name: /continue with google/i });
    await expect(continueButton).toBeEnabled();
    await continueButton.click();

    await expect.poll(() => sessionExchangeCalls).toBe(1);
    await expect.poll(() => exchangeToken).toBe('mock-google-id-token');
    await expect(exchangeType).toBe('oidc_jwt');
    await expect(exchangeProvider).toBe('google');
    await expect(exchangeSessionKind).toBe('cookie');
    await expect(optionsRequestUsedLegacyAuthHeaders).toBe(false);
    await expect(exchangeRequestUsedLegacyAuthHeaders).toBe(false);
    await expect.poll(() => new URL(page.url()).pathname).toBe('/dashboard/onboarding');
  });

  test('dashboard root redirects to overview when organization already exists', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;

    await page.route(`${consoleOrigin}/console/**`, async (route) => {
      const req = route.request();
      const method = req.method().toUpperCase();
      const pathname = new URL(req.url()).pathname;

      if (pathname === '/console/session') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            claims: {
              userId: 'user-dashboard-entry-existing-org',
              orgId: 'org-dashboard-entry-existing-org',
              roles: ['admin'],
              projectId: null,
              environmentId: null,
            },
          }),
        });
        return;
      }

      if (pathname === '/console/onboarding/state' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            state: {
              orgId: 'org-dashboard-entry-existing-org',
              organization: {
                id: 'org-dashboard-entry-existing-org',
                name: 'Dashboard Entry Existing Org',
                slug: 'dashboard-entry-existing-org',
                status: 'ACTIVE',
              },
              activeProjectCount: 0,
              activeEnvironmentCount: 0,
              activeApiKeyCount: 0,
              hasOrganization: true,
              hasProject: false,
              hasEnvironment: false,
              hasApiKey: false,
              accountReady: true,
              organizationReady: true,
              billingReady: false,
              projectReady: false,
              onboardingComplete: false,
              currentStep: 'project',
              complete: false,
              selectedProjectId: null,
              selectedEnvironmentId: null,
            },
          }),
        });
        return;
      }

      if (pathname === '/console/org' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            org: {
              id: 'org-dashboard-entry-existing-org',
              name: 'Dashboard Entry Existing Org',
              slug: 'dashboard-entry-existing-org',
              status: 'ACTIVE',
              createdAt: iso('2026-03-11T00:00:00.000Z'),
              updatedAt: iso('2026-03-11T00:00:00.000Z'),
            },
          }),
        });
        return;
      }

      if (pathname === '/console/projects' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, projects: [] }),
        });
        return;
      }

      if (pathname === '/console/environments' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, environments: [] }),
        });
        return;
      }

      if (pathname === '/console/ops-cockpit/summary' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            summary: {
              generatedAt: iso('2026-03-11T00:00:00.000Z'),
              approvals: { status: { state: 'ok' }, pendingCount: 0, pending: [] },
              billing: { status: { state: 'ok' }, failedInvoiceCount: 0, failedInvoices: [] },
              webhooks: {
                status: { state: 'ok' },
                endpointCount: 0,
                scannedEndpointCount: 0,
                deadLetterCount: 0,
                deadLetters: [],
              },
              auditExports: { status: { state: 'ok' }, queuedExportCount: 0, queuedExports: [] },
              enterpriseIsolation: {
                status: { state: 'ok' },
                activeRequestCount: 0,
                activeRequests: [],
              },
              onboardingTelemetry: {
                status: { state: 'ok' },
                windowMinutes: 60,
                alertCount: 0,
                alerts: [],
              },
            },
          }),
        });
        return;
      }

      await route.fulfill({
        status: 404,
        contentType: 'application/json',
        body: JSON.stringify({
          ok: false,
          code: 'not_stubbed',
          path: pathname,
          method,
        }),
      });
    });

    await page.goto('/dashboard');
    await expect.poll(() => new URL(page.url()).pathname).toBe('/dashboard/overview');
    await expect(page.locator('#dashboard-main-title')).toHaveText(/overview/i);
  });

  test('dashboard root redirects to onboarding when user has no existing organization', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    let onboardingStateCalls = 0;
    let projectCalls = 0;

    await page.route(`${consoleOrigin}/console/**`, async (route) => {
      const req = route.request();
      const method = req.method().toUpperCase();
      const pathname = new URL(req.url()).pathname;

      if (pathname === '/console/session') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            claims: {
              userId: 'user-dashboard-entry-orgless',
              orgId: '',
              roles: [],
              email: 'orgless@example.com',
              name: 'Orgless User',
            },
          }),
        });
        return;
      }

      if (pathname === '/console/onboarding/state' && method === 'GET') {
        onboardingStateCalls += 1;
        await route.fulfill({
          status: 500,
          contentType: 'application/json',
          body: JSON.stringify({ ok: false, code: 'should_not_be_called' }),
        });
        return;
      }

      if (pathname === '/console/account/organizations' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, organizations: [] }),
        });
        return;
      }

      if (pathname === '/console/projects' && method === 'GET') {
        projectCalls += 1;
        await route.fulfill({
          status: 500,
          contentType: 'application/json',
          body: JSON.stringify({ ok: false, code: 'should_not_be_called' }),
        });
        return;
      }

      await route.fulfill({
        status: 404,
        contentType: 'application/json',
        body: JSON.stringify({
          ok: false,
          code: 'not_stubbed',
          path: pathname,
          method,
        }),
      });
    });

    await page.goto('/dashboard');
    await expect.poll(() => new URL(page.url()).pathname).toBe('/dashboard/onboarding');
    await expect.poll(() => onboardingStateCalls).toBe(0);
    await expect.poll(() => projectCalls).toBe(0);
    await expect(page.locator('#dashboard-main-title')).toHaveText(/onboarding/i);
  });

  test('dashboard root recovers organization context and redirects to overview when account already has organizations', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    let sessionClaims: Record<string, unknown> = {
      userId: 'user-dashboard-entry-recover-org',
      orgId: '',
      roles: [],
      email: 'recover@example.com',
      name: 'Recover User',
    };
    const switchBodies: Array<{ orgId: string; body: Record<string, unknown> }> = [];

    await page.route(`${consoleOrigin}/console/**`, async (route) => {
      const req = route.request();
      const method = req.method().toUpperCase();
      const pathname = new URL(req.url()).pathname;

      if (pathname === '/console/session') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            claims: sessionClaims,
          }),
        });
        return;
      }

      if (pathname === '/console/account/organizations' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            organizations: [
              {
                id: 'org_watchbook',
                name: 'Watchbook',
                slug: 'watchbook',
                status: 'ACTIVE',
                createdAt: iso('2026-03-10T00:00:00.000Z'),
                updatedAt: iso('2026-03-11T00:00:00.000Z'),
                isCurrentOrg: false,
                actorRoles: ['owner', 'admin'],
                actorIsOwner: true,
                actorIsAdmin: true,
                onboardingComplete: true,
                selectedProjectId: 'proj_watchbook',
                selectedProjectName: 'Watchbook Core',
                selectedEnvironmentId: 'env_watchbook',
                selectedEnvironmentName: 'Production',
                adminCandidates: [],
              },
              {
                id: 'org_pokopia',
                name: 'Pokopia Labs',
                slug: 'pokopia-labs',
                status: 'ACTIVE',
                createdAt: iso('2026-03-08T00:00:00.000Z'),
                updatedAt: iso('2026-03-09T00:00:00.000Z'),
                isCurrentOrg: false,
                actorRoles: ['owner', 'admin'],
                actorIsOwner: true,
                actorIsAdmin: true,
                onboardingComplete: true,
                selectedProjectId: 'proj_pokopia',
                selectedProjectName: 'Pokopia Core',
                selectedEnvironmentId: 'env_pokopia',
                selectedEnvironmentName: 'Production',
                adminCandidates: [],
              },
            ],
          }),
        });
        return;
      }

      const accountOrgMatch = pathname.match(
        /^\/console\/account\/organizations\/([^/]+?)\/switch-context$/,
      );
      const orgId = accountOrgMatch?.[1] ? decodeURIComponent(accountOrgMatch[1]) : '';
      if (orgId && method === 'POST') {
        const body = parseJsonBody(req.postData());
        switchBodies.push({ orgId, body });
        sessionClaims = {
          userId: 'user-dashboard-entry-recover-org',
          orgId,
          roles: ['owner', 'admin'],
          projectId: 'proj_watchbook',
          environmentId: 'env_watchbook',
          email: 'recover@example.com',
          name: 'Recover User',
        };
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            context: {
              orgId,
              projectId: 'proj_watchbook',
              environmentId: 'env_watchbook',
              actorRoles: ['owner', 'admin'],
              onboardingComplete: true,
            },
          }),
        });
        return;
      }

      if (pathname === '/console/onboarding/state' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            state: {
              orgId: 'org_watchbook',
              organization: {
                id: 'org_watchbook',
                name: 'Watchbook',
                slug: 'watchbook',
                status: 'ACTIVE',
              },
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
              selectedProjectId: 'proj_watchbook',
              selectedEnvironmentId: 'env_watchbook',
            },
          }),
        });
        return;
      }

      if (pathname === '/console/org' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            org: {
              id: 'org_watchbook',
              name: 'Watchbook',
              slug: 'watchbook',
              status: 'ACTIVE',
              createdAt: iso('2026-03-10T00:00:00.000Z'),
              updatedAt: iso('2026-03-11T00:00:00.000Z'),
            },
          }),
        });
        return;
      }

      if (pathname === '/console/projects' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            projects: [
              {
                id: 'proj_watchbook',
                name: 'Watchbook Core',
                slug: 'watchbook-core',
                status: 'ACTIVE',
                environmentCount: 1,
                createdAt: iso('2026-03-10T00:00:00.000Z'),
                updatedAt: iso('2026-03-11T00:00:00.000Z'),
              },
            ],
          }),
        });
        return;
      }

      if (pathname === '/console/environments' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            environments: [
              {
                id: 'env_watchbook',
                projectId: 'proj_watchbook',
                key: 'prod',
                name: 'Production',
                status: 'ACTIVE',
                createdAt: iso('2026-03-10T00:00:00.000Z'),
                updatedAt: iso('2026-03-11T00:00:00.000Z'),
              },
            ],
          }),
        });
        return;
      }

      if (pathname === '/console/ops-cockpit/summary' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            summary: {
              generatedAt: iso('2026-03-11T00:00:00.000Z'),
              approvals: { status: { state: 'ok' }, pendingCount: 0, pending: [] },
              billing: { status: { state: 'ok' }, failedInvoiceCount: 0, failedInvoices: [] },
              webhooks: {
                status: { state: 'ok' },
                endpointCount: 0,
                scannedEndpointCount: 0,
                deadLetterCount: 0,
                deadLetters: [],
              },
              auditExports: { status: { state: 'ok' }, queuedExportCount: 0, queuedExports: [] },
              enterpriseIsolation: {
                status: { state: 'ok' },
                activeRequestCount: 0,
                activeRequests: [],
              },
              onboardingTelemetry: {
                status: { state: 'ok' },
                windowMinutes: 60,
                alertCount: 0,
                alerts: [],
              },
            },
          }),
        });
        return;
      }

      await route.fulfill({
        status: 404,
        contentType: 'application/json',
        body: JSON.stringify({
          ok: false,
          code: 'not_stubbed',
          path: pathname,
          method,
        }),
      });
    });

    await page.goto('/dashboard');
    await expect.poll(() => switchBodies.length).toBe(1);
    expect(switchBodies[0]).toMatchObject({
      orgId: 'org_watchbook',
      body: {},
    });
    await expect.poll(() => new URL(page.url()).pathname).toBe('/dashboard/overview');
    await expect(page.locator('#dashboard-main-title')).toHaveText(/overview/i);
  });

  test('dashboard root redirects to onboarding when org is still a default placeholder identity', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;

    await page.route(`${consoleOrigin}/console/**`, async (route) => {
      const req = route.request();
      const method = req.method().toUpperCase();
      const pathname = new URL(req.url()).pathname;

      if (pathname === '/console/session') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            claims: {
              userId: 'user-dashboard-entry-placeholder-org',
              orgId: 'org_mmm2dbnq_lrhgv',
              roles: ['admin'],
              projectId: null,
              environmentId: null,
            },
          }),
        });
        return;
      }

      if (pathname === '/console/onboarding/state' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            state: {
              orgId: 'org_mmm2dbnq_lrhgv',
              organization: {
                id: 'org_mmm2dbnq_lrhgv',
                name: 'org mmm2dbnq lrhgv',
                slug: 'org-mmm2dbnq-lrhgv',
                status: 'ACTIVE',
              },
              activeProjectCount: 0,
              activeEnvironmentCount: 0,
              activeApiKeyCount: 0,
              hasOrganization: true,
              hasProject: false,
              hasEnvironment: false,
              hasApiKey: false,
              accountReady: true,
              organizationReady: true,
              billingReady: false,
              projectReady: false,
              onboardingComplete: false,
              currentStep: 'project',
              complete: false,
              selectedProjectId: null,
              selectedEnvironmentId: null,
            },
          }),
        });
        return;
      }

      if (pathname === '/console/org' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            org: {
              id: 'org_mmm2dbnq_lrhgv',
              name: 'org mmm2dbnq lrhgv',
              slug: 'org-mmm2dbnq-lrhgv',
              status: 'ACTIVE',
              createdAt: iso('2026-03-11T00:00:00.000Z'),
              updatedAt: iso('2026-03-11T00:00:00.000Z'),
            },
          }),
        });
        return;
      }

      if (pathname === '/console/projects' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, projects: [] }),
        });
        return;
      }

      if (pathname === '/console/environments' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, environments: [] }),
        });
        return;
      }

      await route.fulfill({
        status: 404,
        contentType: 'application/json',
        body: JSON.stringify({
          ok: false,
          code: 'not_stubbed',
          path: pathname,
          method,
        }),
      });
    });

    await page.goto('/dashboard');
    await expect.poll(() => new URL(page.url()).pathname).toBe('/dashboard/onboarding');
    await expect(page.locator('#dashboard-main-title')).toHaveText(/onboarding/i);
  });

  test('onboarding hides fallback org label and lets user choose organization name', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    let lastOrganizationBody: Record<string, unknown> | null = null;
    let onboardingState: Record<string, unknown> = {
      orgId: 'org_mmm2dbnq_lrhgv',
      organization: {
        id: 'org_mmm2dbnq_lrhgv',
        name: 'org mmm2dbnq lrhgv',
        slug: 'org-mmm2dbnq-lrhgv',
        status: 'ACTIVE',
      },
      activeProjectCount: 0,
      activeEnvironmentCount: 0,
      activeApiKeyCount: 0,
      hasOrganization: true,
      hasProject: false,
      hasEnvironment: false,
      hasApiKey: false,
      accountReady: true,
      organizationReady: true,
      billingReady: false,
      projectReady: false,
      onboardingComplete: false,
      currentStep: 'project',
      complete: false,
      selectedProjectId: null,
      selectedEnvironmentId: null,
    };

    await page.route(`${consoleOrigin}/console/**`, async (route) => {
      const req = route.request();
      const method = req.method().toUpperCase();
      const pathname = new URL(req.url()).pathname;

      if (pathname === '/console/session') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            claims: {
              userId: 'user_onboarding_label_hidden',
              orgId: 'org_mmm2dbnq_lrhgv',
              roles: ['admin'],
              projectId: null,
              environmentId: null,
            },
          }),
        });
        return;
      }

      if (pathname === '/console/onboarding/state' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, state: onboardingState }),
        });
        return;
      }

      if (pathname === '/console/onboarding/organization' && method === 'POST') {
        lastOrganizationBody = parseJsonBody(req.postData());
        onboardingState = {
          ...onboardingState,
          organization: {
            id: 'org_mmm2dbnq_lrhgv',
            name: 'Acme Org',
            slug: 'acme-org',
            status: 'ACTIVE',
          },
          currentStep: 'project',
        };
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            result: {
              organization: onboardingState.organization,
              created: {
                organization: false,
                owner: false,
              },
              state: onboardingState,
            },
          }),
        });
        return;
      }

      if (pathname === '/console/org' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            org: {
              id: 'org_mmm2dbnq_lrhgv',
              name: 'org mmm2dbnq lrhgv',
              slug: 'org-mmm2dbnq-lrhgv',
              status: 'ACTIVE',
              createdAt: iso('2026-03-11T00:00:00.000Z'),
              updatedAt: iso('2026-03-11T00:00:00.000Z'),
            },
          }),
        });
        return;
      }

      if (pathname === '/console/projects' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, projects: [] }),
        });
        return;
      }

      if (pathname === '/console/environments' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, environments: [] }),
        });
        return;
      }

      await route.fulfill({
        status: 404,
        contentType: 'application/json',
        body: JSON.stringify({
          ok: false,
          code: 'not_stubbed',
          path: pathname,
          method,
        }),
      });
    });

    await page.goto('/dashboard/onboarding');
    await expect(page.locator('.dashboard-topbar__focused-value')).toHaveText('');

    const onboardingForm = page
      .locator('section[aria-label="Onboarding form"]:has(h2:has-text("Name your organization"))')
      .last();
    await expect(onboardingForm).toBeVisible();
    const organizationNameInput = onboardingForm.locator('input[placeholder="Acme Wallets"]');
    await expect(organizationNameInput).toHaveValue('');
    await organizationNameInput.fill('Acme Org');
    await onboardingForm.locator('button:has-text("Continue to project setup")').click();

    await expect
      .poll(() =>
        String((lastOrganizationBody?.org as Record<string, unknown> | undefined)?.name || ''),
      )
      .toBe('Acme Org');
  });

  test('dashboard sign out revokes session, clears UI state, and routes to login', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    let sessionRevoked = false;
    let sessionRevokeCalls = 0;

    await page.addInitScript(() => {
      window.localStorage.setItem(
        'tatchi-dashboard-ui-state-v1',
        JSON.stringify({
          isSidebarExpanded: true,
          expandedGroups: {
            overview: true,
            administration: true,
            operationsSecurity: true,
            integrations: true,
            billing: true,
          },
          selectedContext: {
            organization: 'org-signout-test',
            project: 'proj-signout-test',
            environment: 'env-signout-test',
            accountSettings: 'Account Settings',
          },
        }),
      );
    });

    await page.route(`${consoleOrigin}/console/**`, async (route) => {
      const req = route.request();
      const method = req.method().toUpperCase();
      const pathname = new URL(req.url()).pathname;

      if (pathname === '/console/session') {
        if (sessionRevoked) {
          await route.fulfill({
            status: 401,
            contentType: 'application/json',
            body: JSON.stringify({
              ok: false,
              code: 'unauthorized',
              message: 'No valid app session',
            }),
          });
          return;
        }
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            claims: {
              userId: 'user-signout-test',
              orgId: 'org-signout-test',
              roles: ['admin'],
              projectId: 'proj-signout-test',
              environmentId: 'env-signout-test',
            },
          }),
        });
        return;
      }

      if (pathname === '/console/onboarding/state' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            state: {
              orgId: 'org-signout-test',
              organization: null,
              activeProjectCount: 0,
              activeEnvironmentCount: 0,
              activeApiKeyCount: 0,
              hasOrganization: false,
              hasProject: false,
              hasEnvironment: false,
              hasApiKey: false,
              accountReady: true,
              organizationReady: false,
              billingReady: false,
              projectReady: false,
              onboardingComplete: false,
              currentStep: 'organization',
              complete: false,
              selectedProjectId: null,
              selectedEnvironmentId: null,
            },
          }),
        });
        return;
      }

      await route.fulfill({
        status: 404,
        contentType: 'application/json',
        body: JSON.stringify({
          ok: false,
          code: 'not_stubbed',
          path: pathname,
          method,
        }),
      });
    });

    await page.route(`${consoleOrigin}/session/revoke`, async (route) => {
      sessionRevokeCalls += 1;
      sessionRevoked = true;
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ ok: true, revoked: true, userId: 'user-signout-test' }),
      });
    });

    await page.goto('/dashboard/onboarding');
    await expect(page.locator('main[aria-label="Dashboard workspace"]')).toBeVisible();

    await page.getByRole('button', { name: /account.*settings/i }).click();
    await page.getByRole('menuitem', { name: /sign out/i }).click();

    await expect.poll(() => sessionRevokeCalls).toBe(1);
    await expect.poll(() => new URL(page.url()).pathname).toBe('/dashboard/login');
    await expect(page.locator('h1')).toHaveText(/sign in with google/i);
    await expect
      .poll(() => page.evaluate(() => window.localStorage.getItem('tatchi-dashboard-ui-state-v1')))
      .toBeNull();
  });

  test('account settings routes to the dedicated account settings page', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    const context = buildMockDashboardContext();
    const accountOrganizations = [
      {
        id: 'org_dash_console_pages',
        name: 'Dashboard Console Pages Org',
        slug: 'dashboard-console-pages-org',
        status: 'ACTIVE',
        createdAt: iso('2026-01-01T00:00:00.000Z'),
        updatedAt: iso('2026-01-02T00:00:00.000Z'),
        isCurrentOrg: true,
        actorRoles: ['admin'],
        actorIsOwner: false,
        actorIsAdmin: true,
        onboardingComplete: true,
        selectedProjectId: 'proj_active',
        selectedProjectName: 'Active Project',
        selectedEnvironmentId: 'env_active',
        selectedEnvironmentName: 'Production',
        adminCandidates: [
          {
            memberId: 'member_admin',
            userId: 'user_admin',
            email: 'admin@example.com',
            displayName: 'Admin User',
            isOwner: false,
          },
        ],
      },
    ];

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

      if (pathname === '/console/onboarding/state' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            state: {
              orgId: 'org_dash_console_pages',
              organization: context.org,
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
              selectedProjectId: 'proj_active',
              selectedEnvironmentId: 'env_active',
            },
          }),
        });
        return;
      }

      if (pathname === '/console/org' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, org: context.org }),
        });
        return;
      }

      if (pathname === '/console/projects' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, projects: [context.activeProject] }),
        });
        return;
      }

      if (pathname === '/console/environments' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, environments: [context.activeEnvironment] }),
        });
        return;
      }

      if (pathname === '/console/account/profile' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            profile: {
              userId: 'user_dash_console_pages',
              displayName: 'User Self',
              primaryEmail: 'user-self@example.com',
              canEditPrimaryEmail: true,
              backupEmails: [],
              createdAt: iso('2026-01-01T00:00:00.000Z'),
              updatedAt: iso('2026-01-01T00:00:00.000Z'),
            },
          }),
        });
        return;
      }

      if (pathname === '/console/account/organizations' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, organizations: accountOrganizations }),
        });
        return;
      }

      if (pathname === '/console/billing/overview' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            overview: {
              usageMetricVersion: 'v1',
              currentMonthUtc: '2026-03',
              monthlyActiveWallets: 12,
              creditBalanceMinor: 125000,
              lowBalanceThresholdMinor: 10000,
              recentUsageDebitMinor: 3200,
              recentCreditPurchasedMinor: 50000,
              documentCount: 2,
            },
          }),
        });
        return;
      }

      if (pathname === '/console/billing/account/activity' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            activity: {
              entries: [],
            },
          }),
        });
        return;
      }

      await route.fulfill({
        status: 404,
        contentType: 'application/json',
        body: JSON.stringify({
          ok: false,
          code: 'not_stubbed',
          path: pathname,
          method,
        }),
      });
    });

    await page.goto('/dashboard/overview');
    await expect(page.locator('#dashboard-main-title')).toHaveText(/overview/i);

    await page.getByRole('button', { name: /account.*settings/i }).click();
    await page.getByRole('menuitem', { name: 'Account Settings' }).click();

    await expect.poll(() => new URL(page.url()).pathname).toBe('/dashboard/account-settings');
    await expect(page.locator('#dashboard-main-title')).toHaveText(/account settings/i);
    await expect(page.locator('[aria-label="Account settings page"]')).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Profile' })).toBeVisible();
  });

  test('account settings drops stale persisted environment ids from the topbar', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;

    await page.addInitScript(() => {
      window.localStorage.setItem(
        'tatchi-dashboard-ui-state-v1',
        JSON.stringify({
          isSidebarExpanded: true,
          expandedGroups: {
            overview: true,
            administration: true,
            operationsSecurity: true,
            integrations: true,
            billing: true,
          },
          selectedContext: {
            organization: 'org-dev',
            project: 'proj_mmggz8jp_v9pft0',
            environment: 'org-dev:proj_mmggz8jp_v9pft0:dev',
            accountSettings: 'Account Settings',
          },
        }),
      );
    });

    await page.route(`${consoleOrigin}/console/**`, async (route) => {
      const req = route.request();
      const method = req.method().toUpperCase();
      const pathname = new URL(req.url()).pathname;

      if (pathname === '/console/session' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            claims: {
              userId: 'user_environment_cleanup',
              orgId: 'org-dev',
              roles: ['admin'],
              projectId: 'proj_mmggz8jp_v9pft0',
              environmentId: 'proj_mmggz8jp_v9pft0:dev',
            },
          }),
        });
        return;
      }

      if (pathname === '/console/onboarding/state' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            state: {
              orgId: 'org-dev',
              organization: {
                id: 'org-dev',
                name: 'tatchi-org-test',
                slug: 'org-dev',
                status: 'ACTIVE',
                createdAt: iso('2026-03-08T00:00:00.000Z'),
                updatedAt: iso('2026-03-11T00:00:00.000Z'),
              },
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
              selectedProjectId: 'proj_mmggz8jp_v9pft0',
              selectedEnvironmentId: 'proj_mmggz8jp_v9pft0:dev',
            },
          }),
        });
        return;
      }

      if (pathname === '/console/org' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            org: {
              id: 'org-dev',
              name: 'tatchi-org-test',
              slug: 'org-dev',
              status: 'ACTIVE',
              createdAt: iso('2026-03-08T00:00:00.000Z'),
              updatedAt: iso('2026-03-11T00:00:00.000Z'),
            },
          }),
        });
        return;
      }

      if (pathname === '/console/projects' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            projects: [
              {
                id: 'proj_mmggz8jp_v9pft0',
                name: 'test1_project',
                slug: 'test1-project',
                status: 'ACTIVE',
                environmentCount: 1,
                createdAt: iso('2026-03-08T00:00:00.000Z'),
                updatedAt: iso('2026-03-11T00:00:00.000Z'),
              },
            ],
          }),
        });
        return;
      }

      if (pathname === '/console/environments' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            environments: [
              {
                id: 'proj_mmggz8jp_v9pft0:dev',
                projectId: 'proj_mmggz8jp_v9pft0',
                key: 'dev',
                name: 'Development',
                status: 'ACTIVE',
                createdAt: iso('2026-03-08T00:00:00.000Z'),
                updatedAt: iso('2026-03-11T00:00:00.000Z'),
              },
            ],
          }),
        });
        return;
      }

      if (pathname === '/console/account/profile' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            profile: {
              userId: 'user_environment_cleanup',
              displayName: 'Pta',
              primaryEmail: 'n6378056@gmail.com',
              canEditPrimaryEmail: true,
              backupEmails: [],
              createdAt: iso('2026-03-08T00:00:00.000Z'),
              updatedAt: iso('2026-03-11T00:00:00.000Z'),
            },
          }),
        });
        return;
      }

      if (pathname === '/console/account/organizations' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            organizations: [
              {
                id: 'org-dev',
                name: 'tatchi-org-test',
                slug: 'org-dev',
                status: 'ACTIVE',
                createdAt: iso('2026-03-08T00:00:00.000Z'),
                updatedAt: iso('2026-03-11T00:00:00.000Z'),
                isCurrentOrg: true,
                actorRoles: ['admin'],
                actorIsOwner: true,
                actorIsAdmin: true,
                onboardingComplete: true,
                selectedProjectId: 'proj_mmggz8jp_v9pft0',
                selectedProjectName: 'test1_project',
                selectedEnvironmentId: 'proj_mmggz8jp_v9pft0:dev',
                selectedEnvironmentName: 'Development',
                adminCandidates: [],
              },
            ],
          }),
        });
        return;
      }

      if (pathname === '/console/billing/overview' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            overview: {
              usageMetricVersion: 'v1',
              currentMonthUtc: '2026-03',
              monthlyActiveWallets: 1,
              creditBalanceMinor: 1000,
              lowBalanceThresholdMinor: 100,
              recentUsageDebitMinor: 0,
              recentCreditPurchasedMinor: 0,
              documentCount: 0,
            },
          }),
        });
        return;
      }

      if (pathname === '/console/billing/account/activity' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            activity: {
              entries: [],
            },
          }),
        });
        return;
      }

      await route.fulfill({
        status: 404,
        contentType: 'application/json',
        body: JSON.stringify({
          ok: false,
          code: 'not_stubbed',
          path: pathname,
          method,
        }),
      });
    });

    await page.goto('/dashboard/account-settings');

    const topbar = page.locator('header[aria-label="Workspace context"]');
    await expect(topbar.locator('button:has-text("Environment")')).toContainText('Development');
    await expect(
      topbar.locator('[aria-label="Environment id"] .dashboard-context-card__value'),
    ).toHaveText('proj_mmggz8jp_v9pft0:dev');
    await expect(topbar).not.toContainText('org-dev:proj_mmggz8jp_v9pft0:dev');
    await expect
      .poll(() =>
        page.evaluate(() => {
          const raw = window.localStorage.getItem('tatchi-dashboard-ui-state-v1');
          const parsed = raw ? JSON.parse(raw) : null;
          return String(parsed?.selectedContext?.environment || '');
        }),
      )
      .toBe('proj_mmggz8jp_v9pft0:dev');
  });

  test('account settings topbar falls back to account organization scope when session context is empty', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;

    await page.route(`${consoleOrigin}/console/**`, async (route) => {
      const req = route.request();
      const method = req.method().toUpperCase();
      const pathname = new URL(req.url()).pathname;

      if (pathname === '/console/session' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            claims: {
              userId: 'user_context_fallback',
              orgId: 'org_pokopia',
              roles: ['owner', 'admin'],
            },
          }),
        });
        return;
      }

      if (pathname === '/console/onboarding/state' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            state: {
              orgId: 'org_pokopia',
              organization: {
                id: 'org_pokopia',
                name: 'Pokopia Labs',
                slug: 'pokopia-labs',
                status: 'ACTIVE',
                createdAt: iso('2026-03-08T00:00:00.000Z'),
                updatedAt: iso('2026-03-11T00:00:00.000Z'),
              },
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
              selectedProjectId: null,
              selectedEnvironmentId: null,
            },
          }),
        });
        return;
      }

      if (pathname === '/console/org' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            org: {
              id: 'org_pokopia',
              name: 'Pokopia Labs',
              slug: 'pokopia-labs',
              status: 'ACTIVE',
              createdAt: iso('2026-03-08T00:00:00.000Z'),
              updatedAt: iso('2026-03-11T00:00:00.000Z'),
            },
          }),
        });
        return;
      }

      if (pathname === '/console/projects' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            projects: [],
          }),
        });
        return;
      }

      if (pathname === '/console/environments' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            environments: [],
          }),
        });
        return;
      }

      if (pathname === '/console/account/profile' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            profile: {
              userId: 'user_context_fallback',
              displayName: 'Pta',
              primaryEmail: 'n6378056@gmail.com',
              canEditPrimaryEmail: true,
              backupEmails: [],
              createdAt: iso('2026-03-08T00:00:00.000Z'),
              updatedAt: iso('2026-03-11T00:00:00.000Z'),
            },
          }),
        });
        return;
      }

      if (pathname === '/console/account/organizations' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            organizations: [
              {
                id: 'org_pokopia',
                name: 'Pokopia Labs',
                slug: 'pokopia-labs',
                status: 'ACTIVE',
                createdAt: iso('2026-03-08T00:00:00.000Z'),
                updatedAt: iso('2026-03-11T00:00:00.000Z'),
                isCurrentOrg: true,
                actorRoles: ['owner', 'admin'],
                actorIsOwner: true,
                actorIsAdmin: true,
                onboardingComplete: true,
                selectedProjectId: 'proj_tlabs',
                selectedProjectName: 'Tlabs',
                selectedEnvironmentId: 'proj_tlabs:dev',
                selectedEnvironmentName: 'Development',
                adminCandidates: [],
              },
            ],
          }),
        });
        return;
      }

      await route.fulfill({
        status: 404,
        contentType: 'application/json',
        body: JSON.stringify({
          ok: false,
          code: 'not_stubbed',
          path: pathname,
          method,
        }),
      });
    });

    await page.goto('/dashboard/account-settings');

    const topbar = page.locator('header[aria-label="Workspace context"]');
    await expect(topbar.locator('button:has-text("Organization")')).toContainText('Pokopia Labs');
    await expect(topbar.locator('button:has-text("Project")')).toContainText('Tlabs');
    await expect(topbar.locator('button:has-text("Environment")')).toContainText('Development');
    await expect(
      topbar.locator('[aria-label="Environment id"] .dashboard-context-card__value'),
    ).toHaveText('proj_tlabs:dev');
  });

  test('topbar organization menu keeps the billing route while switching organizations', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    let activeOrgId = 'org_pokopia';
    let sessionClaims: Record<string, unknown> = {
      userId: 'user_multi_org',
      orgId: 'org_pokopia',
      roles: ['owner', 'admin'],
      projectId: 'proj_pokopia',
      environmentId: 'env_pokopia',
      provider: 'passkey',
    };
    const switchBodies: Array<{ orgId: string; body: Record<string, unknown> }> = [];
    const billingOverviewOrgIds: string[] = [];

    const organizations = [
      {
        id: 'org_pokopia',
        name: 'Pokopia Labs',
        slug: 'pokopia-labs',
        status: 'ACTIVE',
        createdAt: iso('2026-03-01T00:00:00.000Z'),
        updatedAt: iso('2026-03-02T00:00:00.000Z'),
        actorRoles: ['owner', 'admin'],
        actorIsOwner: true,
        actorIsAdmin: true,
        onboardingComplete: true,
        adminCandidates: [],
      },
      {
        id: 'org_watchbook',
        name: 'Watchbook',
        slug: 'watch-book',
        status: 'ACTIVE',
        createdAt: iso('2026-03-03T00:00:00.000Z'),
        updatedAt: iso('2026-03-04T00:00:00.000Z'),
        actorRoles: ['owner', 'admin'],
        actorIsOwner: true,
        actorIsAdmin: true,
        onboardingComplete: true,
        adminCandidates: [],
      },
    ] as const;
    const projectsByOrg = new Map<string, Record<string, unknown>>([
      [
        'org_pokopia',
        {
          id: 'proj_pokopia',
          name: 'Pokopia Core',
          slug: 'pokopia-core',
          status: 'ACTIVE',
          environmentCount: 1,
          createdAt: iso('2026-03-01T00:00:00.000Z'),
          updatedAt: iso('2026-03-02T00:00:00.000Z'),
        },
      ],
      [
        'org_watchbook',
        {
          id: 'proj_watchbook',
          name: 'Watchbook Core',
          slug: 'watchbook-core',
          status: 'ACTIVE',
          environmentCount: 1,
          createdAt: iso('2026-03-03T00:00:00.000Z'),
          updatedAt: iso('2026-03-04T00:00:00.000Z'),
        },
      ],
    ]);
    const environmentsByProject = new Map<string, Record<string, unknown>>([
      [
        'proj_pokopia',
        {
          id: 'env_pokopia',
          projectId: 'proj_pokopia',
          key: 'prod',
          name: 'Production',
          status: 'ACTIVE',
          createdAt: iso('2026-03-01T00:00:00.000Z'),
          updatedAt: iso('2026-03-02T00:00:00.000Z'),
        },
      ],
      [
        'proj_watchbook',
        {
          id: 'env_watchbook',
          projectId: 'proj_watchbook',
          key: 'prod',
          name: 'Production',
          status: 'ACTIVE',
          createdAt: iso('2026-03-03T00:00:00.000Z'),
          updatedAt: iso('2026-03-04T00:00:00.000Z'),
        },
      ],
    ]);

    await page.addInitScript(() => {
      window.localStorage.setItem(
        'tatchi-dashboard-ui-state-v1',
        JSON.stringify({
          isSidebarExpanded: true,
          expandedGroups: {
            overview: true,
            administration: true,
            operationsSecurity: true,
            integrations: true,
            billing: true,
          },
          selectedContext: {
            organization: 'org_pokopia',
            project: 'proj_pokopia',
            environment: 'env_pokopia',
            accountSettings: 'Account Settings',
          },
        }),
      );
    });

    await page.route(`${consoleOrigin}/console/**`, async (route) => {
      const req = route.request();
      const method = req.method().toUpperCase();
      const url = new URL(req.url());
      const { pathname } = url;

      if (pathname === '/console/session' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            claims: sessionClaims,
          }),
        });
        return;
      }

      if (pathname === '/console/onboarding/state' && method === 'GET') {
        const project = projectsByOrg.get(activeOrgId) || null;
        const environment = project
          ? environmentsByProject.get(String(project.id || '').trim()) || null
          : null;
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            state: {
              orgId: activeOrgId,
              organization: organizations.find((entry) => entry.id === activeOrgId) || null,
              activeProjectCount: project ? 1 : 0,
              activeEnvironmentCount: environment ? 1 : 0,
              activeApiKeyCount: 1,
              hasOrganization: true,
              hasProject: Boolean(project),
              hasEnvironment: Boolean(environment),
              hasApiKey: true,
              accountReady: true,
              organizationReady: true,
              billingReady: true,
              projectReady: Boolean(project),
              onboardingComplete: Boolean(project && environment),
              currentStep: project && environment ? 'complete' : 'project',
              complete: Boolean(project && environment),
              selectedProjectId: project ? String(project.id || '').trim() : null,
              selectedEnvironmentId: environment ? String(environment.id || '').trim() : null,
            },
          }),
        });
        return;
      }

      if (pathname === '/console/projects' && method === 'GET') {
        const project = projectsByOrg.get(activeOrgId) || null;
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            projects: project ? [project] : [],
          }),
        });
        return;
      }

      if (pathname === '/console/environments' && method === 'GET') {
        const projectId = String(url.searchParams.get('projectId') || '').trim();
        const environment = environmentsByProject.get(projectId) || null;
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            environments: environment ? [environment] : [],
          }),
        });
        return;
      }

      if (pathname === '/console/account/organizations' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            organizations: organizations.map((organization) => {
              const isCurrentOrg = organization.id === activeOrgId;
              const project = isCurrentOrg ? projectsByOrg.get(activeOrgId) || null : null;
              const environment = project
                ? environmentsByProject.get(String(project.id || '').trim()) || null
                : null;
              return {
                ...organization,
                isCurrentOrg,
                selectedProjectId: project ? String(project.id || '').trim() : null,
                selectedProjectName: project ? String(project.name || '').trim() : null,
                selectedEnvironmentId: environment ? String(environment.id || '').trim() : null,
                selectedEnvironmentName: environment ? String(environment.name || '').trim() : null,
              };
            }),
          }),
        });
        return;
      }

      const accountOrgMatch = pathname.match(
        /^\/console\/account\/organizations\/([^/]+?)\/switch-context$/,
      );
      const orgId = accountOrgMatch?.[1] ? decodeURIComponent(accountOrgMatch[1]) : '';
      if (orgId && method === 'POST') {
        const body = parseJsonBody(req.postData());
        switchBodies.push({ orgId, body });
        activeOrgId = orgId;
        const project = projectsByOrg.get(orgId) || null;
        const environment = project
          ? environmentsByProject.get(String(project.id || '').trim()) || null
          : null;
        sessionClaims = {
          userId: 'user_multi_org',
          orgId,
          roles: ['owner', 'admin'],
          projectId: project ? String(project.id || '').trim() : '',
          environmentId: environment ? String(environment.id || '').trim() : '',
          provider: 'passkey',
        };
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            context: {
              orgId,
              projectId: project ? String(project.id || '').trim() : null,
              environmentId: environment ? String(environment.id || '').trim() : null,
              actorRoles: ['owner', 'admin'],
              onboardingComplete: true,
            },
          }),
        });
        return;
      }

      if (pathname === '/console/billing/overview' && method === 'GET') {
        billingOverviewOrgIds.push(activeOrgId);
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            overview: {
              usageMetricVersion: 'v1',
              currentMonthUtc: '2026-03',
              monthlyActiveWallets: activeOrgId === 'org_watchbook' ? 9 : 3,
              creditBalanceMinor: activeOrgId === 'org_watchbook' ? 37500 : 12000,
              lowBalanceThresholdMinor: 1000,
              recentUsageDebitMinor: activeOrgId === 'org_watchbook' ? 1800 : 600,
              recentCreditPurchasedMinor: activeOrgId === 'org_watchbook' ? 45000 : 15000,
              documentCount: activeOrgId === 'org_watchbook' ? 2 : 1,
            },
          }),
        });
        return;
      }

      if (pathname === '/console/billing/usage/monthly-active-wallets' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            usage: {
              usageMetricVersion: 'v1',
              monthUtc: '2026-03',
              monthlyActiveWallets: activeOrgId === 'org_watchbook' ? 9 : 3,
            },
          }),
        });
        return;
      }

      if (pathname === '/console/billing/invoices' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            invoices: [],
            nextCursor: null,
            totalCount: 0,
            summary: {
              totalCount: 0,
              openCount: 0,
              overdueCount: 0,
              paidCount: 0,
              outstandingAmountMinor: 0,
              latestPeriodMonthUtc: null,
              receiptCount: 0,
              statementCount: 0,
            },
          }),
        });
        return;
      }

      await route.fulfill({
        status: 404,
        contentType: 'application/json',
        body: JSON.stringify({
          ok: false,
          code: 'not_stubbed',
          path: pathname,
          method,
        }),
      });
    });

    await page.goto('/dashboard/billing/account');

    const topbar = page.locator('header[aria-label="Workspace context"]');
    const organizationButton = topbar.locator('button:has-text("Organization")');
    await expect(organizationButton).toContainText('Pokopia Labs');
    await expect(page.locator('[aria-label="Billing account summary metrics"]')).toContainText(
      '$120.00',
    );

    await organizationButton.click();
    const organizationMenu = page.locator('[aria-label="Organization options"]');
    await expect(
      organizationMenu.getByRole('menuitemradio', { name: 'Pokopia Labs' }),
    ).toBeVisible();
    await expect(organizationMenu.getByRole('menuitemradio', { name: 'Watchbook' })).toBeVisible();

    await organizationMenu.getByRole('menuitemradio', { name: 'Watchbook' }).click();
    await expect.poll(() => switchBodies.length).toBe(1);
    expect(switchBodies[0]).toMatchObject({
      orgId: 'org_watchbook',
      body: {},
    });

    await expect.poll(() => new URL(page.url()).pathname).toBe('/dashboard/billing/account');
    await expect(organizationButton).toContainText('Watchbook');
    await expect(topbar.locator('button:has-text("Project")')).toContainText('Watchbook Core');
    await expect(topbar.locator('button:has-text("Environment")')).toContainText('Production');
    await expect(page.locator('[aria-label="Billing account summary metrics"]')).toContainText(
      '$375.00',
    );
    await expect
      .poll(() => billingOverviewOrgIds[billingOverviewOrgIds.length - 1] || '')
      .toBe('org_watchbook');
  });

  test('topbar organization menu updates account settings context when switching organizations', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    let activeOrgId = 'org_pokopia';
    let sessionClaims: Record<string, unknown> = {
      userId: 'user_account_settings_switch',
      orgId: 'org_pokopia',
      roles: ['owner', 'admin'],
      projectId: 'proj_pokopia',
      environmentId: 'env_pokopia',
      provider: 'passkey',
    };
    const switchBodies: Array<{ orgId: string; body: Record<string, unknown> }> = [];

    const organizations = [
      {
        id: 'org_pokopia',
        name: 'Pokopia Labs',
        slug: 'pokopia-labs',
        status: 'ACTIVE',
        createdAt: iso('2026-03-01T00:00:00.000Z'),
        updatedAt: iso('2026-03-02T00:00:00.000Z'),
        actorRoles: ['owner', 'admin'],
        actorIsOwner: true,
        actorIsAdmin: true,
        onboardingComplete: true,
        adminCandidates: [],
      },
      {
        id: 'org_watchbook',
        name: 'Watchbook',
        slug: 'watchbook',
        status: 'ACTIVE',
        createdAt: iso('2026-03-03T00:00:00.000Z'),
        updatedAt: iso('2026-03-04T00:00:00.000Z'),
        actorRoles: ['owner', 'admin'],
        actorIsOwner: true,
        actorIsAdmin: true,
        onboardingComplete: true,
        adminCandidates: [],
      },
    ] as const;
    const projectsByOrg = new Map<string, Record<string, unknown>>([
      [
        'org_pokopia',
        {
          id: 'proj_pokopia',
          name: 'Tlabs',
          slug: 'tlabs',
          status: 'ACTIVE',
          environmentCount: 1,
          createdAt: iso('2026-03-01T00:00:00.000Z'),
          updatedAt: iso('2026-03-02T00:00:00.000Z'),
        },
      ],
      [
        'org_watchbook',
        {
          id: 'proj_watchbook',
          name: 'Watchbook Core',
          slug: 'watchbook-core',
          status: 'ACTIVE',
          environmentCount: 1,
          createdAt: iso('2026-03-03T00:00:00.000Z'),
          updatedAt: iso('2026-03-04T00:00:00.000Z'),
        },
      ],
    ]);
    const environmentsByProject = new Map<string, Record<string, unknown>>([
      [
        'proj_pokopia',
        {
          id: 'env_pokopia',
          projectId: 'proj_pokopia',
          key: 'dev',
          name: 'Development',
          status: 'ACTIVE',
          createdAt: iso('2026-03-01T00:00:00.000Z'),
          updatedAt: iso('2026-03-02T00:00:00.000Z'),
        },
      ],
      [
        'proj_watchbook',
        {
          id: 'env_watchbook',
          projectId: 'proj_watchbook',
          key: 'prod',
          name: 'Production',
          status: 'ACTIVE',
          createdAt: iso('2026-03-03T00:00:00.000Z'),
          updatedAt: iso('2026-03-04T00:00:00.000Z'),
        },
      ],
    ]);

    await page.addInitScript(() => {
      window.localStorage.setItem(
        'tatchi-dashboard-ui-state-v1',
        JSON.stringify({
          isSidebarExpanded: true,
          expandedGroups: {
            overview: true,
            administration: true,
            operationsSecurity: true,
            integrations: true,
            billing: true,
          },
          selectedContext: {
            organization: 'org_pokopia',
            project: 'proj_pokopia',
            environment: 'env_pokopia',
            accountSettings: 'Account Settings',
          },
        }),
      );
    });

    await page.route(`${consoleOrigin}/console/**`, async (route) => {
      const req = route.request();
      const method = req.method().toUpperCase();
      const url = new URL(req.url());
      const { pathname } = url;

      if (pathname === '/console/session' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, claims: sessionClaims }),
        });
        return;
      }

      if (pathname === '/console/onboarding/state' && method === 'GET') {
        const project = projectsByOrg.get(activeOrgId) || null;
        const environment = project
          ? environmentsByProject.get(String(project.id || '').trim()) || null
          : null;
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            state: {
              orgId: activeOrgId,
              organization: organizations.find((entry) => entry.id === activeOrgId) || null,
              activeProjectCount: project ? 1 : 0,
              activeEnvironmentCount: environment ? 1 : 0,
              activeApiKeyCount: 1,
              hasOrganization: true,
              hasProject: Boolean(project),
              hasEnvironment: Boolean(environment),
              hasApiKey: true,
              accountReady: true,
              organizationReady: true,
              billingReady: true,
              projectReady: Boolean(project),
              onboardingComplete: Boolean(project && environment),
              currentStep: project && environment ? 'complete' : 'project',
              complete: Boolean(project && environment),
              selectedProjectId: project ? String(project.id || '').trim() : null,
              selectedEnvironmentId: environment ? String(environment.id || '').trim() : null,
            },
          }),
        });
        return;
      }

      if (pathname === '/console/projects' && method === 'GET') {
        const project = projectsByOrg.get(activeOrgId) || null;
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, projects: project ? [project] : [] }),
        });
        return;
      }

      if (pathname === '/console/environments' && method === 'GET') {
        const projectId = String(url.searchParams.get('projectId') || '').trim();
        const environment = environmentsByProject.get(projectId) || null;
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, environments: environment ? [environment] : [] }),
        });
        return;
      }

      if (pathname === '/console/account/profile' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            profile: {
              userId: 'user_account_settings_switch',
              displayName: 'Switching User',
              primaryEmail: 'switching@example.com',
              canEditPrimaryEmail: true,
              backupEmails: [],
              createdAt: iso('2026-03-01T00:00:00.000Z'),
              updatedAt: iso('2026-03-02T00:00:00.000Z'),
            },
          }),
        });
        return;
      }

      if (pathname === '/console/account/organizations' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            organizations: organizations.map((organization) => {
              const isCurrentOrg = organization.id === activeOrgId;
              const project = isCurrentOrg ? projectsByOrg.get(activeOrgId) || null : null;
              const environment = project
                ? environmentsByProject.get(String(project.id || '').trim()) || null
                : null;
              return {
                ...organization,
                isCurrentOrg,
                selectedProjectId: project ? String(project.id || '').trim() : null,
                selectedProjectName: project ? String(project.name || '').trim() : null,
                selectedEnvironmentId: environment ? String(environment.id || '').trim() : null,
                selectedEnvironmentName: environment ? String(environment.name || '').trim() : null,
              };
            }),
          }),
        });
        return;
      }

      const accountOrgMatch = pathname.match(
        /^\/console\/account\/organizations\/([^/]+?)\/switch-context$/,
      );
      const orgId = accountOrgMatch?.[1] ? decodeURIComponent(accountOrgMatch[1]) : '';
      if (orgId && method === 'POST') {
        const body = parseJsonBody(req.postData());
        switchBodies.push({ orgId, body });
        activeOrgId = orgId;
        const project = projectsByOrg.get(orgId) || null;
        const environment = project
          ? environmentsByProject.get(String(project.id || '').trim()) || null
          : null;
        sessionClaims = {
          userId: 'user_account_settings_switch',
          orgId,
          roles: ['owner', 'admin'],
          projectId: project ? String(project.id || '').trim() : '',
          environmentId: environment ? String(environment.id || '').trim() : '',
          provider: 'passkey',
        };
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            context: {
              orgId,
              projectId: project ? String(project.id || '').trim() : null,
              environmentId: environment ? String(environment.id || '').trim() : null,
              actorRoles: ['owner', 'admin'],
              onboardingComplete: true,
            },
          }),
        });
        return;
      }

      await route.fulfill({
        status: 404,
        contentType: 'application/json',
        body: JSON.stringify({
          ok: false,
          code: 'not_stubbed',
          path: pathname,
          method,
        }),
      });
    });

    await page.goto('/dashboard/account-settings');

    const topbar = page.locator('header[aria-label="Workspace context"]');
    const organizationButton = topbar.locator('button:has-text("Organization")');
    await expect(organizationButton).toContainText('Pokopia Labs');
    await expect(topbar.locator('button:has-text("Project")')).toContainText('Tlabs');
    await expect(topbar.locator('button:has-text("Environment")')).toContainText('Development');

    await organizationButton.click();
    const organizationMenu = page.locator('[aria-label="Organization options"]');
    await expect(organizationMenu.getByRole('menuitemradio', { name: 'Watchbook' })).toBeVisible();
    await organizationMenu.getByRole('menuitemradio', { name: 'Watchbook' }).click();

    await expect.poll(() => switchBodies.length).toBe(1);
    expect(switchBodies[0]).toMatchObject({
      orgId: 'org_watchbook',
      body: {},
    });
    await expect.poll(() => new URL(page.url()).pathname).toBe('/dashboard/account-settings');
    await expect(page.getByRole('heading', { name: 'Profile' })).toBeVisible();
    await expect(organizationButton).toContainText('Watchbook');
    await expect(topbar.locator('button:has-text("Project")')).toContainText('Watchbook Core');
    await expect(topbar.locator('button:has-text("Environment")')).toContainText('Production');
  });

  test('account settings remains reachable while onboarding is incomplete', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;

    await page.route(`${consoleOrigin}/console/**`, async (route) => {
      const req = route.request();
      const method = req.method().toUpperCase();
      const pathname = new URL(req.url()).pathname;

      if (pathname === '/console/session') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            claims: {
              userId: 'user_account_settings_gate',
              orgId: 'org_account_settings_gate',
              roles: ['admin'],
            },
          }),
        });
        return;
      }

      if (pathname === '/console/onboarding/state' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            state: {
              orgId: 'org_account_settings_gate',
              organization: null,
              activeProjectCount: 0,
              activeEnvironmentCount: 0,
              activeApiKeyCount: 0,
              hasOrganization: false,
              hasProject: false,
              hasEnvironment: false,
              hasApiKey: false,
              accountReady: true,
              organizationReady: false,
              billingReady: false,
              projectReady: false,
              onboardingComplete: false,
              currentStep: 'organization',
              complete: false,
              selectedProjectId: null,
              selectedEnvironmentId: null,
            },
          }),
        });
        return;
      }

      if (pathname === '/console/account/profile' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            profile: {
              userId: 'user_account_settings_gate',
              displayName: 'Gate User',
              primaryEmail: 'gate@example.com',
              canEditPrimaryEmail: true,
              backupEmails: [],
              createdAt: iso('2026-01-01T00:00:00.000Z'),
              updatedAt: iso('2026-01-01T00:00:00.000Z'),
            },
          }),
        });
        return;
      }

      if (pathname === '/console/account/organizations' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            organizations: [
              {
                id: 'org_account_settings_gate',
                name: 'org account settings gate',
                slug: 'org-account-settings-gate',
                status: 'ACTIVE',
                createdAt: iso('2026-01-01T00:00:00.000Z'),
                updatedAt: iso('2026-01-01T00:00:00.000Z'),
                isCurrentOrg: true,
                actorRoles: ['admin'],
                actorIsOwner: false,
                actorIsAdmin: true,
                onboardingComplete: false,
                selectedProjectId: null,
                selectedProjectName: null,
                selectedEnvironmentId: null,
                selectedEnvironmentName: null,
                adminCandidates: [],
              },
            ],
          }),
        });
        return;
      }

      await route.fulfill({
        status: 404,
        contentType: 'application/json',
        body: JSON.stringify({
          ok: false,
          code: 'not_stubbed',
          path: pathname,
          method,
        }),
      });
    });

    await page.goto('/dashboard/account-settings');

    await expect.poll(() => new URL(page.url()).pathname).toBe('/dashboard/account-settings');
    await expect(page.locator('#dashboard-main-title')).toHaveText(/account settings/i);
    await expect(page.getByRole('heading', { name: 'Profile' })).toBeVisible();
    await expect(page.getByRole('table', { name: 'Organizations' })).toContainText(
      'No organizations created by this account yet.',
    );
    await expect(page.getByRole('table', { name: 'Organizations' })).not.toContainText(
      'org account settings gate',
    );
  });

  test('account settings stays available before any organization exists and keeps topbar scope blank', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    let onboardingStateCalls = 0;
    let projectCalls = 0;
    let environmentCalls = 0;

    await page.addInitScript(() => {
      window.localStorage.setItem(
        'tatchi-dashboard-ui-state-v1',
        JSON.stringify({
          isSidebarExpanded: true,
          expandedGroups: {
            overview: true,
            administration: true,
            operationsSecurity: true,
            integrations: true,
            billing: true,
          },
          selectedContext: {
            organization: 'stale-org',
            project: 'stale-project',
            environment: 'stale-environment',
            accountSettings: 'Account Settings',
          },
        }),
      );
    });

    await page.route(`${consoleOrigin}/console/**`, async (route) => {
      const req = route.request();
      const method = req.method().toUpperCase();
      const pathname = new URL(req.url()).pathname;

      if (pathname === '/console/session' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            claims: {
              userId: 'user_account_settings_orgless',
              orgId: '',
              roles: [],
              email: 'orgless@example.com',
              name: 'Orgless User',
            },
          }),
        });
        return;
      }

      if (pathname === '/console/onboarding/state' && method === 'GET') {
        onboardingStateCalls += 1;
        await route.fulfill({
          status: 500,
          contentType: 'application/json',
          body: JSON.stringify({ ok: false, code: 'should_not_be_called' }),
        });
        return;
      }

      if (pathname === '/console/account/profile' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            profile: {
              userId: 'user_account_settings_orgless',
              displayName: 'Orgless User',
              primaryEmail: 'orgless@example.com',
              canEditPrimaryEmail: true,
              backupEmails: [],
              createdAt: iso('2026-03-01T00:00:00.000Z'),
              updatedAt: iso('2026-03-01T00:00:00.000Z'),
            },
          }),
        });
        return;
      }

      if (pathname === '/console/account/organizations' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, organizations: [] }),
        });
        return;
      }

      if (pathname === '/console/projects' && method === 'GET') {
        projectCalls += 1;
        await route.fulfill({
          status: 500,
          contentType: 'application/json',
          body: JSON.stringify({ ok: false, code: 'should_not_be_called' }),
        });
        return;
      }

      if (pathname === '/console/environments' && method === 'GET') {
        environmentCalls += 1;
        await route.fulfill({
          status: 500,
          contentType: 'application/json',
          body: JSON.stringify({ ok: false, code: 'should_not_be_called' }),
        });
        return;
      }

      await route.fulfill({
        status: 404,
        contentType: 'application/json',
        body: JSON.stringify({
          ok: false,
          code: 'not_stubbed',
          path: pathname,
          method,
        }),
      });
    });

    await page.goto('/dashboard/account-settings');

    await expect.poll(() => new URL(page.url()).pathname).toBe('/dashboard/account-settings');
    await expect(page.locator('#dashboard-main-title')).toHaveText(/account settings/i);
    await expect(page.getByRole('heading', { name: 'Profile' })).toBeVisible();

    const topbar = page.locator('header[aria-label="Workspace context"]');
    await expect(topbar.locator('button:has-text("Organization")')).not.toContainText('stale-org');
    await expect(topbar.locator('button:has-text("Project")')).not.toContainText('stale-project');
    await expect(topbar.locator('button:has-text("Environment")')).not.toContainText(
      'stale-environment',
    );
    await expect(
      topbar.locator('[aria-label="Environment id"] .dashboard-context-card__value'),
    ).toHaveText('—');
    await expect.poll(() => onboardingStateCalls).toBe(0);
    await expect.poll(() => projectCalls).toBe(0);
    await expect.poll(() => environmentCalls).toBe(0);

    await page.getByRole('button', { name: 'Create an organisation' }).click();
    await expect.poll(() => new URL(page.url()).pathname).toBe('/dashboard/onboarding');
    await expect.poll(() => new URL(page.url()).search).toBe('?createOrganization=1');
  });

  test('account settings delays organization creation until onboarding name submission', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    const accountProfile = {
      userId: 'user_account_settings_flow',
      displayName: 'Account Flow User',
      primaryEmail: 'account-flow@example.com',
      canEditPrimaryEmail: true,
      backupEmails: [],
      createdAt: iso('2026-01-01T00:00:00.000Z'),
      updatedAt: iso('2026-01-01T00:00:00.000Z'),
    };
    const organizations = new Map<string, Record<string, unknown>>([
      [
        'org_current',
        {
          id: 'org_current',
          name: 'Current Org',
          slug: 'current-org',
          status: 'ACTIVE',
          createdAt: iso('2026-01-01T00:00:00.000Z'),
          updatedAt: iso('2026-01-02T00:00:00.000Z'),
          actorRoles: ['owner', 'admin'],
          actorIsOwner: true,
          actorIsAdmin: true,
          onboardingComplete: true,
          selectedProjectId: 'proj_current',
          selectedProjectName: 'Current Project',
          selectedEnvironmentId: 'env_current',
          selectedEnvironmentName: 'Current Environment',
          adminCandidates: [
            {
              memberId: 'member_current_admin',
              userId: 'user_current_admin',
              email: 'current-admin@example.com',
              displayName: 'Current Admin',
              isOwner: false,
            },
          ],
        },
      ],
      [
        'org_target',
        {
          id: 'org_target',
          name: 'Target Org',
          slug: 'target-org',
          status: 'ACTIVE',
          createdAt: iso('2026-01-03T00:00:00.000Z'),
          updatedAt: iso('2026-01-04T00:00:00.000Z'),
          actorRoles: ['owner', 'admin'],
          actorIsOwner: true,
          actorIsAdmin: true,
          onboardingComplete: true,
          selectedProjectId: 'proj_target',
          selectedProjectName: 'Target Project',
          selectedEnvironmentId: 'env_target',
          selectedEnvironmentName: 'Target Environment',
          adminCandidates: [
            {
              memberId: 'member_target_admin',
              userId: 'user_target_admin',
              email: 'target-admin@example.com',
              displayName: 'Target Admin',
              isOwner: false,
            },
          ],
        },
      ],
    ]);
    const orgDetails = new Map<string, Record<string, unknown>>([
      [
        'org_current',
        {
          id: 'org_current',
          name: 'Current Org',
          slug: 'current-org',
          status: 'ACTIVE',
          createdAt: iso('2026-01-01T00:00:00.000Z'),
          updatedAt: iso('2026-01-02T00:00:00.000Z'),
        },
      ],
      [
        'org_target',
        {
          id: 'org_target',
          name: 'Target Org',
          slug: 'target-org',
          status: 'ACTIVE',
          createdAt: iso('2026-01-03T00:00:00.000Z'),
          updatedAt: iso('2026-01-04T00:00:00.000Z'),
        },
      ],
    ]);
    const projectByOrg = new Map<string, Record<string, unknown>>([
      [
        'org_current',
        {
          id: 'proj_current',
          name: 'Current Project',
          slug: 'current-project',
          status: 'ACTIVE',
          environmentCount: 1,
          createdAt: iso('2026-01-01T00:00:00.000Z'),
          updatedAt: iso('2026-01-02T00:00:00.000Z'),
        },
      ],
      [
        'org_target',
        {
          id: 'proj_target',
          name: 'Target Project',
          slug: 'target-project',
          status: 'ACTIVE',
          environmentCount: 1,
          createdAt: iso('2026-01-03T00:00:00.000Z'),
          updatedAt: iso('2026-01-04T00:00:00.000Z'),
        },
      ],
    ]);
    const environmentByProject = new Map<string, Record<string, unknown>>([
      [
        'proj_current',
        {
          id: 'env_current',
          projectId: 'proj_current',
          key: 'prod',
          name: 'Current Environment',
          status: 'ACTIVE',
          createdAt: iso('2026-01-01T00:00:00.000Z'),
          updatedAt: iso('2026-01-02T00:00:00.000Z'),
        },
      ],
      [
        'proj_target',
        {
          id: 'env_target',
          projectId: 'proj_target',
          key: 'prod',
          name: 'Target Environment',
          status: 'ACTIVE',
          createdAt: iso('2026-01-03T00:00:00.000Z'),
          updatedAt: iso('2026-01-04T00:00:00.000Z'),
        },
      ],
    ]);
    let activeOrgId = 'org_current';
    let sessionClaims: Record<string, unknown> = {
      userId: 'user_account_settings_flow',
      orgId: 'org_current',
      roles: ['owner', 'admin'],
      projectId: 'proj_current',
      environmentId: 'env_current',
      provider: 'passkey',
    };
    const createBodies: Record<string, unknown>[] = [];
    const renameBodies: Array<{ orgId: string; body: Record<string, unknown> }> = [];
    const transferBodies: Array<{ orgId: string; body: Record<string, unknown> }> = [];
    const switchBodies: Array<{ orgId: string; body: Record<string, unknown> }> = [];
    const billingOverviewOrgIds: string[] = [];
    const billingUsageOrgIds: string[] = [];
    const billingActivityOrgIds: string[] = [];
    const unstubbedConsoleRequests: string[] = [];

    const readOrganizations = (): Record<string, unknown>[] =>
      Array.from(organizations.values()).map((organization) => {
        const id = String(organization.id || '').trim();
        const projectId =
          id === activeOrgId
            ? String(sessionClaims.projectId || '').trim() || null
            : (organization.selectedProjectId as string | null | undefined) || null;
        const environmentId =
          id === activeOrgId
            ? String(sessionClaims.environmentId || '').trim() || null
            : (organization.selectedEnvironmentId as string | null | undefined) || null;
        const project =
          projectId && id
            ? projectByOrg.get(id) && String(projectByOrg.get(id)?.id || '').trim() === projectId
              ? projectByOrg.get(id) || null
              : null
            : null;
        const environment =
          projectId && environmentId
            ? environmentByProject.get(projectId) &&
              String(environmentByProject.get(projectId)?.id || '').trim() === environmentId
              ? environmentByProject.get(projectId) || null
              : null
            : null;
        return {
          ...organization,
          isCurrentOrg: id === activeOrgId,
          selectedProjectId: projectId,
          selectedProjectName:
            String(project?.name || '').trim() ||
            String(organization.selectedProjectName || '').trim() ||
            null,
          selectedEnvironmentId: environmentId,
          selectedEnvironmentName:
            String(environment?.name || '').trim() ||
            String(organization.selectedEnvironmentName || '').trim() ||
            null,
        };
      });

    const readOnboardingState = (): Record<string, unknown> => {
      const org = orgDetails.get(activeOrgId) || null;
      const project = projectByOrg.get(activeOrgId) || null;
      const environment = project
        ? environmentByProject.get(String(project.id || '').trim())
        : null;
      return {
        orgId: activeOrgId,
        organization: org,
        activeProjectCount: project ? 1 : 0,
        activeEnvironmentCount: environment ? 1 : 0,
        activeApiKeyCount: 1,
        hasOrganization: true,
        hasProject: Boolean(project),
        hasEnvironment: Boolean(environment),
        hasApiKey: true,
        accountReady: true,
        organizationReady: true,
        billingReady: true,
        projectReady: Boolean(project),
        onboardingComplete: Boolean(project && environment),
        currentStep: project && environment ? 'complete' : 'project',
        complete: Boolean(project && environment),
        selectedProjectId: project ? String(project.id || '').trim() : null,
        selectedEnvironmentId: environment ? String(environment.id || '').trim() : null,
      };
    };

    await page.addInitScript(() => {
      window.localStorage.setItem(
        'tatchi-dashboard-ui-state-v1',
        JSON.stringify({
          isSidebarExpanded: true,
          expandedGroups: {
            overview: true,
            administration: true,
            operationsSecurity: true,
            integrations: true,
            billing: true,
          },
          selectedContext: {
            organization: 'org_current',
            project: 'proj_current',
            environment: 'env_current',
            accountSettings: 'Account Settings',
          },
        }),
      );
    });

    await page.route(`${consoleOrigin}/console/**`, async (route) => {
      const req = route.request();
      const method = req.method().toUpperCase();
      const url = new URL(req.url());
      const { pathname } = url;

      if (pathname === '/console/session' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            claims: sessionClaims,
          }),
        });
        return;
      }

      if (pathname === '/console/onboarding/state' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            state: readOnboardingState(),
          }),
        });
        return;
      }

      if (pathname === '/console/org' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            org: orgDetails.get(activeOrgId),
          }),
        });
        return;
      }

      if (pathname === '/console/projects' && method === 'GET') {
        const project = projectByOrg.get(activeOrgId);
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            projects: project ? [project] : [],
          }),
        });
        return;
      }

      if (pathname === '/console/environments' && method === 'GET') {
        const projectId = String(url.searchParams.get('projectId') || '').trim();
        const environment = environmentByProject.get(projectId);
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            environments: environment ? [environment] : [],
          }),
        });
        return;
      }

      if (pathname === '/console/account/profile' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            profile: accountProfile,
          }),
        });
        return;
      }

      if (pathname === '/console/account/organizations' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            organizations: readOrganizations(),
          }),
        });
        return;
      }

      if (pathname === '/console/account/organizations' && method === 'POST') {
        const body = parseJsonBody(req.postData());
        createBodies.push(body);
        const createdOrgId = String(body.id || '').trim() || 'org_created';
        const createdOrgName = String(body.name || '').trim() || createdOrgId;
        const createdOrganization = {
          id: createdOrgId,
          name: createdOrgName,
          slug:
            String(body.slug || '').trim() ||
            createdOrgName
              .toLowerCase()
              .replace(/[^a-z0-9]+/g, '-')
              .replace(/^-+|-+$/g, ''),
          status: 'ACTIVE',
          createdAt: iso('2026-01-05T00:00:00.000Z'),
          updatedAt: iso('2026-01-05T00:00:00.000Z'),
          actorRoles: ['owner', 'admin'],
          actorIsOwner: true,
          actorIsAdmin: true,
          onboardingComplete: false,
          selectedProjectId: null,
          selectedProjectName: null,
          selectedEnvironmentId: null,
          selectedEnvironmentName: null,
          adminCandidates: [],
        };
        organizations.set(createdOrgId, createdOrganization);
        orgDetails.set(createdOrgId, {
          id: createdOrgId,
          name: createdOrganization.name,
          slug: createdOrganization.slug,
          status: 'ACTIVE',
          createdAt: createdOrganization.createdAt,
          updatedAt: createdOrganization.updatedAt,
        });
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            organization: {
              ...createdOrganization,
              isCurrentOrg: false,
            },
          }),
        });
        return;
      }

      const accountOrgMatch = pathname.match(
        /^\/console\/account\/organizations\/([^/]+?)(?:\/(transfer-owner|switch-context))?$/,
      );
      const orgId = accountOrgMatch?.[1] ? decodeURIComponent(accountOrgMatch[1]) : '';
      const action = String(accountOrgMatch?.[2] || '').trim();
      if (orgId && method === 'PATCH' && !action) {
        const body = parseJsonBody(req.postData());
        renameBodies.push({ orgId, body });
        const organization = organizations.get(orgId);
        if (organization) {
          const nextName = String(body.name || organization.name || '').trim();
          const updatedOrganization = {
            ...organization,
            ...(nextName ? { name: nextName } : {}),
            updatedAt: iso('2026-01-06T00:00:00.000Z'),
          };
          organizations.set(orgId, updatedOrganization);
          const details = orgDetails.get(orgId);
          if (details) {
            orgDetails.set(orgId, {
              ...details,
              ...(nextName ? { name: nextName } : {}),
              updatedAt: iso('2026-01-06T00:00:00.000Z'),
            });
          }
        }
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            organization: {
              ...(organizations.get(orgId) || {}),
              isCurrentOrg: orgId === activeOrgId,
            },
          }),
        });
        return;
      }

      if (orgId && method === 'POST' && action === 'transfer-owner') {
        const body = parseJsonBody(req.postData());
        transferBodies.push({ orgId, body });
        const organization = organizations.get(orgId);
        if (organization) {
          organizations.set(orgId, {
            ...organization,
            actorRoles: ['admin'],
            actorIsOwner: false,
            actorIsAdmin: true,
            updatedAt: iso('2026-01-07T00:00:00.000Z'),
          });
        }
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            transfer: {
              organization: {
                ...(organizations.get(orgId) || {}),
                isCurrentOrg: orgId === activeOrgId,
              },
              previousOwner: {
                memberId: 'member_actor',
                userId: 'user_account_settings_flow',
                email: 'account-flow@example.com',
                displayName: 'Account Flow User',
                isOwner: false,
              },
              nextOwner: {
                memberId: 'member_target_admin',
                userId: 'user_target_admin',
                email: 'target-admin@example.com',
                displayName: 'Target Admin',
                isOwner: true,
              },
            },
          }),
        });
        return;
      }

      if (orgId && method === 'POST' && action === 'switch-context') {
        const body = parseJsonBody(req.postData());
        switchBodies.push({ orgId, body });
        const organization = organizations.get(orgId);
        const project = projectByOrg.get(orgId);
        const environment = project
          ? environmentByProject.get(String(project.id || '').trim())
          : null;
        activeOrgId = orgId;
        sessionClaims = {
          userId: 'user_account_settings_flow',
          orgId,
          roles: (organization?.actorRoles as string[] | undefined)?.filter(
            (role) => role === 'owner' || role === 'admin',
          ) || ['admin'],
          projectId: project ? String(project.id || '').trim() : '',
          environmentId: environment ? String(environment.id || '').trim() : '',
          provider: 'passkey',
        };
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            context: {
              orgId,
              projectId: project ? String(project.id || '').trim() : null,
              environmentId: environment ? String(environment.id || '').trim() : null,
              actorRoles: sessionClaims.roles,
              onboardingComplete: Boolean(organization?.onboardingComplete),
            },
          }),
        });
        return;
      }

      if (pathname === '/console/billing/overview' && method === 'GET') {
        billingOverviewOrgIds.push(activeOrgId);
        const isTargetOrg = activeOrgId === 'org_target';
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            overview: {
              usageMetricVersion: 'v1',
              currentMonthUtc: '2026-03',
              monthlyActiveWallets: isTargetOrg ? 9 : 4,
              creditBalanceMinor: isTargetOrg ? 275000 : 150000,
              lowBalanceThresholdMinor: 10000,
              recentUsageDebitMinor: isTargetOrg ? 6400 : 2400,
              recentCreditPurchasedMinor: isTargetOrg ? 55000 : 25000,
              documentCount: 1,
            },
          }),
        });
        return;
      }

      if (pathname === '/console/billing/usage/monthly-active-wallets' && method === 'GET') {
        billingUsageOrgIds.push(activeOrgId);
        const isTargetOrg = activeOrgId === 'org_target';
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            usage: {
              usageMetricVersion: 'v1',
              monthUtc: '2026-03',
              monthlyActiveWallets: isTargetOrg ? 9 : 4,
            },
          }),
        });
        return;
      }

      if (pathname === '/console/billing/account/activity' && method === 'GET') {
        billingActivityOrgIds.push(activeOrgId);
        const isTargetOrg = activeOrgId === 'org_target';
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            activity: {
              entries: isTargetOrg
                ? [
                    {
                      id: 'ledger_target_1',
                      orgId: 'org_target',
                      type: 'CREDIT_PURCHASE',
                      amountMinor: 55000,
                      currency: 'USD',
                      description: 'Top-up for target org',
                      actorType: 'USER',
                      actorUserId: 'user_account_settings_flow',
                      reasonCode: null,
                      note: null,
                      idempotencyKey: null,
                      createdAt: iso('2026-01-08T00:00:00.000Z'),
                    },
                  ]
                : [],
            },
          }),
        });
        return;
      }

      await route.fulfill({
        status: 404,
        contentType: 'application/json',
        body: JSON.stringify({
          ok: false,
          code: 'not_stubbed',
          path: pathname,
          method,
        }),
      });
      unstubbedConsoleRequests.push(`${method} ${pathname}`);
    });

    await page.goto('/dashboard/account-settings');
    expect(unstubbedConsoleRequests).toEqual([]);
    await expect(page.getByRole('heading', { name: 'Profile' })).toBeVisible();

    await page.getByRole('button', { name: 'Create an organisation' }).click();
    await expect.poll(() => new URL(page.url()).pathname).toBe('/dashboard/onboarding');
    await expect.poll(() => new URL(page.url()).search).toBe('?createOrganization=1');
    await expect.poll(() => createBodies.length).toBe(0);
    await expect.poll(() => switchBodies.length).toBe(0);
    await expect(page.locator('.dashboard-topbar__focused-value')).toHaveText('Current Org');
    await expect(page.getByRole('heading', { name: 'Name your organization' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Create your first project' })).toHaveCount(0);

    await page.getByLabel('Organization name').fill('Fresh Org');
    await page.getByRole('button', { name: 'Continue to project setup' }).click();

    await expect.poll(() => createBodies.length).toBe(1);
    expect(createBodies[0]).toMatchObject({
      name: 'Fresh Org',
      slug: 'fresh-org',
    });
    expect(String(createBodies[0]?.id || '')).toBe('');
    await expect.poll(() => switchBodies.length).toBe(1);
    expect(switchBodies[0]).toMatchObject({
      orgId: 'org_created',
      body: {},
    });
    await expect.poll(() => new URL(page.url()).pathname).toBe('/dashboard/onboarding');
    await expect.poll(() => new URL(page.url()).search).toBe('');
    await expect(page.locator('.dashboard-topbar__focused-value')).toHaveText('Fresh Org');
    await expect(page.getByRole('heading', { name: 'Create your first project' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Name your organization' })).toHaveCount(0);
  });

  test('account settings omits primary email updates when provider marks it read-only', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    let profileUpdateBody: Record<string, unknown> | null = null;

    await page.route(`${consoleOrigin}/console/**`, async (route) => {
      const req = route.request();
      const method = req.method().toUpperCase();
      const pathname = new URL(req.url()).pathname;

      if (pathname === '/console/session') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            claims: {
              userId: 'user_account_settings_read_only',
              orgId: 'org_account_settings_read_only',
              roles: ['owner', 'admin'],
              projectId: 'proj_account_settings_read_only',
              environmentId: 'env_account_settings_read_only',
              provider: 'oidc',
            },
          }),
        });
        return;
      }

      if (pathname === '/console/onboarding/state' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            state: {
              orgId: 'org_account_settings_read_only',
              organization: {
                id: 'org_account_settings_read_only',
                name: 'Read Only Org',
                slug: 'read-only-org',
                status: 'ACTIVE',
                createdAt: iso('2026-01-01T00:00:00.000Z'),
                updatedAt: iso('2026-01-01T00:00:00.000Z'),
              },
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
              selectedProjectId: 'proj_account_settings_read_only',
              selectedEnvironmentId: 'env_account_settings_read_only',
            },
          }),
        });
        return;
      }

      if (pathname === '/console/org' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            org: {
              id: 'org_account_settings_read_only',
              name: 'Read Only Org',
              slug: 'read-only-org',
              status: 'ACTIVE',
              createdAt: iso('2026-01-01T00:00:00.000Z'),
              updatedAt: iso('2026-01-01T00:00:00.000Z'),
            },
          }),
        });
        return;
      }

      if (pathname === '/console/projects' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            projects: [
              {
                id: 'proj_account_settings_read_only',
                name: 'Read Only Project',
                slug: 'read-only-project',
                status: 'ACTIVE',
                environmentCount: 1,
                createdAt: iso('2026-01-01T00:00:00.000Z'),
                updatedAt: iso('2026-01-01T00:00:00.000Z'),
              },
            ],
          }),
        });
        return;
      }

      if (pathname === '/console/environments' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            environments: [
              {
                id: 'env_account_settings_read_only',
                projectId: 'proj_account_settings_read_only',
                key: 'prod',
                name: 'Read Only Environment',
                status: 'ACTIVE',
                createdAt: iso('2026-01-01T00:00:00.000Z'),
                updatedAt: iso('2026-01-01T00:00:00.000Z'),
              },
            ],
          }),
        });
        return;
      }

      if (pathname === '/console/account/profile' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            profile: {
              userId: 'user_account_settings_read_only',
              displayName: 'OIDC User',
              primaryEmail: 'oidc-user@example.com',
              canEditPrimaryEmail: false,
              backupEmails: [],
              createdAt: iso('2026-01-01T00:00:00.000Z'),
              updatedAt: iso('2026-01-01T00:00:00.000Z'),
            },
          }),
        });
        return;
      }

      if (pathname === '/console/account/profile' && method === 'PATCH') {
        profileUpdateBody = parseJsonBody(req.postData());
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            profile: {
              userId: 'user_account_settings_read_only',
              displayName: String(profileUpdateBody.displayName || '').trim() || 'OIDC User',
              primaryEmail: 'oidc-user@example.com',
              canEditPrimaryEmail: false,
              backupEmails: [],
              createdAt: iso('2026-01-01T00:00:00.000Z'),
              updatedAt: iso('2026-01-02T00:00:00.000Z'),
            },
          }),
        });
        return;
      }

      if (pathname === '/console/account/organizations' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, organizations: [] }),
        });
        return;
      }

      if (pathname === '/console/billing/overview' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            overview: {
              usageMetricVersion: 'v1',
              currentMonthUtc: '2026-03',
              monthlyActiveWallets: 1,
              creditBalanceMinor: 0,
              lowBalanceThresholdMinor: 10000,
              recentUsageDebitMinor: 0,
              recentCreditPurchasedMinor: 0,
              documentCount: 0,
            },
          }),
        });
        return;
      }

      if (pathname === '/console/billing/account/activity' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            activity: {
              entries: [],
            },
          }),
        });
        return;
      }

      await route.fulfill({
        status: 404,
        contentType: 'application/json',
        body: JSON.stringify({
          ok: false,
          code: 'not_stubbed',
          path: pathname,
          method,
        }),
      });
    });

    await page.goto('/dashboard/account-settings');
    await expect(page.getByRole('heading', { name: 'Profile' })).toBeVisible();
    await expect(
      page.getByText(/primary email is managed by your identity provider/i),
    ).toBeVisible();
    await page.getByRole('button', { name: 'Edit' }).click();
    await expect(page.getByLabel('Edit profile modal')).toBeVisible();
    await expect(page.getByLabel('Primary email (read-only)')).toBeDisabled();

    await page.getByLabel('Display name').fill('OIDC User Renamed');
    await page.getByRole('button', { name: 'Save' }).click();
    await expect.poll(() => profileUpdateBody).not.toBeNull();
    expect(profileUpdateBody).toMatchObject({
      displayName: 'OIDC User Renamed',
    });
    expect(Object.prototype.hasOwnProperty.call(profileUpdateBody || {}, 'primaryEmail')).toBe(
      false,
    );
  });

  test('account settings menu toggles dark and light theme', async ({ page, baseURL }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;

    await page.addInitScript(() => {
      window.localStorage.setItem('tatchi-site-theme', 'dark');
    });

    await page.route(`${consoleOrigin}/console/**`, async (route) => {
      const req = route.request();
      const method = req.method().toUpperCase();
      const pathname = new URL(req.url()).pathname;

      if (pathname === '/console/session') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            claims: {
              userId: 'user-theme-test',
              orgId: 'org-theme-test',
              roles: ['admin'],
              projectId: 'proj-theme-test',
              environmentId: 'env-theme-test',
            },
          }),
        });
        return;
      }

      if (pathname === '/console/onboarding/state' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            state: {
              orgId: 'org-theme-test',
              organization: null,
              activeProjectCount: 0,
              activeEnvironmentCount: 0,
              activeApiKeyCount: 0,
              hasOrganization: false,
              hasProject: false,
              hasEnvironment: false,
              hasApiKey: false,
              accountReady: true,
              organizationReady: false,
              billingReady: false,
              projectReady: false,
              onboardingComplete: false,
              currentStep: 'organization',
              complete: false,
              selectedProjectId: null,
              selectedEnvironmentId: null,
            },
          }),
        });
        return;
      }

      await route.fulfill({
        status: 404,
        contentType: 'application/json',
        body: JSON.stringify({
          ok: false,
          code: 'not_stubbed',
          path: pathname,
          method,
        }),
      });
    });

    await page.goto('/dashboard/onboarding');
    await expect(page.locator('main[aria-label="Dashboard workspace"]')).toBeVisible();
    await expect
      .poll(() => page.evaluate(() => document.documentElement.getAttribute('data-w3a-theme')))
      .toBe('dark');

    await page.getByRole('button', { name: /account.*settings/i }).click();
    await page.getByRole('menuitem', { name: /toggle theme/i }).click();

    await expect
      .poll(() => page.evaluate(() => document.documentElement.getAttribute('data-w3a-theme')))
      .toBe('light');
    await expect(page.locator('[aria-label="Account and Settings options"]')).toBeVisible();
    await expect(page.getByRole('menuitem', { name: /toggle theme/i })).toBeVisible();
    await expect
      .poll(() => page.evaluate(() => window.localStorage.getItem('tatchi-site-theme')))
      .toBe('light');

    await page.getByRole('menuitem', { name: /toggle theme/i }).click();

    await expect
      .poll(() => page.evaluate(() => document.documentElement.getAttribute('data-w3a-theme')))
      .toBe('dark');
    await expect
      .poll(() => page.evaluate(() => window.localStorage.getItem('tatchi-site-theme')))
      .toBe('dark');
  });

  test('restores persisted project and environment context after reload', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    const context = buildMockDashboardContext();
    const persistedProject = {
      id: 'proj_saved',
      name: 'Project Saved',
      slug: 'project-saved',
      status: 'ACTIVE',
      environmentCount: 1,
      createdAt: iso('2026-01-01T00:00:00.000Z'),
      updatedAt: iso('2026-01-05T00:00:00.000Z'),
    };
    const persistedEnvironment = {
      id: 'env_saved',
      projectId: 'proj_saved',
      key: 'staging',
      name: 'Saved Stage',
      status: 'ACTIVE',
      createdAt: iso('2026-01-01T00:00:00.000Z'),
      updatedAt: iso('2026-01-05T00:00:00.000Z'),
    };
    const walletRequestUrls: string[] = [];

    await page.addInitScript(() => {
      window.localStorage.setItem(
        'tatchi-dashboard-ui-state-v1',
        JSON.stringify({
          isSidebarExpanded: true,
          expandedGroups: {
            walletInfrastructure: true,
            securityPolicy: true,
            integrationsAutomation: true,
            environmentSettings: true,
          },
          selectedContext: {
            organization: 'org_dash_console_pages',
            project: 'proj_saved',
            environment: 'env_saved',
            accountSettings: 'Account Settings',
          },
        }),
      );
    });

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

      if (pathname === '/console/onboarding/state' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            state: {
              orgId: 'org_dash_console_pages',
              organization: context.org,
              activeProjectCount: 2,
              activeEnvironmentCount: 2,
              activeApiKeyCount: 1,
              hasOrganization: true,
              hasProject: true,
              hasEnvironment: true,
              hasApiKey: true,
              accountReady: true,
              organizationReady: true,
              billingReady: false,
              projectReady: true,
              onboardingComplete: true,
              currentStep: 'complete',
              complete: true,
              selectedProjectId: 'proj_saved',
              selectedEnvironmentId: 'env_saved',
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
          body: JSON.stringify({
            ok: true,
            projects: [context.activeProject, persistedProject],
          }),
        });
        return;
      }

      if (pathname === '/console/environments') {
        const projectId = String(url.searchParams.get('projectId') || '').trim();
        const environments =
          projectId === 'proj_saved'
            ? [persistedEnvironment]
            : projectId === 'proj_active'
              ? [context.activeEnvironment]
              : [context.activeEnvironment, persistedEnvironment];
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, environments }),
        });
        return;
      }

      if (pathname === '/console/wallets' && method === 'GET') {
        walletRequestUrls.push(url.toString());
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            wallets: [],
            nextCursor: null,
          }),
        });
        return;
      }

      if (pathname === '/console/policies' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            policies: [],
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

    await page.goto('/dashboard/wallets-list');
    await expect(page.locator('#dashboard-main-title')).toHaveText(/user wallets list/i);

    const topbarContext = page.locator('header[aria-label="Workspace context"]');
    await expect(topbarContext.locator('button:has-text("Project")')).toContainText(
      'Project Saved',
    );
    await expect(topbarContext.locator('button.dashboard-context-card--highlight')).toContainText(
      'Saved Stage',
    );

    const walletSummary = page.locator('section[aria-label="Wallet summary metrics"]');
    await expect(walletSummary.locator('.dashboard-wallet-summary__item')).toHaveCount(3);
    await expect(walletSummary).toContainText('#wallets');
    await expect(walletSummary).toContainText('#funded wallets');
    await expect(walletSummary).toContainText('#active wallets');
    await expect(walletSummary).not.toContainText('Recently active');
    await expect(walletSummary).not.toContainText('Chains represented');

    await expect
      .poll(() =>
        walletRequestUrls.some((entry) => {
          const parsed = new URL(entry);
          return (
            parsed.searchParams.get('projectId') === 'proj_saved' &&
            parsed.searchParams.get('environmentId') === 'env_saved'
          );
        }),
      )
      .toBe(true);
  });

  test('environment dropdown keeps Production muted and routes to billing with notice when clicked', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    const context = buildMockDashboardContext();
    const developmentEnvironment = {
      id: 'proj_active:dev',
      projectId: 'proj_active',
      key: 'dev',
      name: 'Development',
      status: 'ACTIVE',
      createdAt: iso('2026-01-01T00:00:00.000Z'),
      updatedAt: iso('2026-01-05T00:00:00.000Z'),
    };
    const productionEnvironment = {
      id: 'proj_active:prod',
      projectId: 'proj_active',
      key: 'prod',
      name: 'Production',
      status: 'DISABLED',
      createdAt: iso('2026-01-01T00:00:00.000Z'),
      updatedAt: iso('2026-01-05T00:00:00.000Z'),
    };

    await page.route(`${consoleOrigin}/console/**`, async (route) => {
      const req = route.request();
      const method = req.method().toUpperCase();
      const url = new URL(req.url());
      const { pathname } = url;

      if (pathname === '/console/session' && method === 'GET') {
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
              environmentId: 'proj_active:dev',
            },
          }),
        });
        return;
      }

      if (pathname === '/console/onboarding/state' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            state: {
              orgId: 'org_dash_console_pages',
              organization: context.org,
              activeProjectCount: 1,
              activeEnvironmentCount: 1,
              activeApiKeyCount: 1,
              hasOrganization: true,
              hasProject: true,
              hasEnvironment: true,
              hasApiKey: true,
              accountReady: true,
              organizationReady: true,
              billingReady: false,
              projectReady: true,
              onboardingComplete: true,
              currentStep: 'complete',
              complete: true,
              selectedProjectId: 'proj_active',
              selectedEnvironmentId: 'proj_active:dev',
            },
          }),
        });
        return;
      }

      if (pathname === '/console/org' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, org: context.org }),
        });
        return;
      }

      if (pathname === '/console/projects' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, projects: [context.activeProject] }),
        });
        return;
      }

      if (pathname === '/console/environments' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            environments: [productionEnvironment, developmentEnvironment],
          }),
        });
        return;
      }

      if (pathname === '/console/wallets' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            wallets: [],
            nextCursor: null,
          }),
        });
        return;
      }

      if (pathname === '/console/policies' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, policies: [] }),
        });
        return;
      }

      if (method === 'GET' && pathname === '/console/billing/overview') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            overview: {
              usageMetricVersion: 'maw_v1',
              currentMonthUtc: '2026-03',
              monthlyActiveWallets: 0,
              creditBalanceMinor: 0,
              lowBalanceThresholdMinor: 2000,
              recentUsageDebitMinor: 0,
              recentCreditPurchasedMinor: 0,
              documentCount: 0,
            },
          }),
        });
        return;
      }

      if (method === 'GET' && pathname === '/console/billing/account/activity') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            activity: {
              entries: [],
            },
          }),
        });
        return;
      }

      if (method === 'GET' && pathname === '/console/billing/usage/monthly-active-wallets') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            usage: {
              usageMetricVersion: 'maw_v1',
              monthUtc: '2026-03',
              monthlyActiveWallets: 0,
            },
          }),
        });
        return;
      }

      if (method === 'GET' && pathname === '/console/billing/invoices') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, invoices: [] }),
        });
        return;
      }

      if (method === 'GET' && pathname === '/console/billing/stablecoins/assets') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, version: 'v1', assets: [] }),
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

    await page.goto('/dashboard/wallets-list');
    await expect(page.locator('#dashboard-main-title')).toHaveText(/user wallets list/i);

    const topbarContext = page.locator('header[aria-label="Workspace context"]');
    const environmentCard = topbarContext.locator('button.dashboard-context-card--highlight');
    await expect(environmentCard).toContainText('Development');
    await environmentCard.click();

    const environmentMenu = page.locator('[aria-label="Environment options"]');
    const developmentOption = environmentMenu.getByRole('menuitemradio', { name: 'Development' });
    const productionOption = environmentMenu.getByRole('menuitemradio', { name: 'Production' });
    await expect(developmentOption).toBeVisible();
    await expect(developmentOption).toBeEnabled();
    await expect(productionOption).toBeVisible();
    await expect(productionOption).toBeEnabled();
    await expect(productionOption).toHaveClass(/is-disabled/);

    await productionOption.click();
    await expect.poll(() => new URL(page.url()).pathname).toBe('/dashboard/billing/account');
    await expect(page.locator('#dashboard-main-title')).toHaveText(/billing/i);
    const billingWarningBanner = page.locator('.dashboard-warning-banner');
    await expect(billingWarningBanner).toContainText('Billing must be configured for production.');
    await billingWarningBanner.locator('button[aria-label="Dismiss billing warning"]').click();
    await expect(billingWarningBanner).toHaveCount(0);
  });

  test('wallets list filter dropdowns send chain, policy, wallet type, and sort params', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    const context = buildMockDashboardContext();
    const walletRequestUrls: string[] = [];

    await page.addInitScript(() => {
      window.localStorage.setItem(
        'tatchi-dashboard-ui-state-v1',
        JSON.stringify({
          isSidebarExpanded: true,
          expandedGroups: {
            walletInfrastructure: true,
            securityPolicy: true,
            integrationsAutomation: true,
            environmentSettings: true,
          },
          selectedContext: {
            organization: 'org_dash_console_pages',
            project: 'proj_active',
            environment: 'env_active',
            accountSettings: 'Account Settings',
          },
        }),
      );
    });

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

      if (pathname === '/console/onboarding/state' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            state: {
              orgId: 'org_dash_console_pages',
              organization: context.org,
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
              selectedProjectId: 'proj_active',
              selectedEnvironmentId: 'env_active',
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
          body: JSON.stringify({
            ok: true,
            projects: [context.activeProject],
          }),
        });
        return;
      }

      if (pathname === '/console/environments') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            environments: [context.activeEnvironment],
          }),
        });
        return;
      }

      if (pathname === '/console/policies' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            policies: [
              {
                id: 'policy_alpha',
                orgId: 'org_dash_console_pages',
                name: 'Alpha Policy',
                description: null,
                status: 'PUBLISHED',
                version: 3,
                rules: {},
                createdAt: iso('2026-01-01T00:00:00.000Z'),
                updatedAt: iso('2026-01-03T00:00:00.000Z'),
                publishedAt: iso('2026-01-03T00:00:00.000Z'),
              },
            ],
          }),
        });
        return;
      }

      if (pathname === '/console/wallets' && method === 'GET') {
        walletRequestUrls.push(url.toString());
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            wallets: [
              {
                id: 'wallet_alpha',
                address: '0xabc123',
                chain: 'Base',
                walletType: 'SMART',
                userId: 'user_alpha',
                policyId: 'policy_alpha',
                balanceMinor: 4200,
                status: 'ACTIVE',
                createdAt: iso('2026-01-01T00:00:00.000Z'),
                updatedAt: iso('2026-01-05T00:00:00.000Z'),
                lastActivityAt: iso('2026-01-06T00:00:00.000Z'),
              },
            ],
            nextCursor: null,
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

    await page.goto('/dashboard/wallets-list');
    await expect(page.locator('#dashboard-main-title')).toHaveText(/user wallets list/i);
    await expect(page.locator('section[aria-label="Wallets table"]')).toContainText('wallet_alpha');

    await page.getByRole('button', { name: 'All chains' }).click();
    await page.getByRole('menuitemradio', { name: 'Base' }).click();
    await expect
      .poll(() => {
        const parsed = new URL(walletRequestUrls[walletRequestUrls.length - 1] || consoleOrigin);
        return parsed.searchParams.get('chain');
      })
      .toBe('Base');

    await page.getByRole('button', { name: 'Any policy' }).click();
    await page.getByRole('menuitemradio', { name: 'Alpha Policy' }).click();
    await expect
      .poll(() => {
        const parsed = new URL(walletRequestUrls[walletRequestUrls.length - 1] || consoleOrigin);
        return parsed.searchParams.get('policyId');
      })
      .toBe('policy_alpha');

    await page.getByRole('button', { name: 'EOA + Smart' }).click();
    await page.getByRole('menuitemradio', { name: 'Smart only' }).click();
    await expect
      .poll(() => {
        const parsed = new URL(walletRequestUrls[walletRequestUrls.length - 1] || consoleOrigin);
        return parsed.searchParams.get('walletType');
      })
      .toBe('SMART');

    await page.getByRole('button', { name: 'Newest first' }).click();
    await page.getByRole('menuitemradio', { name: 'Highest balance' }).click();
    await expect
      .poll(() => {
        const parsed = new URL(walletRequestUrls[walletRequestUrls.length - 1] || consoleOrigin);
        return {
          sortBy: parsed.searchParams.get('sortBy'),
          sortOrder: parsed.searchParams.get('sortOrder'),
        };
      })
      .toEqual({ sortBy: 'balance', sortOrder: 'desc' });
  });

  test('onboarding route wires organization and project steps', async ({ page, baseURL }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    const context = buildMockDashboardContext();
    let sessionRequestCount = 0;
    let onboardingStateRequestCount = 0;
    let lastOrganizationBody: Record<string, unknown> | null = null;
    let lastProjectBody: Record<string, unknown> | null = null;
    const activeProjects: Record<string, unknown>[] = [context.activeProject];
    const activeEnvironments: Record<string, unknown>[] = [context.activeEnvironment];
    let onboardingState: Record<string, unknown> = {
      orgId: 'org_dash_console_pages',
      organization: null,
      activeProjectCount: 0,
      activeEnvironmentCount: 0,
      activeApiKeyCount: 0,
      hasOrganization: false,
      hasProject: false,
      hasEnvironment: false,
      hasApiKey: false,
      accountReady: true,
      organizationReady: false,
      billingReady: false,
      projectReady: false,
      onboardingComplete: false,
      currentStep: 'organization',
      complete: false,
      selectedProjectId: null,
      selectedEnvironmentId: null,
    };

    await page.route(`${consoleOrigin}/console/**`, async (route) => {
      const req = route.request();
      const method = req.method().toUpperCase();
      const url = new URL(req.url());
      const { pathname } = url;

      if (pathname === '/console/session') {
        sessionRequestCount += 1;
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
          body: JSON.stringify({ ok: true, projects: activeProjects }),
        });
        return;
      }

      if (pathname === '/console/environments') {
        const projectId = String(url.searchParams.get('projectId') || '').trim();
        const environments = projectId
          ? activeEnvironments.filter((entry) => String(entry.projectId || '') === projectId)
          : activeEnvironments;
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, environments }),
        });
        return;
      }

      if (pathname === '/console/onboarding/state' && method === 'GET') {
        onboardingStateRequestCount += 1;
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            state: onboardingState,
          }),
        });
        return;
      }

      if (pathname === '/console/onboarding/organization' && method === 'POST') {
        lastOrganizationBody = parseJsonBody(req.postData());
        onboardingState = {
          ...onboardingState,
          organization: context.org,
          hasOrganization: true,
          organizationReady: true,
          currentStep: 'project',
        };
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            result: {
              organization: context.org,
              created: {
                organization: true,
                owner: false,
              },
              state: onboardingState,
            },
          }),
        });
        return;
      }

      if (pathname === '/console/onboarding/project' && method === 'POST') {
        lastProjectBody = parseJsonBody(req.postData());
        const createdProject: Record<string, unknown> = {
          id: 'proj_consumer',
          name: 'Consumer App',
          slug: 'consumer-app',
          status: 'ACTIVE',
        };
        const createdEnvironment: Record<string, unknown> = {
          id: 'proj_consumer:dev',
          projectId: 'proj_consumer',
          key: 'dev',
          name: 'Development',
          status: 'ACTIVE',
        };
        activeProjects.unshift(createdProject);
        activeEnvironments.unshift(createdEnvironment);
        onboardingState = {
          ...onboardingState,
          activeProjectCount: 1,
          activeEnvironmentCount: 1,
          hasProject: true,
          hasEnvironment: true,
          projectReady: true,
          onboardingComplete: true,
          currentStep: 'complete',
          complete: true,
          selectedProjectId: 'proj_consumer',
          selectedEnvironmentId: 'proj_consumer:dev',
        };
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            result: {
              project: createdProject,
              environment: createdEnvironment,
              created: {
                project: true,
                environment: true,
              },
              state: onboardingState,
            },
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

    await page.goto('/dashboard/api-keys');
    await expect.poll(() => new URL(page.url()).pathname).toBe('/dashboard/onboarding');
    await expect.poll(() => sessionRequestCount).toBeGreaterThan(0);
    await expect.poll(() => onboardingStateRequestCount).toBeGreaterThan(0);
    const sidebar = page.locator('aside[aria-label="Primary dashboard navigation"]');
    await expect(sidebar).toBeVisible();
    await expect.poll(() => sidebar.locator('a.dashboard-nav-item').count()).toBeGreaterThan(0);
    await expect
      .poll(() =>
        sidebar.locator('a.dashboard-nav-item').evaluateAll(
          (items) =>
            items.length > 0 &&
            items.every((entry) => {
              const href = String(entry.getAttribute('href') || '');
              const isAccountSettings = href.endsWith('/dashboard/account-settings');
              if (isAccountSettings) {
                return (
                  entry.getAttribute('aria-disabled') !== 'true' &&
                  entry.getAttribute('tabindex') !== '-1'
                );
              }
              return (
                entry.getAttribute('aria-disabled') === 'true' &&
                entry.getAttribute('tabindex') === '-1'
              );
            }),
        ),
      )
      .toBe(true);
    const onboardingForm = page
      .locator('section[aria-label="Onboarding form"]:has(h2:has-text("Name your organization"))')
      .last();
    const projectPanel = page.locator('section[aria-label="Create project"]');
    await expect(projectPanel).toHaveCount(0);
    await expect(onboardingForm.locator('input[placeholder="Acme Wallets"]')).toBeVisible();
    await onboardingForm.locator('input[placeholder="Acme Wallets"]').fill('Acme Wallets');
    await onboardingForm.locator('button:has-text("Continue to project setup")').click();

    await expect
      .poll(() =>
        String((lastOrganizationBody?.org as Record<string, unknown> | undefined)?.name || ''),
      )
      .toBe('Acme Wallets');

    const projectForm = page
      .locator(
        'section[aria-label="Onboarding form"]:has(h2:has-text("Create your first project"))',
      )
      .last();
    await expect(onboardingForm).toHaveCount(0);
    await expect(projectForm.locator('label:has-text("Project name") input')).toBeVisible();
    await expect(projectForm.locator('button:has-text("Back")')).toBeVisible();
    await projectForm.locator('button:has-text("Back")').click();

    const organizationFormAfterBack = page
      .locator('section[aria-label="Onboarding form"]:has(h2:has-text("Name your organization"))')
      .last();
    await expect(organizationFormAfterBack).toBeVisible();
    await expect(
      organizationFormAfterBack.locator('input[placeholder="Acme Wallets"]'),
    ).toHaveValue('Acme Wallets');
    await expect(page.locator('section[aria-label="Create project"]')).toHaveCount(0);
    await organizationFormAfterBack.locator('button:has-text("Continue to project setup")').click();

    const projectFormAfterBack = page
      .locator(
        'section[aria-label="Onboarding form"]:has(h2:has-text("Create your first project"))',
      )
      .last();
    await expect(
      projectFormAfterBack.locator('label:has-text("Project name") input'),
    ).toBeVisible();
    await projectFormAfterBack.locator('label:has-text("Project name") input').fill('Consumer App');
    await expect(projectFormAfterBack.locator('text=Project ID (optional)')).toHaveCount(0);
    await expect(projectFormAfterBack.locator('text=Environment ID (optional)')).toHaveCount(0);
    await projectFormAfterBack.locator('button:has-text("Finish onboarding")').click();

    await expect
      .poll(() =>
        String((lastProjectBody?.project as Record<string, unknown> | undefined)?.name || ''),
      )
      .toBe('Consumer App');
    await expect
      .poll(() =>
        String((lastProjectBody?.project as Record<string, unknown> | undefined)?.id || ''),
      )
      .toBe('');
    await expect.poll(() => String(lastProjectBody?.environment || '')).toBe('');
    const completionSection = page.locator('section[aria-label="Onboarding completed"]').first();
    await expect(completionSection).toContainText('Onboarding complete');
    await completionSection.locator('button:has-text("Go to wallets")').click();
    await expect.poll(() => new URL(page.url()).pathname).toBe('/dashboard/wallets-list');
    await expect.poll(() => new URL(page.url()).search).toBe('');
  });

  test('onboarding prompts for organization name when org profile is still default', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    let lastOrganizationBody: Record<string, unknown> | null = null;
    let onboardingState: Record<string, unknown> = {
      orgId: 'org_dash_console_pages',
      organization: {
        id: 'org_dash_console_pages',
        name: 'org_dash_console_pages',
        slug: '',
        status: 'ACTIVE',
      },
      activeProjectCount: 0,
      activeEnvironmentCount: 0,
      activeApiKeyCount: 0,
      hasOrganization: true,
      hasProject: false,
      hasEnvironment: false,
      hasApiKey: false,
      accountReady: true,
      organizationReady: true,
      billingReady: false,
      projectReady: false,
      onboardingComplete: false,
      currentStep: 'project',
      complete: false,
      selectedProjectId: null,
      selectedEnvironmentId: null,
    };

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
              projectId: null,
              environmentId: null,
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
            org: {
              id: 'org_dash_console_pages',
              name: 'org_dash_console_pages',
              slug: '',
              status: 'ACTIVE',
            },
          }),
        });
        return;
      }

      if (pathname === '/console/projects' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, projects: [] }),
        });
        return;
      }

      if (pathname === '/console/environments' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, environments: [] }),
        });
        return;
      }

      if (pathname === '/console/onboarding/state' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            state: onboardingState,
          }),
        });
        return;
      }

      if (pathname === '/console/onboarding/organization' && method === 'POST') {
        lastOrganizationBody = parseJsonBody(req.postData());
        onboardingState = {
          ...onboardingState,
          organization: {
            id: 'org_dash_console_pages',
            name: 'Acme Org',
            slug: 'acme-org',
            status: 'ACTIVE',
          },
        };
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            result: {
              organization: onboardingState.organization,
              created: {
                organization: false,
                owner: false,
              },
              state: onboardingState,
            },
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

    await page.goto('/dashboard/onboarding');
    const onboardingForm = page
      .locator('section[aria-label="Onboarding form"]:has(h2:has-text("Name your organization"))')
      .last();
    await expect(onboardingForm.locator('input[placeholder="Acme Wallets"]')).toBeVisible();
    await expect(onboardingForm.locator('input[placeholder="Acme Wallets"]')).toHaveValue('');
    await expect(onboardingForm.locator('label:has-text("Organization slug") input')).toHaveValue(
      '',
    );
    await onboardingForm.locator('input[placeholder="Acme Wallets"]').fill('Acme Org');
    await expect(onboardingForm.locator('label:has-text("Organization slug") input')).toHaveValue(
      'acme-org',
    );
    await expect(
      onboardingForm.locator('label:has-text("Organization slug") input'),
    ).toBeDisabled();
    await onboardingForm.locator('button:has-text("Continue to project setup")').click();

    await expect
      .poll(() =>
        String((lastOrganizationBody?.org as Record<string, unknown> | undefined)?.name || ''),
      )
      .toBe('Acme Org');
  });

  test('onboarding allows explicitly keeping organization name equal to org id', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    let lastOrganizationBody: Record<string, unknown> | null = null;
    let onboardingState: Record<string, unknown> = {
      orgId: 'org_pick_same_name',
      organization: {
        id: 'org_pick_same_name',
        name: 'org_pick_same_name',
        slug: '',
        status: 'ACTIVE',
      },
      activeProjectCount: 0,
      activeEnvironmentCount: 0,
      activeApiKeyCount: 0,
      hasOrganization: true,
      hasProject: false,
      hasEnvironment: false,
      hasApiKey: false,
      accountReady: true,
      organizationReady: true,
      billingReady: false,
      projectReady: false,
      onboardingComplete: false,
      currentStep: 'project',
      complete: false,
      selectedProjectId: null,
      selectedEnvironmentId: null,
    };

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
              userId: 'user_pick_same_name',
              orgId: 'org_pick_same_name',
              roles: ['admin'],
              projectId: null,
              environmentId: null,
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
            org: {
              id: 'org_pick_same_name',
              name: 'org_pick_same_name',
              slug: '',
              status: 'ACTIVE',
            },
          }),
        });
        return;
      }

      if (pathname === '/console/projects' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, projects: [] }),
        });
        return;
      }

      if (pathname === '/console/environments' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, environments: [] }),
        });
        return;
      }

      if (pathname === '/console/onboarding/state' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            state: onboardingState,
          }),
        });
        return;
      }

      if (pathname === '/console/onboarding/organization' && method === 'POST') {
        lastOrganizationBody = parseJsonBody(req.postData());
        onboardingState = {
          ...onboardingState,
          organization: {
            id: 'org_pick_same_name',
            name: 'org_pick_same_name',
            slug: 'org-pick-same-name',
            status: 'ACTIVE',
          },
        };
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            result: {
              organization: onboardingState.organization,
              created: {
                organization: false,
                owner: false,
              },
              state: onboardingState,
            },
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

    await page.goto('/dashboard/onboarding');
    const onboardingForm = page
      .locator('section[aria-label="Onboarding form"]:has(h2:has-text("Name your organization"))')
      .last();
    await expect(onboardingForm.locator('input[placeholder="Acme Wallets"]')).toHaveValue('');
    await onboardingForm.locator('input[placeholder="Acme Wallets"]').fill('org_pick_same_name');
    await onboardingForm.locator('button:has-text("Continue to project setup")').click();

    await expect
      .poll(() =>
        String((lastOrganizationBody?.org as Record<string, unknown> | undefined)?.name || ''),
      )
      .toBe('org_pick_same_name');

    const projectForm = page
      .locator(
        'section[aria-label="Onboarding form"]:has(h2:has-text("Create your first project"))',
      )
      .last();
    await expect(projectForm).toBeVisible();
  });

  test('onboarding project step surfaces failure and allows retry recovery', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    const context = buildMockDashboardContext();
    let projectAttemptCount = 0;
    const activeProjects: Record<string, unknown>[] = [context.activeProject];
    const activeEnvironments: Record<string, unknown>[] = [context.activeEnvironment];
    let onboardingState: Record<string, unknown> = {
      orgId: 'org_dash_console_pages',
      organization: context.org,
      activeProjectCount: 0,
      activeEnvironmentCount: 0,
      activeApiKeyCount: 0,
      hasOrganization: true,
      hasProject: false,
      hasEnvironment: false,
      hasApiKey: false,
      accountReady: true,
      organizationReady: true,
      billingReady: false,
      projectReady: false,
      onboardingComplete: false,
      currentStep: 'project',
      complete: false,
      selectedProjectId: null,
      selectedEnvironmentId: null,
    };

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
          body: JSON.stringify({ ok: true, projects: activeProjects }),
        });
        return;
      }

      if (pathname === '/console/environments') {
        const projectId = String(url.searchParams.get('projectId') || '').trim();
        const environments = projectId
          ? activeEnvironments.filter((entry) => String(entry.projectId || '') === projectId)
          : activeEnvironments;
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, environments }),
        });
        return;
      }

      if (pathname === '/console/onboarding/state' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            state: onboardingState,
          }),
        });
        return;
      }

      if (pathname === '/console/onboarding/project' && method === 'POST') {
        projectAttemptCount += 1;
        if (projectAttemptCount === 1) {
          await route.fulfill({
            status: 500,
            contentType: 'application/json',
            body: JSON.stringify({
              ok: false,
              code: 'project_step_failed',
              message: 'project step failed on first attempt',
            }),
          });
          return;
        }

        const createdProject: Record<string, unknown> = {
          id: 'proj_retry',
          name: 'Retry Project',
          slug: 'retry-project',
          status: 'ACTIVE',
        };
        const createdEnvironment: Record<string, unknown> = {
          id: 'proj_retry:dev',
          projectId: 'proj_retry',
          key: 'dev',
          name: 'Development',
          status: 'ACTIVE',
        };
        activeProjects.unshift(createdProject);
        activeEnvironments.unshift(createdEnvironment);
        onboardingState = {
          ...onboardingState,
          activeProjectCount: 1,
          activeEnvironmentCount: 1,
          hasProject: true,
          hasEnvironment: true,
          projectReady: true,
          onboardingComplete: true,
          currentStep: 'complete',
          complete: true,
          selectedProjectId: 'proj_retry',
          selectedEnvironmentId: 'proj_retry:dev',
        };
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            result: {
              project: createdProject,
              environment: createdEnvironment,
              created: {
                project: true,
                environment: true,
              },
              state: onboardingState,
            },
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

    await page.goto('/dashboard/onboarding');
    const onboardingForm = page
      .locator(
        'section[aria-label="Onboarding form"]:has(h2:has-text("Create your first project"))',
      )
      .last();
    await expect(onboardingForm.locator('label:has-text("Project name") input')).toBeVisible();
    await onboardingForm.locator('label:has-text("Project name") input').fill('Retry Project');
    await onboardingForm.locator('button:has-text("Finish onboarding")').click();

    await expect(page.locator('section[aria-label="Onboarding form"]').first()).toContainText(
      'project step failed on first attempt',
    );

    await onboardingForm.locator('button:has-text("Retry")').click();
    await expect(page.locator('section[aria-label="Onboarding completed"]').first()).toContainText(
      'Onboarding complete',
    );
    await page
      .locator('section[aria-label="Onboarding completed"] button:has-text("Go to wallets")')
      .click();
    await expect.poll(() => new URL(page.url()).pathname).toBe('/dashboard/wallets-list');
    await expect.poll(() => new URL(page.url()).search).toBe('');
    await expect.poll(() => projectAttemptCount).toBe(2);
  });

  test('onboarding resumes project step after reload when organization is already completed', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    const context = buildMockDashboardContext();
    const activeProjects: Record<string, unknown>[] = [context.activeProject];
    const activeEnvironments: Record<string, unknown>[] = [context.activeEnvironment];
    let onboardingState: Record<string, unknown> = {
      orgId: 'org_dash_console_pages',
      organization: null,
      activeProjectCount: 0,
      activeEnvironmentCount: 0,
      activeApiKeyCount: 0,
      hasOrganization: false,
      hasProject: false,
      hasEnvironment: false,
      hasApiKey: false,
      accountReady: true,
      organizationReady: false,
      billingReady: false,
      projectReady: false,
      onboardingComplete: false,
      currentStep: 'organization',
      complete: false,
      selectedProjectId: null,
      selectedEnvironmentId: null,
    };

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
          body: JSON.stringify({ ok: true, projects: activeProjects }),
        });
        return;
      }

      if (pathname === '/console/environments') {
        const projectId = String(url.searchParams.get('projectId') || '').trim();
        const environments = projectId
          ? activeEnvironments.filter((entry) => String(entry.projectId || '') === projectId)
          : activeEnvironments;
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, environments }),
        });
        return;
      }

      if (pathname === '/console/onboarding/state' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            state: onboardingState,
          }),
        });
        return;
      }

      if (pathname === '/console/onboarding/organization' && method === 'POST') {
        onboardingState = {
          ...onboardingState,
          organization: context.org,
          hasOrganization: true,
          organizationReady: true,
          currentStep: 'project',
        };
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            result: {
              organization: context.org,
              created: {
                organization: true,
                owner: false,
              },
              state: onboardingState,
            },
          }),
        });
        return;
      }

      if (pathname === '/console/onboarding/project' && method === 'POST') {
        const createdProject: Record<string, unknown> = {
          id: 'proj_resume',
          name: 'Resume Project',
          slug: 'resume-project',
          status: 'ACTIVE',
        };
        const createdEnvironment: Record<string, unknown> = {
          id: 'proj_resume:dev',
          projectId: 'proj_resume',
          key: 'dev',
          name: 'Development',
          status: 'ACTIVE',
        };
        activeProjects.unshift(createdProject);
        activeEnvironments.unshift(createdEnvironment);
        onboardingState = {
          ...onboardingState,
          activeProjectCount: 1,
          activeEnvironmentCount: 1,
          hasProject: true,
          hasEnvironment: true,
          projectReady: true,
          onboardingComplete: true,
          currentStep: 'complete',
          complete: true,
          selectedProjectId: 'proj_resume',
          selectedEnvironmentId: 'proj_resume:dev',
        };
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            result: {
              project: createdProject,
              environment: createdEnvironment,
              created: {
                project: true,
                environment: true,
              },
              state: onboardingState,
            },
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

    await page.goto('/dashboard/onboarding');
    const organizationForm = page
      .locator('section[aria-label="Onboarding form"]:has(h2:has-text("Name your organization"))')
      .last();

    await expect(organizationForm.locator('input[placeholder="Acme Wallets"]')).toBeVisible();
    await organizationForm.locator('input[placeholder="Acme Wallets"]').fill('Resume Org');
    await organizationForm.locator('button:has-text("Continue to project setup")').click();

    const onboardingForm = page
      .locator(
        'section[aria-label="Onboarding form"]:has(h2:has-text("Create your first project"))',
      )
      .last();
    await expect(onboardingForm.locator('button:has-text("Finish onboarding")')).toBeDisabled();

    await page.reload();

    await expect(page.locator('section[aria-label="Onboarding form"]').first()).toBeVisible();
    await expect(onboardingForm.locator('button:has-text("Finish onboarding")')).toBeDisabled();

    await onboardingForm.locator('label:has-text("Project name") input').fill('Resume Project');
    await onboardingForm.locator('button:has-text("Finish onboarding")').click();
    await page
      .locator('section[aria-label="Onboarding completed"] button:has-text("Go to wallets")')
      .click();

    await expect.poll(() => new URL(page.url()).pathname).toBe('/dashboard/wallets-list');
    await expect.poll(() => new URL(page.url()).search).toBe('');
  });

  test('onboarding project step hides billing form fields and omits billing onboarding note', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    const context = buildMockDashboardContext();
    const onboardingState: Record<string, unknown> = {
      orgId: 'org_dash_console_pages',
      organization: context.org,
      activeProjectCount: 0,
      activeEnvironmentCount: 0,
      activeApiKeyCount: 0,
      hasOrganization: true,
      hasProject: false,
      hasEnvironment: false,
      hasApiKey: false,
      accountReady: true,
      organizationReady: true,
      billingReady: false,
      projectReady: false,
      onboardingComplete: false,
      currentStep: 'project',
      complete: false,
      selectedProjectId: null,
      selectedEnvironmentId: null,
    };

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

      if (pathname === '/console/account/organizations' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            organizations: [context.org],
          }),
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

      if (pathname === '/console/onboarding/state' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            state: onboardingState,
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

    await page.goto('/dashboard/onboarding');
    await expect(
      page
        .locator(
          'section[aria-label="Onboarding form"]:has(h2:has-text("Create your first project")) label:has-text("Project name") input',
        )
        .last(),
    ).toBeVisible();
    await expect(page.locator('label:has-text("Provider reference")')).toHaveCount(0);
    await expect(page.locator('section[aria-label="Onboarding form"]')).not.toContainText(
      'Billing is optional for onboarding. Add billing later to create staging/production environments.',
    );
  });

  test('gas sponsorship page wires create and validates scope requirements', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    const context = buildMockDashboardContext();
    const developmentEnvironment = {
      id: 'env_active',
      projectId: 'proj_active',
      key: 'dev',
      name: 'Development',
      status: 'ACTIVE',
      createdAt: iso('2026-01-01T00:00:00.000Z'),
      updatedAt: iso('2026-01-02T00:00:00.000Z'),
    };
    const productionEnvironment = {
      id: 'env_prod',
      projectId: 'proj_active',
      key: 'prod',
      name: 'Production',
      status: 'ACTIVE',
      createdAt: iso('2026-01-01T00:00:00.000Z'),
      updatedAt: iso('2026-01-03T00:00:00.000Z'),
    };
    const gasPolicies: any[] = [
      {
        id: 'gs_existing',
        name: 'Existing sponsorship',
        kind: 'evm_call',
        executionMode: 'evm_eoa',
        scopePolicyName: null,
        scopeType: 'ENVIRONMENT',
        projectId: 'proj_active',
        environmentId: developmentEnvironment.id,
        scopePolicyId: null,
        walletSegmentId: null,
        networkClass: 'TESTNET',
        enabled: true,
        spendCap: {
          mode: 'CHAIN_TOTAL',
          period: 'MONTHLY',
          capsByChain: [{ chainId: 42431, capMinor: 50000 }],
        },
        allowedCalls: [
          {
            chainId: 42431,
            to: '0xBB442B54c85efBa2D7B81eA52990ad638cDbA483',
            functionSignature: 'dripTo(address,address[])',
            selector: '0x867ae9d4',
            maxGasLimit: '1000000',
            maxValueWei: '0',
          },
        ],
        updatedAt: iso('2026-01-10T00:00:00.000Z'),
      },
    ];
    let lastGasCreateBody: Record<string, unknown> | null = null;
    const gasPolicyPatchCalls: Array<{ policyId: string; body: Record<string, unknown> }> = [];
    const toGasPolicy = (policy: (typeof gasPolicies)[number]) => ({
      id: String(policy.id || ''),
      orgId: 'org_dash_console_pages',
      isSystemDefault: false,
      kind: 'GAS_SPONSORSHIP',
      name: String(policy.name || 'Gas Sponsorship Policy'),
      description: null,
      status: 'PUBLISHED',
      version: 1,
      rules: {
        kind: String(policy.kind || 'evm_call'),
        scopeType: String(policy.scopeType || 'ENVIRONMENT'),
        projectId: policy.projectId ?? null,
        environmentId: policy.environmentId ?? null,
        scopePolicyId: policy.scopePolicyId ?? null,
        walletSegmentId: policy.walletSegmentId ?? null,
        templateId: policy.templateId ?? null,
        networkClass: String(policy.networkClass || 'ANY'),
        enabled: policy.enabled !== false,
        executionMode: String(policy.executionMode || 'evm_eoa'),
        spendCap:
          policy.spendCap && typeof policy.spendCap === 'object' && !Array.isArray(policy.spendCap)
            ? policy.spendCap
            : { mode: 'NONE', period: 'MONTHLY', capsByChain: [] },
        allowedCalls: Array.isArray(policy.allowedCalls) ? policy.allowedCalls : [],
        allowedDelegateActions: Array.isArray(policy.allowedDelegateActions)
          ? policy.allowedDelegateActions
          : [],
      },
      createdAt: String(policy.updatedAt || iso('2026-01-10T00:00:00.000Z')),
      updatedAt: String(policy.updatedAt || iso('2026-01-10T00:00:00.000Z')),
      publishedAt: String(policy.updatedAt || iso('2026-01-10T00:00:00.000Z')),
    });

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
              environmentId: developmentEnvironment.id,
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
        const projects =
          status === 'ACTIVE'
            ? [context.activeProject]
            : [context.activeProject, context.archivedProject];
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
        let environments = [developmentEnvironment, productionEnvironment];
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

      if (pathname === '/console/billing/overview' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            overview: {
              usageMetricVersion: 'maw_v1',
              currentMonthUtc: '2026-03',
              monthlyActiveWallets: 4,
              creditBalanceMinor: 0,
              lowBalanceThresholdMinor: 2000,
              reservedSponsorshipMinor: 1250,
              activeSponsorshipReservationCount: 2,
              trailing30DaySponsoredSpendMinor: 3100,
              trailing30DaySponsoredExecutionCount: 14,
              trailing90DaySponsoredSpendMinor: 8400,
              trailing90DaySponsoredExecutionCount: 37,
              recentUsageDebitMinor: 0,
              recentCreditPurchasedMinor: 0,
              documentCount: 0,
            },
          }),
        });
        return;
      }

      if (pathname === '/console/policies' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            policies: gasPolicies.map((entry) => toGasPolicy(entry)),
          }),
        });
        return;
      }

      if (pathname === '/console/policies' && method === 'POST') {
        const body = parseJsonBody(req.postData());
        lastGasCreateBody = body;
        const kind = String(body.kind || '').toUpperCase();
        const rules =
          body.rules && typeof body.rules === 'object' && !Array.isArray(body.rules)
            ? (body.rules as Record<string, unknown>)
            : {};
        const scopeType = String(rules.scopeType || '').toUpperCase();
        const environmentId = String(rules.environmentId || '').trim();
        if (kind !== 'GAS_SPONSORSHIP') {
          await route.fulfill({
            status: 400,
            contentType: 'application/json',
            body: JSON.stringify({
              ok: false,
              code: 'invalid_body',
              message: 'Field kind must be GAS_SPONSORSHIP',
            }),
          });
          return;
        }
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
          id: String(body.id || `policy_created_${Date.now()}`),
          name: String(body.name || 'Gas Sponsorship Policy'),
          kind: String(rules.kind || 'evm_call'),
          executionMode: String(
            rules.executionMode ||
              (String(rules.kind || 'evm_call') === 'near_delegate' ? 'near_delegate' : 'evm_eoa'),
          ),
          scopePolicyName: null,
          scopeType,
          projectId: rules.projectId ?? null,
          environmentId: rules.environmentId ?? null,
          scopePolicyId: rules.scopePolicyId ?? null,
          walletSegmentId: rules.walletSegmentId ?? null,
          networkClass: String(rules.networkClass || 'ANY'),
          enabled: rules.enabled !== false,
          spendCap:
            rules.spendCap && typeof rules.spendCap === 'object' && !Array.isArray(rules.spendCap)
              ? rules.spendCap
              : { mode: 'NONE', period: 'MONTHLY', capsByChain: [] },
          allowedCalls: Array.isArray(rules.allowedCalls) ? rules.allowedCalls : [],
          allowedDelegateActions: Array.isArray(rules.allowedDelegateActions)
            ? rules.allowedDelegateActions
            : [],
          updatedAt: now,
        };
        gasPolicies.unshift(created);
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, policy: toGasPolicy(created) }),
        });
        return;
      }

      const gasPatchMatch = pathname.match(/^\/console\/policies\/([^/]+)$/);
      if (gasPatchMatch && method === 'PATCH') {
        const body = parseJsonBody(req.postData());
        const rules =
          body.rules && typeof body.rules === 'object' && !Array.isArray(body.rules)
            ? (body.rules as Record<string, unknown>)
            : {};
        const policyId = decodeURIComponent(String(gasPatchMatch[1] || ''));
        gasPolicyPatchCalls.push({ policyId, body });
        const target = gasPolicies.find((entry) => String(entry.id || '') === policyId);
        if (!target) {
          await route.fulfill({
            status: 404,
            contentType: 'application/json',
            body: JSON.stringify({
              ok: false,
              code: 'policy_not_found',
              message: `Policy ${policyId} was not found`,
            }),
          });
          return;
        }
        if (rules.scopeType !== undefined) {
          target.scopeType = String(rules.scopeType || target.scopeType || 'ENVIRONMENT');
        }
        if (body.name !== undefined) {
          target.name = String(body.name || target.name || 'Gas Sponsorship Policy');
        }
        if (rules.projectId !== undefined) {
          target.projectId = rules.projectId ?? null;
        }
        if (rules.environmentId !== undefined) {
          target.environmentId = rules.environmentId ?? null;
        }
        if (rules.scopePolicyId !== undefined) {
          target.scopePolicyId = rules.scopePolicyId ?? null;
        }
        if (rules.walletSegmentId !== undefined) {
          target.walletSegmentId = rules.walletSegmentId ?? null;
        }
        if (rules.networkClass !== undefined) {
          target.networkClass = String(rules.networkClass || target.networkClass || 'ANY');
        }
        if (rules.executionMode !== undefined) {
          target.executionMode = String(
            rules.executionMode ||
              target.executionMode ||
              (target.kind === 'near_delegate' ? 'near_delegate' : 'evm_eoa'),
          );
        }
        if (rules.enabled !== undefined) {
          target.enabled = rules.enabled === true;
        }
        if (
          rules.spendCap &&
          typeof rules.spendCap === 'object' &&
          !Array.isArray(rules.spendCap)
        ) {
          target.spendCap = rules.spendCap;
        }
        if (Array.isArray(rules.allowedCalls)) {
          target.allowedCalls = rules.allowedCalls;
        }
        if (Array.isArray(rules.allowedDelegateActions)) {
          target.allowedDelegateActions = rules.allowedDelegateActions;
        }
        target.updatedAt = iso('2026-02-01T00:00:00.000Z');
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, policy: toGasPolicy(target) }),
        });
        return;
      }

      const gasPublishMatch = pathname.match(/^\/console\/policies\/([^/]+)\/publish$/);
      if (gasPublishMatch && method === 'POST') {
        const policyId = decodeURIComponent(String(gasPublishMatch[1] || ''));
        const target = gasPolicies.find((entry) => String(entry.id || '') === policyId);
        if (!target) {
          await route.fulfill({
            status: 404,
            contentType: 'application/json',
            body: JSON.stringify({
              ok: false,
              code: 'policy_not_found',
              message: `Policy ${policyId} was not found`,
            }),
          });
          return;
        }
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            result: {
              published: true,
              policy: toGasPolicy(target),
            },
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

    await page.goto('/dashboard/gas-sponsorship');
    await expect(page.locator('#dashboard-main-title')).toHaveText(/gas sponsorship/i);
    await expect(
      page.locator('section[aria-label="Gas sponsorship balance readiness"]'),
    ).toContainText('Sponsored execution is currently blocked');
    await expect(
      page.locator('section[aria-label="Gas sponsorship balance readiness"]'),
    ).toContainText('Org prepaid balance');
    await expect(
      page.locator('section[aria-label="Gas sponsorship balance readiness"] button'),
    ).toHaveText(/top up balance/i);
    await expect(page.locator('section[aria-label="Gas sponsorship policies"]')).toContainText(
      'Existing sponsorship',
    );
    const gasTableHeader = page.locator(
      'section[aria-label="Gas sponsorship policies"] .dashboard-gas-sponsorship-table__header',
    );
    await expect(gasTableHeader).toContainText('Environment');
    await expect(gasTableHeader).not.toContainText('Scope');
    const existingGasRowBeforeCreate = page
      .locator(
        'section[aria-label="Gas sponsorship policies"] .dashboard-gas-sponsorship-table__row',
      )
      .filter({ hasText: 'Existing sponsorship' })
      .first();
    await expect(existingGasRowBeforeCreate).toContainText('Development');
    await expect(existingGasRowBeforeCreate).not.toContainText(developmentEnvironment.id);

    const gasCreateSection = page.locator('section[aria-label="Gas sponsorship setup"]');
    await gasCreateSection.locator('button:has-text("Create policy")').click();

    const gasCreateModal = page.locator(
      'section[aria-label="Create gas sponsorship policy modal"]',
    );
    const gasPolicyNameInput = gasCreateModal.locator('label:has-text("Policy name") input');
    await gasPolicyNameInput.fill('Draft before close');
    await gasCreateModal.locator('button:has-text("Cancel")').click();

    await gasCreateSection.locator('button:has-text("Create policy")').click();
    await expect(gasPolicyNameInput).toHaveValue('Draft before close');
    await gasPolicyNameInput.fill('Draft before refresh');

    await page.reload();
    await expect(page.locator('#dashboard-main-title')).toHaveText(/gas sponsorship/i);
    await gasCreateSection.locator('button:has-text("Create policy")').click();
    const gasCreateModalAfterRefresh = page.locator(
      'section[aria-label="Create gas sponsorship policy modal"]',
    );
    const gasPolicyNameInputAfterRefresh = gasCreateModalAfterRefresh.locator(
      'label:has-text("Policy name") input',
    );
    await expect(gasPolicyNameInputAfterRefresh).toHaveValue('Draft before refresh');

    await gasPolicyNameInputAfterRefresh.fill('New sponsorship');
    const developmentTargetHeader = gasCreateModalAfterRefresh.locator(
      '.dashboard-gas-target-matrix__header',
    );
    await expect(developmentTargetHeader).toContainText('Testnet');
    await expect(developmentTargetHeader).not.toContainText('Mainnet');
    await expect(
      gasCreateModalAfterRefresh.getByRole('group', { name: 'Tempo Mainnet' }),
    ).toHaveCount(0);
    await expect(
      gasCreateModalAfterRefresh.getByRole('button', { name: 'All mainnets' }),
    ).toHaveCount(0);
    const tempoCreateRow = gasCreateModalAfterRefresh
      .locator('.dashboard-gas-target-matrix__row')
      .filter({ hasText: 'Tempo' });
    await tempoCreateRow.locator('.dashboard-gas-target-toggle__option').first().click();
    await gasCreateModalAfterRefresh.locator('button:has-text("Per chain total")').click();
    const tempoTestnetRow = gasCreateModalAfterRefresh
      .locator('.dashboard-gas-target-matrix__row')
      .filter({ hasText: 'Tempo' });
    await expect(tempoTestnetRow).toContainText('AlphaUSD');
    await gasCreateModalAfterRefresh.getByLabel('Tempo Testnet spend cap').fill('500.00');
    await gasCreateModalAfterRefresh.locator('button:has-text("Add contract")').click();
    await gasCreateModalAfterRefresh
      .locator('label:has-text("Contract address") input')
      .fill('0xBB442B54c85efBa2D7B81eA52990ad638cDbA483');
    await gasCreateModalAfterRefresh
      .locator('label:has-text("Function signature") input')
      .fill('dripTo(address,address[])');
    await gasCreateModalAfterRefresh
      .locator('label:has-text("Max gas limit") input')
      .fill('1000000');
    await gasCreateModalAfterRefresh.locator('label:has-text("Max value (wei)") input').fill('0');
    await gasCreateModalAfterRefresh
      .locator('button:has-text("Create sponsorship policy")')
      .click();

    await expect.poll(() => String(lastGasCreateBody?.kind || '')).toBe('GAS_SPONSORSHIP');
    await expect
      .poll(() =>
        String(
          (lastGasCreateBody?.rules &&
          typeof lastGasCreateBody.rules === 'object' &&
          !Array.isArray(lastGasCreateBody.rules)
            ? (lastGasCreateBody.rules as Record<string, unknown>).scopeType
            : '') || '',
        ),
      )
      .toBe('ENVIRONMENT');
    await expect
      .poll(() =>
        String(
          (lastGasCreateBody?.rules &&
          typeof lastGasCreateBody.rules === 'object' &&
          !Array.isArray(lastGasCreateBody.rules)
            ? (lastGasCreateBody.rules as Record<string, unknown>).environmentId
            : '') || '',
        ),
      )
      .toBe(developmentEnvironment.id);
    await expect
      .poll(() =>
        String(
          (lastGasCreateBody?.rules &&
          typeof lastGasCreateBody.rules === 'object' &&
          !Array.isArray(lastGasCreateBody.rules)
            ? (lastGasCreateBody.rules as Record<string, unknown>).networkClass
            : '') || '',
        ),
      )
      .toBe('TESTNET');
    await expect
      .poll(() =>
        String(
          (lastGasCreateBody?.rules &&
          typeof lastGasCreateBody.rules === 'object' &&
          !Array.isArray(lastGasCreateBody.rules)
            ? (lastGasCreateBody.rules as Record<string, unknown>).executionMode
            : '') || '',
        ),
      )
      .toBe('evm_eoa');
    await expect
      .poll(() =>
        String(
          lastGasCreateBody?.rules &&
            typeof lastGasCreateBody.rules === 'object' &&
            !Array.isArray(lastGasCreateBody.rules)
            ? (lastGasCreateBody.rules as Record<string, unknown>).kind
            : '',
        ),
      )
      .toBe('evm_call');
    await expect
      .poll(() => {
        const spendCap =
          lastGasCreateBody?.rules &&
          typeof lastGasCreateBody.rules === 'object' &&
          !Array.isArray(lastGasCreateBody.rules) &&
          (lastGasCreateBody.rules as Record<string, unknown>).spendCap &&
          typeof (lastGasCreateBody.rules as Record<string, unknown>).spendCap === 'object' &&
          !Array.isArray((lastGasCreateBody.rules as Record<string, unknown>).spendCap)
            ? ((lastGasCreateBody.rules as Record<string, unknown>).spendCap as {
                mode?: unknown;
                period?: unknown;
                capsByChain?: Array<{ chainId?: unknown; capMinor?: unknown }>;
              })
            : null;
        return JSON.stringify(spendCap || {});
      })
      .toBe(
        JSON.stringify({
          mode: 'CHAIN_TOTAL',
          period: 'MONTHLY',
          capsByChain: [{ chainId: 42431, capMinor: 50000 }],
        }),
      );
    await expect
      .poll(() =>
        Array.isArray(
          lastGasCreateBody?.rules &&
            typeof lastGasCreateBody.rules === 'object' &&
            !Array.isArray(lastGasCreateBody.rules)
            ? (lastGasCreateBody.rules as Record<string, unknown>).allowedCalls
            : null,
        )
          ? Array.from(
              new Set(
                (
                  (lastGasCreateBody!.rules as Record<string, unknown>).allowedCalls as Array<{
                    chainId?: unknown;
                  }>
                )
                  .map((entry) => String(entry.chainId || ''))
                  .filter(Boolean),
              ),
            )
              .sort()
              .join(',')
          : '',
      )
      .toBe('42431');
    await expect
      .poll(() => {
        const allowedCalls =
          lastGasCreateBody?.rules &&
          typeof lastGasCreateBody.rules === 'object' &&
          !Array.isArray(lastGasCreateBody.rules)
            ? ((lastGasCreateBody.rules as Record<string, unknown>).allowedCalls as Array<{
                functionSignature?: unknown;
                maxGasLimit?: unknown;
                maxValueWei?: unknown;
              }>)
            : [];
        return JSON.stringify(allowedCalls?.[0] || {});
      })
      .toBe(
        JSON.stringify({
          chainId: 42431,
          to: '0xBB442B54c85efBa2D7B81eA52990ad638cDbA483',
          functionSignature: 'dripTo(address,address[])',
          maxGasLimit: '1000000',
          maxValueWei: '0',
        }),
      );
    await expect(page.locator('section[aria-label="Gas sponsorship policies"]')).toContainText(
      'New sponsorship',
    );
    await expect
      .poll(() =>
        Array.isArray(
          lastGasCreateBody?.rules &&
            typeof lastGasCreateBody.rules === 'object' &&
            !Array.isArray(lastGasCreateBody.rules)
            ? (lastGasCreateBody.rules as Record<string, unknown>).allowedCalls
            : null,
        ),
      )
      .toBe(true);
    const newSponsorshipRow = page
      .locator(
        'section[aria-label="Gas sponsorship policies"] .dashboard-gas-sponsorship-table__row',
      )
      .filter({ hasText: 'New sponsorship' })
      .first();
    await expect(newSponsorshipRow).toContainText('500.00 AlphaUSD');

    await newSponsorshipRow.getByRole('button', { name: 'View' }).click();
    const gasViewModal = page.locator('section[aria-label="View gas sponsorship coverage modal"]');
    await expect(gasViewModal).toContainText('Tempo Testnet monthly cap 500.00 AlphaUSD total');
    await expect(gasViewModal).toContainText('dripTo(address,address[])');
    await expect(gasViewModal).toContainText('gas <= 1000000');
    await gasViewModal.locator('button:has-text("Close")').click();

    await newSponsorshipRow.getByRole('button', { name: 'Edit' }).click();
    const gasEditModal = page.locator('section[aria-label="Edit gas sponsorship policy modal"]');
    const tempoTestnetSpendCapInput = gasEditModal.getByLabel('Tempo Testnet spend cap');
    const tempoEditRow = gasEditModal
      .locator('.dashboard-gas-target-matrix__row')
      .filter({ hasText: 'Tempo' });
    await expect(tempoEditRow).toContainText('AlphaUSD');
    await expect(tempoTestnetSpendCapInput).toHaveValue('500.00');
    await tempoTestnetSpendCapInput.fill('500.123');
    await gasEditModal.locator('button:has-text("Save sponsorship policy")').click();
    await expect(gasEditModal).toContainText(
      'Tempo Testnet spend cap must be a non-negative amount with up to 2 decimal places.',
    );
    await expect.poll(() => gasPolicyPatchCalls.length).toBe(0);

    await tempoTestnetSpendCapInput.fill('725.50');
    await gasEditModal.locator('button:has-text("Save sponsorship policy")').click();
    await expect.poll(() => gasPolicyPatchCalls.length).toBe(1);
    expect(gasPolicyPatchCalls[0]?.body).toMatchObject({
      name: 'New sponsorship',
      rules: {
        networkClass: 'TESTNET',
        kind: 'evm_call',
        executionMode: 'evm_eoa',
        spendCap: {
          mode: 'CHAIN_TOTAL',
          period: 'MONTHLY',
          capsByChain: [{ chainId: 42431, capMinor: 72550 }],
        },
      },
    });
    await expect(newSponsorshipRow).toContainText('725.50 AlphaUSD');

    await gasCreateSection.locator('button:has-text("Create policy")').click();
    const nearCreateModal = page.locator(
      'section[aria-label="Create gas sponsorship policy modal"]',
    );
    await expect(nearCreateModal).toBeVisible();
    await nearCreateModal.locator('button:has-text("NEAR delegate")').click();
    await nearCreateModal.locator('label:has-text("Policy name") input').fill('NEAR sponsorship');
    await nearCreateModal.locator('button:has-text("Per chain total")').click();
    await nearCreateModal.getByLabel('NEAR Testnet spend cap').fill('120.00');
    await nearCreateModal.locator('button:has-text("Add delegate action")').click();
    await nearCreateModal.locator('label:has-text("Receiver ID") input').fill('guest-book.testnet');
    await nearCreateModal
      .locator('label:has-text("Max deposit (yoctoNEAR)") input')
      .fill('1000000000000000000000000');
    await nearCreateModal
      .locator('label:has-text("Allowed methods (comma or newline separated)") textarea')
      .fill('add_message, vote');
    await nearCreateModal
      .locator(
        'label:has-text("Allow native transfers in the delegate action") input[type="checkbox"]',
      )
      .check();
    await nearCreateModal.locator('button:has-text("Create sponsorship policy")').click();

    await expect
      .poll(() =>
        String(
          lastGasCreateBody?.rules &&
            typeof lastGasCreateBody.rules === 'object' &&
            !Array.isArray(lastGasCreateBody.rules)
            ? (lastGasCreateBody.rules as Record<string, unknown>).kind
            : '',
        ),
      )
      .toBe('near_delegate');
    await expect
      .poll(() =>
        String(
          lastGasCreateBody?.rules &&
            typeof lastGasCreateBody.rules === 'object' &&
            !Array.isArray(lastGasCreateBody.rules)
            ? (lastGasCreateBody.rules as Record<string, unknown>).executionMode
            : '',
        ),
      )
      .toBe('near_delegate');
    await expect
      .poll(() =>
        JSON.stringify(
          lastGasCreateBody?.rules &&
            typeof lastGasCreateBody.rules === 'object' &&
            !Array.isArray(lastGasCreateBody.rules)
            ? (lastGasCreateBody.rules as Record<string, unknown>).spendCap
            : null,
        ),
      )
      .toBe(
        JSON.stringify({
          mode: 'CHAIN_TOTAL',
          period: 'MONTHLY',
          capsByChain: [{ chainId: getNearSpendCapChainId('TESTNET'), capMinor: 12000 }],
        }),
      );
    await expect
      .poll(() =>
        JSON.stringify(
          lastGasCreateBody?.rules &&
            typeof lastGasCreateBody.rules === 'object' &&
            !Array.isArray(lastGasCreateBody.rules)
            ? (
                (lastGasCreateBody.rules as Record<string, unknown>).allowedDelegateActions as
                  | Array<unknown>
                  | undefined
              )?.[0] || null
            : null,
        ),
      )
      .toBe(
        JSON.stringify({
          receiverId: 'guest-book.testnet',
          methods: ['add_message', 'vote'],
          maxDepositYocto: '1000000000000000000000000',
          allowTransfers: true,
        }),
      );
    const nearSponsorshipRow = page
      .locator(
        'section[aria-label="Gas sponsorship policies"] .dashboard-gas-sponsorship-table__row',
      )
      .filter({ hasText: 'NEAR sponsorship' })
      .first();
    await expect(nearSponsorshipRow).toContainText('1 delegate action');
    await expect(nearSponsorshipRow).toContainText('Testnet / enabled');
    await expect(nearSponsorshipRow).toContainText('120.00 USD');

    await nearSponsorshipRow.getByRole('button', { name: 'View' }).click();
    const nearViewModal = page.locator('section[aria-label="View gas sponsorship coverage modal"]');
    await expect(nearViewModal).toContainText('guest-book.testnet');
    await expect(nearViewModal).toContainText('add_message, vote');
    await expect(nearViewModal).toContainText('transfers allowed');
    await expect(nearViewModal).toContainText('NEAR Testnet monthly cap 120.00 USD total');
    await nearViewModal.locator('button:has-text("Close")').click();

    await nearSponsorshipRow.getByRole('button', { name: 'Edit' }).click();
    const nearEditModal = page.locator('section[aria-label="Edit gas sponsorship policy modal"]');
    const nearDepositInput = nearEditModal.locator(
      'label:has-text("Max deposit (yoctoNEAR)") input',
    );
    const nearSpendCapInput = nearEditModal.getByLabel('NEAR Testnet spend cap');
    await expect(nearSpendCapInput).toHaveValue('120.00');
    await expect(nearDepositInput).toHaveValue('1000000000000000000000000');
    await nearSpendCapInput.fill('120.123');
    await nearEditModal.locator('button:has-text("Save sponsorship policy")').click();
    await expect(nearEditModal).toContainText(
      'NEAR Testnet spend cap must be a non-negative amount with up to 2 decimal places.',
    );
    await expect.poll(() => gasPolicyPatchCalls.length).toBe(1);
    await nearSpendCapInput.fill('200.50');
    await nearDepositInput.fill('2500000000000000000000000');
    await nearEditModal.locator('button:has-text("Save sponsorship policy")').click();
    await expect.poll(() => gasPolicyPatchCalls.length).toBe(2);
    expect(gasPolicyPatchCalls[1]?.body).toMatchObject({
      name: 'NEAR sponsorship',
      rules: {
        kind: 'near_delegate',
        executionMode: 'near_delegate',
        spendCap: {
          mode: 'CHAIN_TOTAL',
          period: 'MONTHLY',
          capsByChain: [{ chainId: getNearSpendCapChainId('TESTNET'), capMinor: 20050 }],
        },
        allowedDelegateActions: [
          {
            receiverId: 'guest-book.testnet',
            methods: ['add_message', 'vote'],
            maxDepositYocto: '2500000000000000000000000',
            allowTransfers: true,
          },
        ],
      },
    });

    const topbarContext = page.locator('header[aria-label="Workspace context"]');
    const environmentCard = topbarContext.locator('button.dashboard-context-card--highlight');
    await expect(environmentCard).toContainText('Development');
    await environmentCard.click();
    await page
      .locator('[aria-label="Environment options"]')
      .getByRole('menuitemradio', { name: 'Production' })
      .click();
    await expect(environmentCard).toContainText('Production');

    await gasCreateSection.locator('button:has-text("Create policy")').click();
    const gasCreateModalAfterEnvironmentSwitch = page.locator(
      'section[aria-label="Create gas sponsorship policy modal"]',
    );
    const productionTargetHeader = gasCreateModalAfterEnvironmentSwitch.locator(
      '.dashboard-gas-target-matrix__header',
    );
    await expect(
      gasCreateModalAfterEnvironmentSwitch.locator('label:has-text("Policy name") input'),
    ).toHaveValue('Project gas sponsorship');
    await expect(productionTargetHeader).toContainText('Mainnet');
    await expect(productionTargetHeader).not.toContainText('Testnet');
    await expect(
      gasCreateModalAfterEnvironmentSwitch
        .locator('.dashboard-gas-target-matrix__row')
        .filter({ hasText: 'Tempo' }),
    ).toContainText('Tempo');
    await expect(
      gasCreateModalAfterEnvironmentSwitch.getByRole('button', { name: 'All testnets' }),
    ).toHaveCount(0);
    await gasCreateModalAfterEnvironmentSwitch.locator('button:has-text("Cancel")').click();
    await environmentCard.click();
    await page
      .locator('[aria-label="Environment options"]')
      .getByRole('menuitemradio', { name: 'Development' })
      .click();
    await expect(environmentCard).toContainText('Development');

    const existingGasCard = page
      .locator(
        'section[aria-label="Gas sponsorship policies"] .dashboard-gas-sponsorship-table__row',
      )
      .filter({ hasText: 'Existing sponsorship' })
      .first();
    await existingGasCard.locator('button:has-text("Disable")').click();
    await expect.poll(() => gasPolicyPatchCalls.length).toBe(3);
    expect(gasPolicyPatchCalls[2]).toMatchObject({
      policyId: 'gs_existing',
      body: {
        rules: {
          enabled: false,
        },
      },
    });
    await expect(existingGasCard).toContainText('disabled');
  });

  test('policy-engine page schedules live policy changes through approvals', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    const context = buildMockDashboardContext();
    const policies: any[] = [
      {
        id: 'policy_draft_e2e',
        orgId: 'org_dash_console_pages',
        name: 'Draft Policy E2E',
        description: 'Draft policy for publish wiring test',
        status: 'DRAFT',
        version: 1,
        rules: {
          blockedActions: ['export_key'],
          allowedChains: ['Ethereum'],
          maxAmountMinor: 500000,
        },
        createdAt: iso('2026-02-01T00:00:00.000Z'),
        updatedAt: iso('2026-02-01T00:00:00.000Z'),
        publishedAt: iso('2026-01-15T00:00:00.000Z'),
      },
    ];
    const policyVersionsById: Record<string, any[]> = {
      policy_draft_e2e: [
        {
          policyId: 'policy_draft_e2e',
          version: 1,
          status: 'PUBLISHED',
          rules: {
            blockedActions: ['delete_key'],
            allowedChains: ['Ethereum', 'NEAR'],
            maxAmountMinor: 250000,
          },
          publishedAt: iso('2026-01-15T00:00:00.000Z'),
          createdAt: iso('2026-01-15T00:00:00.000Z'),
          actorUserId: 'approver_prev_policy_publish_e2e',
        },
      ],
    };
    const wallets: any[] = [
      {
        id: 'wallet_policy_publish_e2e_1',
        address: '0x1111111111111111111111111111111111111111',
        chain: 'Ethereum',
        userId: 'user_wallet_policy_publish_e2e_1',
        policyId: 'policy_draft_e2e',
        balanceMinor: 500000,
        status: 'ACTIVE',
        updatedAt: iso('2026-02-20T00:00:00.000Z'),
        lastActivityAt: iso('2026-02-20T00:00:00.000Z'),
      },
    ];
    const approvals: any[] = [
      {
        id: 'apr_policy_publish_e2e',
        orgId: 'org_dash_console_pages',
        operationType: 'POLICY_PUBLISH',
        status: 'APPROVED',
        reason: 'Ready to publish from e2e test',
        requestedByUserId: 'user_dash_console_pages',
        requiredApprovals: 1,
        requireMfa: false,
        projectId: 'proj_active',
        environmentId: 'env_active',
        resourceType: 'policy',
        resourceId: 'policy_draft_e2e',
        metadata: {},
        decisions: [
          {
            decision: 'APPROVE',
            actorUserId: 'approver_e2e',
            reason: 'Approved for test',
            mfaVerified: false,
            decidedAt: iso('2026-02-20T01:00:00.000Z'),
          },
        ],
        createdAt: iso('2026-02-20T00:30:00.000Z'),
        updatedAt: iso('2026-02-20T01:00:00.000Z'),
        resolvedAt: iso('2026-02-20T01:00:00.000Z'),
      },
    ];
    const assignments: any[] = [];
    let coverage: Record<string, unknown> = {
      scope: { projectId: 'proj_active', environmentId: 'env_active' },
      totals: {
        walletCount: 3,
        policyCount: 1,
        unassignedWalletCount: 0,
        activeWalletCount: 3,
        archivedWalletCount: 0,
      },
      policies: [
        {
          policyId: 'policy_draft_e2e',
          walletCount: 3,
          activeWalletCount: 3,
          archivedWalletCount: 0,
          totalBalanceMinor: 1500000,
          lastActivityAt: iso('2026-02-20T00:00:00.000Z'),
        },
      ],
      unassignedWalletSample: [],
      truncated: false,
    };
    let lastPublishBody: Record<string, unknown> | null = null;
    let lastPublishPolicyId = '';
    let lastPolicyCreateBody: Record<string, unknown> | null = null;

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

      if (pathname === '/console/account/organizations' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            organizations: [context.org],
          }),
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

      if (pathname === '/console/policy/coverage' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, coverage }),
        });
        return;
      }

      if (pathname === '/console/policies' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, policies }),
        });
        return;
      }

      const versionMatch = pathname.match(/^\/console\/policies\/([^/]+)\/versions$/);
      if (versionMatch && method === 'GET') {
        const policyId = decodeURIComponent(String(versionMatch[1] || ''));
        const versions = policyVersionsById[policyId];
        if (!versions) {
          await route.fulfill({
            status: 404,
            contentType: 'application/json',
            body: JSON.stringify({
              ok: false,
              code: 'policy_not_found',
              message: `Policy ${policyId} was not found`,
            }),
          });
          return;
        }
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, versions }),
        });
        return;
      }

      if (pathname === '/console/policies' && method === 'POST') {
        const body = parseJsonBody(req.postData());
        lastPolicyCreateBody = body;
        const createdAt = iso('2026-02-22T00:00:00.000Z');
        const created = {
          id: `policy_created_${policies.length + 1}`,
          orgId: 'org_dash_console_pages',
          name: String(body.name || `Created policy ${policies.length + 1}`),
          description: String(body.description || ''),
          status: 'DRAFT',
          version: 1,
          rules: isPlainObject(body.rules) ? body.rules : {},
          createdAt,
          updatedAt: createdAt,
          publishedAt: null,
        };
        policies.unshift(created);
        if (isPlainObject(body.assignment)) {
          assignments.unshift({
            id: `assignment_${created.id}`,
            orgId: 'org_dash_console_pages',
            scopeType: String(body.assignment.scopeType || ''),
            scopeId: String(body.assignment.scopeId || ''),
            policyId: created.id,
            createdAt,
            updatedAt: createdAt,
          });
        }
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, policy: created }),
        });
        return;
      }

      if (pathname === '/console/policies/assignments' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, assignments }),
        });
        return;
      }

      if (pathname === '/console/wallets' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, wallets }),
        });
        return;
      }

      if (pathname === '/console/approvals' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, approvals }),
        });
        return;
      }

      const publishMatch = pathname.match(/^\/console\/policies\/([^/]+)\/publish$/);
      if (publishMatch && method === 'POST') {
        const body = parseJsonBody(req.postData());
        lastPublishBody = body;
        const policyId = decodeURIComponent(String(publishMatch[1] || ''));
        lastPublishPolicyId = policyId;
        const target = policies.find((entry) => String(entry.id || '') === policyId);
        if (!target) {
          await route.fulfill({
            status: 404,
            contentType: 'application/json',
            body: JSON.stringify({
              ok: false,
              code: 'policy_not_found',
              message: `Policy ${policyId} was not found`,
            }),
          });
          return;
        }
        target.status = 'PUBLISHED';
        target.version = Number(target.version || 0) + 1;
        target.publishedAt = iso('2026-02-21T00:00:00.000Z');
        target.updatedAt = target.publishedAt;
        policyVersionsById[policyId] = [
          {
            policyId,
            version: target.version,
            status: 'PUBLISHED',
            rules: target.rules,
            publishedAt: target.publishedAt,
            createdAt: target.publishedAt,
            actorUserId: 'user_dash_console_pages',
          },
          ...(policyVersionsById[policyId] || []),
        ];
        coverage = {
          ...coverage,
          policies: [
            {
              policyId: target.id,
              walletCount: 3,
              activeWalletCount: 3,
              archivedWalletCount: 0,
              totalBalanceMinor: 1500000,
              lastActivityAt: target.updatedAt,
            },
          ],
        };
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            result: {
              published: true,
              policy: target,
            },
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

    await page.goto('/dashboard/policy-engine');
    await expect(page.locator('#dashboard-main-title')).toHaveText(/policy engine/i);
    await expect(page.locator('section[aria-label="Policy setup"]')).toContainText('Create policy');
    await expect(page.locator('section[aria-label="Policies table"]')).toContainText(
      'policy_draft_e2e',
    );

    const policySetupSection = page.locator('section[aria-label="Policy setup"]');
    await policySetupSection.locator('button:has-text("Create policy")').click();
    const createPolicyModal = page.locator('section[aria-label="Create policy modal"]');
    const createPolicyNameInput = createPolicyModal.locator('label:has-text("Policy name") input');
    await createPolicyNameInput.fill('Draft before close');
    await createPolicyModal.locator('button:has-text("Cancel")').click();

    await policySetupSection.locator('button:has-text("Create policy")').click();
    await expect(createPolicyNameInput).toHaveValue('Draft before close');
    await createPolicyNameInput.fill('Draft before refresh');
    await createPolicyModal.locator('button:has-text("Cancel")').click();

    await page.reload();
    await expect(page.locator('#dashboard-main-title')).toHaveText(/policy engine/i);
    await policySetupSection.locator('button:has-text("Create policy")').click();
    const createPolicyModalAfterRefresh = page.locator('section[aria-label="Create policy modal"]');
    const createPolicyNameInputAfterRefresh = createPolicyModalAfterRefresh.locator(
      'label:has-text("Policy name") input',
    );
    await expect(createPolicyNameInputAfterRefresh).toHaveValue('Draft before refresh');
    await createPolicyNameInputAfterRefresh.fill('Created from restored draft');
    await createPolicyModalAfterRefresh.locator('button:has-text("Create draft")').click();
    await expect
      .poll(() => String(lastPolicyCreateBody?.name || ''))
      .toBe('Created from restored draft');
    await expect
      .poll(() => JSON.stringify(lastPolicyCreateBody?.assignment || null))
      .toBe(JSON.stringify({ scopeType: 'ENVIRONMENT', scopeId: 'env_active' }));

    await policySetupSection.locator('button:has-text("Create policy")').click();
    const createPolicyModalAfterSave = page.locator('section[aria-label="Create policy modal"]');
    await expect(
      createPolicyModalAfterSave.locator('label:has-text("Policy name") input'),
    ).toHaveValue('Project signing policy');
    await createPolicyModalAfterSave.locator('button:has-text("Cancel")').click();

    const policyRow = page.locator('.dashboard-policy-table__row').filter({
      hasText: 'policy_draft_e2e',
    });
    await policyRow.locator('button:has-text("Go live")').click();

    const publishModal = page.locator('section[aria-label="Schedule live policy change modal"]');
    await expect(publishModal).toContainText('Current live version');
    await expect(publishModal).toContainText('Next live version');
    await expect(publishModal).toContainText('Wallet impact');
    await expect(publishModal).toContainText('Blocked actions');
    await expect(publishModal).toContainText('delete_key -> export_key');
    await expect(publishModal).toContainText('Ethereum, NEAR -> Ethereum');
    await expect(publishModal).toContainText('250000 -> 500000');
    await expect(publishModal).toContainText('apr_policy_publish_e2e');
    await publishModal.locator('button:has-text("Publish live")').click();

    await expect.poll(() => lastPublishPolicyId).toBe('policy_draft_e2e');
    await expect
      .poll(() => String(lastPublishBody?.approvalId || ''))
      .toBe('apr_policy_publish_e2e');
    await expect(page.locator('section[aria-label="Policies table"]')).toContainText('PUBLISHED');
  });

  test('policy-engine page creates contract-call allowlist drafts and simulates from a row', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    const context = buildMockDashboardContext();
    const policies: any[] = [
      {
        id: 'policy_existing_contract_sim_e2e',
        orgId: 'org_dash_console_pages',
        name: 'Existing contract policy',
        description: 'Existing draft policy for simulate test',
        status: 'DRAFT',
        version: 1,
        rules: {
          blockedActions: ['delete_key'],
        },
        createdAt: iso('2026-02-01T00:00:00.000Z'),
        updatedAt: iso('2026-02-01T00:00:00.000Z'),
        publishedAt: null,
      },
    ];
    const wallets: any[] = [
      {
        id: 'wallet_contract_sim_e2e_1',
        address: '0x1111111111111111111111111111111111111111',
        chain: 'Ethereum',
        userId: 'user_wallet_contract_sim_e2e_1',
        policyId: 'policy_existing_contract_sim_e2e',
        balanceMinor: 250000,
        status: 'ACTIVE',
        updatedAt: iso('2026-02-20T00:00:00.000Z'),
        lastActivityAt: iso('2026-02-20T00:00:00.000Z'),
      },
    ];
    const coverage = {
      scope: { projectId: 'proj_active', environmentId: 'env_active' },
      totals: {
        walletCount: 1,
        policyCount: 1,
        unassignedWalletCount: 0,
        activeWalletCount: 1,
        archivedWalletCount: 0,
      },
      policies: [
        {
          policyId: 'policy_existing_contract_sim_e2e',
          walletCount: 1,
          activeWalletCount: 1,
          archivedWalletCount: 0,
          totalBalanceMinor: 250000,
          lastActivityAt: iso('2026-02-20T00:00:00.000Z'),
        },
      ],
      unassignedWalletSample: [],
      truncated: false,
    };
    let lastPolicyCreateBody: Record<string, unknown> | null = null;
    let lastSimulationBody: Record<string, unknown> | null = null;
    let lastSimulationPolicyId = '';
    const assignments: any[] = [];

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

      if (pathname === '/console/account/organizations' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            organizations: [context.org],
          }),
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

      if (pathname === '/console/policy/coverage' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, coverage }),
        });
        return;
      }

      if (pathname === '/console/policies' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, policies }),
        });
        return;
      }

      if (pathname === '/console/policies' && method === 'POST') {
        const body = parseJsonBody(req.postData());
        lastPolicyCreateBody = body;
        const createdAt = iso('2026-02-22T00:00:00.000Z');
        const created = {
          id: 'policy_created_contract_allowlist_e2e',
          orgId: 'org_dash_console_pages',
          name: String(body.name || 'Contract allowlist policy'),
          description: String(body.description || ''),
          status: 'DRAFT',
          version: 1,
          rules: isPlainObject(body.rules) ? body.rules : {},
          createdAt,
          updatedAt: createdAt,
          publishedAt: null,
        };
        policies.unshift(created);
        if (isPlainObject(body.assignment)) {
          assignments.unshift({
            id: `assignment_${created.id}`,
            orgId: 'org_dash_console_pages',
            scopeType: String(body.assignment.scopeType || ''),
            scopeId: String(body.assignment.scopeId || ''),
            policyId: created.id,
            createdAt,
            updatedAt: createdAt,
          });
        }
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, policy: created }),
        });
        return;
      }

      if (pathname === '/console/policies/assignments' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, assignments }),
        });
        return;
      }

      if (pathname === '/console/wallets' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, wallets }),
        });
        return;
      }

      if (pathname === '/console/approvals' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, approvals: [] }),
        });
        return;
      }

      const simulateMatch = pathname.match(/^\/console\/policies\/([^/]+)\/simulate$/);
      if (simulateMatch && method === 'POST') {
        lastSimulationBody = parseJsonBody(req.postData());
        lastSimulationPolicyId = decodeURIComponent(String(simulateMatch[1] || ''));
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            simulation: {
              policyId: lastSimulationPolicyId,
              decision: 'ALLOW',
              denyReasons: [],
              evaluatedAt: iso('2026-02-22T01:00:00.000Z'),
              policyVersion: 1,
              normalizedRequest: {
                action: 'contract_call',
                chain: 'ethereum',
                amountMinor: 10000,
                contractAddress: '0x1111111111111111111111111111111111111111',
                functionSelector: 'transfer(address,uint256)',
              },
            },
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

    await page.goto('/dashboard/policy-engine');
    const policySetupSection = page.locator('section[aria-label="Policy setup"]');
    await policySetupSection.locator('button:has-text("Create policy")').click();

    const createPolicyModal = page.locator('section[aria-label="Create policy modal"]');
    await createPolicyModal
      .locator('label:has-text("Policy name") input')
      .fill('Contract allowlist policy');
    await createPolicyModal.locator('button:has-text("Allowlist")').click();
    await createPolicyModal.locator('button:has-text("Add contract")').click();

    const contractCard = createPolicyModal.locator('.dashboard-policy-contract-card').first();
    await contractCard
      .locator('label:has-text("Contract address") input')
      .fill('0x1111111111111111111111111111111111111111');
    await contractCard
      .locator('label:has-text("Allowed functions") input')
      .fill('transfer(address,uint256)');
    await createPolicyModal.locator('button:has-text("Create draft")').click();

    await expect
      .poll(() => String(lastPolicyCreateBody?.name || ''))
      .toBe('Contract allowlist policy');
    await expect
      .poll(() => JSON.stringify((lastPolicyCreateBody?.rules as Record<string, unknown>) || {}))
      .toBe(
        JSON.stringify({
          blockedActions: ['delete_key'],
          allowedContractCalls: [
            {
              contractAddress: '0x1111111111111111111111111111111111111111',
              functions: ['transfer(address,uint256)'],
            },
          ],
        }),
      );
    await expect
      .poll(() => JSON.stringify(lastPolicyCreateBody?.assignment || null))
      .toBe(JSON.stringify({ scopeType: 'ENVIRONMENT', scopeId: 'env_active' }));

    const createdPolicyRow = page.locator('.dashboard-policy-table__row').filter({
      hasText: 'Contract allowlist policy',
    });
    await expect(createdPolicyRow).toBeVisible();
    await createdPolicyRow.locator('button:has-text("Simulate")').click();

    const simulatePolicyModal = page.locator('section[aria-label="Simulate policy modal"]');
    await simulatePolicyModal
      .locator('label:has-text("Action") select')
      .selectOption('contract_call');
    await simulatePolicyModal
      .locator('label:has-text("Contract address") input')
      .fill('0x1111111111111111111111111111111111111111');
    await simulatePolicyModal
      .locator('label:has-text("Function selector") input')
      .fill('transfer(address,uint256)');
    await simulatePolicyModal.locator('button:has-text("Run simulation")').click();

    await expect.poll(() => lastSimulationPolicyId).toBe('policy_created_contract_allowlist_e2e');
    await expect
      .poll(() => JSON.stringify(lastSimulationBody || {}))
      .toBe(
        JSON.stringify({
          action: 'contract_call',
          chain: 'Ethereum',
          amountMinor: 10000,
          contractAddress: '0x1111111111111111111111111111111111111111',
          functionSelector: 'transfer(address,uint256)',
        }),
      );
    await expect(simulatePolicyModal).toContainText('Decision ALLOW');
    await expect(simulatePolicyModal).toContainText(
      'Allowed contract_call on ethereum with amount 10000',
    );
  });

  test('policy-engine create modal blocks empty contract-call allowlists', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    const context = buildMockDashboardContext();
    let createRequestCount = 0;

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

      if (pathname === '/console/account/organizations' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            organizations: [context.org],
          }),
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

      if (pathname === '/console/policy/coverage' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            coverage: {
              scope: { projectId: 'proj_active', environmentId: 'env_active' },
              totals: {
                walletCount: 0,
                policyCount: 1,
                unassignedWalletCount: 0,
                activeWalletCount: 0,
                archivedWalletCount: 0,
              },
              policies: [],
              unassignedWalletSample: [],
              truncated: false,
            },
          }),
        });
        return;
      }

      if (pathname === '/console/policies' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            policies: [
              {
                id: 'policy_existing_validation_e2e',
                orgId: 'org_dash_console_pages',
                name: 'Existing validation policy',
                description: '',
                status: 'DRAFT',
                version: 1,
                rules: { blockedActions: ['delete_key'] },
                createdAt: iso('2026-02-01T00:00:00.000Z'),
                updatedAt: iso('2026-02-01T00:00:00.000Z'),
                publishedAt: null,
              },
            ],
          }),
        });
        return;
      }

      if (pathname === '/console/policies' && method === 'POST') {
        createRequestCount += 1;
        await route.fulfill({
          status: 500,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: false,
            code: 'unexpected_create',
            message: 'Create should not have been called for an invalid allowlist.',
          }),
        });
        return;
      }

      if (pathname === '/console/policies/assignments' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, assignments: [] }),
        });
        return;
      }

      if (pathname === '/console/wallets' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, wallets: [] }),
        });
        return;
      }

      if (pathname === '/console/approvals' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, approvals: [] }),
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

    await page.goto('/dashboard/policy-engine');
    await page
      .locator('section[aria-label="Policy setup"] button:has-text("Create policy")')
      .click();

    const createPolicyModal = page.locator('section[aria-label="Create policy modal"]');
    await createPolicyModal
      .locator('label:has-text("Policy name") input')
      .fill('Invalid allowlist policy');
    await createPolicyModal.locator('button:has-text("Allowlist")').click();
    await createPolicyModal.locator('button:has-text("Create draft")').click();

    await expect(createPolicyModal).toContainText(
      'Add at least one contract before saving a contract-call allowlist.',
    );
    await expect.poll(() => createRequestCount).toBe(0);
  });

  test('export-keys page removes admin request and approval controls', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    const context = buildMockDashboardContext();

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

      if (pathname === '/console/onboarding/state' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            state: {
              orgId: 'org_dash_console_pages',
              organization: context.org,
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
              selectedProjectId: 'proj_active',
              selectedEnvironmentId: 'env_active',
            },
          }),
        });
        return;
      }

      if (pathname === '/console/org' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, org: context.org }),
        });
        return;
      }

      if (pathname === '/console/projects' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, projects: [context.activeProject] }),
        });
        return;
      }

      if (pathname === '/console/environments' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, environments: [context.activeEnvironment] }),
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
    await expect(
      page.locator(
        'aside[aria-label="Primary dashboard navigation"] a[href="/dashboard/export-keys"]',
      ),
    ).toHaveCount(0);
    await expect(page.locator('section[aria-label="Private key export policy"]')).toContainText(
      'End users can export their own private keys directly in the wallet experience.',
    );
    await expect(page.locator('section[aria-label="Private key export policy"]')).toContainText(
      'admin request and approval controls for private key exports have been removed.',
    );

    await expect(page.locator('section[aria-label="Key export request controls"]')).toHaveCount(0);
    await expect(page.locator('section[aria-label="Create key export request"]')).toHaveCount(0);
    await expect(page.locator('section[aria-label="Approve key export request"]')).toHaveCount(0);
    await expect(page.locator('section[aria-label="Key export requests table"]')).toHaveCount(0);
    await expect(page.locator('button:has-text("Approve request")')).toHaveCount(0);
  });

  test('team-members page wires invite, role update, remove, status, and permission filter flows', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    const context = buildMockDashboardContext();
    const members: any[] = [
      {
        id: 'member_existing_admin',
        orgId: 'org_dash_console_pages',
        userId: 'user_existing_admin',
        email: 'existing-admin@example.com',
        displayName: 'Existing Admin',
        status: 'ACTIVE',
        roles: [{ role: 'admin', scope: 'ORG' }],
        invitedByUserId: 'user_seed',
        invitedAt: iso('2026-01-01T00:00:00.000Z'),
        createdAt: iso('2026-01-01T00:00:00.000Z'),
        updatedAt: iso('2026-01-01T00:00:00.000Z'),
        lastStatusChangedAt: iso('2026-01-01T00:00:00.000Z'),
      },
    ];
    let lastInviteBody: Record<string, unknown> | null = null;
    let lastRolesPatchBody: Record<string, unknown> | null = null;
    let lastRolesPatchMemberId = '';
    let lastRemovedMemberId = '';
    let lastListStatus = '';

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

      if (pathname === '/console/account/organizations' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, organizations: [context.org] }),
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

      if (pathname === '/console/members' && method === 'GET') {
        const status = String(url.searchParams.get('status') || '')
          .trim()
          .toUpperCase();
        lastListStatus = status;
        const rows = status
          ? members.filter((entry) => String(entry.status || '').toUpperCase() === status)
          : [...members];
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, members: rows }),
        });
        return;
      }

      if (pathname === '/console/members/invite' && method === 'POST') {
        const body = parseJsonBody(req.postData());
        lastInviteBody = body;
        const now = iso('2026-02-10T00:00:00.000Z');
        const created = {
          id: `member_${Date.now()}`,
          orgId: 'org_dash_console_pages',
          userId: String(body.userId || '').trim(),
          email: String(body.email || '').trim(),
          displayName: String(body.displayName || '').trim() || undefined,
          status: 'ACTIVE',
          roles: Array.isArray(body.roles) ? body.roles : [],
          invitedByUserId: 'user_dash_console_pages',
          invitedAt: now,
          createdAt: now,
          updatedAt: now,
          lastStatusChangedAt: now,
        };
        members.unshift(created);
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, member: created }),
        });
        return;
      }

      const rolesPatchMatch = pathname.match(/^\/console\/members\/([^/]+)\/roles$/);
      if (rolesPatchMatch && method === 'PATCH') {
        const memberId = decodeURIComponent(String(rolesPatchMatch[1] || ''));
        const body = parseJsonBody(req.postData());
        lastRolesPatchMemberId = memberId;
        lastRolesPatchBody = body;
        const target = members.find((entry) => String(entry.id || '') === memberId);
        if (!target) {
          await route.fulfill({
            status: 404,
            contentType: 'application/json',
            body: JSON.stringify({
              ok: false,
              code: 'member_not_found',
              message: `Member ${memberId} was not found`,
            }),
          });
          return;
        }
        target.roles = Array.isArray(body.roles) ? body.roles : target.roles;
        target.updatedAt = iso('2026-02-11T00:00:00.000Z');
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, member: target }),
        });
        return;
      }

      const removeMatch = pathname.match(/^\/console\/members\/([^/]+)$/);
      if (removeMatch && method === 'DELETE') {
        const memberId = decodeURIComponent(String(removeMatch[1] || ''));
        lastRemovedMemberId = memberId;
        const target = members.find((entry) => String(entry.id || '') === memberId);
        if (!target) {
          await route.fulfill({
            status: 404,
            contentType: 'application/json',
            body: JSON.stringify({
              ok: false,
              code: 'member_not_found',
              message: `Member ${memberId} was not found`,
            }),
          });
          return;
        }
        target.status = 'REMOVED';
        target.roles = [];
        target.updatedAt = iso('2026-02-12T00:00:00.000Z');
        target.lastStatusChangedAt = target.updatedAt;
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, removed: true, member: target }),
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

    await page.goto('/dashboard/team-members');
    await expect(page.locator('#dashboard-main-title')).toHaveText(/team members and roles/i);
    await expect(page.locator('section[aria-label="Team members table"]')).toContainText(
      'existing-admin@example.com',
    );

    await page.locator('button:has-text("Add Team Member")').click();

    const inviteModal = page.locator('section[aria-label="Add team member modal"]');
    await inviteModal.locator('label:has-text("Email") input').fill('new-member@example.com');
    await inviteModal.locator('label:has-text("Admin member") input').check();
    await inviteModal.locator('label:has-text("Can add/remove team members") input').check();
    await inviteModal
      .locator('.dashboard-team-members-access-item', { hasText: 'Integrations' })
      .locator('button:has-text("Write")')
      .click();
    await inviteModal.locator('button:has-text("Invite member")').click();

    await expect.poll(() => String(lastInviteBody?.email || '')).toBe('new-member@example.com');
    await expect.poll(() => String(lastInviteBody?.userId || '')).toBe('user_new_member');
    await expect
      .poll(
        () =>
          Array.isArray(lastInviteBody?.roles) &&
          (lastInviteBody?.roles as any[]).some(
            (entry: any) => String(entry?.role || '') === 'admin',
          ),
      )
      .toBe(true);
    await expect
      .poll(
        () =>
          Array.isArray(lastInviteBody?.roles) &&
          (lastInviteBody?.roles as any[]).some(
            (entry: any) => String(entry?.role || '') === 'integrations_write',
          ),
      )
      .toBe(true);
    await expect(page.locator('section[aria-label="Team members table"]')).toContainText(
      'new-member@example.com',
    );

    const table = page.locator('section[aria-label="Team members table"]');
    const filterSection = page.locator('section[aria-label="Team member filters section"]');
    await filterSection.locator('input[aria-label="Search team members"]').fill('new-member');
    await expect(table).toContainText('new-member@example.com');
    await expect(table).not.toContainText('existing-admin@example.com');
    await filterSection.locator('input[aria-label="Search team members"]').fill('');
    await filterSection
      .locator('select[aria-label="Filter team members by permission"]')
      .selectOption('MANAGE_MEMBERS');
    await expect(table).toContainText('new-member@example.com');
    await expect(table).not.toContainText('existing-admin@example.com');
    await filterSection
      .locator('select[aria-label="Filter team members by permission"]')
      .selectOption('ALL');

    const newMemberRow = table.locator('.dashboard-data-table__row', {
      hasText: 'new-member@example.com',
    });
    await newMemberRow.locator('button:has-text("Edit")').click();

    const updateModal = page.locator('section[aria-label="Update member permissions modal"]');
    await updateModal.locator('label:has-text("Can add/remove team members") input').uncheck();
    await updateModal
      .locator('.dashboard-team-members-access-item', { hasText: 'Integrations' })
      .locator('button:has-text("Read")')
      .click();
    await updateModal.locator('button:has-text("Apply permissions")').click();

    await expect.poll(() => lastRolesPatchMemberId).toContain('member_');
    await expect
      .poll(
        () =>
          Array.isArray(lastRolesPatchBody?.roles) &&
          (lastRolesPatchBody?.roles as any[]).some(
            (entry: any) => String(entry?.role || '') === 'integrations_read',
          ),
      )
      .toBe(true);
    await expect
      .poll(
        () =>
          Array.isArray(lastRolesPatchBody?.roles) &&
          (lastRolesPatchBody?.roles as any[]).some(
            (entry: any) => String(entry?.role || '') === 'admin_manage_members',
          ),
      )
      .toBe(false);
    await expect(newMemberRow).toContainText('Integrations:read');

    page.once('dialog', (dialog) => dialog.accept());
    await newMemberRow.locator('button:has-text("Delete")').click({ force: true });
    await expect.poll(() => lastRemovedMemberId).toContain('member_');
    await expect(newMemberRow).toContainText('REMOVED');

    await filterSection
      .locator('select[aria-label="Filter team members by status"]')
      .selectOption('REMOVED');
    await expect.poll(() => lastListStatus).toBe('REMOVED');
    await expect(page.locator('section[aria-label="Team members table"]')).toContainText(
      'new-member@example.com',
    );
  });

  test('audit page renders a single searchable events table without depending on evidence or exports', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    const context = buildMockDashboardContext();
    const events = [
      {
        id: 'aud_policy_1',
        orgId: 'org_dash_console_pages',
        projectId: 'proj_active',
        environmentId: 'env_active',
        actorUserId: 'user_security',
        actorType: 'USER',
        category: 'POLICY',
        action: 'policy.publish',
        outcome: 'SUCCESS',
        summary: 'Published policy',
        metadata: { policyId: 'policy_1' },
        createdAt: iso('2026-02-15T00:00:00.000Z'),
      },
      {
        id: 'aud_approval_1',
        orgId: 'org_dash_console_pages',
        projectId: 'proj_active',
        environmentId: 'env_active',
        actorUserId: 'user_admin',
        actorType: 'USER',
        category: 'APPROVAL',
        action: 'approval.request.create',
        outcome: 'PENDING',
        summary: 'Approval requested',
        metadata: { approvalId: 'apr_1' },
        createdAt: iso('2026-02-15T00:01:00.000Z'),
      },
    ];
    let lastEventCategoryQuery = '';
    let lastEventSearchQuery = '';
    let evidenceRequestCount = 0;
    let exportRequestCount = 0;

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

      if (pathname === '/console/account/organizations' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, organizations: [context.org] }),
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

      if (pathname === '/console/audit/events' && method === 'GET') {
        const category = String(url.searchParams.get('category') || '')
          .trim()
          .toUpperCase();
        const q = String(url.searchParams.get('q') || '')
          .trim()
          .toLowerCase();
        lastEventCategoryQuery = category;
        lastEventSearchQuery = q;
        const rows = events.filter((entry) => {
          if (category && entry.category !== category) return false;
          if (!q) return true;
          return [
            entry.id,
            entry.actorUserId,
            entry.category,
            entry.action,
            entry.summary,
            JSON.stringify(entry.metadata),
          ]
            .join(' ')
            .toLowerCase()
            .includes(q);
        });
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, events: rows }),
        });
        return;
      }

      if (pathname === '/console/audit/evidence' && method === 'GET') {
        evidenceRequestCount += 1;
        await route.fulfill({
          status: 501,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: false,
            code: 'audit_evidence_not_configured',
            message: 'Audit evidence is not configured for this test',
          }),
        });
        return;
      }

      if (pathname === '/console/audit/exports' && method === 'GET') {
        exportRequestCount += 1;
        await route.fulfill({
          status: 501,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: false,
            code: 'audit_exports_not_configured',
            message: 'Audit exports service is not configured on this server',
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

    await page.goto('/dashboard/audit');
    await expect(page.locator('#dashboard-main-title')).toHaveText(/audit logs/i);
    await expect(page.locator('section[aria-label="Audit events table"]')).toContainText(
      'Published policy',
    );
    await expect(page.locator('section[aria-label="Audit events table"]')).toContainText(
      'Created approval request',
    );
    await expect(page.locator('section[aria-label="Audit events table"]')).not.toContainText(
      'Invoice settlement evidence',
    );
    expect(evidenceRequestCount).toBe(0);
    expect(exportRequestCount).toBe(0);

    const filterSection = page.locator('section[aria-label="Audit event filters"]');
    await filterSection.locator('input[aria-label="Search events"]').fill('apr_1');
    await expect.poll(() => lastEventSearchQuery).toBe('apr_1');
    await expect(page.locator('section[aria-label="Audit events table"]')).toContainText(
      'Created approval request',
    );
    await expect(page.locator('section[aria-label="Audit events table"]')).not.toContainText(
      'Published policy',
    );

    await filterSection.locator('label:has-text("Category") select').selectOption('APPROVAL');
    await expect.poll(() => lastEventCategoryQuery).toBe('APPROVAL');
    await expect(page.locator('section[aria-label="Audit events table"]')).toContainText(
      'approval.request.create',
    );
  });

  test('audit page surfaces actor identifiers and deep links to policy, invoice, and webhook destinations', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    const context = buildMockDashboardContext();
    const events = [
      {
        id: 'aud_policy_link_1',
        orgId: 'org_dash_console_pages',
        projectId: 'proj_active',
        environmentId: 'env_active',
        policyId: 'policy_linked_1',
        policyName: 'Treasury publish policy',
        policyKind: 'TRANSACTION',
        actorUserId: 'user_security',
        actorType: 'USER',
        category: 'POLICY',
        action: 'policy.publish',
        outcome: 'SUCCESS',
        summary: 'Published policy',
        metadata: {
          policyId: 'policy_linked_1',
          policyName: 'Treasury publish policy',
          policyKind: 'TRANSACTION',
          version: 2,
          status: 'PUBLISHED',
          approvalId: 'apr_audit_link_1',
          scopeType: 'ENVIRONMENT',
        },
        createdAt: iso('2026-03-10T12:00:00.000Z'),
      },
      {
        id: 'aud_billing_link_1',
        orgId: 'org_dash_console_pages',
        actorUserId: 'system_billing',
        actorType: 'SYSTEM',
        category: 'BILLING',
        action: 'billing.credit_purchase.settled',
        outcome: 'SUCCESS',
        summary: 'Settled Stripe credit purchase',
        metadata: {
          purchaseId: 'purchase_bcp_1',
          receiptId: 'receipt_bcp_1',
          amountMinor: 2500,
          currency: 'USD',
          providerCheckoutSessionRef: 'cs_test_123',
          settlementSource: 'STRIPE_WEBHOOK',
        },
        createdAt: iso('2026-03-10T11:00:00.000Z'),
      },
      {
        id: 'aud_billing_adjustment_link_1',
        orgId: 'org_target_customer',
        actorUserId: 'user_ops',
        actorType: 'USER',
        category: 'BILLING',
        action: 'billing.adjustment.support_credit',
        outcome: 'SUCCESS',
        summary: 'Appended manual support credit for org org_target_customer',
        metadata: {
          organizationId: 'org_target_customer',
          organizationName: 'Target Customer Org',
          platformBilling: true,
          adjustmentId: 'ble_adj_1',
          amountMinor: 1500,
          currency: 'USD',
          resultingBalanceMinor: 6500,
          reasonCode: 'incident_credit',
          relatedInvoiceId: 'inv_audit_credit_1',
          note: 'Applied goodwill credit',
          created: true,
        },
        createdAt: iso('2026-03-10T10:30:00.000Z'),
      },
      {
        id: 'aud_webhook_link_1',
        orgId: 'org_dash_console_pages',
        projectId: 'proj_active',
        environmentId: 'env_active',
        actorUserId: 'user_ops',
        actorType: 'USER',
        category: 'WEBHOOK',
        action: 'webhook.delivery.replay_requested',
        outcome: 'SUCCESS',
        summary: 'Requested webhook replay',
        metadata: {
          endpointId: 'wh_ep_link_1',
          deliveryId: 'dlv_link_1',
        },
        createdAt: iso('2026-03-10T10:00:00.000Z'),
      },
    ];
    const approvals = [
      {
        id: 'apr_audit_link_1',
        orgId: 'org_dash_console_pages',
        operationType: 'POLICY_PUBLISH',
        status: 'APPROVED',
        reason: 'Approved for audit deep link test',
        requestedByUserId: 'user_admin',
        requiredApprovals: 1,
        requireMfa: false,
        projectId: 'proj_active',
        environmentId: 'env_active',
        resourceType: 'policy',
        resourceId: 'policy_linked_1',
        policyId: 'policy_linked_1',
        policyName: 'Treasury publish policy',
        metadata: {
          policyId: 'policy_linked_1',
          policyName: 'Treasury publish policy',
        },
        decisions: [],
        createdAt: iso('2026-03-10T09:00:00.000Z'),
        updatedAt: iso('2026-03-10T09:30:00.000Z'),
        resolvedAt: iso('2026-03-10T09:30:00.000Z'),
      },
    ];
    const members = [
      {
        id: 'mbr_user_security',
        orgId: 'org_dash_console_pages',
        userId: 'user_security',
        email: 'security@example.com',
        displayName: 'Security Admin',
        status: 'ACTIVE',
        roles: [{ role: 'admin', scope: 'ORG' }],
        invitedByUserId: 'user_owner',
        invitedAt: iso('2026-01-01T00:00:00.000Z'),
        createdAt: iso('2026-01-01T00:00:00.000Z'),
        updatedAt: iso('2026-01-01T00:00:00.000Z'),
        lastStatusChangedAt: iso('2026-01-01T00:00:00.000Z'),
      },
      {
        id: 'mbr_user_ops',
        orgId: 'org_dash_console_pages',
        userId: 'user_ops',
        email: 'ops@example.com',
        displayName: 'Ops Admin',
        status: 'ACTIVE',
        roles: [{ role: 'admin', scope: 'ORG' }],
        invitedByUserId: 'user_owner',
        invitedAt: iso('2026-01-01T00:00:00.000Z'),
        createdAt: iso('2026-01-01T00:00:00.000Z'),
        updatedAt: iso('2026-01-01T00:00:00.000Z'),
        lastStatusChangedAt: iso('2026-01-01T00:00:00.000Z'),
      },
    ];

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

      if (pathname === '/console/account/organizations' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, organizations: [context.org] }),
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

      if (pathname === '/console/members' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, members }),
        });
        return;
      }

      if (pathname === '/console/approvals' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, approvals }),
        });
        return;
      }

      if (pathname === '/console/audit/events' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, events }),
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

    await page.goto('/dashboard/audit');
    await expect(page.locator('#dashboard-main-title')).toHaveText(/audit logs/i);

    const policyRow = page.locator('.dashboard-audit-events__row').filter({
      hasText: 'Published policy',
    });
    await policyRow.getByRole('button', { name: 'View' }).click();
    let detailsPanel = page.locator('.dashboard-audit-events__details-panel.is-expanded');
    await expect(detailsPanel).toContainText('Security Admin');
    await expect(detailsPanel).toContainText('user_security');
    await expect(
      detailsPanel.getByRole('link', { name: 'Treasury publish policy' }),
    ).toHaveAttribute('href', '/dashboard/policy-engine?policyId=policy_linked_1');
    await expect(detailsPanel.getByRole('link', { name: 'apr_audit_link_1' })).toHaveAttribute(
      'href',
      '/dashboard/policy-engine?policyId=policy_linked_1&approvalId=apr_audit_link_1',
    );
    await expect(detailsPanel).toContainText('Environment');
    await expect(detailsPanel).toContainText('env_active');

    const billingRow = page.locator('.dashboard-audit-events__row').filter({
      hasText: 'Settled Stripe credit purchase',
    });
    await billingRow.getByRole('button', { name: 'View' }).click();
    detailsPanel = page.locator('.dashboard-audit-events__details-panel.is-expanded');
    await expect(detailsPanel).toContainText('purchase_bcp_1');
    await expect(detailsPanel).toContainText('SYSTEM');
    await expect(detailsPanel.getByRole('link', { name: 'receipt_bcp_1' })).toHaveAttribute(
      'href',
      '/dashboard/invoices/receipt_bcp_1',
    );
    await expect(detailsPanel).toContainText('Organization');
    await expect(detailsPanel).toContainText('org_dash_console_pages');

    const adjustmentRow = page.locator('.dashboard-audit-events__row').filter({
      hasText: 'Granted customer support credit',
    });
    await expect(adjustmentRow).toContainText('Target Customer Org');
    await expect(adjustmentRow).toContainText('$15.00');
    await adjustmentRow.getByRole('button', { name: 'View' }).click();
    detailsPanel = page.locator('.dashboard-audit-events__details-panel.is-expanded');
    await expect(detailsPanel).toContainText('Applied goodwill credit');
    await expect(detailsPanel).toContainText('$65.00');
    await expect(detailsPanel).toContainText('Target Customer Org');
    await expect(detailsPanel.getByRole('link', { name: 'inv_audit_credit_1' })).toHaveAttribute(
      'href',
      '/dashboard/invoices/inv_audit_credit_1',
    );

    const webhookRow = page.locator('.dashboard-audit-events__row').filter({
      hasText: 'Requested webhook replay',
    });
    await webhookRow.getByRole('button', { name: 'View' }).click();
    detailsPanel = page.locator('.dashboard-audit-events__details-panel.is-expanded');
    await expect(detailsPanel.getByRole('link', { name: 'wh_ep_link_1' })).toHaveAttribute(
      'href',
      '/dashboard/webhooks?endpointId=wh_ep_link_1',
    );
    await expect(detailsPanel.getByRole('link', { name: 'dlv_link_1' })).toHaveAttribute(
      'href',
      '/dashboard/webhooks?endpointId=wh_ep_link_1&deliveryId=dlv_link_1',
    );
  });

  test('audit page resolves organization names in rendered event summaries', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    const context = buildMockDashboardContext();
    const organizations = [
      context.org,
      {
        id: 'org_audit_named',
        name: 'Audit Named Org',
        slug: 'audit-named-org',
        status: 'ACTIVE',
        createdAt: iso('2026-01-05T00:00:00.000Z'),
        updatedAt: iso('2026-01-06T00:00:00.000Z'),
      },
      {
        id: 'org_audit_directory',
        name: 'Directory Resolved Org',
        slug: 'directory-resolved-org',
        status: 'ACTIVE',
        createdAt: iso('2026-01-07T00:00:00.000Z'),
        updatedAt: iso('2026-01-08T00:00:00.000Z'),
      },
    ];
    const events = [
      {
        id: 'aud_org_create_named',
        orgId: 'org_dash_console_pages',
        actorUserId: 'user_owner',
        actorType: 'USER',
        category: 'ORG_PROJECT_ENV',
        action: 'organization.create',
        outcome: 'SUCCESS',
        summary: 'Created organization org_audit_named from account settings',
        metadata: {
          organizationId: 'org_audit_named',
          organizationName: 'Audit Named Org',
          source: 'account_settings',
        },
        createdAt: iso('2026-03-11T12:00:00.000Z'),
      },
      {
        id: 'aud_org_update_directory',
        orgId: 'org_dash_console_pages',
        actorUserId: 'user_owner',
        actorType: 'USER',
        category: 'ORG_PROJECT_ENV',
        action: 'organization.update',
        outcome: 'SUCCESS',
        summary: 'Updated organization org_audit_directory from account settings',
        metadata: {
          organizationId: 'org_audit_directory',
          source: 'account_settings',
        },
        createdAt: iso('2026-03-11T11:00:00.000Z'),
      },
      {
        id: 'aud_org_create_deleted_history',
        orgId: 'org_dash_console_pages',
        actorUserId: 'user_owner',
        actorType: 'USER',
        category: 'ORG_PROJECT_ENV',
        action: 'organization.create',
        outcome: 'SUCCESS',
        summary: 'Created organization org_audit_deleted from account settings',
        metadata: {
          organizationId: 'org_audit_deleted',
          organizationName: 'Deleted Org Name',
          source: 'account_settings',
        },
        createdAt: iso('2026-03-11T10:30:00.000Z'),
      },
      {
        id: 'aud_org_delete_named',
        orgId: 'org_dash_console_pages',
        actorUserId: 'user_owner',
        actorType: 'USER',
        category: 'ORG_PROJECT_ENV',
        action: 'organization.delete',
        outcome: 'SUCCESS',
        summary: 'Deleted organization org_audit_deleted from account settings',
        metadata: {
          organizationId: 'org_audit_deleted',
          source: 'account_settings',
        },
        createdAt: iso('2026-03-11T10:00:00.000Z'),
      },
    ];
    const members = [
      {
        id: 'mbr_user_owner',
        orgId: 'org_dash_console_pages',
        userId: 'user_owner',
        email: 'owner@example.com',
        displayName: 'Owner User',
        status: 'ACTIVE',
        roles: [{ role: 'owner', scope: 'ORG' }],
        invitedByUserId: 'user_owner',
        invitedAt: iso('2026-01-01T00:00:00.000Z'),
        createdAt: iso('2026-01-01T00:00:00.000Z'),
        updatedAt: iso('2026-01-01T00:00:00.000Z'),
        lastStatusChangedAt: iso('2026-01-01T00:00:00.000Z'),
      },
    ];

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

      if (pathname === '/console/account/organizations' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, organizations }),
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

      if (pathname === '/console/members' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, members }),
        });
        return;
      }

      if (pathname === '/console/approvals' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, approvals: [] }),
        });
        return;
      }

      if (pathname === '/console/audit/events' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, events }),
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

    await page.goto('/dashboard/audit');
    await expect(page.locator('#dashboard-main-title')).toHaveText(/audit logs/i);

    const table = page.locator('section[aria-label="Audit events table"]');
    await expect(table).toContainText('Created organization Audit Named Org from account settings');
    await expect(table).toContainText(
      'Updated organization Directory Resolved Org from account settings',
    );
    await expect(table).toContainText(
      'Deleted organization Deleted Org Name from account settings',
    );
    await expect(table).not.toContainText('org_audit_named from account settings');
    await expect(table).not.toContainText('org_audit_directory from account settings');
    await expect(table).not.toContainText('org_audit_deleted from account settings');
  });

  test('credentials page supports publishable_key creation and mode-specific snippet wiring', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    const context = buildMockDashboardContext();
    const seededAllowedOrigins = [
      'https://app.example.com',
      'https://localhost:8443',
      'https://wallet.example.localhost',
    ];
    let lastCreateBody: Record<string, unknown> | null = null;
    let lastUpdateBody: Record<string, unknown> | null = null;
    let lastPurgedApiKeyId = '';
    let apiKeys: Record<string, unknown>[] = [
      {
        id: 'ak_existingsecret',
        kind: 'secret_key',
        orgId: 'org_dash_console_pages',
        name: 'existing-server',
        environmentId: 'env_active',
        scopes: ['accounts.create'],
        ipAllowlist: ['203.0.113.10/32'],
        status: 'ACTIVE',
        secretVersion: 1,
        secretPreview: 'sk_abcd...',
        createdAt: iso('2026-03-01T00:00:00.000Z'),
        updatedAt: iso('2026-03-01T00:00:00.000Z'),
        lastUsedAt: iso('2026-03-02T00:00:00.000Z'),
        endpointUsageCounts: {
          '/registration/bootstrap': 3,
        },
        anomalyFlags: [],
      },
      {
        id: 'ak_revokedpublishable',
        kind: 'publishable_key',
        orgId: 'org_dash_console_pages',
        name: 'revoked-browser',
        environmentId: 'env_active',
        allowedOrigins: seededAllowedOrigins,
        rateLimitBucket: 'default_web_v1',
        quotaBucket: 'free_registrations_v1',
        riskPolicy: {},
        paymentPolicy: { mode: 'disabled' },
        status: 'REVOKED',
        secretVersion: 1,
        secretPreview: 'pk_revoked...',
        createdAt: iso('2026-03-01T00:00:00.000Z'),
        updatedAt: iso('2026-03-01T12:00:00.000Z'),
        lastUsedAt: null,
        endpointUsageCounts: {},
        anomalyFlags: [],
      },
    ];

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
              roles: ['owner', 'admin'],
              projectId: 'proj_active',
              environmentId: 'env_active',
            },
          }),
        });
        return;
      }

      if (pathname === '/console/onboarding/state' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            state: {
              orgId: 'org_dash_console_pages',
              organization: context.org,
              activeProjectCount: 1,
              activeEnvironmentCount: 1,
              activeApiKeyCount: apiKeys.length,
              hasOrganization: true,
              hasProject: true,
              hasEnvironment: true,
              hasApiKey: apiKeys.length > 0,
              accountReady: true,
              organizationReady: true,
              billingReady: true,
              projectReady: true,
              onboardingComplete: true,
              currentStep: 'complete',
              complete: true,
              selectedProjectId: 'proj_active',
              selectedEnvironmentId: 'env_active',
            },
          }),
        });
        return;
      }

      if (pathname === '/console/org' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, org: context.org }),
        });
        return;
      }

      if (pathname === '/console/projects' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, projects: [context.activeProject] }),
        });
        return;
      }

      if (pathname === '/console/environments' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, environments: [context.activeEnvironment] }),
        });
        return;
      }

      if (pathname === '/console/api-keys' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            apiKeys,
          }),
        });
        return;
      }

      if (pathname === '/console/api-keys' && method === 'POST') {
        lastCreateBody = parseJsonBody(req.postData());
        const created = {
          id: 'ak_newpublishable',
          kind: 'publishable_key',
          orgId: 'org_dash_console_pages',
          name: String(lastCreateBody.name || '').trim() || 'frontend-app',
          environmentId: String(lastCreateBody.environmentId || '').trim() || 'env_active',
          allowedOrigins: Array.isArray(lastCreateBody.allowedOrigins)
            ? lastCreateBody.allowedOrigins
            : seededAllowedOrigins,
          rateLimitBucket: String(lastCreateBody.rateLimitBucket || '').trim() || 'default',
          quotaBucket: String(lastCreateBody.quotaBucket || '').trim() || 'default',
          riskPolicy:
            lastCreateBody.riskPolicy && typeof lastCreateBody.riskPolicy === 'object'
              ? lastCreateBody.riskPolicy
              : {},
          paymentPolicy:
            lastCreateBody.paymentPolicy && typeof lastCreateBody.paymentPolicy === 'object'
              ? lastCreateBody.paymentPolicy
              : {},
          status: 'ACTIVE',
          secretVersion: 1,
          secretPreview: 'pk_efgh...',
          createdAt: iso('2026-03-03T00:00:00.000Z'),
          updatedAt: iso('2026-03-03T00:00:00.000Z'),
          lastUsedAt: null,
          endpointUsageCounts: {},
          anomalyFlags: [],
        };
        apiKeys = [created, ...apiKeys];
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            apiKey: created,
            secret: 'pk_publishablecreated',
          }),
        });
        return;
      }

      if (/^\/console\/api-keys\/[^/]+$/.test(pathname) && method === 'PATCH') {
        lastUpdateBody = parseJsonBody(req.postData());
        const apiKeyId = decodeURIComponent(pathname.split('/').pop() || '');
        apiKeys = apiKeys.map((entry) => {
          if (String(entry.id || '') !== apiKeyId) return entry;
          return {
            ...entry,
            ...(lastUpdateBody?.name !== undefined
              ? { name: String(lastUpdateBody.name || '').trim() || entry.name }
              : {}),
            ...(Array.isArray(lastUpdateBody?.allowedOrigins)
              ? { allowedOrigins: lastUpdateBody.allowedOrigins }
              : {}),
            ...(lastUpdateBody?.rateLimitBucket !== undefined
              ? { rateLimitBucket: String(lastUpdateBody.rateLimitBucket || '').trim() }
              : {}),
            ...(lastUpdateBody?.quotaBucket !== undefined
              ? { quotaBucket: String(lastUpdateBody.quotaBucket || '').trim() }
              : {}),
            ...(lastUpdateBody?.riskPolicy && typeof lastUpdateBody.riskPolicy === 'object'
              ? { riskPolicy: lastUpdateBody.riskPolicy }
              : {}),
            ...(lastUpdateBody?.paymentPolicy && typeof lastUpdateBody.paymentPolicy === 'object'
              ? { paymentPolicy: lastUpdateBody.paymentPolicy }
              : {}),
            ...(lastUpdateBody?.expiresAt !== undefined
              ? { expiresAt: lastUpdateBody.expiresAt }
              : {}),
            updatedAt: iso('2026-03-04T00:00:00.000Z'),
          };
        });
        const updated = apiKeys.find((entry) => String(entry.id || '') === apiKeyId) || null;
        await route.fulfill({
          status: updated ? 200 : 404,
          contentType: 'application/json',
          body: JSON.stringify(
            updated
              ? { ok: true, apiKey: updated }
              : { ok: false, code: 'api_key_not_found', message: 'api key not found' },
          ),
        });
        return;
      }

      if (/^\/console\/api-keys\/[^/]+\/purge$/.test(pathname) && method === 'DELETE') {
        const parts = pathname.split('/');
        const apiKeyId = decodeURIComponent(parts[parts.length - 2] || '');
        const removed = apiKeys.find((entry) => String(entry.id || '') === apiKeyId) || null;
        if (removed) {
          apiKeys = apiKeys.filter((entry) => String(entry.id || '') !== apiKeyId);
          lastPurgedApiKeyId = apiKeyId;
        }
        await route.fulfill({
          status: removed ? 200 : 404,
          contentType: 'application/json',
          body: JSON.stringify(
            removed
              ? { ok: true, deleted: true, apiKey: removed }
              : { ok: false, code: 'api_key_not_found', message: 'api key not found' },
          ),
        });
        return;
      }

      await route.fulfill({
        status: 404,
        contentType: 'application/json',
        body: JSON.stringify({
          ok: false,
          code: 'not_found',
          path: pathname,
          method,
        }),
      });
    });

    await page.goto('/dashboard/api-keys');

    const credentialControls = page.locator('section[aria-label="Credential controls"]');
    const credentialsTable = page.locator('section[aria-label="Credentials table"]');
    await expect(credentialControls).toContainText('Create credential');
    await expect(credentialsTable.getByRole('columnheader', { name: 'Overage' })).toBeVisible();
    await expect(credentialsTable.getByRole('columnheader', { name: 'Origins' })).toBeVisible();
    await expect(credentialsTable).toContainText('existing-server');
    await expect(credentialsTable).not.toContainText('sk_abcd...');
    const existingSecretRow = page
      .locator('section[aria-label="Credentials table"] .dashboard-data-table__row')
      .filter({ hasText: 'existing-server' });
    await existingSecretRow.getByRole('button', { name: 'Edit' }).click();
    const existingSecretEditModal = page.locator('section[aria-label="Edit credential modal"]');
    await expect(existingSecretEditModal).toBeVisible();
    await expect(
      existingSecretEditModal.getByRole('button', { name: /accounts\.create/i }),
    ).toHaveAttribute('aria-pressed', 'true');
    await expect(
      existingSecretEditModal.getByRole('group', { name: 'Scopes toggles' }).getByRole('button'),
    ).toHaveCount(1);
    await existingSecretEditModal.getByRole('button', { name: 'Cancel' }).click();
    const revokedRow = page
      .locator('section[aria-label="Credentials table"] .dashboard-data-table__row')
      .filter({ hasText: 'revoked-browser' });
    await expect(revokedRow).toContainText('REVOKED');
    await expect(revokedRow.getByRole('button', { name: 'Delete' })).toBeVisible();
    page.once('dialog', (dialog) => dialog.accept());
    await revokedRow.getByRole('button', { name: 'Delete' }).click({ force: true });
    await expect.poll(() => lastPurgedApiKeyId).toBe('ak_revokedpublishable');
    await expect(page.locator('section[aria-label="Credentials table"]')).not.toContainText(
      'revoked-browser',
    );

    await credentialControls.getByRole('button', { name: 'Create credential' }).click();
    const createCredentialModal = page.locator('section[aria-label="Create credential modal"]');
    await expect(createCredentialModal).toBeVisible();
    await createCredentialModal.getByRole('button', { name: /browser publishable_key/i }).click();
    const walletOriginHint =
      String(
        (await createCredentialModal
          .locator('p')
          .filter({ hasText: 'In this local dev setup, include' })
          .locator('code')
          .textContent()) || '',
      ).trim() || 'https://localhost:8443';
    const createAllowedOrigins = Array.from(
      new Set(['https://app.example.com', walletOriginHint, 'https://admin.example.com']),
    );
    const updatedAllowedOrigins = Array.from(
      new Set(['https://admin.example.com', walletOriginHint, 'https://localhost:9443']),
    );
    await createCredentialModal.locator('input[placeholder="frontend-app"]').fill('frontend-app');
    await createCredentialModal
      .getByLabel('Allowed origins URI 1')
      .fill(createAllowedOrigins[0] || '');
    await createCredentialModal
      .getByLabel('Allowed origins URI 2')
      .fill(createAllowedOrigins[1] || '');
    await createCredentialModal.getByRole('button', { name: /\+ add uri/i }).click();
    await createCredentialModal
      .getByLabel('Allowed origins URI 3')
      .fill(createAllowedOrigins[2] || '');
    await createCredentialModal.getByLabel('Overage behavior').selectOption('quota_then_x402');
    await createCredentialModal.getByRole('button', { name: /create publishable_key/i }).click();

    await expect.poll(() => String(lastCreateBody?.kind || '')).toBe('publishable_key');
    await expect
      .poll(() => JSON.stringify(lastCreateBody?.allowedOrigins || []))
      .toBe(JSON.stringify(createAllowedOrigins));
    await expect.poll(() => String(lastCreateBody?.rateLimitBucket || '')).toBe('default_web_v1');
    await expect
      .poll(() => String(lastCreateBody?.quotaBucket || ''))
      .toBe('free_registrations_v1');
    await expect
      .poll(() => JSON.stringify(lastCreateBody?.riskPolicy || {}))
      .toBe(JSON.stringify({ captcha: 'adaptive' }));
    await expect
      .poll(() => JSON.stringify(lastCreateBody?.paymentPolicy || {}))
      .toBe(JSON.stringify({ mode: 'quota_then_x402', productId: 'wallet_registration_v1' }));

    await expect(
      page.locator('section[aria-label="Credential integration snippet"]'),
    ).toContainText('Managed browser bootstrap snippet');
    await expect(
      page.locator('section[aria-label="Credential integration snippet"]'),
    ).toContainText("publishableKey: 'pk_publishablecreated'");
    await expect(page.locator('.dashboard-secret-banner')).toContainText(
      'Save this publishable key now',
    );
    await expect(page.locator('.dashboard-secret-banner')).toContainText('Credential ID');
    await expect(page.locator('.dashboard-secret-banner')).toContainText('ak_newpublishable');
    await expect(page.getByRole('button', { name: 'Copy publishable_key value' })).toBeVisible();
    await expect(credentialsTable).toContainText('frontend-app');
    await expect(credentialsTable).toContainText('pk_efgh...');
    await expect(credentialsTable).toContainText('Use paid overage after quota');
    await expect(credentialsTable).toContainText(createAllowedOrigins.join(', '));
    await expect(credentialsTable).toContainText('Publishable Key');

    const publishableRow = page
      .locator('section[aria-label="Credentials table"] .dashboard-data-table__row')
      .filter({ hasText: 'frontend-app' })
      .filter({ hasText: 'Publishable Key' });
    await publishableRow.getByRole('button', { name: 'Edit' }).click();

    const editCredentialModal = page.locator('section[aria-label="Edit credential modal"]');
    await expect(editCredentialModal).toBeVisible();
    await editCredentialModal.getByLabel('Name').fill('frontend-app-updated');
    await editCredentialModal
      .getByLabel('Allowed origins URI 1')
      .fill(updatedAllowedOrigins[0] || '');
    await editCredentialModal
      .getByLabel('Allowed origins URI 2')
      .fill(updatedAllowedOrigins[1] || '');
    await editCredentialModal
      .getByLabel('Allowed origins URI 3')
      .fill(updatedAllowedOrigins[2] || '');
    await editCredentialModal.getByLabel('Overage behavior').selectOption('always_x402');
    await editCredentialModal.evaluate((node) => {
      node.scrollTop = node.scrollHeight;
    });
    await editCredentialModal.getByRole('button', { name: 'Save changes' }).click();

    await expect.poll(() => String(lastUpdateBody?.name || '')).toBe('frontend-app-updated');
    await expect
      .poll(() => JSON.stringify(lastUpdateBody?.allowedOrigins || []))
      .toBe(JSON.stringify(updatedAllowedOrigins));
    await expect.poll(() => String(lastUpdateBody?.rateLimitBucket || '')).toBe('default_web_v1');
    await expect
      .poll(() => String(lastUpdateBody?.quotaBucket || ''))
      .toBe('free_registrations_v1');
    await expect
      .poll(() => JSON.stringify(lastUpdateBody?.riskPolicy || {}))
      .toBe(JSON.stringify({ captcha: 'adaptive' }));
    await expect
      .poll(() => JSON.stringify(lastUpdateBody?.paymentPolicy || {}))
      .toBe(JSON.stringify({ mode: 'always_x402', productId: 'wallet_registration_v1' }));
    await expect(page.locator('section[aria-label="Credentials table"]')).toContainText(
      'frontend-app-updated',
    );
  });

  test('observability page wires API and renders no-data + module warnings', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    const context = buildMockDashboardContext();
    let lastSummaryProjectId = '';
    let lastSummaryEnvironmentId = '';
    let lastEventsLimit = '';
    let lastEventsFrom = '';
    let lastEventsTo = '';

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
              roles: ['admin', 'ops'],
              projectId: 'proj_active',
              environmentId: 'env_active',
            },
          }),
        });
        return;
      }

      if (pathname === '/console/onboarding/state' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            state: {
              orgId: 'org_dash_console_pages',
              organization: context.org,
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
              selectedProjectId: 'proj_active',
              selectedEnvironmentId: 'env_active',
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

      if (pathname === '/console/observability/summary' && method === 'GET') {
        lastSummaryProjectId = String(url.searchParams.get('projectId') || '').trim();
        lastSummaryEnvironmentId = String(url.searchParams.get('environmentId') || '').trim();
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            summary: {
              generatedAt: iso('2026-03-03T10:00:00.000Z'),
              status: { state: 'ok' },
              errorRate: 0,
              p95LatencyMs: 12,
              failingServices: 0,
              deadLetterCount: 0,
            },
          }),
        });
        return;
      }

      if (pathname === '/console/observability/events' && method === 'GET') {
        lastEventsLimit = String(url.searchParams.get('limit') || '').trim();
        lastEventsFrom = String(url.searchParams.get('from') || '').trim();
        lastEventsTo = String(url.searchParams.get('to') || '').trim();
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            status: {
              state: 'not_configured',
              code: 'observability_storage_not_ready',
              message: 'Storage wiring pending',
            },
            events: [],
            totalPages: 1,
          }),
        });
        return;
      }

      if (pathname === '/console/observability/services' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            status: {
              state: 'forbidden',
              code: 'forbidden',
              message: 'Support role requires redaction profile',
            },
            services: [],
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

    await page.goto('/dashboard/observability');
    await expect(page.locator('#dashboard-main-title')).toHaveText(/observability/i);
    await expect.poll(() => lastSummaryProjectId).toBe('proj_active');
    await expect.poll(() => lastSummaryEnvironmentId).toBe('env_active');
    await expect.poll(() => lastEventsLimit).toBe('100');
    await expect.poll(() => lastEventsFrom).not.toBe('');
    await expect.poll(() => lastEventsTo).not.toBe('');
    const eventsFromMs = Date.parse(lastEventsFrom);
    const eventsToMs = Date.parse(lastEventsTo);
    expect(Number.isFinite(eventsFromMs)).toBe(true);
    expect(Number.isFinite(eventsToMs)).toBe(true);
    expect(eventsToMs - eventsFromMs).toBeGreaterThan(1000 * 60 * 60 * 23);
    expect(eventsToMs - eventsFromMs).toBeLessThan(1000 * 60 * 60 * 25);
    await expect(page.locator('section[aria-label="Observability summary metrics"]')).toContainText(
      '12ms',
    );
    await expect(page.locator('ul[aria-label="Observability status warnings"]')).toContainText(
      'Events is not configured',
    );
    await expect(page.locator('ul[aria-label="Observability status warnings"]')).toContainText(
      'Service health is not available for this role',
    );
    const serviceControlsSection = page.locator(
      'section[aria-label="Observability service health controls"]',
    );
    const serviceSection = page.locator('section[aria-label="Observability service health"]');
    const eventsSection = page.locator('section[aria-label="Observability events table"]');
    const eventControlsSection = page.locator('div[aria-label="Observability event controls"]');
    await expect(serviceControlsSection).toContainText(
      'Aggregated incident roll-up by service for the selected scope.',
    );
    await expect(serviceControlsSection).toContainText('Incident window: Last 24 hours.');
    await expect(eventsSection).toContainText(
      'Detailed incident rows behind the service health snapshot.',
    );
    await expect(eventControlsSection).toContainText('Incident window: Last 24 hours.');
    await expect(eventsSection).toContainText(
      'No incidents in the selected window. Observability is incident-driven, so healthy periods can be empty.',
    );
    const [serviceControlsBox, serviceBox, eventControlsBox, eventsBox] = await Promise.all([
      serviceControlsSection.boundingBox(),
      serviceSection.boundingBox(),
      eventControlsSection.boundingBox(),
      page.locator('section[aria-label="Observability events"]').boundingBox(),
    ]);
    expect(serviceControlsBox).not.toBeNull();
    expect(serviceBox).not.toBeNull();
    expect(eventControlsBox).not.toBeNull();
    expect(eventsBox).not.toBeNull();
    expect(serviceBox!.y).toBeGreaterThan(serviceControlsBox!.y);
    expect(eventControlsBox!.y).toBeGreaterThan(serviceBox!.y);
    expect(eventsBox!.y).toBeGreaterThan(eventControlsBox!.y);
    await expect(eventsSection.getByRole('button', { name: 'Load more events' })).toHaveCount(0);
  });

  test('observability events fetches first page on mount and uses explicit load-more for cursor pages', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    const context = buildMockDashboardContext();
    const allEvents = Array.from({ length: 102 }, (_, index) => ({
      id: `evt_${index + 1}`,
      orgId: 'org_dash_console_pages',
      projectId: 'proj_active',
      environmentId: 'env_active',
      timestamp: iso(
        `2026-03-03T${String(10 + Math.floor(index / 60)).padStart(2, '0')}:${String(index % 60).padStart(2, '0')}:00.000Z`,
      ),
      service: 'webhooks',
      component: 'delivery',
      level: 'WARN',
      eventType: 'delivery.retry',
      message: `Event ${index + 1}`,
      requestId: `req_${index + 1}`,
      traceId: `trace_${index + 1}`,
      metadata: { retry: index + 1 },
    }));
    const requestedEventLimits: string[] = [];
    const requestedEventCursors: string[] = [];

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
              roles: ['admin', 'ops'],
              projectId: 'proj_active',
              environmentId: 'env_active',
            },
          }),
        });
        return;
      }

      if (pathname === '/console/onboarding/state' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            state: {
              orgId: 'org_dash_console_pages',
              organization: context.org,
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
              selectedProjectId: 'proj_active',
              selectedEnvironmentId: 'env_active',
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

      if (pathname === '/console/observability/summary' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            summary: {
              generatedAt: iso('2026-03-03T10:00:00.000Z'),
              status: { state: 'ok' },
              errorRate: 0,
              p95LatencyMs: 20,
              failingServices: 0,
              deadLetterCount: 0,
            },
          }),
        });
        return;
      }

      if (pathname === '/console/observability/events' && method === 'GET') {
        requestedEventLimits.push(String(url.searchParams.get('limit') || '').trim());
        requestedEventCursors.push(String(url.searchParams.get('cursor') || '').trim());
        const limit = Math.max(1, Number(url.searchParams.get('limit') || '50'));
        const cursor = String(url.searchParams.get('cursor') || '').trim();
        const pageIndex = cursor.startsWith('page_') ? Number(cursor.slice(5)) : 0;
        const normalizedPageIndex = Number.isFinite(pageIndex) && pageIndex > 0 ? pageIndex : 0;
        const sliceStart = normalizedPageIndex * limit;
        const events = allEvents.slice(sliceStart, sliceStart + limit);
        const totalPages = Math.max(1, Math.ceil(allEvents.length / limit));
        const nextCursor =
          sliceStart + limit < allEvents.length ? `page_${normalizedPageIndex + 1}` : '';
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            status: { state: 'ok' },
            events,
            totalPages,
            ...(nextCursor ? { nextCursor } : {}),
          }),
        });
        return;
      }

      if (pathname === '/console/observability/services' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            status: { state: 'ok' },
            services: [],
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

    await page.goto('/dashboard/observability');
    await expect(page.locator('#dashboard-main-title')).toHaveText(/observability/i);
    await expect.poll(() => requestedEventLimits[0] || '').toBe('100');
    await expect.poll(() => requestedEventCursors.includes('page_1')).toBe(false);

    const eventsSection = page.locator('section[aria-label="Observability events table"]');
    await expect(eventsSection).toContainText('Showing 1-10 of 100 events');
    await expect(eventsSection).toContainText('Page 1 | 10');

    await eventsSection.getByRole('button', { name: 'Next' }).click();
    await expect(eventsSection).toContainText('Page 2 | 10');
    await expect.poll(() => requestedEventCursors.includes('page_1')).toBe(false);

    await eventsSection.getByRole('button', { name: 'Load more events' }).click();
    await expect.poll(() => requestedEventCursors.includes('page_1')).toBe(true);
    await expect(eventsSection).toContainText('of 102 events');
    await expect(eventsSection.getByRole('button', { name: 'Load more events' })).toHaveCount(0);
  });

  test('observability events search and filters drive API params', async ({ page, baseURL }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    const context = buildMockDashboardContext();
    const allEvents = [
      {
        id: 'evt_obs_webhooks_warn',
        orgId: 'org_dash_console_filters',
        projectId: 'proj_active',
        environmentId: 'env_active',
        timestamp: iso('2026-03-03T10:00:00.000Z'),
        service: 'webhooks',
        component: 'delivery',
        level: 'WARN',
        eventType: 'delivery.retry',
        message: 'Dead letter retry queued',
        requestId: 'req_webhook_1',
        traceId: 'trace_webhook_1',
        metadata: { queue: 'dlq' },
      },
      {
        id: 'evt_obs_billing_error',
        orgId: 'org_dash_console_filters',
        projectId: 'proj_active',
        environmentId: 'env_active',
        timestamp: iso('2026-03-03T10:01:00.000Z'),
        service: 'billing',
        component: 'invoice',
        level: 'ERROR',
        eventType: 'invoice.reconcile_failed',
        message: 'Invoice settle timeout',
        requestId: 'req_billing_1',
        traceId: 'trace_billing_1',
        metadata: { invoiceId: 'inv_1' },
      },
    ];
    let lastEventsQuery = '';
    let lastEventsLevel = '';
    let lastEventsService = '';
    let lastEventsComponent = '';
    let lastEventsEventType = '';
    let lastEventsFrom = '';
    let lastEventsTo = '';

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
              userId: 'user_dash_console_filters',
              orgId: 'org_dash_console_filters',
              roles: ['admin', 'ops'],
              projectId: 'proj_active',
              environmentId: 'env_active',
            },
          }),
        });
        return;
      }

      if (pathname === '/console/onboarding/state' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            state: {
              orgId: 'org_dash_console_filters',
              organization: context.org,
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
              selectedProjectId: 'proj_active',
              selectedEnvironmentId: 'env_active',
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

      if (pathname === '/console/observability/summary' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            summary: {
              generatedAt: iso('2026-03-03T10:00:00.000Z'),
              status: { state: 'ok' },
              errorRate: 0,
              p95LatencyMs: 20,
              failingServices: 1,
              deadLetterCount: 1,
            },
          }),
        });
        return;
      }

      if (pathname === '/console/observability/events' && method === 'GET') {
        lastEventsQuery = String(url.searchParams.get('query') || '').trim();
        lastEventsLevel = String(url.searchParams.get('level') || '').trim();
        lastEventsService = String(url.searchParams.get('service') || '').trim();
        lastEventsComponent = String(url.searchParams.get('component') || '').trim();
        lastEventsEventType = String(url.searchParams.get('eventType') || '').trim();
        lastEventsFrom = String(url.searchParams.get('from') || '').trim();
        lastEventsTo = String(url.searchParams.get('to') || '').trim();
        const normalizedQuery = lastEventsQuery.toLowerCase();
        const filteredEvents = allEvents.filter((entry) => {
          if (lastEventsLevel && entry.level !== lastEventsLevel) return false;
          if (lastEventsService && entry.service !== lastEventsService) return false;
          if (lastEventsComponent && entry.component !== lastEventsComponent) return false;
          if (lastEventsEventType && entry.eventType !== lastEventsEventType) return false;
          if (!normalizedQuery) return true;
          const haystack = [
            entry.id,
            entry.service,
            entry.component,
            entry.eventType,
            entry.message,
            entry.requestId,
            entry.traceId,
            JSON.stringify(entry.metadata),
          ]
            .join(' ')
            .toLowerCase();
          return haystack.includes(normalizedQuery);
        });
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            status: { state: 'ok' },
            events: filteredEvents,
            totalPages: 1,
          }),
        });
        return;
      }

      if (pathname === '/console/observability/services' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            status: { state: 'ok' },
            services: [],
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

    await page.goto('/dashboard/observability');
    await expect(page.locator('#dashboard-main-title')).toHaveText(/observability/i);

    await page
      .locator('select[aria-label="Filter observability events by time window"]')
      .selectOption('1h');
    await expect.poll(() => lastEventsFrom).not.toBe('');
    await expect.poll(() => lastEventsTo).not.toBe('');
    await expect
      .poll(() => Date.parse(lastEventsTo) - Date.parse(lastEventsFrom))
      .toBeGreaterThan(1000 * 60 * 55);
    await expect
      .poll(() => Date.parse(lastEventsTo) - Date.parse(lastEventsFrom))
      .toBeLessThan(1000 * 60 * 65);

    await page.locator('input[aria-label="Search observability events"]').fill('invoice');
    await expect.poll(() => lastEventsQuery).toBe('invoice');
    await expect(page.locator('section[aria-label="Observability events table"]')).toContainText(
      'Invoice settle timeout',
    );
    await expect(
      page.locator('section[aria-label="Observability events table"]'),
    ).not.toContainText('Dead letter retry queued');

    await page
      .locator('select[aria-label="Filter observability events by level"]')
      .selectOption('ERROR');
    await expect.poll(() => lastEventsLevel).toBe('ERROR');

    await page
      .locator('div[aria-label="Observability event controls"]')
      .getByRole('button', { name: 'Billing' })
      .click();
    await expect.poll(() => lastEventsService).toBe('billing');

    await page
      .locator('input[aria-label="Filter observability events by component"]')
      .fill('invoice');
    await expect.poll(() => lastEventsComponent).toBe('invoice');

    await page
      .locator('input[aria-label="Filter observability events by event type"]')
      .fill('invoice.reconcile_failed');
    await expect.poll(() => lastEventsEventType).toBe('invoice.reconcile_failed');
    await expect(page.locator('section[aria-label="Observability events table"]')).toContainText(
      'Invoice settle timeout',
    );

    await page.locator('input[aria-label="Search observability events"]').fill('missing-token');
    await expect.poll(() => lastEventsQuery).toBe('missing-token');
    await expect(page.locator('section[aria-label="Observability events table"]')).toContainText(
      'No observability incidents match the current filters.',
    );
  });

  test('observability page surfaces forbidden and not-configured API errors', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    const context = buildMockDashboardContext();
    let responseMode: 'forbidden' | 'not_configured' = 'forbidden';

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
              roles: ['developer'],
              projectId: 'proj_active',
              environmentId: 'env_active',
            },
          }),
        });
        return;
      }

      if (pathname === '/console/onboarding/state' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            state: {
              orgId: 'org_dash_console_pages',
              organization: context.org,
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
              selectedProjectId: 'proj_active',
              selectedEnvironmentId: 'env_active',
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

      if (pathname.startsWith('/console/observability/')) {
        if (responseMode === 'forbidden') {
          await route.fulfill({
            status: 403,
            contentType: 'application/json',
            body: JSON.stringify({
              ok: false,
              code: 'forbidden',
              message: 'Only owner, admin, security_admin, ops, or support can view observability',
            }),
          });
          return;
        }
        await route.fulfill({
          status: 501,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: false,
            code: 'observability_not_configured',
            message: 'Observability service is not configured for this server',
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

    await page.goto('/dashboard/observability');
    await expect(page.locator('#dashboard-main-title')).toHaveText(/observability/i);
    await expect(page.locator('p[role="alert"]')).toContainText(
      'Observability is not available for this role.',
    );

    responseMode = 'not_configured';
    await page.reload();
    await expect(page.locator('p[role="alert"]')).toContainText(
      'Observability service is not configured on this server.',
    );
  });

  test('ops cockpit route aggregates operator queues from console APIs', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    const context = buildMockDashboardContext();
    let lastSummaryWindowMinutes = '';
    let approveRequestCount = 0;
    let rejectRequestCount = 0;
    let lastApproveBody: Record<string, unknown> | null = null;
    let lastRejectBody: Record<string, unknown> | null = null;
    let auditExportListRequestCount = 0;
    let auditExportCreateRequestCount = 0;
    let lastAuditExportCreateBody: Record<string, unknown> | null = null;
    let replayRequestCount = 0;
    let lastReplayBody: Record<string, unknown> | null = null;

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
              roles: ['admin', 'ops'],
              projectId: 'proj_active',
              environmentId: 'env_active',
            },
          }),
        });
        return;
      }

      if (pathname === '/console/onboarding/state' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            state: {
              orgId: 'org_dash_console_pages',
              organization: context.org,
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
              selectedProjectId: 'proj_active',
              selectedEnvironmentId: 'env_active',
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

      if (pathname === '/console/ops-cockpit/summary' && method === 'GET') {
        lastSummaryWindowMinutes = String(url.searchParams.get('windowMinutes') || '').trim();
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            summary: {
              generatedAt: iso('2026-03-02T12:00:00.000Z'),
              approvals: {
                status: { state: 'ok' },
                pendingCount: 2,
                pending: [
                  {
                    id: 'apr_1',
                    operationType: 'POLICY_PUBLISH',
                    reason: 'Policy reviewed for publish.',
                    requestedByUserId: 'user_alpha',
                    requiredApprovals: 1,
                    requireMfa: false,
                    resourceType: 'POLICY',
                    resourceId: 'pol_123',
                    createdAt: iso('2026-03-01T10:00:00.000Z'),
                  },
                  {
                    id: 'apr_2',
                    operationType: 'KEY_EXPORT',
                    reason: 'Emergency recovery export.',
                    requestedByUserId: 'user_beta',
                    requiredApprovals: 2,
                    requireMfa: true,
                    resourceType: 'KEY_EXPORT',
                    resourceId: 'ke_123',
                    createdAt: iso('2026-03-01T11:00:00.000Z'),
                  },
                ],
              },
              billing: {
                status: { state: 'ok' },
                failedInvoiceCount: 2,
                failedInvoices: [
                  {
                    id: 'inv_failed',
                    status: 'UNCOLLECTIBLE',
                    dueAt: iso('2026-03-01T00:00:00.000Z'),
                  },
                  {
                    id: 'inv_overdue',
                    status: 'OPEN',
                    dueAt: iso('2026-03-01T00:00:00.000Z'),
                  },
                ],
              },
              webhooks: {
                status: { state: 'ok' },
                endpointCount: 2,
                scannedEndpointCount: 2,
                deadLetterCount: 1,
                deadLetters: [
                  {
                    endpointId: 'wh_ep_1',
                    endpointUrl: 'https://example.com/hook-1',
                    endpointStatus: 'ACTIVE',
                    deadLetter: {
                      id: 'dlq_1',
                      deliveryId: 'del_1',
                      eventId: 'evt_1',
                      eventType: 'billing.invoice.payment_failed',
                      failedAttempts: 3,
                      lastErrorMessage: 'Upstream unavailable',
                      movedToDlqAt: iso('2026-03-01T12:00:00.000Z'),
                    },
                  },
                ],
              },
              auditExports: {
                status: { state: 'ok' },
                queuedExportCount: 2,
                queuedExports: [
                  {
                    id: 'exp_queued',
                    status: 'QUEUED',
                    format: 'JSONL',
                    createdAt: iso('2026-03-01T09:00:00.000Z'),
                  },
                  {
                    id: 'exp_processing',
                    status: 'PROCESSING',
                    format: 'CSV',
                    createdAt: iso('2026-03-01T09:30:00.000Z'),
                  },
                ],
              },
              enterpriseIsolation: {
                status: { state: 'ok' },
                activeRequestCount: 1,
                activeRequests: [
                  {
                    status: 'REQUESTED',
                    trigger: 'MANUAL',
                  },
                ],
              },
              onboardingTelemetry: {
                status: { state: 'ok' },
                windowMinutes: 60,
                alertCount: 1,
                alerts: [
                  {
                    code: 'onboarding_latency_slo_breached',
                    operation: 'project',
                    severity: 'WARN',
                    message: 'project p95 latency exceeded threshold',
                  },
                ],
              },
            },
          }),
        });
        return;
      }

      if (pathname === '/console/webhooks/wh_ep_1/replay' && method === 'POST') {
        replayRequestCount += 1;
        lastReplayBody = parseJsonBody(req.postData());
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            replay: {
              replayed: true,
            },
          }),
        });
        return;
      }

      if (pathname === '/console/audit/exports' && method === 'GET') {
        auditExportListRequestCount += 1;
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            exports: [
              {
                id: 'exp_queued',
                orgId: 'org_dash_console_pages',
                requestedByUserId: 'user_dash_console_pages',
                status: 'QUEUED',
                format: 'JSONL',
                filters: {
                  domain: 'POLICY',
                  projectId: 'proj_active',
                  environmentId: 'env_active',
                },
                createdAt: iso('2026-03-01T09:00:00.000Z'),
                updatedAt: iso('2026-03-01T09:00:00.000Z'),
                readyAt: null,
                expiresAt: null,
                downloadUrl: null,
                failureCode: null,
                failureMessage: null,
              },
              {
                id: 'exp_processing',
                orgId: 'org_dash_console_pages',
                requestedByUserId: 'user_dash_console_pages',
                status: 'PROCESSING',
                format: 'CSV',
                filters: {
                  domain: 'BILLING',
                  projectId: 'proj_active',
                  environmentId: 'env_active',
                },
                createdAt: iso('2026-03-01T09:30:00.000Z'),
                updatedAt: iso('2026-03-01T09:30:00.000Z'),
                readyAt: null,
                expiresAt: null,
                downloadUrl: null,
                failureCode: null,
                failureMessage: null,
              },
            ],
          }),
        });
        return;
      }

      if (pathname === '/console/audit/exports' && method === 'POST') {
        auditExportCreateRequestCount += 1;
        lastAuditExportCreateBody = parseJsonBody(req.postData());
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            export: {
              id: 'exp_requeued_1',
              orgId: 'org_dash_console_pages',
              requestedByUserId: 'user_dash_console_pages',
              status: 'QUEUED',
              format: String(lastAuditExportCreateBody?.format || 'JSONL'),
              filters: {
                domain: String(lastAuditExportCreateBody?.domain || ''),
                projectId: String(lastAuditExportCreateBody?.projectId || ''),
                environmentId: String(lastAuditExportCreateBody?.environmentId || ''),
              },
              createdAt: iso('2026-03-02T13:05:00.000Z'),
              updatedAt: iso('2026-03-02T13:05:00.000Z'),
              readyAt: null,
              expiresAt: null,
              downloadUrl: null,
              failureCode: null,
              failureMessage: null,
            },
          }),
        });
        return;
      }

      if (pathname === '/console/approvals/apr_1/approve' && method === 'POST') {
        approveRequestCount += 1;
        lastApproveBody = parseJsonBody(req.postData());
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            approval: {
              id: 'apr_1',
              orgId: 'org_dash_console_pages',
              operationType: 'POLICY_PUBLISH',
              status: 'APPROVED',
              reason: 'Policy reviewed for publish.',
              requestedByUserId: 'user_alpha',
              requiredApprovals: 1,
              requireMfa: false,
              projectId: 'proj_active',
              environmentId: 'env_active',
              resourceType: 'POLICY',
              resourceId: 'pol_123',
              metadata: {},
              decisions: [
                {
                  decision: 'APPROVE',
                  actorUserId: 'user_dash_console_pages',
                  reason: String(lastApproveBody?.reason || ''),
                  mfaVerified: lastApproveBody?.mfaVerified === true,
                  decidedAt: iso('2026-03-02T13:00:00.000Z'),
                },
              ],
              createdAt: iso('2026-03-01T10:00:00.000Z'),
              updatedAt: iso('2026-03-02T13:00:00.000Z'),
              resolvedAt: iso('2026-03-02T13:00:00.000Z'),
            },
          }),
        });
        return;
      }

      if (pathname === '/console/approvals/apr_2/reject' && method === 'POST') {
        rejectRequestCount += 1;
        lastRejectBody = parseJsonBody(req.postData());
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            approval: {
              id: 'apr_2',
              orgId: 'org_dash_console_pages',
              operationType: 'KEY_EXPORT',
              status: 'REJECTED',
              reason: 'Emergency recovery export.',
              requestedByUserId: 'user_beta',
              requiredApprovals: 2,
              requireMfa: true,
              projectId: 'proj_active',
              environmentId: 'env_active',
              resourceType: 'KEY_EXPORT',
              resourceId: 'ke_123',
              metadata: {},
              decisions: [
                {
                  decision: 'REJECT',
                  actorUserId: 'user_dash_console_pages',
                  reason: String(lastRejectBody?.reason || ''),
                  mfaVerified: false,
                  decidedAt: iso('2026-03-02T13:01:00.000Z'),
                },
              ],
              createdAt: iso('2026-03-01T11:00:00.000Z'),
              updatedAt: iso('2026-03-02T13:01:00.000Z'),
              resolvedAt: iso('2026-03-02T13:01:00.000Z'),
            },
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

    await page.goto('/dashboard/overview');
    await expect(page.locator('#dashboard-main-title')).toHaveText(/overview/i);
    await expect.poll(() => lastSummaryWindowMinutes).toBe('60');

    const summary = page.locator('section[aria-label="Ops cockpit summary"]');
    await expect(summary).toContainText(
      'Daily queues for approvals, billing, webhooks, audit exports, isolation, and onboarding alerts.',
    );
    await expect(summary.locator('button:has-text("Refresh queues")')).toHaveCount(0);
    await expect(summary.locator('article:has(h2:has-text("Pending approvals"))')).toContainText(
      '2',
    );
    await expect(
      summary.locator('article:has(h2:has-text("Failed or overdue invoices"))'),
    ).toContainText('2');
    await expect(summary.locator('article:has(h2:has-text("Failed webhooks"))')).toContainText('1');
    await expect(summary.locator('article:has(h2:has-text("Queued audit exports"))')).toContainText(
      '2',
    );
    await expect(summary.locator('article:has(h2:has-text("Isolation requests"))')).toContainText(
      '1',
    );
    await expect(
      summary.locator('article:has(h2:has-text("Onboarding SLO alerts"))'),
    ).toContainText('1');

    const pendingApprovalsSummary = page.locator('section[aria-label="Pending approvals summary"]');
    await expect(pendingApprovalsSummary).not.toContainText('Approval action reason');
    await expect(pendingApprovalsSummary).not.toContainText('MFA verified (approve)');
    await expect(pendingApprovalsSummary).toContainText(
      'Requested reason: Policy reviewed for publish.',
    );
    await expect(pendingApprovalsSummary).toContainText(
      'Requested reason: Emergency recovery export.',
    );
    await expect(pendingApprovalsSummary).toContainText(
      'Approve unavailable in overview: this request requires MFA verification.',
    );

    const policyApprovalRow = pendingApprovalsSummary.locator('li').filter({ hasText: 'pol_123' });
    await policyApprovalRow.locator('button:has-text("Approve")').click();
    await expect.poll(() => approveRequestCount).toBe(1);
    await expect
      .poll(() => String(lastApproveBody?.reason || ''))
      .toBe('Approved from Ops Cockpit');
    await expect.poll(() => lastApproveBody?.mfaVerified === true).toBe(false);
    await expect(pendingApprovalsSummary).toContainText('Approval request apr_1 is now APPROVED.');

    const keyExportApprovalRow = pendingApprovalsSummary
      .locator('li')
      .filter({ hasText: 'ke_123' });
    await expect(keyExportApprovalRow.locator('button:has-text("Approve")')).toHaveCount(0);
    await keyExportApprovalRow.locator('button:has-text("Reject")').click();
    await expect.poll(() => rejectRequestCount).toBe(1);
    await expect.poll(() => String(lastRejectBody?.reason || '')).toBe('Rejected from Ops Cockpit');
    await expect(pendingApprovalsSummary).toContainText('Approval request apr_2 is now REJECTED.');

    const failedWebhookSummary = page.locator('section[aria-label="Failed webhook summary"]');
    await failedWebhookSummary.locator('button:has-text("Replay")').click();
    await expect.poll(() => replayRequestCount).toBe(1);
    await expect.poll(() => String(lastReplayBody?.deliveryId || '')).toBe('del_1');
    await expect(failedWebhookSummary).toContainText('Replay queued for delivery del_1.');

    const auditExportSummary = page.locator('section[aria-label="Audit export queue summary"]');
    await auditExportSummary.locator('button:has-text("Requeue")').first().click();
    await expect.poll(() => auditExportListRequestCount).toBe(1);
    await expect.poll(() => auditExportCreateRequestCount).toBe(1);
    await expect.poll(() => String(lastAuditExportCreateBody?.format || '')).toBe('JSONL');
    await expect.poll(() => String(lastAuditExportCreateBody?.domain || '')).toBe('POLICY');
    await expect.poll(() => String(lastAuditExportCreateBody?.projectId || '')).toBe('proj_active');
    await expect
      .poll(() => String(lastAuditExportCreateBody?.environmentId || ''))
      .toBe('env_active');
    await expect(auditExportSummary).toContainText(
      'Queued replacement export exp_requeued_1 from exp_queued.',
    );

    await summary
      .locator('article:has(h2:has-text("Pending approvals")) button:has-text("View pending")')
      .click();
    await expect(page.locator('section[aria-label="Pending approvals summary"]')).toBeVisible();
  });

  test('overview route moves not-configured audit export and enterprise isolation states into queue panels', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    const context = buildMockDashboardContext();

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
              roles: ['admin', 'ops'],
              projectId: 'proj_active',
              environmentId: 'env_active',
            },
          }),
        });
        return;
      }

      if (pathname === '/console/onboarding/state' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            state: {
              orgId: 'org_dash_console_pages',
              organization: context.org,
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
              selectedProjectId: 'proj_active',
              selectedEnvironmentId: 'env_active',
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

      if (pathname === '/console/ops-cockpit/summary' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            summary: {
              generatedAt: iso('2026-03-02T12:00:00.000Z'),
              approvals: {
                status: { state: 'ok' },
                pendingCount: 0,
                pending: [],
              },
              billing: {
                status: { state: 'ok' },
                failedInvoiceCount: 0,
                failedInvoices: [],
              },
              webhooks: {
                status: { state: 'ok' },
                endpointCount: 0,
                scannedEndpointCount: 0,
                deadLetterCount: 0,
                deadLetters: [],
              },
              auditExports: {
                status: { state: 'not_configured', message: 'Audit exports backend disabled' },
                queuedExportCount: 0,
                queuedExports: [],
              },
              enterpriseIsolation: {
                status: { state: 'not_configured', message: 'Isolation backend disabled' },
                activeRequestCount: 0,
                activeRequests: [],
              },
              onboardingTelemetry: {
                status: { state: 'ok' },
                windowMinutes: 60,
                alertCount: 0,
                alerts: [],
              },
            },
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

    await page.goto('/dashboard/overview');
    await expect(page.locator('#dashboard-main-title')).toHaveText(/overview/i);

    const summary = page.locator('section[aria-label="Ops cockpit summary"]');
    await expect(summary).not.toContainText('Audit export queue is not configured');
    await expect(summary).not.toContainText('Enterprise isolation queue is not configured');

    await expect(page.locator('section[aria-label="Audit export queue status"]')).toContainText(
      'Audit export queue is not configured',
    );
    await expect(page.locator('section[aria-label="Audit export queue status"]')).toContainText(
      'Audit exports backend disabled',
    );
    await expect(
      page.locator('section[aria-label="Enterprise isolation queue status"]'),
    ).toContainText('Enterprise isolation queue is not configured');
    await expect(
      page.locator('section[aria-label="Enterprise isolation queue status"]'),
    ).toContainText('Isolation backend disabled');
    await expect(page.locator('section[aria-label="Onboarding telemetry summary"]')).toContainText(
      'No active onboarding SLO alerts.',
    );
    await expect(page.locator('section[aria-label="Audit export queue summary"]')).toHaveCount(0);
    await expect(
      page.locator('section[aria-label="Isolation and onboarding telemetry summary"]'),
    ).toHaveCount(0);
  });
});

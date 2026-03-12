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
    await onboardingForm.locator('input[placeholder="Acme Wallets"]').fill('Acme Org');
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

  test('account settings create, rename, transfer, and open flows rehydrate switched context', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    let sessionRequestCount = 0;
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
      [
        'org_created',
        {
          id: 'proj_created',
          name: 'Created Project',
          slug: 'created-project',
          status: 'ACTIVE',
          environmentCount: 1,
          createdAt: iso('2026-01-05T00:00:00.000Z'),
          updatedAt: iso('2026-01-05T00:00:00.000Z'),
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
      [
        'proj_created',
        {
          id: 'env_created',
          projectId: 'proj_created',
          key: 'prod',
          name: 'Created Environment',
          status: 'ACTIVE',
          createdAt: iso('2026-01-05T00:00:00.000Z'),
          updatedAt: iso('2026-01-05T00:00:00.000Z'),
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
        sessionRequestCount += 1;
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
        const createdOrganization = {
          id: 'org_created',
          name: String(body.name || '').trim() || 'Created Org',
          slug: String(body.slug || '').trim() || 'created-org',
          status: 'ACTIVE',
          createdAt: iso('2026-01-05T00:00:00.000Z'),
          updatedAt: iso('2026-01-05T00:00:00.000Z'),
          actorRoles: ['owner', 'admin'],
          actorIsOwner: true,
          actorIsAdmin: true,
          onboardingComplete: true,
          selectedProjectId: 'proj_created',
          selectedProjectName: 'Created Project',
          selectedEnvironmentId: 'env_created',
          selectedEnvironmentName: 'Created Environment',
          adminCandidates: [],
        };
        organizations.set('org_created', createdOrganization);
        orgDetails.set('org_created', {
          id: 'org_created',
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
        activeOrgId = orgId;
        sessionClaims = {
          userId: 'user_account_settings_flow',
          orgId: 'org_target',
          roles: ['admin'],
          projectId: 'proj_target',
          environmentId: 'env_target',
          provider: 'passkey',
        };
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            context: {
              orgId: 'org_target',
              projectId: 'proj_target',
              environmentId: 'env_target',
              actorRoles: ['admin'],
              onboardingComplete: true,
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

    await page.getByRole('button', { name: 'Create organization' }).click();
    const createOrganizationDialog = page.getByLabel('Create organization modal');
    await createOrganizationDialog.getByLabel('Organization name').fill('Created Org');
    await createOrganizationDialog.getByLabel('Slug').fill('created-org');
    await createOrganizationDialog.getByRole('button', { name: 'Create organization' }).click();
    await expect.poll(() => createBodies.length).toBe(1);
    expect(createBodies[0]).toMatchObject({
      name: 'Created Org',
      slug: 'created-org',
    });
    await expect(page.getByRole('status')).toContainText(/organization created/i);

    const organizationsTable = page.getByRole('table', { name: 'Organizations' });
    const targetRowBeforeTransfer = organizationsTable
      .getByRole('row')
      .filter({ hasText: 'Target Org' });
    await expect(targetRowBeforeTransfer).toContainText('Target Project');
    await expect(targetRowBeforeTransfer).toContainText('Target Environment');
    await targetRowBeforeTransfer.getByRole('button', { name: 'Rename' }).click();
    const renameDialog = page.getByLabel('Rename organization modal');
    await renameDialog.getByLabel('Organization name').fill('Target Org Renamed');
    await renameDialog.getByRole('button', { name: 'Rename' }).click();
    await expect.poll(() => renameBodies.length).toBe(1);
    expect(renameBodies[0]).toMatchObject({
      orgId: 'org_target',
      body: {
        name: 'Target Org Renamed',
      },
    });

    const targetRow = organizationsTable.getByRole('row').filter({ hasText: 'Target Org Renamed' });
    await expect(targetRow).toBeVisible();

    await targetRow.locator('select').selectOption('member_target_admin');
    await targetRow.getByRole('button', { name: 'Transfer' }).click();
    await expect.poll(() => transferBodies.length).toBe(1);
    expect(transferBodies[0]).toMatchObject({
      orgId: 'org_target',
      body: {
        targetMemberId: 'member_target_admin',
      },
    });

    const targetRowAfterTransfer = organizationsTable
      .getByRole('row')
      .filter({ hasText: 'Target Org Renamed' });
    await targetRowAfterTransfer.getByRole('button', { name: 'Open' }).click();
    await expect.poll(() => switchBodies.length).toBe(1);
    expect(switchBodies[0]).toMatchObject({
      orgId: 'org_target',
    });

    await expect.poll(() => new URL(page.url()).pathname).toBe('/dashboard/overview');
    await expect.poll(() => sessionRequestCount).toBeGreaterThan(1);

    const topbarContext = page.locator('header[aria-label="Workspace context"]');
    await expect(topbarContext.locator('button:has-text("Project")')).toContainText(
      'Target Project',
    );
    await expect(topbarContext.locator('button:has-text("Environment")')).toContainText(
      'Target Environment',
    );
    await expect
      .poll(() =>
        page.evaluate(() => {
          const raw = window.localStorage.getItem('tatchi-dashboard-ui-state-v1');
          const parsed = raw ? JSON.parse(raw) : null;
          return String(parsed?.selectedContext?.project || '');
        }),
      )
      .toBe('proj_target');
    await expect
      .poll(() =>
        page.evaluate(() => {
          const raw = window.localStorage.getItem('tatchi-dashboard-ui-state-v1');
          const parsed = raw ? JSON.parse(raw) : null;
          return String(parsed?.selectedContext?.environment || '');
        }),
      )
      .toBe('env_target');

    await page.goto('/dashboard/billing/account');
    await expect.poll(() => new URL(page.url()).pathname).toBe('/dashboard/billing/account');
    await expect(page.locator('#dashboard-main-title')).toHaveText(/billing account/i);
    await expect
      .poll(() => billingOverviewOrgIds[billingOverviewOrgIds.length - 1] || '')
      .toBe('org_target');
    await expect
      .poll(() => billingUsageOrgIds[billingUsageOrgIds.length - 1] || '')
      .toBe('org_target');
    await expect
      .poll(() => billingActivityOrgIds[billingActivityOrgIds.length - 1] || '')
      .toBe('org_target');
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
      window.localStorage.setItem('vitepress-theme-appearance', 'dark');
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

  test('dashboard strips legacy db_* query params from URL', async ({ page, baseURL }) => {
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

      if (pathname === '/console/wallets' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, wallets: [], nextCursor: null }),
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

    await page.goto(
      '/dashboard/wallets-list?db_sb=1&db_groups=walletInfrastructure%2CsecurityPolicy%2CintegrationsAutomation%2CenvironmentSettings&db_org=org-dev&db_project=proj_console_core&db_env=proj_console_core-prod&db_acct=Account+%26+Settings',
    );

    await expect(page.locator('#dashboard-main-title')).toHaveText(/user wallets list/i);
    await expect.poll(() => new URL(page.url()).search).toBe('');
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
    const projectPanel = page.locator('section[aria-label="Create project"]').first();
    await expect(projectPanel).toBeVisible();
    await expect(projectPanel).toHaveAttribute('aria-disabled', 'true');
    await expect(projectPanel.locator('label:has-text("Project name") input')).toBeDisabled();
    await expect(projectPanel.locator('button:has-text("Finish onboarding")')).toBeDisabled();
    await expect(onboardingForm.locator('input[placeholder="Acme Wallets"]')).toBeVisible();
    await onboardingForm.locator('input[placeholder="Acme Wallets"]').fill('Acme Wallets');
    await onboardingForm.locator('button:has-text("Continue to project setup")').click();
    await expect(projectPanel).toHaveAttribute('aria-disabled', 'false');
    await expect(projectPanel.locator('label:has-text("Project name") input')).toBeEnabled();

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
    await expect(projectForm.locator('label:has-text("Project name") input')).toBeVisible();
    await projectForm.locator('label:has-text("Project name") input').fill('Consumer App');
    await expect(projectForm.locator('text=Project ID (optional)')).toHaveCount(0);
    await expect(projectForm.locator('text=Environment ID (optional)')).toHaveCount(0);
    await projectForm.locator('button:has-text("Finish onboarding")').click();

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
    await expect(onboardingForm.locator('input[placeholder="Acme Wallets"]')).toHaveValue(
      'Acme Corp',
    );
    await expect(onboardingForm.locator('label:has-text("Organization slug") input')).toHaveValue(
      'acme-corp',
    );
    await onboardingForm.locator('input[placeholder="Acme Wallets"]').fill('Acme Org');
    await expect(onboardingForm.locator('label:has-text("Organization slug") input')).toHaveValue(
      'acme-org',
    );
    await expect(onboardingForm.locator('label:has-text("Organization slug") input')).toBeDisabled();
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
    await expect(onboardingForm.locator('input[placeholder="Acme Wallets"]')).toHaveValue(
      'Acme Corp',
    );
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
        scopePolicyName: null,
        scopeType: 'ENVIRONMENT',
        projectId: 'proj_active',
        environmentId: developmentEnvironment.id,
        scopePolicyId: null,
        walletSegmentId: null,
        networkClass: 'TESTNET',
        enabled: true,
        allowedChainIds: [42431],
        callMode: 'ALLOWLIST',
        spendCap: {
          mode: 'CHAIN_TOTAL',
          period: 'MONTHLY',
          capsByChain: [{ chainId: 42431, capMinor: 50000 }],
        },
        allowedCalls: [
          {
            chainId: 42431,
            to: '0xbb85080E6953f25197ec68798360667140EbAf4b',
            selector: '0x428dc451',
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
        scopeType: String(policy.scopeType || 'ENVIRONMENT'),
        projectId: policy.projectId ?? null,
        environmentId: policy.environmentId ?? null,
        scopePolicyId: policy.scopePolicyId ?? null,
        walletSegmentId: policy.walletSegmentId ?? null,
        templateId: policy.templateId ?? null,
        networkClass: String(policy.networkClass || 'ANY'),
        enabled: policy.enabled !== false,
        allowedChainIds: Array.isArray(policy.allowedChainIds) ? policy.allowedChainIds : [],
        callMode: String(policy.callMode || 'ALLOW_ALL'),
        spendCap:
          policy.spendCap && typeof policy.spendCap === 'object' && !Array.isArray(policy.spendCap)
            ? policy.spendCap
            : { mode: 'NONE', period: 'MONTHLY', capsByChain: [] },
        allowedCalls: Array.isArray(policy.allowedCalls) ? policy.allowedCalls : [],
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

      if (pathname === '/console/policies' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, policies: gasPolicies.map((entry) => toGasPolicy(entry)) }),
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
          scopePolicyName: null,
          scopeType,
          projectId: rules.projectId ?? null,
          environmentId: rules.environmentId ?? null,
          scopePolicyId: rules.scopePolicyId ?? null,
          walletSegmentId: rules.walletSegmentId ?? null,
          networkClass: String(rules.networkClass || 'ANY'),
          enabled: rules.enabled !== false,
          allowedChainIds: Array.isArray(rules.allowedChainIds) ? rules.allowedChainIds : [],
          callMode: String(rules.callMode || 'ALLOW_ALL'),
          spendCap:
            rules.spendCap && typeof rules.spendCap === 'object' && !Array.isArray(rules.spendCap)
              ? rules.spendCap
              : { mode: 'NONE', period: 'MONTHLY', capsByChain: [] },
          allowedCalls: Array.isArray(rules.allowedCalls) ? rules.allowedCalls : [],
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
        if (rules.enabled !== undefined) {
          target.enabled = rules.enabled === true;
        }
        if (Array.isArray(rules.allowedChainIds)) {
          target.allowedChainIds = rules.allowedChainIds;
        }
        if (rules.callMode !== undefined) {
          target.callMode = String(rules.callMode || target.callMode || 'ALLOW_ALL');
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
    await gasCreateModalAfterRefresh
      .getByRole('group', { name: 'Tempo Testnet' })
      .getByRole('button', { name: 'On' })
      .click();
    await gasCreateModalAfterRefresh.getByRole('button', { name: 'Per chain total' }).click();
    const tempoTestnetRow = gasCreateModalAfterRefresh
      .locator('.dashboard-gas-target-matrix__row')
      .filter({ hasText: 'Tempo' });
    await expect(tempoTestnetRow).toContainText('AlphaUSD');
    await gasCreateModalAfterRefresh.getByLabel('Tempo Testnet spend cap').fill('500.00');
    await gasCreateModalAfterRefresh.getByRole('button', { name: 'Allowlist' }).click();
    await gasCreateModalAfterRefresh.getByRole('button', { name: 'Add contract' }).click();
    await gasCreateModalAfterRefresh
      .locator('label:has-text("Contract address") input')
      .fill('0xbb85080E6953f25197ec68798360667140EbAf4b');
    await gasCreateModalAfterRefresh
      .locator('label:has-text("Allowed functions") input')
      .fill('0x428dc451');
    await expect(
      gasCreateModalAfterRefresh.locator('label:has-text("Max gas limit") input'),
    ).toHaveCount(0);
    await expect(
      gasCreateModalAfterRefresh.locator('label:has-text("Max value (wei)") input'),
    ).toHaveCount(0);
    await gasCreateModalAfterRefresh
      .locator('button:has-text("Create sponsorship policy")')
      .click();

    await expect.poll(() => String(lastGasCreateBody?.kind || '')).toBe('GAS_SPONSORSHIP');
    await expect
      .poll(() =>
        String(
          (
            lastGasCreateBody?.rules &&
            typeof lastGasCreateBody.rules === 'object' &&
            !Array.isArray(lastGasCreateBody.rules)
              ? (lastGasCreateBody.rules as Record<string, unknown>).scopeType
              : ''
          ) || '',
        ),
      )
      .toBe('ENVIRONMENT');
    await expect
      .poll(() =>
        String(
          (
            lastGasCreateBody?.rules &&
            typeof lastGasCreateBody.rules === 'object' &&
            !Array.isArray(lastGasCreateBody.rules)
              ? (lastGasCreateBody.rules as Record<string, unknown>).environmentId
              : ''
          ) || '',
        ),
      )
      .toBe(developmentEnvironment.id);
    await expect
      .poll(() =>
        String(
          (
            lastGasCreateBody?.rules &&
            typeof lastGasCreateBody.rules === 'object' &&
            !Array.isArray(lastGasCreateBody.rules)
              ? (lastGasCreateBody.rules as Record<string, unknown>).networkClass
              : ''
          ) || '',
        ),
      )
      .toBe('TESTNET');
    await expect
      .poll(() =>
        String(
          (
            lastGasCreateBody?.rules &&
            typeof lastGasCreateBody.rules === 'object' &&
            !Array.isArray(lastGasCreateBody.rules)
              ? (lastGasCreateBody.rules as Record<string, unknown>).callMode
              : ''
          ) || '',
        ),
      )
      .toBe('ALLOWLIST');
    await expect
      .poll(() =>
        Array.isArray(
          lastGasCreateBody?.rules &&
            typeof lastGasCreateBody.rules === 'object' &&
            !Array.isArray(lastGasCreateBody.rules)
            ? (lastGasCreateBody.rules as Record<string, unknown>).allowedChainIds
            : null,
        )
          ? [
              ...(
                (lastGasCreateBody!.rules as Record<string, unknown>)
                  .allowedChainIds as any[]
              ),
            ]
              .map(String)
              .sort()
              .join(',')
          : '',
      )
      .toBe('42431');
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
                  (lastGasCreateBody!.rules as Record<string, unknown>)
                    .allowedCalls as Array<{ chainId?: unknown }>
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
    await gasViewModal.getByRole('button', { name: 'Close' }).click();

    await newSponsorshipRow.getByRole('button', { name: 'Edit' }).click();
    const gasEditModal = page.locator('section[aria-label="Edit gas sponsorship policy modal"]');
    const tempoTestnetSpendCapInput = gasEditModal.getByLabel('Tempo Testnet spend cap');
    const tempoEditRow = gasEditModal
      .locator('.dashboard-gas-target-matrix__row')
      .filter({ hasText: 'Tempo' });
    await expect(tempoEditRow).toContainText('AlphaUSD');
    await expect(tempoTestnetSpendCapInput).toHaveValue('500.00');
    await tempoTestnetSpendCapInput.fill('500.123');
    await gasEditModal.getByRole('button', { name: 'Save sponsorship policy' }).click();
    await expect(gasEditModal).toContainText(
      'Tempo Testnet spend cap must be a non-negative amount with up to 2 decimal places.',
    );
    await expect.poll(() => gasPolicyPatchCalls.length).toBe(0);

    await tempoTestnetSpendCapInput.fill('725.50');
    await gasEditModal.getByRole('button', { name: 'Save sponsorship policy' }).click();
    await expect.poll(() => gasPolicyPatchCalls.length).toBe(1);
    expect(gasPolicyPatchCalls[0]?.body).toMatchObject({
      name: 'New sponsorship',
      rules: {
        networkClass: 'TESTNET',
        callMode: 'ALLOWLIST',
        spendCap: {
          mode: 'CHAIN_TOTAL',
          period: 'MONTHLY',
          capsByChain: [{ chainId: 42431, capMinor: 72550 }],
        },
      },
    });
    await expect(newSponsorshipRow).toContainText('725.50 AlphaUSD');

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
      gasCreateModalAfterEnvironmentSwitch.getByRole('group', { name: 'Tempo Mainnet' }),
    ).toBeVisible();
    await expect(
      gasCreateModalAfterEnvironmentSwitch.getByRole('group', { name: 'Tempo Testnet' }),
    ).toHaveCount(0);
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
    await expect.poll(() => gasPolicyPatchCalls.length).toBe(2);
    expect(gasPolicyPatchCalls[1]).toMatchObject({
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

  test('approvals route is removed from dashboard navigation and redirects', async ({
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

      if (pathname === '/console/wallets' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, wallets: [], nextCursor: null }),
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

    await page.goto('/dashboard/approvals');
    await expect.poll(() => new URL(page.url()).pathname).not.toBe('/dashboard/approvals');
    await expect(
      page.locator(
        'aside[aria-label="Primary dashboard navigation"] a[href="/dashboard/approvals"]',
      ),
    ).toHaveCount(0);
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
      'Approval requested',
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
      'Approval requested',
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
        scopes: ['accounts.create', 'accounts.sync'],
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
            secret: 'pk_publishable_created',
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
    ).toContainText("publishableKey: 'pk_publishable_created'");
    await expect(page.locator('.dashboard-secret-banner')).toContainText('Save this publishable key now');
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
    await expect(page.locator('section[aria-label="Observability events table"]')).toContainText(
      'No observability events for this scope.',
    );
    await expect(page.locator('section[aria-label="Observability events table"]')).toContainText(
      'Default window: last 24 hours.',
    );
    const eventsSection = page.locator('section[aria-label="Observability events table"]');
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
    let lastEventsEventType = '';

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
        lastEventsEventType = String(url.searchParams.get('eventType') || '').trim();
        const normalizedQuery = lastEventsQuery.toLowerCase();
        const filteredEvents = allEvents.filter((entry) => {
          if (lastEventsLevel && entry.level !== lastEventsLevel) return false;
          if (lastEventsService && entry.service !== lastEventsService) return false;
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
      .locator('input[aria-label="Filter observability events by service"]')
      .fill('billing');
    await expect.poll(() => lastEventsService).toBe('billing');

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
      'No observability events match the current filters.',
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

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
            accountSettings: 'Account & Settings',
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
    await page.getByRole('menuitemradio', { name: /sign out/i }).click();

    await expect.poll(() => sessionRevokeCalls).toBe(1);
    await expect.poll(() => new URL(page.url()).pathname).toBe('/dashboard/login');
    await expect(page.locator('h1')).toHaveText(/sign in with google/i);
    await expect
      .poll(() => page.evaluate(() => window.localStorage.getItem('tatchi-dashboard-ui-state-v1')))
      .toBeNull();
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
            accountSettings: 'Account & Settings',
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
        sidebar
          .locator('a.dashboard-nav-item')
          .evaluateAll(
            (items) =>
              items.length > 0 &&
              items.every(
                (entry) =>
                  entry.getAttribute('aria-disabled') === 'true' &&
                  entry.getAttribute('tabindex') === '-1',
              ),
          ),
      )
      .toBe(true);
    const onboardingForm = page
      .locator('section[aria-label="Onboarding form"]:has(h2:has-text("Name your organization"))')
      .last();
    await expect(onboardingForm.locator('input[placeholder="Acme Wallets"]')).toBeVisible();
    await onboardingForm.locator('input[placeholder="Acme Wallets"]').fill('Acme Wallets');
    await onboardingForm
      .locator('label:has-text("I confirm this organization name is correct.") input')
      .check();
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
    await expect(projectForm.locator('label:has-text("Project name") input')).toBeVisible();
    await projectForm.locator('label:has-text("Project name") input').fill('Consumer App');
    await projectForm.locator('button:has-text("Add optional IDs")').click();
    await projectForm
      .locator('label:has-text("Project ID (optional)") input')
      .fill('proj_consumer');
    await projectForm
      .locator('label:has-text("Environment ID (optional)") input')
      .fill('proj_consumer:dev');
    await projectForm.locator('button:has-text("Finish onboarding")').click();

    await expect
      .poll(() =>
        String((lastProjectBody?.project as Record<string, unknown> | undefined)?.name || ''),
      )
      .toBe('Consumer App');
    await expect
      .poll(() =>
        String(
          ((lastProjectBody?.environment as Record<string, unknown> | undefined)?.id as string) ||
            '',
        ),
      )
      .toBe('proj_consumer:dev');
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
      'org_dash_console_pages',
    );
    await onboardingForm.locator('input[placeholder="Acme Wallets"]').fill('Acme Org');
    await onboardingForm.locator('button:has-text("Add optional organization details")').click();
    await onboardingForm
      .locator('label:has-text("Organization slug (optional)") input')
      .fill('acme-org');
    await onboardingForm
      .locator('label:has-text("I confirm this organization name is correct.") input')
      .check();
    await onboardingForm.locator('button:has-text("Continue to project setup")').click();

    await expect
      .poll(() =>
        String((lastOrganizationBody?.org as Record<string, unknown> | undefined)?.name || ''),
      )
      .toBe('Acme Org');
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
    await organizationForm
      .locator('label:has-text("I confirm this organization name is correct.") input')
      .check();
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

  test('onboarding project step hides billing form fields and shows billing unlock note', async ({
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
    await expect(page.locator('section[aria-label="Onboarding form"]')).toContainText(
      'Billing is optional for onboarding.',
    );
  });

  test('gas-smart-wallets page wires create and validates scope requirements', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
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
    await expect(page.locator('#dashboard-main-title')).toHaveText(
      /gas sponsorship and smart wallets/i,
    );
    await expect(page.locator('section[aria-label="Gas sponsorship configs table"]')).toContainText(
      'gs_existing',
    );

    const gasCreateSection = page.locator('section[aria-label="Create gas sponsorship config"]');
    await gasCreateSection
      .locator('label:has-text("Config ID (optional)") input')
      .fill('gs_new_e2e');
    await gasCreateSection
      .locator('label:has-text("Budget chain (optional)") input')
      .fill('Ethereum');
    await gasCreateSection.locator('label:has-text("Budget (minor units)") input').fill('50000');
    await gasCreateSection.locator('label:has-text("Quota transactions") input').fill('1200');
    await gasCreateSection.locator('button:has-text("Create gas sponsorship config")').click();

    await expect.poll(() => String(lastGasCreateBody?.id || '')).toBe('gs_new_e2e');
    await expect(page.locator('section[aria-label="Gas sponsorship configs table"]')).toContainText(
      'gs_new_e2e',
    );

    const gasTable = page.locator('section[aria-label="Gas sponsorship configs table"]');
    const existingGasRow = gasTable.locator('.dashboard-table-row', { hasText: 'gs_existing' });
    await existingGasRow.locator('button:has-text("Disable")').click();
    await expect.poll(() => lastGasPatchConfigId).toBe('gs_existing');
    await expect(existingGasRow).toContainText('false');
  });

  test('policy-engine page wires publish flow with optional approval request id', async ({
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
        publishedAt: null,
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

      if (pathname === '/console/policies/assignments' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, assignments }),
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
    await expect(page.locator('section[aria-label="Policy lifecycle registry"]')).toContainText(
      'policy_draft_e2e',
    );

    const controls = page.locator('section[aria-label="Policy lifecycle controls"]');
    await controls
      .locator('label:has-text("Publish approval request ID (optional)") input')
      .fill('apr_policy_publish_e2e');

    const registry = page.locator('section[aria-label="Policy lifecycle registry"]');
    const draftRow = registry.locator('.dashboard-table-row', { hasText: 'policy_draft_e2e' });
    await draftRow.locator('button:has-text("Publish")').click();

    await expect.poll(() => lastPublishPolicyId).toBe('policy_draft_e2e');
    await expect
      .poll(() => String(lastPublishBody?.approvalId || ''))
      .toBe('apr_policy_publish_e2e');
    await expect(draftRow).toContainText('PUBLISHED');
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

  test('team-members page wires invite, role update, remove, and status filter flows', async ({
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

    const newMemberRow = table.locator('.dashboard-table-row', {
      hasText: 'new-member@example.com',
    });
    await newMemberRow.locator('button:has-text("Update permissions")').click();

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
    await newMemberRow.locator('button:has-text("Delete member")').click({ force: true });
    await expect.poll(() => lastRemovedMemberId).toContain('member_');
    await expect(newMemberRow).toContainText('REMOVED');

    await filterSection.locator('label:has-text("Status") select').selectOption('REMOVED');
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

  test('audit page wires timeline and evidence filters to console APIs', async ({
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
    const evidenceRecords = [
      {
        id: 'evd_policy_1',
        orgId: 'org_dash_console_pages',
        projectId: 'proj_active',
        environmentId: 'env_active',
        domain: 'POLICY',
        title: 'Policy publish evidence',
        summary: 'Policy publication trace',
        eventIds: ['aud_policy_1'],
        references: [{ kind: 'LOG', referenceId: 'policy_1:v1', label: 'Policy log' }],
        createdAt: iso('2026-02-15T00:02:00.000Z'),
      },
      {
        id: 'evd_billing_1',
        orgId: 'org_dash_console_pages',
        projectId: 'proj_active',
        environmentId: 'env_active',
        domain: 'BILLING',
        title: 'Invoice settlement evidence',
        summary: 'Payment settlement trace',
        eventIds: ['aud_approval_1'],
        references: [{ kind: 'PAYMENT', referenceId: 'pi_1', label: 'Payment intent' }],
        createdAt: iso('2026-02-15T00:03:00.000Z'),
      },
    ];
    let lastEventCategoryQuery = '';
    let lastEvidenceDomainQuery = '';

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
        lastEventCategoryQuery = category;
        const rows = category ? events.filter((entry) => entry.category === category) : [...events];
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, events: rows }),
        });
        return;
      }

      if (pathname === '/console/audit/evidence' && method === 'GET') {
        const domain = String(url.searchParams.get('domain') || '')
          .trim()
          .toUpperCase();
        lastEvidenceDomainQuery = domain;
        const rows = domain
          ? evidenceRecords.filter((entry) => entry.domain === domain)
          : [...evidenceRecords];
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, evidence: rows }),
        });
        return;
      }

      if (pathname === '/console/audit/exports' && method === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, exports: [] }),
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
    await expect(page.locator('#dashboard-main-title')).toHaveText(/audit\s*&\s*evidence/i);
    await expect(page.locator('section[aria-label="Audit events table"]')).toContainText(
      'policy.publish',
    );
    await expect(page.locator('section[aria-label="Audit evidence table"]')).toContainText(
      'Invoice settlement evidence',
    );

    const filterSection = page.locator('section[aria-label="Audit filters"]');
    await filterSection.locator('label:has-text("Category") select').selectOption('APPROVAL');
    await filterSection.locator('button:has-text("Reload audit data")').click();
    await expect.poll(() => lastEventCategoryQuery).toBe('APPROVAL');
    await expect(page.locator('section[aria-label="Audit events table"]')).toContainText(
      'approval.request.create',
    );

    await filterSection.locator('label:has-text("Evidence domain") select').selectOption('BILLING');
    await filterSection.locator('button:has-text("Reload audit data")').click();
    await expect.poll(() => lastEvidenceDomainQuery).toBe('BILLING');
    await expect(page.locator('section[aria-label="Audit evidence table"]')).toContainText(
      'Invoice settlement evidence',
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
        id: 'ak_existing_secret',
        kind: 'secret_key',
        orgId: 'org_dash_console_pages',
        name: 'existing-server',
        environmentId: 'env_active',
        scopes: ['accounts.create', 'accounts.sync'],
        ipAllowlist: ['203.0.113.10/32'],
        status: 'ACTIVE',
        secretVersion: 1,
        secretPreview: 'tsk_v1_abcd...',
        createdAt: iso('2026-03-01T00:00:00.000Z'),
        updatedAt: iso('2026-03-01T00:00:00.000Z'),
        lastUsedAt: iso('2026-03-02T00:00:00.000Z'),
        endpointUsageCounts: {
          '/registration/bootstrap': 3,
        },
        anomalyFlags: [],
      },
      {
        id: 'ak_revoked_publishable',
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
        secretPreview: 'tpk_v1_revoked...',
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
          id: 'ak_new_publishable',
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
          secretPreview: 'tpk_v1_efgh...',
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
            secret: 'tpk_v1_publishable_created',
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
    await expect(credentialControls).toContainText('Create credential');
    await expect(page.locator('section[aria-label="Credentials table"]')).toContainText(
      'existing-server',
    );
    const revokedRow = page
      .locator('section[aria-label="Credentials table"] .dashboard-table-row')
      .filter({ hasText: 'revoked-browser' });
    await expect(revokedRow).toContainText('REVOKED');
    await expect(revokedRow.getByRole('button', { name: 'Delete' })).toBeVisible();
    page.once('dialog', (dialog) => dialog.accept());
    await revokedRow.getByRole('button', { name: 'Delete' }).click({ force: true });
    await expect.poll(() => lastPurgedApiKeyId).toBe('ak_revoked_publishable');
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
    ).toContainText("publishableKey: 'tpk_v1_publishable_created'");
    await expect(page.locator('section[aria-label="Credentials table"]')).toContainText(
      'frontend-app',
    );
    await expect(page.locator('section[aria-label="Credentials table"]')).toContainText(
      'publishable_key',
    );

    const publishableRow = page
      .locator('section[aria-label="Credentials table"] .dashboard-table-row')
      .filter({ hasText: 'frontend-app' })
      .filter({ hasText: 'publishable_key' });
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
    await expect.poll(() => lastEventsLimit).toBe('50');
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
    await expect(page.locator('button:has-text("Previous page")')).toBeDisabled();
    await expect(page.locator('button:has-text("Next page")')).toBeDisabled();
  });

  test('observability events pagination uses 50-event pages and cursor navigation', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    const context = buildMockDashboardContext();
    const firstPageEvents = Array.from({ length: 50 }, (_, index) => ({
      id: `evt_page1_${index + 1}`,
      orgId: 'org_dash_console_pages',
      projectId: 'proj_active',
      environmentId: 'env_active',
      timestamp: iso(`2026-03-03T10:${String(index % 60).padStart(2, '0')}:00.000Z`),
      service: 'webhooks',
      component: 'delivery',
      level: 'WARN',
      eventType: 'delivery.retry',
      message: `Page 1 event ${index + 1}`,
      requestId: `req_page1_${index + 1}`,
      traceId: `trace_page1_${index + 1}`,
      metadata: { retry: index + 1 },
    }));
    const secondPageEvents = [
      {
        id: 'evt_page2_1',
        orgId: 'org_dash_console_pages',
        projectId: 'proj_active',
        environmentId: 'env_active',
        timestamp: iso('2026-03-03T11:00:00.000Z'),
        service: 'billing',
        component: 'invoice',
        level: 'ERROR',
        eventType: 'invoice.reconcile_failed',
        message: 'Page 2 event 1',
        requestId: 'req_page2_1',
        traceId: 'trace_page2_1',
        metadata: { invoiceId: 'inv_1' },
      },
      {
        id: 'evt_page2_2',
        orgId: 'org_dash_console_pages',
        projectId: 'proj_active',
        environmentId: 'env_active',
        timestamp: iso('2026-03-03T11:01:00.000Z'),
        service: 'billing',
        component: 'invoice',
        level: 'ERROR',
        eventType: 'invoice.reconcile_failed',
        message: 'Page 2 event 2',
        requestId: 'req_page2_2',
        traceId: 'trace_page2_2',
        metadata: { invoiceId: 'inv_2' },
      },
    ];
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
        const cursor = String(url.searchParams.get('cursor') || '').trim();
        if (!cursor) {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              ok: true,
              status: { state: 'ok' },
              events: firstPageEvents,
              nextCursor: 'cursor_page_2',
            }),
          });
          return;
        }
        if (cursor === 'cursor_page_2') {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              ok: true,
              status: { state: 'ok' },
              events: secondPageEvents,
            }),
          });
          return;
        }
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
    await expect.poll(() => requestedEventLimits[0] || '').toBe('50');
    await expect(page.locator('section[aria-label="Observability events table"]')).toContainText(
      'Page 1 event 50',
    );
    await expect(page.locator('section[aria-label="Observability events table"]')).toContainText(
      'Page 1 | 50 events',
    );
    await expect(page.locator('button:has-text("Previous page")')).toBeDisabled();
    await expect(page.locator('button:has-text("Next page")')).toBeEnabled();

    await page.locator('button:has-text("Next page")').click();
    await expect.poll(() => requestedEventCursors.includes('cursor_page_2')).toBe(true);
    await expect(page.locator('section[aria-label="Observability events table"]')).toContainText(
      'Page 2 event 2',
    );
    await expect(page.locator('section[aria-label="Observability events table"]')).toContainText(
      'Page 2 | 2 events',
    );
    await expect(page.locator('button:has-text("Previous page")')).toBeEnabled();
    await expect(page.locator('button:has-text("Next page")')).toBeDisabled();

    await page.locator('button:has-text("Previous page")').click();
    await expect(page.locator('section[aria-label="Observability events table"]')).toContainText(
      'Page 1 event 50',
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
                    operationType: 'KEY_EXPORT',
                    requestedByUserId: 'user_alpha',
                    resourceType: 'KEY_EXPORT',
                    resourceId: 'ke_123',
                    createdAt: iso('2026-03-01T10:00:00.000Z'),
                  },
                  {
                    id: 'apr_2',
                    operationType: 'POLICY_PUBLISH',
                    requestedByUserId: 'user_beta',
                    resourceType: 'POLICY',
                    resourceId: 'pol_123',
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
              operationType: 'KEY_EXPORT',
              status: 'APPROVED',
              reason: 'Approve export request',
              requestedByUserId: 'user_alpha',
              requiredApprovals: 1,
              requireMfa: true,
              projectId: 'proj_active',
              environmentId: 'env_active',
              resourceType: 'KEY_EXPORT',
              resourceId: 'ke_123',
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
              operationType: 'POLICY_PUBLISH',
              status: 'REJECTED',
              reason: 'Reject policy publish request',
              requestedByUserId: 'user_beta',
              requiredApprovals: 1,
              requireMfa: false,
              projectId: 'proj_active',
              environmentId: 'env_active',
              resourceType: 'POLICY',
              resourceId: 'pol_123',
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

    await page.goto('/dashboard/ops-cockpit');
    await expect(page.locator('#dashboard-main-title')).toHaveText(/overview/i);
    await expect.poll(() => lastSummaryWindowMinutes).toBe('60');

    const summary = page.locator('section[aria-label="Ops cockpit summary"]');
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
    await pendingApprovalsSummary.locator('button:has-text("Approve")').first().click();
    await expect.poll(() => approveRequestCount).toBe(1);
    await expect
      .poll(() => String(lastApproveBody?.reason || ''))
      .toBe('Processed from Ops Cockpit');
    await expect.poll(() => lastApproveBody?.mfaVerified === true).toBe(true);
    await expect(pendingApprovalsSummary).toContainText('Approved request apr_1.');

    await pendingApprovalsSummary.locator('button:has-text("Reject")').nth(1).click();
    await expect.poll(() => rejectRequestCount).toBe(1);
    await expect
      .poll(() => String(lastRejectBody?.reason || ''))
      .toBe('Processed from Ops Cockpit');
    await expect(pendingApprovalsSummary).toContainText('Rejected request apr_2.');

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
});

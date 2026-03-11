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
  _consoleOrigin: string,
  input: {
    userId: string;
    roles?: string[];
    org: Record<string, unknown>;
    project: Record<string, unknown>;
    environment: Record<string, unknown>;
    handleBillingRequest: (
      route: Route,
      pathname: string,
      method: string,
      url: URL,
    ) => Promise<boolean>;
  },
): Promise<void> {
  await page.route(/^https?:\/\/[^/]+\/console\/.*/i, async (route) => {
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
          roles: Array.isArray(input.roles) && input.roles.length > 0 ? input.roles : ['admin'],
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

    if (await input.handleBillingRequest(route, pathname, method, url)) {
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

test.describe('dashboard billing prepaid console api wiring', () => {
  test('wires prepaid top-up actions', async ({ page, baseURL }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    const checkoutBodies: Record<string, unknown>[] = [];

    const org = {
      id: 'org_dash_billing_prepaid',
      name: 'Dashboard Billing Org',
      slug: 'dashboard-billing-org',
      status: 'ACTIVE',
      createdAt: iso('2026-01-01T00:00:00.000Z'),
      updatedAt: iso('2026-01-01T00:00:00.000Z'),
    };
    const project = {
      id: 'proj_dash_billing_prepaid',
      name: 'Billing Project',
      slug: 'billing-project',
      status: 'ACTIVE',
      environmentCount: 1,
      createdAt: iso('2026-01-01T00:00:00.000Z'),
      updatedAt: iso('2026-01-01T00:00:00.000Z'),
    };
    const environment = {
      id: 'env_dash_billing_prepaid',
      projectId: project.id,
      key: 'prod',
      name: 'Production',
      status: 'ACTIVE',
      createdAt: iso('2026-01-01T00:00:00.000Z'),
      updatedAt: iso('2026-01-01T00:00:00.000Z'),
    };

    await routeWorkspaceScaffold(page, consoleOrigin, {
      userId: 'user_dash_billing_prepaid',
      org,
      project,
      environment,
      handleBillingRequest: async (route, pathname, method, _url) => {
        if (method === 'GET' && pathname === '/console/billing/overview') {
          await fulfillJson(route, {
            ok: true,
            overview: {
              usageMetricVersion: 'maw_v1',
              currentMonthUtc: '2026-03',
              monthlyActiveWallets: 42,
              creditBalanceMinor: 2500,
              lowBalanceThresholdMinor: 3000,
              recentUsageDebitMinor: 12600,
              recentCreditPurchasedMinor: 2500,
              documentCount: 3,
            },
          });
          return true;
        }

        if (method === 'GET' && pathname === '/console/billing/usage/monthly-active-wallets') {
          await fulfillJson(route, {
            ok: true,
            usage: {
              usageMetricVersion: 'maw_v1',
              monthUtc: '2026-03',
              monthlyActiveWallets: 42,
            },
          });
          return true;
        }

        if (method === 'GET' && pathname === '/console/billing/account/activity') {
          await fulfillJson(route, {
            ok: true,
            activity: {
              entries: [],
            },
          });
          return true;
        }

        if (method === 'GET' && pathname === '/console/billing/invoices') {
          await fulfillJson(route, {
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
          });
          return true;
        }

        if (method === 'POST' && pathname === '/console/billing/stripe/checkout-session') {
          checkoutBodies.push(parseJsonBody(route.request().postData()));
          await fulfillJson(
            route,
            {
              ok: true,
              checkoutSession: {
                id: 'cs_dash_billing_prepaid',
                url: `${consoleOrigin}/dashboard/billing/account?checkout=success`,
                customerRef: 'cus_dash_billing_prepaid',
                creditPackId: 'usd_25',
                amountMinor: 2500,
                expiresAt: iso('2026-03-01T01:00:00.000Z'),
              },
            },
            201,
          );
          return true;
        }

        return false;
      },
    });

    await page.goto('/dashboard/billing/account');

    const billingScope = page.locator('section[aria-label="Billing scope and actions"]');
    await expect(billingScope).toContainText(project.name);
    await expect(billingScope).toContainText(environment.name);
    await expect(billingScope).not.toContainText(project.id);
    await expect(billingScope).not.toContainText(environment.id);
    await expect(page.getByText(/subscription/i)).toHaveCount(0);

    const metrics = page.locator('section[aria-label="Billing account summary metrics"]');
    await expect(metrics).toContainText('Balance');
    await expect(metrics).toContainText('$25.00');
    await expect(metrics).toContainText('Recent top-ups');

    await expect(page.locator('.dashboard-warning-banner')).toContainText('warning threshold');

    const topUpSection = page.locator('section[aria-label="Prepaid top-up actions"]');
    await expect(topUpSection).toContainText('Top up credits');
    await topUpSection.getByRole('button', { name: 'Buy $25' }).click();
    await expect.poll(() => checkoutBodies.length).toBe(1);
    expect(String(checkoutBodies[0]?.creditPackId || '')).toBe('usd_25');
    expect(String(checkoutBodies[0]?.successUrl || '')).toContain(
      '/dashboard/billing/account?checkout=success',
    );
    await expect(page.locator('.dashboard-info-banner')).toContainText('Top-up checkout completed');
  });

  test('wires internal manual adjustments with impact preview for admin role', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    const manualRequests: Record<string, unknown>[] = [];
    const activityEntries: Record<string, unknown>[] = [];
    let creditBalanceMinor = 5000;

    await routeWorkspaceScaffold(page, consoleOrigin, {
      userId: 'user_dash_billing_adjustments_admin',
      org: {
        id: 'org_dash_billing_adjustments',
        name: 'Dashboard Billing Adjustments Org',
        slug: 'dashboard-billing-adjustments-org',
        status: 'ACTIVE',
        createdAt: iso('2026-01-01T00:00:00.000Z'),
        updatedAt: iso('2026-01-01T00:00:00.000Z'),
      },
      project: {
        id: 'proj_dash_billing_adjustments',
        name: 'Billing Adjustments Project',
        slug: 'billing-adjustments-project',
        status: 'ACTIVE',
        environmentCount: 1,
        createdAt: iso('2026-01-01T00:00:00.000Z'),
        updatedAt: iso('2026-01-01T00:00:00.000Z'),
      },
      environment: {
        id: 'env_dash_billing_adjustments',
        projectId: 'proj_dash_billing_adjustments',
        key: 'prod',
        name: 'Production',
        status: 'ACTIVE',
        createdAt: iso('2026-01-01T00:00:00.000Z'),
        updatedAt: iso('2026-01-01T00:00:00.000Z'),
      },
      handleBillingRequest: async (route, pathname, method, _url) => {
        if (method === 'GET' && pathname === '/console/billing/overview') {
          await fulfillJson(route, {
            ok: true,
            overview: {
              usageMetricVersion: 'maw_v1',
              currentMonthUtc: '2026-03',
              monthlyActiveWallets: 0,
              creditBalanceMinor,
              lowBalanceThresholdMinor: 2000,
              recentUsageDebitMinor: 0,
              recentCreditPurchasedMinor: 0,
              documentCount: activityEntries.length,
            },
          });
          return true;
        }

        if (method === 'GET' && pathname === '/console/billing/usage/monthly-active-wallets') {
          await fulfillJson(route, {
            ok: true,
            usage: {
              usageMetricVersion: 'maw_v1',
              monthUtc: '2026-03',
              monthlyActiveWallets: 0,
            },
          });
          return true;
        }

        if (method === 'GET' && pathname === '/console/billing/account/activity') {
          await fulfillJson(route, {
            ok: true,
            activity: {
              entries: activityEntries,
            },
          });
          return true;
        }

        if (method === 'GET' && pathname === '/console/billing/invoices') {
          await fulfillJson(route, {
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
          });
          return true;
        }

        if (method === 'POST' && pathname === '/console/billing/adjustments/support-credit') {
          const body = parseJsonBody(route.request().postData());
          manualRequests.push(body);
          const amountMinor = Number(body.amountMinor || 0);
          const relatedInvoiceId = String(body.relatedInvoiceId || '').trim() || null;
          creditBalanceMinor += amountMinor;
          activityEntries.unshift({
            id: `ble_adj_${manualRequests.length}`,
            orgId: 'org_dash_billing_adjustments',
            type: 'MANUAL_ADJUSTMENT',
            amountMinor,
            currency: 'USD',
            description: `Manual support credit (${String(body.reasonCode || '').trim()})`,
            monthUtc: '2026-03',
            relatedInvoiceId,
            relatedPurchaseId: null,
            sourceEventId: null,
            actorType: 'USER',
            actorUserId: 'user_dash_billing_adjustments_admin',
            reasonCode: String(body.reasonCode || '').trim() || null,
            note: String(body.note || '').trim() || null,
            idempotencyKey: String(body.idempotencyKey || '').trim() || null,
            createdAt: iso('2026-03-20T00:00:00.000Z'),
          });
          await fulfillJson(
            route,
            {
              ok: true,
              result: {
                created: true,
                adjustment: activityEntries[0],
                creditBalanceMinor,
              },
            },
            201,
          );
          return true;
        }

        return false;
      },
    });

    await page.goto('/dashboard/billing/account');

    const adjustmentSection = page.locator('section[aria-label="Internal billing adjustments"]');
    await expect(adjustmentSection).toBeVisible();

    await adjustmentSection.getByLabel('Amount (USD)').fill('15.00');
    await adjustmentSection.getByLabel('Reason code').fill('incident_credit');
    await adjustmentSection.getByLabel('Related document ID (optional)').fill('inv_202603_001');
    await adjustmentSection.getByLabel('Operator note').fill('Applied goodwill credit');

    await expect(adjustmentSection).toContainText('Impact preview: $50.00 -> $65.00 (+$15.00).');

    await adjustmentSection.getByRole('button', { name: 'Apply support credit' }).click();
    await expect.poll(() => manualRequests.length).toBe(1);
    expect(Number(manualRequests[0]?.amountMinor || 0)).toBe(1500);
    expect(String(manualRequests[0]?.reasonCode || '')).toBe('incident_credit');
    expect(String(manualRequests[0]?.relatedInvoiceId || '')).toBe('inv_202603_001');

    await expect(adjustmentSection).toContainText('Manual support credit recorded.');
    await expect(
      page.locator('section[aria-label="Billing account summary metrics"]'),
    ).toContainText('$65.00');
    await expect(page.locator('section[aria-label="Billing account activity"]')).toContainText(
      'incident_credit',
    );
  });

  test('hides internal manual adjustments for non-admin role', async ({ page, baseURL }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;

    await routeWorkspaceScaffold(page, consoleOrigin, {
      userId: 'user_dash_billing_adjustments_ops',
      roles: ['ops'],
      org: {
        id: 'org_dash_billing_adjustments_ops',
        name: 'Dashboard Billing Ops Org',
        slug: 'dashboard-billing-ops-org',
        status: 'ACTIVE',
        createdAt: iso('2026-01-01T00:00:00.000Z'),
        updatedAt: iso('2026-01-01T00:00:00.000Z'),
      },
      project: {
        id: 'proj_dash_billing_adjustments_ops',
        name: 'Billing Ops Project',
        slug: 'billing-ops-project',
        status: 'ACTIVE',
        environmentCount: 1,
        createdAt: iso('2026-01-01T00:00:00.000Z'),
        updatedAt: iso('2026-01-01T00:00:00.000Z'),
      },
      environment: {
        id: 'env_dash_billing_adjustments_ops',
        projectId: 'proj_dash_billing_adjustments_ops',
        key: 'prod',
        name: 'Production',
        status: 'ACTIVE',
        createdAt: iso('2026-01-01T00:00:00.000Z'),
        updatedAt: iso('2026-01-01T00:00:00.000Z'),
      },
      handleBillingRequest: async (route, pathname, method, _url) => {
        if (method === 'GET' && pathname === '/console/billing/overview') {
          await fulfillJson(route, {
            ok: true,
            overview: {
              usageMetricVersion: 'maw_v1',
              currentMonthUtc: '2026-03',
              monthlyActiveWallets: 0,
              creditBalanceMinor: 3000,
              lowBalanceThresholdMinor: 2000,
              recentUsageDebitMinor: 0,
              recentCreditPurchasedMinor: 0,
              documentCount: 0,
            },
          });
          return true;
        }

        if (method === 'GET' && pathname === '/console/billing/usage/monthly-active-wallets') {
          await fulfillJson(route, {
            ok: true,
            usage: {
              usageMetricVersion: 'maw_v1',
              monthUtc: '2026-03',
              monthlyActiveWallets: 0,
            },
          });
          return true;
        }

        if (method === 'GET' && pathname === '/console/billing/account/activity') {
          await fulfillJson(route, {
            ok: true,
            activity: {
              entries: [],
            },
          });
          return true;
        }

        if (method === 'GET' && pathname === '/console/billing/invoices') {
          await fulfillJson(route, {
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
          });
          return true;
        }

        return false;
      },
    });

    await page.goto('/dashboard/billing/account');
    await expect(page.locator('section[aria-label="Internal billing adjustments"]')).toHaveCount(0);
  });

  test('wires billing document navigation, filters, and PDF export actions', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    const invoiceListUrls: string[] = [];
    let overviewRequestCount = 0;
    let usageRequestCount = 0;
    let pdfDownloadCount = 0;
    const documents = [
      {
        id: 'receipt_dash_billing_1',
        documentType: 'PURCHASE_RECEIPT',
        status: 'PAID',
        amountDueMinor: 2500,
        amountPaidMinor: 2500,
        periodMonthUtc: '2026-03',
        dueAt: null,
        createdAt: iso('2026-03-05T00:00:00.000Z'),
      },
      {
        id: 'stmt_dash_billing_1',
        documentType: 'USAGE_STATEMENT',
        status: 'PAID',
        amountDueMinor: 12600,
        amountPaidMinor: 12600,
        periodMonthUtc: '2026-03',
        dueAt: null,
        createdAt: iso('2026-03-31T00:00:00.000Z'),
      },
    ] as const;

    await page.addInitScript(() => {
      const target = window as typeof window & { __lastBillingBlobSize?: number };
      const originalCreateObjectURL = URL.createObjectURL.bind(URL);
      target.__lastBillingBlobSize = 0;
      URL.createObjectURL = ((blob: Blob) => {
        target.__lastBillingBlobSize = blob.size;
        return originalCreateObjectURL(blob);
      }) as typeof URL.createObjectURL;
    });

    await routeWorkspaceScaffold(page, consoleOrigin, {
      userId: 'user_dash_billing_invoice',
      org: {
        id: 'org_dash_billing_invoice',
        name: 'Dashboard Billing Documents Org',
        slug: 'dashboard-billing-documents-org',
        status: 'ACTIVE',
        createdAt: iso('2026-01-01T00:00:00.000Z'),
        updatedAt: iso('2026-01-01T00:00:00.000Z'),
      },
      project: {
        id: 'proj_dash_billing_invoice',
        name: 'Billing Documents Project',
        slug: 'billing-documents-project',
        status: 'ACTIVE',
        environmentCount: 1,
        createdAt: iso('2026-01-01T00:00:00.000Z'),
        updatedAt: iso('2026-01-01T00:00:00.000Z'),
      },
      environment: {
        id: 'env_dash_billing_invoice',
        projectId: 'proj_dash_billing_invoice',
        key: 'prod',
        name: 'Production',
        status: 'ACTIVE',
        createdAt: iso('2026-01-01T00:00:00.000Z'),
        updatedAt: iso('2026-01-01T00:00:00.000Z'),
      },
      handleBillingRequest: async (route, pathname, method, url) => {
        if (method === 'GET' && pathname === '/console/billing/overview') {
          overviewRequestCount += 1;
          await fulfillJson(route, {
            ok: true,
            overview: {
              usageMetricVersion: 'maw_v1',
              currentMonthUtc: '2026-03',
              monthlyActiveWallets: 42,
              creditBalanceMinor: 7400,
              lowBalanceThresholdMinor: 2000,
              recentUsageDebitMinor: 12600,
              recentCreditPurchasedMinor: 2500,
              documentCount: 2,
            },
          });
          return true;
        }

        if (method === 'GET' && pathname === '/console/billing/usage/monthly-active-wallets') {
          usageRequestCount += 1;
          await fulfillJson(route, {
            ok: true,
            usage: { usageMetricVersion: 'maw_v1', monthUtc: '2026-03', monthlyActiveWallets: 42 },
          });
          return true;
        }

        if (method === 'GET' && pathname === '/console/billing/account/activity') {
          await fulfillJson(route, {
            ok: true,
            activity: {
              entries: [],
            },
          });
          return true;
        }

        if (method === 'GET' && pathname === '/console/billing/invoices') {
          invoiceListUrls.push(url.toString());
          const documentType = String(url.searchParams.get('documentType') || '').trim();
          const filtered = documentType
            ? documents.filter((invoice) => invoice.documentType === documentType)
            : [...documents];
          await fulfillJson(route, {
            ok: true,
            invoices: filtered,
            nextCursor: null,
            totalCount: filtered.length,
            summary: {
              totalCount: filtered.length,
              openCount: 0,
              overdueCount: 0,
              paidCount: filtered.length,
              outstandingAmountMinor: 0,
              latestPeriodMonthUtc: filtered[0]?.periodMonthUtc || null,
              receiptCount: filtered.filter((entry) => entry.documentType === 'PURCHASE_RECEIPT')
                .length,
              statementCount: filtered.filter((entry) => entry.documentType === 'USAGE_STATEMENT')
                .length,
            },
          });
          return true;
        }

        const invoiceMatch = pathname.match(/^\/console\/billing\/invoices\/([^/]+)$/);
        if (method === 'GET' && invoiceMatch) {
          const invoice = documents.find(
            (entry) => entry.id === decodeURIComponent(invoiceMatch[1] || ''),
          );
          await fulfillJson(route, { ok: true, invoice: invoice || null });
          return true;
        }

        const lineItemsMatch = pathname.match(
          /^\/console\/billing\/invoices\/([^/]+)\/line-items$/,
        );
        if (method === 'GET' && lineItemsMatch) {
          const invoiceId = decodeURIComponent(lineItemsMatch[1] || '');
          const lineItems =
            invoiceId === 'receipt_dash_billing_1'
              ? [
                  {
                    id: 'li_receipt_1',
                    invoiceId,
                    itemType: 'CREDIT_TOP_UP',
                    description: 'Prepaid credit top-up (usd_25)',
                    quantity: 1,
                    unitAmountMinor: 2500,
                    amountMinor: 2500,
                    periodMonthUtc: '2026-03',
                  },
                ]
              : [
                  {
                    id: 'li_stmt_1',
                    invoiceId,
                    itemType: 'MAW_USAGE_DEBIT',
                    description: 'Monthly Active Wallet usage (2026-03)',
                    quantity: 42,
                    unitAmountMinor: 300,
                    amountMinor: 12600,
                    periodMonthUtc: '2026-03',
                  },
                ];
          await fulfillJson(route, { ok: true, lineItems });
          return true;
        }

        const activityMatch = pathname.match(/^\/console\/billing\/invoices\/([^/]+)\/activity$/);
        if (method === 'GET' && activityMatch) {
          const invoiceId = decodeURIComponent(activityMatch[1] || '');
          const invoice = documents.find((entry) => entry.id === invoiceId);
          await fulfillJson(route, {
            ok: true,
            activity: {
              invoice,
              entries: [
                {
                  id: `${invoiceId}:document`,
                  type: 'DOCUMENT',
                  invoiceId,
                  fromState: null,
                  toState: invoice?.status || 'PAID',
                  occurredAt: invoice?.createdAt || iso('2026-03-01T00:00:00.000Z'),
                  actorType: 'SYSTEM',
                  actorUserId: null,
                  reason: invoiceId.startsWith('receipt_')
                    ? 'purchase_receipt_created'
                    : 'usage_statement_created',
                  sourceEventId: null,
                  summary: invoiceId.startsWith('receipt_')
                    ? `Purchase receipt ${invoiceId} recorded for 2026-03.`
                    : `Usage statement ${invoiceId} recorded for 2026-03.`,
                  visibility: 'CUSTOMER',
                },
                {
                  id: `${invoiceId}:ledger`,
                  type: 'LEDGER',
                  invoiceId,
                  fromState: null,
                  toState: invoiceId.startsWith('receipt_') ? 'CREDIT_PURCHASE' : 'USAGE_DEBIT',
                  occurredAt: iso('2026-03-06T00:00:00.000Z'),
                  actorType: 'SYSTEM',
                  actorUserId: null,
                  reason: invoiceId.startsWith('receipt_') ? 'credit_purchase' : 'usage_debit',
                  sourceEventId: invoiceId.startsWith('receipt_')
                    ? 'cs_dash_billing_prepaid'
                    : 'evt_usage_stmt_1',
                  summary: invoiceId.startsWith('receipt_')
                    ? 'Credit pack usd_25 settled'
                    : 'MAW usage debit for March activity',
                  visibility: 'CUSTOMER',
                },
                ...(invoiceId.startsWith('receipt_')
                  ? [
                      {
                        id: `${invoiceId}:manual-adjustment`,
                        type: 'LEDGER',
                        invoiceId,
                        fromState: null,
                        toState: 'MANUAL_ADJUSTMENT',
                        occurredAt: iso('2026-03-07T00:00:00.000Z'),
                        actorType: 'USER',
                        actorUserId: 'owner_dash_billing',
                        reason: 'invoice_correction',
                        sourceEventId: null,
                        summary: 'Manual support credit linked to receipt review',
                        visibility: 'INTERNAL',
                      },
                    ]
                  : []),
              ],
            },
          });
          return true;
        }

        const pdfMatch = pathname.match(/^\/console\/billing\/invoices\/([^/]+)\/pdf$/);
        if (method === 'GET' && pdfMatch) {
          pdfDownloadCount += 1;
          const invoiceId = decodeURIComponent(pdfMatch[1] || '');
          await route.fulfill({
            status: 200,
            contentType: 'application/pdf',
            headers: {
              'Content-Disposition': `attachment; filename="invoice_${invoiceId}.pdf"`,
            },
            body: `%PDF-1.4\nBilling document\nDocument ID: ${invoiceId}\n%%EOF`,
          });
          return true;
        }

        return false;
      },
    });

    await page.goto('/dashboard/invoices');

    const invoicesTable = page.locator('section[aria-label="Billing documents table"]');
    await expect(invoicesTable).toContainText('receipt_dash_billing_1');
    await expect(invoicesTable).toContainText('stmt_dash_billing_1');
    expect(invoiceListUrls.length).toBe(1);
    expect(overviewRequestCount).toBe(0);
    expect(usageRequestCount).toBe(0);

    await page.locator('select.dashboard-input').first().selectOption('PURCHASE_RECEIPT');
    await expect(invoicesTable).toContainText('receipt_dash_billing_1');
    await expect(invoicesTable).not.toContainText('stmt_dash_billing_1');
    expect(invoiceListUrls.length).toBe(1);

    await invoicesTable.locator('button:has-text("Download PDF")').click();
    await expect.poll(() => pdfDownloadCount).toBe(1);

    await invoicesTable.locator('button:has-text("View document")').click();
    await expect(page).toHaveURL(/\/dashboard\/invoices\/receipt_dash_billing_1$/);
    await expect(
      page.locator('section[aria-label="Billing document detail header"]'),
    ).toContainText('receipt_dash_billing_1');
    await expect(
      page.locator('section[aria-label="Billing document activity timeline"]'),
    ).toContainText('Credit pack usd_25 settled');
    await expect(
      page.locator('section[aria-label="Billing document activity timeline"]'),
    ).toContainText(
      'Internal manual adjustments are visible in this staff timeline only and are excluded from exported PDFs.',
    );
    await expect(
      page.locator('section[aria-label="Billing document activity timeline"]'),
    ).toContainText('Internal only');
    await expect(page.locator('section[aria-label="Billing document line items"]')).toContainText(
      'Prepaid credit top-up (usd_25)',
    );
    await expect(page.locator('section[aria-label="Payment execution table"]')).toHaveCount(0);
    expect(overviewRequestCount).toBe(0);
    expect(usageRequestCount).toBe(0);

    await page
      .locator('section[aria-label="Billing document detail header"]')
      .locator('button:has-text("Download PDF")')
      .click();
    await expect.poll(() => pdfDownloadCount).toBe(2);
  });
});

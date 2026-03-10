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
    handleBillingRequest: (
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
  test('wires prepaid top-up and portal actions', async ({ page, baseURL }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    const checkoutBodies: Record<string, unknown>[] = [];
    const portalBodies: Record<string, unknown>[] = [];

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

        if (method === 'GET' && pathname === '/console/billing/payment-methods') {
          await fulfillJson(route, { ok: true, paymentMethods: [] });
          return true;
        }

        if (method === 'POST' && pathname === '/console/billing/stripe/customer-portal-session') {
          portalBodies.push(parseJsonBody(route.request().postData()));
          await fulfillJson(
            route,
            {
              ok: true,
              portalSession: {
                id: 'bps_dash_billing_prepaid',
                url: `${consoleOrigin}/dashboard/billing/account`,
                customerRef: 'cus_dash_billing_prepaid',
                expiresAt: iso('2026-03-01T01:00:00.000Z'),
              },
            },
            201,
          );
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

    await page.goto('/dashboard/billing');
    await expect(page).toHaveURL(/\/dashboard\/billing\/account$/);

    const billingScope = page.locator('section[aria-label="Billing scope and actions"]');
    await expect(billingScope).toContainText(project.name);
    await expect(billingScope).toContainText(environment.name);
    await expect(billingScope).not.toContainText(project.id);
    await expect(billingScope).not.toContainText(environment.id);
    await expect(page.locator('section[aria-label="Subscription management table"]')).toHaveCount(
      0,
    );

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

    const paymentMethodsSection = page.locator('section[aria-label="Payment methods table"]');
    await paymentMethodsSection
      .getByRole('button', { name: 'Update billing profile in portal' })
      .click();
    await expect.poll(() => portalBodies.length).toBe(1);
    expect(String(portalBodies[0]?.returnUrl || '')).toContain('/dashboard/billing/account');
  });

  test('wires invoice navigation, filters, and PDF export actions', async ({ page, baseURL }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    const invoiceListUrls: string[] = [];
    let overviewRequestCount = 0;
    let usageRequestCount = 0;
    let paymentMethodRequestCount = 0;
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
        name: 'Dashboard Billing Invoice Org',
        slug: 'dashboard-billing-invoice-org',
        status: 'ACTIVE',
        createdAt: iso('2026-01-01T00:00:00.000Z'),
        updatedAt: iso('2026-01-01T00:00:00.000Z'),
      },
      project: {
        id: 'proj_dash_billing_invoice',
        name: 'Billing Invoice Project',
        slug: 'billing-invoice-project',
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

        if (method === 'GET' && pathname === '/console/billing/payment-methods') {
          paymentMethodRequestCount += 1;
          await fulfillJson(route, { ok: true, paymentMethods: [] });
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
                },
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

    const invoicesTable = page.locator('section[aria-label="Invoices table"]');
    await expect(invoicesTable).toContainText('receipt_dash_billing_1');
    await expect(invoicesTable).toContainText('stmt_dash_billing_1');
    expect(invoiceListUrls.length).toBe(1);
    expect(overviewRequestCount).toBe(0);
    expect(usageRequestCount).toBe(0);
    expect(paymentMethodRequestCount).toBe(0);

    await page.locator('select.dashboard-input').first().selectOption('PURCHASE_RECEIPT');
    await expect(invoicesTable).toContainText('receipt_dash_billing_1');
    await expect(invoicesTable).not.toContainText('stmt_dash_billing_1');
    expect(invoiceListUrls.length).toBe(1);

    await invoicesTable.locator('button:has-text("Download PDF")').click();
    await expect.poll(() => pdfDownloadCount).toBe(1);

    await invoicesTable.locator('button:has-text("View document")').click();
    await expect(page).toHaveURL(/\/dashboard\/invoices\/receipt_dash_billing_1$/);
    await expect(page.locator('section[aria-label="Invoice detail header"]')).toContainText(
      'receipt_dash_billing_1',
    );
    await expect(page.locator('section[aria-label="Invoice activity timeline"]')).toContainText(
      'Credit pack usd_25 settled',
    );
    await expect(page.locator('section[aria-label="Invoice line items"]')).toContainText(
      'Prepaid credit top-up (usd_25)',
    );
    await expect(page.locator('section[aria-label="Payment execution table"]')).toHaveCount(0);
    expect(overviewRequestCount).toBe(0);
    expect(usageRequestCount).toBe(0);
    expect(paymentMethodRequestCount).toBe(0);

    await page
      .locator('section[aria-label="Invoice detail header"]')
      .locator('button:has-text("Download PDF")')
      .click();
    await expect.poll(() => pdfDownloadCount).toBe(2);
  });

  test('wires payment-method mutation and replacement actions', async ({ page, baseURL }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    const addBodies: Record<string, unknown>[] = [];
    const setDefaultIds: string[] = [];
    const removedIds: string[] = [];
    const setupBodies: Record<string, unknown>[] = [];
    const portalBodies: Record<string, unknown>[] = [];

    const org = {
      id: 'org_dash_billing_payment_methods',
      name: 'Dashboard Billing PM Org',
      slug: 'dashboard-billing-pm-org',
      status: 'ACTIVE',
      createdAt: iso('2026-01-01T00:00:00.000Z'),
      updatedAt: iso('2026-01-01T00:00:00.000Z'),
    };
    const project = {
      id: 'proj_dash_billing_payment_methods',
      name: 'Billing PM Project',
      slug: 'billing-pm-project',
      status: 'ACTIVE',
      environmentCount: 1,
      createdAt: iso('2026-01-01T00:00:00.000Z'),
      updatedAt: iso('2026-01-01T00:00:00.000Z'),
    };
    const environment = {
      id: 'env_dash_billing_payment_methods',
      projectId: project.id,
      key: 'prod',
      name: 'Production',
      status: 'ACTIVE',
      createdAt: iso('2026-01-01T00:00:00.000Z'),
      updatedAt: iso('2026-01-01T00:00:00.000Z'),
    };

    let paymentMethods = [
      {
        id: 'pm_dash_existing_default',
        provider: 'stripe',
        type: 'card',
        brand: 'visa',
        last4: '1111',
        expMonth: 1,
        expYear: 2030,
        isDefault: true,
        createdAt: iso('2026-01-01T00:00:00.000Z'),
      },
      {
        id: 'pm_dash_existing_secondary',
        provider: 'stripe',
        type: 'card',
        brand: 'mastercard',
        last4: '2222',
        expMonth: 2,
        expYear: 2031,
        isDefault: false,
        createdAt: iso('2026-01-02T00:00:00.000Z'),
      },
    ];

    page.on('dialog', async (dialog) => {
      await dialog.accept();
    });

    await routeWorkspaceScaffold(page, consoleOrigin, {
      userId: 'user_dash_billing_payment_methods',
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
              monthlyActiveWallets: 8,
              creditBalanceMinor: 7400,
              lowBalanceThresholdMinor: 2000,
              recentUsageDebitMinor: 2400,
              recentCreditPurchasedMinor: 10000,
              documentCount: 2,
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
              monthlyActiveWallets: 8,
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

        if (method === 'GET' && pathname === '/console/billing/payment-methods') {
          await fulfillJson(route, { ok: true, paymentMethods });
          return true;
        }

        if (method === 'POST' && pathname === '/console/billing/payment-methods') {
          const body = parseJsonBody(route.request().postData());
          addBodies.push(body);
          const nextId = `pm_dash_added_${paymentMethods.length + 1}`;
          paymentMethods = [
            {
              id: nextId,
              provider: 'stripe',
              type: 'card',
              brand: String(body.brand || 'visa'),
              last4: String(body.last4 || '0000'),
              expMonth: Number(body.expMonth || 1),
              expYear: Number(body.expYear || 2035),
              isDefault: false,
              createdAt: iso('2026-03-05T00:00:00.000Z'),
            },
            ...paymentMethods,
          ];
          await fulfillJson(route, { ok: true, paymentMethod: paymentMethods[0] }, 201);
          return true;
        }

        const paymentMethodDefaultMatch = pathname.match(
          /^\/console\/billing\/payment-methods\/([^/]+)\/default$/,
        );
        if (method === 'POST' && paymentMethodDefaultMatch) {
          const paymentMethodId = decodeURIComponent(paymentMethodDefaultMatch[1] || '');
          setDefaultIds.push(paymentMethodId);
          paymentMethods = paymentMethods.map((method) => ({
            ...method,
            isDefault: method.id === paymentMethodId,
          }));
          await fulfillJson(route, {
            ok: true,
            paymentMethod: paymentMethods.find((method) => method.id === paymentMethodId) || null,
          });
          return true;
        }

        const paymentMethodMatch = pathname.match(/^\/console\/billing\/payment-methods\/([^/]+)$/);
        if (method === 'DELETE' && paymentMethodMatch) {
          const paymentMethodId = decodeURIComponent(paymentMethodMatch[1] || '');
          removedIds.push(paymentMethodId);
          paymentMethods = paymentMethods.filter((method) => method.id !== paymentMethodId);
          if (!paymentMethods.some((method) => method.isDefault) && paymentMethods[0]) {
            paymentMethods = paymentMethods.map((method, index) => ({
              ...method,
              isDefault: index === 0,
            }));
          }
          await fulfillJson(route, { ok: true, removed: true });
          return true;
        }

        if (method === 'POST' && pathname === '/console/billing/stripe/setup-intent') {
          setupBodies.push(parseJsonBody(route.request().postData()));
          await fulfillJson(
            route,
            {
              ok: true,
              setupIntent: {
                id: 'seti_dash_billing_payment_methods',
                clientSecret: 'seti_dash_billing_payment_methods_secret',
                customerRef: 'cus_dash_billing_payment_methods',
                expiresAt: iso('2026-03-05T01:00:00.000Z'),
              },
            },
            200,
          );
          return true;
        }

        if (method === 'POST' && pathname === '/console/billing/stripe/customer-portal-session') {
          portalBodies.push(parseJsonBody(route.request().postData()));
          await fulfillJson(
            route,
            {
              ok: true,
              portalSession: {
                id: 'bps_dash_billing_payment_methods',
                url: `${consoleOrigin}/dashboard/billing/account`,
                customerRef: 'cus_dash_billing_payment_methods',
                expiresAt: iso('2026-03-05T01:00:00.000Z'),
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

    const paymentMethodsSection = page.locator('section[aria-label="Payment methods table"]');
    await expect(paymentMethodsSection).toContainText('pm_dash_existing_default');
    await expect(paymentMethodsSection).toContainText('pm_dash_existing_secondary');

    await paymentMethodsSection
      .getByRole('button', { name: 'Start Stripe card replacement' })
      .click();
    await expect.poll(() => setupBodies.length).toBe(1);
    await expect(paymentMethodsSection).toContainText('seti_dash_billing_payment_methods');

    await paymentMethodsSection
      .getByRole('textbox', { name: 'Provider reference' })
      .fill('pm_new_dashboard_card');
    await paymentMethodsSection.getByRole('textbox', { name: 'Brand' }).fill('amex');
    await paymentMethodsSection.getByRole('textbox', { name: 'Last4' }).fill('3434');
    await paymentMethodsSection.getByRole('textbox', { name: 'Expiry month' }).fill('11');
    await paymentMethodsSection.getByRole('textbox', { name: 'Expiry year' }).fill('2036');
    await paymentMethodsSection.locator('form').evaluate((form) => {
      (form as HTMLFormElement).requestSubmit();
    });

    await expect.poll(() => addBodies.length).toBe(1);
    expect(String(addBodies[0]?.providerRef || '')).toBe('pm_new_dashboard_card');
    await expect(paymentMethodsSection).toContainText('pm_dash_added_3');

    await paymentMethodsSection.getByRole('button', { name: 'Set default' }).first().click();
    await expect.poll(() => setDefaultIds.length).toBe(1);
    expect(setDefaultIds[0]).toBe('pm_dash_added_3');

    const addedRow = paymentMethodsSection.getByRole('row', {
      name: /pm_dash_added_3/i,
    });
    await expect(addedRow).toContainText('Yes');

    await addedRow.getByRole('button', { name: 'Remove' }).click();
    await expect.poll(() => removedIds.length).toBe(1);
    expect(removedIds[0]).toBe('pm_dash_added_3');
    await expect(paymentMethodsSection).not.toContainText('pm_dash_added_3');

    await paymentMethodsSection
      .getByRole('button', { name: 'Update billing profile in portal' })
      .click();
    await expect.poll(() => portalBodies.length).toBe(1);
    expect(String(portalBodies[0]?.returnUrl || '')).toContain('/dashboard/billing/account');
  });
});

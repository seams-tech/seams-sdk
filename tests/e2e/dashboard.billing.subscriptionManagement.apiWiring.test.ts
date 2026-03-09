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

test.describe('dashboard billing subscription management api wiring', () => {
  test('wires subscription lifecycle and Stripe checkout/portal actions', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    const checkoutBodies: Record<string, unknown>[] = [];
    const portalBodies: Record<string, unknown>[] = [];
    let cancelCount = 0;
    let resumeCount = 0;

    const org = {
      id: 'org_dash_billing_subs',
      name: 'Dashboard Billing Org',
      slug: 'dashboard-billing-org',
      status: 'ACTIVE',
      createdAt: iso('2026-01-01T00:00:00.000Z'),
      updatedAt: iso('2026-01-01T00:00:00.000Z'),
    };

    const project = {
      id: 'proj_dash_billing_subs',
      name: 'Billing Project',
      slug: 'billing-project',
      status: 'ACTIVE',
      environmentCount: 1,
      createdAt: iso('2026-01-01T00:00:00.000Z'),
      updatedAt: iso('2026-01-01T00:00:00.000Z'),
    };

    const environment = {
      id: 'env_dash_billing_subs',
      projectId: project.id,
      key: 'prod',
      name: 'Production',
      status: 'ACTIVE',
      createdAt: iso('2026-01-01T00:00:00.000Z'),
      updatedAt: iso('2026-01-01T00:00:00.000Z'),
    };

    let subscription = {
      id: 'sub_dash_billing_subs',
      orgId: org.id,
      provider: 'stripe',
      providerCustomerRef: 'cus_dash_billing_subs',
      providerSubscriptionRef: 'sub_provider_dash_billing_subs',
      planId: 'pro_maw_v1',
      planName: 'Pro MAW',
      status: 'ACTIVE',
      cancelAtPeriodEnd: false,
      currentPeriodStart: iso('2026-02-01T00:00:00.000Z'),
      currentPeriodEnd: iso('2026-03-01T00:00:00.000Z'),
      cancelAt: null as string | null,
      canceledAt: null as string | null,
      createdAt: iso('2026-02-01T00:00:00.000Z'),
      updatedAt: iso('2026-02-01T00:00:00.000Z'),
    };

    page.on('dialog', async (dialog) => {
      await dialog.accept();
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
              userId: 'user_dash_billing_subs',
              orgId: org.id,
              roles: ['admin'],
              projectId: project.id,
              environmentId: environment.id,
            },
          }),
        });
        return;
      }

      if (pathname === '/console/org') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, org }),
        });
        return;
      }

      if (pathname === '/console/projects') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, projects: [project] }),
        });
        return;
      }

      if (pathname === '/console/environments') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, environments: [environment] }),
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
              planId: subscription.planId,
              planName: subscription.planName,
              usageMetricVersion: 'maw_v1',
              currentMonthUtc: '2026-03',
              monthlyActiveWallets: 42,
              creditBalanceMinor: 2500,
              upcomingChargeEstimateMinor: 5500,
              openInvoiceCount: 1,
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
              monthlyActiveWallets: 42,
            },
          }),
        });
        return;
      }

      if (method === 'GET' && pathname === '/console/billing/invoices') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            invoices: [
              {
                id: 'inv_dash_billing_subs_1',
                status: 'OPEN',
                amountDueMinor: 5500,
                amountPaidMinor: 0,
                railLock: null,
                periodMonthUtc: '2026-03',
                dueAt: iso('2026-03-05T00:00:00.000Z'),
                createdAt: iso('2026-03-01T00:00:00.000Z'),
              },
            ],
          }),
        });
        return;
      }

      const lineItemsMatch = pathname.match(/^\/console\/billing\/invoices\/([^/]+)\/line-items$/);
      if (method === 'GET' && lineItemsMatch) {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            lineItems: [],
          }),
        });
        return;
      }

      const activityMatch = pathname.match(/^\/console\/billing\/invoices\/([^/]+)\/activity$/);
      if (method === 'GET' && activityMatch) {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            activity: {
              invoice,
              latestPaymentState: 'PENDING',
              latestPaymentRail: 'CARD',
              entries: [
                {
                  id: `${invoice.id}:issued`,
                  type: 'INVOICE',
                  invoiceId: invoice.id,
                  paymentId: null,
                  rail: null,
                  fromState: null,
                  toState: 'OPEN',
                  occurredAt: invoice.createdAt,
                  actorType: 'SYSTEM',
                  actorUserId: null,
                  reason: 'invoice_created',
                  sourceEventId: null,
                  summary: `Invoice ${invoice.id} issued for billing period ${invoice.periodMonthUtc}.`,
                },
                {
                  id: 'pi_dash_billing_invoice_transition_1',
                  type: 'PAYMENT',
                  invoiceId: invoice.id,
                  paymentId: 'pi_dash_billing_invoice_1',
                  rail: 'CARD',
                  fromState: null,
                  toState: 'PENDING',
                  occurredAt: iso('2026-03-02T00:00:00.000Z'),
                  actorType: 'PROVIDER',
                  actorUserId: null,
                  reason: 'provider_pending',
                  sourceEventId: 'evt_dash_billing_invoice_pending',
                  summary: 'Card payment pi_dash_billing_invoice_1 moved to pending.',
                },
              ],
            },
          }),
        });
        return;
      }

      if (method === 'GET' && pathname === '/console/billing/payment-methods') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            paymentMethods: [],
          }),
        });
        return;
      }

      if (method === 'GET' && pathname === '/console/billing/subscription') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            subscription,
          }),
        });
        return;
      }

      if (method === 'POST' && pathname === '/console/billing/subscription/cancel') {
        cancelCount += 1;
        subscription = {
          ...subscription,
          cancelAtPeriodEnd: true,
          cancelAt: subscription.currentPeriodEnd,
          updatedAt: iso('2026-03-02T00:00:00.000Z'),
        };
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            subscription,
          }),
        });
        return;
      }

      if (method === 'POST' && pathname === '/console/billing/subscription/resume') {
        resumeCount += 1;
        subscription = {
          ...subscription,
          cancelAtPeriodEnd: false,
          cancelAt: null,
          updatedAt: iso('2026-03-02T01:00:00.000Z'),
        };
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            subscription,
          }),
        });
        return;
      }

      if (method === 'POST' && pathname === '/console/billing/stripe/customer-portal-session') {
        portalBodies.push(parseJsonBody(req.postData()));
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            portalSession: {
              id: 'bps_dash_billing_subs',
              url: `${consoleOrigin}/dashboard/billing/account`,
              customerRef: subscription.providerCustomerRef,
              expiresAt: iso('2026-03-01T01:00:00.000Z'),
            },
          }),
        });
        return;
      }

      if (method === 'POST' && pathname === '/console/billing/stripe/checkout-session') {
        checkoutBodies.push(parseJsonBody(req.postData()));
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            checkoutSession: {
              id: 'cs_dash_billing_subs',
              url: `${consoleOrigin}/dashboard/billing/account?checkout=success`,
              customerRef: subscription.providerCustomerRef,
              expiresAt: iso('2026-03-01T01:00:00.000Z'),
            },
          }),
        });
        return;
      }

      if (method === 'GET' && pathname === '/console/billing/stablecoins/assets') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            version: 'v1',
            assets: [
              {
                asset: 'USDC',
                chains: [
                  {
                    chain: 'Ethereum',
                    requiredConfirmations: 12,
                    confirmationTimeoutMinutes: 30,
                    reorgRiskWindowHours: 24,
                  },
                ],
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
          code: 'not_found',
          message: `Unhandled mock path ${pathname}`,
        }),
      });
    });

    await page.goto('/dashboard/billing');
    await expect(page).toHaveURL(/\/dashboard\/billing\/account$/);
    const subscriptionSection = page.locator('section[aria-label="Subscription management table"]');
    await expect(subscriptionSection).toContainText(/Status\s*Active/);
    await expect(subscriptionSection).toContainText(/Cancel at period end\s*No/);

    await subscriptionSection.locator('button:has-text("Cancel at period end")').click();
    await expect.poll(() => cancelCount).toBe(1);
    await expect(subscriptionSection).toContainText(/Cancel at period end\s*Yes/);

    await subscriptionSection.locator('button:has-text("Resume subscription")').click();
    await expect.poll(() => resumeCount).toBe(1);
    await expect(subscriptionSection).toContainText(/Cancel at period end\s*No/);

    await subscriptionSection.locator('button:has-text("Open Stripe Customer Portal")').click();
    await expect.poll(() => portalBodies.length).toBe(1);
    expect(String(portalBodies[0]?.returnUrl || '')).toContain('/dashboard/billing/account');

    await subscriptionSection.locator('button:has-text("Start Stripe Checkout")').click();
    await expect(
      page.locator('.dashboard-info-banner', {
        hasText: 'Stripe Checkout completed',
      }),
    ).toContainText('Stripe Checkout completed');
    await expect.poll(() => checkoutBodies.length).toBe(1);
    expect(String(checkoutBodies[0]?.successUrl || '')).toContain(
      '/dashboard/billing/account?checkout=success',
    );
    expect(String(checkoutBodies[0]?.cancelUrl || '')).toContain('/pricing?checkout=cancel');
    expect(String(checkoutBodies[0]?.planId || '')).toBe('pro_maw_v1');
  });

  test('wires invoice navigation and PDF export actions', async ({ page, baseURL }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    let pdfDownloadCount = 0;
    const invoice = {
      id: 'inv_dash_billing_invoice_1',
      status: 'OPEN',
      amountDueMinor: 4900,
      amountPaidMinor: 0,
      railLock: null,
      periodMonthUtc: '2026-03',
      dueAt: iso('2026-03-10T00:00:00.000Z'),
      createdAt: iso('2026-03-01T00:00:00.000Z'),
    };
    const lineItems = [
      {
        id: 'li_dash_billing_invoice_1',
        invoiceId: invoice.id,
        itemType: 'PLAN_BASE_FEE',
        description: 'Pro MAW base fee',
        quantity: 1,
        unitAmountMinor: 1900,
        amountMinor: 1900,
        periodMonthUtc: '2026-03',
      },
      {
        id: 'li_dash_billing_invoice_2',
        invoiceId: invoice.id,
        itemType: 'MAW_USAGE',
        description: '10 monthly active wallets',
        quantity: 10,
        unitAmountMinor: 300,
        amountMinor: 3000,
        periodMonthUtc: '2026-03',
      },
    ];

    await page.addInitScript(() => {
      const target = window as typeof window & {
        __lastBillingBlobSize?: number;
      };
      const originalCreateObjectURL = URL.createObjectURL.bind(URL);
      target.__lastBillingBlobSize = 0;
      URL.createObjectURL = ((blob: Blob) => {
        target.__lastBillingBlobSize = blob.size;
        return originalCreateObjectURL(blob);
      }) as typeof URL.createObjectURL;
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
              userId: 'user_dash_billing_invoice',
              orgId: 'org_dash_billing_invoice',
              roles: ['admin'],
              projectId: 'proj_dash_billing_invoice',
              environmentId: 'env_dash_billing_invoice',
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
              id: 'org_dash_billing_invoice',
              name: 'Dashboard Billing Invoice Org',
              slug: 'dashboard-billing-invoice-org',
              status: 'ACTIVE',
              createdAt: iso('2026-01-01T00:00:00.000Z'),
              updatedAt: iso('2026-01-01T00:00:00.000Z'),
            },
          }),
        });
        return;
      }

      if (pathname === '/console/projects') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            projects: [
              {
                id: 'proj_dash_billing_invoice',
                name: 'Billing Invoice Project',
                slug: 'billing-invoice-project',
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

      if (pathname === '/console/environments') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            environments: [
              {
                id: 'env_dash_billing_invoice',
                projectId: 'proj_dash_billing_invoice',
                key: 'prod',
                name: 'Production',
                status: 'ACTIVE',
                createdAt: iso('2026-01-01T00:00:00.000Z'),
                updatedAt: iso('2026-01-01T00:00:00.000Z'),
              },
            ],
          }),
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
              planId: 'pro_maw_v1',
              planName: 'Pro MAW',
              usageMetricVersion: 'maw_v1',
              currentMonthUtc: '2026-03',
              monthlyActiveWallets: 10,
              creditBalanceMinor: 0,
              upcomingChargeEstimateMinor: invoice.amountDueMinor,
              openInvoiceCount: 1,
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
              monthlyActiveWallets: 10,
            },
          }),
        });
        return;
      }

      if (method === 'GET' && pathname === '/console/billing/invoices') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            invoices: [invoice],
          }),
        });
        return;
      }

      const invoiceMatch = pathname.match(/^\/console\/billing\/invoices\/([^/]+)$/);
      if (method === 'GET' && invoiceMatch) {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            invoice,
          }),
        });
        return;
      }

      const lineItemsMatch = pathname.match(/^\/console\/billing\/invoices\/([^/]+)\/line-items$/);
      if (method === 'GET' && lineItemsMatch) {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            lineItems,
          }),
        });
        return;
      }

      const activityMatch = pathname.match(/^\/console\/billing\/invoices\/([^/]+)\/activity$/);
      if (method === 'GET' && activityMatch) {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            activity: {
              invoice,
              latestPaymentState: 'PENDING',
              latestPaymentRail: 'CARD',
              entries: [
                {
                  id: `${invoice.id}:issued`,
                  type: 'INVOICE',
                  invoiceId: invoice.id,
                  paymentId: null,
                  rail: null,
                  fromState: null,
                  toState: 'OPEN',
                  occurredAt: invoice.createdAt,
                  actorType: 'SYSTEM',
                  actorUserId: null,
                  reason: 'invoice_created',
                  sourceEventId: null,
                  summary: `Invoice ${invoice.id} issued for billing period ${invoice.periodMonthUtc}.`,
                },
                {
                  id: 'pi_dash_billing_invoice_transition_1',
                  type: 'PAYMENT',
                  invoiceId: invoice.id,
                  paymentId: 'pi_dash_billing_invoice_1',
                  rail: 'CARD',
                  fromState: null,
                  toState: 'PENDING',
                  occurredAt: iso('2026-03-02T00:00:00.000Z'),
                  actorType: 'PROVIDER',
                  actorUserId: null,
                  reason: 'provider_pending',
                  sourceEventId: 'evt_dash_billing_invoice_pending',
                  summary: 'Card payment pi_dash_billing_invoice_1 moved to pending.',
                },
              ],
            },
          }),
        });
        return;
      }

      const pdfMatch = pathname.match(/^\/console\/billing\/invoices\/([^/]+)\/pdf$/);
      if (method === 'GET' && pdfMatch) {
        pdfDownloadCount += 1;
        await route.fulfill({
          status: 200,
          contentType: 'application/pdf',
          headers: {
            'Content-Disposition': `attachment; filename="invoice_${invoice.periodMonthUtc}_${invoice.id}.pdf"`,
          },
          body: `%PDF-1.4\nBilling invoice\nInvoice ID: ${invoice.id}\n%%EOF`,
        });
        return;
      }

      if (method === 'GET' && pathname === '/console/billing/payment-methods') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            paymentMethods: [],
          }),
        });
        return;
      }

      if (method === 'GET' && pathname === '/console/billing/subscription') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            subscription: {
              id: 'sub_dash_billing_invoice',
              orgId: 'org_dash_billing_invoice',
              provider: 'stripe',
              providerCustomerRef: 'cus_dash_billing_invoice',
              providerSubscriptionRef: 'sub_provider_dash_billing_invoice',
              planId: 'pro_maw_v1',
              planName: 'Pro MAW',
              status: 'ACTIVE',
              cancelAtPeriodEnd: false,
              currentPeriodStart: iso('2026-03-01T00:00:00.000Z'),
              currentPeriodEnd: iso('2026-04-01T00:00:00.000Z'),
              cancelAt: null,
              canceledAt: null,
              createdAt: iso('2026-03-01T00:00:00.000Z'),
              updatedAt: iso('2026-03-01T00:00:00.000Z'),
            },
          }),
        });
        return;
      }

      if (method === 'GET' && pathname === '/console/billing/stablecoins/assets') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            version: 'v1',
            assets: [
              {
                asset: 'USDC',
                chains: [
                  {
                    chain: 'Ethereum',
                    requiredConfirmations: 12,
                    confirmationTimeoutMinutes: 30,
                    reorgRiskWindowHours: 24,
                  },
                ],
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
          code: 'not_found',
          message: `Unhandled mock path ${pathname}`,
        }),
      });
    });

    await page.goto('/dashboard/billing/account');
    await page
      .locator('aside[aria-label="Primary dashboard navigation"]')
      .getByRole('link', { name: 'Invoices' })
      .click();
    await expect(page).toHaveURL(/\/dashboard\/invoices$/);

    const invoicesTable = page.locator('section[aria-label="Invoices table"]');
    await expect(invoicesTable).toContainText(invoice.id);
    await invoicesTable.locator('button:has-text("Download PDF")').click();
    await expect.poll(() => pdfDownloadCount).toBe(1);

    const invoiceDetailRequest = page.waitForResponse((response) => {
      const url = new URL(response.url());
      return (
        response.request().method() === 'GET' &&
        url.pathname === `/console/billing/invoices/${encodeURIComponent(invoice.id)}`
      );
    });
    const lineItemsRequest = page.waitForResponse((response) => {
      const url = new URL(response.url());
      return (
        response.request().method() === 'GET' &&
        url.pathname === `/console/billing/invoices/${encodeURIComponent(invoice.id)}/line-items`
      );
    });

    await invoicesTable.locator('button:has-text("View invoice")').click();
    await Promise.all([invoiceDetailRequest, lineItemsRequest]);
    await expect(page).toHaveURL(
      new RegExp(`/dashboard/invoices/${encodeURIComponent(invoice.id)}$`),
    );

    await expect(page.locator('section[aria-label="Invoice detail header"]')).toContainText(
      invoice.id,
    );
    await expect(page.getByText('Loading invoice detail...')).toBeHidden();
    await expect(page.locator('section[aria-label="Invoice line items"]')).toContainText(
      'Pro MAW base fee',
    );
    await expect(page.locator('section[aria-label="Invoice activity timeline"]')).toContainText(
      'Latest payment state',
    );
    await expect(page.locator('section[aria-label="Payment execution table"]')).toContainText(
      'Stripe card payment',
    );

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
              userId: 'user_dash_billing_payment_methods',
              orgId: org.id,
              roles: ['admin'],
              projectId: project.id,
              environmentId: environment.id,
            },
          }),
        });
        return;
      }

      if (pathname === '/console/org') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, org }),
        });
        return;
      }

      if (pathname === '/console/projects') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, projects: [project] }),
        });
        return;
      }

      if (pathname === '/console/environments') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true, environments: [environment] }),
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
              planId: 'pro_maw_v1',
              planName: 'Pro MAW',
              usageMetricVersion: 'maw_v1',
              currentMonthUtc: '2026-03',
              monthlyActiveWallets: 8,
              creditBalanceMinor: 0,
              upcomingChargeEstimateMinor: 4900,
              openInvoiceCount: 1,
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
              monthlyActiveWallets: 8,
            },
          }),
        });
        return;
      }

      if (method === 'GET' && pathname === '/console/billing/payment-methods') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            paymentMethods,
          }),
        });
        return;
      }

      if (method === 'POST' && pathname === '/console/billing/payment-methods') {
        const body = parseJsonBody(req.postData());
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
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            paymentMethod: paymentMethods[0],
          }),
        });
        return;
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
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            paymentMethod: paymentMethods.find((method) => method.id === paymentMethodId) || null,
          }),
        });
        return;
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
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            removed: true,
          }),
        });
        return;
      }

      if (method === 'GET' && pathname === '/console/billing/subscription') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            subscription: {
              id: 'sub_dash_billing_payment_methods',
              orgId: org.id,
              provider: 'stripe',
              providerCustomerRef: 'cus_dash_billing_payment_methods',
              providerSubscriptionRef: 'sub_provider_dash_billing_payment_methods',
              planId: 'pro_maw_v1',
              planName: 'Pro MAW',
              status: 'ACTIVE',
              cancelAtPeriodEnd: false,
              currentPeriodStart: iso('2026-03-01T00:00:00.000Z'),
              currentPeriodEnd: iso('2026-04-01T00:00:00.000Z'),
              cancelAt: null,
              canceledAt: null,
              createdAt: iso('2026-03-01T00:00:00.000Z'),
              updatedAt: iso('2026-03-01T00:00:00.000Z'),
            },
          }),
        });
        return;
      }

      if (method === 'POST' && pathname === '/console/billing/stripe/setup-intent') {
        setupBodies.push(parseJsonBody(req.postData()));
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            setupIntent: {
              id: 'seti_dash_billing_payment_methods',
              clientSecret: 'seti_dash_billing_payment_methods_secret',
              customerRef: 'cus_dash_billing_payment_methods',
              expiresAt: iso('2026-03-05T01:00:00.000Z'),
            },
          }),
        });
        return;
      }

      if (method === 'POST' && pathname === '/console/billing/stripe/customer-portal-session') {
        portalBodies.push(parseJsonBody(req.postData()));
        await route.fulfill({
          status: 201,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            portalSession: {
              id: 'bps_dash_billing_payment_methods',
              url: `${consoleOrigin}/dashboard/billing/account`,
              customerRef: 'cus_dash_billing_payment_methods',
              expiresAt: iso('2026-03-05T01:00:00.000Z'),
            },
          }),
        });
        return;
      }

      if (method === 'GET' && pathname === '/console/billing/stablecoins/assets') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            ok: true,
            version: 'v1',
            assets: [],
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

    await page.goto('/dashboard/billing');

    const paymentMethodsSection = page.locator('section[aria-label="Payment methods table"]');
    await expect(paymentMethodsSection).toContainText('pm_dash_existing_default');
    await expect(paymentMethodsSection).toContainText('pm_dash_existing_secondary');

    await paymentMethodsSection
      .getByRole('button', { name: 'Start Stripe card replacement' })
      .click();
    await expect.poll(() => setupBodies.length).toBe(1);
    await expect(paymentMethodsSection).toContainText('seti_dash_billing_payment_methods');

    await paymentMethodsSection
      .getByRole('button', { name: 'Update billing profile in portal' })
      .click();
    await expect.poll(() => portalBodies.length).toBe(1);
    expect(String(portalBodies[0]?.returnUrl || '')).toContain('/dashboard/billing/account');
    await page.goto('/dashboard/billing/account');
    await expect(paymentMethodsSection).toBeVisible();

    await paymentMethodsSection
      .getByRole('textbox', { name: 'Provider reference' })
      .fill('pm_new_dashboard_card');
    await paymentMethodsSection.getByRole('textbox', { name: 'Brand' }).fill('amex');
    await paymentMethodsSection.getByRole('textbox', { name: 'Last4' }).fill('3434');
    await paymentMethodsSection.getByRole('textbox', { name: 'Expiry month' }).fill('11');
    await paymentMethodsSection.getByRole('textbox', { name: 'Expiry year' }).fill('2036');
    await paymentMethodsSection.getByRole('button', { name: 'Add card' }).click();

    await expect.poll(() => addBodies.length).toBe(1);
    expect(String(addBodies[0]?.providerRef || '')).toBe('pm_new_dashboard_card');
    await expect(paymentMethodsSection).toContainText('pm_dash_added_3');
    await expect(paymentMethodsSection).toContainText('3434');

    await paymentMethodsSection.getByRole('button', { name: 'Set default' }).first().click();
    await expect.poll(() => setDefaultIds.length).toBe(1);
    expect(setDefaultIds[0]).toBe('pm_dash_added_3');

    const addedRow = paymentMethodsSection.locator('.dashboard-table-row', {
      hasText: 'pm_dash_added_3',
    });
    await expect(addedRow).toContainText('Yes');

    await addedRow.getByRole('button', { name: 'Remove' }).click();
    await expect.poll(() => removedIds.length).toBe(1);
    expect(removedIds[0]).toBe('pm_dash_added_3');
    await expect(paymentMethodsSection).not.toContainText('pm_dash_added_3');
  });
});

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
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:5174')).origin;
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
              url: `${consoleOrigin}/dashboard/billing`,
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
              url: `${consoleOrigin}/dashboard/billing?checkout=success`,
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
    const subscriptionSection = page.locator('section[aria-label="Subscription management table"]');
    await expect(subscriptionSection).toContainText('Status: ACTIVE');
    await expect(subscriptionSection).toContainText('Cancel at period end: No');

    await subscriptionSection.locator('button:has-text("Cancel at period end")').click();
    await expect.poll(() => cancelCount).toBe(1);
    await expect(subscriptionSection).toContainText('Cancel at period end: Yes');

    await subscriptionSection.locator('button:has-text("Resume subscription")').click();
    await expect.poll(() => resumeCount).toBe(1);
    await expect(subscriptionSection).toContainText('Cancel at period end: No');

    await subscriptionSection.locator('button:has-text("Open Stripe Customer Portal")').click();
    await expect.poll(() => portalBodies.length).toBe(1);
    expect(String(portalBodies[0]?.returnUrl || '')).toContain('/dashboard/billing');

    await subscriptionSection.locator('button:has-text("Start Stripe Checkout")').click();
    await expect(
      page.locator('.dashboard-info-banner', {
        hasText: 'Stripe Checkout completed',
      }),
    ).toContainText('Stripe Checkout completed');
    await expect.poll(() => checkoutBodies.length).toBe(1);
    expect(String(checkoutBodies[0]?.successUrl || '')).toContain('/dashboard/billing?checkout=success');
    expect(String(checkoutBodies[0]?.cancelUrl || '')).toContain('/pricing?checkout=cancel');
    expect(String(checkoutBodies[0]?.planId || '')).toBe('pro_maw_v1');
  });
});

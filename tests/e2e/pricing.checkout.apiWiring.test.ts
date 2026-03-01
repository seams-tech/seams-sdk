import { expect, test } from '@playwright/test';

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

test.describe('pricing checkout api wiring', () => {
  test('creates Stripe checkout session and redirects to returned URL', async ({ page, baseURL }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:5174')).origin;
    const checkoutBodies: Record<string, unknown>[] = [];

    await page.route(`${consoleOrigin}/console/billing/stripe/checkout-session`, async (route) => {
      const req = route.request();
      if (req.method().toUpperCase() !== 'POST') {
        await route.fulfill({
          status: 405,
          contentType: 'application/json',
          body: JSON.stringify({ ok: false, code: 'method_not_allowed' }),
        });
        return;
      }

      checkoutBodies.push(parseJsonBody(req.postData()));
      await route.fulfill({
        status: 201,
        contentType: 'application/json',
        body: JSON.stringify({
          ok: true,
          checkoutSession: {
            id: 'cs_pricing_checkout_test',
            url: `${consoleOrigin}/dashboard/billing?checkout=success`,
            customerRef: 'cus_pricing_checkout_test',
            expiresAt: new Date('2026-03-01T01:00:00.000Z').toISOString(),
          },
        }),
      });
    });

    await page.goto('/pricing');
    await page
      .locator('.pricing-hero-actions .pricing-button--solid')
      .click();

    await expect.poll(() => checkoutBodies.length).toBe(1);
    expect(String(checkoutBodies[0]?.successUrl || '')).toContain('/dashboard/billing?checkout=success');
    expect(String(checkoutBodies[0]?.cancelUrl || '')).toContain('/pricing?checkout=cancel');
    expect(String(checkoutBodies[0]?.planId || '')).toBe('pro_maw_v1');

    await expect(page).toHaveURL(/\/dashboard\/billing\?checkout=success/);
  });
});

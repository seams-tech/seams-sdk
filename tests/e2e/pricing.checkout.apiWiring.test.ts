import { expect, test } from '@playwright/test';

test.describe('pricing onboarding CTA wiring', () => {
  test('hero Get started CTA opens dashboard auth modal and does not call Stripe checkout', async ({
    page,
    baseURL,
  }) => {
    const consoleOrigin = new URL(String(baseURL || 'http://127.0.0.1:3600')).origin;
    let stripeCheckoutCalls = 0;

    await page.route(`${consoleOrigin}/console/billing/stripe/checkout-session`, async (route) => {
      stripeCheckoutCalls += 1;
      await route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({ ok: false, code: 'unexpected_checkout_call' }),
      });
    });

    await page.goto('/pricing');
    const heroCta = page.locator('.pricing-hero-actions .pricing-button--solid');
    await expect(heroCta).toHaveText('Get started');
    await heroCta.click();

    await expect(page.locator('#navbar-dashboard-auth-title')).toHaveText(
      /Sign In To Open Dashboard/i,
    );
    await expect.poll(() => stripeCheckoutCalls).toBe(0);
    await expect.poll(() => new URL(page.url()).pathname).toBe('/pricing');
  });

  test('self-serve card CTA is labeled Get started', async ({ page }) => {
    await page.goto('/pricing');
    await expect(page.locator('.pricing-card--self-serve .pricing-button--solid')).toHaveText(
      'Get started',
    );
  });
});

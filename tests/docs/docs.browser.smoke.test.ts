import { expect, test, type Page } from '@playwright/test';

function readHorizontalMetrics(): { viewportWidth: number; documentWidth: number } {
  return {
    viewportWidth: window.innerWidth,
    documentWidth: document.documentElement.scrollWidth,
  };
}

function readDocsAppearance(): { colorScheme: string; canvas: string; hasDarkClass: boolean } {
  const styles = getComputedStyle(document.documentElement);
  return {
    colorScheme: styles.colorScheme,
    canvas: styles.getPropertyValue('--vp-c-bg').trim(),
    hasDarkClass: document.documentElement.classList.contains('dark'),
  };
}

async function assertNoHorizontalOverflow(page: Page): Promise<void> {
  const metrics = await page.evaluate(readHorizontalMetrics);

  expect(metrics.documentWidth).toBeLessThanOrEqual(metrics.viewportWidth);
}

test('docs onboarding, examples, search, appearance, and responsive navigation stay operable', async ({
  page,
}) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Start here', level: 1 })).toBeVisible();
  await expect(
    page.getByRole('navigation', { name: 'Sidebar Navigation' }).getByText('Installation'),
  ).toBeVisible();

  await page
    .getByRole('navigation', { name: 'Sidebar Navigation' })
    .getByRole('link', { name: 'Create a wallet' })
    .click();
  await expect(page).toHaveURL(/\/getting-started\/create-wallet$/);
  await expect(page.getByRole('heading', { name: 'Create a wallet', level: 1 })).toBeVisible();

  const sidebar = page.getByRole('navigation', { name: 'Sidebar Navigation' });
  // Top-level sections render expanded; only the nested groups toggle.
  await sidebar.getByRole('button', { name: 'Examples' }).click();
  await sidebar.locator('a[href="/examples/"]').click();
  await expect(page).toHaveURL(/\/examples\/$/);
  await expect(page.getByRole('heading', { name: 'Examples', level: 1 })).toBeVisible();
  await expect(page.locator('.vp-doc div[class*="language-"]').first()).toBeVisible();

  await sidebar.locator('a[href="/reference/"]').click();
  await expect(page).toHaveURL(/\/reference\/$/);
  await expect(page.getByRole('heading', { name: 'SDK reference', level: 1 })).toBeVisible();

  // The nav bar is gone: brand, search, and appearance switch live in the sidebar.
  await expect(page.locator('.VPNav')).toBeHidden();
  await expect(sidebar.getByRole('button', { name: 'Search' })).toBeVisible();

  await page.getByRole('button', { name: 'Search' }).click();
  await page.getByPlaceholder('Search').fill('wallet sessions');
  await page
    .locator('#localsearch-list')
    .locator('a[href="/concepts/sessions/wallet-sessions#wallet-sessions"]')
    .click();
  await expect(page).toHaveURL(/\/concepts\/sessions\/wallet-sessions#wallet-sessions$/);

  await page.goto('/');
  const appearanceSwitch = page
    .locator('.VPSidebar')
    .getByRole('switch', { name: /appearance|theme/i });
  await expect(appearanceSwitch).toBeVisible();
  await expect
    .poll(async () => page.evaluate(readDocsAppearance))
    .toEqual({
      colorScheme: 'light',
      canvas: '#ffffff',
      hasDarkClass: false,
    });

  await appearanceSwitch.click();
  await expect
    .poll(async () => page.evaluate(readDocsAppearance))
    .toEqual({
      colorScheme: 'dark',
      canvas: '#121110',
      hasDarkClass: true,
    });

  await appearanceSwitch.click();
  await expect
    .poll(async () => page.evaluate(readDocsAppearance))
    .toEqual({
      colorScheme: 'light',
      canvas: '#ffffff',
      hasDarkClass: false,
    });

  for (const viewport of [
    { width: 390, height: 844 },
    { width: 320, height: 800 },
    { width: 768, height: 1000 },
  ]) {
    await page.setViewportSize(viewport);
    await page.goto('/');
    await assertNoHorizontalOverflow(page);
  }

  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/');
  // Without a nav bar, the local-nav menu button is the only sidebar handle.
  await page.getByRole('button', { name: /menu/i }).first().click();
  await expect(page.locator('.VPSidebar.open')).toBeVisible();
  await expect(
    page.locator('.VPSidebar').getByRole('link', { name: 'Create a wallet', exact: true }),
  ).toBeVisible();
});

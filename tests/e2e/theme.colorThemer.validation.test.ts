import { expect, test, type Page } from '@playwright/test';

type RouteSpec = {
  path: string;
  readySelector: string;
};

type PaperThemeState = {
  dataTheme: string | null;
  bodyTheme: string | null;
  hasDarkClass: boolean;
  canvas: string;
  text: string;
  surfaceMuted: string;
};

const ROUTES: RouteSpec[] = [
  { path: '/', readySelector: '#h2-home-title' },
  { path: '/pricing', readySelector: '#pricing-page-title' },
  { path: '/company', readySelector: '#company-page-title' },
  { path: '/contact', readySelector: '#contact-page-title' },
  { path: '/wallet', readySelector: '#h2-hero-title' },
];

function readPaperThemeState(): PaperThemeState {
  const root = document.documentElement;
  const styles = getComputedStyle(root);
  return {
    dataTheme: root.getAttribute('data-w3a-theme'),
    bodyTheme: document.body.getAttribute('data-w3a-theme'),
    hasDarkClass: root.classList.contains('dark'),
    canvas: styles.getPropertyValue('--site-canvas').trim(),
    text: styles.getPropertyValue('--site-text-primary').trim(),
    surfaceMuted: styles.getPropertyValue('--site-surface-muted').trim(),
  };
}

function readFocusedControlStyle(): { outlineStyle: string; outlineWidth: string } {
  const focused = document.activeElement;
  if (!(focused instanceof HTMLElement)) {
    return { outlineStyle: 'none', outlineWidth: '0px' };
  }
  const styles = getComputedStyle(focused);
  return { outlineStyle: styles.outlineStyle, outlineWidth: styles.outlineWidth };
}

async function navigateViaSpa(page: Page, path: string): Promise<void> {
  await page.evaluate((nextPath: string) => {
    window.history.pushState({}, '', nextPath);
    window.dispatchEvent(new CustomEvent('site:navigate'));
  }, path);
}

async function expectPaperTheme(page: Page): Promise<void> {
  await expect
    .poll(async () => page.evaluate(readPaperThemeState))
    .toEqual({
      dataTheme: 'light',
      bodyTheme: 'light',
      hasDarkClass: false,
      canvas: '#ffffff',
      text: '#000000',
      surfaceMuted: '#f5f3f1',
    });
}

test.describe('Paper theme', () => {
  test('stays light across site routes with no appearance toggle', async ({ page }) => {
    await page.goto('/', { waitUntil: 'domcontentloaded' });

    for (const route of ROUTES) {
      await navigateViaSpa(page, route.path);
      await expect(page.locator(route.readySelector)).toBeVisible();
      await expectPaperTheme(page);
      await expect(page.getByRole('button', { name: /toggle (dark|light) mode/i })).toHaveCount(0);
    }

    await page.reload({ waitUntil: 'domcontentloaded' });
    await expectPaperTheme(page);
  });

  test('keeps a visible keyboard focus indicator', async ({ page }) => {
    await page.goto('/contact', { waitUntil: 'domcontentloaded' });
    await expect(page.locator('#contact-page-title')).toBeVisible();

    await page.getByRole('textbox', { name: 'Name' }).press('Tab');
    const focusStyle = await page.evaluate(readFocusedControlStyle);
    expect(focusStyle.outlineStyle).not.toBe('none');
    expect(Number.parseFloat(focusStyle.outlineWidth)).toBeGreaterThanOrEqual(2);
  });
});

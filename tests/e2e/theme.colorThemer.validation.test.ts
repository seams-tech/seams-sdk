import { createHash } from 'node:crypto';
import { expect, test, type Page, type TestInfo } from '@playwright/test';

type ThemeMode = 'light' | 'dark';

type RouteSpec = {
  id: string;
  path: string;
  waitFor: (page: Page) => Promise<void>;
};

const ROUTES: RouteSpec[] = [
  {
    id: 'home',
    path: '/',
    waitFor: async (page: Page) => {
      await expect(page.locator('#hero-title')).toBeVisible();
    },
  },
  {
    id: 'pricing',
    path: '/pricing',
    waitFor: async (page: Page) => {
      await expect(page.locator('#pricing-page-title')).toBeVisible();
    },
  },
  {
    id: 'company',
    path: '/company',
    waitFor: async (page: Page) => {
      await expect(page.locator('#site-page-title')).toHaveText(/company/i);
    },
  },
  {
    id: 'contact',
    path: '/contact',
    waitFor: async (page: Page) => {
      await expect(page.locator('#contact-page-title')).toBeVisible();
      await expect(page.locator('.contact-form')).toBeVisible();
    },
  },
  {
    id: 'dashboard',
    path: '/dashboard/wallets-list',
    waitFor: async (page: Page) => {
      await expect(page.locator('main[aria-label="Dashboard workspace"]')).toBeVisible();
      await expect(page.locator('#dashboard-main-title')).toBeVisible();
    },
  },
];

async function waitForRoute(page: Page, route: RouteSpec): Promise<void> {
  await route.waitFor(page);
  await page.waitForLoadState('networkidle');
}

async function navigateViaSpa(page: Page, path: string): Promise<void> {
  await page.evaluate((nextPath: string) => {
    if (window.location.pathname === nextPath) {
      window.dispatchEvent(new CustomEvent('site:navigate'));
      return;
    }
    window.history.pushState({}, '', nextPath);
    window.dispatchEvent(new CustomEvent('site:navigate'));
  }, path);
}

async function readDocumentTheme(page: Page): Promise<ThemeMode> {
  return await page.evaluate(() => {
    const attr = document.documentElement.getAttribute('data-w3a-theme');
    if (attr === 'light' || attr === 'dark') return attr;
    return document.documentElement.classList.contains('dark') ? 'dark' : 'light';
  });
}

async function expectTheme(page: Page, theme: ThemeMode): Promise<void> {
  await expect.poll(async () => await readDocumentTheme(page)).toBe(theme);
}

async function readStoredTheme(page: Page, key: string): Promise<string | null> {
  return await page.evaluate((storageKey: string) => {
    try {
      return window.localStorage.getItem(storageKey);
    } catch {
      return null;
    }
  }, key);
}

async function expectStoredTheme(page: Page, theme: ThemeMode): Promise<void> {
  await expect
    .poll(async () => {
      return await readStoredTheme(page, 'tatchi-site-theme');
    })
    .toBe(theme);
}

async function setTheme(page: Page, target: ThemeMode): Promise<void> {
  const current = await readDocumentTheme(page);
  if (current === target) {
    await expectStoredTheme(page, target);
    return;
  }

  const toggle = page.getByRole('button', { name: 'Toggle dark mode' }).first();
  const hasToggle = (await toggle.count()) > 0;

  if (hasToggle && (await toggle.isVisible())) {
    await toggle.click();
    await expectTheme(page, target);
    await expectStoredTheme(page, target);
    return;
  }

  await page.evaluate((next: ThemeMode) => {
    document.documentElement.classList.toggle('dark', next === 'dark');
    document.documentElement.setAttribute('data-w3a-theme', next);
    try {
      window.localStorage.setItem('tatchi-site-theme', next);
    } catch {}
    window.dispatchEvent(new CustomEvent('w3a:appearance', { detail: next }));
  }, target);

  await expectTheme(page, target);
  await expectStoredTheme(page, target);
}

async function captureRouteScreenshot(
  page: Page,
  testInfo: TestInfo,
  theme: ThemeMode,
  routeId: string,
): Promise<string> {
  const path = testInfo.outputPath(`color-themer-${theme}-${routeId}.png`);
  const bytes = await page.screenshot({
    path,
    fullPage: true,
    animations: 'disabled',
  });
  await testInfo.attach(`color-themer-${theme}-${routeId}`, {
    path,
    contentType: 'image/png',
  });
  return createHash('sha256').update(bytes).digest('hex');
}

async function captureThemeState(
  page: Page,
  testInfo: TestInfo,
  theme: ThemeMode,
): Promise<Record<string, string>> {
  const hashes: Record<string, string> = {};

  for (const route of ROUTES) {
    await navigateViaSpa(page, route.path);
    await waitForRoute(page, route);
    await expectTheme(page, theme);
    await expectStoredTheme(page, theme);
    hashes[route.id] = await captureRouteScreenshot(page, testInfo, theme, route.id);
  }

  return hashes;
}

type FocusStyles = {
  outlineStyle: string;
  outlineWidth: string;
  boxShadow: string;
};

function hasVisibleFocusIndicator(styles: FocusStyles): boolean {
  const outlinePx = Number.parseFloat(styles.outlineWidth || '0');
  const hasOutline = styles.outlineStyle !== 'none' && Number.isFinite(outlinePx) && outlinePx > 0;
  const hasBoxShadow = styles.boxShadow !== 'none';
  return hasOutline || hasBoxShadow;
}

async function focusViaTab(page: Page, selector: string, maxTabs: number = 160): Promise<void> {
  await page.mouse.click(1, 1);

  for (let i = 0; i < maxTabs; i += 1) {
    await page.keyboard.press('Tab');
    const focused = await page.evaluate((sel: string) => {
      const el = document.querySelector(sel);
      return !!el && document.activeElement === el && el.matches(':focus-visible');
    }, selector);

    if (focused) return;
  }

  throw new Error(`Unable to focus selector via keyboard: ${selector}`);
}

async function readFocusStyles(page: Page, selector: string): Promise<FocusStyles> {
  return await page.evaluate((sel: string) => {
    const el = document.querySelector(sel);
    if (!el) throw new Error(`Missing selector: ${sel}`);
    const styles = getComputedStyle(el as Element);
    return {
      outlineStyle: styles.outlineStyle,
      outlineWidth: styles.outlineWidth,
      boxShadow: styles.boxShadow,
    };
  }, selector);
}

type ContrastSample = {
  ratio: number;
  foreground: string;
  background: string;
};

async function measureCssVarContrast(
  page: Page,
  foregroundVar: string,
  backgroundVar: string,
): Promise<ContrastSample> {
  return await page.evaluate(
    ({ foregroundVar, backgroundVar }) => {
      type Parsed = { r: number; g: number; b: number; a: number };

      function parseColor(input: string): Parsed {
        const canvas = document.createElement('canvas');
        canvas.width = 1;
        canvas.height = 1;
        const ctx = canvas.getContext('2d');
        if (!ctx) throw new Error('2d canvas context unavailable');
        ctx.clearRect(0, 0, 1, 1);
        ctx.fillStyle = input;
        ctx.fillRect(0, 0, 1, 1);
        const data = ctx.getImageData(0, 0, 1, 1).data;
        return {
          r: data[0] ?? 0,
          g: data[1] ?? 0,
          b: data[2] ?? 0,
          a: (data[3] ?? 255) / 255,
        };
      }

      function flatten(top: Parsed, bottom: Parsed): Parsed {
        const alpha = top.a + bottom.a * (1 - top.a);
        if (alpha <= 0) return { r: 0, g: 0, b: 0, a: 0 };
        return {
          r: (top.r * top.a + bottom.r * bottom.a * (1 - top.a)) / alpha,
          g: (top.g * top.a + bottom.g * bottom.a * (1 - top.a)) / alpha,
          b: (top.b * top.a + bottom.b * bottom.a * (1 - top.a)) / alpha,
          a: alpha,
        };
      }

      function channelToLinear(channel: number): number {
        const c = channel / 255;
        return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
      }

      function luminance(color: Parsed): number {
        return (
          0.2126 * channelToLinear(color.r) +
          0.7152 * channelToLinear(color.g) +
          0.0722 * channelToLinear(color.b)
        );
      }

      function contrastRatio(foreground: Parsed, background: Parsed): number {
        const white: Parsed = { r: 255, g: 255, b: 255, a: 1 };
        const resolvedBackground = background.a < 1 ? flatten(background, white) : background;
        const resolvedForeground =
          foreground.a < 1 ? flatten(foreground, resolvedBackground) : foreground;
        const l1 = luminance(resolvedForeground);
        const l2 = luminance(resolvedBackground);
        const brighter = Math.max(l1, l2);
        const darker = Math.min(l1, l2);
        return Number(((brighter + 0.05) / (darker + 0.05)).toFixed(2));
      }

      const scope =
        document.querySelector('.w3a-theme-provider[data-w3a-theme]') ||
        document.querySelector('.w3a-theme-provider') ||
        document.querySelector('[data-w3a-theme]') ||
        document.documentElement;
      const rootStyles = getComputedStyle(scope);
      const foregroundRaw = rootStyles.getPropertyValue(foregroundVar).trim();
      const backgroundRaw = rootStyles.getPropertyValue(backgroundVar).trim();
      if (!foregroundRaw || !backgroundRaw) {
        throw new Error(
          `Missing CSS vars: ${foregroundVar}=${foregroundRaw}, ${backgroundVar}=${backgroundRaw}`,
        );
      }

      const foreground = parseColor(foregroundRaw);
      const background = parseColor(backgroundRaw);
      return {
        ratio: contrastRatio(foreground, background),
        foreground: foregroundRaw,
        background: backgroundRaw,
      };
    },
    { foregroundVar, backgroundVar },
  );
}

async function measureElementContrast(page: Page, selector: string): Promise<ContrastSample> {
  return await page.evaluate((sel: string) => {
    type Parsed = { r: number; g: number; b: number; a: number };

    function parseColor(input: string): Parsed {
      const canvas = document.createElement('canvas');
      canvas.width = 1;
      canvas.height = 1;
      const ctx = canvas.getContext('2d');
      if (!ctx) throw new Error('2d canvas context unavailable');
      ctx.clearRect(0, 0, 1, 1);
      ctx.fillStyle = input;
      ctx.fillRect(0, 0, 1, 1);
      const data = ctx.getImageData(0, 0, 1, 1).data;
      return {
        r: data[0] ?? 0,
        g: data[1] ?? 0,
        b: data[2] ?? 0,
        a: (data[3] ?? 255) / 255,
      };
    }

    function flatten(top: Parsed, bottom: Parsed): Parsed {
      const alpha = top.a + bottom.a * (1 - top.a);
      if (alpha <= 0) return { r: 0, g: 0, b: 0, a: 0 };
      return {
        r: (top.r * top.a + bottom.r * bottom.a * (1 - top.a)) / alpha,
        g: (top.g * top.a + bottom.g * bottom.a * (1 - top.a)) / alpha,
        b: (top.b * top.a + bottom.b * bottom.a * (1 - top.a)) / alpha,
        a: alpha,
      };
    }

    function channelToLinear(channel: number): number {
      const c = channel / 255;
      return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
    }

    function luminance(color: Parsed): number {
      return (
        0.2126 * channelToLinear(color.r) +
        0.7152 * channelToLinear(color.g) +
        0.0722 * channelToLinear(color.b)
      );
    }

    function contrastRatio(foreground: Parsed, background: Parsed): number {
      const white: Parsed = { r: 255, g: 255, b: 255, a: 1 };
      const resolvedBackground = background.a < 1 ? flatten(background, white) : background;
      const resolvedForeground =
        foreground.a < 1 ? flatten(foreground, resolvedBackground) : foreground;
      const l1 = luminance(resolvedForeground);
      const l2 = luminance(resolvedBackground);
      const brighter = Math.max(l1, l2);
      const darker = Math.min(l1, l2);
      return Number(((brighter + 0.05) / (darker + 0.05)).toFixed(2));
    }

    function resolveElementBackground(element: Element): string {
      let node: Element | null = element;
      while (node) {
        const bg = getComputedStyle(node).backgroundColor;
        const parsed = parseColor(bg);
        if (parsed.a > 0) return bg;
        node = node.parentElement;
      }
      const rootStyles = getComputedStyle(document.documentElement);
      return rootStyles.getPropertyValue('--site-canvas').trim() || 'rgb(255, 255, 255)';
    }

    const element = document.querySelector(sel);
    if (!element) throw new Error(`Missing selector: ${sel}`);

    const styles = getComputedStyle(element);
    const foregroundRaw = styles.color;
    const backgroundRaw = resolveElementBackground(element);
    const foreground = parseColor(foregroundRaw);
    const background = parseColor(backgroundRaw);

    return {
      ratio: contrastRatio(foreground, background),
      foreground: foregroundRaw,
      background: backgroundRaw,
    };
  }, selector);
}

test.describe('color-themer phase 5 validation', () => {
  test('theme toggle and persistence across route transitions with screenshot capture', async ({
    page,
  }, testInfo) => {
    await page.goto('/', { waitUntil: 'domcontentloaded' });
    await waitForRoute(page, ROUTES[0]!);
    await page.emulateMedia({ reducedMotion: 'reduce' });

    await setTheme(page, 'dark');
    const darkHashes = await captureThemeState(page, testInfo, 'dark');

    await navigateViaSpa(page, '/');
    await waitForRoute(page, ROUTES[0]!);
    await setTheme(page, 'light');
    const lightHashes = await captureThemeState(page, testInfo, 'light');

    for (const route of ROUTES) {
      expect(lightHashes[route.id], `light screenshot hash missing for ${route.id}`).toBeTruthy();
      expect(darkHashes[route.id], `dark screenshot hash missing for ${route.id}`).toBeTruthy();
      expect(lightHashes[route.id]).not.toBe(darkHashes[route.id]);
    }

    await navigateViaSpa(page, '/');
    await waitForRoute(page, ROUTES[0]!);
    await expectTheme(page, 'light');
    await expectStoredTheme(page, 'light');

    await page.reload({ waitUntil: 'domcontentloaded' });
    await waitForRoute(page, ROUTES[0]!);
    await expectTheme(page, 'light');
    await expectStoredTheme(page, 'light');
  });

  test('contrast and focus indicators remain accessible in light and dark themes', async ({
    page,
  }) => {
    await page.goto('/', { waitUntil: 'domcontentloaded' });
    await waitForRoute(page, ROUTES[0]!);
    await page.emulateMedia({ reducedMotion: 'reduce' });

    for (const theme of ['dark', 'light'] as const) {
      await navigateViaSpa(page, '/');
      await waitForRoute(page, ROUTES[0]!);
      await setTheme(page, theme);

      const textPrimary = await measureCssVarContrast(page, '--site-text-primary', '--site-canvas');
      expect(
        textPrimary.ratio,
        `${theme} text-primary/canvas contrast (${textPrimary.foreground} on ${textPrimary.background})`,
      ).toBeGreaterThanOrEqual(4.5);

      const textSecondary = await measureCssVarContrast(
        page,
        '--site-text-secondary',
        '--site-canvas',
      );
      expect(
        textSecondary.ratio,
        `${theme} text-secondary/canvas contrast (${textSecondary.foreground} on ${textSecondary.background})`,
      ).toBeGreaterThanOrEqual(3.0);

      const textButton = await measureCssVarContrast(page, '--site-text-button', '--site-brand');
      expect(
        textButton.ratio,
        `${theme} text-button/brand contrast (${textButton.foreground} on ${textButton.background})`,
      ).toBeGreaterThanOrEqual(4.5);

      await navigateViaSpa(page, '/pricing');
      await waitForRoute(page, ROUTES[1]!);
      const pricingButtonContrast = await measureElementContrast(page, '.pricing-button--solid');
      expect(
        pricingButtonContrast.ratio,
        `${theme} pricing button contrast (${pricingButtonContrast.foreground} on ${pricingButtonContrast.background})`,
      ).toBeGreaterThanOrEqual(4.5);

      await navigateViaSpa(page, '/contact');
      await waitForRoute(page, ROUTES[3]!);
      const contactInputContrast = await measureElementContrast(
        page,
        '.contact-form input[name="firstName"]',
      );
      expect(
        contactInputContrast.ratio,
        `${theme} contact input contrast (${contactInputContrast.foreground} on ${contactInputContrast.background})`,
      ).toBeGreaterThanOrEqual(4.5);

      await navigateViaSpa(page, '/');
      await waitForRoute(page, ROUTES[0]!);
      await focusViaTab(page, '.navbar-static__theme-toggle');
      const navbarFocus = await readFocusStyles(page, '.navbar-static__theme-toggle');
      expect(hasVisibleFocusIndicator(navbarFocus)).toBeTruthy();

      await navigateViaSpa(page, '/contact');
      await waitForRoute(page, ROUTES[3]!);
      await focusViaTab(page, '.contact-form input[name="firstName"]');
      const contactFocus = await readFocusStyles(page, '.contact-form input[name="firstName"]');
      expect(hasVisibleFocusIndicator(contactFocus)).toBeTruthy();
    }
  });
});

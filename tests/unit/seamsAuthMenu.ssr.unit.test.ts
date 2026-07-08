import { test, expect } from '@playwright/test';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import url from 'node:url';

test.describe('SSR sanity: SeamsAuthMenuSkeleton', () => {
  test('imports public subpath and renders without window', async () => {
    const here = path.dirname(url.fileURLToPath(import.meta.url));
    const packageJsonPath = path.resolve(here, '../../packages/sdk-web/package.json');
    const packageRequire = createRequire(packageJsonPath);
    const React = packageRequire('react');
    const { renderToString } = packageRequire('react-dom/server');
    const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
    const exportTarget =
      packageJson.exports?.['./react/seams-auth-menu']?.import ||
      packageJson.exports?.['./react/seams-auth-menu']?.default;
    expect(exportTarget).toBe('./dist/esm/react/components/SeamsAuthMenu/public.js');

    const distMarkerCandidates = [path.resolve(path.dirname(packageJsonPath), exportTarget)];
    test.skip(
      distMarkerCandidates.every((p) => !fs.existsSync(p)),
      `SDK dist not found at ${distMarkerCandidates[0]}; run pnpm -C packages/sdk-web build:rolldown`,
    );

    expect(typeof (globalThis as any).window).toBe('undefined');

    const mod: any = await import(url.pathToFileURL(distMarkerCandidates[0]).href);
    expect(mod).toHaveProperty('SeamsAuthMenuSkeleton');
    expect(typeof mod.SeamsAuthMenuSkeleton).toBe('function');

    const html = renderToString(React.createElement(mod.SeamsAuthMenuSkeleton));
    expect(html).toContain('w3a-signup-menu-root');

    expect(typeof (globalThis as any).window).toBe('undefined');
  });
});

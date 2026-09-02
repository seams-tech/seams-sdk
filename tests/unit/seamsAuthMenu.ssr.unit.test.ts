import { test, expect } from '@playwright/test';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import url from 'node:url';

test.describe('SSR sanity: SeamsAuthMenu adapter', () => {
  test('imports the public subpath and renders one inert host marker', async () => {
    const here = path.dirname(url.fileURLToPath(import.meta.url));
    const packageJsonPath = path.resolve(here, '../../packages/wallet/package.json');
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
      distMarkerCandidates.every((candidate) => !fs.existsSync(candidate)),
      `SDK dist not found at ${distMarkerCandidates[0]}; run pnpm -C packages/wallet build:rolldown`,
    );

    expect(typeof (globalThis as any).window).toBe('undefined');

    const mod: any = await import(url.pathToFileURL(distMarkerCandidates[0]).href);
    expect(mod).toHaveProperty('SeamsAuthMenu');
    expect(typeof mod.SeamsAuthMenu).toBe('function');
    expect(mod).not.toHaveProperty('SeamsAuthMenuSkeleton');
    expect(mod).not.toHaveProperty('SeamsAuthMenuClient');

    const html = renderToString(
      React.createElement(mod.SeamsAuthMenu, { onOutcome: () => undefined }),
    );
    expect(html).toContain('data-seams-auth-menu-host="true"');
    expect(html).not.toContain('<button');
    expect(html).not.toContain('w3a-signup-menu-root');

    expect(typeof (globalThis as any).window).toBe('undefined');
  });
});

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

function collectSourceFiles(rootDir: string): string[] {
  const out: string[] = [];
  const stack = [rootDir];
  while (stack.length > 0) {
    const current = stack.pop()!;
    const entries = fs.readdirSync(current, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(fullPath);
        continue;
      }
      if (!entry.isFile()) continue;
      if (!/\.(ts|tsx|js|mjs)$/.test(entry.name)) continue;
      out.push(fullPath);
    }
  }
  return out;
}

test.describe('key export legacy-surface guard', () => {
  test('forbids removed export APIs/protocol messages in SDK + tests', () => {
    const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
    const thisFile = path.resolve(fileURLToPath(import.meta.url));
    const scanRoots = [
      path.join(repoRoot, 'client/src'),
      path.join(repoRoot, 'tests'),
    ];

    const forbiddenNeedles = [
      ['exportNear', 'KeypairWithUI'].join(''),
      ['PM_EXPORT_NEAR', '_KEYPAIR_UI'].join(''),
      ['PM_EXPORT', '_KEYS_UI'].join(''),
    ];

    const violations: string[] = [];
    for (const root of scanRoots) {
      const files = collectSourceFiles(root);
      for (const file of files) {
        if (path.resolve(file) === thisFile) continue;
        const content = fs.readFileSync(file, 'utf8');
        for (const needle of forbiddenNeedles) {
          if (!content.includes(needle)) continue;
          violations.push(`${needle}: ${path.relative(repoRoot, file)}`);
        }
      }
    }

    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('account menu export action uses canonical chain-scoped API', () => {
    const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
    const accountMenuPath = path.join(
      repoRoot,
      'client/src/react/components/AccountMenuButton/index.tsx',
    );
    const content = fs.readFileSync(accountMenuPath, 'utf8');
    expect(content.includes('.keys.exportKeypairWithUI(')).toBe(true);
    expect(content.includes("chain: 'near'")).toBe(true);
  });
});

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

function repoRoot(): string {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
}

function collectSourceFiles(rootDir: string): string[] {
  if (!fs.existsSync(rootDir)) return [];
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
  return out.sort();
}

function literal(parts: string[]): string {
  return parts.join('');
}

test.describe('signing-session sealed-refresh legacy-surface guard', () => {
  test('forbids PRF-specific sealed-refresh files and route paths after the generic rename', () => {
    const root = repoRoot();
    const forbiddenPaths = [
      'client/src/core/signingEngine/api/session/prfSessionSealedStore.ts',
      'server/src/threshold/session/prfSessionSeal',
    ];

    const violations = forbiddenPaths
      .filter((relativePath) => fs.existsSync(path.join(root, relativePath)))
      .map((relativePath) => `legacy path remains: ${relativePath}`);

    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('forbids PRF-specific sealed-refresh API names in generic session boundaries', () => {
    const root = repoRoot();
    const scanRoots = [
      'client/src/core/signingEngine/api/session',
      'client/src/core/signingEngine/touchConfirm',
      'client/src/core/types',
      'client/src/core/WalletIframe',
      'client/src/core/rpcClients/relayer',
      'server/src/router',
      'server/src/threshold/session',
    ].map((relativePath) => path.join(root, relativePath));
    const forbiddenNeedles = [
      literal(['prf', 'SessionSealedStore']),
      literal(['Prf', 'SessionSealedStore']),
      literal(['sealed', 'PrfFirstB64u']),
      literal(['sealed', 'PRF.first']),
      literal(['PRF', ' session seal']),
      literal(['prf', 'SessionSeal']),
      literal(['Prf', 'SessionSeal']),
      literal(['/threshold-ecdsa/', 'prf-seal']),
      literal(['threshold-', 'prf-sealed']),
    ];

    const violations: string[] = [];
    for (const file of scanRoots.flatMap(collectSourceFiles)) {
      const relativePath = path.relative(root, file);
      const content = fs.readFileSync(file, 'utf8');
      for (const needle of forbiddenNeedles) {
        if (!content.includes(needle)) continue;
        violations.push(`${needle}: ${relativePath}`);
      }
    }

    expect(violations, violations.join('\n')).toEqual([]);
  });
});

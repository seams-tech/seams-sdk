import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { expect, test } from '@playwright/test';

const REPO_ROOT = path.resolve(process.cwd(), '..');
const REGISTRATION_BUTTON_ROOT =
  'packages/sdk-web/src/core/signingEngine/uiConfirm/ui/lit-components/passkey-registration-btn';

function listTypeScriptFiles(relativeRoot: string): string[] {
  const absoluteRoot = path.join(REPO_ROOT, relativeRoot);
  return readdirSync(absoluteRoot).flatMap((entry) => {
    const relativePath = path.join(relativeRoot, entry);
    const absolutePath = path.join(REPO_ROOT, relativePath);
    const stat = statSync(absolutePath);
    if (stat.isDirectory()) return listTypeScriptFiles(relativePath);
    return /\.(ts|tsx)$/.test(entry) ? [relativePath] : [];
  });
}

function readSource(relativePath: string): string {
  return readFileSync(path.join(REPO_ROOT, relativePath), 'utf8');
}

function importSpecifiers(source: string): string[] {
  const specifiers: string[] = [];
  const importPattern =
    /import\s+(?:type\s+)?(?:[^'"]+\s+from\s+)?['"]([^'"]+)['"]|import\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
  for (const match of source.matchAll(importPattern)) {
    const specifier = match[1] || match[2];
    if (specifier) specifiers.push(specifier);
  }
  return specifiers;
}

test.describe('refactor 8X registration button source guards', () => {
  test('seams-passkey-registration-btn stays independent from tx-confirm, export, modal, drawer, and React surfaces', () => {
    const forbiddenImport = /(?:IframeTxConfirmer|TxTree|tx-confirmer|tx-confirm|export-key|export-private-key|ExportKey|viewer-modal|viewer-drawer|Drawer|Modal|\/react\b|@\/react\b|PasskeyAuthMenu)/;
    const offenders = listTypeScriptFiles(REGISTRATION_BUTTON_ROOT).flatMap((relativePath) => {
      const specifiers = importSpecifiers(readSource(relativePath));
      return specifiers
        .filter((specifier) => forbiddenImport.test(specifier))
        .map((specifier) => ({ relativePath, specifier }));
    });

    expect(offenders).toEqual([]);
  });
});

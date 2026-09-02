import { expect, test } from '@playwright/test';
import fs from 'fs';
import path from 'path';

/**
 * Components that render into a MEASURED surface hold their first paint until
 * their stylesheet is adopted, so a sheet the wallet document does not carry
 * is fetched on demand: the host is measured empty, the parent reveals a small
 * box, and it jumps to the real size when the sheet lands. The cost is paid
 * once per browser cache, which is what makes it easy to miss — key export
 * shipped that way.
 *
 * Read from source rather than importing the plugin: this asserts a property
 * of the document every wallet origin serves, not of one bundle.
 */
const repoRoot = process.env.W3A_REPO_ROOT ?? path.resolve(process.cwd(), '..');
const walletSrc = path.join(repoRoot, 'packages/wallet/src');

/** Marker attribute -> the component that blocks its first paint on it. */
const GATED_STYLESHEETS: ReadonlyArray<readonly [string, string]> = [
  ['data-w3a-components-css', 'shared component tokens'],
  ['data-w3a-recovery-code-backup-css', 'RecoveryCodeBackup/viewer.ts'],
  ['data-w3a-copy-icon-css', 'ExportPrivateKey/viewer.ts'],
  ['data-w3a-export-viewer-css', 'ExportPrivateKey/viewer.ts'],
  ['data-w3a-export-iframe-css', 'ExportPrivateKey/iframe-host.ts'],
];

test('the wallet document carries every stylesheet a measured surface waits for', () => {
  const template = fs.readFileSync(path.join(walletSrc, 'plugins/plugin-utils.ts'), 'utf8');
  const head = template.slice(template.indexOf('<!doctype html>'), template.indexOf('</head>'));
  const missing = GATED_STYLESHEETS.filter(([marker]) => !head.includes(marker)).map(
    ([marker, owner]) => `${marker} (${owner})`,
  );
  expect(missing).toEqual([]);
});

test('every stylesheet the document claims to carry is built into the public SDK', () => {
  const template = fs.readFileSync(path.join(walletSrc, 'plugins/plugin-utils.ts'), 'utf8');
  const referenced = Array.from(template.matchAll(/\$\{sdkBasePath\}\/([\w.-]+\.css)/g)).map(
    (match) => match[1],
  );
  expect(referenced.length).toBeGreaterThan(0);
  const publicRoot = path.join(repoRoot, 'packages/wallet/dist/public/sdk');
  const missing = referenced.filter((name) => !fs.existsSync(path.join(publicRoot, name)));
  expect(missing).toEqual([]);
});

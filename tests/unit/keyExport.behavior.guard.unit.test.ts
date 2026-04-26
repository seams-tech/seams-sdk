import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

test.describe('key export behavior guard', () => {
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

  test('account menu does not block Email OTP accounts from opening export drawer', () => {
    const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
    const accountMenuPath = path.join(
      repoRoot,
      'client/src/react/components/AccountMenuButton/index.tsx',
    );
    const modalPath = path.join(
      repoRoot,
      'client/src/react/components/AccountMenuButton/ExportKeyTypeModal.tsx',
    );
    const accountMenu = fs.readFileSync(accountMenuPath, 'utf8');
    const modal = fs.readFileSync(modalPath, 'utf8');

    expect(accountMenu.includes("loginState.authMethod === 'email_otp'")).toBe(false);
    expect(accountMenu.includes('setExportRestrictionMessage(')).toBe(true);
    expect(accountMenu.includes('Key export requires a passkey-authenticated account.')).toBe(
      false,
    );
    expect(accountMenu.includes('if (exportRestrictionMessage) return;')).toBe(true);
    expect(modal.includes('restrictionMessage')).toBe(true);
    expect(modal.includes('disabled={isBusy || isRestricted}')).toBe(true);
  });

  test('account menu export modal uses the resolved portal host', () => {
    const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
    const accountMenuPath = path.join(
      repoRoot,
      'client/src/react/components/AccountMenuButton/index.tsx',
    );
    const content = fs.readFileSync(accountMenuPath, 'utf8');

    expect(content.includes('{canPortal &&')).toBe(true);
    expect(content.includes('          portalHost!,')).toBe(true);
    expect(content.includes('document.body so global modal CSS applies consistently')).toBe(false);
    expect(
      content.includes("(typeof document !== 'undefined' ? document.body : portalHost)!"),
    ).toBe(false);
  });

  test('react styles include export modal stylesheet', () => {
    const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
    const reactStylesPath = path.join(repoRoot, 'client/src/react/styles.css');
    const content = fs.readFileSync(reactStylesPath, 'utf8');

    expect(
      content.includes("@import './components/AccountMenuButton/ExportKeyTypeModal.css';"),
    ).toBe(true);
  });
});

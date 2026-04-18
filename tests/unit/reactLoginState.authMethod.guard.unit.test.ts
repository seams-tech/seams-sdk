import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

function readRepoFile(relativePath: string): string {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

test.describe('React login state auth-method guard', () => {
  test('LoginState exposes authMethod for AccountMenu and downstream UI', () => {
    const content = readRepoFile('client/src/react/types.ts');

    expect(content.includes("import type { ThemeName, WalletAuthMethod }")).toBe(true);
    expect(content.includes('authMethod?: WalletAuthMethod | null;')).toBe(true);
  });

  test('direct login refresh preserves wallet-session authMethod and clears it on logout', () => {
    const content = readRepoFile('client/src/react/context/useLoginStateRefresher.ts');

    expect(content.includes('authMethod: session.authMethod || st.authMethod || null')).toBe(true);
    expect(content.includes('authMethod: session.authMethod || ls.authMethod || null')).toBe(true);
    expect(content.includes('authMethod: null')).toBe(true);
  });

  test('wallet-iframe reconnect/login handlers preserve wallet-session authMethod', () => {
    const content = readRepoFile('client/src/react/context/useWalletIframeLifecycle.ts');

    expect(content.includes('authMethod: session.authMethod || state.authMethod || null')).toBe(
      true,
    );
    expect(content.includes('authMethod: session.authMethod || st.authMethod || null')).toBe(true);
    expect(content.includes('authMethod: null')).toBe(true);
  });

  test('explicit unlock event refresh preserves wallet-session authMethod', () => {
    const content = readRepoFile('client/src/react/context/useTatchiContextValue.ts');

    expect(content.includes('authMethod: isLoggedIn ? session.authMethod || login.authMethod || null : null')).toBe(
      true,
    );
  });
});

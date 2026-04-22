import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

function readRepoFile(relativePath: string): string {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

test.describe('Tx Confirmer auth-mode rendering guard', () => {
  test('modal renders distinct webauthn, Email OTP, and warm-session presentations', () => {
    const content = readRepoFile(
      'client/src/core/signingEngine/touchConfirm/ui/lit-components/IframeTxConfirmer/viewer-modal.ts',
    );

    expect(content.includes("this.signingAuthMode === 'emailOtp'")).toBe(true);
    expect(content.includes("this.signingAuthMode === 'warmSession'")).toBe(true);
    expect(content.includes("if (this._isEmailOtpMode()) return 'Enter email code to sign';")).toBe(
      true,
    );
    expect(content.includes("if (this._isWarmSessionMode()) return 'Review transaction';")).toBe(
      true,
    );
    expect(content.includes("this.signingAuthMode === 'webauthn' || this._isWarmSessionMode()")).toBe(
      true,
    );
    expect(content.includes('id="email-otp-confirm-code"')).toBe(true);
    expect(content.includes(".iconVariant=${this._isEmailOtpMode() ? 'mail' : 'fingerprint'}")).toBe(
      true,
    );
    expect(content.includes('w3a-passkey-halo-loading')).toBe(true);
  });

  test('drawer renders distinct webauthn, Email OTP, and warm-session presentations', () => {
    const content = readRepoFile(
      'client/src/core/signingEngine/touchConfirm/ui/lit-components/IframeTxConfirmer/viewer-drawer.ts',
    );

    expect(content.includes("this.signingAuthMode === 'emailOtp'")).toBe(true);
    expect(content.includes("this.signingAuthMode === 'warmSession'")).toBe(true);
    expect(content.includes("? 'Enter email code to sign'")).toBe(true);
    expect(content.includes("? 'Review transaction'")).toBe(true);
    expect(content.includes("this.signingAuthMode === 'webauthn' || this._isWarmSessionMode()")).toBe(
      true,
    );
    expect(content.includes('id="drawer-email-otp-confirm-code"')).toBe(true);
    expect(content.includes('<h2 class="drawer-title">${heading}</h2>')).toBe(true);
  });
});

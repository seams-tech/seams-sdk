import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function readRepoFile(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

test.describe('hosted Email OTP account ID privacy guard', () => {
  test('source code does not reintroduce email-derived Google wallet-id generation', () => {
    const guardedFiles = [
      'server/src/core/AuthService.ts',
      'server/src/core/hostedAccountIds.ts',
      'server/src/router/express/routes/sessions.ts',
      'server/src/router/cloudflare/routes/sessions.ts',
      'client/src/core/TatchiPasskey/emailOtp.ts',
      'client/src/core/TatchiPasskey/index.ts',
      'client/src/react/components/PasskeyAuthMenu/controller/usePasskeyAuthMenuController.ts',
      'examples/tatchi-site/src/flows/demo/PasskeyLoginMenu.tsx',
    ];
    const forbidden = [
      /EMAIL_OTP_GOOGLE_REGISTRATION_WALLET_ID_POLICY/,
      /timestamped_dev/,
      /forceNewDevWallet/,
      /force_new_dev_wallet/,
      /normalizeEmailWalletIdStem/,
      /buildTimestampedEmailWalletId/,
      /buildStableEmailWalletId/,
      /deriveHashedOidcWalletId/,
      /getGoogleEmailOtpRegistrationWalletIdPolicy/,
    ];

    const violations: string[] = [];
    for (const relativePath of guardedFiles) {
      const source = readRepoFile(relativePath);
      for (const pattern of forbidden) {
        if (pattern.test(source)) {
          violations.push(`legacy hosted account-id surface: ${relativePath}`);
        }
      }
    }

    expect(violations, violations.join('\n')).toEqual([]);
  });
});

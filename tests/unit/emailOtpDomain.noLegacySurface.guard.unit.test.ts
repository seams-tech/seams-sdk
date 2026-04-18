import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function readRepoFile(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function listTsFiles(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) return listTsFiles(fullPath);
    if (!entry.isFile() || !entry.name.endsWith('.ts')) return [];
    return [fullPath];
  });
}

test.describe('Email OTP domain no-legacy-surface guard', () => {
  test('shared wire values are not redeclared in parser/client/store modules', () => {
    const guardedFiles = [
      'server/src/router/emailOtpRequestValidation.ts',
      'server/src/router/express/routes/sessions.ts',
      'server/src/router/cloudflare/routes/sessions.ts',
      'server/src/core/EmailOtpStores.ts',
      'client/src/core/TatchiPasskey/emailOtp.ts',
      'client/src/core/TatchiPasskey/interfaces.ts',
      'client/src/core/TatchiPasskey/index.ts',
      'client/src/core/WalletIframe/client/router.ts',
      'client/src/core/WalletIframe/shared/messages.ts',
      'client/src/core/signingEngine/workerManager/workerTypes.ts',
      'client/src/core/signingEngine/workerManager/workers/email-otp.worker.ts',
      'client/src/core/signingEngine/SigningEngine.ts',
    ];
    const forbidden = [
      /type\s+\w*EmailOtp\w*Channel\s*=\s*['"]email_otp['"]/,
      /type\s+\w*EmailOtp\w*Operation\s*=\s*['"]wallet_unlock['"]\s*\|/,
      /operation\?:\s*['"]wallet_unlock['"]\s*\|\s*['"]transaction_sign['"]\s*\|\s*['"]export_key['"]/,
      /operation:\s*['"]export_key['"]/,
      /operation\s*===\s*['"]export_key['"]/,
      /otpChannel\??:\s*['"]email_otp['"]/,
      /otpChannel:\s*EMAIL_OTP_CHANNEL[^,;\n]/,
    ];

    const violations: string[] = [];
    for (const relativePath of guardedFiles) {
      const source = readRepoFile(relativePath);
      if (!source.includes('@shared/utils/emailOtpDomain')) {
        violations.push(`missing shared Email OTP domain import: ${relativePath}`);
      }
      for (const pattern of forbidden) {
        if (pattern.test(source)) {
          violations.push(`redeclared Email OTP wire literal: ${relativePath}`);
        }
      }
    }

    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('router boundary code uses shared validation helpers for generic claim parsing', () => {
    const guardedFiles = [
      'server/src/router/express/routes/sessions.ts',
      'server/src/router/cloudflare/routes/sessions.ts',
      'server/src/router/relayWebhooks.ts',
    ];
    const forbidden = [
      /function\s+optionalClaimString\b/,
      /function\s+toOptionalTrimmedString\b/,
      /const\s+toOptionalTrimmedString\s*=/,
    ];

    const violations: string[] = [];
    for (const relativePath of guardedFiles) {
      const source = readRepoFile(relativePath);
      if (!source.includes('@shared/utils/validation')) {
        violations.push(`missing shared validation import: ${relativePath}`);
      }
      for (const pattern of forbidden) {
        if (pattern.test(source)) {
          violations.push(`local generic validation helper: ${relativePath}`);
        }
      }
    }

    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('server router code does not redeclare generic object/string helpers', () => {
    const routerRoot = path.join(repoRoot, 'server/src/router');
    const allowedLocalHelpers = new Set([
      'server/src/router/cloudflare/http.ts',
    ]);
    const forbidden = [
      /function\s+isObject\s*\(/,
      /function\s+optionalClaimString\b/,
      /function\s+toOptionalTrimmedString\b/,
      /const\s+toOptionalTrimmedString\s*=/,
    ];

    const violations: string[] = [];
    for (const absolutePath of listTsFiles(routerRoot)) {
      const relativePath = path.relative(repoRoot, absolutePath);
      if (allowedLocalHelpers.has(relativePath)) continue;
      const source = readRepoFile(relativePath);
      for (const pattern of forbidden) {
        if (pattern.test(source)) {
          violations.push(`local generic helper: ${relativePath}`);
        }
      }
    }

    expect(violations, violations.join('\n')).toEqual([]);
  });
});

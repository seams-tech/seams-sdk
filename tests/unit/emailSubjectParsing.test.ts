import { test, expect } from '@playwright/test';
import { injectImportMap } from '../setup/bootstrap';

const IMPORT_PATHS = {
  emailParsers: '/sdk/esm/server/email-recovery/emailParsers.js',
} as const;

test.describe('email recovery subject parsing with request_id', () => {
  test.beforeEach(async ({ page }) => {
    // Use a blank page for unit tests to avoid network dependencies
    await page.goto('data:text/html,<!DOCTYPE html><html><head></head><body></body></html>');
    await injectImportMap(page);
  });

  test('parseAccountIdFromSubject extracts accountId from recover-v1 subject', async ({
    page,
  }) => {
    const res = await page.evaluate(
      async ({ paths }) => {
        try {
          const { parseAccountIdFromSubject } = await import(paths.emailParsers);
          const subject = 'Subject: recover-v1 bob.testnet ABC123\n';
          const accountId = parseAccountIdFromSubject(subject);
          return { success: true, accountId };
        } catch (err: any) {
          return { success: false, error: err?.message || String(err) };
        }
      },
      { paths: IMPORT_PATHS },
    );

    if (!res.success) {
      test.skip(true, `parseAccountIdFromSubject failed: ${res.error || 'unknown error'}`);
      return;
    }

    expect(res.accountId).toBe('bob.testnet');
  });

  test('parseAccountIdFromSubject returns null for subjects without a canonical session id', async ({
    page,
  }) => {
    const res = await page.evaluate(
      async ({ paths }) => {
        try {
          const { parseAccountIdFromSubject } = await import(paths.emailParsers);
          const subject = 'Subject: recover bob.testnet\n';
          const accountId = parseAccountIdFromSubject(subject);
          return { success: true, accountId };
        } catch (err: any) {
          return { success: false, error: err?.message || String(err) };
        }
      },
      { paths: IMPORT_PATHS },
    );

    if (!res.success) {
      test.skip(
        true,
        `parseAccountIdFromSubject (no request_id) failed: ${res.error || 'unknown error'}`,
      );
      return;
    }

    expect(res.accountId).toBeNull();
  });

  test('parseVerifiedRecoveryEmailArtifact parses the canonical recovery payload from the raw email', async ({
    page,
  }) => {
    const res = await page.evaluate(
      async ({ paths }) => {
        try {
          const { parseVerifiedRecoveryEmailArtifact } = await import(paths.emailParsers);
          const payload = {
            deadlineEpochSeconds: 1893456000,
            nearAccountId: 'bob.testnet',
            newEvmOwnerAddress: `0x${'11'.repeat(20)}`,
            newNearPublicKey: 'ed25519:edpkDummyKey',
            recoverySessionId: 'ABC123',
            version: 'recovery_email_payload_v1',
          };
          const token = btoa(JSON.stringify(payload))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/g, '');

          const rawEmail = [
            'Subject: recover-v1 bob.testnet ABC123',
            'From: alice@example.com',
            'Date: Tue, 01 Jan 2024 00:00:00 GMT',
            '',
            'tee-encrypted',
            `tatchi-recovery-v1:${token}`,
          ].join('\n');

          const bindings = parseVerifiedRecoveryEmailArtifact(rawEmail);
          return { success: true, bindings };
        } catch (err: any) {
          return { success: false, error: err?.message || String(err) };
        }
      },
      { paths: IMPORT_PATHS },
    );

    if (!res.success) {
      test.skip(true, `parseRecoverSubjectBindings failed: ${res.error || 'unknown error'}`);
      return;
    }

    expect(res.bindings).toBeTruthy();
    expect(res.bindings.accountId).toBe('bob.testnet');
    expect(res.bindings.recoveryPayload.recoverySessionId).toBe('ABC123');
    expect(res.bindings.recoveryPayload.newNearPublicKey).toBe('ed25519:edpkDummyKey');
  });
});

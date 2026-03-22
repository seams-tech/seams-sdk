import { test, expect } from '@playwright/test';
import { parseRecoverEmailRequest } from '@server/email-recovery/emailParsers';
import { buildRecoveryEmailBody, buildRecoveryEmailPayload } from '@shared/utils/recoveryEmail';

test.describe('parseRecoverEmailRequest', () => {
  test('parses accountId from Subject header', async () => {
    const payload = buildRecoveryEmailPayload({
      nearAccountId: 'bob.testnet',
      recoverySessionId: 'ABC123',
      newNearPublicKey: 'ed25519:somepk',
      newEvmOwnerAddress: `0x${'11'.repeat(20)}`,
      deadlineEpochSeconds: 1893456000,
    });
    const body = {
      from: 'sender@example.com',
      to: 'recover@web3authn.org',
      headers: {
        Subject: 'recover-v1 bob.testnet ABC123',
      },
      raw: ['Subject: recover-v1 bob.testnet ABC123', '', buildRecoveryEmailBody(payload)].join('\r\n'),
      rawSize: 1,
    };

    const parsed = parseRecoverEmailRequest(body);

    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.accountId).toBe('bob.testnet');
    expect(parsed.emailBlob.length).toBeGreaterThan(0);
  });

  test('returns missing_email when raw email blob is absent', async () => {
    const body = {
      from: 'sender@example.com',
      to: 'recover@web3authn.org',
      headers: {
        Subject: 'recover-v1 bob.testnet ABC123',
      },
      rawSize: 1,
    };

    const parsed = parseRecoverEmailRequest(body);
    expect(parsed.ok).toBe(false);
    if (parsed.ok) return;
    expect(parsed.status).toBe(400);
    expect(parsed.code).toBe('missing_email');
  });

  test('returns invalid_email for non-object input', async () => {
    const parsed = parseRecoverEmailRequest(null);
    expect(parsed.ok).toBe(false);
    if (parsed.ok) return;
    expect(parsed.status).toBe(400);
    expect(parsed.code).toBe('invalid_email');
  });
});

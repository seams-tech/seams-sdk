import { expect, test } from '@playwright/test';
import { parsePrepareEmailRecoveryRequest } from '@server/router/emailRecoveryRequestValidation';

test('email-recovery prepare rejects raw threshold ECDSA bootstrap payloads at the route boundary', () => {
  const result = parsePrepareEmailRecoveryRequest({
    body: {
      threshold_ecdsa: { client_root_share32_b64u: 'raw-root-share' },
    },
    origin: 'https://wallet.example.test',
  });

  expect(result).toMatchObject({
    ok: false,
    body: { code: 'invalid_body' },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.body.message).toBe('Unsupported email-recovery prepare field: threshold_ecdsa');
});

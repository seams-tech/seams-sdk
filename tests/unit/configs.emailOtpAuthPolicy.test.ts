import { expect, test } from '@playwright/test';
import { buildConfigsFromEnv } from '@/core/config/defaultConfigs';

test.describe('buildConfigsFromEnv Email OTP auth policy', () => {
  test('defaults Email OTP auth policy to session', async () => {
    const cfg = buildConfigsFromEnv({
      relayer: { url: 'https://relay.example' },
    });
    expect(cfg.signing.emailOtp.authPolicy).toBe('session');
  });

  test('accepts explicit per_operation Email OTP auth policy', async () => {
    const cfg = buildConfigsFromEnv({
      relayer: { url: 'https://relay.example' },
      emailOtpAuthPolicy: 'per_operation',
    });
    expect(cfg.signing.emailOtp.authPolicy).toBe('per_operation');
  });

  test('rejects invalid Email OTP auth policy values', async () => {
    expect(() =>
      buildConfigsFromEnv({
        relayer: { url: 'https://relay.example' },
        emailOtpAuthPolicy: 'invalid' as any,
      }),
    ).toThrow(
      '[configPresets] Invalid config: emailOtpAuthPolicy (invalid); expected "session" or "per_operation"',
    );
  });
});

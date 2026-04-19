import { expect, test } from '@playwright/test';
import {
  createEmailOtpWalletAuthAdapter,
  createPasskeyWalletAuthAdapter,
  createWalletAuthModeResolver,
  resolveAccountAuthMetadataForSignerSource,
  WalletAuthModeResolutionError,
} from '@/core/signingEngine/auth';
import {
  accountAuthFixtures,
  type AccountAuthFixture,
} from './helpers/accountAuth.fixtures';

function createResolverHarness(args?: { warmSessionFor?: AccountAuthFixture }) {
  const calls: string[] = [];
  const resolver = createWalletAuthModeResolver({
    passkey: createPasskeyWalletAuthAdapter({
      challenge: async (input) => {
        calls.push(`passkey:challenge:${input.accountId}:${input.intent}`);
        return { challengeId: `passkey-${input.accountId}` };
      },
      complete: async ({ request }) => {
        calls.push(`passkey:complete:${request.accountId}:${request.intent}`);
        return {
          method: 'passkey',
          webauthnAuthentication: { id: `credential-${request.accountId}` },
        };
      },
    }),
    emailOtp: createEmailOtpWalletAuthAdapter({
      challenge: async (input) => {
        calls.push(`email_otp:challenge:${input.accountId}:${input.intent}`);
        return {
          challengeId: `email-otp-${input.accountId}`,
          email: input.accountAuth.email || 'missing-email@example.test',
        };
      },
      complete: async ({ request, challengeId, code }) => {
        calls.push(`email_otp:complete:${request.accountId}:${challengeId}:${code}`);
        return {
          method: 'email_otp',
          emailOtpAuthentication: { challengeId, code },
        };
      },
    }),
    warmSession: args?.warmSessionFor
      ? {
          resolveWarmSessionPlan: async (input) =>
            input.accountId === args.warmSessionFor?.accountId
              ? {
                  kind: 'warmSession',
                  method: args.warmSessionFor.metadata.primaryAuthMethod,
                  accountId: input.accountId,
                  intent: input.intent,
                  ...(input.curve ? { curve: input.curve } : {}),
                  sessionId: `warm-${input.accountId}`,
                  retention: 'session',
                  expiresAtMs: Date.now() + 60_000,
                  remainingUses: 3,
                }
              : null,
        }
      : undefined,
  });
  return { calls, resolver };
}

test.describe('WalletAuthModeResolver', () => {
  test('derives account auth metadata from canonical signer source', async () => {
    expect(resolveAccountAuthMetadataForSignerSource()).toEqual({
      primaryAuthMethod: 'passkey',
      linkedAuthMethods: ['passkey'],
    });
    expect(resolveAccountAuthMetadataForSignerSource({ source: 'passkey' })).toEqual({
      primaryAuthMethod: 'passkey',
      linkedAuthMethods: ['passkey'],
    });
    expect(
      resolveAccountAuthMetadataForSignerSource({
        source: 'email_otp',
        email: 'alice@example.test',
      }),
    ).toEqual({
      primaryAuthMethod: 'email_otp',
      linkedAuthMethods: ['email_otp'],
      email: 'alice@example.test',
    });
  });

  test('routes passkey-only accounts to passkey reauth', async () => {
    const fixture = accountAuthFixtures.passkeyOnly;
    const { calls, resolver } = createResolverHarness();
    const plan = await resolver.resolveWalletAuthPlan({
      accountId: fixture.accountId,
      accountAuth: fixture.metadata,
      intent: 'transaction_sign',
      curve: 'ed25519',
    });

    expect(plan.kind).toBe('passkeyReauth');
    if (plan.kind !== 'passkeyReauth') throw new Error('expected passkey plan');
    const challenge = await plan.challenge();
    const proof = await plan.complete(challenge);

    expect(proof.method).toBe('passkey');
    expect(calls).toEqual([
      `passkey:challenge:${fixture.accountId}:transaction_sign`,
      `passkey:complete:${fixture.accountId}:transaction_sign`,
    ]);
  });

  test('routes Email OTP-only accounts to Email OTP reauth', async () => {
    const fixture = accountAuthFixtures.emailOtpOnly;
    const { calls, resolver } = createResolverHarness();
    const plan = await resolver.resolveWalletAuthPlan({
      accountId: fixture.accountId,
      accountAuth: fixture.metadata,
      intent: 'transaction_sign',
      curve: 'ecdsa',
    });

    expect(plan.kind).toBe('emailOtpReauth');
    if (plan.kind !== 'emailOtpReauth') throw new Error('expected Email OTP plan');
    const challenge = await plan.challenge();
    const proof = await plan.complete({ challengeId: challenge.challengeId, code: '123456' });

    expect(challenge.email).toBe('email-otp-only@example.test');
    expect(proof.method).toBe('email_otp');
    expect(calls).toEqual([
      `email_otp:challenge:${fixture.accountId}:transaction_sign`,
      `email_otp:complete:${fixture.accountId}:email-otp-${fixture.accountId}:123456`,
    ]);
  });

  test('prefers warm session before reauth adapter challenge', async () => {
    const fixture = accountAuthFixtures.emailOtpOnly;
    const { calls, resolver } = createResolverHarness({ warmSessionFor: fixture });
    const plan = await resolver.resolveWalletAuthPlan({
      accountId: fixture.accountId,
      accountAuth: fixture.metadata,
      intent: 'wallet_unlock',
    });

    expect(plan).toEqual({
      kind: 'warmSession',
      method: 'email_otp',
      accountId: fixture.accountId,
      intent: 'wallet_unlock',
      sessionId: `warm-${fixture.accountId}`,
      retention: 'session',
      expiresAtMs: expect.any(Number),
      remainingUses: 3,
    });
    expect(calls).toEqual([]);
  });

  test('rejects warm sessions that do not match the requested account scope', async () => {
    const fixture = accountAuthFixtures.emailOtpOnly;
    const resolver = createWalletAuthModeResolver({
      passkey: createPasskeyWalletAuthAdapter({
        challenge: async () => ({}),
        complete: async () => ({
          method: 'passkey',
          webauthnAuthentication: {},
        }),
      }),
      emailOtp: createEmailOtpWalletAuthAdapter({
        challenge: async () => ({
          challengeId: 'email-otp',
          email: fixture.metadata.email || 'email@example.test',
        }),
        complete: async () => ({
          method: 'email_otp',
          emailOtpAuthentication: {},
        }),
      }),
      warmSession: {
        resolveWarmSessionPlan: async () => ({
          kind: 'warmSession',
          method: 'email_otp',
          accountId: 'other-account.testnet',
          intent: 'transaction_sign',
          curve: 'ed25519',
          sessionId: 'warm-session',
          retention: 'session',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 1,
        }),
      },
    });

    await expect(
      resolver.resolveWalletAuthPlan({
        accountId: fixture.accountId,
        accountAuth: fixture.metadata,
        intent: 'transaction_sign',
        curve: 'ed25519',
      }),
    ).rejects.toMatchObject({
      name: 'WalletAuthModeResolutionError',
      code: 'invalid_warm_session_plan',
    } satisfies Partial<WalletAuthModeResolutionError>);
  });

  test('rejects primary auth methods that are not linked', async () => {
    const { resolver } = createResolverHarness();
    await expect(
      resolver.resolveWalletAuthPlan({
        accountId: 'broken.testnet',
        accountAuth: {
          primaryAuthMethod: 'email_otp',
          linkedAuthMethods: ['passkey'],
        },
        intent: 'transaction_sign',
      }),
    ).rejects.toMatchObject({
      name: 'WalletAuthModeResolutionError',
      code: 'unlinked_primary_auth_method',
    } satisfies Partial<WalletAuthModeResolutionError>);
  });

  test('rejects missing account auth metadata', async () => {
    const { resolver } = createResolverHarness();
    await expect(
      resolver.resolveWalletAuthPlan({
        accountId: 'missing-auth.testnet',
        accountAuth: null as any,
        intent: 'transaction_sign',
      }),
    ).rejects.toMatchObject({
      name: 'WalletAuthModeResolutionError',
      code: 'missing_auth_metadata',
    } satisfies Partial<WalletAuthModeResolutionError>);
  });

  test('rejects unsupported primary auth methods', async () => {
    const { resolver } = createResolverHarness();
    await expect(
      resolver.resolveWalletAuthPlan({
        accountId: 'unsupported-auth.testnet',
        accountAuth: {
          primaryAuthMethod: 'magic_link',
          linkedAuthMethods: ['magic_link'],
        } as any,
        intent: 'transaction_sign',
      }),
    ).rejects.toMatchObject({
      name: 'WalletAuthModeResolutionError',
      code: 'unsupported_primary_auth_method',
    } satisfies Partial<WalletAuthModeResolutionError>);
  });

  test('rejects invalid auth metadata before accepting warm sessions', async () => {
    const fixture = accountAuthFixtures.emailOtpOnly;
    const { resolver } = createResolverHarness({ warmSessionFor: fixture });
    await expect(
      resolver.resolveWalletAuthPlan({
        accountId: fixture.accountId,
        accountAuth: {
          primaryAuthMethod: 'email_otp',
          linkedAuthMethods: ['passkey'],
        },
        intent: 'wallet_unlock',
      }),
    ).rejects.toMatchObject({
      name: 'WalletAuthModeResolutionError',
      code: 'unlinked_primary_auth_method',
    } satisfies Partial<WalletAuthModeResolutionError>);
  });

  test('does not fall through to WebAuthn for Email OTP accounts', async () => {
    const fixture = accountAuthFixtures.emailOtpOnly;
    const { calls, resolver } = createResolverHarness();
    const plan = await resolver.resolveWalletAuthPlan({
      accountId: fixture.accountId,
      accountAuth: fixture.metadata,
      intent: 'transaction_sign',
      curve: 'ed25519',
    });

    expect(plan.kind).toBe('emailOtpReauth');
    expect(calls).toEqual([]);
    if (plan.kind !== 'emailOtpReauth') throw new Error('expected Email OTP plan');

    const challenge = await plan.challenge();
    await plan.complete({ challengeId: challenge.challengeId, code: '654321' });

    expect(calls).toEqual([
      `email_otp:challenge:${fixture.accountId}:transaction_sign`,
      `email_otp:complete:${fixture.accountId}:email-otp-${fixture.accountId}:654321`,
    ]);
    expect(calls.some((entry) => entry.startsWith('passkey:'))).toBe(false);
  });

  test('does not consume Email OTP proof for passkey-primary mixed accounts', async () => {
    const fixture = accountAuthFixtures.passkeyAndEmailOtp;
    const { calls, resolver } = createResolverHarness();
    const plan = await resolver.resolveWalletAuthPlan({
      accountId: fixture.accountId,
      accountAuth: fixture.metadata,
      intent: 'session_mint',
      curve: 'ed25519',
    });

    expect(plan.kind).toBe('passkeyReauth');
    expect(calls).toEqual([]);
    if (plan.kind !== 'passkeyReauth') throw new Error('expected passkey plan');

    const challenge = await plan.challenge();
    await plan.complete(challenge);

    expect(calls).toEqual([
      `passkey:challenge:${fixture.accountId}:session_mint`,
      `passkey:complete:${fixture.accountId}:session_mint`,
    ]);
    expect(calls.some((entry) => entry.startsWith('email_otp:'))).toBe(false);
  });

  test('pins passkey account auth matrix across unlock, signing, session mint, and export intents', async () => {
    const fixture = accountAuthFixtures.passkeyOnly;
    const { calls, resolver } = createResolverHarness();
    const cases = [
      { intent: 'wallet_unlock' as const },
      { intent: 'transaction_sign' as const, curve: 'ed25519' as const },
      { intent: 'transaction_sign' as const, curve: 'ecdsa' as const },
      { intent: 'session_mint' as const, curve: 'ed25519' as const },
      { intent: 'ed25519_export' as const, curve: 'ed25519' as const },
      { intent: 'ecdsa_export' as const, curve: 'ecdsa' as const },
    ];

    for (const entry of cases) {
      const plan = await resolver.resolveWalletAuthPlan({
        accountId: fixture.accountId,
        accountAuth: fixture.metadata,
        intent: entry.intent,
        ...(entry.curve ? { curve: entry.curve } : {}),
      });
      expect(plan.kind, entry.intent).toBe('passkeyReauth');
      expect(plan.method, entry.intent).toBe('passkey');
    }

    expect(calls).toEqual([]);
  });

  test('pins Email OTP account auth matrix for unlock, signing, session mint, and export intents', async () => {
    const fixture = accountAuthFixtures.emailOtpOnly;
    const { calls, resolver } = createResolverHarness();
    const cases = [
      { intent: 'wallet_unlock' as const },
      { intent: 'transaction_sign' as const, curve: 'ed25519' as const },
      { intent: 'transaction_sign' as const, curve: 'ecdsa' as const },
      { intent: 'session_mint' as const, curve: 'ed25519' as const },
      { intent: 'ed25519_export' as const, curve: 'ed25519' as const },
      { intent: 'ecdsa_export' as const, curve: 'ecdsa' as const },
    ];

    for (const entry of cases) {
      const plan = await resolver.resolveWalletAuthPlan({
        accountId: fixture.accountId,
        accountAuth: fixture.metadata,
        intent: entry.intent,
        ...(entry.curve ? { curve: entry.curve } : {}),
      });
      expect(plan.kind, entry.intent).toBe('emailOtpReauth');
      expect(plan.method, entry.intent).toBe('email_otp');
    }

    expect(calls).toEqual([]);
  });

  test('pins mixed-account default auth matrix to the primary passkey method', async () => {
    const fixture = accountAuthFixtures.passkeyAndEmailOtp;
    const { calls, resolver } = createResolverHarness();
    const cases = [
      { intent: 'wallet_unlock' as const },
      { intent: 'transaction_sign' as const, curve: 'ed25519' as const },
      { intent: 'transaction_sign' as const, curve: 'ecdsa' as const },
      { intent: 'ed25519_export' as const, curve: 'ed25519' as const },
      { intent: 'ecdsa_export' as const, curve: 'ecdsa' as const },
    ];

    for (const entry of cases) {
      const plan = await resolver.resolveWalletAuthPlan({
        accountId: fixture.accountId,
        accountAuth: fixture.metadata,
        intent: entry.intent,
        ...(entry.curve ? { curve: entry.curve } : {}),
      });
      expect(plan.kind, entry.intent).toBe('passkeyReauth');
      expect(plan.method, entry.intent).toBe('passkey');
    }

    expect(calls).toEqual([]);
  });
});

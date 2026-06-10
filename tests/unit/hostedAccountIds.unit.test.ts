import { expect, test } from '@playwright/test';
import { deriveHostedNearAccountId } from '../../packages/sdk-server-ts/src/core/hostedAccountIds';

const BASE_INPUT = {
  accountIdDerivationSecret: 'unit-test-account-id-secret',
  relayerAccount: 'relayer.testnet',
  projectId: 'proj_test',
  envId: 'dev',
  authProvider: 'google_oidc',
  providerSubject: 'google:117142622123955425762',
  verifiedEmail: 'alice.example+demo@example.com',
};

test.describe('hosted account ID derivation', () => {
  test('derives deterministic readable NEAR subaccounts without raw email substrings', async () => {
    const first = await deriveHostedNearAccountId(BASE_INPUT);
    const second = await deriveHostedNearAccountId({
      ...BASE_INPUT,
      verifiedEmail: 'different-address@example.com',
    });

    expect(first).toBe(second);
    expect(first).toMatch(/^[a-z]+-[a-z]+-[a-z0-9]{10}\.relayer\.testnet$/);
    expect(first).not.toContain('alice');
    expect(first).not.toContain('example');
    expect(first).not.toContain('google');
  });

  test('binds generated account IDs to project, env, provider, and collision counter', async () => {
    const base = await deriveHostedNearAccountId(BASE_INPUT);
    const differentProject = await deriveHostedNearAccountId({ ...BASE_INPUT, projectId: 'proj_other' });
    const differentEnv = await deriveHostedNearAccountId({ ...BASE_INPUT, envId: 'prod' });
    const differentProvider = await deriveHostedNearAccountId({ ...BASE_INPUT, authProvider: 'oidc' });
    const collisionRetry = await deriveHostedNearAccountId({ ...BASE_INPUT, collisionCounter: 1 });

    expect(new Set([base, differentProject, differentEnv, differentProvider, collisionRetry]).size).toBe(
      5,
    );
  });

  test('uses a derivation nonce to randomize readable account slugs per registration attempt', async () => {
    const base = await deriveHostedNearAccountId(BASE_INPUT);
    const nonceA = await deriveHostedNearAccountId({
      ...BASE_INPUT,
      walletIdDerivationNonce: 'nonceA0123456789',
    });
    const sameNonceA = await deriveHostedNearAccountId({
      ...BASE_INPUT,
      walletIdDerivationNonce: 'nonceA0123456789',
    });
    const nonceB = await deriveHostedNearAccountId({
      ...BASE_INPUT,
      walletIdDerivationNonce: 'nonceB0123456789',
    });

    expect(nonceA).toBe(sameNonceA);
    expect(new Set([base, nonceA, nonceB]).size).toBe(3);
  });

  test('requires a derivation secret and provider identity', async () => {
    await expect(
      deriveHostedNearAccountId({
        ...BASE_INPUT,
        accountIdDerivationSecret: '',
      }),
    ).rejects.toThrow('ACCOUNT_ID_DERIVATION_SECRET is required');

    await expect(
      deriveHostedNearAccountId({
        ...BASE_INPUT,
        providerSubject: '',
        verifiedEmail: '',
      }),
    ).rejects.toThrow('providerSubject or verifiedEmail');
  });
});

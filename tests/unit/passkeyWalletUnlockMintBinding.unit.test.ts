import { expect, test } from '@playwright/test';
import { bindPasskeyEcdsaSessionPolicyToUnlockChallenge } from '@/SeamsWeb/operations/auth/login';
import { createEcdsaSessionActivationFixture } from './helpers/ecdsaBootstrap.fixtures';

test('Passkey combined unlock binds its ECDSA Wallet Session mint to the verified challenge', () => {
  const activation = createEcdsaSessionActivationFixture({
    walletId: 'wallet:passkey-combined-unlock',
    chain: 'ethereum',
  });
  const preparedPolicy = {
    kind: 'router_ab_ecdsa_post_registration_session_activation_policy_v1' as const,
    key_handle: 'ecdsa-key-handle:passkey-combined-unlock',
    session_policy: activation.request.session_policy,
  };

  const boundPolicy = bindPasskeyEcdsaSessionPolicyToUnlockChallenge(
    preparedPolicy,
    'challenge:passkey-combined-unlock',
  );

  expect(boundPolicy).toEqual({
    ...preparedPolicy,
    session_policy: {
      ...preparedPolicy.session_policy,
      wallet_session_mint_id: 'challenge:passkey-combined-unlock',
    },
  });
});

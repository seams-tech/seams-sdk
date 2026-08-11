import { expect, test } from '@playwright/test';
import { parseSessionExchangeRouteCommand } from '../../packages/sdk-server-ts/src/router/auth/sessionExchangeRequestValidation';
import { createThresholdEcdsaBootstrapFixture } from './helpers/ecdsaBootstrap.fixtures';
import { parseReusableWalletSessionMintId } from '@shared/authorization/capabilityKinds';

const PASSKEY_ASSERTION = {
  id: 'credential-id',
  rawId: 'credential-id',
  type: 'public-key',
  authenticatorAttachment: null,
  response: {
    clientDataJSON: 'client-data',
    authenticatorData: 'authenticator-data',
    signature: 'signature',
    userHandle: null,
  },
  clientExtensionResults: null,
};

function firstEcdsaSessionActivationPolicy() {
  const bootstrap = createThresholdEcdsaBootstrapFixture({
    nearAccountId: 'alice.testnet',
    chain: 'evm',
  });
  if (!bootstrap.session.runtimePolicyScope) {
    throw new Error('expected ECDSA runtime policy scope');
  }
  const mintId = parseReusableWalletSessionMintId('wallet-session-mint-fixture');
  if (!mintId.ok) throw new Error('expected valid Wallet Session mint fixture');
  return {
    kind: 'router_ab_ecdsa_post_registration_session_activation_policy_v1' as const,
    key_handle: bootstrap.thresholdEcdsaKeyRef.keyHandle,
    session_policy: {
      threshold_session_id: bootstrap.session.thresholdSessionId,
      wallet_session_mint_id: mintId.value,
      ttl_ms: 120_000,
      remaining_uses: bootstrap.session.remainingUses,
      runtime_policy_scope: bootstrap.session.runtimePolicyScope,
    },
  };
}

test.describe('passkey session exchange ECDSA activation validation', () => {
  test('accepts exact first-session activation only on passkey exchange', () => {
    const policy = firstEcdsaSessionActivationPolicy();
    const parsed = parseSessionExchangeRouteCommand({
      sessionKind: 'jwt',
      exchange: {
        type: 'passkey_assertion',
        challengeId: 'challenge-id',
        webauthn_authentication: PASSKEY_ASSERTION,
        wallet_id: 'wallet-fixture',
        ecdsa_session_policy: policy,
      },
    });
    if (!parsed.ok) throw new Error(parsed.body.message);
    expect(parsed).toMatchObject({
      ok: true,
      command: {
        kind: 'passkey_assertion',
        ecdsaActivation: {
          kind: 'activate_first_ecdsa_wallet_session',
          policy,
        },
      },
    });
  });

  test('rejects ECDSA activation on OIDC and hosted-wallet exchanges', () => {
    const policy = firstEcdsaSessionActivationPolicy();
    expect(
      parseSessionExchangeRouteCommand({
        sessionKind: 'jwt',
        exchange: {
          type: 'oidc_jwt',
          token: 'oidc-token',
          provider: 'oidc',
          wallet_id: 'wallet-fixture',
          ecdsa_session_policy: policy,
        },
      }),
    ).toMatchObject({ ok: false });
    expect(
      parseSessionExchangeRouteCommand({
        sessionKind: 'jwt',
        exchange: {
          type: 'hosted_wallet_exchange_code',
          wallet_origin: 'https://wallet.example.test',
          wallet_id: 'wallet-fixture',
          ecdsa_session_policy: policy,
        },
      }),
    ).toMatchObject({ ok: false });
  });
});

test.describe('hosted-wallet Seams session exchange request validation', () => {
  test('parses code issuance and redemption as exact JWT exchanges', () => {
    expect(
      parseSessionExchangeRouteCommand({
        sessionKind: 'jwt',
        exchange: {
          type: 'hosted_wallet_exchange_code',
          wallet_origin: 'https://wallet.example.test',
        },
      }),
    ).toEqual({
      ok: true,
      command: {
        kind: 'hosted_wallet_exchange_code',
        sessionKind: 'jwt',
        walletOrigin: 'https://wallet.example.test',
      },
    });

    expect(
      parseSessionExchangeRouteCommand({
        sessionKind: 'jwt',
        exchange: {
          type: 'hosted_wallet_exchange_code_redeem',
          exchange_code: 'exchange-code',
          nonce: 'exchange-nonce',
        },
      }),
    ).toEqual({
      ok: true,
      command: {
        kind: 'hosted_wallet_exchange_code_redeem',
        sessionKind: 'jwt',
        exchangeCode: 'exchange-code',
        nonce: 'exchange-nonce',
      },
    });
  });

  test('rejects cookie delivery and unexpected exchange fields', () => {
    expect(
      parseSessionExchangeRouteCommand({
        sessionKind: 'cookie',
        exchange: {
          type: 'hosted_wallet_exchange_code',
          wallet_origin: 'https://wallet.example.test',
        },
      }),
    ).toMatchObject({ ok: false });
    expect(
      parseSessionExchangeRouteCommand({
        sessionKind: 'jwt',
        exchange: {
          type: 'hosted_wallet_exchange_code_redeem',
          exchange_code: 'exchange-code',
          nonce: 'exchange-nonce',
          appSessionJwt: 'bearer-must-not-cross-this-boundary',
        },
      }),
    ).toMatchObject({ ok: false });
  });
});

test.describe('GitHub OAuth session exchange request validation', () => {
  test('accepts a bounded authorization-code exchange', () => {
    expect(
      parseSessionExchangeRouteCommand({
        session_kind: 'cookie',
        exchange: { type: 'github_oauth_code', code: 'temporary-code' },
      }),
    ).toEqual({
      ok: true,
      command: {
        kind: 'github_oauth_code',
        sessionKind: 'cookie',
        code: 'temporary-code',
      },
    });
  });

  test('rejects missing codes and provider tokens', () => {
    expect(
      parseSessionExchangeRouteCommand({
        session_kind: 'cookie',
        exchange: { type: 'github_oauth_code', code: '' },
      }),
    ).toMatchObject({ ok: false });
    expect(
      parseSessionExchangeRouteCommand({
        session_kind: 'cookie',
        exchange: { type: 'github_oauth_code', code: 'temporary-code', access_token: 'secret' },
      }),
    ).toMatchObject({ ok: false });
  });
});

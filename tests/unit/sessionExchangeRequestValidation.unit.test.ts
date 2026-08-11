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

function firstEcdsaSessionActivationRequest() {
  const bootstrap = createThresholdEcdsaBootstrapFixture({
    nearAccountId: 'alice.testnet',
    chain: 'evm',
  });
  const binding = bootstrap.thresholdEcdsaKeyRef.backendBinding;
  if (!binding || binding.materialKind !== 'role_local_worker_handle') {
    throw new Error('expected passkey ECDSA role-local fixture');
  }
  if (!bootstrap.session.runtimePolicyScope) {
    throw new Error('expected ECDSA runtime policy scope');
  }
  const mintId = parseReusableWalletSessionMintId('wallet-session-mint-fixture');
  if (!mintId.ok) throw new Error('expected valid Wallet Session mint fixture');
  return {
    kind: 'router_ab_ecdsa_post_registration_session_activation_v1',
    public_capability: binding.publicFacts.publicCapability,
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
    const activation = firstEcdsaSessionActivationRequest();
    const parsed = parseSessionExchangeRouteCommand({
      sessionKind: 'jwt',
      exchange: {
        type: 'passkey_assertion',
        challengeId: 'challenge-id',
        webauthn_authentication: PASSKEY_ASSERTION,
        ecdsa_session_activation: activation,
      },
    });
    if (!parsed.ok) throw new Error(parsed.body.message);
    expect(parsed).toMatchObject({
      ok: true,
      command: {
        kind: 'passkey_assertion',
        ecdsaActivation: {
          kind: 'activate_first_ecdsa_wallet_session',
          request: activation,
        },
      },
    });
  });

  test('rejects ECDSA activation on OIDC and hosted-wallet exchanges', () => {
    const activation = firstEcdsaSessionActivationRequest();
    expect(
      parseSessionExchangeRouteCommand({
        sessionKind: 'jwt',
        exchange: {
          type: 'oidc_jwt',
          token: 'oidc-token',
          provider: 'oidc',
          ecdsa_session_activation: activation,
        },
      }),
    ).toMatchObject({ ok: false });
    expect(
      parseSessionExchangeRouteCommand({
        sessionKind: 'jwt',
        exchange: {
          type: 'hosted_wallet_exchange_code',
          wallet_origin: 'https://wallet.example.test',
          ecdsa_session_activation: activation,
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

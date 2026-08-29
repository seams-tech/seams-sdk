import { expect, test } from '@playwright/test';
import { parseRouterAbEcdsaPostRegistrationSessionActivationResponseV1 } from '@shared/utils/routerAbEcdsaDerivation';
import { createEcdsaSessionActivationFixture } from './helpers/ecdsaBootstrap.fixtures';

test('ECDSA activation wire carries an exact session and its primary operation credential', () => {
  const fixture = createEcdsaSessionActivationFixture({
    walletId: 'ecdsa-exact-activation.testnet',
    chain: 'tempo',
    sessionId: 'ecdsa-exact-activation',
  });

  expect(fixture.request).not.toHaveProperty('wallet_session_client_capability');
  expect(fixture.response.session.wallet_session.authorizationId).toBe(
    fixture.response.session.authorization_id,
  );
  expect(fixture.response.session.operation_credential.walletSessionId).toBe(
    fixture.response.session.wallet_session_id,
  );
  expect(fixture.response.session.operation_credential.token).toMatch(/^wst_[A-Za-z0-9_-]{43}$/);
});

test('ECDSA activation response rejects legacy bearers and mismatched exact material', () => {
  const first = createEcdsaSessionActivationFixture({
    walletId: 'ecdsa-response.testnet',
    chain: 'tempo',
    sessionId: 'ecdsa-response-first',
  });
  const second = createEcdsaSessionActivationFixture({
    walletId: 'ecdsa-response.testnet',
    chain: 'tempo',
    sessionId: 'ecdsa-response-second',
  });
  const firstSession = first.response.session;

  expect(() =>
    parseRouterAbEcdsaPostRegistrationSessionActivationResponseV1({
      kind: first.response.kind,
      public_capability: first.response.public_capability,
      session: {
        authorization_session_id: firstSession.authorization_session_id,
        authorization_id: firstSession.authorization_id,
        threshold_session_id: firstSession.threshold_session_id,
        wallet_session_id: firstSession.wallet_session_id,
        quota_id: firstSession.quota_id,
        expires_at_ms: firstSession.expires_at_ms,
        remaining_uses: firstSession.remaining_uses,
        wallet_session_token: firstSession.operation_credential.token,
      },
      normal_signing: first.response.normal_signing,
    }),
  ).toThrow(/wallet_session_token/);

  expect(() =>
    parseRouterAbEcdsaPostRegistrationSessionActivationResponseV1({
      kind: first.response.kind,
      public_capability: first.response.public_capability,
      session: second.response.session,
      normal_signing: first.response.normal_signing,
    }),
  ).toThrow(/exact Wallet Session/);
});

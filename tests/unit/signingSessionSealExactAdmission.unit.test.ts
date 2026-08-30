import { expect, test } from '@playwright/test';
import type {
  RouterApiAuthorizationSessionService,
  RouterApiWalletRegistrationService,
  RouterApiWalletSessionAuthorizationV2AdmissionContext,
} from '../../packages/wallet-server/src/router/framework/authServicePort';
import { authorizeSigningSessionSealWithExactWalletSession } from '../../packages/wallet-server/src/router/transport/fetch/createFetchRouter';
import type { SigningSessionSealAuthorizeResult } from '../../packages/wallet-server/src/threshold/session/signingSessionSeal/signingSessionSeal.types';
import { parseTenantId } from '../../packages/shared-ts/src/authorization/capabilityKinds';
import {
  buildEcdsaSigningSessionSealAdmissionFixture,
  buildEd25519SigningSessionSealAdmissionFixture,
  type SigningSessionSealAdmissionFixture,
} from './helpers/signingSessionSealAdmission.fixtures';

async function unsupportedAuthorizationSessionOperation(): Promise<never> {
  throw new Error('authorization session operation is outside this test boundary');
}

class AuthorizationSessionsFixture implements RouterApiAuthorizationSessionService {
  readonly tenantId: RouterApiAuthorizationSessionService['tenantId'];
  exactReads = 0;

  constructor(
    private readonly context: RouterApiWalletSessionAuthorizationV2AdmissionContext | null,
  ) {
    const fallback = parseTenantId('tenant:signing-seal');
    if (!fallback.ok) throw new Error(fallback.error.message);
    this.tenantId = context?.authorization.session.tenantId ?? fallback.value;
  }

  async readWalletSessionAuthorizationV2ByOperationCredential(): Promise<RouterApiWalletSessionAuthorizationV2AdmissionContext | null> {
    this.exactReads += 1;
    return this.context;
  }

  async readLinkedDeviceWalletSessionAuthorization(): Promise<never> {
    return await unsupportedAuthorizationSessionOperation();
  }

  async renewLinkedDeviceWalletSession(): Promise<never> {
    return await unsupportedAuthorizationSessionOperation();
  }

  async mintHostedWalletSeamsSessionExchange(): Promise<never> {
    return await unsupportedAuthorizationSessionOperation();
  }

  async redeemHostedWalletSeamsSessionExchange(): Promise<never> {
    return await unsupportedAuthorizationSessionOperation();
  }
}

async function authorizeFixture(
  fixture: SigningSessionSealAdmissionFixture,
  thresholdSessionId = fixture.thresholdSessionId,
): Promise<{
  readonly result: SigningSessionSealAuthorizeResult;
  readonly sessions: AuthorizationSessionsFixture;
}> {
  const sessions = new AuthorizationSessionsFixture(fixture.context);
  const result = await authorizeSigningSessionSealWithExactWalletSession(
    sessions,
    fixture.walletRegistration as RouterApiWalletRegistrationService,
    {
      headers: { authorization: `Bearer ${fixture.token}` },
      thresholdSessionId,
    },
  );
  return { result, sessions };
}

test('exact Ed25519 operation credential authorizes its active threshold session', async () => {
  const fixture = await buildEd25519SigningSessionSealAdmissionFixture();
  const { result, sessions } = await authorizeFixture(fixture);

  expect(result).toEqual({
    ok: true,
    auth: {
      userId: String(fixture.context.authority.walletId),
      session: {
        kind: 'exact_wallet_session_operation_credential',
        curve: 'ed25519',
        thresholdSessionId: fixture.thresholdSessionId,
        userId: String(fixture.context.authority.walletId),
        expiresAtMs: fixture.context.authorization.session.expiresAtMs,
      },
    },
  });
  expect(sessions.exactReads).toBe(1);
});

test('exact ECDSA operation credential authorizes its active derivation state', async () => {
  const fixture = await buildEcdsaSigningSessionSealAdmissionFixture();
  const { result, sessions } = await authorizeFixture(fixture);

  expect(result).toMatchObject({
    ok: true,
    auth: {
      userId: String(fixture.context.authority.walletId),
      session: {
        kind: 'exact_wallet_session_operation_credential',
        curve: 'ecdsa',
        thresholdSessionId: fixture.thresholdSessionId,
      },
    },
  });
  expect(sessions.exactReads).toBe(1);
});

test('exact credential cannot seal a different threshold session', async () => {
  const fixture = await buildEd25519SigningSessionSealAdmissionFixture();
  const { result, sessions } = await authorizeFixture(fixture, 'threshold-session:other');

  expect(result).toEqual({
    ok: false,
    code: 'wallet_session_scope_mismatch',
    message: 'Wallet Session does not match the requested threshold session',
    status: 403,
  });
  expect(sessions.exactReads).toBe(1);
});

test('missing exact credential fails without consulting the legacy store', async () => {
  const fixture = await buildEd25519SigningSessionSealAdmissionFixture();
  const sessions = new AuthorizationSessionsFixture(null);
  const result = await authorizeSigningSessionSealWithExactWalletSession(
    sessions,
    fixture.walletRegistration as RouterApiWalletRegistrationService,
    {
      headers: { authorization: `Bearer ${fixture.token}` },
      thresholdSessionId: fixture.thresholdSessionId,
    },
  );

  expect(result).toEqual({
    ok: false,
    code: 'wallet_session_invalid',
    message: 'Wallet Session is invalid',
    status: 401,
  });
  expect(sessions.exactReads).toBe(1);
});

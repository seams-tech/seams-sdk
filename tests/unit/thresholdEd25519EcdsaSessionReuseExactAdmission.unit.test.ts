import { expect, test } from '@playwright/test';
import type {
  RouterApiAuthorizationSessionService,
  RouterApiWalletSessionAuthorizationV2AdmissionContext,
} from '../../packages/wallet-server/src/router/framework/authServicePort';
import { resolveReusedEcdsaWalletSession } from '../../packages/wallet-server/src/router/transport/fetch/routes/thresholdEd25519';
import { buildPasskeyWalletAuthAuthority } from '../../packages/shared-ts/src/utils/walletAuthAuthority';
import { buildEcdsaSigningSessionSealAdmissionFixture } from './helpers/signingSessionSealAdmission.fixtures';

type AuthorizationSessionFixture = {
  readonly service: RouterApiAuthorizationSessionService;
  readonly exactReads: () => number;
};

function buildAuthorizationSessionFixture(
  context: RouterApiWalletSessionAuthorizationV2AdmissionContext | null,
): AuthorizationSessionFixture {
  let exactReads = 0;
  const issued = context?.authorization;
  const service = {
    tenantId: issued?.session.tenantId,
    async readWalletSessionAuthorizationV2ByOperationCredential() {
      exactReads += 1;
      return context;
    },
  } as unknown as RouterApiAuthorizationSessionService;
  return {
    service,
    exactReads: () => exactReads,
  };
}

function requirePasskeyAuthority(context: RouterApiWalletSessionAuthorizationV2AdmissionContext) {
  const authMethod = context.authMethod;
  if (authMethod.kind !== 'passkey') {
    throw new Error('ECDSA reuse fixture requires a Passkey auth method');
  }
  return buildPasskeyWalletAuthAuthority({
    walletId: context.authority.walletId,
    rpId: authMethod.rpId,
    credentialIdB64u: authMethod.credentialIdB64u,
  });
}

const runtimePolicyScope = {
  orgId: 'tenant:management',
  projectId: 'project:signing-seal-ecdsa',
  envId: 'test',
  signingRootVersion: 'v1',
} as const;

test('Ed25519 mint reuses an exact active ECDSA session without legacy admission', async () => {
  const fixture = await buildEcdsaSigningSessionSealAdmissionFixture();
  const sessions = buildAuthorizationSessionFixture(fixture.context);
  const result = await resolveReusedEcdsaWalletSession({
    authorizationSessions: sessions.service,
    walletRegistration: fixture.walletRegistration,
    headers: new Headers({ authorization: `Bearer ${fixture.token}` }),
    runtimePolicyScope,
    authority: requirePasskeyAuthority(fixture.context),
  });

  expect(result).toEqual({
    ok: true,
    existingWalletSession: {
      authorizationId: fixture.context.authorization.session.authorizationId,
      walletSessionId: fixture.context.authorization.session.walletSessionId,
      quotaId: fixture.context.authorization.session.quotaId,
      expiresAtMs: fixture.context.authorization.session.expiresAtMs,
      remainingUses: fixture.context.authorization.quota.remainingUses,
    },
  });
  expect(sessions.exactReads()).toBe(1);
});

test('missing exact ECDSA session fails without reading the opaque-token store', async () => {
  const fixture = await buildEcdsaSigningSessionSealAdmissionFixture();
  const sessions = buildAuthorizationSessionFixture(null);
  const result = await resolveReusedEcdsaWalletSession({
    authorizationSessions: sessions.service,
    walletRegistration: fixture.walletRegistration,
    headers: new Headers({ authorization: `Bearer ${fixture.token}` }),
    runtimePolicyScope,
    authority: requirePasskeyAuthority(fixture.context),
  });
  if (result.ok) throw new Error('missing exact session was admitted');

  await expect(result.response.json()).resolves.toMatchObject({
    code: 'wallet_session_invalid',
  });
  expect(result.response.status).toBe(401);
  expect(sessions.exactReads()).toBe(1);
});

test('exact ECDSA session cannot cross into a different runtime policy scope', async () => {
  const fixture = await buildEcdsaSigningSessionSealAdmissionFixture();
  const sessions = buildAuthorizationSessionFixture(fixture.context);
  const result = await resolveReusedEcdsaWalletSession({
    authorizationSessions: sessions.service,
    walletRegistration: fixture.walletRegistration,
    headers: new Headers({ authorization: `Bearer ${fixture.token}` }),
    runtimePolicyScope: { ...runtimePolicyScope, projectId: 'project:other' },
    authority: requirePasskeyAuthority(fixture.context),
  });
  if (result.ok) throw new Error('runtime policy substitution was admitted');

  await expect(result.response.json()).resolves.toMatchObject({ code: 'scope_mismatch' });
  expect(result.response.status).toBe(403);
  expect(sessions.exactReads()).toBe(1);
});

test('exact ECDSA session cannot cross into a sibling Passkey method', async () => {
  const fixture = await buildEcdsaSigningSessionSealAdmissionFixture();
  const sessions = buildAuthorizationSessionFixture(fixture.context);
  const result = await resolveReusedEcdsaWalletSession({
    authorizationSessions: sessions.service,
    walletRegistration: fixture.walletRegistration,
    headers: new Headers({ authorization: `Bearer ${fixture.token}` }),
    runtimePolicyScope,
    authority: buildPasskeyWalletAuthAuthority({
      walletId: fixture.context.authority.walletId,
      rpId: 'wallet.example.test',
      credentialIdB64u: 'sibling-passkey-credential',
    }),
  });
  if (result.ok) throw new Error('sibling Passkey method was admitted');

  await expect(result.response.json()).resolves.toMatchObject({ code: 'scope_mismatch' });
  expect(result.response.status).toBe(403);
  expect(sessions.exactReads()).toBe(1);
});

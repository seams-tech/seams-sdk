import { expect, test } from '@playwright/test';
import {
  createRouterApiRouteDefinitions,
  findRouteDefinitionById,
} from '../../packages/sdk-server-ts/src/router/framework/routeDefinitions';
import { handleWalletRecoveryPrepare } from '../../packages/sdk-server-ts/src/router/transport/fetch/routes/passkeyCustody';
import {
  buildActiveAuthorizationSession,
  buildAuthorizedOperation,
  parseSessionOrigin,
} from '../../packages/sdk-server-ts/src/authorization/domain';
import { buildVerifiedFactorEvidenceSet } from '../../packages/sdk-server-ts/src/authorization/factorEvidence';
import {
  parseDeviceId,
  parsePrincipalId,
  parseSeamsSessionId,
  parseTenantId,
} from '../../packages/shared-ts/src/authorization/capabilityKinds';
import {
  parseAppSessionVersion,
  parseProviderSubject,
  parseWalletAuthorityBindingDigest,
  parseWalletId,
} from '../../packages/shared-ts/src/utils/domainIds';
import { parseWalletAuthAuthorityRef } from '../../packages/shared-ts/src/utils/walletAuthAuthority';

const routeDefinitions = createRouterApiRouteDefinitions();
const NOW = Date.now();
const ORIGIN = 'https://wallet.localhost';
const VALID_BODY = {
  walletId: 'alice.testnet',
  recoveryCode: 'QUJDREVGR0hJSktMTU5PUFFSU1Q',
  reservationId: 'recovery-operation-1',
  challengeId: 'challenge-1',
  otpCode: '123456',
};

function parsed<T>(
  value: string,
  parser: (raw: unknown) => { readonly ok: true; readonly value: T } | { readonly ok: false },
): T {
  const result = parser(value);
  if (!result.ok) throw new Error(`invalid test fixture: ${value}`);
  return result.value;
}

async function authorizedContext(input: {
  readonly custodyResult: unknown;
  readonly seen: { otp: number; admission: number; custody: number };
}) {
  const tenantId = parsed('tenant-recovery', parseTenantId);
  const principalId = parsed('principal-recovery', parsePrincipalId);
  const sessionId = parsed('session-recovery', parseSeamsSessionId);
  const deviceId = parsed('device-recovery', parseDeviceId);
  const walletId = parsed(VALID_BODY.walletId, parseWalletId);
  const authorityRef = parseWalletAuthAuthorityRef({
    kind: 'wallet_auth_authority_ref',
    walletId,
    authorityDigest: parsed('authority-recovery', parseWalletAuthorityBindingDigest),
  });
  if (!authorityRef) throw new Error('invalid authority fixture');
  const activeSession = buildActiveAuthorizationSession({
    tenantId,
    principalId,
    sessionId,
    authSource: {
      kind: 'oidc_provider',
      providerId: 'oidc',
      providerSubject: parsed('provider-recovery', parseProviderSubject),
    },
    deviceId,
    audience: { kind: 'first_party_web', origin: parseSessionOrigin(ORIGIN) },
    appSessionVersion: parsed('app-session-recovery', parseAppSessionVersion),
    assurance: 'session',
    createdAtMs: NOW - 1_000,
    lifecycle: { kind: 'active', expiresAtMs: NOW + 60_000 },
  });
  const claims = {
    kind: 'app_session_v1',
    sub: principalId,
    appSessionVersion: activeSession.appSessionVersion,
    seamsSessionId: sessionId,
    walletId,
    walletAuthAuthorityRef: authorityRef,
    runtimePolicyScope: {
      orgId: tenantId,
      projectId: 'project-recovery',
      envId: 'env-recovery',
      signingRootVersion: 'root-v1',
    },
    tenantId,
    exp: Math.floor((NOW + 60_000) / 1_000),
  };
  const request = new Request('https://relay.localhost/wallets/recovery/prepare', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: ORIGIN },
    body: JSON.stringify(VALID_BODY),
  });
  return {
    routeDefinitions,
    method: 'POST',
    pathname: '/wallets/recovery/prepare',
    request,
    service: {
      authorizationSessions: {
        tenantId,
        readActiveSession: async () => activeSession,
      },
      authorizedOperations: {
        tenantId,
        readAuthorizedOperation: async () => null,
        recordVerifiedFactorEvidenceSet: buildVerifiedFactorEvidenceSet,
        admitAuthorizedOperation: async ({ operation }: { operation: never }) => {
          input.seen.admission += 1;
          return { kind: 'claimed' as const, operation: await buildAuthorizedOperation(operation) };
        },
      },
      emailOtp: {
        verifyEmailOtpChallenge: async () => {
          input.seen.otp += 1;
          return {
            ok: true as const,
            challengeId: 'challenge-1',
            loginGrant: 'grant-1',
            grantExpiresAtMs: NOW + 30_000,
            otpChannel: 'email_otp' as const,
          };
        },
        consumeEmailOtpGrant: async () => ({ ok: true as const, challengeId: 'challenge-1' }),
      },
      passkeyCustody: {
        prepareRecovery: async () => {
          input.seen.custody += 1;
          return input.custodyResult;
        },
      },
    },
    logger: { error: () => {}, warn: () => {}, info: () => {}, debug: () => {} },
    opts: {
      session: {
        signJwt: async () => 'unused',
        verifyJwt: async () => ({ valid: false as const }),
        parse: async () => ({ ok: true as const, claims }),
        buildSetCookie: () => '',
        buildClearCookie: () => '',
        refresh: async () => ({ ok: false }),
      },
    },
  } as never;
}

test('the admitted prepare route is registered without a consume-first route', () => {
  const route = findRouteDefinitionById(routeDefinitions, 'wallet_recovery_prepare');
  expect(route?.path).toBe('/wallets/recovery/prepare');
  expect(findRouteDefinitionById(routeDefinitions, 'wallet_recovery_code_spend')).toBeNull();
});

test('fresh Email OTP admission happens before the recovery code is reserved', async () => {
  const seen = { otp: 0, admission: 0, custody: 0 };
  const response = await handleWalletRecoveryPrepare(
    await authorizedContext({
      seen,
      custodyResult: {
        kind: 'prepared',
        wrap: { nonceB64u: 'n', wrappedManifestKekB64u: 'k', aadHashB64u: 'a' },
        entries: [],
        reservationId: VALID_BODY.reservationId,
        reservationExpiresAtMs: NOW + 120_000,
        storeVersion: '5',
      },
    }),
  );
  expect(response?.status).toBe(200);
  expect(seen).toEqual({ otp: 1, admission: 1, custody: 1 });
  expect(await response!.json()).toMatchObject({
    ok: true,
    reservationId: VALID_BODY.reservationId,
  });
});

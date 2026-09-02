import { expect, test } from '@playwright/test';
import {
  handleOwnerWalletExecutionLanePreflight,
  OWNER_WALLET_EXECUTION_LANE_PREFLIGHT_PATH,
} from '../../packages/wallet-server/src/router/transport/fetch/routes/walletExecutionLanePreflight';
import {
  resolveActiveOwnerWalletExecutionLane,
  type WalletExecutionLaneProjectionSource,
} from '../../packages/wallet-server/src/core/signingLanes/WalletExecutionLaneProjection';
import type { RouterApiWalletRegistrationService } from '../../packages/wallet-server/src/router/framework/authServicePort';
import type { RouterApiWalletSessionAuthorizationV2AdmissionContext } from '../../packages/wallet-server/src/router/framework/authServicePort';
import type { SessionAdapter } from '../../packages/wallet-server/src/router/framework/routerApi';
import type { FetchRouterApiContext } from '../../packages/wallet-server/src/router/transport/fetch/createFetchRouter';
import {
  buildYaoEd25519WalletSignerRecord,
  ed25519NearPublicKeyFromBytes,
} from '../../packages/wallet-server/src/router/cloudflare/d1/ed25519Yao/d1Ed25519YaoWalletSigner';
import { parseWalletId } from '../../packages/shared-ts/src/utils/domainIds';
import { routerAbMpcMaterialActivationRefFromWire } from '../../packages/shared-ts/src/utils/routerAbNormalSigningIdentity';
import { buildRouterAbEd25519YaoCapabilityReplacementFixture } from './helpers/routerAbEd25519YaoRecoveryRequestScoped.fixtures';
import { buildFullOwnerPermissionsV1 } from '../../packages/shared-ts/src/authorization/delegatedAuthority';
import { buildLinkedDeviceManagementAuthorityFixture } from './helpers/linkedDeviceManagement.fixtures';

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}

function sessionWithClaims(claims: Record<string, unknown>): SessionAdapter {
  return {
    signJwt: async () => 'unused',
    verifyJwt: async () => ({ valid: false as const }),
    parse: async () => ({ ok: true as const, claims }),
    buildSetCookie: (token) => `session=${token}`,
    buildClearCookie: () => 'session=',
    refresh: async () => ({ ok: false }),
  };
}

function context(
  request: Request,
  session: SessionAdapter,
  service: Record<string, unknown>,
): FetchRouterApiContext {
  return {
    request,
    url: new URL(request.url),
    pathname: new URL(request.url).pathname,
    method: request.method,
    runtime: { kind: 'inline' },
    service,
    opts: { session },
    logger: {},
    mePath: '/me',
    routeDefinitions: [],
  } as unknown as FetchRouterApiContext;
}

test('owner execution-lane preflight authenticates the Wallet Session and serializes the exact projection', async () => {
  const fixture = buildRouterAbEd25519YaoCapabilityReplacementFixture();
  const capability = fixture.next;
  const walletId = required(parseWalletId(fixture.walletId));
  const application = capability.admissionRequest.application_binding;
  const scope = capability.admissionRequest.scope;
  const materialActivation = routerAbMpcMaterialActivationRefFromWire(
    capability.activationResult.public_receipt.material_activation,
  );
  const exact = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'owner-execution-lane-preflight',
    permissions: buildFullOwnerPermissionsV1(),
    provenance: 'wallet_registration',
    keyFamily: 'ed25519',
    materialActivation,
    expiresAtMs: Date.now() + 60_000,
    identity: {
      walletId: fixture.walletId,
      authorityId: 'authority:owner-execution-lane-preflight',
      walletAuthMethodId: 'wallet-auth-method:owner-execution-lane-preflight',
      rpId: 'router.example.test',
    },
  });
  const signer = buildYaoEd25519WalletSignerRecord({
    walletId,
    nearAccountId: fixture.nearAccountId,
    nearEd25519SigningKeyId: fixture.nearSigningKeyId,
    thresholdSessionId: scope.threshold_session_id,
    signerSlot: application.key_creation_signer_slot,
    publicKey: ed25519NearPublicKeyFromBytes(
      capability.activationResult.public_receipt.registered_public_key,
    ),
    signingWorkerId: fixture.signingWorkerId,
    keyVersion: 'yao-recovery-key-v1',
    participantIds: capability.admissionRequest.participant_ids,
    signingRootId: application.signing_root_id,
    signingRootVersion: scope.root_share_epoch,
    runtimePolicyScope: capability.runtimePolicyScope,
    activeYaoCapability: capability,
    custodyKeyManifestDigestB64u: Buffer.alloc(32, 21).toString('base64url'),
    now: 1_900_000_000_000,
  });
  const authMethod = exact.authMethod;
  const projectionResult = await resolveActiveOwnerWalletExecutionLane({
    source: {
      listWalletAuthMethods: async () => [authMethod],
      listWalletSigners: async () => [signer],
    } satisfies WalletExecutionLaneProjectionSource,
    walletId,
    walletAuthMethodId: authMethod.walletAuthMethodId,
    expectedMaterialActivation: materialActivation,
  });
  if (projectionResult.kind !== 'projected') {
    throw new Error(`projection fixture refused: ${projectionResult.reason}`);
  }

  const admissionContext: RouterApiWalletSessionAuthorizationV2AdmissionContext = {
    authorization: exact.issuedSession,
    authority: exact.authority,
    authMethod: exact.authMethod,
    retiredAtMs: null,
  };
  const authorizationSessions = {
    tenantId: exact.issuedSession.session.tenantId,
    readWalletSessionAuthorizationV2ByOperationCredential: async () => admissionContext,
  };

  let received:
    | Parameters<RouterApiWalletRegistrationService['resolveActiveOwnerWalletExecutionLane']>[0]
    | null = null;
  const walletRegistration = {
    resolveActiveOwnerWalletExecutionLane: async (
      input: Parameters<
        RouterApiWalletRegistrationService['resolveActiveOwnerWalletExecutionLane']
      >[0],
    ) => {
      received = input;
      return projectionResult;
    },
  };
  const body = {
    curve: 'ed25519',
    expectedMaterialActivation: JSON.parse(JSON.stringify(materialActivation)),
  };
  const request = new Request(
    `https://router.example.test${OWNER_WALLET_EXECUTION_LANE_PREFLIGHT_PATH}`,
    {
      method: 'POST',
      headers: {
        authorization: 'Bearer owner-wallet-session',
        'content-type': 'application/json',
      },
      body: JSON.stringify(body),
    },
  );
  const response = await handleOwnerWalletExecutionLanePreflight(
    context(request, sessionWithClaims({}), {
      walletRegistration,
      authorizationSessions,
    }),
  );

  expect(response?.status).toBe(200);
  expect(received?.walletId).toBe(walletId);
  expect(received?.authorization).toEqual({
    kind: 'wallet_auth_method',
    walletAuthMethodId: authMethod.walletAuthMethodId,
  });
  await expect(response?.json()).resolves.toMatchObject({
    ok: true,
    projection: {
      kind: 'active_owner_wallet_execution_lane_projection_v1',
      walletKey: { keyFamily: 'ed25519', walletId: fixture.walletId },
      lane: { laneKind: 'owner_passkey', walletId: fixture.walletId },
      materialActivation: body.expectedMaterialActivation,
    },
  });
});

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
import type { SessionAdapter } from '../../packages/wallet-server/src/router/framework/routerApi';
import type { FetchRouterApiContext } from '../../packages/wallet-server/src/router/transport/fetch/createFetchRouter';
import { normalizeWalletAuthMethod } from '../../packages/wallet-server/src/core/d1WalletAuthMethodStore';
import {
  buildYaoEd25519WalletSignerRecord,
  ed25519NearPublicKeyFromBytes,
} from '../../packages/wallet-server/src/router/cloudflare/d1/ed25519Yao/d1Ed25519YaoWalletSigner';
import { walletAuthMethodRecordId } from '../../packages/shared-ts/src/utils/registrationIntent';
import { parseWalletId } from '../../packages/shared-ts/src/utils/domainIds';
import { routerAbMpcMaterialActivationRefFromWire } from '../../packages/shared-ts/src/utils/routerAbNormalSigningIdentity';
import { buildPasskeyWalletAuthAuthority } from '../../packages/shared-ts/src/utils/walletAuthAuthority';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '../../packages/shared-ts/src/utils/signingSessionSeal';
import { buildRouterAbEd25519WalletSessionClaimsFixture } from './helpers/routerAbEd25519WalletSessionClaims.fixtures';
import { buildRouterAbEd25519YaoCapabilityReplacementFixture } from './helpers/routerAbEd25519YaoRecoveryRequestScoped.fixtures';

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
  const authMethod = normalizeWalletAuthMethod({
    version: 'wallet_auth_method_v1',
    kind: 'passkey',
    status: 'active',
    walletId,
    rpId: 'router.example.test',
    credentialIdB64u: 'recovery-request-scoped-credential-1',
    credentialPublicKeyB64u: 'public-key-r101-preflight',
    counter: 0,
    createdAtMs: 1_900_000_000_000,
    updatedAtMs: 1_900_000_000_000,
  });
  if (!authMethod) throw new Error('preflight auth method fixture is invalid');
  const projectionResult = await resolveActiveOwnerWalletExecutionLane({
    source: {
      listWalletAuthMethods: async () => [authMethod],
      listWalletSigners: async () => [signer],
    } satisfies WalletExecutionLaneProjectionSource,
    walletId,
    walletAuthMethodId: walletAuthMethodRecordId(authMethod),
    expectedMaterialActivation: materialActivation,
  });
  if (projectionResult.kind !== 'projected') {
    throw new Error(`projection fixture refused: ${projectionResult.reason}`);
  }

  const authority = buildPasskeyWalletAuthAuthority({
    walletId: fixture.walletId,
    rpId: 'router.example.test',
    credentialIdB64u: 'recovery-request-scoped-credential-1',
  });
  const claims = buildRouterAbEd25519WalletSessionClaimsFixture({
    walletId: fixture.walletId,
    nearAccountId: fixture.nearAccountId,
    nearEd25519SigningKeyId: fixture.nearSigningKeyId,
    relayerKeyId: fixture.signingWorkerId,
    participantIds: [1, 2],
    thresholdExpiresAtMs: Date.now() + 60_000,
    runtimePolicyScope: capability.runtimePolicyScope,
    normalSigning: {
      kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
      signingWorkerId: fixture.signingWorkerId,
    },
    authority,
    walletSessionId: fixture.walletSessionId,
    quotaId: fixture.quotaId,
    thresholdSessionId: fixture.thresholdSessionId,
  });

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
    context(request, sessionWithClaims(claims), { walletRegistration }),
  );

  expect(response?.status).toBe(200);
  expect(received?.walletId).toBe(walletId);
  expect(received?.authorization).toEqual({
    kind: 'wallet_auth_method',
    walletAuthMethodId: walletAuthMethodRecordId(authMethod),
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

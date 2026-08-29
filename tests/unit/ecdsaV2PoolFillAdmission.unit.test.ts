import { expect, test } from '@playwright/test';
import { buildWalletSessionCapabilitySubjectsV1 } from '../../packages/wallet-server/src/authorization/domain';
import {
  buildActiveWalletSessionQuota,
  buildWalletSessionAuthorizationV2,
} from '../../packages/wallet-server/src/authorization/domain';
import type { FetchRouterApiContext } from '../../packages/wallet-server/src/router/transport/fetch/fetchRouter.types';
import {
  parseRouterAbEcdsaDerivationPoolFillInitRouteRequest,
  parseRouterAbEcdsaDerivationPoolFillStepRouteRequest,
} from '../../packages/wallet-server/src/router/domains/ecdsa/thresholdEcdsaRequestValidation';
import { authorizeEcdsaPoolFill } from '../../packages/wallet-server/src/router/transport/fetch/routes/thresholdEcdsa';
import {
  parseMpcWalletSigningQuotaId,
  parsePrincipalId,
  parseWalletSessionMintId,
  parseTenantId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '../../packages/shared-ts/src/authorization/capabilityKinds';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';
import { parseDigestB64u } from '../../packages/shared-ts/src/utils/canonicalPrimitives';
import { routerAbMpcMaterialActivationRefToWire } from '../../packages/shared-ts/src/utils/routerAbNormalSigningIdentity';
import type { RouterAbEcdsaDerivationNormalSigningStateV1 } from '../../packages/shared-ts/src/utils/routerAbEcdsaDerivation';
import { buildLinkedDeviceUnlockRuntimeFixture } from './helpers/linkedDeviceUnlockRuntime.fixtures';

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

function bytes(length: number, value: number): Uint8Array {
  return new Uint8Array(length).fill(value);
}

test('V2 operation credential authorizes linked ECDSA pool fill without legacy fallback', async () => {
  const fixture = await buildLinkedDeviceUnlockRuntimeFixture();
  const ecdsaActivation = fixture.authority.signerActivations.ecdsa;
  if (!ecdsaActivation) throw new Error('linked ECDSA authority fixture is missing');
  const nowMs = Date.now();
  const tenantId = required(parseTenantId('tenant:v2-pool-fill'));
  const principalId = required(parsePrincipalId('principal:v2-pool-fill'));
  const authorizationId = required(parseWalletSessionAuthorizationId('authorization:v2-pool-fill'));
  const exactWalletSessionId = required(
    parseWalletSessionId(String(fixture.operationCredential.walletSessionId)),
  );
  const quotaId = required(parseMpcWalletSigningQuotaId('quota:v2-pool-fill'));
  const session = buildWalletSessionAuthorizationV2({
    tenantId,
    principalId,
    walletId: fixture.walletId,
    authorityId: fixture.authority.authorityId,
    walletAuthMethodId: fixture.authMethod.walletAuthMethodId,
    authorityDigestB64u: fixture.authority.authorityDigestB64u,
    authorityRevocationEpoch: fixture.authority.revocationEpoch,
    mintId: required(parseWalletSessionMintId('mint:v2-pool-fill')),
    authorizationId,
    walletSessionId: exactWalletSessionId,
    quotaId,
    capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(fixture.authority),
    createdAtMs: nowMs - 1_000,
    expiresAtMs: nowMs + 60_000,
  });
  const quota = buildActiveWalletSessionQuota({
    tenantId,
    principalId,
    walletSessionId: exactWalletSessionId,
    quotaId,
    remainingUses: 5,
    expiresAtMs: session.expiresAtMs,
  });
  const materialActivation = routerAbMpcMaterialActivationRefToWire(
    ecdsaActivation.materialActivation,
  );
  const normalSigning: RouterAbEcdsaDerivationNormalSigningStateV1 = {
    kind: 'router_ab_ecdsa_derivation_normal_signing_v1',
    scope: {
      wallet_id: String(fixture.walletId),
      ecdsa_threshold_key_id: 'ecdsa-threshold-key:v2-pool-fill',
      signing_root_id: 'project:v2-pool-fill',
      signing_root_version: 'v1',
      context: { application_binding_digest_b64u: parseDigestB64u(base64UrlEncode(bytes(32, 1))) },
      public_identity: {
        context_binding_b64u: base64UrlEncode(bytes(32, 2)),
        derivation_client_share_public_key33_b64u: base64UrlEncode(
          new Uint8Array([2, ...bytes(32, 3)]),
        ),
        server_public_key33_b64u: base64UrlEncode(new Uint8Array([2, ...bytes(32, 4)])),
        threshold_public_key33_b64u: ecdsaActivation.signer.thresholdPublicKey33B64u,
        ethereum_address20_b64u: base64UrlEncode(bytes(20, 0x11)),
        client_share_retry_counter: 0,
        server_share_retry_counter: 0,
      },
      material_activation: materialActivation,
      signing_worker: {
        server_id: String(ecdsaActivation.materialActivation.signingWorker),
        key_epoch: 'epoch:v2-pool-fill',
        recipient_encryption_key: `x25519:${'05'.repeat(32)}`,
      },
      activation_epoch: 'v1',
    },
  };
  const parsedRequest = parseRouterAbEcdsaDerivationPoolFillInitRouteRequest({
    keyHandle: 'ecdsa-key-handle:v2-pool-fill',
    count: 1,
    poolFill: {
      kind: 'router_ab_ecdsa_derivation_signing_worker_pool',
      scope: normalSigning.scope,
      expiresAtMs: nowMs + 30_000,
    },
    authorization: {
      kind: 'reusable_wallet_session',
      wallet_session_id: String(exactWalletSessionId),
    },
  });
  if (!parsedRequest.ok) throw new Error(parsedRequest.body.message);

  let legacyFallbacks = 0;
  const admittedOperationCredentials: string[] = [];
  const request = new Request('https://wallet.example.test/router-ab/pool-fill', {
    headers: { authorization: `Bearer ${fixture.operationCredential.token}` },
  });
  const ctx = {
    request,
    service: {
      authorizationSessions: {
        tenantId,
        async readWalletSessionAuthorizationV2ByOperationCredential(input: {
          readonly token: string;
        }) {
          admittedOperationCredentials.push(input.token);
          return {
            authorization: { session, quota },
            authority: fixture.authority,
            authMethod: fixture.authMethod,
            retiredAtMs: null,
          };
        },
        async resolveOpaqueWalletSessionToken() {
          legacyFallbacks += 1;
          return null;
        },
      },
      walletRegistration: {
        async resolveEcdsaMaterialActivation() {
          return {
            ok: true as const,
            materialActivation,
            keyHandle: 'ecdsa-key-handle:v2-pool-fill',
            relayerKeyId: 'relayer-key:v2-pool-fill',
            participantIds: [1, 2] as const,
            runtimePolicyScope: {
              orgId: String(tenantId),
              projectId: 'project:v2-pool-fill',
              envId: 'test',
              signingRootVersion: 'v1',
            },
            routerAbEcdsaDerivationNormalSigning: normalSigning,
          };
        },
      },
    },
  } as unknown as FetchRouterApiContext;

  const authorized = await authorizeEcdsaPoolFill({ ctx, request: parsedRequest.request });
  const parsedStep = parseRouterAbEcdsaDerivationPoolFillStepRouteRequest({
    presignSessionId: 'presign-session:v2-pool-fill',
    stage: 'triples',
    outgoingMessagesB64u: [],
    authorization: {
      kind: 'reusable_wallet_session',
      wallet_session_id: String(exactWalletSessionId),
    },
  });
  if (!parsedStep.ok) throw new Error(parsedStep.body.message);
  const authorizedStep = await authorizeEcdsaPoolFill({ ctx, request: parsedStep.request });

  expect(legacyFallbacks).toBe(0);
  expect(admittedOperationCredentials).toEqual([
    fixture.operationCredential.token,
    fixture.operationCredential.token,
  ]);
  expect(authorized).toMatchObject({
    ok: true,
    binding: {
      walletId: fixture.walletId,
      keyHandle: 'ecdsa-key-handle:v2-pool-fill',
      thresholdExpiresAtMs: session.expiresAtMs,
      routerAbEcdsaDerivationNormalSigning: normalSigning,
    },
  });
  expect(authorizedStep).toEqual(authorized);
  expect(authorizedStep).toMatchObject({
    ok: true,
    binding: {
      walletId: fixture.authority.walletId,
      routerAbEcdsaDerivationNormalSigning: {
        scope: { material_activation: materialActivation },
      },
    },
  });
});

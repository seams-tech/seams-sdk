import { parseLinkDeviceSessionId, type LinkDeviceSessionId } from '@shared/signing-lanes/ids';
import type { D1DatabaseLike } from '../../../../storage/tenantRoute';
import type {
  DeviceLinkingAuthDeniedV1,
  DeviceLinkingAuthenticatedRequestV1,
  DeviceLinkingDeviceAuthenticatedRequestV1,
  DeviceLinkingOwnerRequestInputV1,
  DeviceLinkingRouteServiceV1,
} from '../../../../router/transport/fetch/routes/deviceLinking';
import { LinkedDeviceRequestProofVerifierV1 } from '../../../../core/deviceLinking/requestProof';
import type { LinkedDeviceOwnerAuthorizationPortV1 } from '../../../../core/deviceLinking/linkedDeviceSession';
import { readJson } from '../../../../router/framework/http';
import { D1LinkedDeviceEd25519ExportRootStoreV1 } from './d1LinkedDeviceEd25519ExportRootStore';
import { D1LinkedDeviceRequestProofNonceStoreV1 } from './d1LinkedDeviceRequestProofNonceStore';
import { createD1LinkedDeviceSessionServiceV1 } from './d1LinkedDeviceSessionService';
import type { D1LinkedDeviceSessionScopeV1 } from './d1LinkedDeviceSessionStore';

export type D1LinkedDeviceRouteServiceOptionsV1 = {
  readonly database: D1DatabaseLike;
  readonly scope: D1LinkedDeviceSessionScopeV1;
  readonly ownerAuthorization: LinkedDeviceOwnerAuthorizationPortV1;
  readonly emailOtpBaseFactors?: Parameters<
    typeof createD1LinkedDeviceSessionServiceV1
  >[0]['emailOtpBaseFactors'];
  readonly emailOtpTargetFactor?: DeviceLinkingRouteServiceV1['emailOtpTargetFactor'];
  readonly authenticateOwnerRequestV1: (
    input: DeviceLinkingOwnerRequestInputV1,
  ) => Promise<DeviceLinkingAuthenticatedRequestV1 | DeviceLinkingAuthDeniedV1>;
  readonly targetCredential: DeviceLinkingRouteServiceV1['targetCredential'];
  readonly installationReceipt?: DeviceLinkingRouteServiceV1['installationReceipt'];
  readonly nowV1?: () => number;
};

export function createD1LinkedDeviceRouteServiceV1(
  options: D1LinkedDeviceRouteServiceOptionsV1,
): DeviceLinkingRouteServiceV1 {
  const nowV1 = options.nowV1 ?? Date.now;
  const proofNonceStore = new D1LinkedDeviceRequestProofNonceStoreV1({
    database: options.database,
    scope: options.scope,
  });
  const proofVerifier = new LinkedDeviceRequestProofVerifierV1({ nonceStore: proofNonceStore });
  const { sessionService } = createD1LinkedDeviceSessionServiceV1({
    database: options.database,
    scope: options.scope,
    ownerAuthorization: options.ownerAuthorization,
    ...(options.emailOtpBaseFactors === undefined
      ? {}
      : { emailOtpBaseFactors: options.emailOtpBaseFactors }),
    nowV1,
  });

  const routeSessionService: DeviceLinkingRouteServiceV1['sessionService'] = {
    createUnclaimedSessionV1: sessionService.createUnclaimedSessionV1.bind(sessionService),
    claimSessionV1: sessionService.claimSessionV1.bind(sessionService),
    recordOwnerApprovalV1: sessionService.recordOwnerApprovalV1.bind(sessionService),
    recordTargetCredentialV1: sessionService.recordTargetCredentialV1.bind(sessionService),
    recordSourceContributionV1: sessionService.recordSourceContributionV1.bind(sessionService),
    recordEmailOtpChallengeStateV1:
      sessionService.recordEmailOtpChallengeStateV1.bind(sessionService),
    cancelSessionV1: sessionService.cancelSessionV1.bind(sessionService),
    getSessionV1: sessionService.getSessionV1.bind(sessionService),
    listSessionsForWalletV1: sessionService.listSessionsForWalletV1.bind(sessionService),
  };

  return {
    sessionService: routeSessionService,
    nowV1,
    ...(options.emailOtpTargetFactor === undefined
      ? {}
      : { emailOtpTargetFactor: options.emailOtpTargetFactor }),
    ed25519ExportRoot: new D1LinkedDeviceEd25519ExportRootStoreV1({
      database: options.database,
      scope: options.scope,
    }),
    verifyPublicSessionProofV1: async (input) => {
      const result = await proofVerifier.verifyPublicCreateV1({
        proof: input.proof,
        devicePublicKeyB64u: input.payload.devicePublicKeyB64u,
        devicePublicKeyDigestB64u: input.devicePublicKeyDigestB64u,
        linkSessionId: input.payload.linkSessionId,
        method: input.method,
        canonicalPath: input.canonicalPath,
        bodyDigestB64u: input.bodyDigestB64u,
        nowMs: input.requestedAtMs,
      });
      return result.kind === 'authorized' ? result : mapProofDenied(result);
    },
    authenticateOwnerRequestV1: options.authenticateOwnerRequestV1,
    authenticateDeviceRequestV1: async (input) => {
      const linkSessionId = parseSessionId(input.linkSessionId);
      const result = await proofVerifier.verifyV1({
        proof: input.proof,
        expectedDevicePublicKeyB64u: input.expectedDevicePublicKeyB64u,
        expectedDevicePublicKeyDigestB64u: input.expectedDevicePublicKeyDigestB64u,
        expectedLinkSessionId: linkSessionId,
        expectedMethod: input.method,
        expectedCanonicalPath: input.pathname,
        expectedBodyDigestB64u: input.bodyDigestB64u,
        nowMs: input.requestedAtMs,
      });
      if (result.kind === 'denied') return mapProofDenied(result);
      const body = input.method === 'GET' ? null : await readJson(input.request);
      return {
        kind: 'authorized',
        body,
        proof: input.proof,
      } satisfies DeviceLinkingDeviceAuthenticatedRequestV1;
    },
    targetCredential: options.targetCredential,
    ...(options.installationReceipt === undefined
      ? {}
      : { installationReceipt: options.installationReceipt }),
  };
}

function parseSessionId(raw: string): LinkDeviceSessionId {
  const result = parseLinkDeviceSessionId(raw);
  if (!result.ok) throw new Error(`link session id is invalid: ${result.error.message}`);
  return result.value;
}

function mapProofDenied(
  result: Extract<
    Awaited<ReturnType<LinkedDeviceRequestProofVerifierV1['verifyV1']>>,
    { readonly kind: 'denied' }
  >,
): DeviceLinkingAuthDeniedV1 {
  return {
    kind: 'denied',
    code: result.code,
    message: result.message,
  };
}

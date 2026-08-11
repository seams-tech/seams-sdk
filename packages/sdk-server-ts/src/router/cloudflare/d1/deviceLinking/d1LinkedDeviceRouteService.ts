import { parseLinkDeviceSessionId, type LinkDeviceSessionId } from '@shared/signing-lanes/ids';
import { readJson } from '../../../../router/framework/http';
import { LinkedDeviceRequestProofVerifierV1 } from '../../../../core/deviceLinking/requestProof';
import { type LinkedDeviceOwnerAuthorizationPortV1 } from '../../../../core/deviceLinking/linkedDeviceSession';
import type { D1DatabaseLike } from '../../../../storage/tenantRoute';
import { D1LinkedDeviceRequestProofNonceStoreV1 } from './d1LinkedDeviceRequestProofNonceStore';
import { type D1LinkedDeviceSessionScopeV1 } from './d1LinkedDeviceSessionStore';
import { CloudflareD1LaneLifecycleStore } from '../signingLanes/d1LaneLifecycleStore';
import { createD1LinkedDeviceSessionServiceV1 } from './d1LinkedDeviceSessionService';
import { D1LinkedDeviceProvisioningVerifierV1 } from './d1LinkedDeviceProvisioningVerifier';
import {
  D1LinkedDeviceWalletSessionIssuerV1,
  type ActiveLinkedDeviceSessionRecordV1,
} from './d1LinkedDeviceWalletSessionIssuer';
import type { AuthorizationService } from '../../../../authorization/service';
import type { TenantId } from '@shared/authorization/capabilityKinds';
import { alphabetizeStringify } from '@shared/utils/digests';
import type {
  DeviceLinkingAuthenticatedRequestV1,
  DeviceLinkingAuthDeniedV1,
  DeviceLinkingDeviceAuthenticatedRequestV1,
  DeviceLinkingOwnerRequestInputV1,
  DeviceLinkingOperatorRecoveryProviderV1,
  DeviceLinkingOwnerSourceHandoffProviderV1,
  DeviceLinkingRouteServiceV1,
} from '../../../../router/transport/fetch/routes/deviceLinking';

export type D1LinkedDeviceRouteServiceOptionsV1 = {
  readonly database: D1DatabaseLike;
  readonly scope: D1LinkedDeviceSessionScopeV1;
  readonly tenantId: TenantId;
  readonly authorizationService: Pick<
    AuthorizationService,
    | 'getLinkedDeviceWalletSessionStatus'
    | 'issueLinkedDeviceWalletSession'
    | 'readLinkedDeviceWalletSessionAuthorization'
  >;
  readonly ownerAuthorization: LinkedDeviceOwnerAuthorizationPortV1;
  readonly authenticateOwnerRequestV1: (
    input: DeviceLinkingOwnerRequestInputV1,
  ) => Promise<DeviceLinkingAuthenticatedRequestV1 | DeviceLinkingAuthDeniedV1>;
  readonly targetCredential: DeviceLinkingRouteServiceV1['targetCredential'];
  readonly acknowledgeReceiptV1: DeviceLinkingRouteServiceV1['acknowledgeReceiptV1'];
  readonly retryCommittedDeliveryV1: DeviceLinkingRouteServiceV1['retryCommittedDeliveryV1'];
  readonly operatorRecovery?: DeviceLinkingOperatorRecoveryProviderV1;
  readonly provisioning: DeviceLinkingRouteServiceV1['provisioning'];
  readonly sourceHandoff: DeviceLinkingOwnerSourceHandoffProviderV1;
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
  const laneLifecycle = new CloudflareD1LaneLifecycleStore({
    database: options.database,
    scope: options.scope,
    now: nowV1,
  });
  const { sessionService, sessionStore } = createD1LinkedDeviceSessionServiceV1({
    database: options.database,
    scope: options.scope,
    ownerAuthorization: options.ownerAuthorization,
    laneLifecycle,
    nowV1,
  });
  const provisioningVerifier = new D1LinkedDeviceProvisioningVerifierV1({
    lifecycleStore: laneLifecycle,
  });
  const walletSessionIssuer = new D1LinkedDeviceWalletSessionIssuerV1({
    tenantId: options.tenantId,
    authorizationService: options.authorizationService,
    laneLifecycle,
  });
  const acknowledgeReceiptV1 = acknowledgeReceiptAndIssueWalletSessionV1.bind(
    undefined,
    options.acknowledgeReceiptV1,
    walletSessionIssuer,
  );
  const readWalletSessionAuthorizationV1: DeviceLinkingRouteServiceV1['readWalletSessionAuthorizationV1'] =
    async (input) => await walletSessionIssuer.resolveActiveForSessionV1(input);
  const routeSessionService: DeviceLinkingRouteServiceV1['sessionService'] = {
    createUnclaimedSessionV1: sessionService.createUnclaimedSessionV1.bind(sessionService),
    claimSessionV1: sessionService.claimSessionV1.bind(sessionService),
    recordOwnerApprovalV1: sessionService.recordOwnerApprovalV1.bind(sessionService),
    recordTargetCredentialV1: sessionService.recordTargetCredentialV1.bind(sessionService),
    bindRecoveryContinuationV1: sessionService.bindRecoveryContinuationV1.bind(sessionService),
    cancelSessionV1: sessionService.cancelSessionV1.bind(sessionService),
    // A string input is the pre-proof, read-only QR lookup. Authenticated reads
    // use the core service so expiry projection receives the request clock.
    getSessionV1: async (input) =>
      typeof input === 'string'
        ? await sessionStore.getSessionV1(input)
        : await sessionService.getSessionV1(input),
  };
  return {
    sessionService: routeSessionService,
    nowV1,
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
    acknowledgeReceiptV1,
    readWalletSessionAuthorizationV1,
    retryCommittedDeliveryV1: options.retryCommittedDeliveryV1,
    operatorRecovery: options.operatorRecovery,
    provisioning: options.provisioning,
    provisioningVerifier,
    sourceHandoff: options.sourceHandoff,
  };
}

async function acknowledgeReceiptAndIssueWalletSessionV1(
  acknowledgeReceiptV1: DeviceLinkingRouteServiceV1['acknowledgeReceiptV1'],
  walletSessionIssuer: D1LinkedDeviceWalletSessionIssuerV1,
  input: Parameters<DeviceLinkingRouteServiceV1['acknowledgeReceiptV1']>[0],
): ReturnType<DeviceLinkingRouteServiceV1['acknowledgeReceiptV1']> {
  const result = await acknowledgeReceiptV1(input);
  if (
    (result.outcome !== 'applied' && result.outcome !== 'replayed') ||
    !isActiveLinkedDeviceSessionRecord(result.record)
  ) {
    return result;
  }
  if (
    result.record.linkSessionId !== input.acknowledgement.linkSessionId ||
    alphabetizeStringify(result.record.aggregateReceipt) !==
      alphabetizeStringify(input.acknowledgement.receipt)
  ) {
    throw new Error('linked-device receipt acknowledgement returned a different active session');
  }
  await walletSessionIssuer.issueForActiveSessionV1({
    session: result.record,
    requestedAtMs: input.requestedAtMs,
  });
  return result;
}

function isActiveLinkedDeviceSessionRecord(
  record: DeviceLinkingRouteMutationResultV1Record,
): record is ActiveLinkedDeviceSessionRecordV1 {
  return record.state.state === 'active';
}

type DeviceLinkingRouteMutationResultV1Record = Extract<
  Awaited<ReturnType<DeviceLinkingRouteServiceV1['acknowledgeReceiptV1']>>,
  { readonly outcome: 'applied' | 'replayed' }
>['record'];

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

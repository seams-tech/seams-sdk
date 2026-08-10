import type { LinkedDeviceOwnerAuthorizationPortV1 } from '../../../../core/deviceLinking/linkedDeviceSession';
import type { LaneLifecycleStore } from '../../../../core/signingLanes/LaneLifecycleStore';
import type { D1DatabaseLike } from '../../../../storage/tenantRoute';
import type {
  DeviceLinkingGatewayAuthDeniedV1,
  DeviceLinkingGatewayAuthenticatedRequestV1,
  DeviceLinkingGatewayCompletionServiceV1,
} from '../../../../router/transport/fetch/routes/deviceLinkingGateway';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import type { D1LinkedDeviceSessionScopeV1 } from './d1LinkedDeviceSessionStore';
import { createD1LinkedDeviceSessionServiceV1 } from './d1LinkedDeviceSessionService';

export type D1LinkedDeviceGatewayCompletionServiceOptionsV1 = {
  readonly database: D1DatabaseLike;
  readonly scope: D1LinkedDeviceSessionScopeV1;
  readonly ownerAuthorization: LinkedDeviceOwnerAuthorizationPortV1;
  readonly laneLifecycle: Pick<
    LaneLifecycleStore,
    'getEnrollment' | 'getProtocol' | 'listEnrollmentProductEpochs'
  >;
  readonly nowV1: () => number;
  readonly authenticateGatewayRequestV1: (input: {
    readonly request: Request;
    readonly method: string;
    readonly pathname: string;
    readonly bodyDigestB64u: DigestB64u;
    readonly requestedAtMs: number;
  }) => Promise<
    | DeviceLinkingGatewayAuthenticatedRequestV1
    | DeviceLinkingGatewayAuthDeniedV1
  >;
};

export function createD1LinkedDeviceGatewayCompletionServiceV1(
  options: D1LinkedDeviceGatewayCompletionServiceOptionsV1,
): DeviceLinkingGatewayCompletionServiceV1 {
  const { sessionService } = createD1LinkedDeviceSessionServiceV1({
    database: options.database,
    scope: options.scope,
    ownerAuthorization: options.ownerAuthorization,
    laneLifecycle: options.laneLifecycle,
    nowV1: options.nowV1,
  });
  return {
    sessionService,
    nowV1: options.nowV1,
    authenticateGatewayRequestV1: options.authenticateGatewayRequestV1,
  };
}

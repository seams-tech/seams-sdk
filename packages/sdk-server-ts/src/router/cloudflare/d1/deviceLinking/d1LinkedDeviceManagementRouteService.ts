import type { DeviceManagementRouteServiceV1 } from '../../../../router/transport/fetch/routes/deviceManagement';
import {
  LinkedDeviceManagementServiceV1,
  type LinkedDeviceAggregateRevocationPortV1,
  type LinkedDeviceLocalStateInvalidationPortV1,
  type LinkedDeviceRevocationPreparationPortV1,
  type LinkedDeviceWalletSessionRevocationPortV1,
} from '../../../../core/deviceLinking/linkedDeviceManagement';
import type { D1DatabaseLike } from '../../../../storage/tenantRoute';
import type { D1LinkedDeviceSessionScopeV1 } from './d1LinkedDeviceSessionStore';
import type { LinkedDeviceSessionServiceV1 } from '../../../../core/deviceLinking/linkedDeviceSession';
import {
  D1LinkedDeviceManagementStoreV1,
  type D1LinkedDeviceManagementMetadataPortV1,
} from './d1LinkedDeviceManagementStore';
import type { DeviceLinkingRouteServiceV1 } from '../../../../router/transport/fetch/routes/deviceLinking';

export type D1LinkedDeviceManagementRouteServiceOptionsV1 = {
  readonly database: D1DatabaseLike;
  readonly scope: D1LinkedDeviceSessionScopeV1;
  readonly sessionService: Pick<LinkedDeviceSessionServiceV1, 'getSessionV1'>;
  readonly metadata: D1LinkedDeviceManagementMetadataPortV1;
  readonly preparation: LinkedDeviceRevocationPreparationPortV1;
  readonly aggregateRevocation: LinkedDeviceAggregateRevocationPortV1;
  readonly walletSessionRevocation: LinkedDeviceWalletSessionRevocationPortV1;
  readonly localStateInvalidation: LinkedDeviceLocalStateInvalidationPortV1;
  readonly nowV1: () => number;
  readonly authenticateOwnerRequestV1: DeviceLinkingRouteServiceV1['authenticateOwnerRequestV1'];
};

export function createD1LinkedDeviceManagementRouteServiceV1(
  options: D1LinkedDeviceManagementRouteServiceOptionsV1,
): DeviceManagementRouteServiceV1 {
  const projection = new D1LinkedDeviceManagementStoreV1({
    database: options.database,
    scope: options.scope,
    sessionService: options.sessionService,
    nowV1: options.nowV1,
    metadata: options.metadata,
  });
  const management = new LinkedDeviceManagementServiceV1({
    projection,
    preparation: options.preparation,
    aggregateRevocation: options.aggregateRevocation,
    walletSessionRevocation: options.walletSessionRevocation,
    localStateInvalidation: options.localStateInvalidation,
  });
  return {
    management,
    nowV1: options.nowV1,
    authenticateOwnerRequestV1: options.authenticateOwnerRequestV1,
  };
}

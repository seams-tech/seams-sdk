import type { RouterAbEd25519YaoActivationKeysetV1 } from '@shared/utils/routerAbEd25519Yao';
import type {
  LaneLifecycleAuthorizationPortV1,
  LaneLifecycleCurveExecutionPortsV1,
} from '../../../../core/signingLanes/LaneLifecycleApplicationService';
import type { D1DatabaseLike } from '../../../../storage/tenantRoute';
import type { RouterApiWalletRegistrationService } from '../../../framework/authServicePort';
import type { DeviceLinkingLaneGatewayRouteServiceV1 } from '../../../transport/fetch/routes/deviceLinkingLaneGateway';
import type { DeviceLinkingOwnerRequestAuthenticationV1 } from '../../../transport/fetch/routes/deviceLinkingOwnerAuthorization';
import type { DeviceLinkingOwnerRequestInputV1 } from '../../../transport/fetch/routes/deviceLinking';
import {
  CloudflareEd25519LaneProtocolTransportV1,
  type CloudflareLaneServiceBindingV1,
} from '../../signingLanes/cloudflareLaneProtocolCommitter';
import {
  CloudflareSigningWorkerEcdsaLaneTransportV1,
  CloudflareSigningWorkerEcdsaRetirementTransportV1,
  LaneLifecycleStoreEcdsaLanePrivateBindingResolverV1,
  LaneLifecycleStoreEd25519LanePrivateBindingResolverV1,
  createCloudflareLaneCurveExecutionPortsV1,
} from '../../signingLanes/cloudflareLaneCurveExecution';
import { createLinkedDeviceEd25519CeremonyBindingResolverV1 } from '../../signingLanes/linkedDeviceEd25519CeremonyBinding';
import { createD1LinkedDeviceLaneLifecycleAuthorizationV1 } from '../deviceLinking/d1LinkedDeviceLaneLifecycleAuthorization';
import type { D1LinkedDeviceSessionScopeV1 } from '../deviceLinking/d1LinkedDeviceSessionStore';
import { D1LinkedDeviceOwnerPlanningSnapshotStoreV1 } from '../deviceLinking/d1LinkedDeviceOwnerPlanningSnapshotStore';
import { CloudflareD1LaneEnrollmentGateway } from './d1LaneEnrollmentGateway';
import { CloudflareD1LaneLifecycleStore } from './d1LaneLifecycleStore';
import { createCloudflareD1LaneProtocolCommitterV1 } from './d1LaneProtocolCommitter';
import {
  createD1LinkedDeviceLaneCeremonyResolverV1,
  createD1LinkedDeviceLaneGatewayRouteServiceV1,
  createD1LinkedDeviceLaneOwnerProjectionGuardV1,
} from './d1LinkedDeviceLaneOwnerAuthorization';

export type D1LinkedDeviceLaneRuntimeOptionsV1 = {
  readonly database: D1DatabaseLike;
  readonly scope: D1LinkedDeviceSessionScopeV1;
  readonly nowV1: () => number;
  readonly walletRegistration: Pick<
    RouterApiWalletRegistrationService,
    'resolveActiveOwnerWalletExecutionLane'
  >;
  readonly authenticateOwnerRequestV1: (
    input: DeviceLinkingOwnerRequestInputV1,
  ) => Promise<DeviceLinkingOwnerRequestAuthenticationV1>;
  readonly router: CloudflareLaneServiceBindingV1;
  readonly signingWorker: CloudflareLaneServiceBindingV1;
  readonly internalServiceAuth: string;
  readonly ed25519YaoKeyset: RouterAbEd25519YaoActivationKeysetV1;
};

export type D1LinkedDeviceLaneRuntimeV1 = {
  readonly laneLifecycle: {
    readonly authorization: LaneLifecycleAuthorizationPortV1;
    readonly execution: LaneLifecycleCurveExecutionPortsV1;
  };
  readonly laneGatewayRoute: DeviceLinkingLaneGatewayRouteServiceV1;
};

export function createD1LinkedDeviceLaneRuntimeV1(
  options: D1LinkedDeviceLaneRuntimeOptionsV1,
): D1LinkedDeviceLaneRuntimeV1 {
  const storeOptions = {
    database: options.database,
    scope: options.scope,
    now: options.nowV1,
  };
  const lifecycleStore = new CloudflareD1LaneLifecycleStore(storeOptions);
  const snapshots = new D1LinkedDeviceOwnerPlanningSnapshotStoreV1({
    database: options.database,
    scope: options.scope,
    walletRegistration: options.walletRegistration,
    nowV1: options.nowV1,
  });
  const authorization = createD1LinkedDeviceLaneLifecycleAuthorizationV1({
    snapshots,
    lifecycle: lifecycleStore,
  });
  const ceremonyBinding = createLinkedDeviceEd25519CeremonyBindingResolverV1();
  const ed25519Transport = new CloudflareEd25519LaneProtocolTransportV1({
    router: options.router,
    internalServiceAuth: options.internalServiceAuth,
    bindingResolver: ceremonyBinding,
  });
  const ecdsaBinding = new LaneLifecycleStoreEcdsaLanePrivateBindingResolverV1(lifecycleStore);
  const retirement = new CloudflareSigningWorkerEcdsaRetirementTransportV1({
    signingWorker: options.signingWorker,
    internalServiceAuth: options.internalServiceAuth,
    bindingResolver: ecdsaBinding,
    ed25519BindingResolver: new LaneLifecycleStoreEd25519LanePrivateBindingResolverV1(
      lifecycleStore,
    ),
  });
  const signingWorker = new CloudflareSigningWorkerEcdsaLaneTransportV1({
    signingWorker: options.signingWorker,
    internalServiceAuth: options.internalServiceAuth,
    bindingResolver: ecdsaBinding,
    retirementTransport: retirement,
  });
  const execution = createCloudflareLaneCurveExecutionPortsV1({
    ed25519Transport,
    signingWorker,
  });
  const protocolCommitter = createCloudflareD1LaneProtocolCommitterV1({
    ...storeOptions,
    authorization,
    execution,
    ed25519Transport,
  });
  const ownerProjection = createD1LinkedDeviceLaneOwnerProjectionGuardV1({
    walletRegistration: options.walletRegistration,
  });
  const laneGatewayRoute = createD1LinkedDeviceLaneGatewayRouteServiceV1({
    authenticateOwnerRequestV1: options.authenticateOwnerRequestV1,
    gateway: new CloudflareD1LaneEnrollmentGateway({ lifecycleStore }),
    protocolCommitter: {
      async executeAndRecordEd25519YaoLaneV1(input) {
        return {
          curve: 'ed25519_yao',
          ...(await protocolCommitter.executeAndRecordEd25519YaoLaneV1(input)),
        };
      },
      async executeAndRecordEcdsaAdditiveLaneV1(input) {
        return {
          curve: 'ecdsa_additive',
          ...(await protocolCommitter.executeAndRecordEcdsaAdditiveLaneV1(input)),
        };
      },
    },
    ownerProjection,
    resolveCeremonyBindingV1: createD1LinkedDeviceLaneCeremonyResolverV1({
      lifecycleStore,
      bindingResolver: ceremonyBinding,
      keyset: options.ed25519YaoKeyset,
      ownerProjection,
    }),
  });
  return {
    laneLifecycle: { authorization, execution },
    laneGatewayRoute,
  };
}

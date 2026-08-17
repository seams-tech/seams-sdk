import type { LinkedDeviceAggregateActivationVerifierV1, LinkedDeviceOwnerAuthorizationPortV1, LinkedDeviceSessionServiceV1 } from '../../../../core/deviceLinking/linkedDeviceSession';
import { LinkedDeviceSessionServiceV1 as CoreLinkedDeviceSessionServiceV1 } from '../../../../core/deviceLinking/linkedDeviceSession';
import type { LinkedOwnerEnrollmentCeremonyReaderV1 } from '../../../../core/deviceLinking/linkedOwnerEnrollmentProvenance';
import type { LaneLifecycleStore } from '../../../../core/signingLanes/LaneLifecycleStore';
import type { D1DatabaseLike } from '../../../../storage/tenantRoute';
import { D1LinkedDeviceAggregateActivationVerifierV1 } from './d1LinkedDeviceAggregateActivationVerifier';
import {
  D1LinkedDeviceSessionStoreV1,
  type D1LinkedDeviceSessionScopeV1,
} from './d1LinkedDeviceSessionStore';

export type D1LinkedDeviceSessionServiceOptionsV1 = {
  readonly database: D1DatabaseLike;
  readonly scope: D1LinkedDeviceSessionScopeV1;
  readonly ownerAuthorization: LinkedDeviceOwnerAuthorizationPortV1;
  /**
   * Reads back the add-auth-method ceremony an approval names, so its
   * provenance is checked against the server's own record before the approval
   * digest seals it.
   */
  readonly ownerEnrollmentCeremonies: LinkedOwnerEnrollmentCeremonyReaderV1;
  readonly laneLifecycle: Pick<
    LaneLifecycleStore,
    'getEnrollment' | 'getProtocol' | 'listEnrollmentProductEpochs'
  >;
  readonly nowV1: () => number;
};

export type D1LinkedDeviceSessionServiceCompositionV1 = {
  readonly sessionService: LinkedDeviceSessionServiceV1;
  readonly sessionStore: D1LinkedDeviceSessionStoreV1;
};

export function createD1LinkedDeviceSessionServiceV1(
  options: D1LinkedDeviceSessionServiceOptionsV1,
): D1LinkedDeviceSessionServiceCompositionV1 {
  const sessionStore = new D1LinkedDeviceSessionStoreV1({
    database: options.database,
    scope: options.scope,
    now: options.nowV1,
  });
  const aggregateActivationVerifier: LinkedDeviceAggregateActivationVerifierV1 =
    new D1LinkedDeviceAggregateActivationVerifierV1({ lifecycleStore: options.laneLifecycle });
  const sessionService = new CoreLinkedDeviceSessionServiceV1({
    store: sessionStore,
    authorization: options.ownerAuthorization,
    aggregateActivationVerifier,
    ownerEnrollmentCeremonies: options.ownerEnrollmentCeremonies,
  });
  return { sessionService, sessionStore };
}

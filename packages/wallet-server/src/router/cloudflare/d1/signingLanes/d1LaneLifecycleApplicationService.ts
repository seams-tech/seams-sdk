import {
  LaneLifecycleApplicationService,
  type LaneLifecycleAuthorizationPortV1,
  type LaneLifecycleCurveExecutionPortsV1,
} from '../../../../core/signingLanes/LaneLifecycleApplicationService';
import type { CloudflareD1LaneStoreOptions } from './d1LaneRecords';
import { CloudflareD1LaneEnrollmentGateway } from './d1LaneEnrollmentGateway';
import { CloudflareD1LaneLifecycleStore } from './d1LaneLifecycleStore';

export type CloudflareD1LaneLifecycleApplicationServiceOptions = CloudflareD1LaneStoreOptions & {
  readonly authorization: LaneLifecycleAuthorizationPortV1;
  readonly execution: LaneLifecycleCurveExecutionPortsV1;
};

/**
 * Builds the authenticated server-internal lane lifecycle boundary. Routes
 * should receive this service from their private composition and never expose
 * the receipt methods as a public raw-receipt endpoint.
 */
export function createCloudflareD1LaneLifecycleApplicationService(
  options: CloudflareD1LaneLifecycleApplicationServiceOptions,
): LaneLifecycleApplicationService {
  const lifecycleStore = new CloudflareD1LaneLifecycleStore(options);
  const gateway = new CloudflareD1LaneEnrollmentGateway({ lifecycleStore });
  return new LaneLifecycleApplicationService({
    gateway,
    authorization: options.authorization,
    execution: options.execution,
  });
}

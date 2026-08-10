import { LaneAggregateRevocationApplicationService } from '../../../../core/signingLanes/LaneAggregateRevocationApplicationService';
import { LaneEnrollmentRevocation } from '../../../../core/signingLanes/LaneEnrollmentRevocation';
import { LaneLifecycleApplicationService } from '../../../../core/signingLanes/LaneLifecycleApplicationService';
import type { CloudflareD1LaneLifecycleApplicationServiceOptions } from './d1LaneLifecycleApplicationService';
import { CloudflareD1LaneEnrollmentGateway } from './d1LaneEnrollmentGateway';
import { CloudflareD1LaneLifecycleStore } from './d1LaneLifecycleStore';

export function createCloudflareD1LaneAggregateRevocationApplicationService(
  options: CloudflareD1LaneLifecycleApplicationServiceOptions,
): LaneAggregateRevocationApplicationService {
  const lifecycleStore = new CloudflareD1LaneLifecycleStore(options);
  const gateway = new CloudflareD1LaneEnrollmentGateway({ lifecycleStore });
  const laneLifecycle = new LaneLifecycleApplicationService({
    gateway,
    authorization: options.authorization,
    execution: options.execution,
  });
  return new LaneAggregateRevocationApplicationService({
    lifecycleStore,
    laneLifecycle,
    enrollmentRevocation: new LaneEnrollmentRevocation(lifecycleStore),
  });
}

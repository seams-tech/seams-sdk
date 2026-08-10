import {
  CloudflareLaneProtocolCommitterV1,
  type CloudflareLaneProtocolCommitterOptionsV1,
} from '../../signingLanes/cloudflareLaneProtocolCommitter';
import type { CloudflareD1LaneStoreOptions } from './d1LaneRecords';
import { CloudflareD1LaneEnrollmentGateway } from './d1LaneEnrollmentGateway';
import { CloudflareD1LaneLifecycleStore } from './d1LaneLifecycleStore';

export type CloudflareD1LaneProtocolCommitterOptionsV1 = CloudflareD1LaneStoreOptions &
  Omit<CloudflareLaneProtocolCommitterOptionsV1, 'gateway'>;

export function createCloudflareD1LaneProtocolCommitterV1(
  options: CloudflareD1LaneProtocolCommitterOptionsV1,
): CloudflareLaneProtocolCommitterV1 {
  const lifecycleStore = new CloudflareD1LaneLifecycleStore(options);
  const gateway = new CloudflareD1LaneEnrollmentGateway({ lifecycleStore });
  return new CloudflareLaneProtocolCommitterV1({
    gateway,
    authorization: options.authorization,
    execution: options.execution,
    ed25519Transport: options.ed25519Transport,
  });
}

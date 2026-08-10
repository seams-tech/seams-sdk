import {
  LaneLifecycleStoreEcdsaLanePrivateBindingResolverV1,
  type EcdsaLanePrivateBindingResolverPortV1,
} from '../../signingLanes/cloudflareLaneCurveExecution';
import type { CloudflareD1LaneStoreOptions } from './d1LaneRecords';
import { CloudflareD1LaneLifecycleStore } from './d1LaneLifecycleStore';

export function createCloudflareD1EcdsaLanePrivateBindingResolverV1(
  options: CloudflareD1LaneStoreOptions,
): EcdsaLanePrivateBindingResolverPortV1 {
  return new LaneLifecycleStoreEcdsaLanePrivateBindingResolverV1(
    new CloudflareD1LaneLifecycleStore(options),
  );
}

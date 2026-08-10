import type { LaneOperationId, LaneProtocolRecordV1 } from '@shared/signing-lanes';

export interface SigningLaneRotationStore {
  getRotationJob(operationId: LaneOperationId): Promise<LaneProtocolRecordV1 | null>;
  putRotationJob(job: LaneProtocolRecordV1): Promise<void>;
}

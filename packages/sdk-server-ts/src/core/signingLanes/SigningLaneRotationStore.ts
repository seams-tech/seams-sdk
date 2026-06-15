import type { RotationOperationId, ShareRotationJob } from '@shared/signing-lanes';

export interface SigningLaneRotationStore {
  getRotationJob(operationId: RotationOperationId): Promise<ShareRotationJob | null>;
  putRotationJob(job: ShareRotationJob): Promise<void>;
}

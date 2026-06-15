import type { RotationOperationId } from '@shared/signing-lanes';

export type RotationTranscriptRecord = {
  kind: 'rotation_transcript_v1';
  operationId: RotationOperationId;
  transcriptHashB64u: string;
  createdAtMs: number;
};

export interface RotationTranscriptStore {
  getRotationTranscript(operationId: RotationOperationId): Promise<RotationTranscriptRecord | null>;
  putRotationTranscript(record: RotationTranscriptRecord): Promise<void>;
}

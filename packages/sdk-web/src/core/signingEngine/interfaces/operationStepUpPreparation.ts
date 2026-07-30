import type { TransactionContext } from '@/core/types/rpc';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';

declare const nearOperationStepUpHandleBrand: unique symbol;
export type NearOperationStepUpHandle = string & {
  readonly [nearOperationStepUpHandleBrand]: true;
};
export type NearOperationStepUpPreparationRef = {
  kind: 'near_operation_step_up_prepared_v1';
  handle: NearOperationStepUpHandle;
  challengeB64u: string;
};

export type NearOperationStepUpPreparationPort = {
  prepare(
    input:
      | {
          kind: 'near_transaction';
          requestId: string;
          transactionContext: TransactionContext;
          operationId: string;
          operationFingerprint: string;
          displayDigest: string;
        }
      | {
          kind: 'near_signature_only';
          requestId: string;
          displayDigest: string;
          transactionContext?: never;
          operationId?: never;
          operationFingerprint?: never;
        },
  ): Promise<NearOperationStepUpPreparationRef>;
  cancel(input: { requestId: string; handle?: NearOperationStepUpHandle }): void;
};

export function parseNearOperationStepUpPreparationRef(
  raw: unknown,
): NearOperationStepUpPreparationRef {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('operation step-up preparation ref must be an object');
  }
  const record = raw as Record<string, unknown>;
  if (Object.keys(record).length !== 3 || record.kind !== 'near_operation_step_up_prepared_v1') {
    throw new Error('operation step-up preparation ref is invalid');
  }
  const handle = String(record.handle || '').trim();
  if (!handle.startsWith('near-operation-step-up:') || /\s/.test(handle)) {
    throw new Error('operation step-up preparation handle is invalid');
  }
  return {
    kind: 'near_operation_step_up_prepared_v1',
    handle: handle as NearOperationStepUpHandle,
    challengeB64u: parseDigestB64u(record.challengeB64u),
  };
}

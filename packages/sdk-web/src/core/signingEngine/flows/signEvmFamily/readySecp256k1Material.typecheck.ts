import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import type { ThresholdEcdsaSessionRecord } from '../../session/persistence/records';
import { buildReadySecp256k1SigningMaterialFromRecord } from './readySecp256k1Material';

type ReadySecp256k1MaterialFromRecordInput = Parameters<
  typeof buildReadySecp256k1SigningMaterialFromRecord
>[0];

declare const record: ThresholdEcdsaSessionRecord;
declare const workerCtx: WorkerOperationContext;

const validRehydrationInput = {
  record,
  requestLabel: 'evm',
  evmFamilySigningKeySlotId: record.evmFamilySigningKeySlotId,
  workerCtx,
} satisfies ReadySecp256k1MaterialFromRecordInput;
void validRehydrationInput;

const { workerCtx: omittedWorkerContext, ...inputWithoutWorkerContext } = validRehydrationInput;
void omittedWorkerContext;

// @ts-expect-error durable material cannot be treated as ready without a worker rehydration boundary.
const invalidRehydrationInput: ReadySecp256k1MaterialFromRecordInput = inputWithoutWorkerContext;
void invalidRehydrationInput;

export {};

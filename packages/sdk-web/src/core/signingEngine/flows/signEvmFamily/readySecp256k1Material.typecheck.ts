import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import type { EcdsaRoleLocalPersistedMaterialRef } from '../../session/keyMaterialBrands';
import type { ThresholdEcdsaSessionRecord } from '../../session/persistence/records';
import {
  buildReadySecp256k1SigningMaterialFromRecord,
  hydrateEcdsaRoleLocalMaterialForSigning,
} from './readySecp256k1Material';

type ReadySecp256k1MaterialFromRecordInput = Parameters<
  typeof buildReadySecp256k1SigningMaterialFromRecord
>[0];

declare const record: ThresholdEcdsaSessionRecord;
declare const materialRef: EcdsaRoleLocalPersistedMaterialRef;
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

type HydrationInput = Parameters<typeof hydrateEcdsaRoleLocalMaterialForSigning>[0];

const validMaterialHydrationInput = {
  materialRef,
  workerCtx,
} satisfies HydrationInput;
void validMaterialHydrationInput;

// @ts-expect-error material hydration cannot accept Wallet Session authorization state.
const invalidMaterialHydrationInput: HydrationInput = { record, workerCtx };
void invalidMaterialHydrationInput;

type HydrationResult = Awaited<ReturnType<typeof hydrateEcdsaRoleLocalMaterialForSigning>>;
declare const hydrationResult: HydrationResult;
hydrationResult.materialRef satisfies EcdsaRoleLocalPersistedMaterialRef;
void hydrationResult.liveHandle;

export {};

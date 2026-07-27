import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import type { EcdsaRoleLocalPersistedMaterialRef } from '../../session/keyMaterialBrands';
import type { ThresholdEcdsaSessionRecord } from '../../session/persistence/records';
import { hydrateEcdsaRoleLocalMaterialForExport } from './ecdsaDerivationExport';

type ExportHydrationInput = Parameters<typeof hydrateEcdsaRoleLocalMaterialForExport>[0];

declare const materialRef: EcdsaRoleLocalPersistedMaterialRef;
declare const record: ThresholdEcdsaSessionRecord;
declare const workerCtx: WorkerOperationContext;

const validExportHydrationInput = {
  materialRef,
  workerCtx,
} satisfies ExportHydrationInput;
void validExportHydrationInput;

// @ts-expect-error export hydration cannot accept authorization/session state.
const invalidExportHydrationInput: ExportHydrationInput = { record, workerCtx };
void invalidExportHydrationInput;

export {};

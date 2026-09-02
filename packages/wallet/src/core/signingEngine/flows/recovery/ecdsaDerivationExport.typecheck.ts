import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import type { EcdsaRoleLocalPersistedMaterialRef } from '../../session/keyMaterialBrands';
import type { PersistedEcdsaRoleLocalMaterial } from '../../session/material/ecdsaRoleLocalMaterialResolver';
import { hydrateEcdsaRoleLocalMaterialForExport } from './ecdsaDerivationExport';

type ExportHydrationInput = Parameters<typeof hydrateEcdsaRoleLocalMaterialForExport>[0];

declare const materialRef: EcdsaRoleLocalPersistedMaterialRef;
declare const persistedMaterial: PersistedEcdsaRoleLocalMaterial;
declare const workerCtx: WorkerOperationContext;

const validExportHydrationInput = {
  persistedMaterial,
  workerCtx,
} satisfies ExportHydrationInput;
void validExportHydrationInput;

const invalidMaterialRefOnlyExportHydrationInput: ExportHydrationInput = {
  // @ts-expect-error export hydration requires exact authority and material activation.
  materialRef,
  workerCtx,
};
void invalidMaterialRefOnlyExportHydrationInput;

const invalidExportHydrationInput: ExportHydrationInput = {
  // @ts-expect-error export hydration cannot accept authorization/session state.
  authorization: { kind: 'reusable_wallet_session' },
  workerCtx,
};
void invalidExportHydrationInput;

export {};

import type { ThemeMode } from '@/core/types/seams';
import {
  exportKeypairWithUI as exportKeypairWithUIValue,
  type ExportKeypairWithUIDeps,
  resolveExactKeyExportLane as resolveExactKeyExportLaneValue,
  type SigningEngineExportKeypairWithUIInput,
  type SigningEngineResolveExactKeyExportLaneInput,
  type SigningEngineResolveExactKeyExportLaneResult,
} from './exportKeypairOperation';
import type { KeyExportEventCallback } from './keyExportFlow';

export type RecoveryPublicDeps = {
  laneSelection: ExportKeypairWithUIDeps['laneSelection'];
  ecdsa: Omit<ExportKeypairWithUIDeps['ecdsa'], 'theme'>;
  ed25519Yao: Omit<ExportKeypairWithUIDeps['ed25519Yao'], 'theme'>;
  getTheme: () => ThemeMode;
};

export type RecoveryPublicEcdsaSessionStoreDeps = RecoveryPublicDeps['ecdsa']['sessionStore'];

function exportKeypairDeps(deps: RecoveryPublicDeps): ExportKeypairWithUIDeps {
  return {
    laneSelection: deps.laneSelection,
    ecdsa: {
      ...deps.ecdsa,
      theme: deps.getTheme(),
    },
    ed25519Yao: {
      ...deps.ed25519Yao,
      theme: deps.getTheme(),
    },
  };
}

export async function exportKeypairWithUI(
  deps: RecoveryPublicDeps,
  input: SigningEngineExportKeypairWithUIInput,
): Promise<{ accountId: string; exportedSchemes: Array<'ed25519' | 'secp256k1'> }> {
  return await exportKeypairWithUIValue(exportKeypairDeps(deps), input);
}

export async function resolveExactKeyExportLane(
  deps: RecoveryPublicDeps,
  input: SigningEngineResolveExactKeyExportLaneInput,
): Promise<SigningEngineResolveExactKeyExportLaneResult> {
  return await resolveExactKeyExportLaneValue(exportKeypairDeps(deps), input);
}

export type {
  SigningEngineExportKeypairWithUIInput,
  SigningEngineResolveExactKeyExportLaneInput,
  SigningEngineResolveExactKeyExportLaneResult,
  KeyExportEventCallback,
};

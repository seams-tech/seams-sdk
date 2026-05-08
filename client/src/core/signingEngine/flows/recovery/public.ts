import type { AccountId } from '@/core/types/accountIds';
import type { ThemeName } from '@/core/types/seams';
import type { PrivateKeyExportRecoveryDeps } from '../../interfaces/operationDeps';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import {
  exportKeypairWithUI as exportKeypairWithUIValue,
  type ExportKeypairWithUIDeps,
  type SigningEngineExportKeypairWithUIInput,
} from './exportKeypairOperation';
import {
  exportNearEd25519SeedArtifactWithUI as exportNearEd25519SeedArtifactWithUIValue,
} from './privateKeyExportRecovery';
import {
  exportThresholdEd25519SeedFromHssReport as exportThresholdEd25519SeedFromHssReportValue,
} from './nearEd25519SeedReportExport';
import type { KeyExportEventCallback } from './keyExportFlow';

export type RecoveryPublicDeps = {
  laneSelection: ExportKeypairWithUIDeps['laneSelection'];
  nearSingleKeyHss: Omit<ExportKeypairWithUIDeps['nearSingleKeyHss'], 'theme'>;
  ecdsa: Omit<ExportKeypairWithUIDeps['ecdsa'], 'theme'>;
  touchConfirm: Parameters<typeof exportThresholdEd25519SeedFromHssReportValue>[0]['touchConfirm'];
  getTheme: () => ThemeName;
  getSignerWorkerContext: () => WorkerOperationContext;
  privateKeyExportRecovery: PrivateKeyExportRecoveryDeps;
};

export type RecoveryPublicEcdsaSessionStoreDeps = RecoveryPublicDeps['ecdsa']['sessionStore'];

function exportKeypairDeps(deps: RecoveryPublicDeps): ExportKeypairWithUIDeps {
  return {
    laneSelection: deps.laneSelection,
    nearSingleKeyHss: {
      ...deps.nearSingleKeyHss,
      theme: deps.getTheme(),
    },
    ecdsa: {
      ...deps.ecdsa,
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

export function exportNearEd25519SeedArtifactWithUI(
  deps: RecoveryPublicDeps,
  args: {
    nearAccountId: AccountId;
    seedB64u: string;
    expectedPublicKey: string;
    options: {
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
    };
  },
): Promise<{ accountId: string; exportedSchemes: Array<'ed25519' | 'secp256k1'> }> {
  return exportNearEd25519SeedArtifactWithUIValue(deps.privateKeyExportRecovery, args);
}

export async function exportThresholdEd25519SeedFromHssReport(
  deps: RecoveryPublicDeps,
  args: {
    nearAccountId: AccountId;
    preparedSession: Parameters<
      typeof exportThresholdEd25519SeedFromHssReportValue
    >[1]['preparedSession'];
    finalizedReport: Parameters<
      typeof exportThresholdEd25519SeedFromHssReportValue
    >[1]['finalizedReport'];
    expectedPublicKey: string;
    options: {
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
      onEvent?: KeyExportEventCallback;
    };
  },
): Promise<{ accountId: string; exportedSchemes: Array<'ed25519' | 'secp256k1'> }> {
  return await exportThresholdEd25519SeedFromHssReportValue(
    {
      touchConfirm: deps.touchConfirm,
      theme: deps.getTheme(),
      getSignerWorkerContext: deps.getSignerWorkerContext,
    },
    args,
  );
}

export type { SigningEngineExportKeypairWithUIInput, KeyExportEventCallback };

export function createRecoveryPublicApi(deps: RecoveryPublicDeps) {
  return {
    exportKeypairWithUI: (input: SigningEngineExportKeypairWithUIInput) =>
      exportKeypairWithUI(deps, input),
    exportNearEd25519SeedArtifactWithUI: (args: {
      nearAccountId: AccountId;
      seedB64u: string;
      expectedPublicKey: string;
      options: {
        variant?: 'drawer' | 'modal';
        theme?: 'dark' | 'light';
      };
    }) => exportNearEd25519SeedArtifactWithUI(deps, args),
    exportThresholdEd25519SeedFromHssReport: (args: {
      nearAccountId: AccountId;
      preparedSession: Parameters<
        typeof exportThresholdEd25519SeedFromHssReportValue
      >[1]['preparedSession'];
      finalizedReport: Parameters<
        typeof exportThresholdEd25519SeedFromHssReportValue
      >[1]['finalizedReport'];
      expectedPublicKey: string;
      options: {
        variant?: 'drawer' | 'modal';
        theme?: 'dark' | 'light';
        onEvent?: KeyExportEventCallback;
      };
    }) => exportThresholdEd25519SeedFromHssReport(deps, args),
  };
}

export type RecoveryPublicApi = ReturnType<typeof createRecoveryPublicApi>;

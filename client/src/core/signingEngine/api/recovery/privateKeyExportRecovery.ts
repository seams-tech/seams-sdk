import type { UnifiedIndexedDBManager } from '@/core/indexedDB';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type {
  ExportPrivateKeysWithUiWorkerPayload,
  ExportPrivateKeysWithUiWorkerResult,
} from '@/core/types/secure-confirm-worker';
import type { ThemeName } from '@/core/types/tatchi';
import { getLastLoggedInDeviceNumber } from '../../signers/webauthn/device/getDeviceNumber';

type ExportKeypairChain = 'near' | 'evm' | 'tempo';
type ExportScheme = 'ed25519' | 'secp256k1';

type ExportHardeningErrorCode = 'SIGNER_EXPORT_TEMP_DISABLED_LEGACY_SHORTCUT';
type ExportHardeningError = Error & { code: ExportHardeningErrorCode };

const EXPORT_LEGACY_SHORTCUT_DISABLED_CODE: ExportHardeningErrorCode =
  'SIGNER_EXPORT_TEMP_DISABLED_LEGACY_SHORTCUT';

function createExportHardeningError(args: {
  message: string;
  code: ExportHardeningErrorCode;
}): ExportHardeningError {
  const error = new Error(args.message) as ExportHardeningError;
  error.name = 'SignerExportHardeningError';
  error.code = args.code;
  return error;
}

function emitExportHardeningTelemetry(args: {
  event: 'signer.export.legacy_shortcut_blocked';
  nearAccountId: string;
  deviceNumber?: number;
  reason: string;
}): void {
  // Structured logs are currently the canonical low-overhead telemetry surface in wallet origin.
  console.warn('[signer-export-telemetry]', {
    event: args.event,
    nearAccountId: args.nearAccountId,
    ...(typeof args.deviceNumber === 'number' ? { deviceNumber: args.deviceNumber } : {}),
    reason: args.reason,
    timestamp: Date.now(),
  });
}

// Export orchestration boundary rule:
// - This module may only invoke the worker-owned export operation.
// - It must not orchestrate confirm steps or parse PRF material in JS main thread.
function throwLegacyExportShortcutDisabled(args: {
  nearAccountId: string;
  deviceNumber?: number;
  reason: string;
}): never {
  emitExportHardeningTelemetry({
    event: 'signer.export.legacy_shortcut_blocked',
    nearAccountId: args.nearAccountId,
    deviceNumber: args.deviceNumber,
    reason: args.reason,
  });
  throw createExportHardeningError({
    code: EXPORT_LEGACY_SHORTCUT_DISABLED_CODE,
    message:
      `Export is temporarily disabled until worker-owned export hardening is active ` +
      `(${EXPORT_LEGACY_SHORTCUT_DISABLED_CODE})`,
  });
}

export type PrivateKeyExportRecoveryDeps = {
  indexedDB: UnifiedIndexedDBManager;
  requestExportPrivateKeysWithUi?: (
    payload: ExportPrivateKeysWithUiWorkerPayload,
  ) => Promise<ExportPrivateKeysWithUiWorkerResult>;
  getTheme: () => ThemeName;
};

async function runExportWorkerOperation(
  deps: PrivateKeyExportRecoveryDeps,
  args: {
    nearAccountId: AccountId;
    options: {
      chain: ExportKeypairChain;
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
    };
  },
): Promise<ExportPrivateKeysWithUiWorkerResult> {
  const accountId = toAccountId(args.nearAccountId);
  if (typeof deps.requestExportPrivateKeysWithUi !== 'function') {
    throwLegacyExportShortcutDisabled({
      nearAccountId: accountId,
      reason: 'missing_export_worker_operation',
    });
  }
  const requestExportPrivateKeysWithUi = deps.requestExportPrivateKeysWithUi;

  const resolvedTheme = args.options?.theme ?? deps.getTheme();
  const deviceNumber = await getLastLoggedInDeviceNumber(accountId, deps.indexedDB.clientDB).catch(
    () => null as number | null,
  );
  if (deviceNumber == null) {
    throw new Error(`No deviceNumber found for account ${accountId} (export/decrypt)`);
  }

  const [userForAccount, thresholdKeyMaterial] = await Promise.all([
    deps.indexedDB.clientDB.getNearAccountProjection(accountId, deviceNumber).catch(() => null),
    deps.indexedDB.getNearThresholdKeyMaterial(accountId, deviceNumber).catch(() => null),
  ]);

  if (!thresholdKeyMaterial) {
    throw new Error(
      `No threshold key material found for account ${accountId} device ${deviceNumber}`,
    );
  }

  const publicKeyHint = String(
    userForAccount?.clientNearPublicKey || thresholdKeyMaterial?.publicKey || '',
  ).trim();

  const result = await (async (): Promise<ExportPrivateKeysWithUiWorkerResult> => {
    try {
      return await requestExportPrivateKeysWithUi({
        nearAccountId: accountId,
        deviceNumber,
        chain: args.options.chain,
        publicKeyHint,
        variant: args.options.variant,
        theme: resolvedTheme,
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error || '');
      if (
        message.includes('Unsupported UserConfirm worker message type: EXPORT_PRIVATE_KEYS_WITH_UI')
      ) {
        throwLegacyExportShortcutDisabled({
          nearAccountId: accountId,
          deviceNumber,
          reason: 'worker_missing_export_operation',
        });
      }
      throw error;
    }
  })();
  if (!result.ok) {
    throw new Error(result.error || 'Export private keys request failed');
  }
  return result;
}

export async function exportKeypairWithUIWorkerDriven(
  deps: PrivateKeyExportRecoveryDeps,
  args: {
    nearAccountId: AccountId;
    options: {
      chain: ExportKeypairChain;
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
    };
  },
): Promise<ExportPrivateKeysWithUiWorkerResult> {
  return runExportWorkerOperation(deps, args);
}

export async function exportKeypairWithUI(
  deps: PrivateKeyExportRecoveryDeps,
  args: {
    nearAccountId: AccountId;
    options: {
      chain: ExportKeypairChain;
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
    };
  },
): Promise<{ accountId: string; exportedSchemes: ExportScheme[] }> {
  const result = await exportKeypairWithUIWorkerDriven(deps, args);
  return {
    accountId: result.accountId,
    exportedSchemes: result.exportedSchemes,
  };
}

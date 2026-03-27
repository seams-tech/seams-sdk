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

type ExportRecoveryErrorCode =
  | 'SIGNER_EXPORT_WORKER_BOUNDARY_REQUIRED'
  | 'SIGNER_EXPORT_RECOVERY_NOT_PROVISIONED';
type ExportRecoveryError = Error & { code: ExportRecoveryErrorCode };

const EXPORT_WORKER_BOUNDARY_REQUIRED_CODE: ExportRecoveryErrorCode =
  'SIGNER_EXPORT_WORKER_BOUNDARY_REQUIRED';
const EXPORT_RECOVERY_NOT_PROVISIONED_CODE: ExportRecoveryErrorCode =
  'SIGNER_EXPORT_RECOVERY_NOT_PROVISIONED';

function createExportRecoveryError(args: {
  message: string;
  code: ExportRecoveryErrorCode;
}): ExportRecoveryError {
  const error = new Error(args.message) as ExportRecoveryError;
  error.name = 'SignerExportRecoveryError';
  error.code = args.code;
  return error;
}

function emitExportRecoveryTelemetry(args: {
  event: 'signer.export.worker_boundary_required' | 'signer.export.recovery_not_provisioned';
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

function throwExportWorkerBoundaryRequired(args: {
  nearAccountId: string;
  deviceNumber?: number;
  reason: string;
}): never {
  emitExportRecoveryTelemetry({
    event: 'signer.export.worker_boundary_required',
    nearAccountId: args.nearAccountId,
    deviceNumber: args.deviceNumber,
    reason: args.reason,
  });
  throw createExportRecoveryError({
    code: EXPORT_WORKER_BOUNDARY_REQUIRED_CODE,
    message: `Export requires the worker-owned recovery export operation (${EXPORT_WORKER_BOUNDARY_REQUIRED_CODE})`,
  });
}

function throwRecoveryExportNotProvisioned(args: {
  nearAccountId: string;
  deviceNumber?: number;
  reason: string;
}): never {
  emitExportRecoveryTelemetry({
    event: 'signer.export.recovery_not_provisioned',
    nearAccountId: args.nearAccountId,
    deviceNumber: args.deviceNumber,
    reason: args.reason,
  });
  throw createExportRecoveryError({
    code: EXPORT_RECOVERY_NOT_PROVISIONED_CODE,
    message: `Threshold Ed25519 recovery export is not provisioned (${EXPORT_RECOVERY_NOT_PROVISIONED_CODE})`,
  });
}

export type PrivateKeyExportRecoveryDeps = {
  indexedDB: UnifiedIndexedDBManager;
  relayerUrl: string;
  getRpId: () => string | null;
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
    throwExportWorkerBoundaryRequired({
      nearAccountId: accountId,
      reason: 'missing_export_worker_operation',
    });
  }
  const requestExportPrivateKeysWithUi = deps.requestExportPrivateKeysWithUi;
  const relayerUrl = String(deps.relayerUrl || '').trim();
  if (!relayerUrl) {
    throw new Error('Missing relayerUrl for export recovery');
  }
  const rpId = String(deps.getRpId?.() || '').trim();
  if (!rpId) {
    throw new Error('Missing rpId for export recovery');
  }

  const resolvedTheme = args.options?.theme ?? deps.getTheme();
  const deviceNumber = await getLastLoggedInDeviceNumber(accountId, deps.indexedDB.clientDB).catch(
    () => null as number | null,
  );
  if (deviceNumber == null) {
    throw new Error(`No deviceNumber found for account ${accountId} (export/decrypt)`);
  }

  const thresholdKeyMaterial = await deps.indexedDB
    .getNearThresholdKeyMaterial(accountId, deviceNumber)
    .catch(() => null);

  if (!thresholdKeyMaterial) {
    throwRecoveryExportNotProvisioned({
      nearAccountId: accountId,
      deviceNumber,
      reason: 'missing_threshold_key_material',
    });
  }
  if (
    thresholdKeyMaterial.artifactKind !== 'near-ed25519-option-b-v1' ||
    thresholdKeyMaterial.recoveryExportCapable !== true ||
    !String(thresholdKeyMaterial.recoveryPublicKey || '').trim()
  ) {
    throwRecoveryExportNotProvisioned({
      nearAccountId: accountId,
      deviceNumber,
      reason: 'threshold_ed25519_recovery_export_not_provisioned',
    });
  }
  const relayerKeyId = String(thresholdKeyMaterial.relayerKeyId || '').trim();
  if (!relayerKeyId) {
    throwRecoveryExportNotProvisioned({
      nearAccountId: accountId,
      deviceNumber,
      reason: 'missing_relayer_key_id',
    });
  }
  const recoveryPublicKey = String(thresholdKeyMaterial.recoveryPublicKey || '').trim();
  if (!recoveryPublicKey) {
    throwRecoveryExportNotProvisioned({
      nearAccountId: accountId,
      deviceNumber,
      reason: 'missing_recovery_public_key',
    });
  }

  const result = await (async (): Promise<ExportPrivateKeysWithUiWorkerResult> => {
    try {
      return await requestExportPrivateKeysWithUi({
        nearAccountId: accountId,
        deviceNumber,
        chain: args.options.chain,
        artifactKind: thresholdKeyMaterial.artifactKind,
        keyVersion: thresholdKeyMaterial.keyVersion,
        recoveryExportCapable: thresholdKeyMaterial.recoveryExportCapable,
        relayerUrl,
        relayerKeyId,
        rpId,
        recoveryPublicKey,
        variant: args.options.variant,
        theme: resolvedTheme,
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error || '');
      if (
        message.includes('Unsupported UserConfirm worker message type: EXPORT_PRIVATE_KEYS_WITH_UI')
      ) {
        throwExportWorkerBoundaryRequired({
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

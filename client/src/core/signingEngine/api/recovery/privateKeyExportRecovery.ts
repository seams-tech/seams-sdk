import type { UnifiedIndexedDBManager } from '@/core/indexedDB';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { ExportPrivateKeysWithUiWorkerResult } from '@/core/types/secure-confirm-worker';
import type { ThemeName } from '@/core/types/tatchi';
import type { WebAuthnAuthenticationCredential } from '@/core/types';
import type { TouchConfirmSecureConfirmationPort } from '../../touchConfirm';
import { getLastLoggedInDeviceNumber } from '../../signers/webauthn/device/getDeviceNumber';

type ExportScheme = 'ed25519' | 'secp256k1';

type RecoverKeypairResult = {
  publicKey: string;
  encryptedPrivateKey: string;
  chacha20NonceB64u: string;
  accountIdHint?: string;
  wrapKeySalt: string;
  stored?: boolean;
};

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
      `Export is temporarily disabled until worker-owned export hardening is active `
      + `(${EXPORT_LEGACY_SHORTCUT_DISABLED_CODE})`,
  });
}

export type PrivateKeyExportRecoveryDeps = {
  indexedDB: UnifiedIndexedDBManager;
  touchConfirmManager: Pick<TouchConfirmSecureConfirmationPort, 'exportPrivateKeysWithUi'>;
  getTheme: () => ThemeName;
  signingKeyOps: {
    recoverKeypairFromPasskey: (args: {
      credential: WebAuthnAuthenticationCredential;
      accountIdHint?: string;
      sessionId: string;
    }) => Promise<RecoverKeypairResult>;
  };
  createSessionId: (prefix: string) => string;
};

function normalizeRequestedSchemes(input?: ExportScheme[]): ExportScheme[] {
  const requested = Array.isArray(input) && input.length
    ? input
    : (['ed25519', 'secp256k1'] as const);
  return Array.from(new Set(requested)).filter(
    (scheme): scheme is ExportScheme => scheme === 'ed25519' || scheme === 'secp256k1',
  );
}

async function runExportWorkerOperation(
  deps: PrivateKeyExportRecoveryDeps,
  args: {
    nearAccountId: AccountId;
    options?: {
      schemes?: ExportScheme[];
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
    };
  },
): Promise<ExportPrivateKeysWithUiWorkerResult> {
  const accountId = toAccountId(args.nearAccountId);
  const schemes = normalizeRequestedSchemes(args.options?.schemes);
  if (!schemes.length) throw new Error('No export schemes requested');
  const touchConfirmManager = deps.touchConfirmManager as {
    exportPrivateKeysWithUi?: unknown;
  };
  const exportPrivateKeysWithUiMaybe = touchConfirmManager.exportPrivateKeysWithUi;
  if (typeof exportPrivateKeysWithUiMaybe !== 'function') {
    throwLegacyExportShortcutDisabled({
      nearAccountId: accountId,
      reason: 'missing_export_worker_operation',
    });
  }
  const exportPrivateKeysWithUi =
    touchConfirmManager.exportPrivateKeysWithUi as TouchConfirmSecureConfirmationPort['exportPrivateKeysWithUi'];
  const exportPrivateKeysWithUiBound = exportPrivateKeysWithUi.bind(touchConfirmManager);

  const resolvedTheme = args.options?.theme ?? deps.getTheme();
  const deviceNumber = await getLastLoggedInDeviceNumber(accountId, deps.indexedDB.clientDB).catch(
    () => null as number | null,
  );
  if (deviceNumber == null) {
    throw new Error(`No deviceNumber found for account ${accountId} (export/decrypt)`);
  }

  const [userForAccount, keyMaterial, thresholdKeyMaterial] = await Promise.all([
    deps.indexedDB.clientDB.getNearAccountProjection(accountId, deviceNumber).catch(() => null),
    deps.indexedDB.getNearLocalKeyMaterial(accountId, deviceNumber).catch(() => null),
    deps.indexedDB.getNearThresholdKeyMaterial(accountId, deviceNumber).catch(() => null),
  ]);

  if (!keyMaterial && !thresholdKeyMaterial) {
    throw new Error(`No key material found for account ${accountId} device ${deviceNumber}`);
  }

  const publicKeyHint = String(
    userForAccount?.clientNearPublicKey
      || keyMaterial?.publicKey
      || thresholdKeyMaterial?.publicKey
      || '',
  ).trim();

  const encryptedSk = String(keyMaterial?.encryptedSk || '').trim();
  const chacha20NonceB64u = String(keyMaterial?.chacha20NonceB64u || '').trim();
  const wrapKeySalt = String(keyMaterial?.wrapKeySalt || '').trim();
  const localKeyMaterial = (encryptedSk && chacha20NonceB64u && wrapKeySalt)
    ? {
        encryptedSk,
        chacha20NonceB64u,
        wrapKeySalt,
        publicKey: String(keyMaterial?.publicKey || publicKeyHint || '').trim(),
      }
    : undefined;

  const result = await (async (): Promise<ExportPrivateKeysWithUiWorkerResult> => {
    try {
      return await exportPrivateKeysWithUiBound({
        nearAccountId: accountId,
        deviceNumber,
        publicKeyHint,
        hasThresholdKeyMaterial: !!thresholdKeyMaterial,
        localKeyMaterial,
        schemes,
        variant: args.options?.variant,
        theme: resolvedTheme,
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error || '');
      if (message.includes('Unsupported UserConfirm worker message type: EXPORT_PRIVATE_KEYS_WITH_UI')) {
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

export async function exportNearKeypairWithUIWorkerDriven(
  deps: PrivateKeyExportRecoveryDeps,
  args: {
    nearAccountId: AccountId;
    options?: { variant?: 'drawer' | 'modal'; theme?: 'dark' | 'light' };
  },
): Promise<void> {
  await runExportWorkerOperation(deps, {
    nearAccountId: args.nearAccountId,
    options: {
      schemes: ['ed25519'],
      variant: args.options?.variant,
      theme: args.options?.theme,
    },
  });
}

export async function exportNearKeypairWithUI(
  deps: PrivateKeyExportRecoveryDeps,
  args: {
    nearAccountId: AccountId;
    options?: {
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
    };
  },
): Promise<{ accountId: string; publicKey: string; privateKey: string }> {
  await exportNearKeypairWithUIWorkerDriven(deps, args);
  const accountId = toAccountId(args.nearAccountId);
  const deviceNumber = await getLastLoggedInDeviceNumber(accountId, deps.indexedDB.clientDB).catch(
    () => null as number | null,
  );
  const userData =
    deviceNumber != null
      ? await deps.indexedDB.clientDB.getNearAccountProjection(accountId, deviceNumber).catch(() => null)
      : null;
  return {
    accountId: String(args.nearAccountId),
    publicKey: userData?.clientNearPublicKey ?? '',
    privateKey: '',
  };
}

export async function exportPrivateKeysWithUIWorkerDriven(
  deps: PrivateKeyExportRecoveryDeps,
  args: {
    nearAccountId: AccountId;
    options?: {
      schemes?: ExportScheme[];
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
    };
  },
): Promise<ExportPrivateKeysWithUiWorkerResult> {
  return runExportWorkerOperation(deps, args);
}

export async function exportPrivateKeysWithUI(
  deps: PrivateKeyExportRecoveryDeps,
  args: {
    nearAccountId: AccountId;
    options?: {
      schemes?: ExportScheme[];
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
    };
  },
): Promise<{ accountId: string; exportedSchemes: ExportScheme[] }> {
  const result = await exportPrivateKeysWithUIWorkerDriven(deps, args);
  return {
    accountId: result.accountId,
    exportedSchemes: result.exportedSchemes,
  };
}

export async function recoverKeypairFromPasskey(
  deps: PrivateKeyExportRecoveryDeps,
  args: {
    authenticationCredential: WebAuthnAuthenticationCredential;
    accountIdHint?: string;
  },
): Promise<RecoverKeypairResult> {
  try {
    if (!args.authenticationCredential) {
      throw new Error(
        'Authentication credential required for account recovery. '
          + 'Use an existing credential with dual PRF outputs to re-derive the same NEAR keypair.',
      );
    }

    const prfResults = args.authenticationCredential.clientExtensionResults?.prf?.results;
    if (!prfResults?.first || !prfResults?.second) {
      throw new Error(
        'Dual PRF outputs required for account recovery - both AES and Ed25519 PRF outputs must be available',
      );
    }

    const sessionId = deps.createSessionId('recover');
    return await deps.signingKeyOps.recoverKeypairFromPasskey({
      credential: args.authenticationCredential,
      accountIdHint: args.accountIdHint,
      sessionId,
    });
  } catch (error: unknown) {
    console.error('SigningEngine: Deterministic keypair derivation error:', error);
    const message = error instanceof Error ? error.message : String(error || 'Unknown error');
    throw new Error(`Deterministic keypair derivation failed: ${message}`);
  }
}

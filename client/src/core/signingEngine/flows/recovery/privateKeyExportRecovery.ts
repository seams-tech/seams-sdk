import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { ExportPrivateKeysWithUiWorkerResult } from '@/core/types/secure-confirm-worker';
import type { PrivateKeyExportRecoveryDeps } from '../../interfaces/operationDeps';
import { getLastLoggedInSignerSlot } from '../../webauthnAuth/device/signerSlot';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

type ExportScheme = 'ed25519' | 'secp256k1';
type EcdsaHssExportArtifactKind = 'ecdsa-hss-secp256k1-export';

type ExportRecoveryErrorCode = 'SIGNER_EXPORT_WORKER_BOUNDARY_REQUIRED';
type ExportRecoveryError = Error & { code: ExportRecoveryErrorCode };

const EXPORT_WORKER_BOUNDARY_REQUIRED_CODE: ExportRecoveryErrorCode =
  'SIGNER_EXPORT_WORKER_BOUNDARY_REQUIRED';
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
  event: 'signer.export.worker_boundary_required';
  nearAccountId: string;
  signerSlot?: number;
  reason: string;
}): void {
  // Structured logs are currently the canonical low-overhead telemetry surface in wallet origin.
  console.warn('[signer-export-telemetry]', {
    event: args.event,
    nearAccountId: args.nearAccountId,
    ...(typeof args.signerSlot === 'number' ? { signerSlot: args.signerSlot } : {}),
    reason: args.reason,
    timestamp: Date.now(),
  });
}

function throwExportWorkerBoundaryRequired(args: {
  nearAccountId: string;
  signerSlot?: number;
  reason: string;
}): never {
  emitExportRecoveryTelemetry({
    event: 'signer.export.worker_boundary_required',
    nearAccountId: args.nearAccountId,
    signerSlot: args.signerSlot,
    reason: args.reason,
  });
  throw createExportRecoveryError({
    code: EXPORT_WORKER_BOUNDARY_REQUIRED_CODE,
    message: `Export requires the worker-owned recovery export operation (${EXPORT_WORKER_BOUNDARY_REQUIRED_CODE})`,
  });
}

export async function exportNearEd25519SeedArtifactWithUIWorkerDriven(
  deps: PrivateKeyExportRecoveryDeps,
  args: {
    nearAccountId: AccountId;
    seedB64u: string;
    expectedPublicKey: string;
    options: {
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
  const expectedPublicKey = String(args.expectedPublicKey || '').trim();
  const seedB64u = String(args.seedB64u || '').trim();
  if (!expectedPublicKey) {
    throw new Error('Missing expectedPublicKey for single-key HSS seed export');
  }
  if (!seedB64u) {
    throw new Error('Missing seedB64u for single-key HSS seed export');
  }

  const resolvedTheme = args.options?.theme ?? deps.getTheme();
  const signerSlot = await getLastLoggedInSignerSlot(accountId, deps.indexedDB.clientDB).catch(
    () => null as number | null,
  );
  if (signerSlot == null) {
    throw new Error(`No signerSlot found for account ${accountId} (export/decrypt)`);
  }

  const result = await (async (): Promise<ExportPrivateKeysWithUiWorkerResult> => {
    try {
      return await requestExportPrivateKeysWithUi({
        nearAccountId: accountId,
        signerSlot,
        chain: 'near',
        artifactKind: 'near-ed25519-seed-v1',
        expectedPublicKey,
        seedB64u,
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
          signerSlot,
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

export async function exportNearEd25519SeedArtifactWithUI(
  deps: PrivateKeyExportRecoveryDeps,
  args: {
    nearAccountId: AccountId;
    seedB64u: string;
    expectedPublicKey: string;
    options: {
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
    };
  },
): Promise<{ accountId: string; exportedSchemes: ExportScheme[] }> {
  const result = await exportNearEd25519SeedArtifactWithUIWorkerDriven(deps, args);
  return {
    accountId: result.accountId,
    exportedSchemes: result.exportedSchemes,
  };
}

export async function exportEcdsaHssThresholdKeyArtifactWithUIWorkerDriven(
  deps: PrivateKeyExportRecoveryDeps,
  args: {
    nearAccountId: AccountId;
    artifact: {
      artifactKind: EcdsaHssExportArtifactKind;
      chainTarget: ThresholdEcdsaChainTarget;
      publicKeyHex: string;
      privateKeyHex: string;
      ethereumAddress: string;
    };
    options: {
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
  const resolvedTheme = args.options?.theme ?? deps.getTheme();
  const signerSlot = await getLastLoggedInSignerSlot(accountId, deps.indexedDB.clientDB).catch(
    () => null as number | null,
  );
  if (signerSlot == null) {
    throw new Error(`No signerSlot found for account ${accountId} (export/decrypt)`);
  }

  const artifactKind = String(args.artifact.artifactKind || '').trim();
  const publicKeyHex = String(args.artifact.publicKeyHex || '').trim();
  const privateKeyHex = String(args.artifact.privateKeyHex || '').trim();
  const ethereumAddress = String(args.artifact.ethereumAddress || '').trim();
  if (artifactKind !== 'ecdsa-hss-secp256k1-export') {
    throw new Error('Missing or invalid ecdsa-hss export artifactKind');
  }
  if (!publicKeyHex || !privateKeyHex || !ethereumAddress) {
    throw new Error('Incomplete ecdsa-hss secp256k1 export artifact');
  }
  const result = await (async (): Promise<ExportPrivateKeysWithUiWorkerResult> => {
    try {
      return await requestExportPrivateKeysWithUi({
        nearAccountId: accountId,
        signerSlot,
        chainTarget: args.artifact.chainTarget,
        artifactKind,
        publicKeyHex,
        privateKeyHex,
        ethereumAddress,
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
          signerSlot,
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

export async function exportEcdsaHssThresholdKeyArtifactWithUI(
  deps: PrivateKeyExportRecoveryDeps,
  args: {
    nearAccountId: AccountId;
    artifact: {
      artifactKind: EcdsaHssExportArtifactKind;
      chainTarget: ThresholdEcdsaChainTarget;
      publicKeyHex: string;
      privateKeyHex: string;
      ethereumAddress: string;
    };
    options: {
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
    };
  },
): Promise<{ accountId: string; exportedSchemes: ExportScheme[] }> {
  const result = await exportEcdsaHssThresholdKeyArtifactWithUIWorkerDriven(deps, args);
  return {
    accountId: result.accountId,
    exportedSchemes: result.exportedSchemes,
  };
}

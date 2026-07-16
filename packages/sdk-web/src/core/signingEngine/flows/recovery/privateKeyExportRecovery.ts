import type { ExportPrivateKeysWithUiWorkerResult } from '@/core/types/secure-confirm-worker';
import type { PrivateKeyExportRecoveryDeps } from '../../interfaces/operationDeps';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { parseWalletId, type WalletId } from '@shared/utils/domainIds';

type ExportScheme = 'secp256k1';
type EcdsaDerivationExportArtifactKind = 'ecdsa-derivation-secp256k1-export';

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
  subjectId: string;
  signerSlot?: number;
  reason: string;
}): void {
  // Structured logs are currently the canonical low-overhead telemetry surface in wallet origin.
  console.warn('[signer-export-telemetry]', {
    event: args.event,
    subjectId: args.subjectId,
    ...(typeof args.signerSlot === 'number' ? { signerSlot: args.signerSlot } : {}),
    reason: args.reason,
    timestamp: Date.now(),
  });
}

function throwExportWorkerBoundaryRequired(args: {
  subjectId: string;
  signerSlot?: number;
  reason: string;
}): never {
  emitExportRecoveryTelemetry({
    event: 'signer.export.worker_boundary_required',
    subjectId: args.subjectId,
    signerSlot: args.signerSlot,
    reason: args.reason,
  });
  throw createExportRecoveryError({
    code: EXPORT_WORKER_BOUNDARY_REQUIRED_CODE,
    message: `Export requires the worker-owned recovery export operation (${EXPORT_WORKER_BOUNDARY_REQUIRED_CODE})`,
  });
}

function requireSecp256k1ExportSchemes(
  schemes: ExportPrivateKeysWithUiWorkerResult['exportedSchemes'],
): ExportScheme[] {
  const validated: ExportScheme[] = [];
  for (const scheme of schemes) {
    if (scheme !== 'secp256k1') {
      throw new Error('ECDSA export worker returned a non-secp256k1 key scheme');
    }
    validated.push(scheme);
  }
  return validated;
}

export async function exportEcdsaDerivationThresholdKeyArtifactWithUIWorkerDriven(
  deps: PrivateKeyExportRecoveryDeps,
  args: {
    walletId: WalletId | string;
    artifact: {
      artifactKind: EcdsaDerivationExportArtifactKind;
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
  const parsedWalletId = parseWalletId(args.walletId);
  if (!parsedWalletId.ok) {
    throw new Error(parsedWalletId.error.message);
  }
  const walletId = String(parsedWalletId.value);
  if (typeof deps.requestExportPrivateKeysWithUi !== 'function') {
    throwExportWorkerBoundaryRequired({
      subjectId: walletId,
      reason: 'missing_export_worker_operation',
    });
  }
  const requestExportPrivateKeysWithUi = deps.requestExportPrivateKeysWithUi;
  const resolvedTheme = args.options?.theme ?? deps.getTheme();

  const artifactKind = String(args.artifact.artifactKind || '').trim();
  const publicKeyHex = String(args.artifact.publicKeyHex || '').trim();
  const privateKeyHex = String(args.artifact.privateKeyHex || '').trim();
  const ethereumAddress = String(args.artifact.ethereumAddress || '').trim();
  if (artifactKind !== 'ecdsa-derivation-secp256k1-export') {
    throw new Error('Missing or invalid ecdsa-derivation export artifactKind');
  }
  if (!publicKeyHex || !privateKeyHex || !ethereumAddress) {
    throw new Error('Incomplete ecdsa-derivation secp256k1 export artifact');
  }
  const result = await (async (): Promise<ExportPrivateKeysWithUiWorkerResult> => {
    try {
      return await requestExportPrivateKeysWithUi({
        walletId,
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
          subjectId: walletId,
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

export async function exportEcdsaDerivationThresholdKeyArtifactWithUI(
  deps: PrivateKeyExportRecoveryDeps,
  args: {
    walletId: WalletId | string;
    artifact: {
      artifactKind: EcdsaDerivationExportArtifactKind;
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
  const result = await exportEcdsaDerivationThresholdKeyArtifactWithUIWorkerDriven(deps, args);
  return {
    accountId: result.accountId,
    exportedSchemes: requireSecp256k1ExportSchemes(result.exportedSchemes),
  };
}

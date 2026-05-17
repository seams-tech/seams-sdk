import { toAccountId } from '@/core/types/accountIds';
import { thresholdEcdsaChainTargetKey } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  ecdsaSigningTargetFromChainTarget,
  resolveEcdsaExportMaterialForLane,
  type EcdsaExportMaterial,
} from './ecdsaExportMaterial';
import {
  exportThresholdEcdsaKeyWithAuthorization,
  exportThresholdEcdsaKeyWithFreshEmailOtpAuthorization,
  type EcdsaExportFlowDeps,
} from './ecdsaExportFlow';
import {
  restoreEcdsaSessionForExport,
  restoreNearEd25519SessionForExport,
  type ExportLaneSelectionDeps,
} from './exportLaneSelection';
import {
  runKeyExportWithFlowEvents,
  type SigningEngineExportKeypairWithUIInput,
} from './keyExportFlow';
import { deriveEvmFamilyKeyFingerprint } from '../../session/identity/evmFamilyEcdsaIdentity';
import {
  tryExportNearEd25519SingleKeyHssWithAuthorization,
  type NearEd25519SingleKeyExportDeps,
} from './nearEd25519ExportFlow';

export type ExportKeypairWithUIDeps = {
  laneSelection: ExportLaneSelectionDeps;
  nearSingleKeyHss: NearEd25519SingleKeyExportDeps;
  ecdsa: EcdsaExportFlowDeps;
};

type ExportedKeySchemes = Array<'ed25519' | 'secp256k1'>;
type ExportKeypairResult = { accountId: string; exportedSchemes: ExportedKeySchemes };

function emitEcdsaExportFailureDiagnostics(args: {
  input: Extract<SigningEngineExportKeypairWithUIInput, { kind: 'ecdsa' }>;
  flowId: string;
  exportLane?: Awaited<ReturnType<typeof restoreEcdsaSessionForExport>>;
  exportMaterial?: EcdsaExportMaterial;
  error: unknown;
}): void {
  const keyFingerprint =
    args.exportMaterial?.kind === 'ready'
      ? deriveEvmFamilyKeyFingerprint(args.exportMaterial.readyMaterial.key)
      : args.exportLane
        ? deriveEvmFamilyKeyFingerprint(args.exportLane.key)
        : undefined;
  try {
    console.warn('[SigningEngine][ecdsa-export][failure]', {
      operationId: args.flowId,
      authMethod: args.exportLane?.session.authMethod,
      ...(keyFingerprint ? { evmFamilyKeyFingerprint: keyFingerprint } : {}),
      chainTargetKey: thresholdEcdsaChainTargetKey(args.input.chainTarget),
      ecdsaThresholdKeyId:
        args.exportLane?.key.ecdsaThresholdKeyId ||
        (args.exportMaterial?.kind === 'ready'
          ? args.exportMaterial.readyMaterial.key.ecdsaThresholdKeyId
          : args.exportMaterial?.kind === 'fresh_email_otp'
            ? args.exportMaterial.ecdsaThresholdKeyId
            : undefined),
      walletSigningSessionId: args.exportLane?.session.walletSigningSessionId,
      thresholdSessionId: args.exportLane?.session.thresholdSessionId,
      budgetProjectionVersion: undefined,
      freshAuthRetrySideEffectState: 'not_applicable',
      error: args.error instanceof Error ? args.error.message : String(args.error || 'unknown error'),
    });
  } catch {}
}

async function exportKeypairWithFlowId(
  deps: ExportKeypairWithUIDeps,
  args: SigningEngineExportKeypairWithUIInput & { flowId: string },
): Promise<ExportKeypairResult> {
  if (args.kind === 'near') {
    const nearAccountId = toAccountId(args.nearAccount.accountId);
    const exportLane = await restoreNearEd25519SessionForExport(deps.laneSelection, {
      nearAccountId,
    });
    const singleKeyHssResult = await tryExportNearEd25519SingleKeyHssWithAuthorization(
      deps.nearSingleKeyHss,
      {
        nearAccountId,
        exportLane,
        options: {
          variant: args.options.variant,
          theme: args.options.theme,
        },
        flowId: args.flowId,
        onEvent: args.options.onEvent,
      },
    );
    if (singleKeyHssResult) return singleKeyHssResult;
    throw new Error('NEAR Ed25519 export now requires the canonical single-key HSS export path');
  }

  const walletSessionUserId = toAccountId(
    args.walletSession.walletSessionUserId || args.walletSession.walletId,
  );
  const exportTarget = ecdsaSigningTargetFromChainTarget(args.chainTarget);
  const rpId = String(deps.ecdsa.getRpId() || '').trim();
  if (!rpId) {
    throw new Error('Missing rpId for threshold-ecdsa export material resolution');
  }
  let exportLane: Awaited<ReturnType<typeof restoreEcdsaSessionForExport>> | undefined;
  let exportMaterial: EcdsaExportMaterial | undefined;
  try {
    exportLane = await restoreEcdsaSessionForExport(deps.laneSelection, {
      walletId: walletSessionUserId,
      rpId,
      subjectId: args.subjectId,
      signingTarget: exportTarget,
    });
    exportMaterial = await resolveEcdsaExportMaterialForLane(
      deps.ecdsa.sessionStore,
      exportLane,
      rpId,
    );
    if (exportMaterial.kind === 'fresh_email_otp') {
      return await exportThresholdEcdsaKeyWithFreshEmailOtpAuthorization(deps.ecdsa, {
        walletSessionUserId,
        exportLane,
        material: exportMaterial,
        options: {
          variant: args.options.variant,
          theme: args.options.theme,
        },
        flowId: args.flowId,
        onEvent: args.options.onEvent,
      });
    }
    return await exportThresholdEcdsaKeyWithAuthorization(deps.ecdsa, {
      walletSessionUserId,
      material: exportMaterial.readyMaterial,
      exportLane,
      options: {
        variant: args.options.variant,
        theme: args.options.theme,
      },
      flowId: args.flowId,
      onEvent: args.options.onEvent,
    });
  } catch (error: unknown) {
    emitEcdsaExportFailureDiagnostics({
      input: args,
      flowId: args.flowId,
      ...(exportLane ? { exportLane } : {}),
      ...(exportMaterial ? { exportMaterial } : {}),
      error,
    });
    throw error;
  }
}

export async function exportKeypairWithUI(
  deps: ExportKeypairWithUIDeps,
  input: SigningEngineExportKeypairWithUIInput,
): Promise<ExportKeypairResult> {
  return await runKeyExportWithFlowEvents(input, (args) => exportKeypairWithFlowId(deps, args));
}

export type { SigningEngineExportKeypairWithUIInput } from './keyExportFlow';

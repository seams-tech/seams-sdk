import { toAccountId } from '@/core/types/accountIds';
import {
  ecdsaSigningTargetFromChainTarget,
  resolveEcdsaExportMaterialForLane,
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

  const walletSessionUserId = toAccountId(args.walletSessionUserId);
  const exportTarget = ecdsaSigningTargetFromChainTarget(args.chainTarget);
  const exportLane = await restoreEcdsaSessionForExport(deps.laneSelection, {
    nearAccountId: walletSessionUserId,
    subjectId: args.subjectId,
    signingTarget: exportTarget,
  });
  const exportMaterial = await resolveEcdsaExportMaterialForLane(
    deps.ecdsa.sessionStore,
    exportLane,
  );
  if (exportMaterial.kind === 'fresh_email_otp') {
    return await exportThresholdEcdsaKeyWithFreshEmailOtpAuthorization(deps.ecdsa, {
      nearAccountId: walletSessionUserId,
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
    nearAccountId: walletSessionUserId,
    keyRef: exportMaterial.keyRef,
    exportLane,
    options: {
      variant: args.options.variant,
      theme: args.options.theme,
    },
    flowId: args.flowId,
    onEvent: args.options.onEvent,
  });
}

export async function exportKeypairWithUI(
  deps: ExportKeypairWithUIDeps,
  input: SigningEngineExportKeypairWithUIInput,
): Promise<ExportKeypairResult> {
  return await runKeyExportWithFlowEvents(input, (args) => exportKeypairWithFlowId(deps, args));
}

export type { SigningEngineExportKeypairWithUIInput } from './keyExportFlow';

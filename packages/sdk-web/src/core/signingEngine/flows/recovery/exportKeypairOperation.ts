import { toAccountId } from '@/core/types/accountIds';
import {
  thresholdEcdsaChainTargetKey,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildImplicitNearAccountBinding,
  buildNamedNearAccountBinding,
  buildNearEd25519SignerBinding,
  buildWalletIdentity,
} from '@shared/utils/walletCapabilityBindings';
import {
  isImplicitNearAccountId,
  parseImplicitNearAccountId,
  parseNamedNearAccountId,
} from '@shared/utils/near';
import { ed25519KeyScopeIdFromString } from '@shared/utils/registrationIntent';
import {
  ecdsaSigningTargetFromChainTarget,
  resolveEcdsaExportMaterialForLane,
  type EcdsaExportMaterial,
} from './ecdsaExportMaterial';
import {
  exportThresholdEcdsaKeyWithAuthorization,
  exportThresholdEcdsaKeyWithFreshEmailOtpAuthorization,
  exportThresholdEcdsaKeyWithFreshEmailOtpRouteAuth,
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
import { deriveEvmFamilyKeyFingerprintFromPublicFacts } from '../../session/identity/evmFamilyEcdsaIdentity';
import {
  tryExportNearEd25519SingleKeyHssWithAuthorization,
  type NearEd25519SingleKeyExportDeps,
} from './nearEd25519ExportFlow';
import { getStoredThresholdEd25519SessionRecordForAccount } from '../../session/persistence/records';

export type ExportKeypairWithUIDeps = {
  laneSelection: ExportLaneSelectionDeps;
  nearSingleKeyHss: NearEd25519SingleKeyExportDeps;
  ecdsa: EcdsaExportFlowDeps;
};

type ExportedKeySchemes = Array<'ed25519' | 'secp256k1'>;
type ExportKeypairResult = { accountId: string; exportedSchemes: ExportedKeySchemes };

function buildNearAccountBindingForExport(args: {
  wallet: ReturnType<typeof buildWalletIdentity>;
  nearAccountId: ReturnType<typeof toAccountId>;
}) {
  if (isImplicitNearAccountId(args.nearAccountId)) {
    const parsed = parseImplicitNearAccountId(args.nearAccountId);
    if (!parsed.ok) throw new Error(parsed.message);
    return buildImplicitNearAccountBinding({
      wallet: args.wallet,
      nearAccountId: parsed.value,
    });
  }
  const parsed = parseNamedNearAccountId(args.nearAccountId);
  if (!parsed.ok) throw new Error(parsed.message);
  return buildNamedNearAccountBinding({
    wallet: args.wallet,
    nearAccountId: parsed.value,
  });
}

function resolveNearEd25519SignerBindingForExport(
  args: Extract<SigningEngineExportKeypairWithUIInput, { kind: 'near' }>,
) {
  const nearAccountId = toAccountId(args.nearAccount.accountId);
  const walletId = String(args.walletSession.walletId || '').trim();
  if (!walletId) {
    throw new Error('NEAR Ed25519 export requires wallet session identity');
  }
  const record = getStoredThresholdEd25519SessionRecordForAccount(nearAccountId);
  if (!record) {
    throw new Error('NEAR Ed25519 export requires a stored signer binding');
  }
  if (String(record.walletId) !== walletId) {
    throw new Error('NEAR Ed25519 export wallet identity mismatch');
  }
  if (String(record.nearAccountId) !== String(nearAccountId)) {
    throw new Error('NEAR Ed25519 export account identity mismatch');
  }
  const rawEd25519KeyScopeId = String(record.ed25519KeyScopeId || '').trim();
  if (!rawEd25519KeyScopeId) {
    throw new Error('NEAR Ed25519 export requires ed25519KeyScopeId');
  }
  const signerSlot = Number(record.signerSlot ?? 0);
  const wallet = buildWalletIdentity({ walletId: record.walletId });
  const account = buildNearAccountBindingForExport({ wallet, nearAccountId });
  return buildNearEd25519SignerBinding({
    account,
    ed25519KeyScopeId: ed25519KeyScopeIdFromString(rawEd25519KeyScopeId),
    signerSlot,
  });
}

function emitEcdsaExportFailureDiagnostics(args: {
  input: Extract<SigningEngineExportKeypairWithUIInput, { kind: 'ecdsa' }>;
  flowId: string;
  exportLane?: Awaited<ReturnType<typeof restoreEcdsaSessionForExport>>;
  exportMaterial?: EcdsaExportMaterial;
  error: unknown;
}): void {
  const publicFacts = args.exportMaterial?.publicFacts || args.exportLane?.publicFacts;
  const keyFingerprint =
    args.exportMaterial?.kind === 'ready_threshold_ecdsa_export_material'
      ? args.exportMaterial.evmFamilyKeyFingerprint
      : args.exportLane
        ? deriveEvmFamilyKeyFingerprintFromPublicFacts({
            walletId: args.exportLane.key.walletId,
            publicFacts: args.exportLane.publicFacts,
          })
        : undefined;
  try {
    console.warn('[SigningEngine][ecdsa-export][failure]', {
      operationId: args.flowId,
      authMethod: args.exportLane?.session.authMethod,
      ...(keyFingerprint ? { evmFamilyKeyFingerprint: keyFingerprint } : {}),
      ...(publicFacts ? { keyHandle: String(publicFacts.keyHandle) } : {}),
      chainTargetKey: thresholdEcdsaChainTargetKey(args.input.chainTarget),
      signingGrantId: args.exportLane?.session.signingGrantId,
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
    const signer = resolveNearEd25519SignerBindingForExport(args);
    const exportLane = await restoreNearEd25519SessionForExport(deps.laneSelection, {
      signer,
      laneIdentity: args.laneIdentity,
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

  const walletId = toWalletId(args.walletSession.walletId);
  const exportTarget = ecdsaSigningTargetFromChainTarget(args.chainTarget);
  let exportLane: Awaited<ReturnType<typeof restoreEcdsaSessionForExport>> | undefined;
  let exportMaterial: EcdsaExportMaterial | undefined;
  try {
    exportLane = await restoreEcdsaSessionForExport(deps.laneSelection, {
      walletId,
      signingTarget: exportTarget,
      laneIdentity: args.laneIdentity,
    });
    exportMaterial = await resolveEcdsaExportMaterialForLane(
      deps.ecdsa.sessionStore,
      exportLane,
    );
    if (exportMaterial.kind === 'fresh_email_otp_needs_challenge') {
      return await exportThresholdEcdsaKeyWithFreshEmailOtpAuthorization(deps.ecdsa, {
        walletId,
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
    if (exportMaterial.kind === 'fresh_email_otp_route_auth_ready') {
      return await exportThresholdEcdsaKeyWithFreshEmailOtpRouteAuth(deps.ecdsa, {
        walletId,
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
      walletId,
      material: exportMaterial,
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

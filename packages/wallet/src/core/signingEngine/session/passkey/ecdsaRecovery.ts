import type { WarmSessionSealTransportInput } from '@/core/types/secure-confirm-worker';
import type { RestorePersistedSessionPurpose } from '@/core/signingEngine/session/sealedRecovery/sealedRecovery.types';
import type { PasskeyEcdsaSealedRecoveryRecord } from '@/core/signingEngine/session/sealedRecovery/recoveryRecord';
import type { WarmSessionStatusResult } from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import {
  thresholdEcdsaChainTargetsEqual,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  ActiveEcdsaCapabilityRuntimeResolver,
  ActiveEcdsaCapabilityRuntimeResolution,
} from '../material/activeEcdsaCapabilityRuntime';
import { mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';
import {
  parseSigningSessionSealKeyVersion,
  type SigningSessionSealKeyVersion,
} from '../keyMaterialBrands';

function shouldDeletePasskeyEcdsaSealedRecordAfterRestoreFailure(
  status: WarmSessionStatusResult,
): boolean {
  if (status.ok) return false;
  switch (status.code) {
    case 'expired':
    case 'exhausted':
      return false;
    case 'not_found':
    case 'invalid_args':
    case 'invalid_response':
      return true;
    default:
      return false;
  }
}

type PasskeyEcdsaRestoreRuntimeCheck =
  | {
      kind: 'current';
      resolution: Extract<ActiveEcdsaCapabilityRuntimeResolution, { kind: 'resolved' }>;
    }
  | { kind: 'superseded'; status: Extract<WarmSessionStatusResult, { ok: false }> };

async function checkCurrentPasskeyEcdsaRuntime(args: {
  record: PasskeyEcdsaSealedRecoveryRecord;
  resolveCurrentEcdsaCapabilityRuntime: ActiveEcdsaCapabilityRuntimeResolver;
}): Promise<PasskeyEcdsaRestoreRuntimeCheck> {
  const resolution = await args.resolveCurrentEcdsaCapabilityRuntime({
    walletId: toWalletId(args.record.walletId),
    chainTarget: args.record.chainTarget,
  });
  if (
    resolution.kind === 'resolved' &&
    mpcMaterialActivationRefsEqual(
      resolution.runtime.materialActivation,
      args.record.roleLocalMaterialRef.materialActivation,
    )
  ) {
    return { kind: 'current', resolution };
  }
  const reason = resolution.kind === 'blocked' ? resolution.reason : 'material_activation_mismatch';
  return {
    kind: 'superseded',
    status: {
      ok: false,
      code: 'superseded',
      message: `Passkey ECDSA sealed recovery was superseded (${reason})`,
    },
  };
}

export async function restorePasskeyEcdsaSealedRecordForWallet(args: {
  record: PasskeyEcdsaSealedRecoveryRecord;
  purpose: RestorePersistedSessionPurpose & { authMethod: 'passkey' };
  transport: WarmSessionSealTransportInput;
  groupId: string;
  rehydrateWarmSessionMaterial: (args: {
    thresholdSessionId: string;
    sealedSecretB64u: string;
    signingSessionSealKeyVersion?: SigningSessionSealKeyVersion;
    expiresAtMs: number;
    remainingUses: number;
    transport: WarmSessionSealTransportInput;
  }) => Promise<WarmSessionStatusResult>;
  deletePersistedRecord: () => Promise<void>;
  recordSessionMaterialRestored: (status: WarmSessionStatusResult) => Promise<void>;
  readWarmSessionStatusFromWorker: (
    thresholdSessionId: string,
  ) => Promise<WarmSessionStatusResult | null>;
  resolveCurrentEcdsaCapabilityRuntime: ActiveEcdsaCapabilityRuntimeResolver;
  updatePersistedPolicy: (args: {
    expiresAtMs: number;
    remainingUses: number;
    updatedAtMs: number;
  }) => Promise<void>;
}): Promise<WarmSessionStatusResult | null> {
  if (!thresholdEcdsaChainTargetsEqual(args.record.chainTarget, args.purpose.chainTarget)) {
    return null;
  }
  const thresholdSessionId = String(args.purpose.thresholdSessionId || '').trim();
  if (!thresholdSessionId || !args.groupId) {
    return null;
  }

  const currentBeforeWorker = await checkCurrentPasskeyEcdsaRuntime({
    record: args.record,
    resolveCurrentEcdsaCapabilityRuntime: args.resolveCurrentEcdsaCapabilityRuntime,
  });
  if (currentBeforeWorker.kind === 'superseded') return currentBeforeWorker.status;

  const rehydrated = await args.rehydrateWarmSessionMaterial({
    thresholdSessionId,
    sealedSecretB64u: args.record.sealedSecretB64u,
    signingSessionSealKeyVersion: parseSigningSessionSealKeyVersion(args.record.keyVersion),
    expiresAtMs: args.record.expiresAtMs,
    remainingUses: args.record.remainingUses,
    transport: {
      ...args.transport,
      groupId: args.groupId,
    },
  });
  if (!rehydrated.ok) {
    const currentBeforeFailureWrites = await checkCurrentPasskeyEcdsaRuntime({
      record: args.record,
      resolveCurrentEcdsaCapabilityRuntime: args.resolveCurrentEcdsaCapabilityRuntime,
    });
    if (currentBeforeFailureWrites.kind === 'superseded') {
      return currentBeforeFailureWrites.status;
    }
    if (shouldDeletePasskeyEcdsaSealedRecordAfterRestoreFailure(rehydrated)) {
      await args.deletePersistedRecord().catch(() => undefined);
    }
    await args.recordSessionMaterialRestored(rehydrated);
    return rehydrated;
  }

  const parsed = await args.readWarmSessionStatusFromWorker(thresholdSessionId);
  if (!parsed) {
    return {
      ok: false,
      code: 'worker_error',
      message: 'Warm-session status read failed after rehydrate',
    };
  }
  const currentBeforeDurableWrites = await checkCurrentPasskeyEcdsaRuntime({
    record: args.record,
    resolveCurrentEcdsaCapabilityRuntime: args.resolveCurrentEcdsaCapabilityRuntime,
  });
  if (currentBeforeDurableWrites.kind === 'superseded') {
    return currentBeforeDurableWrites.status;
  }
  if (parsed.ok) {
    await args
      .updatePersistedPolicy({
        expiresAtMs: parsed.expiresAtMs,
        remainingUses: parsed.remainingUses,
        updatedAtMs: Date.now(),
      })
      .catch(() => undefined);
  } else {
    if (shouldDeletePasskeyEcdsaSealedRecordAfterRestoreFailure(parsed)) {
      await args.deletePersistedRecord().catch(() => undefined);
    }
  }
  await args.recordSessionMaterialRestored(parsed);
  return parsed;
}

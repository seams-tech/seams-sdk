import {
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WarmSessionSealTransportInput } from '@/core/types/secure-confirm-worker';
import type { RestorePersistedEcdsaSessionPurpose } from '@/core/signingEngine/session/sealedRecovery/sealedRecovery.types';
import {
  type PasskeyEcdsaSealedRecoveryRecord,
} from '@/core/signingEngine/session/sealedRecovery/recoveryRecord';
import type { WarmSessionStatusResult } from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import { thresholdEcdsaChainTargetsEqual } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { publishResolvedIdentity } from '@/core/signingEngine/session/persistence/sealedSessionStore';
import {
  parseSigningSessionSealKeyVersion,
  type SigningSessionSealKeyVersion,
} from '../keyMaterialBrands';
import {
} from '@/core/signingEngine/session/persistence/records';
import { claimWarmSessionPrfFirst, type PasskeyWarmSessionRecoveryPorts } from './prfClaim';

type PasskeySessionRestoreIdentity = {
  touchConfirm: PasskeyWarmSessionRecoveryPorts;
  walletId: string;
  signingGrantId: string;
  thresholdSessionId: string;
};

function shouldDeletePasskeyEcdsaSealedRecordAfterRestoreFailure(
  status: WarmSessionStatusResult,
): boolean {
  if (status.ok) return false;
  switch (status.code) {
    case 'expired':
    case 'not_found':
    case 'invalid_args':
    case 'invalid_response':
      return true;
    case 'exhausted':
      return false;
    default:
      return false;
  }
}

export type PasskeyEcdsaPrfClaimArgs = PasskeySessionRestoreIdentity & {
  chainTarget: ThresholdEcdsaChainTarget;
  errorContext: string;
  uses?: number;
  consume?: boolean;
};

async function publishPasskeyEcdsaSealedRecordForWallet(args: {
  walletId: string;
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdSessionId: string;
  signingGrantId: string;
}): Promise<void> {
  const updatedAtMs = Date.now();
  publishResolvedIdentity({
    walletId: args.walletId,
    authMethod: 'passkey',
    curve: 'ecdsa',
    chainTarget: args.chainTarget,
    signingGrantId: args.signingGrantId,
    thresholdSessionId: args.thresholdSessionId,
    updatedAtMs,
  });
}

export async function claimPasskeyEcdsaPrfFirst(args: PasskeyEcdsaPrfClaimArgs): Promise<string> {
  return await claimWarmSessionPrfFirst({
    touchConfirm: args.touchConfirm,
    thresholdSessionId: args.thresholdSessionId,
    errorContext: args.errorContext,
    uses: args.uses,
    ...(typeof args.consume === 'boolean' ? { consume: args.consume } : {}),
    curve: 'ecdsa',
    chainTarget: args.chainTarget,
  });
}

export async function restorePasskeyEcdsaSealedRecordForWallet(args: {
  walletId: string;
  record: PasskeyEcdsaSealedRecoveryRecord;
  purpose: RestorePersistedEcdsaSessionPurpose & { authMethod: 'passkey' };
  transport: WarmSessionSealTransportInput;
  shamirPrimeB64u: string;
  rehydrateWarmSessionMaterial: (args: {
    sessionId: string;
    sealedSecretB64u: string;
    signingSessionSealKeyVersion?: SigningSessionSealKeyVersion;
    expiresAtMs: number;
    remainingUses: number;
    transport: WarmSessionSealTransportInput;
  }) => Promise<WarmSessionStatusResult>;
  deletePersistedRecord: () => Promise<void>;
  recordSessionMaterialRestored: (status: WarmSessionStatusResult) => Promise<void>;
  readWarmSessionStatusFromWorker: (sessionId: string) => Promise<WarmSessionStatusResult | null>;
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
  const signingGrantId = String(args.purpose.signingGrantId || '').trim();
  if (!thresholdSessionId || !signingGrantId || !args.shamirPrimeB64u) {
    return null;
  }

  try {
    await publishPasskeyEcdsaSealedRecordForWallet({
      walletId: args.walletId,
      chainTarget: args.purpose.chainTarget,
      thresholdSessionId,
      signingGrantId,
    });
  } catch (error) {
    return {
      ok: false,
      code: 'invalid_role_local_durable_restore',
      message: error instanceof Error ? error.message : String(error),
    };
  }

  const rehydrated = await args.rehydrateWarmSessionMaterial({
    sessionId: thresholdSessionId,
    sealedSecretB64u: args.record.sealedSecretB64u,
    signingSessionSealKeyVersion: parseSigningSessionSealKeyVersion(args.record.keyVersion),
    expiresAtMs: args.record.expiresAtMs,
    remainingUses: Math.max(1_000_000, Math.floor(Number(args.record.remainingUses) || 0)),
    transport: {
      ...args.transport,
      shamirPrimeB64u: args.shamirPrimeB64u,
    },
  });
  if (!rehydrated.ok) {
    if (rehydrated.code === 'exhausted') {
      await publishPasskeyEcdsaSealedRecordForWallet({
        walletId: args.walletId,
        chainTarget: args.purpose.chainTarget,
        thresholdSessionId,
        signingGrantId,
      }).catch(() => undefined);
    }
    if (shouldDeletePasskeyEcdsaSealedRecordAfterRestoreFailure(rehydrated)) {
      await args.deletePersistedRecord().catch(() => undefined);
    }
    await args.recordSessionMaterialRestored(rehydrated);
    return rehydrated;
  }

  try {
    await publishPasskeyEcdsaSealedRecordForWallet({
      walletId: args.walletId,
      chainTarget: args.purpose.chainTarget,
      thresholdSessionId,
      signingGrantId,
    });
  } catch (error) {
    return {
      ok: false,
      code: 'invalid_role_local_durable_restore',
      message: error instanceof Error ? error.message : String(error),
    };
  }
  await args.recordSessionMaterialRestored(rehydrated);
  const parsed = await args.readWarmSessionStatusFromWorker(thresholdSessionId);
  if (!parsed) {
    return {
      ok: false,
      code: 'worker_error',
      message: 'Warm-session status read failed after rehydrate',
    };
  }
  if (parsed.ok) {
    await publishPasskeyEcdsaSealedRecordForWallet({
      walletId: args.walletId,
      chainTarget: args.purpose.chainTarget,
      thresholdSessionId,
      signingGrantId,
    }).catch(() => undefined);
    await args
      .updatePersistedPolicy({
        expiresAtMs: parsed.expiresAtMs,
        remainingUses: parsed.remainingUses,
        updatedAtMs: Date.now(),
      })
      .catch(() => undefined);
  } else {
    if (parsed.code === 'exhausted') {
      await publishPasskeyEcdsaSealedRecordForWallet({
        walletId: args.walletId,
        chainTarget: args.purpose.chainTarget,
        thresholdSessionId,
        signingGrantId,
      });
    }
    if (shouldDeletePasskeyEcdsaSealedRecordAfterRestoreFailure(parsed)) {
      await args.deletePersistedRecord().catch(() => undefined);
    }
  }
  return parsed;
}

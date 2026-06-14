import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WarmSessionSealTransportInput } from '@/core/types/secure-confirm-worker';
import type { RestorePersistedEcdsaSessionPurpose } from '@/core/signingEngine/session/sealedRecovery/types';
import type { PasskeyEcdsaSealedRecoveryRecord } from '@/core/signingEngine/session/sealedRecovery/recoveryRecord';
import type { WarmSessionStatusResult } from '@/core/signingEngine/uiConfirm/types';
import { toAccountId } from '@/core/types/accountIds';
import { thresholdEcdsaChainTargetsEqual } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toEvmFamilyEcdsaKeyHandle } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { publishResolvedIdentity } from '@/core/signingEngine/session/persistence/sealedSessionStore';
import {
  getStoredThresholdEcdsaSessionRecordByThresholdSessionId,
  thresholdEcdsaRecordRpId,
  upsertStoredThresholdEcdsaSessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import { buildEcdsaSessionIdentity } from '@/core/signingEngine/session/warmCapabilities/ecdsaProvisionPlan';
import { claimWarmSessionPrfFirst, type PasskeyWarmSessionRecoveryPorts } from './prfClaim';

type PasskeySessionRestoreIdentity = {
  touchConfirm: PasskeyWarmSessionRecoveryPorts;
  walletId: string;
  walletSigningSessionId: string;
  thresholdSessionId: string;
};

function isPermanentSealedSessionRehydrateFailure(status: WarmSessionStatusResult): boolean {
  if (status.ok) return false;
  return (
    status.code === 'expired' ||
    status.code === 'exhausted' ||
    status.code === 'not_found' ||
    status.code === 'invalid_args' ||
    status.code === 'invalid_response'
  );
}

export type PasskeyEcdsaPrfClaimArgs = PasskeySessionRestoreIdentity & {
  chainTarget: ThresholdEcdsaChainTarget;
  errorContext: string;
  uses?: number;
  consume?: boolean;
};

export async function restorePasskeyEcdsaSessionBeforeClaim(
  args: PasskeySessionRestoreIdentity & { chainTarget: ThresholdEcdsaChainTarget },
): Promise<void> {
  if (typeof args.touchConfirm.restorePersistedSessionForSigning !== 'function') return;
  const identity = buildEcdsaSessionIdentity({
    walletSigningSessionId: args.walletSigningSessionId,
    thresholdSessionId: args.thresholdSessionId,
  });
  await args.touchConfirm.restorePersistedSessionForSigning({
    walletId: String(args.walletId).trim(),
    authMethod: 'passkey',
    curve: 'ecdsa',
    chainTarget: args.chainTarget,
    walletSigningSessionId: identity.walletSigningSessionId,
    thresholdSessionId: identity.thresholdSessionId,
    reason: 'transaction',
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
    restoreBeforeClaim: () =>
      restorePasskeyEcdsaSessionBeforeClaim({
        touchConfirm: args.touchConfirm,
        walletId: args.walletId,
        walletSigningSessionId: args.walletSigningSessionId,
        thresholdSessionId: args.thresholdSessionId,
        chainTarget: args.chainTarget,
      }),
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
    keyVersion?: string;
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
  const walletSigningSessionId = String(args.purpose.walletSigningSessionId || '').trim();
  if (!thresholdSessionId || !walletSigningSessionId || !args.shamirPrimeB64u) {
    return null;
  }

  const publishRecord = (policy: { expiresAtMs: number; remainingUses: number }): void => {
    const existingRecord =
      getStoredThresholdEcdsaSessionRecordByThresholdSessionId(thresholdSessionId);
    const ecdsaRoleLocalReadyRecord = existingRecord?.ecdsaRoleLocalReadyRecord;
    if (!ecdsaRoleLocalReadyRecord) {
      throw new Error('passkey ECDSA restore requires existing role-local ready record');
    }

    upsertStoredThresholdEcdsaSessionRecord(
      { recordsByLane: new Map() },
      {
        walletId: toAccountId(args.walletId),
        authMetadata: { rpId: thresholdEcdsaRecordRpId(args.record) },
        chainTarget: args.record.chainTarget,
        relayerUrl: args.record.relayerUrl,
        keyHandle: toEvmFamilyEcdsaKeyHandle(args.record.keyHandle),
        ecdsaThresholdKeyId: args.record.ecdsaThresholdKeyId,
        relayerKeyId: args.record.relayerKeyId,
        clientVerifyingShareB64u: args.record.clientVerifyingShareB64u,
        ecdsaRoleLocalReadyRecord,
        participantIds: [...args.record.participantIds],
        ...(args.record.thresholdEcdsaPublicKeyB64u
          ? { thresholdEcdsaPublicKeyB64u: args.record.thresholdEcdsaPublicKeyB64u }
          : {}),
        ethereumAddress: args.record.ethereumAddress,
        ...(args.record.runtimePolicyScope
          ? { runtimePolicyScope: args.record.runtimePolicyScope }
          : existingRecord?.runtimePolicyScope
            ? { runtimePolicyScope: existingRecord.runtimePolicyScope }
            : {}),
        thresholdSessionKind: args.record.sessionKind,
        thresholdSessionId,
        walletSigningSessionId,
        ...(args.record.sessionKind === 'jwt'
          ? { thresholdSessionAuthToken: args.record.thresholdSessionAuthToken }
          : {}),
        ...(args.record.keyVersion ? { signingSessionSealKeyVersion: args.record.keyVersion } : {}),
        ...(args.record.shamirPrimeB64u
          ? { signingSessionSealShamirPrimeB64u: args.record.shamirPrimeB64u }
          : {}),
        expiresAtMs: policy.expiresAtMs,
        remainingUses: policy.remainingUses,
        updatedAtMs: Date.now(),
        source: 'login',
      },
    );
    publishResolvedIdentity({
      walletId: args.walletId,
      authMethod: 'passkey',
      curve: 'ecdsa',
      chainTarget: args.purpose.chainTarget,
      walletSigningSessionId,
      thresholdSessionId,
    });
  };

  try {
    publishRecord({
      expiresAtMs: Math.floor(Number(args.record.expiresAtMs) || 0),
      remainingUses: Math.max(0, Math.floor(Number(args.record.remainingUses) || 0)),
    });
  } catch (error) {
    return {
      ok: false,
      code: 'missing_role_local_ready_record',
      message: error instanceof Error ? error.message : String(error),
    };
  }

  const rehydrated = await args.rehydrateWarmSessionMaterial({
    sessionId: thresholdSessionId,
    sealedSecretB64u: args.record.sealedSecretB64u,
    keyVersion: args.record.keyVersion,
    expiresAtMs: args.record.expiresAtMs,
    remainingUses: Math.max(1_000_000, Math.floor(Number(args.record.remainingUses) || 0)),
    transport: {
      ...args.transport,
      shamirPrimeB64u: args.shamirPrimeB64u,
    },
  });
  if (!rehydrated.ok) {
    if (isPermanentSealedSessionRehydrateFailure(rehydrated)) {
      await args.deletePersistedRecord().catch(() => undefined);
    }
    await args.recordSessionMaterialRestored(rehydrated);
    return rehydrated;
  }

  try {
    publishRecord({
      expiresAtMs: rehydrated.expiresAtMs,
      remainingUses: rehydrated.remainingUses,
    });
  } catch (error) {
    return {
      ok: false,
      code: 'missing_role_local_ready_record',
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
    await args
      .updatePersistedPolicy({
        expiresAtMs: parsed.expiresAtMs,
        remainingUses: parsed.remainingUses,
        updatedAtMs: Date.now(),
      })
      .catch(() => undefined);
  }
  return parsed;
}

import type { WarmSessionSealTransportInput } from '@/core/types/secure-confirm-worker';
import type { AccountId } from '@/core/types/accountIds';
import {
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  upsertStoredThresholdEd25519SessionRecord,
  type ThresholdEd25519SessionRecord,
} from '../persistence/records';
import type {
  ProvisionWarmEd25519CapabilityArgs,
  ProvisionWarmEd25519CapabilityResult,
} from '../warmCapabilities/types';
import {
  sealedRecoverySessionKind,
  sealedRecoveryWalletSessionJwt,
  type PasskeyEd25519SealedRecoveryRecord,
} from '@/core/signingEngine/session/sealedRecovery/recoveryRecord';
import type { RestorePersistedEd25519SessionPurpose } from '@/core/signingEngine/session/sealedRecovery/types';
import type { WarmSessionStatusResult } from '@/core/signingEngine/uiConfirm/types';
import { publishResolvedIdentity } from '@/core/signingEngine/session/persistence/sealedSessionStore';
import { SigningSessionIds } from '@/core/signingEngine/session/operationState/types';
import type { ThresholdEd25519WebAuthnPrfSecretSource } from '../../threshold/ed25519/walletSession';
import { claimWarmSessionPrfFirst, type PasskeyWarmSessionRecoveryPorts } from './prfClaim';

type PasskeyEd25519SessionRestoreIdentity = {
  touchConfirm: PasskeyWarmSessionRecoveryPorts;
  walletId: string;
  signingGrantId: string;
  thresholdSessionId: string;
};

export type PasskeyEd25519PrfClaimArgs = PasskeyEd25519SessionRestoreIdentity & {
  errorContext: string;
  uses?: number;
  consume?: boolean;
};

export async function restorePasskeyEd25519SessionBeforeClaim(
  args: PasskeyEd25519SessionRestoreIdentity,
): Promise<void> {
  if (typeof args.touchConfirm.restorePersistedSessionForSigning !== 'function') return;
  const signingGrantId = SigningSessionIds.signingGrant(
    args.signingGrantId,
  );
  const thresholdSessionId = SigningSessionIds.thresholdEd25519Session(args.thresholdSessionId);
  await args.touchConfirm.restorePersistedSessionForSigning({
    walletId: String(args.walletId).trim(),
    authMethod: 'passkey',
    curve: 'ed25519',
    chain: 'near',
    signingGrantId,
    thresholdSessionId,
    reason: 'transaction',
  });
}

export async function claimPasskeyEd25519PrfFirst(
  args: PasskeyEd25519PrfClaimArgs,
): Promise<string> {
  return await claimWarmSessionPrfFirst({
    touchConfirm: args.touchConfirm,
    thresholdSessionId: args.thresholdSessionId,
    errorContext: args.errorContext,
    uses: args.uses,
    ...(typeof args.consume === 'boolean' ? { consume: args.consume } : {}),
    curve: 'ed25519',
    chain: 'near',
    restoreBeforeClaim: () =>
      restorePasskeyEd25519SessionBeforeClaim({
        touchConfirm: args.touchConfirm,
        walletId: args.walletId,
        signingGrantId: args.signingGrantId,
        thresholdSessionId: args.thresholdSessionId,
      }),
  });
}

export async function reconnectPasskeyEd25519CapabilityForSigning(args: {
  nearAccountId: AccountId;
  record: ThresholdEd25519SessionRecord;
  policySecretSource: ThresholdEd25519WebAuthnPrfSecretSource;
  remainingUses?: number;
  sessionId: string;
  signingGrantId: string;
  provisionThresholdEd25519Session: (
    args: ProvisionWarmEd25519CapabilityArgs,
  ) => Promise<ProvisionWarmEd25519CapabilityResult>;
  readStoredThresholdEd25519SessionRecordByThresholdSessionId?: (
    thresholdSessionId: string,
  ) => ThresholdEd25519SessionRecord | null;
}): Promise<{ sessionId: string; record?: ThresholdEd25519SessionRecord }> {
  const reconnectRemainingUses = Math.max(1, Math.floor(Number(args.remainingUses) || 1));
  const sessionId = String(args.sessionId || '').trim();
  const signingGrantId = String(args.signingGrantId || '').trim();
  if (!sessionId || !signingGrantId) {
    throw new Error('Passkey Ed25519 signing session reconnect requires exact session identity');
  }
  const provisioned = await args.provisionThresholdEd25519Session({
    kind: 'exact_ed25519_provisioning',
    nearAccountId: args.nearAccountId,
    relayerUrl: args.record.relayerUrl,
    relayerKeyId: args.record.relayerKeyId,
    source: 'login',
    auth: {
      kind: 'threshold_session_policy_webauthn',
      policySecretSource: args.policySecretSource,
    },
    ...(args.record.runtimePolicyScope
      ? { runtimePolicyScope: args.record.runtimePolicyScope }
      : {}),
    ...(args.record.routerAbNormalSigning
      ? { routerAbNormalSigning: args.record.routerAbNormalSigning }
      : {}),
    participantIds: args.record.participantIds,
    sessionKind: 'jwt',
    sessionId,
    signingGrantId,
    remainingUses: reconnectRemainingUses,
  });
  if (!provisioned.ok) {
    throw new Error(
      provisioned.message || provisioned.code || 'Passkey Ed25519 signing session reconnect failed',
    );
  }
  const refreshedRecord =
    args.readStoredThresholdEd25519SessionRecordByThresholdSessionId?.(sessionId) ||
    getStoredThresholdEd25519SessionRecordByThresholdSessionId(sessionId);
  if (!refreshedRecord) {
    throw new Error(
      '[SigningEngine][near] passkey Ed25519 reconnect did not publish the planned session record',
    );
  }
  if (String(refreshedRecord.signingGrantId || '').trim() !== signingGrantId) {
    throw new Error(
      '[SigningEngine][near] passkey Ed25519 reconnect returned a wallet signing-session mismatch',
    );
  }
  return {
    sessionId: provisioned.sessionId,
    record: refreshedRecord,
  };
}

export async function restorePasskeyEd25519SealedRecordForAccount(args: {
  accountId: string;
  record: PasskeyEd25519SealedRecoveryRecord;
  purpose: RestorePersistedEd25519SessionPurpose & { authMethod: 'passkey' };
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
  const thresholdSessionId = String(args.purpose.thresholdSessionId || '').trim();
  const signingGrantId = String(args.purpose.signingGrantId || '').trim();
  if (!thresholdSessionId || !signingGrantId || !args.shamirPrimeB64u) {
    return null;
  }

  const publishRecord = (policy: { expiresAtMs: number; remainingUses: number }): void => {
    const walletSessionJwt = sealedRecoveryWalletSessionJwt(args.record.walletSessionAuth);
    upsertStoredThresholdEd25519SessionRecord({
      nearAccountId: args.accountId,
      rpId: args.record.rpId,
      relayerUrl: args.record.relayerUrl,
      relayerKeyId: args.record.relayerKeyId,
      participantIds: [...args.record.participantIds],
      ...(args.record.runtimePolicyScope
        ? { runtimePolicyScope: args.record.runtimePolicyScope }
        : {}),
      ...(args.record.routerAbNormalSigning
        ? { routerAbNormalSigning: args.record.routerAbNormalSigning }
        : {}),
      thresholdSessionKind: sealedRecoverySessionKind(args.record.walletSessionAuth),
      thresholdSessionId,
      signingGrantId,
      ...(walletSessionJwt ? { walletSessionJwt: walletSessionJwt } : {}),
      expiresAtMs: policy.expiresAtMs,
      remainingUses: policy.remainingUses,
      updatedAtMs: Date.now(),
      source: 'login',
    });
    publishResolvedIdentity({
      walletId: args.accountId,
      authMethod: 'passkey',
      curve: 'ed25519',
      chain: 'near',
      signingGrantId,
      thresholdSessionId,
    });
  };

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
    await args.deletePersistedRecord().catch(() => undefined);
    await args.recordSessionMaterialRestored(rehydrated);
    return rehydrated;
  }

  const parsed = await args.readWarmSessionStatusFromWorker(thresholdSessionId);
  if (!parsed) {
    await args.deletePersistedRecord().catch(() => undefined);
    const failed: WarmSessionStatusResult = {
      ok: false,
      code: 'worker_error',
      message: 'Warm-session status read failed after rehydrate',
    };
    await args.recordSessionMaterialRestored(failed);
    return failed;
  }
  if (!parsed.ok) {
    await args.deletePersistedRecord().catch(() => undefined);
    await args.recordSessionMaterialRestored(parsed);
    return parsed;
  }
  publishRecord({
    expiresAtMs: parsed.expiresAtMs,
    remainingUses: parsed.remainingUses,
  });
  await args.recordSessionMaterialRestored(parsed);
  await args
    .updatePersistedPolicy({
      expiresAtMs: parsed.expiresAtMs,
      remainingUses: parsed.remainingUses,
      updatedAtMs: Date.now(),
    })
    .catch(() => undefined);
  return parsed;
}

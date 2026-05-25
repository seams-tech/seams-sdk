import type { WebAuthnAuthenticationCredential } from '@/core/types';
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
import type { PasskeyEd25519SealedRecoveryRecord } from '@/core/signingEngine/session/sealedRecovery/recoveryRecord';
import type { RestorePersistedEd25519SessionPurpose } from '@/core/signingEngine/session/sealedRecovery/types';
import type { WarmSessionStatusResult } from '@/core/signingEngine/uiConfirm/types';
import { publishResolvedIdentity } from '@/core/signingEngine/session/persistence/sealedSessionStore';
import { SigningSessionIds } from '@/core/signingEngine/session/operationState/types';
import { claimWarmSessionPrfFirst, type PasskeyWarmSessionRecoveryPorts } from './prfClaim';

type PasskeyEd25519SessionRestoreIdentity = {
  touchConfirm: PasskeyWarmSessionRecoveryPorts;
  walletId: string;
  walletSigningSessionId: string;
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
  const walletSigningSessionId = SigningSessionIds.walletSigningSession(
    args.walletSigningSessionId,
  );
  const thresholdSessionId = SigningSessionIds.thresholdEd25519Session(args.thresholdSessionId);
  await args.touchConfirm.restorePersistedSessionForSigning({
    walletId: String(args.walletId).trim(),
    authMethod: 'passkey',
    curve: 'ed25519',
    chain: 'near',
    walletSigningSessionId,
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
        walletSigningSessionId: args.walletSigningSessionId,
        thresholdSessionId: args.thresholdSessionId,
      }),
  });
}

export async function reconnectPasskeyEd25519CapabilityForSigning(args: {
  nearAccountId: AccountId;
  record: ThresholdEd25519SessionRecord;
  localPrfCredential: WebAuthnAuthenticationCredential;
  remainingUses?: number;
  sessionId: string;
  walletSigningSessionId: string;
  provisionThresholdEd25519Session: (
    args: ProvisionWarmEd25519CapabilityArgs,
  ) => Promise<ProvisionWarmEd25519CapabilityResult>;
  readStoredThresholdEd25519SessionRecordByThresholdSessionId?: (
    thresholdSessionId: string,
  ) => ThresholdEd25519SessionRecord | null;
}): Promise<{ sessionId: string; record?: ThresholdEd25519SessionRecord }> {
  const reconnectRemainingUses = Math.max(1, Math.floor(Number(args.remainingUses) || 1));
  const sessionId = String(args.sessionId || '').trim();
  const walletSigningSessionId = String(args.walletSigningSessionId || '').trim();
  if (!sessionId || !walletSigningSessionId) {
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
      webauthnAuthentication: args.localPrfCredential,
    },
    ...(args.record.runtimePolicyScope
      ? { runtimePolicyScope: args.record.runtimePolicyScope }
      : {}),
    participantIds: args.record.participantIds,
    sessionKind: args.record.thresholdSessionKind,
    sessionId,
    walletSigningSessionId,
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
  if (String(refreshedRecord.walletSigningSessionId || '').trim() !== walletSigningSessionId) {
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
  const walletSigningSessionId = String(args.purpose.walletSigningSessionId || '').trim();
  if (!thresholdSessionId || !walletSigningSessionId || !args.shamirPrimeB64u) {
    return null;
  }

  const publishRecord = (policy: { expiresAtMs: number; remainingUses: number }): void => {
    upsertStoredThresholdEd25519SessionRecord({
      nearAccountId: args.accountId,
      rpId: args.record.rpId,
      relayerUrl: args.record.relayerUrl,
      relayerKeyId: args.record.relayerKeyId,
      participantIds: [...args.record.participantIds],
      ...(args.record.runtimePolicyScope
        ? { runtimePolicyScope: args.record.runtimePolicyScope }
        : {}),
      ...(args.record.xClientBaseB64u ? { xClientBaseB64u: args.record.xClientBaseB64u } : {}),
      thresholdSessionKind: args.record.sessionKind,
      thresholdSessionId,
      walletSigningSessionId,
      ...(args.record.sessionKind === 'jwt'
        ? { thresholdSessionAuthToken: args.record.thresholdSessionAuthToken }
        : {}),
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
      walletSigningSessionId,
      thresholdSessionId,
    });
  };

  publishRecord({
    expiresAtMs: Math.floor(Number(args.record.expiresAtMs) || 0),
    remainingUses: Math.max(0, Math.floor(Number(args.record.remainingUses) || 0)),
  });

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
    if (rehydrated.code === 'expired') {
      await args.deletePersistedRecord().catch(() => undefined);
    }
    await args.recordSessionMaterialRestored(rehydrated);
    return rehydrated;
  }

  publishRecord({
    expiresAtMs: rehydrated.expiresAtMs,
    remainingUses: rehydrated.remainingUses,
  });
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

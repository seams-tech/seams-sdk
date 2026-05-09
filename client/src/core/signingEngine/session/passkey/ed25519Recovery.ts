import type { WebAuthnAuthenticationCredential } from '@/core/types';
import type { AccountId } from '@/core/types/accountIds';
import {
  getStoredThresholdEd25519SessionRecordForAccount,
  type ThresholdEd25519SessionRecord,
} from '../persistence/records';
import type {
  ProvisionWarmEd25519CapabilityArgs,
  ProvisionWarmEd25519CapabilityResult,
} from '../warmCapabilities/types';
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
  await args.touchConfirm.restorePersistedSessionForSigning({
    walletId: String(args.walletId).trim(),
    authMethod: 'passkey',
    curve: 'ed25519',
    chain: 'near',
    walletSigningSessionId: String(args.walletSigningSessionId).trim(),
    thresholdSessionId: String(args.thresholdSessionId).trim(),
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
  nearAccountId: AccountId | string;
  record: ThresholdEd25519SessionRecord;
  localPrfCredential: WebAuthnAuthenticationCredential;
  remainingUses?: number;
  sessionId?: string;
  walletSigningSessionId?: string;
  provisionThresholdEd25519Session: (
    args: ProvisionWarmEd25519CapabilityArgs,
  ) => Promise<ProvisionWarmEd25519CapabilityResult>;
  readStoredThresholdEd25519SessionRecord?: (
    nearAccountId: AccountId | string,
  ) => ThresholdEd25519SessionRecord | null;
}): Promise<{ sessionId: string; record?: ThresholdEd25519SessionRecord }> {
  const reconnectRemainingUses = Math.max(1, Math.floor(Number(args.remainingUses) || 1));
  const provisioned = await args.provisionThresholdEd25519Session({
    nearAccountId: args.nearAccountId,
    relayerUrl: args.record.relayerUrl,
    relayerKeyId: args.record.relayerKeyId,
    localPrfCredential: args.localPrfCredential,
    ...(args.record.runtimePolicyScope
      ? { runtimePolicyScope: args.record.runtimePolicyScope }
      : {}),
    participantIds: args.record.participantIds,
    sessionKind: args.record.thresholdSessionKind,
    ...(args.sessionId ? { sessionId: args.sessionId } : {}),
    ...(args.walletSigningSessionId || args.record.walletSigningSessionId
      ? { walletSigningSessionId: args.walletSigningSessionId || args.record.walletSigningSessionId }
      : {}),
    remainingUses: reconnectRemainingUses,
  });
  if (!provisioned.ok || !provisioned.sessionId) {
    throw new Error(
      provisioned.message || provisioned.code || 'Passkey Ed25519 signing session reconnect failed',
    );
  }
  const refreshedRecord =
    args.readStoredThresholdEd25519SessionRecord?.(args.nearAccountId) ||
    getStoredThresholdEd25519SessionRecordForAccount(args.nearAccountId);
  return {
    sessionId: provisioned.sessionId,
    ...(refreshedRecord ? { record: refreshedRecord } : {}),
  };
}

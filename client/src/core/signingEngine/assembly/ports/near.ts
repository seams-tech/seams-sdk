import { IndexedDBManager } from '@/core/indexedDB';
import type { AccountId } from '@/core/types/accountIds';
import type { NearSigningApiDeps } from '../../interfaces/operationDeps';
import { getStoredThresholdEd25519SessionRecordForAccount } from '../../session/persistence/records';
import { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import { resolveEvmFamilyTransactionAccountAuth } from '../../flows/signEvmFamily/accountAuth';
import { createWarmSessionCapabilityReader } from '../../session/warmSigning/capabilityReader';
import { createWarmSessionStatusReader } from '../../session/warmSigning/statusReader';
import { generateSessionId as generateSessionIdValue } from '../../session/warmSigning/prfCache';
import type { WarmSessionStatusResult } from '../../uiConfirm/types';
import type { CreateSigningEnginePortsArgs } from './shared';

export function createNearSigningDeps(args: {
  createArgs: CreateSigningEnginePortsArgs;
  nearRpcUrl: string;
  signingSessionCoordinator: SigningSessionCoordinator;
  getEmailOtpWarmSessionStatus: (sessionId: string) => Promise<WarmSessionStatusResult>;
}): NearSigningApiDeps {
  const {
    createArgs,
    nearRpcUrl,
    signingSessionCoordinator,
    getEmailOtpWarmSessionStatus,
  } = args;
  return {
    nearRpcUrl,
    resolveThresholdEd25519SessionId: (nearAccountId: AccountId): string | null => {
      try {
        const record = getStoredThresholdEd25519SessionRecordForAccount(nearAccountId);
        const thresholdSessionId = String(record?.thresholdSessionId || '').trim();
        return thresholdSessionId || null;
      } catch {
        return null;
      }
    },
    createSigningSessionId: (prefix: string): string => generateSessionIdValue(prefix),
    getSignerWorkerContext: () => createArgs.signerWorkerManager.getContext(),
    requestEmailOtpTransactionSigningChallenge: ({ nearAccountId, chain, authLane }) =>
      createArgs.requestEmailOtpTransactionSigningChallenge?.({
        nearAccountId,
        chain,
        ...(authLane ? { authLane } : {}),
      }) || Promise.reject(new Error('Email OTP signing challenge is not configured')),
    resolveEmailOtpSigningSessionAuthLane: ({ thresholdSessionId, curve }) =>
      createWarmSessionCapabilityReader({
        touchConfirm: createArgs.touchConfirm,
      }).resolveEmailOtpSigningSessionAuthLane({ thresholdSessionId, curve }),
    isEmailOtpEd25519WarmupPending: ({ nearAccountId }) =>
      createArgs.isEmailOtpEd25519WarmupPending?.({ nearAccountId }) === true,
    waitForPendingEmailOtpEd25519Warmup: ({ nearAccountId }) =>
      createArgs.waitForPendingEmailOtpEd25519Warmup?.({ nearAccountId }) ||
      Promise.resolve(false),
    loginWithEmailOtpEd25519CapabilityForSigning: ({
      nearAccountId,
      challengeId,
      otpCode,
      record,
      remainingUses,
      authLane,
    }) =>
      createArgs.loginWithEmailOtpEd25519CapabilityForSigning?.({
        nearAccountId,
        challengeId,
        otpCode,
        record,
        ...(typeof remainingUses === 'number' ? { remainingUses } : {}),
        ...(authLane ? { authLane } : {}),
      }) || Promise.reject(new Error('Email OTP Ed25519 signing bootstrap is not configured')),
    restorePersistedSessionForSigning: (restoreArgs) =>
      createArgs.restorePersistedSessionForSigning(restoreArgs),
    readAvailableSigningLanesForSigning: (snapshotArgs) =>
      createArgs.readAvailableSigningLanesForSigning(snapshotArgs),
    resolveAccountAuthMethodForSigning: async ({ nearAccountId }) => {
      const accountAuth = await resolveEvmFamilyTransactionAccountAuth({
        deps: { indexedDB: IndexedDBManager },
        nearAccountId: String(nearAccountId),
        senderSignatureAlgorithm: 'secp256k1',
      });
      return accountAuth.primaryAuthMethod === 'email_otp' ? 'email_otp' : 'passkey';
    },
    reconnectPasskeyEd25519CapabilityForSigning: async ({
      nearAccountId,
      record,
      localPrfCredential,
      remainingUses,
      sessionId,
      walletSigningSessionId,
    }) => {
      const reconnectRemainingUses = Math.max(1, Math.floor(Number(remainingUses) || 1));
      const provisioned = await createArgs.provisionThresholdEd25519Session({
        nearAccountId,
        relayerUrl: record.relayerUrl,
        relayerKeyId: record.relayerKeyId,
        localPrfCredential,
        ...(record.runtimePolicyScope ? { runtimePolicyScope: record.runtimePolicyScope } : {}),
        participantIds: record.participantIds,
        sessionKind: record.thresholdSessionKind,
        ...(sessionId ? { sessionId } : {}),
        ...(walletSigningSessionId || record.walletSigningSessionId
          ? { walletSigningSessionId: walletSigningSessionId || record.walletSigningSessionId }
          : {}),
        remainingUses: reconnectRemainingUses,
      });
      if (!provisioned.ok || !provisioned.sessionId) {
        throw new Error(
          provisioned.message ||
            provisioned.code ||
            'Passkey Ed25519 signing session reconnect failed',
        );
      }
      const refreshedRecord = getStoredThresholdEd25519SessionRecordForAccount(nearAccountId);
      return {
        sessionId: provisioned.sessionId,
        ...(refreshedRecord ? { record: refreshedRecord } : {}),
      };
    },
    signingSessionCoordinator,
    getWarmThresholdEd25519SessionStatusForSession: ({ nearAccountId, thresholdSessionId }) =>
      createWarmSessionStatusReader({
        touchConfirm: createArgs.touchConfirm,
        getEmailOtpWarmSessionStatus,
      }).getEd25519SigningSessionStatusForSession({ nearAccountId, thresholdSessionId }),
    withThresholdEd25519CommitQueue: (queueArgs) =>
      createArgs.withThresholdEd25519CommitQueue(queueArgs),
  };
}

import type { AccountId } from '@/core/types/accountIds';
import type { NearSigningApiDeps } from '../../interfaces/operationDeps';
import {
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  getStoredThresholdEd25519SessionRecordForAccount,
} from '../../session/persistence/records';
import { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import { resolveEvmFamilyTransactionWalletAuth } from '../../flows/signEvmFamily/accountAuth';
import type { EvmFamilyWalletSignerStorePort } from '../../flows/signEvmFamily/accountAuth';
import { createWarmSessionCapabilityReader } from '../../session/warmCapabilities/capabilityReader';
import { createWarmSessionStatusReader } from '../../session/warmCapabilities/statusReader';
import { generateSessionId as generateSessionIdValue } from '../../session/passkey/prfCache';
import { reconnectPasskeyEd25519CapabilityForSigning } from '../../session/passkey/ed25519Recovery';
import type { WarmSessionStatusResult } from '../../uiConfirm/types';
import type { CreateSigningEnginePortsArgs } from './shared';

export function createNearSigningDeps(args: {
  createArgs: CreateSigningEnginePortsArgs;
  walletSignerStore: EvmFamilyWalletSignerStorePort;
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
        signingSessionSeal: null,
        getEmailOtpWarmSessionStatus,
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
      const accountAuth = await resolveEvmFamilyTransactionWalletAuth({
        deps: { walletSignerStore: args.walletSignerStore },
        walletId: String(nearAccountId),
        senderSignatureAlgorithm: 'secp256k1',
      });
      return accountAuth.primaryAuthMethod === 'email_otp' ? 'email_otp' : 'passkey';
    },
    reconnectPasskeyEd25519CapabilityForSigning: async ({
      nearAccountId,
      record,
      policySecretSource,
      remainingUses,
      sessionId,
      signingGrantId,
    }) =>
      reconnectPasskeyEd25519CapabilityForSigning({
        nearAccountId,
        record,
        policySecretSource,
        remainingUses,
        sessionId,
        signingGrantId,
        provisionThresholdEd25519Session: (provisionArgs) =>
          createArgs.provisionThresholdEd25519Session(provisionArgs),
        readStoredThresholdEd25519SessionRecordByThresholdSessionId: (thresholdSessionId) =>
          getStoredThresholdEd25519SessionRecordByThresholdSessionId(thresholdSessionId),
      }),
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

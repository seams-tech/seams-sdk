import type { EvmFamilySigningDeps } from '../../interfaces/operationDeps';
import { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import { listExactSealedSessionsForWallet } from '../../session/persistence/sealedSessionStore';
import { exactEmailOtpEcdsaSigningSessionAuthorityFromSealedRecords } from '../../session/emailOtp/sealedSigningSessionAuth';
import type { WarmSessionStatusResult } from '../../uiConfirm/uiConfirm.types';
import type { CreateSigningEnginePortsArgs } from './shared';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ExactEcdsaSigningLaneIdentity } from '../../session/identity/exactSigningLaneIdentity';
import type { EmailOtpEcdsaSigningSessionAuthority } from '../../session/emailOtp/ecdsaSigningSessionAuthority';

async function resolveDurableEmailOtpEcdsaAuthority(
  lane: ExactEcdsaSigningLaneIdentity,
): Promise<EmailOtpEcdsaSigningSessionAuthority | null> {
  let sealedRecords;
  try {
    sealedRecords = await listExactSealedSessionsForWallet({
      walletId: String(lane.signer.walletId),
      filter: {
        authMethod: 'email_otp',
        curve: 'ecdsa',
        chainTarget: lane.signer.chainTarget,
      },
    });
  } catch {
    return null;
  }
  return exactEmailOtpEcdsaSigningSessionAuthorityFromSealedRecords({ lane, sealedRecords });
}

export function createEvmFamilySigningDeps(args: {
  createArgs: CreateSigningEnginePortsArgs;
  walletSignerStore: EvmFamilySigningDeps['walletSignerStore'];
  passkeyAuthenticatorStore: EvmFamilySigningDeps['passkeyAuthenticatorStore'];
  signingSessionCoordinator: SigningSessionCoordinator;
  getEmailOtpWarmSessionStatus: (sessionId: string) => Promise<WarmSessionStatusResult>;
}): EvmFamilySigningDeps {
  const { createArgs, signingSessionCoordinator, getEmailOtpWarmSessionStatus } = args;
  return {
    resolveAuthorizedEcdsaSigningCapability: createArgs.resolveAuthorizedEcdsaSigningCapability,
    ...(createArgs.resolveActiveEcdsaWalletSessionAuthorization
      ? {
          resolveActiveEcdsaWalletSessionAuthorization:
            createArgs.resolveActiveEcdsaWalletSessionAuthorization,
        }
      : {}),
    walletSignerStore: args.walletSignerStore,
    passkeyAuthenticatorStore: args.passkeyAuthenticatorStore,
    seamsWebConfigs: createArgs.seamsWebConfigs,
    nonceCoordinator: createArgs.nonceCoordinator,
    ensureSealedRefreshStartupParity: createArgs.ensureSealedRefreshStartupParity,
    getSignerWorkerContext: () => createArgs.signerWorkerManager.getContext(),
    requestEmailOtpTransactionSigningChallenge: ({ walletSession, chain, authority }) =>
      createArgs.requestEmailOtpTransactionSigningChallenge?.({
        walletSession,
        chain,
        authority,
      }) || Promise.reject(new Error('Email OTP signing challenge is not configured')),
    resolveDurableEmailOtpEcdsaSigningSessionAuthority: async ({ lane }) =>
      await resolveDurableEmailOtpEcdsaAuthority(lane),
    resolveEcdsaOperationStepUpSessionAuth: (input) =>
      createArgs.resolveEcdsaOperationStepUpSessionAuth(input),
    restorePersistedSessionForSigning: (restoreArgs) =>
      createArgs.restorePersistedSessionForSigning(restoreArgs),
    readAvailableSigningLanesForSigning: (snapshotArgs) =>
      createArgs.readAvailableSigningLanesForSigning(snapshotArgs),
    signingSessionCoordinator,
    getEmailOtpWarmSessionStatus,
    provisionThresholdEcdsaSession: (provisionArgs) =>
      createArgs.provisionThresholdEcdsaSession(provisionArgs),
    withThresholdEcdsaSigningQueue: (queueArgs) =>
      createArgs.withThresholdEcdsaSigningQueue(queueArgs),
    touchConfirm: createArgs.touchConfirm,
  };
}

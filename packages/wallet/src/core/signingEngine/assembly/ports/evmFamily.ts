import type { EvmFamilySigningDeps } from '../../interfaces/operationDeps';
import { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import type { WarmSessionStatusResult } from '../../uiConfirm/uiConfirm.types';
import type { CreateSigningEnginePortsArgs } from './shared';
import type { EmailOtpWarmMaterialTarget } from '../../workerManager/workerTypes';
import type { ExactEcdsaSigningLaneIdentity } from '../../session/identity/exactSigningLaneIdentity';
import { authorizeEvmFamilyEcdsaSigningCapability } from '../../session/material/ecdsaSigningCapability';
import {
  isEmailOtpWalletAuthAuthority,
  walletAuthAuthoritiesMatch,
} from '@shared/utils/walletAuthAuthority';
import { mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';
import { thresholdEcdsaChainTargetsEqual } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ExactEvmFamilyWalletSessionAuthorization } from '../../session/material/ecdsaSigningCapability';

async function resolveDurableEmailOtpEcdsaAuthority(args: {
  lane: ExactEcdsaSigningLaneIdentity;
  createArgs: CreateSigningEnginePortsArgs;
}): Promise<ExactEvmFamilyWalletSessionAuthorization | null> {
  if (args.lane.auth.kind !== 'email_otp') return null;
  try {
    const capability = await args.createArgs.resolveCanonicalEcdsaSigningCapability({
      walletId: args.lane.signer.walletId,
      chainTarget: args.lane.signer.chainTarget,
      materialActivation: args.lane.signer.materialActivation,
    });
    if (
      !isEmailOtpWalletAuthAuthority(capability.authority) ||
      capability.authority.factor.providerUserId !== args.lane.auth.providerSubjectId
    ) {
      return null;
    }
    const authorization = await args.createArgs.resolveActiveEcdsaWalletSessionAuthorization({
      walletId: args.lane.signer.walletId,
      chainTarget: args.lane.signer.chainTarget,
      materialActivation: args.lane.signer.materialActivation,
    });
    if (!authorization) return null;
    const authorized = authorizeEvmFamilyEcdsaSigningCapability({
      capability,
      authorization,
      nowMs: Date.now(),
    });
    const runtime = authorized.authorization.runtime;
    if (
      authorized.authorization.selectedAuthMethod.kind !== 'email_otp' ||
      runtime.authBinding.kind !== 'email_otp' ||
      !walletAuthAuthoritiesMatch(capability.authority, runtime.authBinding.emailOtpAuthority) ||
      capability.authority.factor.providerUserId !== args.lane.auth.providerSubjectId ||
      runtime.walletId !== args.lane.signer.walletId ||
      !thresholdEcdsaChainTargetsEqual(runtime.chainTarget, args.lane.signer.chainTarget) ||
      !mpcMaterialActivationRefsEqual(
        runtime.materialActivation,
        args.lane.signer.materialActivation,
      )
    ) {
      return null;
    }
    return authorized.authorization;
  } catch {
    return null;
  }
}

export function createEvmFamilySigningDeps(args: {
  createArgs: CreateSigningEnginePortsArgs;
  walletSignerStore: EvmFamilySigningDeps['walletSignerStore'];
  passkeyAuthenticatorStore: EvmFamilySigningDeps['passkeyAuthenticatorStore'];
  signingSessionCoordinator: SigningSessionCoordinator;
  getEmailOtpWarmSessionStatus: (
    target: EmailOtpWarmMaterialTarget,
  ) => Promise<WarmSessionStatusResult>;
}): EvmFamilySigningDeps {
  const { createArgs, signingSessionCoordinator, getEmailOtpWarmSessionStatus } = args;
  return {
    resolveOwnerLaneScope: createArgs.resolveOwnerLaneScope,
    resolveCanonicalEcdsaSigningCapability: createArgs.resolveCanonicalEcdsaSigningCapability,
    resolveAuthorizedEcdsaSigningCapability: createArgs.resolveAuthorizedEcdsaSigningCapability,
    resolveActiveEcdsaWalletSessionAuthorization:
      createArgs.resolveActiveEcdsaWalletSessionAuthorization,
    walletSignerStore: args.walletSignerStore,
    passkeyAuthenticatorStore: args.passkeyAuthenticatorStore,
    seamsWebConfigs: createArgs.seamsWebConfigs,
    nonceCoordinator: createArgs.nonceCoordinator,
    ensureSealedRefreshStartupParity: createArgs.ensureSealedRefreshStartupParity,
    getSignerWorkerContext: () => createArgs.signerWorkerManager.getContext(),
    requestEmailOtpTransactionSigningChallenge: ({
      walletSession,
      chain,
      authority,
      operationFingerprintDigest,
    }) =>
      createArgs.requestEmailOtpTransactionSigningChallenge?.({
        walletSession,
        chain,
        authority,
        operationFingerprintDigest,
      }) || Promise.reject(new Error('Email OTP signing challenge is not configured')),
    resolveDurableEmailOtpEcdsaSigningSessionAuthority: async ({ lane }) =>
      await resolveDurableEmailOtpEcdsaAuthority({ lane, createArgs }),
    restorePersistedSessionForSigning: (restoreArgs) =>
      createArgs.restorePersistedSessionForSigning(restoreArgs),
    readAvailableSigningLanesForSigning: (snapshotArgs) =>
      createArgs.readAvailableSigningLanesForSigning(snapshotArgs),
    signingSessionCoordinator,
    getEmailOtpWarmSessionStatus: (thresholdSessionId) =>
      getEmailOtpWarmSessionStatus({ kind: 'ecdsa', thresholdSessionId }),
    provisionThresholdEcdsaSession: (provisionArgs) =>
      createArgs.provisionThresholdEcdsaSession(provisionArgs),
    withThresholdEcdsaSigningQueue: (queueArgs) =>
      createArgs.withThresholdEcdsaSigningQueue(queueArgs),
    touchConfirm: createArgs.touchConfirm,
  };
}

import { toAccountId, type AccountId } from '@/core/types/accountIds';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import type {
  ThresholdEcdsaEmailOtpAuthContext,
  ThresholdEcdsaSessionStoreSource,
} from '../identity/laneIdentity';
import {
  upsertThresholdEcdsaSessionFromBootstrap,
  type ThresholdEcdsaSessionStoreDeps,
} from '../persistence/records';
import type {
  ThresholdEcdsaChainTarget,
  WalletSubjectId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import { withThresholdEcdsaBootstrapQueue } from './ecdsaBootstrapQueue';
import {
  persistThresholdEcdsaBootstrapChainAccount,
  type ThresholdEcdsaBootstrapIndexedDbPort,
  type ThresholdEcdsaSmartAccountBootstrapInput,
} from './ecdsaBootstrapPersistence';
import {
  assertWarmThresholdEcdsaCapabilityReady,
  type EcdsaWarmCapabilityReader,
} from './ecdsaCapabilityReadiness';
import type { WarmSessionEcdsaCapabilityState } from './types';

export type CommitWorkerProvisionedThresholdEcdsaSessionDeps = {
  queueByAccount: Map<string, Promise<void>>;
  indexedDB: ThresholdEcdsaBootstrapIndexedDbPort;
  ecdsaSessions: ThresholdEcdsaSessionStoreDeps;
  ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap: (args: {
    nearAccountId: AccountId;
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
    source: ThresholdEcdsaSessionStoreSource;
    emailOtpAuthContext?: ThresholdEcdsaEmailOtpAuthContext;
    smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
  }) => Promise<void>;
};

export type CommitEvmFamilyThresholdEcdsaSessionsDeps =
  CommitWorkerProvisionedThresholdEcdsaSessionDeps & {
    warmCapabilityReader: EcdsaWarmCapabilityReader;
  };

function canonicalizeWorkerProvisionedBootstrap(
  bootstrap: ThresholdEcdsaSessionBootstrapResult,
): ThresholdEcdsaSessionBootstrapResult {
  const ecdsaThresholdKeyId = String(
    bootstrap.thresholdEcdsaKeyRef.ecdsaThresholdKeyId || '',
  ).trim();
  if (!ecdsaThresholdKeyId) {
    throw new Error(
      '[SigningEngine] threshold-ecdsa bootstrap did not provide canonical ecdsaThresholdKeyId',
    );
  }
  const walletSigningSessionId = String(
    bootstrap.session.walletSigningSessionId ||
      bootstrap.thresholdEcdsaKeyRef.walletSigningSessionId ||
      '',
  ).trim();
  return {
    ...bootstrap,
    thresholdEcdsaKeyRef: {
      ...bootstrap.thresholdEcdsaKeyRef,
      ecdsaThresholdKeyId,
      ...(walletSigningSessionId ? { walletSigningSessionId } : {}),
    },
    session: {
      ...bootstrap.session,
      ...(walletSigningSessionId ? { walletSigningSessionId } : {}),
    },
  };
}

export async function commitWorkerProvisionedThresholdEcdsaSession(
  deps: CommitWorkerProvisionedThresholdEcdsaSessionDeps,
  args: {
    nearAccountId: AccountId | string;
    chainTarget: ThresholdEcdsaChainTarget;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    source: ThresholdEcdsaSessionStoreSource;
    emailOtpAuthContext?: ThresholdEcdsaEmailOtpAuthContext;
    smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
  },
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  const nearAccountId = toAccountId(args.nearAccountId);
  await deps.ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap({
    nearAccountId,
    subjectId: args.bootstrap.thresholdEcdsaKeyRef.subjectId,
    chainTarget: args.chainTarget,
    source: args.source,
    emailOtpAuthContext: args.emailOtpAuthContext,
    smartAccount: args.smartAccount,
  });

  return await withThresholdEcdsaBootstrapQueue(deps.queueByAccount, nearAccountId, async () => {
    const canonicalBootstrap = canonicalizeWorkerProvisionedBootstrap(args.bootstrap);
    await persistThresholdEcdsaBootstrapChainAccount({
      indexedDB: deps.indexedDB,
      nearAccountId,
      chainTarget: args.chainTarget,
      bootstrap: canonicalBootstrap,
      smartAccount: args.smartAccount,
      ensureEmailOtpNearAccountMapping: args.source === SIGNER_AUTH_METHODS.emailOtp,
    });
    upsertThresholdEcdsaSessionFromBootstrap(deps.ecdsaSessions, {
      nearAccountId,
      chainTarget: args.chainTarget,
      bootstrap: canonicalBootstrap,
      source: args.source,
      ...(args.emailOtpAuthContext ? { emailOtpAuthContext: args.emailOtpAuthContext } : {}),
    });
    return canonicalBootstrap;
  });
}

export async function commitEvmFamilyThresholdEcdsaSessions(
  deps: CommitEvmFamilyThresholdEcdsaSessionsDeps,
  args: {
    nearAccountId: AccountId | string;
    primaryChain: ThresholdEcdsaChainTarget;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    source: ThresholdEcdsaSessionStoreSource;
    emailOtpAuthContext?: ThresholdEcdsaEmailOtpAuthContext;
    smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
  },
): Promise<{
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  warmCapability: WarmSessionEcdsaCapabilityState;
}> {
  const bootstrap = await commitWorkerProvisionedThresholdEcdsaSession(deps, {
    nearAccountId: args.nearAccountId,
    chainTarget: args.primaryChain,
    bootstrap: args.bootstrap,
    source: args.source,
    ...(args.emailOtpAuthContext ? { emailOtpAuthContext: args.emailOtpAuthContext } : {}),
    ...(args.smartAccount ? { smartAccount: args.smartAccount } : {}),
  });
  const warmCapability = await assertWarmThresholdEcdsaCapabilityReady(deps.warmCapabilityReader, {
    nearAccountId: args.nearAccountId,
    chainTarget: args.primaryChain,
  });
  return {
    bootstrap,
    warmCapability,
  };
}

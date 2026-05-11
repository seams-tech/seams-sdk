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
import { withThresholdEcdsaBootstrapQueue } from '../warmCapabilities/ecdsaBootstrapQueue';
import {
  persistThresholdEcdsaBootstrapChainAccount,
  type ThresholdEcdsaBootstrapIndexedDbPort,
  type ThresholdEcdsaSmartAccountBootstrapInput,
} from '../warmCapabilities/ecdsaBootstrapPersistence';
import {
  assertWarmThresholdEcdsaCapabilityReady,
  type EcdsaWarmCapabilityReader,
} from '../warmCapabilities/ecdsaCapabilityReadiness';
import type { ThresholdEcdsaBootstrapParityArgs } from '../warmCapabilities/sealedRefreshParity';
import type { WarmSessionEcdsaCapabilityState } from '../warmCapabilities/types';

export type CommitWorkerProvisionedThresholdEcdsaSessionDeps = {
  queueByAccount: Map<string, Promise<void>>;
  indexedDB: ThresholdEcdsaBootstrapIndexedDbPort;
  ecdsaSessions: ThresholdEcdsaSessionStoreDeps;
  ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap: (
    args: ThresholdEcdsaBootstrapParityArgs,
  ) => Promise<void>;
};

export type CommitEvmFamilyThresholdEcdsaSessionsDeps =
  CommitWorkerProvisionedThresholdEcdsaSessionDeps & {
    warmCapabilityReader: EcdsaWarmCapabilityReader;
  };

type CommitThresholdEcdsaSessionBaseArgs = {
  nearAccountId: AccountId | string;
  chainTarget: ThresholdEcdsaChainTarget;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
};

type CommitEmailOtpThresholdEcdsaSessionArgs = CommitThresholdEcdsaSessionBaseArgs & {
  source: 'email_otp';
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
};

type CommitPasskeyThresholdEcdsaSessionArgs = CommitThresholdEcdsaSessionBaseArgs & {
  source: Exclude<ThresholdEcdsaSessionStoreSource, 'email_otp'>;
  emailOtpAuthContext?: never;
};

type CommitWorkerProvisionedThresholdEcdsaSessionArgs =
  | CommitEmailOtpThresholdEcdsaSessionArgs
  | CommitPasskeyThresholdEcdsaSessionArgs;

type CommitEvmFamilyThresholdEcdsaSessionsBaseArgs = {
  nearAccountId: AccountId | string;
  primaryChain: ThresholdEcdsaChainTarget;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
};

type CommitEmailOtpEvmFamilyThresholdEcdsaSessionsArgs =
  CommitEvmFamilyThresholdEcdsaSessionsBaseArgs & {
    source: 'email_otp';
    emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  };

type CommitPasskeyEvmFamilyThresholdEcdsaSessionsArgs =
  CommitEvmFamilyThresholdEcdsaSessionsBaseArgs & {
    source: Exclude<ThresholdEcdsaSessionStoreSource, 'email_otp'>;
    emailOtpAuthContext?: never;
  };

type CommitEvmFamilyThresholdEcdsaSessionsArgs =
  | CommitEmailOtpEvmFamilyThresholdEcdsaSessionsArgs
  | CommitPasskeyEvmFamilyThresholdEcdsaSessionsArgs;

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
  args: CommitWorkerProvisionedThresholdEcdsaSessionArgs,
): Promise<ThresholdEcdsaSessionBootstrapResult> {
  const nearAccountId = toAccountId(args.nearAccountId);
  if (args.source === 'email_otp') {
    await deps.ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap({
      kind: 'email_otp_bootstrap_parity',
      nearAccountId,
      chainTarget: args.chainTarget,
      authMethod: SIGNER_AUTH_METHODS.emailOtp,
    });
  } else {
    await deps.ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap({
      kind: 'default_bootstrap_parity',
      nearAccountId,
      chainTarget: args.chainTarget,
    });
  }

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
    if (args.source === 'email_otp') {
      upsertThresholdEcdsaSessionFromBootstrap(deps.ecdsaSessions, {
        nearAccountId,
        chainTarget: args.chainTarget,
        bootstrap: canonicalBootstrap,
        source: 'email_otp',
        emailOtpAuthContext: args.emailOtpAuthContext,
      });
    } else {
      upsertThresholdEcdsaSessionFromBootstrap(deps.ecdsaSessions, {
        nearAccountId,
        chainTarget: args.chainTarget,
        bootstrap: canonicalBootstrap,
        source: args.source,
      });
    }
    return canonicalBootstrap;
  });
}

export async function commitEvmFamilyThresholdEcdsaSessions(
  deps: CommitEvmFamilyThresholdEcdsaSessionsDeps,
  args: CommitEvmFamilyThresholdEcdsaSessionsArgs,
): Promise<{
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  warmCapability: WarmSessionEcdsaCapabilityState;
}> {
  const bootstrap =
    args.source === 'email_otp'
      ? await commitWorkerProvisionedThresholdEcdsaSession(deps, {
          nearAccountId: args.nearAccountId,
          chainTarget: args.primaryChain,
          bootstrap: args.bootstrap,
          source: 'email_otp',
          emailOtpAuthContext: args.emailOtpAuthContext,
          smartAccount: args.smartAccount,
        })
      : await commitWorkerProvisionedThresholdEcdsaSession(deps, {
          nearAccountId: args.nearAccountId,
          chainTarget: args.primaryChain,
          bootstrap: args.bootstrap,
          source: args.source,
          smartAccount: args.smartAccount,
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

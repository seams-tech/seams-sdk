import { SIGNER_AUTH_METHODS, SIGNER_SOURCES } from '@shared/utils/signerDomain';
import type {
  ThresholdEcdsaEmailOtpAuthContext,
  ThresholdEcdsaSessionStoreSource,
} from '../identity/laneIdentity';
import {
  upsertThresholdEcdsaSessionFromBootstrap,
  type ThresholdEcdsaSessionStoreDeps,
} from '../persistence/records';
import {
  ThresholdEcdsaChainTarget,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import { withThresholdEcdsaBootstrapQueue } from '../warmCapabilities/ecdsaBootstrapQueue';
import {
  persistThresholdEcdsaBootstrapForWalletTarget,
  type ThresholdEcdsaBootstrapIndexedDbPort,
} from '../warmCapabilities/ecdsaBootstrapPersistence';
import {
  assertWarmThresholdEcdsaCapabilityReady,
  type EcdsaWarmCapabilityReader,
} from '../warmCapabilities/ecdsaCapabilityReadiness';
import type { ThresholdEcdsaBootstrapParityArgs } from '../warmCapabilities/sealedRefreshParity';
import type { WarmSessionEcdsaCapabilityState } from '../warmCapabilities/types';

export type CommitWorkerProvisionedThresholdEcdsaSessionDeps = {
  queueByWallet: Map<string, Promise<void>>;
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
  walletId: WalletId;
  chainTarget: ThresholdEcdsaChainTarget;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
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
  walletId: WalletId;
  primaryChain: ThresholdEcdsaChainTarget;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
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
  if (args.source === 'email_otp') {
    await deps.ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap({
      kind: 'email_otp_bootstrap_parity',
      walletId: args.walletId,
      chainTarget: args.chainTarget,
      authMethod: SIGNER_AUTH_METHODS.emailOtp,
    });
  } else {
    await deps.ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap({
      kind: 'default_bootstrap_parity',
      walletId: args.walletId,
      chainTarget: args.chainTarget,
    });
  }

  return await withThresholdEcdsaBootstrapQueue(deps.queueByWallet, args.walletId, async () => {
    const canonicalBootstrap = canonicalizeWorkerProvisionedBootstrap(args.bootstrap);
    await persistThresholdEcdsaBootstrapForWalletTarget({
      indexedDB: deps.indexedDB,
      walletId: args.walletId,
      chainTarget: args.chainTarget,
      bootstrap: canonicalBootstrap,
      signerAuth:
        args.source === 'email_otp'
          ? {
              authMethod: SIGNER_AUTH_METHODS.emailOtp,
              signerSource: SIGNER_SOURCES.emailOtpRegistration,
            }
          : {
              authMethod: SIGNER_AUTH_METHODS.passkey,
              signerSource: SIGNER_SOURCES.passkeyRegistration,
            },
    });
    if (args.source === 'email_otp') {
      upsertThresholdEcdsaSessionFromBootstrap(deps.ecdsaSessions, {
        walletId: args.walletId,
        chainTarget: args.chainTarget,
        bootstrap: canonicalBootstrap,
        source: 'email_otp',
        emailOtpAuthContext: args.emailOtpAuthContext,
      });
    } else {
      upsertThresholdEcdsaSessionFromBootstrap(deps.ecdsaSessions, {
        walletId: args.walletId,
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
          walletId: args.walletId,
          chainTarget: args.primaryChain,
          bootstrap: args.bootstrap,
          source: 'email_otp',
          emailOtpAuthContext: args.emailOtpAuthContext,
        })
      : await commitWorkerProvisionedThresholdEcdsaSession(deps, {
          walletId: args.walletId,
          chainTarget: args.primaryChain,
          bootstrap: args.bootstrap,
          source: args.source,
        });
  const warmCapability = await assertWarmThresholdEcdsaCapabilityReady(deps.warmCapabilityReader, {
    walletId: args.walletId,
    chainTarget: args.primaryChain,
    bootstrap,
  });
  return {
    bootstrap,
    warmCapability,
  };
}

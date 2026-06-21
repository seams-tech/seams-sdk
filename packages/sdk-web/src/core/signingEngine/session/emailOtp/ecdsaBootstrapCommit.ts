import { SIGNER_AUTH_METHODS, SIGNER_SOURCES } from '@shared/utils/signerDomain';
import type {
  ThresholdEcdsaEmailOtpAuthContext,
  ThresholdEcdsaSessionStoreSource,
} from '../identity/laneIdentity';
import {
  upsertThresholdEcdsaSessionFromBootstrap,
  type ThresholdEcdsaSessionRecord,
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
  type ThresholdEcdsaBootstrapStorePort,
} from '../warmCapabilities/ecdsaBootstrapPersistence';
import { parseEcdsaThresholdKeyId } from '../keyMaterialBrands';
import {
  assertWarmThresholdEcdsaCapabilityReady,
  type EcdsaWarmCapabilityReader,
} from '../warmCapabilities/ecdsaCapabilityReadiness';
import type { ThresholdEcdsaBootstrapParityArgs } from '../warmCapabilities/sealedRefreshParity';
import type { WarmSessionEcdsaCapabilityState } from '../warmCapabilities/types';
import { markRouterAbEcdsaHssWorkerMaterialRuntimeValidated } from '../routerAbSigningWalletSession';

export type CommitWorkerProvisionedThresholdEcdsaSessionDeps = {
  queueByWallet: Map<string, Promise<void>>;
  bootstrapStore: ThresholdEcdsaBootstrapStorePort;
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

function assertNeverThresholdEcdsaBootstrapBackendBinding(
  value: never,
): never {
  throw new Error(
    `[SigningEngine] unsupported threshold ECDSA bootstrap backend binding: ${JSON.stringify(value)}`,
  );
}

function isRuntimeValidatedWorkerBootstrapBinding(
  binding: ThresholdEcdsaSessionBootstrapResult['thresholdEcdsaKeyRef']['backendBinding'],
): boolean {
  if (!binding) return false;
  switch (binding.materialKind) {
    case 'email_otp_worker_handle':
    case 'role_local_worker_handle':
      return true;
    case 'role_local_ready_state_blob':
    case 'metadata_only':
      return false;
    default:
      return assertNeverThresholdEcdsaBootstrapBackendBinding(
        binding satisfies never,
      );
  }
}

function canonicalizeWorkerProvisionedBootstrap(
  bootstrap: ThresholdEcdsaSessionBootstrapResult,
): ThresholdEcdsaSessionBootstrapResult {
  const ecdsaThresholdKeyIdRaw = String(
    bootstrap.thresholdEcdsaKeyRef.ecdsaThresholdKeyId || '',
  ).trim();
  if (!ecdsaThresholdKeyIdRaw) {
    throw new Error(
      '[SigningEngine] threshold-ecdsa bootstrap did not provide canonical ecdsaThresholdKeyId',
    );
  }
  const ecdsaThresholdKeyId = parseEcdsaThresholdKeyId(ecdsaThresholdKeyIdRaw);
  const signingGrantId = String(
    bootstrap.session.signingGrantId ||
      bootstrap.thresholdEcdsaKeyRef.signingGrantId ||
      '',
  ).trim();
  return {
    ...bootstrap,
    thresholdEcdsaKeyRef: {
      ...bootstrap.thresholdEcdsaKeyRef,
      ecdsaThresholdKeyId,
      ...(signingGrantId ? { signingGrantId } : {}),
    },
    session: {
      ...bootstrap.session,
      ...(signingGrantId ? { signingGrantId } : {}),
    },
  };
}

function markWorkerProvisionedEcdsaSessionRuntimeValidated(args: {
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  record: ThresholdEcdsaSessionRecord;
}): void {
  if (
    !isRuntimeValidatedWorkerBootstrapBinding(args.bootstrap.thresholdEcdsaKeyRef.backendBinding)
  ) {
    return;
  }
  if (markRouterAbEcdsaHssWorkerMaterialRuntimeValidated(args.record)) return;
  throw new Error(
    '[SigningEngine] ECDSA-HSS bootstrap returned worker material that could not be runtime-validated',
  );
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
      bootstrapStore: deps.bootstrapStore,
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
      const record = upsertThresholdEcdsaSessionFromBootstrap(deps.ecdsaSessions, {
        walletId: args.walletId,
        chainTarget: args.chainTarget,
        bootstrap: canonicalBootstrap,
        source: 'email_otp',
        emailOtpAuthContext: args.emailOtpAuthContext,
      });
      markWorkerProvisionedEcdsaSessionRuntimeValidated({
        bootstrap: canonicalBootstrap,
        record,
      });
    } else {
      const record = upsertThresholdEcdsaSessionFromBootstrap(deps.ecdsaSessions, {
        walletId: args.walletId,
        chainTarget: args.chainTarget,
        bootstrap: canonicalBootstrap,
        source: args.source,
      });
      markWorkerProvisionedEcdsaSessionRuntimeValidated({
        bootstrap: canonicalBootstrap,
        record,
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

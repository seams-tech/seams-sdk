import { SIGNER_AUTH_METHODS, SIGNER_SOURCES } from '@shared/utils/signerDomain';
import type {
  ThresholdEcdsaEmailOtpAuthContext,
  ThresholdEcdsaSessionStoreSource,
} from '../identity/laneIdentity';
import {
  upsertThresholdEcdsaSessionFromBootstrap,
  toExactEcdsaSigningLaneIdentity,
  type ThresholdEcdsaSessionRecord,
  type ThresholdEcdsaSessionStoreDeps,
} from '../persistence/records';
import {
  thresholdEcdsaChainTargetKey,
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
import { resolveRouterAbEcdsaWalletSessionAuthFromRecord } from '../warmCapabilities/routerAbEcdsaWalletSessionAuth';

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
  chainTarget: ThresholdEcdsaChainTarget;
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
  // Worker-handle bootstrap outputs are already loaded in the current runtime.
  // Mark the exact persisted record before capability readers inspect it.
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

function summarizeThresholdEcdsaCommitBootstrap(
  bootstrap: ThresholdEcdsaSessionBootstrapResult,
): Record<string, unknown> {
  const backendBinding = bootstrap.thresholdEcdsaKeyRef.backendBinding;
  return {
    thresholdSessionId: bootstrap.session.thresholdSessionId,
    signingGrantId:
      bootstrap.session.signingGrantId || bootstrap.thresholdEcdsaKeyRef.signingGrantId,
    ecdsaThresholdKeyId: bootstrap.thresholdEcdsaKeyRef.ecdsaThresholdKeyId,
    keyHandle: bootstrap.thresholdEcdsaKeyRef.keyHandle,
    chainTarget: thresholdEcdsaChainTargetKey(bootstrap.thresholdEcdsaKeyRef.chainTarget),
    backendBindingKind: backendBinding?.materialKind || null,
  };
}

function summarizeThresholdEcdsaCommitRecord(
  record: ThresholdEcdsaSessionRecord,
): Record<string, unknown> {
  const walletSessionAuth = resolveRouterAbEcdsaWalletSessionAuthFromRecord(record);
  return {
    source: record.source,
    thresholdSessionId: record.thresholdSessionId,
    signingGrantId: record.signingGrantId,
    keyHandle: record.keyHandle,
    relayerKeyId: record.relayerKeyId,
    chainTarget: thresholdEcdsaChainTargetKey(record.chainTarget),
    walletSessionAuthKind: walletSessionAuth.kind,
    walletSessionAuthSource:
      walletSessionAuth.kind === 'ready' ? walletSessionAuth.source : walletSessionAuth.reason,
    hasWalletSessionJwt: Boolean(record.walletSessionJwt),
    emailOtpReason: record.source === 'email_otp' ? record.emailOtpAuthContext.reason : null,
    emailOtpRetention:
      record.source === 'email_otp' ? record.emailOtpAuthContext.retention : null,
  };
}

function logThresholdEcdsaCommitDiagnostic(
  message: string,
  details: Record<string, unknown>,
): void {
  try {
    console.info(`[SigningEngine][ecdsa][commit] ${message}`, details);
  } catch {}
}

export async function commitWorkerProvisionedThresholdEcdsaSession(
  deps: CommitWorkerProvisionedThresholdEcdsaSessionDeps,
  args: CommitWorkerProvisionedThresholdEcdsaSessionArgs,
): Promise<{
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  record: ThresholdEcdsaSessionRecord;
}> {
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
    let record: ThresholdEcdsaSessionRecord;
    if (args.source === 'email_otp') {
      record = upsertThresholdEcdsaSessionFromBootstrap(deps.ecdsaSessions, {
        walletId: args.walletId,
        chainTarget: args.chainTarget,
        bootstrap: canonicalBootstrap,
        source: 'email_otp',
        emailOtpAuthContext: args.emailOtpAuthContext,
      });
    } else {
      record = upsertThresholdEcdsaSessionFromBootstrap(deps.ecdsaSessions, {
        walletId: args.walletId,
        chainTarget: args.chainTarget,
        bootstrap: canonicalBootstrap,
        source: args.source,
      });
    }
    markWorkerProvisionedEcdsaSessionRuntimeValidated({
      bootstrap: canonicalBootstrap,
      record,
    });
    if (args.source === 'email_otp') {
      logThresholdEcdsaCommitDiagnostic('Email OTP ECDSA session record committed', {
        walletId: args.walletId,
        requestedChainTarget: thresholdEcdsaChainTargetKey(args.chainTarget),
        bootstrap: summarizeThresholdEcdsaCommitBootstrap(canonicalBootstrap),
        record: summarizeThresholdEcdsaCommitRecord(record),
      });
    }
    return { bootstrap: canonicalBootstrap, record };
  });
}

export async function commitEvmFamilyThresholdEcdsaSessions(
  deps: CommitEvmFamilyThresholdEcdsaSessionsDeps,
  args: CommitEvmFamilyThresholdEcdsaSessionsArgs,
): Promise<{
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  warmCapability: WarmSessionEcdsaCapabilityState;
}> {
  const committed =
    args.source === 'email_otp'
      ? await commitWorkerProvisionedThresholdEcdsaSession(deps, {
          walletId: args.walletId,
          chainTarget: args.chainTarget,
          bootstrap: args.bootstrap,
          source: 'email_otp',
          emailOtpAuthContext: args.emailOtpAuthContext,
        })
      : await commitWorkerProvisionedThresholdEcdsaSession(deps, {
          walletId: args.walletId,
          chainTarget: args.chainTarget,
          bootstrap: args.bootstrap,
          source: args.source,
        });
  const bootstrap = committed.bootstrap;
  // Prove the exact thresholdSessionId from this bootstrap is ready. Wallet-level
  // lane reads can select older records for the same chain.
  let warmCapability: WarmSessionEcdsaCapabilityState;
  try {
    warmCapability = await assertWarmThresholdEcdsaCapabilityReady(deps.warmCapabilityReader, {
      walletId: args.walletId,
      chainTarget: args.chainTarget,
      bootstrap,
      lane: toExactEcdsaSigningLaneIdentity(committed.record),
    });
  } catch (error) {
    logThresholdEcdsaCommitDiagnostic('ECDSA warm capability assertion failed after commit', {
      walletId: args.walletId,
      source: args.source,
      chainTarget: thresholdEcdsaChainTargetKey(args.chainTarget),
      bootstrap: summarizeThresholdEcdsaCommitBootstrap(bootstrap),
      record: summarizeThresholdEcdsaCommitRecord(committed.record),
      error: error instanceof Error ? error.message : String(error),
    });
    throw error;
  }
  if (args.source === 'email_otp') {
    logThresholdEcdsaCommitDiagnostic('Email OTP ECDSA warm capability ready', {
      walletId: args.walletId,
      chainTarget: thresholdEcdsaChainTargetKey(args.chainTarget),
      bootstrap: summarizeThresholdEcdsaCommitBootstrap(bootstrap),
      warmCapabilityState: warmCapability.state,
      record: warmCapability.record
        ? summarizeThresholdEcdsaCommitRecord(warmCapability.record)
        : { present: false },
    });
  }
  return {
    bootstrap,
    warmCapability,
  };
}

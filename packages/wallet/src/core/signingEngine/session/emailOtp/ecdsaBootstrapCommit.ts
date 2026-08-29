import { SIGNER_AUTH_METHODS, SIGNER_SOURCES } from '@shared/utils/signerDomain';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import type { DurableRecordStore } from '@/core/platform';
import type {
  ThresholdEcdsaEmailOtpAuthContext,
  ThresholdEcdsaSessionStoreSource,
} from '../identity/laneIdentity';
import { ecdsaRoleLocalReadyRecordStorageKeyFacts } from '../persistence/ecdsaRoleLocalRecords';
import {
  ThresholdEcdsaChainTarget,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import type { ThresholdEcdsaBackendBinding } from '../../interfaces/signing';
import { withThresholdEcdsaBootstrapQueue } from '../warmCapabilities/ecdsaBootstrapQueue';
import {
  persistThresholdEcdsaBootstrapForWalletTarget,
  type ThresholdEcdsaBootstrapSignerAuth,
  type ThresholdEcdsaBootstrapStorePort,
} from '../warmCapabilities/ecdsaBootstrapPersistence';
import type { ThresholdEcdsaBootstrapParityArgs } from '../warmCapabilities/sealedRefreshParity';
import { walletSessionAuthorizations } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import {
  persistExactWalletSessionAuthorizationFromEcdsaBootstrap,
  type ExactWalletSessionAuthorization,
} from '../persistence/walletSessionAuthorizationProjection';

export type CommitWorkerProvisionedThresholdEcdsaSessionDeps = {
  queueByWallet: Map<string, Promise<void>>;
  bootstrapStore: ThresholdEcdsaBootstrapStorePort;
  persistEcdsaRoleLocalReadyRecord: DurableRecordStore['persistEcdsaRoleLocalReadyRecord'];
  ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap: (
    args: ThresholdEcdsaBootstrapParityArgs,
  ) => Promise<void>;
};

export type CommitEvmFamilyThresholdEcdsaSessionsDeps =
  CommitWorkerProvisionedThresholdEcdsaSessionDeps;

type CommitThresholdEcdsaSessionBaseArgs = {
  walletId: WalletId;
  chainTarget: ThresholdEcdsaChainTarget;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
};

type CommitEmailOtpThresholdEcdsaSessionArgs = CommitThresholdEcdsaSessionBaseArgs & {
  source: 'email_otp';
  authority: WalletAuthAuthorityRef;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
};

type CommitPasskeyThresholdEcdsaSessionArgs = CommitThresholdEcdsaSessionBaseArgs & {
  source: Exclude<ThresholdEcdsaSessionStoreSource, 'email_otp'>;
  authority: WalletAuthAuthorityRef;
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
    authority: WalletAuthAuthorityRef;
    emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  };

type CommitPasskeyEvmFamilyThresholdEcdsaSessionsArgs =
  CommitEvmFamilyThresholdEcdsaSessionsBaseArgs & {
    source: Exclude<ThresholdEcdsaSessionStoreSource, 'email_otp'>;
    authority: WalletAuthAuthorityRef;
    emailOtpAuthContext?: never;
  };

type CommitEvmFamilyThresholdEcdsaSessionsArgs =
  | CommitEmailOtpEvmFamilyThresholdEcdsaSessionsArgs
  | CommitPasskeyEvmFamilyThresholdEcdsaSessionsArgs;

function signerDomainForThresholdEcdsaSource(
  source: ThresholdEcdsaSessionStoreSource,
): ThresholdEcdsaBootstrapSignerAuth {
  switch (source) {
    case 'email_otp':
      return {
        authMethod: SIGNER_AUTH_METHODS.emailOtp,
        signerSource: SIGNER_SOURCES.emailOtpRegistration,
      };
    case 'login':
    case 'registration':
    case 'manual-bootstrap':
      return {
        authMethod: SIGNER_AUTH_METHODS.passkey,
        signerSource: SIGNER_SOURCES.passkeyRegistration,
      };
    default:
      source satisfies never;
      throw new Error('[SigningEngine] unsupported threshold ECDSA session source');
  }
}

function assertNeverThresholdEcdsaBootstrapBackendBinding(value: never): never {
  throw new Error(
    `[SigningEngine] unsupported threshold ECDSA bootstrap backend binding: ${JSON.stringify(value)}`,
  );
}

async function persistWorkerProvisionedRoleLocalReadyRecord(args: {
  deps: CommitWorkerProvisionedThresholdEcdsaSessionDeps;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
}): Promise<void> {
  const binding = args.bootstrap.thresholdEcdsaKeyRef.backendBinding;
  if (!binding) {
    throw new Error('[SigningEngine] ECDSA bootstrap is missing its backend binding');
  }
  const record = workerProvisionedReadyRecordForPersistence(binding);
  if (!record) return;
  const persisted = await args.deps.persistEcdsaRoleLocalReadyRecord({
    record,
    storageKeyFacts: ecdsaRoleLocalReadyRecordStorageKeyFacts(record),
  });
  if (!persisted.ok) {
    throw new Error(
      `[SigningEngine] ECDSA role-local ready record persistence failed (${persisted.code}): ${persisted.message}`,
    );
  }
}

function workerProvisionedReadyRecordForPersistence(
  binding: ThresholdEcdsaBackendBinding,
): ThresholdEcdsaBackendBinding['ecdsaRoleLocalReadyRecord'] | null {
  switch (binding.materialKind) {
    case 'role_local_ready_state_blob':
      return binding.ecdsaRoleLocalReadyRecord;
    case 'role_local_worker_handle':
    case 'role_local_durable_public_anchor':
    case 'role_local_durable_sealed_ref':
    case 'metadata_only':
      return null;
    default:
      return assertNeverThresholdEcdsaBootstrapBackendBinding(binding satisfies never);
  }
}

export async function commitWorkerProvisionedThresholdEcdsaSession(
  deps: CommitWorkerProvisionedThresholdEcdsaSessionDeps,
  args: CommitWorkerProvisionedThresholdEcdsaSessionArgs,
): Promise<{
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  authorization: ExactWalletSessionAuthorization;
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
    const canonicalBootstrap = args.bootstrap;
    if (!String(canonicalBootstrap.thresholdEcdsaKeyRef.ecdsaThresholdKeyId || '').trim()) {
      throw new Error(
        '[SigningEngine] threshold-ecdsa bootstrap did not provide canonical ecdsaThresholdKeyId',
      );
    }
    await persistThresholdEcdsaBootstrapForWalletTarget({
      bootstrapStore: deps.bootstrapStore,
      walletId: args.walletId,
      chainTarget: args.chainTarget,
      bootstrap: canonicalBootstrap,
      signerAuth: signerDomainForThresholdEcdsaSource(args.source),
    });
    await persistWorkerProvisionedRoleLocalReadyRecord({
      deps,
      bootstrap: canonicalBootstrap,
    });
    const authorization = await persistExactWalletSessionAuthorizationFromEcdsaBootstrap(
      walletSessionAuthorizations,
      {
        walletId: args.walletId,
        authority: args.authority,
        bootstrap: canonicalBootstrap,
      },
    );
    return { bootstrap: canonicalBootstrap, authorization };
  });
}

export async function commitEvmFamilyThresholdEcdsaSessions(
  deps: CommitEvmFamilyThresholdEcdsaSessionsDeps,
  args: CommitEvmFamilyThresholdEcdsaSessionsArgs,
): Promise<{
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  authorization: ExactWalletSessionAuthorization;
}> {
  const committed =
    args.source === 'email_otp'
      ? await commitWorkerProvisionedThresholdEcdsaSession(deps, {
          walletId: args.walletId,
          chainTarget: args.chainTarget,
          bootstrap: args.bootstrap,
          source: 'email_otp',
          authority: args.authority,
          emailOtpAuthContext: args.emailOtpAuthContext,
        })
      : await commitWorkerProvisionedThresholdEcdsaSession(deps, {
          walletId: args.walletId,
          chainTarget: args.chainTarget,
          bootstrap: args.bootstrap,
          source: args.source,
          authority: args.authority,
        });
  return {
    bootstrap: committed.bootstrap,
    authorization: committed.authorization,
  };
}

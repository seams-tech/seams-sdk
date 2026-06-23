import type { AccountId } from '@/core/types/accountIds';
import {
  thresholdEcdsaChainTargetKey,
  toWalletId,
  type ThresholdEcdsaChainTarget,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../interfaces/signing';
import {
  readPersistedAvailableSigningLanes as readPersistedAvailableSigningLanesValue,
  type PersistedAvailableSigningLanesDeps,
} from './availability/persistedAvailableSigningLanes';
import type {
  ReadAvailableSigningLanesInput,
  AvailableSigningLanes,
} from './availability/availableSigningLanes';
import type {
  RestorePersistedSessionsForWalletInput,
  RestorePersistedSessionsForWalletResult,
} from './sealedRecovery/sealedRecovery.types';
import {
  clearAllThresholdEcdsaSessionRecords as clearAllThresholdEcdsaSessionRecordsValue,
  clearThresholdEcdsaSessionRecordForWallet as clearThresholdEcdsaSessionRecordForWalletValue,
  getThresholdEcdsaKeyRefByKey as getThresholdEcdsaKeyRefByKeyValue,
  getThresholdEcdsaSessionRecordForWalletTarget as getThresholdEcdsaSessionRecordForWalletTargetValue,
  listThresholdEcdsaSessionRecordsForWalletTarget as listThresholdEcdsaSessionRecordsForWalletTargetValue,
  clearThresholdEcdsaSessionRecordForWalletTarget as clearThresholdEcdsaSessionRecordForWalletTargetValue,
  listStoredThresholdEcdsaSessionRecordsForWallet,
  upsertThresholdEcdsaSessionFromBootstrap as upsertThresholdEcdsaSessionFromBootstrapValue,
  type ThresholdEcdsaSessionRecord,
  type ThresholdEcdsaSessionStoreDeps,
} from './persistence/records';
import type {
  ThresholdEcdsaEmailOtpAuthContext,
  ThresholdEcdsaSessionStoreSource,
} from './identity/laneIdentity';
import type { ThresholdEcdsaSessionBootstrapResult } from '../threshold/ecdsa/activation';
import { markRouterAbEcdsaHssWorkerMaterialRuntimeValidated } from './routerAbSigningWalletSession';

const EMPTY_RESTORE_PERSISTED_SESSIONS_FOR_WALLET_RESULT: RestorePersistedSessionsForWalletResult =
  {
    listed: 0,
    attempted: 0,
    restored: 0,
    deferred: 0,
    skipped: 0,
    truncated: 0,
  };

export type SessionPublicDeps = {
  availableLanes: PersistedAvailableSigningLanesDeps;
  getConfiguredEcdsaChainTargets: () => readonly ThresholdEcdsaChainTarget[];
  ecdsaSessions: ThresholdEcdsaSessionStoreDeps;
  signingSessionSeal?: {
    keyVersion?: string;
    shamirPrimeB64u?: string;
  };
  restore: {
    emailOtp: (
      args: RestorePersistedSessionsForWalletInput & {
        walletId: string;
        authMethod: 'email_otp';
      },
    ) => Promise<RestorePersistedSessionsForWalletResult>;
    passkey?: (
      args: RestorePersistedSessionsForWalletInput & {
        walletId: string;
        authMethod: 'passkey';
      },
    ) => Promise<RestorePersistedSessionsForWalletResult>;
  };
};

type UpsertThresholdEcdsaSessionFromBootstrapInputBase = {
  walletId: WalletId;
  chainTarget: ThresholdEcdsaChainTarget;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
};

export type UpsertThresholdEcdsaSessionFromBootstrapInput =
  | (UpsertThresholdEcdsaSessionFromBootstrapInputBase & {
      source: 'email_otp';
      emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
    })
  | (UpsertThresholdEcdsaSessionFromBootstrapInputBase & {
      source: Exclude<ThresholdEcdsaSessionStoreSource, 'email_otp'>;
      emailOtpAuthContext?: never;
    });

export type GetThresholdEcdsaKeyRefForWalletTargetInput = {
  walletId: WalletId;
  chainTarget: ThresholdEcdsaChainTarget;
  source: ThresholdEcdsaSessionStoreSource;
};

export type ListThresholdEcdsaSessionRecordsForWalletTargetInput = {
  walletId: WalletId;
  chainTarget: ThresholdEcdsaChainTarget;
  source?: ThresholdEcdsaSessionStoreSource;
};

function mergeRestorePersistedSessionsForWalletResults(
  results: readonly RestorePersistedSessionsForWalletResult[],
): RestorePersistedSessionsForWalletResult {
  return results.reduce<RestorePersistedSessionsForWalletResult>(
    (acc, result) => ({
      listed: acc.listed + result.listed,
      attempted: acc.attempted + result.attempted,
      restored: acc.restored + result.restored,
      deferred: acc.deferred + result.deferred,
      skipped: acc.skipped + result.skipped,
      truncated: acc.truncated + result.truncated,
    }),
    EMPTY_RESTORE_PERSISTED_SESSIONS_FOR_WALLET_RESULT,
  );
}

function markRouterAbEcdsaHssBootstrapWorkerMaterialRuntimeValidated(
  record: ThresholdEcdsaSessionRecord,
): void {
  if (markRouterAbEcdsaHssWorkerMaterialRuntimeValidated(record)) return;
  throw new Error(
    '[SigningEngine] ECDSA-HSS bootstrap returned worker material that could not be runtime-validated',
  );
}

export async function restorePersistedSessionsForWallet(
  deps: SessionPublicDeps,
  args: RestorePersistedSessionsForWalletInput,
): Promise<RestorePersistedSessionsForWalletResult> {
  const walletId = toWalletId(args.walletId);

  const authMethods = args.authMethod ? [args.authMethod] : (['email_otp', 'passkey'] as const);
  const results = await Promise.all(
    authMethods.map(async (authMethod) => {
      if (authMethod === 'email_otp') {
        return await deps.restore.emailOtp({
          ...args,
          walletId,
          authMethod,
        });
      }
      return (
        (await deps.restore.passkey?.({
          ...args,
          walletId,
          authMethod,
        })) ?? EMPTY_RESTORE_PERSISTED_SESSIONS_FOR_WALLET_RESULT
      );
    }),
  );

  return mergeRestorePersistedSessionsForWalletResults(results);
}

export async function readPersistedAvailableSigningLanes(
  deps: SessionPublicDeps,
  args: Omit<ReadAvailableSigningLanesInput, 'ecdsaChainTargets'>,
): Promise<AvailableSigningLanes> {
  return await readPersistedAvailableSigningLanesValue(
    deps.availableLanes,
    args,
    deps.getConfiguredEcdsaChainTargets(),
  );
}

export function upsertThresholdEcdsaSessionFromBootstrap(
  deps: SessionPublicDeps,
  args: UpsertThresholdEcdsaSessionFromBootstrapInput,
): void {
  if (args.source === 'email_otp') {
    const record = upsertThresholdEcdsaSessionFromBootstrapValue(deps.ecdsaSessions, {
      walletId: args.walletId,
      chainTarget: args.chainTarget,
      bootstrap: args.bootstrap,
      source: 'email_otp',
      emailOtpAuthContext: args.emailOtpAuthContext,
      ...(deps.signingSessionSeal ? { signingSessionSeal: deps.signingSessionSeal } : {}),
    });
    if (args.bootstrap.thresholdEcdsaKeyRef.backendBinding?.materialKind === 'role_local_worker_handle') {
      markRouterAbEcdsaHssBootstrapWorkerMaterialRuntimeValidated(record);
    }
    return;
  }
  const record = upsertThresholdEcdsaSessionFromBootstrapValue(deps.ecdsaSessions, {
    walletId: args.walletId,
    chainTarget: args.chainTarget,
    bootstrap: args.bootstrap,
    source: args.source,
    ...(deps.signingSessionSeal ? { signingSessionSeal: deps.signingSessionSeal } : {}),
  });
  if (args.bootstrap.thresholdEcdsaKeyRef.backendBinding?.materialKind === 'role_local_worker_handle') {
    markRouterAbEcdsaHssBootstrapWorkerMaterialRuntimeValidated(record);
  }
}

export function getThresholdEcdsaKeyRefForWalletTarget(
  deps: SessionPublicDeps,
  args: GetThresholdEcdsaKeyRefForWalletTargetInput,
): ThresholdEcdsaSecp256k1KeyRef {
  const records = listStoredThresholdEcdsaSessionRecordsForWallet(args.walletId, {
    chainTarget: args.chainTarget,
    source: args.source,
  });
  if (records.length !== 1) {
    throw new Error(
      records.length > 1
        ? `[SigningEngine] ambiguous threshold ECDSA keyRef for wallet ${String(args.walletId)} ${thresholdEcdsaChainTargetKey(args.chainTarget)}`
        : `[SigningEngine] missing threshold ECDSA keyRef for wallet ${String(args.walletId)} ${thresholdEcdsaChainTargetKey(args.chainTarget)}`,
    );
  }
  const record = records[0]!;
  const selected = getThresholdEcdsaKeyRefByKeyValue(deps.ecdsaSessions, {
    walletId: record.walletId,
    keyHandle: record.keyHandle,
    authMethod: record.source === 'email_otp' ? 'email_otp' : 'passkey',
    curve: 'ecdsa',
    chainTarget: record.chainTarget,
    signingGrantId: record.signingGrantId,
    thresholdSessionId: record.thresholdSessionId,
  })?.keyRef;
  if (selected) return selected;
  throw new Error(
    `[SigningEngine] missing threshold ECDSA keyRef for wallet ${String(args.walletId)} ${thresholdEcdsaChainTargetKey(args.chainTarget)}`,
  );
}

export function listThresholdEcdsaSessionRecordsForWalletTarget(
  deps: SessionPublicDeps,
  args: ListThresholdEcdsaSessionRecordsForWalletTargetInput,
): ThresholdEcdsaSessionRecord[] {
  return listThresholdEcdsaSessionRecordsForWalletTargetValue(deps.ecdsaSessions, args);
}

export function clearThresholdEcdsaSessionRecordForWalletTarget(
  deps: SessionPublicDeps,
  args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    source?: ThresholdEcdsaSessionStoreSource;
  },
): void {
  clearThresholdEcdsaSessionRecordForWalletTargetValue(deps.ecdsaSessions, args);
}

export function clearThresholdEcdsaSessionRecordForWallet(
  deps: SessionPublicDeps,
  walletId: WalletId,
): void {
  clearThresholdEcdsaSessionRecordForWalletValue(deps.ecdsaSessions, walletId);
}

export function clearAllThresholdEcdsaSessionRecords(deps: SessionPublicDeps): void {
  clearAllThresholdEcdsaSessionRecordsValue(deps.ecdsaSessions);
}

export type {
  RestorePersistedSessionsForWalletInput,
  RestorePersistedSessionsForWalletResult,
} from './sealedRecovery/sealedRecovery.types';
export type {
  EmailOtpEcdsaSealedRecoveryRecord,
  EmailOtpEd25519SealedRecoveryRecord,
  PasskeyEcdsaSealedRecoveryRecord,
  PasskeyEd25519SealedRecoveryRecord,
  RejectedSealedRecoveryRecord,
  SealedRecoveryRecord,
  SealedRecoveryRejectionReason,
} from './sealedRecovery/recoveryRecord';
export type {
  ReadAvailableSigningLanesInput,
  AvailableSigningLanes,
} from './availability/availableSigningLanes';
export type { ThresholdEcdsaSessionRecord } from './persistence/records';

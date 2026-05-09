import { toAccountId, type AccountId } from '@/core/types/accountIds';
import {
  thresholdEcdsaChainTargetKey,
  toWalletSubjectId,
  type ThresholdEcdsaChainTarget,
  type WalletSubjectId,
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
  RestorePersistedSessionsForAccountInput,
  RestorePersistedSessionsForAccountResult,
} from './sealedRecovery/types';
import {
  clearAllThresholdEcdsaSessionRecords as clearAllThresholdEcdsaSessionRecordsValue,
  clearThresholdEcdsaSessionRecordForAccount as clearThresholdEcdsaSessionRecordForAccountValue,
  getThresholdEcdsaKeyRefByKey as getThresholdEcdsaKeyRefByKeyValue,
  getThresholdEcdsaSessionRecordForTarget as getThresholdEcdsaSessionRecordForTargetValue,
  listThresholdEcdsaSessionRecordsForSubject as listThresholdEcdsaSessionRecordsForSubjectValue,
  upsertThresholdEcdsaSessionFromBootstrap as upsertThresholdEcdsaSessionFromBootstrapValue,
  type ThresholdEcdsaSessionRecord,
  type ThresholdEcdsaSessionStoreDeps,
} from './persistence/records';
import type {
  ThresholdEcdsaEmailOtpAuthContext,
  ThresholdEcdsaSessionStoreSource,
} from './identity/laneIdentity';
import type { ThresholdEcdsaSessionBootstrapResult } from '../threshold/ecdsa/activation';

const EMPTY_RESTORE_PERSISTED_SESSIONS_FOR_ACCOUNT_RESULT: RestorePersistedSessionsForAccountResult = {
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
      args: RestorePersistedSessionsForAccountInput & {
        walletId: string;
        authMethod: 'email_otp';
      },
    ) => Promise<RestorePersistedSessionsForAccountResult>;
    passkey?: (
      args: RestorePersistedSessionsForAccountInput & {
        walletId: string;
        authMethod: 'passkey';
      },
    ) => Promise<RestorePersistedSessionsForAccountResult>;
  };
};

export type UpsertThresholdEcdsaSessionFromBootstrapInput = {
  nearAccountId: AccountId | string;
  chainTarget: ThresholdEcdsaChainTarget;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  source: ThresholdEcdsaSessionStoreSource;
  emailOtpAuthContext?: ThresholdEcdsaEmailOtpAuthContext;
};

export type GetThresholdEcdsaKeyRefForAccountTargetInput = {
  nearAccountId: AccountId | string;
  chainTarget: ThresholdEcdsaChainTarget;
  source: ThresholdEcdsaSessionStoreSource;
};

function mergeRestorePersistedSessionsForAccountResults(
  results: readonly RestorePersistedSessionsForAccountResult[],
): RestorePersistedSessionsForAccountResult {
  return results.reduce<RestorePersistedSessionsForAccountResult>(
    (acc, result) => ({
      listed: acc.listed + result.listed,
      attempted: acc.attempted + result.attempted,
      restored: acc.restored + result.restored,
      deferred: acc.deferred + result.deferred,
      skipped: acc.skipped + result.skipped,
      truncated: acc.truncated + result.truncated,
    }),
    EMPTY_RESTORE_PERSISTED_SESSIONS_FOR_ACCOUNT_RESULT,
  );
}

export async function restorePersistedSessionsForAccount(
  deps: SessionPublicDeps,
  args: RestorePersistedSessionsForAccountInput,
): Promise<RestorePersistedSessionsForAccountResult> {
  const walletId = String(toAccountId(args.walletId) || '').trim();
  if (!walletId) return EMPTY_RESTORE_PERSISTED_SESSIONS_FOR_ACCOUNT_RESULT;

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
        })) ?? EMPTY_RESTORE_PERSISTED_SESSIONS_FOR_ACCOUNT_RESULT
      );
    }),
  );

  return mergeRestorePersistedSessionsForAccountResults(results);
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
  upsertThresholdEcdsaSessionFromBootstrapValue(deps.ecdsaSessions, {
    ...args,
    ...(deps.signingSessionSeal ? { signingSessionSeal: deps.signingSessionSeal } : {}),
  });
}

export function getThresholdEcdsaKeyRefForAccountTarget(
  deps: SessionPublicDeps,
  args: GetThresholdEcdsaKeyRefForAccountTargetInput,
): ThresholdEcdsaSecp256k1KeyRef {
  const record = getThresholdEcdsaSessionRecordForTargetValue(deps.ecdsaSessions, {
    subjectId: toWalletSubjectId(args.nearAccountId),
    chainTarget: args.chainTarget,
    source: args.source,
  });
  const selected = getThresholdEcdsaKeyRefByKeyValue(deps.ecdsaSessions, {
    subjectId: record.subjectId,
    authMethod: record.source === 'email_otp' ? 'email_otp' : 'passkey',
    curve: 'ecdsa',
    chainTarget: record.chainTarget,
    ecdsaThresholdKeyId: record.ecdsaThresholdKeyId,
    signingRootId: record.signingRootId,
    signingRootVersion: record.signingRootVersion || 'default',
    walletSigningSessionId: record.walletSigningSessionId,
    thresholdSessionId: record.thresholdSessionId,
  })?.keyRef;
  if (selected) return selected;
  throw new Error(
    `[SigningEngine] missing threshold ECDSA keyRef for ${thresholdEcdsaChainTargetKey(args.chainTarget)}`,
  );
}

export function listThresholdEcdsaSessionRecordsForSubject(
  deps: SessionPublicDeps,
  args: { subjectId: WalletSubjectId },
): ThresholdEcdsaSessionRecord[] {
  return listThresholdEcdsaSessionRecordsForSubjectValue(deps.ecdsaSessions, args);
}

export function clearThresholdEcdsaSessionRecordForAccount(
  deps: SessionPublicDeps,
  nearAccountId: AccountId | string,
): void {
  clearThresholdEcdsaSessionRecordForAccountValue(deps.ecdsaSessions, nearAccountId);
}

export function clearAllThresholdEcdsaSessionRecords(deps: SessionPublicDeps): void {
  clearAllThresholdEcdsaSessionRecordsValue(deps.ecdsaSessions);
}

export function createSessionPublicApi(deps: SessionPublicDeps) {
  return {
    restorePersistedSessionsForAccount: (args: RestorePersistedSessionsForAccountInput) =>
      restorePersistedSessionsForAccount(deps, args),
    readPersistedAvailableSigningLanes: (
      args: Omit<ReadAvailableSigningLanesInput, 'ecdsaChainTargets'>,
    ) => readPersistedAvailableSigningLanes(deps, args),
    upsertThresholdEcdsaSessionFromBootstrap: (
      args: UpsertThresholdEcdsaSessionFromBootstrapInput,
    ) => upsertThresholdEcdsaSessionFromBootstrap(deps, args),
    getThresholdEcdsaKeyRefForAccountTarget: (
      args: GetThresholdEcdsaKeyRefForAccountTargetInput,
    ) => getThresholdEcdsaKeyRefForAccountTarget(deps, args),
    listThresholdEcdsaSessionRecordsForSubject: (args: { subjectId: WalletSubjectId }) =>
      listThresholdEcdsaSessionRecordsForSubject(deps, args),
    clearThresholdEcdsaSessionRecordForAccount: (nearAccountId: AccountId | string) =>
      clearThresholdEcdsaSessionRecordForAccount(deps, nearAccountId),
    clearAllThresholdEcdsaSessionRecords: () => clearAllThresholdEcdsaSessionRecords(deps),
  };
}

export type SessionPublicApi = ReturnType<typeof createSessionPublicApi>;

export type {
  RestorePersistedSessionsForAccountInput,
  RestorePersistedSessionsForAccountResult,
} from './sealedRecovery/types';
export type { ReadAvailableSigningLanesInput, AvailableSigningLanes } from './availability/availableSigningLanes';
export type { ThresholdEcdsaSessionRecord } from './persistence/records';

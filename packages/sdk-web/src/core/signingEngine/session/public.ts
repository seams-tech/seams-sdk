import type { AccountId } from '@/core/types/accountIds';
import {
  thresholdEcdsaChainTargetKey,
  toWalletId,
  type ThresholdEcdsaChainTarget,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  readPersistedAvailableSigningLanes as readPersistedAvailableSigningLanesValue,
  type PersistedAvailableSigningLanesDeps,
} from './availability/persistedAvailableSigningLanes';
import type {
  ReadAvailableSigningLanesInput,
  AvailableSigningLanes,
} from './availability/availableSigningLanes';
import type {
  DiscoverPersistedSessionsForWalletInput,
  DiscoverPersistedSessionsForWalletResult,
} from './sealedRecovery/sealedRecovery.types';
import {
  clearAllThresholdEcdsaSessionRecords as clearAllThresholdEcdsaSessionRecordsValue,
  clearThresholdEcdsaSessionRecordForWallet as clearThresholdEcdsaSessionRecordForWalletValue,
  getThresholdEcdsaSessionRecordForWalletTarget as getThresholdEcdsaSessionRecordForWalletTargetValue,
  listThresholdEcdsaSessionRecordsForWalletTarget as listThresholdEcdsaSessionRecordsForWalletTargetValue,
  clearThresholdEcdsaSessionRecordForWalletTarget as clearThresholdEcdsaSessionRecordForWalletTargetValue,
  type ThresholdEcdsaSessionRecord,
  type ThresholdEcdsaSessionStoreDeps,
} from './persistence/records';
import type { ThresholdEcdsaSessionStoreSource } from './identity/laneIdentity';
import { SIGNER_AUTH_METHODS, type SignerAuthMethod } from '@shared/utils/signerDomain';

const EMPTY_DISCOVER_PERSISTED_SESSIONS_FOR_WALLET_RESULT: DiscoverPersistedSessionsForWalletResult =
  {
    listed: 0,
    discovered: 0,
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
  discovery: {
    emailOtp: (
      args: DiscoverPersistedSessionsForWalletInput & {
        walletId: string;
        authMethod: typeof SIGNER_AUTH_METHODS.emailOtp;
      },
    ) => Promise<DiscoverPersistedSessionsForWalletResult>;
    passkey?: (
      args: DiscoverPersistedSessionsForWalletInput & {
        walletId: string;
        authMethod: typeof SIGNER_AUTH_METHODS.passkey;
      },
    ) => Promise<DiscoverPersistedSessionsForWalletResult>;
  };
};

export type ListThresholdEcdsaSessionRecordsForWalletTargetInput = {
  walletId: WalletId;
  chainTarget: ThresholdEcdsaChainTarget;
  source?: ThresholdEcdsaSessionStoreSource;
};

function mergeDiscoverPersistedSessionsForWalletResults(
  results: readonly DiscoverPersistedSessionsForWalletResult[],
): DiscoverPersistedSessionsForWalletResult {
  return results.reduce<DiscoverPersistedSessionsForWalletResult>(
    (acc, result) => ({
      listed: acc.listed + result.listed,
      discovered: acc.discovered + result.discovered,
      truncated: acc.truncated + result.truncated,
    }),
    EMPTY_DISCOVER_PERSISTED_SESSIONS_FOR_WALLET_RESULT,
  );
}

export async function discoverPersistedSessionsForWallet(
  deps: SessionPublicDeps,
  args: DiscoverPersistedSessionsForWalletInput,
): Promise<DiscoverPersistedSessionsForWalletResult> {
  const walletId = toWalletId(args.walletId);

  const authMethods: readonly SignerAuthMethod[] = args.authMethod
    ? [args.authMethod]
    : [SIGNER_AUTH_METHODS.emailOtp, SIGNER_AUTH_METHODS.passkey];
  const results = await Promise.all(
    authMethods.map(async (authMethod) => {
      switch (authMethod) {
        case SIGNER_AUTH_METHODS.emailOtp:
          return await deps.discovery.emailOtp({
            ...args,
            walletId,
            authMethod,
          });
        case SIGNER_AUTH_METHODS.passkey:
          return (
            (await deps.discovery.passkey?.({
              ...args,
              walletId,
              authMethod,
            })) ?? EMPTY_DISCOVER_PERSISTED_SESSIONS_FOR_WALLET_RESULT
          );
        default:
          return assertNeverSignerAuthMethod(authMethod);
      }
    }),
  );

  return mergeDiscoverPersistedSessionsForWalletResults(results);
}

function assertNeverSignerAuthMethod(value: never): never {
  throw new Error(`Unsupported signer auth method: ${String(value)}`);
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
  DiscoverPersistedSessionsForWalletInput,
  DiscoverPersistedSessionsForWalletResult,
} from './sealedRecovery/sealedRecovery.types';
export type {
  EmailOtpEcdsaSealedRecoveryRecord,
  PasskeyEcdsaSealedRecoveryRecord,
  RejectedSealedRecoveryRecord,
  SealedRecoveryRecord,
  SealedRecoveryRejectionReason,
} from './sealedRecovery/recoveryRecord';
export type {
  ReadAvailableSigningLanesInput,
  AvailableSigningLanes,
} from './availability/availableSigningLanes';
export type { ThresholdEcdsaSessionRecord } from './persistence/records';

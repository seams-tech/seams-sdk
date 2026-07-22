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
  DiscoverPersistedSessionsForWalletInput,
  DiscoverPersistedSessionsForWalletResult,
} from './sealedRecovery/sealedRecovery.types';
import {
  clearAllThresholdEcdsaSessionRecords as clearAllThresholdEcdsaSessionRecordsValue,
  clearThresholdEcdsaSessionRecordForWallet as clearThresholdEcdsaSessionRecordForWalletValue,
  clearThresholdEcdsaSessionRecordForExactIdentity as clearThresholdEcdsaSessionRecordForExactIdentityValue,
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
import type { ExactEcdsaSigningLaneIdentity } from './identity/exactSigningLaneIdentity';
import type { ThresholdEcdsaSessionBootstrapResult } from '../threshold/ecdsa/activation';
import { markRouterAbEcdsaDerivationWorkerMaterialRuntimeValidated } from './routerAbSigningWalletSession';
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

type UpsertThresholdEcdsaSessionFromBootstrapInputBase = {
  purpose: 'transaction_signing';
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

function markRouterAbEcdsaDerivationBootstrapWorkerMaterialRuntimeValidated(
  record: ThresholdEcdsaSessionRecord,
): void {
  if (markRouterAbEcdsaDerivationWorkerMaterialRuntimeValidated(record)) return;
  throw new Error(
    '[SigningEngine] Router A/B ECDSA derivation bootstrap returned worker material that could not be runtime-validated',
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

function assertNeverThresholdEcdsaSessionStoreSource(value: never): never {
  throw new Error(`Unsupported threshold ECDSA session source: ${String(value)}`);
}

function ecdsaAuthMethodForSessionSource(
  source: ThresholdEcdsaSessionStoreSource,
): SignerAuthMethod {
  switch (source) {
    case SIGNER_AUTH_METHODS.emailOtp:
      return SIGNER_AUTH_METHODS.emailOtp;
    case 'login':
    case 'registration':
    case 'manual-bootstrap':
      return SIGNER_AUTH_METHODS.passkey;
    default:
      return assertNeverThresholdEcdsaSessionStoreSource(source);
  }
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
  if (args.source === SIGNER_AUTH_METHODS.emailOtp) {
    const record = upsertThresholdEcdsaSessionFromBootstrapValue(deps.ecdsaSessions, {
      purpose: 'transaction_signing',
      walletId: args.walletId,
      chainTarget: args.chainTarget,
      bootstrap: args.bootstrap,
      source: SIGNER_AUTH_METHODS.emailOtp,
      emailOtpAuthContext: args.emailOtpAuthContext,
      ...(deps.signingSessionSeal ? { signingSessionSeal: deps.signingSessionSeal } : {}),
    });
    if (
      args.bootstrap.thresholdEcdsaKeyRef.backendBinding?.materialKind ===
      'role_local_worker_handle'
    ) {
      markRouterAbEcdsaDerivationBootstrapWorkerMaterialRuntimeValidated(record);
    }
    return;
  }
  const record = upsertThresholdEcdsaSessionFromBootstrapValue(deps.ecdsaSessions, {
    purpose: 'transaction_signing',
    walletId: args.walletId,
    chainTarget: args.chainTarget,
    bootstrap: args.bootstrap,
    source: args.source,
    ...(deps.signingSessionSeal ? { signingSessionSeal: deps.signingSessionSeal } : {}),
  });
  if (
    args.bootstrap.thresholdEcdsaKeyRef.backendBinding?.materialKind === 'role_local_worker_handle'
  ) {
    markRouterAbEcdsaDerivationBootstrapWorkerMaterialRuntimeValidated(record);
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
    authMethod: ecdsaAuthMethodForSessionSource(record.source),
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

export function clearThresholdEcdsaSessionRecordForExactIdentity(
  deps: SessionPublicDeps,
  identity: ExactEcdsaSigningLaneIdentity,
): void {
  clearThresholdEcdsaSessionRecordForExactIdentityValue(deps.ecdsaSessions, identity);
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

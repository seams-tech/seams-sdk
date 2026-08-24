import type { AccountId } from '@/core/types/accountIds';
import {
  thresholdEcdsaChainTargetKey,
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  readPersistedAvailableSigningLanes as readPersistedAvailableSigningLanesValue,
  readOwnerScopedAvailableSigningLanes as readOwnerScopedAvailableSigningLanesValue,
  type PersistedAvailableSigningLanesDeps,
} from './availability/persistedAvailableSigningLanes';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { OwnerLaneScope } from './identity/signingLaneAuthBinding';
import type {
  ReadAvailableSigningLanesInput,
  AvailableSigningLanes,
} from './availability/availableSigningLanes';
import type {
  DiscoverPersistedSessionsForWalletInput,
  DiscoverPersistedSessionsForWalletResult,
} from './sealedRecovery/sealedRecovery.types';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';

const EMPTY_DISCOVER_PERSISTED_SESSIONS_FOR_WALLET_RESULT: DiscoverPersistedSessionsForWalletResult =
  {
    listed: 0,
    discovered: 0,
    truncated: 0,
  };

export type SessionPublicDeps = {
  availableLanes: PersistedAvailableSigningLanesDeps;
  getConfiguredEcdsaChainTargets: () => readonly ThresholdEcdsaChainTarget[];
  signingSessionSeal?: {
    keyVersion?: string;
    groupId?: string;
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

export async function discoverPersistedSessionsForWallet(
  deps: SessionPublicDeps,
  args: DiscoverPersistedSessionsForWalletInput,
): Promise<DiscoverPersistedSessionsForWalletResult> {
  const walletId = toWalletId(args.walletId);
  switch (args.authMethod) {
    case SIGNER_AUTH_METHODS.emailOtp:
      return await deps.discovery.emailOtp({
        ...args,
        walletId,
        authMethod: SIGNER_AUTH_METHODS.emailOtp,
      });
    case SIGNER_AUTH_METHODS.passkey:
      return (
        (await deps.discovery.passkey?.({
          ...args,
          walletId,
          authMethod: SIGNER_AUTH_METHODS.passkey,
        })) ?? EMPTY_DISCOVER_PERSISTED_SESSIONS_FOR_WALLET_RESULT
      );
    default:
      args.authMethod satisfies never;
      throw new Error('Unsupported signer auth method');
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

/** R103C human operational read: one exact owner, configured ECDSA targets. */
export async function readOwnerScopedSigningLanes(
  deps: SessionPublicDeps,
  args: {
    readonly walletId: WalletId | string;
    readonly ownerScope: OwnerLaneScope;
  },
): Promise<AvailableSigningLanes> {
  return await readOwnerScopedAvailableSigningLanesValue(deps.availableLanes, {
    walletId: args.walletId,
    ownerScope: args.ownerScope,
    ecdsaChainTargets: deps.getConfiguredEcdsaChainTargets(),
    requiredEcdsaCapability: 'sign',
  });
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

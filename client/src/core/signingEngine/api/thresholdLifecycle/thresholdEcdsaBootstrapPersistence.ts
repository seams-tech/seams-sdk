import type {
  ChainAccountRecord,
  UpsertChainAccountInput,
  UpsertProfileInput,
} from '@/core/indexedDB/passkeyClientDB.types';
import { buildNearAccountRefs, inferNearChainIdKey } from '@/core/accountData/near/accountRefs';
import { buildNearProfileId } from '@/core/accountData/near/profileId';
import { resolveProfileAccountContextFromCandidates } from '@/core/indexedDB/profileAccountProjection';
import type { UndeployedSmartAccountSignerSet } from '@shared/utils';
import { normalizeOptionalNonEmptyString } from '@shared/utils/normalize';
import { DEFAULT_CONFIRMATION_CONFIG } from '@/core/types/signer-worker';
import {
  normalizeIndexedDbAccountAddress,
  normalizeIndexedDbOptionalChainIdNumber,
  toIndexedDbChainIdKey,
} from '@/core/indexedDB/normalization';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type {
  ThresholdEcdsaActivationChain,
  ThresholdEcdsaSessionBootstrapResult,
} from '../../orchestration/thresholdActivation';

export type ThresholdEcdsaSmartAccountBootstrapInput = {
  chainId: number;
  factory?: string;
  entryPoint?: string;
  salt?: string;
  counterfactualAddress?: string;
};

export type ThresholdEcdsaSmartAccountDeploymentInput = {
  deployed: boolean;
  deploymentTxHash?: string;
};

export type ThresholdEcdsaBootstrapIndexedDbPort = {
  clientDB: {
    resolveProfileAccountContext: (args: {
      chainIdKey: string;
      accountAddress: string;
    }) => Promise<{ profileId: string; accountRef: { chainIdKey: string; accountAddress: string } } | null>;
    getProfile?: (profileId: string) => Promise<{ defaultDeviceNumber?: number } | null>;
    upsertProfile: (input: UpsertProfileInput) => Promise<unknown>;
    setLastProfileStateForProfile: (profileId: string, deviceNumber: number) => Promise<void>;
  };
  upsertChainAccount: (input: UpsertChainAccountInput) => Promise<ChainAccountRecord>;
};

function getUnknownChainIdKeyForActivationChain(chain: ThresholdEcdsaActivationChain): string {
  return chain === 'evm' ? 'evm:unknown' : 'tempo:42431';
}

function resolveBootstrapTargetChainIdKey(args: {
  chain: ThresholdEcdsaActivationChain;
  smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
}): string {
  const explicitChainId = normalizeIndexedDbOptionalChainIdNumber(args.smartAccount?.chainId);
  if (typeof explicitChainId === 'number')
    return toIndexedDbChainIdKey(args.chain, explicitChainId);
  const keygenChainId = normalizeIndexedDbOptionalChainIdNumber(args.bootstrap.keygen.chainId);
  if (typeof keygenChainId === 'number') return toIndexedDbChainIdKey(args.chain, keygenChainId);
  return getUnknownChainIdKeyForActivationChain(args.chain);
}

function deriveMirrorChainDefaults(chain: ThresholdEcdsaActivationChain): {
  chainIdKey: string;
  accountModel: 'erc4337' | 'tempo-native';
} {
  if (chain === 'evm') {
    return {
      chainIdKey: 'tempo:42431',
      accountModel: 'tempo-native',
    };
  }
  return {
    chainIdKey: 'evm:unknown',
    accountModel: 'erc4337',
  };
}

export function buildThresholdEcdsaBootstrapUndeployedSignerSet(args: {
  accountAddress: string;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
}): UndeployedSmartAccountSignerSet {
  const participantIds = Array.isArray(args.bootstrap.keygen.participantIds)
    ? args.bootstrap.keygen.participantIds
        .map((value) => Math.floor(Number(value)))
        .filter((value) => Number.isFinite(value) && value > 0)
    : [];
  return {
    version: 'undeployed_smart_account_signer_set_v1',
    ownerAddresses: [args.accountAddress],
    activeOwnerAddresses: [args.accountAddress],
    pendingOwnerAddresses: [],
    owners: [
      {
        signerId: args.accountAddress,
        signerType: 'threshold',
        status: 'active',
        ...(typeof args.bootstrap.keygen.relayerKeyId === 'string' &&
        args.bootstrap.keygen.relayerKeyId.trim()
          ? { relayerKeyId: args.bootstrap.keygen.relayerKeyId.trim() }
          : {}),
        ...(typeof args.bootstrap.keygen.thresholdEcdsaPublicKeyB64u === 'string' &&
        args.bootstrap.keygen.thresholdEcdsaPublicKeyB64u.trim()
          ? { thresholdEcdsaPublicKeyB64u: args.bootstrap.keygen.thresholdEcdsaPublicKeyB64u.trim() }
          : {}),
        ...(participantIds.length ? { participantIds } : {}),
      },
    ],
  };
}

async function ensureEmailOtpNearProfileAccountMapping(args: {
  indexedDB: ThresholdEcdsaBootstrapIndexedDbPort;
  nearAccountId: AccountId;
}): Promise<void> {
  const nearAccountId = toAccountId(String(args.nearAccountId || '').trim());
  const existing = await resolveProfileAccountContextFromCandidates(
    args.indexedDB.clientDB as any,
    buildNearAccountRefs(nearAccountId),
  );
  if (existing?.profileId) {
    const profile = await args.indexedDB.clientDB.getProfile?.(existing.profileId).catch(() => null);
    const deviceNumber = Number(profile?.defaultDeviceNumber);
    await args.indexedDB.clientDB.setLastProfileStateForProfile(
      existing.profileId,
      Number.isSafeInteger(deviceNumber) && deviceNumber >= 1 ? deviceNumber : 1,
    );
    return;
  }

  const accountAddress = normalizeIndexedDbAccountAddress(nearAccountId);
  if (!accountAddress) {
    throw new Error(
      `[SigningEngine] cannot create Email OTP profile/account mapping for ${String(nearAccountId)}`,
    );
  }
  const profileId = buildNearProfileId(nearAccountId);
  const chainIdKey = inferNearChainIdKey(nearAccountId);
  const useNetwork = chainIdKey.endsWith('mainnet') ? 'mainnet' : 'testnet';

  await args.indexedDB.clientDB.upsertProfile({
    profileId,
    defaultDeviceNumber: 1,
    preferences: {
      useRelayer: false,
      useNetwork,
      confirmationConfig: DEFAULT_CONFIRMATION_CONFIG,
    },
  });
  await args.indexedDB.upsertChainAccount({
    profileId,
    chainIdKey,
    accountAddress,
    accountModel: 'near-native',
    isPrimary: true,
  });
  await args.indexedDB.clientDB.setLastProfileStateForProfile(profileId, 1);
}

export async function persistThresholdEcdsaBootstrapChainAccount(args: {
  indexedDB: ThresholdEcdsaBootstrapIndexedDbPort;
  nearAccountId: AccountId;
  chain: ThresholdEcdsaActivationChain;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
  deployment?: ThresholdEcdsaSmartAccountDeploymentInput;
  ensureEmailOtpNearAccountMapping?: boolean;
}): Promise<void> {
  const nearAccountId = toAccountId(String(args.nearAccountId || '').trim());
  if (args.ensureEmailOtpNearAccountMapping) {
    await ensureEmailOtpNearProfileAccountMapping({
      indexedDB: args.indexedDB,
      nearAccountId,
    });
  }
  const nearContext = await resolveProfileAccountContextFromCandidates(
    args.indexedDB.clientDB as any,
    buildNearAccountRefs(nearAccountId),
  );
  if (!nearContext?.profileId) {
    throw new Error(`[SigningEngine] missing profile/account mapping for ${String(nearAccountId)}`);
  }

  const accountAddress = normalizeIndexedDbAccountAddress(
    args.smartAccount?.counterfactualAddress ||
      args.bootstrap.keygen.counterfactualAddress ||
      args.bootstrap.keygen.ethereumAddress,
  );
  if (!accountAddress) {
    throw new Error(
      '[SigningEngine] threshold-ecdsa bootstrap did not provide a counterfactual/account address',
    );
  }

  const chainIdKey = resolveBootstrapTargetChainIdKey({
    chain: args.chain,
    smartAccount: args.smartAccount,
    bootstrap: args.bootstrap,
  });
  const factory = normalizeOptionalNonEmptyString(
    args.smartAccount?.factory || args.bootstrap.keygen.factory,
  );
  const entryPoint = normalizeOptionalNonEmptyString(
    args.smartAccount?.entryPoint || args.bootstrap.keygen.entryPoint,
  );
  const salt = normalizeOptionalNonEmptyString(
    args.smartAccount?.salt || args.bootstrap.keygen.salt,
  );
  const deploymentCheckedAt = args.deployment?.deployed ? Date.now() : null;
  const undeployedSignerSet = buildThresholdEcdsaBootstrapUndeployedSignerSet({
    accountAddress,
    bootstrap: args.bootstrap,
  });

  await args.indexedDB.upsertChainAccount({
    profileId: nearContext.profileId,
    chainIdKey,
    accountAddress,
    accountModel: args.chain === 'evm' ? 'erc4337' : 'tempo-native',
    isPrimary: true,
    ...(factory ? { factory } : {}),
    ...(entryPoint ? { entryPoint } : {}),
    ...(salt ? { salt } : {}),
    counterfactualAddress: accountAddress,
    deployed: args.deployment?.deployed === true,
    deploymentTxHash:
      args.deployment?.deployed === true
        ? normalizeOptionalNonEmptyString(args.deployment.deploymentTxHash) || null
        : null,
    lastDeploymentCheckAt: deploymentCheckedAt,
    undeployedSignerSet,
  });

  // Provisioning once (tempo or evm) should still leave an "unknown" row for the
  // counterpart chain so first-send deployment gates can resolve the account without
  // forcing an extra WebAuthn bootstrap prompt.
  const mirror = deriveMirrorChainDefaults(args.chain);
  if (mirror.chainIdKey !== chainIdKey) {
    await args.indexedDB.upsertChainAccount({
      profileId: nearContext.profileId,
      chainIdKey: mirror.chainIdKey,
      accountAddress,
      accountModel: mirror.accountModel,
      isPrimary: true,
      ...(factory ? { factory } : {}),
      ...(entryPoint ? { entryPoint } : {}),
      ...(salt ? { salt } : {}),
      counterfactualAddress: accountAddress,
      deployed: false,
      deploymentTxHash: null,
      lastDeploymentCheckAt: null,
      undeployedSignerSet,
    });
  }
}

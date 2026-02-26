import type {
  ChainAccountRecord,
  UpsertChainAccountInput,
} from '@/core/indexedDB/passkeyClientDB.types';
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

export type ThresholdEcdsaBootstrapIndexedDbPort = {
  clientDB: {
    resolveNearAccountContext: (
      nearAccountId: AccountId,
    ) => Promise<{ profileId: string; sourceChainIdKey: string; sourceAccountAddress: string } | null>;
  };
  upsertChainAccount: (input: UpsertChainAccountInput) => Promise<ChainAccountRecord>;
};

function normalizeOptionalAccountAddress(value: unknown): string | undefined {
  const normalized = String(value || '')
    .trim()
    .toLowerCase();
  return normalized || undefined;
}

function normalizeOptionalString(value: unknown): string | undefined {
  const normalized = String(value || '').trim();
  return normalized || undefined;
}

function normalizeOptionalChainIdNumber(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) {
    return value;
  }
  const raw = String(value || '')
    .trim()
    .toLowerCase();
  if (!raw) return undefined;
  if (raw.includes(':')) return undefined;
  if (!/^\d+$/.test(raw)) return undefined;
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed) || parsed < 0) return undefined;
  return parsed;
}

function getUnknownChainIdKeyForActivationChain(chain: ThresholdEcdsaActivationChain): string {
  return chain === 'evm' ? 'evm:unknown' : 'tempo:42431';
}

function toChainIdKey(chain: ThresholdEcdsaActivationChain, chainId: number): string {
  return `${chain}:${String(chainId)}`;
}

function normalizeTargetChainIdForActivationChain(
  chain: ThresholdEcdsaActivationChain,
  value: unknown,
): number | undefined {
  void chain;
  return normalizeOptionalChainIdNumber(value);
}

function resolveBootstrapTargetChainIdKey(args: {
  chain: ThresholdEcdsaActivationChain;
  smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
}): string {
  const explicitChainId = normalizeTargetChainIdForActivationChain(
    args.chain,
    args.smartAccount?.chainId,
  );
  if (typeof explicitChainId === 'number') return toChainIdKey(args.chain, explicitChainId);
  const keygenChainId = normalizeTargetChainIdForActivationChain(
    args.chain,
    args.bootstrap.keygen.chainId,
  );
  if (typeof keygenChainId === 'number') return toChainIdKey(args.chain, keygenChainId);
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

export async function persistThresholdEcdsaBootstrapChainAccount(args: {
  indexedDB: ThresholdEcdsaBootstrapIndexedDbPort;
  nearAccountId: AccountId;
  chain: ThresholdEcdsaActivationChain;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
}): Promise<void> {
  const nearAccountId = toAccountId(String(args.nearAccountId || '').trim());
  const nearContext = await args.indexedDB.clientDB.resolveNearAccountContext(nearAccountId);
  if (!nearContext?.profileId) {
    throw new Error(`[SigningEngine] missing profile/account mapping for ${String(nearAccountId)}`);
  }

  const accountAddress = normalizeOptionalAccountAddress(
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
  const factory = normalizeOptionalString(
    args.smartAccount?.factory || args.bootstrap.keygen.factory,
  );
  const entryPoint = normalizeOptionalString(
    args.smartAccount?.entryPoint || args.bootstrap.keygen.entryPoint,
  );
  const salt = normalizeOptionalString(args.smartAccount?.salt || args.bootstrap.keygen.salt);

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
    deployed: false,
    deploymentTxHash: null,
    lastDeploymentCheckAt: null,
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
    });
  }
}

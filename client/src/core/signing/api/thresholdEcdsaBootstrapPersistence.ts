import type {
  ChainAccountRecord,
  UpsertChainAccountInput,
} from '../../IndexedDBManager/passkeyClientDB';
import type { AccountId } from '../../types/accountIds';
import type {
  ThresholdEcdsaActivationChain,
  ThresholdEcdsaSessionBootstrapResult,
} from '../orchestration/activation';

export type ThresholdEcdsaSmartAccountBootstrapInput = {
  chainId?: string;
  factory?: string;
  entryPoint?: string;
  salt?: string;
  counterfactualAddress?: string;
};

export type ThresholdEcdsaBootstrapIndexedDbPort = {
  clientDB: {
    resolveNearAccountContext: (
      nearAccountId: AccountId,
    ) => Promise<{ profileId: string; sourceChainId: string; sourceAccountAddress: string } | null>;
  };
  upsertChainAccount: (input: UpsertChainAccountInput) => Promise<ChainAccountRecord>;
};

function normalizeOptionalChainId(value: unknown): string | undefined {
  const normalized = String(value || '').trim().toLowerCase();
  return normalized || undefined;
}

function normalizeOptionalAccountAddress(value: unknown): string | undefined {
  const normalized = String(value || '').trim().toLowerCase();
  return normalized || undefined;
}

function normalizeOptionalString(value: unknown): string | undefined {
  const normalized = String(value || '').trim();
  return normalized || undefined;
}

function resolveBootstrapTargetChainId(args: {
  chain: ThresholdEcdsaActivationChain;
  smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
}): string {
  const explicitChainId = normalizeOptionalChainId(args.smartAccount?.chainId);
  if (explicitChainId) return explicitChainId;
  const keygenChainId = normalizeOptionalChainId(args.bootstrap.keygen.chainId);
  if (keygenChainId) return keygenChainId;
  return args.chain === 'evm' ? 'eip155:unknown' : 'tempo:unknown';
}

function deriveMirrorChainDefaults(chain: ThresholdEcdsaActivationChain): {
  chainId: string;
  accountModel: 'erc4337' | 'tempo-native';
} {
  if (chain === 'evm') {
    return {
      chainId: 'tempo:unknown',
      accountModel: 'tempo-native',
    };
  }
  return {
    chainId: 'eip155:unknown',
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
  const nearContext = await args.indexedDB.clientDB.resolveNearAccountContext(args.nearAccountId);
  if (!nearContext?.profileId) {
    throw new Error(
      `[WebAuthnManager] missing profile/account mapping for ${String(args.nearAccountId)}`,
    );
  }

  const accountAddress = normalizeOptionalAccountAddress(
    args.smartAccount?.counterfactualAddress
      || args.bootstrap.keygen.counterfactualAddress
      || args.bootstrap.keygen.ethereumAddress,
  );
  if (!accountAddress) {
    throw new Error(
      '[WebAuthnManager] threshold-ecdsa bootstrap did not provide a counterfactual/account address',
    );
  }

  const chainId = resolveBootstrapTargetChainId({
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
  const salt = normalizeOptionalString(
    args.smartAccount?.salt || args.bootstrap.keygen.salt,
  );

  await args.indexedDB.upsertChainAccount({
    profileId: nearContext.profileId,
    chainId,
    accountAddress,
    accountModel: args.chain === 'evm' ? 'erc4337' : 'tempo-native',
    isPrimary: true,
    ...(factory ? { factory } : {}),
    ...(entryPoint ? { entryPoint } : {}),
    ...(salt ? { salt } : {}),
    counterfactualAddress: accountAddress,
    deployed: false,
  });

  // Provisioning once (tempo or evm) should still leave an "unknown" row for the
  // counterpart chain so first-send deployment gates can resolve the account without
  // forcing an extra WebAuthn bootstrap prompt.
  const mirror = deriveMirrorChainDefaults(args.chain);
  if (mirror.chainId !== chainId) {
    await args.indexedDB.upsertChainAccount({
      profileId: nearContext.profileId,
      chainId: mirror.chainId,
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

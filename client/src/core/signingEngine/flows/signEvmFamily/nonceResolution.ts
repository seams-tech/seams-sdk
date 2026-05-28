import { buildNearAccountRefs } from '@/core/accountData/near/accountRefs';
import { chainFamilyFromNetwork } from '@/core/config/chains';
import {
  toIndexedDbChainTargetKey,
} from '@/core/indexedDB/normalization';
import type { ChainAccountRecord } from '@/core/indexedDB/passkeyClientDB.types';
import { resolveProfileAccountContextFromCandidates } from '@/core/indexedDB/profileAccountProjection';
import { toAccountId } from '@/core/types/accountIds';
import type { SeamsChainConfig, SeamsConfigsReadonly } from '@/core/types/seams';
import type { EvmSigningRequest } from '../../chains/evm/types';
import type { TempoSigningRequest } from '../../chains/tempo/types';
import type { ThresholdEcdsaChainTarget } from '../../interfaces/ecdsaChainTarget';
import type { EvmFamilyAccountMetadataDeps } from './accountAuth';
import { toOptionalEvmAddress } from './addresses';

export type { EvmFamilyAccountMetadataDeps };

export type EvmFamilyNonceNetworkDeps = {
  seamsPasskeyConfigs: SeamsConfigsReadonly;
};

function readOptionalChainId(chain: SeamsChainConfig): number | undefined {
  if (!('chainId' in chain)) return undefined;
  return typeof chain.chainId === 'number' ? chain.chainId : undefined;
}

function isEvmFamilyNetwork(chain: SeamsChainConfig): boolean {
  return String(chainFamilyFromNetwork(chain.network)) === 'evm';
}

function isTempoFamilyNetwork(chain: SeamsChainConfig): boolean {
  return String(chainFamilyFromNetwork(chain.network)) === 'tempo';
}

export function resolveNonceNetworkKey(args: {
  configs: SeamsConfigsReadonly;
  request: EvmSigningRequest | TempoSigningRequest;
}): string {
  const resolved = tryResolveNonceNetworkKey(args);
  if (resolved) return resolved;
  const chainId = args.request.tx.chainId;
  throw new Error(
    `[SigningEngine] unable to resolve nonce network for ${args.request.chain} chainId=${String(chainId)} from configured chains`,
  );
}

export function resolveNonceNetworkKeyForError(args: {
  configs: SeamsConfigsReadonly;
  request: EvmSigningRequest | TempoSigningRequest;
}): string {
  return (
    tryResolveNonceNetworkKey(args) || `${args.request.chain}:${String(args.request.tx.chainId)}`
  );
}

function tryResolveNonceNetworkKey(args: {
  configs: SeamsConfigsReadonly;
  request: EvmSigningRequest | TempoSigningRequest;
}): string | null {
  const chainId = args.request.tx.chainId;
  const matchesByChainId = args.configs.network.chains.filter((chain) => {
    const configured = readOptionalChainId(chain);
    return typeof configured === 'number' && configured === chainId;
  });
  if (!matchesByChainId.length) return null;

  if (args.request.chain === 'tempo') {
    const tempoMatches = matchesByChainId.filter((chain) => isTempoFamilyNetwork(chain));
    if (tempoMatches.length === 1) return tempoMatches[0]!.network;
    if (tempoMatches.length > 1) {
      const candidates = tempoMatches.map((chain) => chain.network).join(', ');
      throw new Error(
        `[SigningEngine] ambiguous nonce network for tempo chainId=${String(args.request.tx.chainId)} across [${candidates}]`,
      );
    }
    return null;
  }

  const evmMatches = matchesByChainId.filter((chain) => isEvmFamilyNetwork(chain));
  if (evmMatches.length === 1) return evmMatches[0]!.network;
  if (evmMatches.length > 1) {
    const candidates = evmMatches.map((chain) => chain.network).join(', ');
    throw new Error(
      `[SigningEngine] ambiguous nonce network for evm chainId=${String(args.request.tx.chainId)} across [${candidates}]`,
    );
  }

  const tempoMatches = matchesByChainId.filter((chain) => isTempoFamilyNetwork(chain));
  if (tempoMatches.length === 1) return tempoMatches[0]!.network;
  if (tempoMatches.length > 1) {
    const candidates = tempoMatches.map((chain) => chain.network).join(', ');
    throw new Error(
      `[SigningEngine] ambiguous nonce network for evm->tempo chainId=${String(args.request.tx.chainId)} across [${candidates}]`,
    );
  }
  return null;
}

export type EvmFamilyManagedNonceSenderIdentity =
  | {
      kind: 'threshold_owner';
      thresholdOwnerAddress: `0x${string}`;
      chainAccountAddress?: never;
    }
  | {
      kind: 'chain_account';
      chainAccountAddress: `0x${string}`;
      thresholdOwnerAddress?: never;
    };

function pickPreferredChainAccountRow(rows: ChainAccountRecord[]): ChainAccountRecord | null {
  if (!rows.length) return null;
  return rows.find((row) => !!row.isPrimary) || rows[0] || null;
}

export function thresholdOwnerNonceSenderIdentity(
  thresholdOwnerAddress: `0x${string}`,
): EvmFamilyManagedNonceSenderIdentity {
  return {
    kind: 'threshold_owner',
    thresholdOwnerAddress,
  };
}

export function chainAccountNonceSenderIdentity(
  chainAccountAddress: `0x${string}`,
): EvmFamilyManagedNonceSenderIdentity {
  return {
    kind: 'chain_account',
    chainAccountAddress,
  };
}

function senderAddressFromIdentity(
  senderIdentity: EvmFamilyManagedNonceSenderIdentity,
): `0x${string}` {
  switch (senderIdentity.kind) {
    case 'threshold_owner':
      return senderIdentity.thresholdOwnerAddress;
    case 'chain_account':
      return senderIdentity.chainAccountAddress;
    default: {
      const _exhaustive: never = senderIdentity;
      return _exhaustive;
    }
  }
}

export async function resolveProfileChainAccountNonceSenderIdentity(args: {
  deps: EvmFamilyAccountMetadataDeps;
  walletId: string;
  chainTarget: ThresholdEcdsaChainTarget;
}): Promise<EvmFamilyManagedNonceSenderIdentity> {
  const walletId = toAccountId(args.walletId);
  const context = await resolveProfileAccountContextFromCandidates(
    args.deps.indexedDB,
    buildNearAccountRefs(walletId),
  );
  if (!context?.profileId) {
    throw new Error(
      `[SigningEngine] unable to resolve profile mapping for managed nonce (${String(walletId)})`,
    );
  }

  const chainIdKey = toIndexedDbChainTargetKey(args.chainTarget);
  const rows = await args.deps.indexedDB
    .listChainAccountsByProfileAndChain(context.profileId, chainIdKey)
    .catch(() => []);
  const selected = pickPreferredChainAccountRow(rows);
  const chainAccountAddress = toOptionalEvmAddress(selected?.accountAddress);
  if (chainAccountAddress) return chainAccountNonceSenderIdentity(chainAccountAddress);

  const contextMappedSender = toOptionalEvmAddress(context.accountRef.accountAddress);
  if (contextMappedSender) return chainAccountNonceSenderIdentity(contextMappedSender);

  throw new Error(
    `[SigningEngine] unable to resolve managed nonce chain account for ${context.profileId} (${chainIdKey})`,
  );
}

export async function resolveManagedNonceSender(args: {
  senderIdentity: EvmFamilyManagedNonceSenderIdentity;
}): Promise<`0x${string}`> {
  return senderAddressFromIdentity(args.senderIdentity);
}

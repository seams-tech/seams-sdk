import { buildNearAccountRefs } from '@/core/accountData/near/accountRefs';
import { chainFamilyFromNetwork } from '@/core/config/chains';
import {
  normalizeIndexedDbAccountModel,
  toIndexedDbChainTargetKey,
} from '@/core/indexedDB/normalization';
import type { ChainAccountRecord } from '@/core/indexedDB/passkeyClientDB.types';
import { resolveProfileAccountContextFromCandidates } from '@/core/indexedDB/profileAccountProjection';
import { toAccountId } from '@/core/types/accountIds';
import type { SeamsChainConfig, SeamsConfigsReadonly } from '@/core/types/seams';
import type { EvmSigningRequest } from '../../chains/evm/types';
import type { TempoSigningRequest } from '../../chains/tempo/types';
import type { EvmFamilyAccountMetadataDeps } from './accountAuth';
import { deriveSmartAccountDeploymentTargetFromSigningRequest } from './smartAccountDeploymentState';
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

function pickPreferredSmartAccountRow(args: {
  rows: ChainAccountRecord[];
  accountModelCandidates: readonly string[];
}): ChainAccountRecord | null {
  const modelSet = new Set(args.accountModelCandidates.map(normalizeIndexedDbAccountModel));
  const filtered = args.rows.filter((row) =>
    modelSet.has(normalizeIndexedDbAccountModel(row.accountModel)),
  );
  const source = filtered.length ? filtered : args.rows;
  if (!source.length) return null;
  return source.find((row) => !!row.isPrimary) || source[0] || null;
}

export async function resolveManagedNonceSender(args: {
  deps: EvmFamilyAccountMetadataDeps;
  walletId: string;
  request: EvmSigningRequest | TempoSigningRequest;
  senderHint?: `0x${string}`;
}): Promise<`0x${string}`> {
  if (args.senderHint) return args.senderHint;

  const walletId = toAccountId(args.walletId);
  const context = await resolveProfileAccountContextFromCandidates(
    args.deps.indexedDB.clientDB,
    buildNearAccountRefs(walletId),
  );
  if (!context?.profileId) {
    throw new Error(
      `[SigningEngine] unable to resolve profile mapping for managed ${args.request.chain.toUpperCase()} nonce (${String(walletId)})`,
    );
  }

  const target = deriveSmartAccountDeploymentTargetFromSigningRequest(args.request);
  for (const chainTarget of target.chainTargetCandidates) {
    const chainIdKey = toIndexedDbChainTargetKey(chainTarget);
    const rows = await args.deps.indexedDB.clientDB
      .listChainAccountsByProfileAndChain(context.profileId, chainIdKey)
      .catch(() => []);
    if (!rows.length) continue;
    const selected = pickPreferredSmartAccountRow({
      rows,
      accountModelCandidates: target.accountModelCandidates,
    });
    const sender = toOptionalEvmAddress(selected?.accountAddress);
    if (sender) return sender;
  }

  const contextMappedSender = toOptionalEvmAddress(context.accountRef.accountAddress);
  if (contextMappedSender) return contextMappedSender;

  throw new Error(
    `[SigningEngine] unable to resolve managed ${args.request.chain.toUpperCase()} nonce sender (no usable sender row for ${context.profileId})`,
  );
}

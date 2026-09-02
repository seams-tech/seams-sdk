import { chainFamilyFromNetwork } from '@/core/config/chains';
import type { AccountId } from '@/core/types/accountIds';
import type {
  SeamsChainConfig,
  SeamsEvmChainNetwork,
  SeamsNearChainNetwork,
  SeamsTempoChainNetwork,
} from '@/core/types/seams';
import { parseWalletId, type WalletId } from '@shared/utils/domainIds';
import type {
  EvmEip155ChainTarget,
  TempoChainTarget,
  ThresholdEcdsaChainTarget,
} from '@/core/platform/types';

export type { WalletId } from '@shared/utils/domainIds';
export type {
  EvmEip155ChainTarget,
  TempoChainTarget,
  ThresholdEcdsaChainTarget,
} from '@/core/platform/types';

export type NearAccountRef =
  | { kind: 'named'; accountId: AccountId }
  | { kind: 'implicit'; accountId: AccountId };

/**
 * What `thresholdEcdsaChainTargetFromConfig` actually needs: the network slug
 * plus — for the ECDSA families — a chain id. `rpcUrl`/`explorerUrl` stay
 * accepted (so a resolved `SeamsChainConfig` is still assignable) but unread.
 */
export type ThresholdEcdsaChainTargetConfigInput =
  | { network: SeamsNearChainNetwork; rpcUrl?: string; explorerUrl?: string }
  | { network: SeamsTempoChainNetwork; chainId: number; rpcUrl?: string; explorerUrl?: string }
  | { network: SeamsEvmChainNetwork; chainId: number; rpcUrl?: string; explorerUrl?: string };

export type WalletSessionRef = {
  walletId: WalletId;
  walletSessionUserId: string;
};

export type EcdsaCommandSubject = {
  walletSession: WalletSessionRef;
  subjectId?: never;
};

export type NearCommandSubject = {
  walletSession: WalletSessionRef;
  nearAccount: NearAccountRef;
};

type BoundaryEcdsaChainFamily = 'evm' | 'tempo';

function nonEmptyString(value: unknown): string | null {
  const normalized = String(value ?? '').trim();
  return normalized ? normalized : null;
}

function requireNonEmptyString(value: unknown, field: string): string {
  const normalized = nonEmptyString(value);
  if (!normalized) throw new Error(`[threshold-ecdsa] missing ${field}`);
  return normalized;
}

function normalizePositiveSafeInteger(value: unknown, field: string): number {
  const normalized = Number(value);
  if (!Number.isSafeInteger(normalized) || normalized <= 0) {
    throw new Error(`[threshold-ecdsa] ${field} must be a positive safe integer`);
  }
  return normalized;
}

function defaultNetworkSlug(kind: BoundaryEcdsaChainFamily, chainId: number): string {
  return kind === 'tempo' ? `tempo-${chainId}` : `evm-${chainId}`;
}

export function toWalletId(value: unknown): WalletId {
  const parsed = parseWalletId(value);
  if (!parsed.ok) {
    throw new Error(parsed.error.message);
  }
  return parsed.value;
}

export function walletIdFromWalletProfile(args: { walletId: unknown }): WalletId {
  return toWalletId(args.walletId);
}

/**
 * Builds the exact wallet-session reference an operation authorizes.
 *
 * `walletSessionUserId` is a wallet-scoped audit subject and defaults to the
 * wallet id — which is what every application call site uses. It is never a
 * provider subject (`google:<sub>`); provider-scoped custody lanes carry their
 * own `providerSubjectId` argument. See
 * docs/refactor-36-narrow-lifecycle-types.md for the regression that rule
 * encodes.
 */
export function walletSessionRefFromSession(value: {
  walletId?: unknown;
  walletSessionUserId?: unknown;
  userId?: unknown;
}): WalletSessionRef {
  if (!('walletId' in value)) {
    throw new Error('[wallet-session] missing wallet id');
  }
  const walletId = toWalletId(value.walletId);
  const walletSessionUserId =
    nonEmptyString(value.walletSessionUserId) || nonEmptyString(value.userId) || String(walletId);
  return {
    walletId,
    walletSessionUserId,
  };
}

export function nearAccountRefFromAccountId(value: unknown): NearAccountRef {
  const accountId = requireNonEmptyString(value, 'NEAR account id') as AccountId;
  return accountId.length === 64 && /^[0-9a-f]+$/i.test(accountId)
    ? { kind: 'implicit', accountId }
    : { kind: 'named', accountId };
}

export function thresholdEcdsaChainTargetKey(target: ThresholdEcdsaChainTarget): string {
  if (target.kind === 'evm') return `evm:eip155:${target.chainId}`;
  return `tempo:${target.chainId}`;
}

export function thresholdEcdsaChainTargetsEqual(
  left: ThresholdEcdsaChainTarget,
  right: ThresholdEcdsaChainTarget,
): boolean {
  return thresholdEcdsaChainTargetKey(left) === thresholdEcdsaChainTargetKey(right);
}

export function thresholdEcdsaChainTargetFromChainFamily(args: {
  chain: 'tempo';
  chainId: unknown;
  networkSlug?: unknown;
}): TempoChainTarget;
export function thresholdEcdsaChainTargetFromChainFamily(args: {
  chain: 'evm';
  chainId: unknown;
  networkSlug?: unknown;
}): EvmEip155ChainTarget;
export function thresholdEcdsaChainTargetFromChainFamily(args: {
  chain: BoundaryEcdsaChainFamily;
  chainId: unknown;
  networkSlug?: unknown;
}): ThresholdEcdsaChainTarget;
export function thresholdEcdsaChainTargetFromChainFamily(args: {
  chain: BoundaryEcdsaChainFamily;
  chainId: unknown;
  networkSlug?: unknown;
}): ThresholdEcdsaChainTarget {
  const chainId = normalizePositiveSafeInteger(args.chainId, 'chainId');
  const networkSlug = nonEmptyString(args.networkSlug) || defaultNetworkSlug(args.chain, chainId);
  if (args.chain === 'tempo') {
    return { kind: 'tempo', chainId, networkSlug };
  }
  return { kind: 'evm', namespace: 'eip155', chainId, networkSlug };
}

/**
 * Builds a concrete ECDSA chain target from a chain descriptor.
 *
 * `rpcUrl` and `explorerUrl` are accepted so a full `SeamsChainConfig` stays
 * assignable, but they are ignored: the RPC endpoint is resolved at execution
 * time from `configs.network.chains` by target key (`resolveEvmFamilyRpcUrl`).
 * Prefer `seams.chainTarget(selector)`, which can only name a configured chain.
 */
export function thresholdEcdsaChainTargetFromConfig(
  chain: ThresholdEcdsaChainTargetConfigInput,
): ThresholdEcdsaChainTarget {
  const family = chainFamilyFromNetwork(chain.network);
  if (family !== 'evm' && family !== 'tempo') {
    throw new Error(`[threshold-ecdsa] ${chain.network} is not an ECDSA signing target`);
  }
  return thresholdEcdsaChainTargetFromChainFamily({
    chain: family,
    chainId: (chain as { chainId?: unknown }).chainId,
    networkSlug: chain.network,
  });
}

export function configuredThresholdEcdsaChainTargets(
  chains: readonly SeamsChainConfig[],
): ThresholdEcdsaChainTarget[] {
  const targets: ThresholdEcdsaChainTarget[] = [];
  const seen = new Set<string>();
  for (const chain of chains) {
    const family = chainFamilyFromNetwork(chain.network);
    if (family !== 'evm' && family !== 'tempo') continue;
    const target = thresholdEcdsaChainTargetFromConfig(chain);
    const key = thresholdEcdsaChainTargetKey(target);
    if (seen.has(key)) continue;
    seen.add(key);
    targets.push(target);
  }
  return targets;
}

export function thresholdEcdsaChainTargetFromRequest(args: {
  chain?: unknown;
  kind?: unknown;
  namespace?: unknown;
  chainId?: unknown;
  networkSlug?: unknown;
}): ThresholdEcdsaChainTarget {
  const rawKind = String(args.kind ?? args.chain ?? '')
    .trim()
    .toLowerCase();
  if (rawKind !== 'evm' && rawKind !== 'tempo') {
    throw new Error('[threshold-ecdsa] ECDSA request target requires chain kind evm or tempo');
  }
  if (rawKind === 'evm') {
    const namespace = String(args.namespace ?? 'eip155')
      .trim()
      .toLowerCase();
    if (namespace !== 'eip155') {
      throw new Error('[threshold-ecdsa] EVM chain target namespace must be eip155');
    }
  }
  return thresholdEcdsaChainTargetFromChainFamily({
    chain: rawKind,
    chainId: args.chainId,
    networkSlug: args.networkSlug,
  });
}

export function thresholdEcdsaChainTargetFromConfiguredRequest(args: {
  chain: BoundaryEcdsaChainFamily;
  chains: readonly SeamsChainConfig[];
  explicitChainId?: unknown;
  networkSlug?: unknown;
}): ThresholdEcdsaChainTarget {
  const explicitChainId =
    args.explicitChainId == null
      ? null
      : normalizePositiveSafeInteger(args.explicitChainId, 'chainId');
  const family = args.chain;
  const matchingConfig = args.chains.find((chain) => {
    if (chainFamilyFromNetwork(chain.network) !== family) return false;
    if (explicitChainId == null) return true;
    return Number((chain as { chainId?: unknown }).chainId) === explicitChainId;
  });
  if (matchingConfig) {
    const target = thresholdEcdsaChainTargetFromConfig(matchingConfig);
    if (explicitChainId == null || target.chainId === explicitChainId) return target;
  }
  if (explicitChainId == null) {
    throw new Error(
      `[threshold-ecdsa] missing configured ${family} chainId for concrete ECDSA target`,
    );
  }
  return thresholdEcdsaChainTargetFromChainFamily({
    chain: family,
    chainId: explicitChainId,
    networkSlug: args.networkSlug,
  });
}

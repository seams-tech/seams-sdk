import { isObject as isObjectLoose, toOptionalTrimmedString } from '@shared/utils/validation';

export type SmartAccountChainTarget =
  | {
      kind: 'evm';
      namespace: 'eip155';
      chainId: number;
      networkSlug: string;
    }
  | {
      kind: 'tempo';
      chainId: number;
      networkSlug: string;
    };

type SmartAccountChainKind = SmartAccountChainTarget['kind'];

function normalizePositiveSafeInteger(value: unknown): number | null {
  const normalized = Math.floor(Number(value));
  return Number.isSafeInteger(normalized) && normalized > 0 ? normalized : null;
}

function defaultNetworkSlug(kind: SmartAccountChainKind, chainId: number): string {
  return kind === 'tempo' ? `tempo-${chainId}` : `evm-${chainId}`;
}

export function smartAccountChainTargetFromParts(args: {
  chain: unknown;
  chainId: unknown;
  namespace?: unknown;
  networkSlug?: unknown;
}): SmartAccountChainTarget | null {
  const kind = toOptionalTrimmedString(args.chain)?.toLowerCase();
  if (kind !== 'evm' && kind !== 'tempo') return null;
  const chainId = normalizePositiveSafeInteger(args.chainId);
  if (!chainId) return null;
  const networkSlug = toOptionalTrimmedString(args.networkSlug) || defaultNetworkSlug(kind, chainId);
  if (kind === 'tempo') return { kind: 'tempo', chainId, networkSlug };
  const namespace = toOptionalTrimmedString(args.namespace)?.toLowerCase() || 'eip155';
  if (namespace !== 'eip155') return null;
  return { kind: 'evm', namespace: 'eip155', chainId, networkSlug };
}

export function smartAccountChainTargetFromValue(value: unknown): SmartAccountChainTarget | null {
  if (!isObjectLoose(value)) return null;
  return smartAccountChainTargetFromParts({
    chain: value.kind ?? value.chain,
    chainId: value.chainId ?? value.chain_id,
    namespace: value.namespace,
    networkSlug: value.networkSlug ?? value.network_slug,
  });
}

export function smartAccountChainTargetKey(target: SmartAccountChainTarget): string {
  if (target.kind === 'evm') return `evm:eip155:${target.chainId}`;
  return `tempo:${target.chainId}`;
}

export function smartAccountModelForTarget(
  target: SmartAccountChainTarget,
  preferred?: unknown,
): 'erc4337' | 'tempo-native' {
  const normalized = toOptionalTrimmedString(preferred);
  if (normalized === 'erc4337' || normalized === 'tempo-native') return normalized;
  return target.kind === 'evm' ? 'erc4337' : 'tempo-native';
}

export type ThresholdEcdsaChainTarget =
  | {
      kind: 'evm';
      namespace: 'eip155';
      chainId: number;
      networkSlug?: string;
    }
  | {
      kind: 'tempo';
      chainId: number;
      networkSlug?: string;
    };

function positiveSafeInteger(value: unknown): number | null {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0 ? value : null;
}

function nonEmptyString(value: unknown): string | undefined {
  const text = String(value ?? '').trim();
  return text || undefined;
}

export function thresholdEcdsaChainTargetFromValue(
  value: unknown,
): ThresholdEcdsaChainTarget | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  const kind = String(record.kind || '').trim();
  const chainId = positiveSafeInteger(record.chainId);
  if (!chainId) return null;
  if (kind === 'evm') {
    if (String(record.namespace || '').trim() !== 'eip155') return null;
    const networkSlug = nonEmptyString(record.networkSlug);
    return {
      kind: 'evm',
      namespace: 'eip155',
      chainId,
      ...(networkSlug ? { networkSlug } : {}),
    };
  }
  if (kind === 'tempo') {
    const networkSlug = nonEmptyString(record.networkSlug);
    return {
      kind: 'tempo',
      chainId,
      ...(networkSlug ? { networkSlug } : {}),
    };
  }
  return null;
}

export function thresholdEcdsaChainTargetKey(target: ThresholdEcdsaChainTarget): string {
  return target.kind === 'evm' ? `evm:eip155:${target.chainId}` : `tempo:${target.chainId}`;
}

export function thresholdEcdsaChainTargetsEqual(
  left: ThresholdEcdsaChainTarget,
  right: ThresholdEcdsaChainTarget,
): boolean {
  return thresholdEcdsaChainTargetKey(left) === thresholdEcdsaChainTargetKey(right);
}

export function thresholdEcdsaChainTargetsShareEvmFamilyAddress(
  left: ThresholdEcdsaChainTarget,
  right: ThresholdEcdsaChainTarget,
): boolean {
  return isEvmFamilyAddressTarget(left) && isEvmFamilyAddressTarget(right);
}

function isEvmFamilyAddressTarget(target: ThresholdEcdsaChainTarget): boolean {
  return target.kind === 'evm' || target.kind === 'tempo';
}

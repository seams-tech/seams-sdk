import {
  chainFamilyFromNetwork,
  isEvmChainNetwork,
  isTempoChainNetwork,
} from '@/core/config/chains';
import type { AccountId } from '@/core/types/accountIds';
import type { SeamsChainConfig, SeamsChainNetwork } from '@/core/types/seams';

export type WalletId = string & { readonly __brand: 'WalletId' };

export type WalletSubjectId = string & { readonly __brand: 'WalletSubjectId' };

export type NearAccountRef =
  | { kind: 'named'; accountId: AccountId }
  | { kind: 'implicit'; accountId: AccountId };

export type WalletSessionRef = {
  walletId: WalletId;
  walletSessionUserId: string;
};

export type EcdsaCommandSubject = {
  walletSession: WalletSessionRef;
  subjectId: WalletSubjectId;
};

export type NearCommandSubject = {
  walletSession: WalletSessionRef;
  nearAccount: NearAccountRef;
};

export type EvmEip155ChainTarget = {
  kind: 'evm';
  namespace: 'eip155';
  chainId: number;
  // Display/config metadata only. Canonical equality must ignore this field.
  networkSlug: string;
};

export type TempoChainTarget = {
  kind: 'tempo';
  chainId: number;
  // Display/config metadata only. Canonical equality must ignore this field.
  networkSlug: string;
};

export type ThresholdEcdsaChainTarget = EvmEip155ChainTarget | TempoChainTarget;

export type ThresholdEcdsaSessionRecordKey = {
  subjectId: WalletSubjectId;
  authMethod: 'email_otp' | 'passkey';
  curve: 'ecdsa';
  chainTarget: ThresholdEcdsaChainTarget;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  walletSigningSessionId: string;
  thresholdSessionId: string;
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

export function toWalletSubjectId(value: unknown): WalletSubjectId {
  return requireNonEmptyString(value, 'wallet subject id') as WalletSubjectId;
}

export function toWalletId(value: unknown): WalletId {
  return requireNonEmptyString(value, 'wallet id') as WalletId;
}

export function walletSubjectIdFromAccountContext(args: {
  subjectId?: unknown;
  walletId?: unknown;
  profileId?: unknown;
}): WalletSubjectId {
  const subjectId =
    nonEmptyString(args.subjectId) ||
    nonEmptyString(args.walletId) ||
    nonEmptyString(args.profileId);
  if (!subjectId) {
    throw new Error('[threshold-ecdsa] missing protocol-neutral wallet subject id');
  }
  return subjectId as WalletSubjectId;
}

export function walletSubjectIdFromWalletProfile(args: {
  subjectId?: unknown;
  walletId?: unknown;
  profileId?: unknown;
}): WalletSubjectId {
  return walletSubjectIdFromAccountContext(args);
}

export function walletIdFromSessionValue(value: unknown): WalletId {
  if (typeof value === 'object' && value !== null && 'walletId' in value) {
    return toWalletId((value as { walletId?: unknown }).walletId);
  }
  if (typeof value === 'object' && value !== null) {
    throw new Error('[wallet-session] missing wallet id');
  }
  return toWalletId(value);
}

export function walletSessionRefFromSession(value: {
  walletId?: unknown;
  walletSessionUserId?: unknown;
  userId?: unknown;
}): WalletSessionRef {
  const walletSessionUserId =
    nonEmptyString(value.walletSessionUserId) || nonEmptyString(value.userId);
  if (!walletSessionUserId) {
    throw new Error('[wallet-session] missing wallet session user id');
  }
  return {
    walletId: walletIdFromSessionValue(value),
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

export function thresholdEcdsaChainTargetFromConfig(
  chain: SeamsChainConfig,
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
  const rawKind = String(args.kind ?? args.chain ?? '').trim().toLowerCase();
  if (rawKind !== 'evm' && rawKind !== 'tempo') {
    throw new Error('[threshold-ecdsa] ECDSA request target requires chain kind evm or tempo');
  }
  if (rawKind === 'evm') {
    const namespace = String(args.namespace ?? 'eip155').trim().toLowerCase();
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

export function thresholdEcdsaChainTargetFromNetwork(args: {
  network: SeamsChainNetwork;
  chainId: unknown;
}): ThresholdEcdsaChainTarget {
  if (isTempoChainNetwork(args.network)) {
    return thresholdEcdsaChainTargetFromChainFamily({
      chain: 'tempo',
      chainId: args.chainId,
      networkSlug: args.network,
    });
  }
  if (isEvmChainNetwork(args.network)) {
    return thresholdEcdsaChainTargetFromChainFamily({
      chain: 'evm',
      chainId: args.chainId,
      networkSlug: args.network,
    });
  }
  throw new Error(`[threshold-ecdsa] ${args.network} is not an ECDSA chain target`);
}

function laneKeyPart(value: unknown): string {
  return encodeURIComponent(requireNonEmptyString(value, 'ECDSA lane key part'));
}

export function thresholdEcdsaLaneKey(lane: ThresholdEcdsaSessionRecordKey): string {
  return [
    laneKeyPart(lane.subjectId),
    laneKeyPart(lane.ecdsaThresholdKeyId),
    laneKeyPart(lane.authMethod),
    'ecdsa',
    laneKeyPart(thresholdEcdsaChainTargetKey(lane.chainTarget)),
    laneKeyPart(lane.signingRootId),
    laneKeyPart(lane.signingRootVersion),
    laneKeyPart(lane.walletSigningSessionId),
    laneKeyPart(lane.thresholdSessionId),
  ].join(':');
}

export function thresholdEcdsaSessionRecordKeysEqual(
  left: ThresholdEcdsaSessionRecordKey,
  right: ThresholdEcdsaSessionRecordKey,
): boolean {
  return thresholdEcdsaLaneKey(left) === thresholdEcdsaLaneKey(right);
}

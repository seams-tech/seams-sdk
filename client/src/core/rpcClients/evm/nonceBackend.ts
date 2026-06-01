import { chainFamilyFromNetwork } from '@/core/config/chains';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  thresholdEcdsaChainTargetFromRequest,
  type ThresholdEcdsaChainTarget,
  toWalletId,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { SeamsChainConfig } from '@/core/types/seams';

export type EvmNonceChain = 'evm' | 'tempo';

export type ReserveNonceInput = {
  chainTarget: ThresholdEcdsaChainTarget;
  subjectId: WalletId;
  sender: `0x${string}`;
  nonceKey?: bigint;
};

export type ReserveNonceBoundaryInput = {
  chain: EvmNonceChain;
  networkKey: string;
  chainId: number;
  sender: `0x${string}`;
  nonceKey?: bigint;
  walletId: string;
};

export type ManagedNonceReservationSnapshot = {
  chainTarget: ThresholdEcdsaChainTarget;
  subjectId: WalletId;
  sender: `0x${string}`;
  nonceKey?: string;
  nonce: string;
  leaseId: string;
  operationId: string;
  operationFingerprint: string;
  reservedAtMs?: number;
  expiresAtMs?: number;
};

export type ManagedNonceReservationSnapshotInput = Omit<
  ManagedNonceReservationSnapshot,
  'leaseId' | 'operationId' | 'operationFingerprint' | 'subjectId'
> & {
  leaseId?: string;
  operationId?: string;
  operationFingerprint?: string;
  subjectId?: string;
  chain?: EvmNonceChain;
  networkKey?: string;
  chainId?: number;
  walletId?: string;
};

export type ManagedNonceReservation = ReserveNonceInput & {
  nonce: bigint;
  leaseId: string;
  operationId: string;
  operationFingerprint: string;
  reservedAtMs?: number;
  expiresAtMs?: number;
};

export interface EvmNonceBackend {
  fetchChainNonce(input: ReserveNonceInput): Promise<bigint>;
}

export type NonceLaneStatus = {
  chainNextNonce: bigint;
  unresolvedInFlightNonces: bigint[];
  blocked: boolean;
  blockedNonce?: bigint;
};

export type FetchChainNoncePort = (input: ReserveNonceInput) => Promise<bigint>;

export type CreateEvmNonceBackendWithFetcherArgs = {
  fetchChainNonce: FetchChainNoncePort;
};

export type CreateEvmNonceBackendArgs = {
  chains: readonly SeamsChainConfig[];
  fetchImpl?: typeof fetch;
};

type ChainWithChainId = Extract<SeamsChainConfig, { chainId: number }>;

export function toManagedNonceReservationSnapshot(
  input: ManagedNonceReservation,
): ManagedNonceReservationSnapshot {
  const subjectId = toWalletId(input.subjectId);
  const leaseId = normalizeRequiredString(input.leaseId, 'leaseId');
  const operationId = normalizeRequiredString(input.operationId, 'operationId');
  const operationFingerprint = normalizeRequiredString(
    input.operationFingerprint,
    'operationFingerprint',
  );
  const snapshot: ManagedNonceReservationSnapshot = {
    chainTarget: input.chainTarget,
    subjectId,
    sender: normalizeSender(input.sender),
    nonce: normalizeBigint(input.nonce, 'nonce').toString(),
    leaseId,
    operationId,
    operationFingerprint,
  };

  if (input.nonceKey != null) {
    snapshot.nonceKey = normalizeBigint(input.nonceKey, 'nonceKey').toString();
  }

  if (Number.isSafeInteger(input.reservedAtMs)) {
    snapshot.reservedAtMs = input.reservedAtMs;
  }
  if (Number.isSafeInteger(input.expiresAtMs)) {
    snapshot.expiresAtMs = input.expiresAtMs;
  }

  return snapshot;
}

export function fromManagedNonceReservationSnapshot(
  snapshot: ManagedNonceReservationSnapshotInput,
): ManagedNonceReservation {
  if (!snapshot || typeof snapshot !== 'object') {
    throw new Error('[evmNonceBackend] invalid managed nonce snapshot: object');
  }
  const chainTarget = parseManagedNonceSnapshotChainTarget(snapshot);
  const subjectId = toWalletId(snapshot.subjectId ?? snapshot.walletId);
  const sender = normalizeSender(snapshot.sender);
  const nonce = normalizeBigint(snapshot.nonce, 'nonce');
  const parsedNonceKey =
    snapshot.nonceKey == null ? undefined : normalizeBigint(snapshot.nonceKey, 'nonceKey');
  const leaseId = normalizeRequiredString(snapshot.leaseId, 'leaseId');
  const operationId = normalizeRequiredString(snapshot.operationId, 'operationId');
  const operationFingerprint = normalizeRequiredString(
    snapshot.operationFingerprint,
    'operationFingerprint',
  );
  const reservedAtMs = normalizeOptionalSafeInteger(snapshot.reservedAtMs);
  const expiresAtMs = normalizeOptionalSafeInteger(snapshot.expiresAtMs);

  return {
    chainTarget,
    subjectId,
    sender,
    ...(parsedNonceKey != null ? { nonceKey: parsedNonceKey } : {}),
    nonce,
    leaseId,
    operationId,
    operationFingerprint,
    ...(reservedAtMs != null ? { reservedAtMs } : {}),
    ...(expiresAtMs != null ? { expiresAtMs } : {}),
  };
}

export function reserveNonceInputFromBoundary(input: ReserveNonceBoundaryInput): ReserveNonceInput {
  return {
    chainTarget: thresholdEcdsaChainTargetFromChainFamily({
      chain: input.chain,
      chainId: input.chainId,
      networkSlug: input.networkKey,
    }),
    subjectId: toWalletId(input.walletId),
    sender: normalizeSender(input.sender),
    ...(input.nonceKey != null ? { nonceKey: normalizeBigint(input.nonceKey, 'nonceKey') } : {}),
  };
}

type NormalizedInput = {
  chain: EvmNonceChain;
  networkKey: string;
  chainId: number;
  sender: `0x${string}`;
  nonceKey: bigint;
  walletId?: string;
};

const DEFAULT_RPC_TIMEOUT_MS = 15_000;

export function createEvmNonceBackendWithFetcher(
  args: CreateEvmNonceBackendWithFetcherArgs,
): EvmNonceBackend {
  return {
    async fetchChainNonce(input) {
      const normalized = normalizeInput(input);
      return await args.fetchChainNonce(normalized);
    },
  };
}

export function createEvmNonceBackend(args: CreateEvmNonceBackendArgs): EvmNonceBackend {
  const fetchImpl = args.fetchImpl || fetch.bind(globalThis);
  return createEvmNonceBackendWithFetcher({
    fetchChainNonce: async (input) =>
      await fetchChainNonceFromRpc({
        chains: args.chains,
        input,
        fetchImpl,
      }),
  });
}

async function fetchChainNonceFromRpc(args: {
  chains: readonly SeamsChainConfig[];
  input: ReserveNonceInput;
  fetchImpl: typeof fetch;
}): Promise<bigint> {
  const rpcUrl = resolveRpcUrlForInput(args.chains, args.input);
  const timeout = withTimeoutAbort(DEFAULT_RPC_TIMEOUT_MS);
  try {
    const response = await args.fetchImpl(rpcUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 'evm-nonce-backend',
        method: 'eth_getTransactionCount',
        params: [args.input.sender, 'pending'],
      }),
      signal: timeout.signal,
    });
    if (!response.ok) {
      throw new Error(`[evmNonceBackend] RPC returned HTTP ${response.status}`);
    }
    const payload = (await response.json().catch(() => null)) as {
      result?: unknown;
      error?: { code?: unknown; message?: unknown };
    } | null;
    if (!payload) {
      throw new Error('[evmNonceBackend] RPC returned invalid JSON');
    }
    if (payload.error) {
      const code = typeof payload.error.code === 'number' ? payload.error.code : 'unknown';
      const message = String(payload.error.message || 'unknown error');
      throw new Error(
        `[evmNonceBackend] eth_getTransactionCount failed (${String(code)}): ${message}`,
      );
    }
    return parseRpcHexQuantity(payload.result, 'eth_getTransactionCount');
  } finally {
    timeout.clear();
  }
}

function resolveRpcUrlForInput(
  chains: readonly SeamsChainConfig[],
  input: ReserveNonceInput,
): string {
  const requestedChain = input.chainTarget.kind;
  const targetChainId = input.chainTarget.chainId;
  const networkKey = String(input.chainTarget.networkSlug || '')
    .trim()
    .toLowerCase();
  const byChainId = (source: readonly SeamsChainConfig[]): SeamsChainConfig[] =>
    source.filter((chain) => {
      const chainId = getOptionalConfigChainId(chain);
      return typeof chainId === 'number' && chainId === targetChainId;
    });
  const byNetworkKey = (source: readonly SeamsChainConfig[]): SeamsChainConfig[] =>
    source.filter(
      (chain) =>
        String(chain.network || '')
          .trim()
          .toLowerCase() === networkKey,
    );

  const supportedChains = chains.filter((chain) => isSupportedNonceRoutingChain(chain));
  if (!supportedChains.length) {
    throw new Error('[evmNonceBackend] missing RPC config for nonce-enabled chains');
  }

  const networkMatches = byNetworkKey(supportedChains);
  if (networkMatches.length === 1) {
    const only = networkMatches[0];
    assertChainSupportsRequestedRoute({
      chain: only,
      requestedChain,
      networkKey: input.chainTarget.networkSlug,
      chainId: targetChainId,
    });
    assertConfiguredChainIdMatchesInput({
      chain: only,
      chainId: targetChainId,
      networkKey: input.chainTarget.networkSlug,
    });
    return mustTrimmedRpcUrl(only.rpcUrl, only.network);
  }
  if (networkMatches.length > 1) {
    const chainIdMatched = byChainId(networkMatches).filter((chain) =>
      isChainCompatibleWithRequestChain(chain, requestedChain),
    );
    if (chainIdMatched.length === 1) {
      const only = chainIdMatched[0];
      return mustTrimmedRpcUrl(only.rpcUrl, only.network);
    }
    throw new Error(
      `[evmNonceBackend] ambiguous networkKey mapping for ${input.chainTarget.networkSlug} (chainId=${String(targetChainId)})`,
    );
  }

  const chainIdMatches = byChainId(supportedChains);
  const compatibleMatches = chainIdMatches.filter((chain) =>
    isChainCompatibleWithRequestChain(chain, requestedChain),
  );
  if (compatibleMatches.length === 1) {
    const only = compatibleMatches[0];
    return mustTrimmedRpcUrl(only.rpcUrl, only.network);
  }
  if (compatibleMatches.length > 1) {
    const candidates = compatibleMatches
      .map((chain) => String(chain.network || '').trim())
      .join(', ');
    throw new Error(
      `[evmNonceBackend] ambiguous chainId routing for ${requestedChain} chainId=${String(targetChainId)} across [${candidates}]`,
    );
  }
  if (chainIdMatches.length > 0) {
    const families = Array.from(
      new Set(chainIdMatches.map((chain) => chainFamilyFromNetwork(chain.network))),
    );
    throw new Error(
      `[evmNonceBackend] chainId=${String(targetChainId)} is configured for [${families.join(', ')}] but is incompatible with ${requestedChain} routing`,
    );
  }

  throw new Error(
    `[evmNonceBackend] unable to resolve RPC URL for ${requestedChain} ${input.chainTarget.networkSlug} (chainId=${String(targetChainId)})`,
  );
}

function isSupportedNonceRoutingChain(chain: SeamsChainConfig): boolean {
  const family = chainFamilyFromNetwork(chain.network);
  return family === 'evm' || family === 'tempo';
}

function isChainCompatibleWithRequestChain(
  chain: SeamsChainConfig,
  requestedChain: EvmNonceChain,
): boolean {
  const family = chainFamilyFromNetwork(chain.network);
  if (requestedChain === 'tempo') {
    return family === 'tempo';
  }
  // EVM tx format can target tempo-configured chains (e.g. chainId 42431).
  return family === 'evm' || family === 'tempo';
}

function assertConfiguredChainIdMatchesInput(args: {
  chain: SeamsChainConfig;
  chainId: number;
  networkKey: string;
}): void {
  const configuredChainId = getOptionalConfigChainId(args.chain);
  if (typeof configuredChainId !== 'number') {
    throw new Error(
      `[evmNonceBackend] configured network ${args.chain.network} is missing numeric chainId`,
    );
  }
  if (configuredChainId !== args.chainId) {
    throw new Error(
      `[evmNonceBackend] chainId mismatch for network ${args.networkKey}: expected ${configuredChainId}, received ${String(args.chainId)}`,
    );
  }
}

function assertChainSupportsRequestedRoute(args: {
  chain: SeamsChainConfig;
  requestedChain: EvmNonceChain;
  networkKey: string;
  chainId: number;
}): void {
  if (isChainCompatibleWithRequestChain(args.chain, args.requestedChain)) {
    return;
  }
  const resolvedFamily = chainFamilyFromNetwork(args.chain.network);
  throw new Error(
    `[evmNonceBackend] network ${args.networkKey} (family=${resolvedFamily}) is incompatible with ${args.requestedChain} request (chainId=${String(args.chainId)})`,
  );
}

function getOptionalConfigChainId(chain: SeamsChainConfig): number | undefined {
  return isChainWithChainId(chain) ? chain.chainId : undefined;
}

function isChainWithChainId(chain: SeamsChainConfig): chain is ChainWithChainId {
  return chainFamilyFromNetwork(chain.network) !== 'near';
}

function withTimeoutAbort(timeoutMs: number): { signal: AbortSignal; clear: () => void } {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  return {
    signal: controller.signal,
    clear: () => clearTimeout(timeoutId),
  };
}

function mustTrimmedRpcUrl(rpcUrl: string, network: string): string {
  const trimmed = String(rpcUrl || '').trim();
  if (!trimmed) {
    throw new Error(`[evmNonceBackend] missing rpcUrl for ${network}`);
  }
  return trimmed;
}

function normalizeInput(input: ReserveNonceInput): NormalizedInput {
  const chain = input.chainTarget.kind;
  if (chain !== 'evm' && chain !== 'tempo') {
    throw new Error(`[evmNonceBackend] invalid chain '${String(chain)}'`);
  }
  const networkKey = String(input.chainTarget.networkSlug || '')
    .trim()
    .toLowerCase();
  if (!networkKey) {
    throw new Error('[evmNonceBackend] networkKey is required');
  }
  const chainId = input.chainTarget.chainId;
  const sender = normalizeAddress(input.sender, 'sender');
  const nonceKey = chain === 'tempo' ? normalizeBigint(input.nonceKey, 'nonceKey') : 0n;
  const walletId = String(toWalletId(input.subjectId));

  return {
    chain,
    networkKey,
    chainId,
    sender,
    nonceKey,
    walletId,
  };
}

function parseManagedNonceSnapshotChainTarget(
  snapshot: ManagedNonceReservationSnapshotInput,
): ThresholdEcdsaChainTarget {
  if (snapshot.chainTarget) {
    return thresholdEcdsaChainTargetFromRequest(snapshot.chainTarget);
  }
  const chain = snapshot.chain;
  if (chain !== 'evm' && chain !== 'tempo') {
    throw new Error('[evmNonceBackend] invalid managed nonce snapshot: chain');
  }
  const networkKey = String(snapshot.networkKey || '').trim();
  if (!networkKey) {
    throw new Error('[evmNonceBackend] invalid managed nonce snapshot: networkKey');
  }
  const chainId = snapshot.chainId;
  if (!Number.isSafeInteger(chainId) || chainId <= 0) {
    throw new Error('[evmNonceBackend] invalid managed nonce snapshot: chainId');
  }
  return thresholdEcdsaChainTargetFromChainFamily({
    chain,
    chainId,
    networkSlug: networkKey,
  });
}

function normalizeAddress(value: unknown, label: string): `0x${string}` {
  const normalized = String(value || '')
    .trim()
    .toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(normalized)) {
    throw new Error(`[evmNonceBackend] invalid ${label}: expected 20-byte 0x-prefixed hex`);
  }
  return normalized as `0x${string}`;
}

function normalizeSender(value: unknown): `0x${string}` {
  return normalizeAddress(value, 'sender');
}

function normalizeBigint(value: unknown, label: string): bigint {
  try {
    const parsed = BigInt(value as bigint | number | string);
    if (parsed < 0n) {
      throw new Error(`[evmNonceBackend] ${label} must be non-negative`);
    }
    return parsed;
  } catch {
    throw new Error(`[evmNonceBackend] invalid ${label}: expected bigint-compatible value`);
  }
}

function normalizeAccountId(value: unknown): string | undefined {
  const normalized = String(value || '').trim();
  return normalized || undefined;
}

function normalizeRequiredString(value: unknown, label: string): string {
  const normalized = String(value || '').trim();
  if (!normalized) {
    throw new Error(`[evmNonceBackend] invalid managed nonce snapshot: ${label}`);
  }
  return normalized;
}

function normalizeOptionalSafeInteger(value: unknown): number | undefined {
  if (value == null) return undefined;
  const parsed = Math.floor(Number(value));
  return Number.isSafeInteger(parsed) ? parsed : undefined;
}

function parseRpcHexQuantity(value: unknown, method: string): bigint {
  const raw = String(value || '').trim();
  if (!/^0x[0-9a-fA-F]+$/.test(raw)) {
    throw new Error(`[evmNonceBackend] invalid ${method} result: expected hex quantity`);
  }
  return BigInt(raw);
}

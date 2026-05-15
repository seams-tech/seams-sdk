import { chainFamilyFromNetwork } from '@/core/config/chains';
import type { SeamsChainConfig } from '@/core/types/seams';

export type EvmNonceChain = 'evm' | 'tempo';

export type ReserveNonceInput = {
  chain: EvmNonceChain;
  networkKey: string;
  chainId: number;
  sender: `0x${string}`;
  nonceKey?: bigint;
  walletId?: string;
};

export type ManagedNonceReservationSnapshot = {
  chain: EvmNonceChain;
  networkKey: string;
  chainId: number;
  sender: `0x${string}`;
  nonceKey?: string;
  nonce: string;
  walletId?: string;
  leaseId?: string;
  operationId?: string;
  operationFingerprint?: string;
  reservedAtMs?: number;
  expiresAtMs?: number;
};

export type ManagedNonceReservation = ReserveNonceInput & {
  nonce: bigint;
  leaseId?: string;
  operationId?: string;
  operationFingerprint?: string;
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
  const walletId = normalizeAccountId(input.walletId);
  const snapshot: ManagedNonceReservationSnapshot = {
    chain: input.chain,
    networkKey: String(input.networkKey || '').trim(),
    chainId: input.chainId,
    sender: normalizeSender(input.sender),
    nonce: normalizeBigint(input.nonce, 'nonce').toString(),
  };

  if (input.nonceKey != null) {
    snapshot.nonceKey = normalizeBigint(input.nonceKey, 'nonceKey').toString();
  }

  if (walletId) {
    snapshot.walletId = walletId;
  }
  if (typeof input.leaseId === 'string' && input.leaseId.trim()) {
    snapshot.leaseId = input.leaseId.trim();
  }
  if (typeof input.operationId === 'string' && input.operationId.trim()) {
    snapshot.operationId = input.operationId.trim();
  }
  if (typeof input.operationFingerprint === 'string' && input.operationFingerprint.trim()) {
    snapshot.operationFingerprint = input.operationFingerprint.trim();
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
  snapshot: ManagedNonceReservationSnapshot,
): ManagedNonceReservation {
  if (!snapshot || typeof snapshot !== 'object') {
    throw new Error('[evmNonceBackend] invalid managed nonce snapshot: object');
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
  const sender = normalizeSender(snapshot.sender);
  const nonce = normalizeBigint(snapshot.nonce, 'nonce');
  const parsedNonceKey =
    snapshot.nonceKey == null ? undefined : normalizeBigint(snapshot.nonceKey, 'nonceKey');
  const walletId = normalizeAccountId(snapshot.walletId);
  const leaseId = normalizeOptionalString(snapshot.leaseId);
  const operationId = normalizeOptionalString(snapshot.operationId);
  const operationFingerprint = normalizeOptionalString(snapshot.operationFingerprint);
  const reservedAtMs = normalizeOptionalSafeInteger(snapshot.reservedAtMs);
  const expiresAtMs = normalizeOptionalSafeInteger(snapshot.expiresAtMs);

  return {
    chain,
    networkKey,
    chainId,
    sender,
    ...(parsedNonceKey != null ? { nonceKey: parsedNonceKey } : {}),
    ...(walletId ? { walletId } : {}),
    nonce,
    ...(leaseId ? { leaseId } : {}),
    ...(operationId ? { operationId } : {}),
    ...(operationFingerprint ? { operationFingerprint } : {}),
    ...(reservedAtMs != null ? { reservedAtMs } : {}),
    ...(expiresAtMs != null ? { expiresAtMs } : {}),
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
  const targetChainId = input.chainId;
  const networkKey = String(input.networkKey || '')
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
      requestedChain: input.chain,
      networkKey: input.networkKey,
      chainId: targetChainId,
    });
    assertConfiguredChainIdMatchesInput({
      chain: only,
      chainId: targetChainId,
      networkKey: input.networkKey,
    });
    return mustTrimmedRpcUrl(only.rpcUrl, only.network);
  }
  if (networkMatches.length > 1) {
    const chainIdMatched = byChainId(networkMatches).filter((chain) =>
      isChainCompatibleWithRequestChain(chain, input.chain),
    );
    if (chainIdMatched.length === 1) {
      const only = chainIdMatched[0];
      return mustTrimmedRpcUrl(only.rpcUrl, only.network);
    }
    throw new Error(
      `[evmNonceBackend] ambiguous networkKey mapping for ${input.networkKey} (chainId=${String(input.chainId)})`,
    );
  }

  const chainIdMatches = byChainId(supportedChains);
  const compatibleMatches = chainIdMatches.filter((chain) =>
    isChainCompatibleWithRequestChain(chain, input.chain),
  );
  if (compatibleMatches.length === 1) {
    const only = compatibleMatches[0];
    return mustTrimmedRpcUrl(only.rpcUrl, only.network);
  }
  if (compatibleMatches.length > 1) {
    const candidates = compatibleMatches.map((chain) => String(chain.network || '').trim()).join(', ');
    throw new Error(
      `[evmNonceBackend] ambiguous chainId routing for ${input.chain} chainId=${String(input.chainId)} across [${candidates}]`,
    );
  }
  if (chainIdMatches.length > 0) {
    const families = Array.from(
      new Set(chainIdMatches.map((chain) => chainFamilyFromNetwork(chain.network))),
    );
    throw new Error(
      `[evmNonceBackend] chainId=${String(input.chainId)} is configured for [${families.join(', ')}] but is incompatible with ${input.chain} routing`,
    );
  }

  throw new Error(
    `[evmNonceBackend] unable to resolve RPC URL for ${input.chain} ${input.networkKey} (chainId=${String(input.chainId)})`,
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
  const chain = input.chain;
  if (chain !== 'evm' && chain !== 'tempo') {
    throw new Error(`[evmNonceBackend] invalid chain '${String(input.chain)}'`);
  }
  const networkKey = String(input.networkKey || '')
    .trim()
    .toLowerCase();
  if (!networkKey) {
    throw new Error('[evmNonceBackend] networkKey is required');
  }
  const chainId = input.chainId;
  const sender = normalizeAddress(input.sender, 'sender');
  const nonceKey = chain === 'tempo' ? normalizeBigint(input.nonceKey, 'nonceKey') : 0n;
  const walletId = normalizeAccountId(input.walletId);

  return {
    chain,
    networkKey,
    chainId,
    sender,
    nonceKey,
    ...(walletId ? { walletId } : {}),
  };
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

function normalizeOptionalString(value: unknown): string | undefined {
  const normalized = String(value || '').trim();
  return normalized || undefined;
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

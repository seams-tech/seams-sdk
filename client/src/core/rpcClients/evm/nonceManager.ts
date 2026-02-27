import { chainFamilyFromNetwork } from '@/core/config/chains';
import type { TatchiChainConfig } from '@/core/types/tatchi';

export type EvmNonceChain = 'evm' | 'tempo';

export type ReserveNonceInput = {
  chain: EvmNonceChain;
  networkKey: string;
  chainId: number;
  sender: `0x${string}`;
  nonceKey?: bigint;
  nearAccountId?: string;
};

export type ManagedNonceReservationSnapshot = {
  chain: EvmNonceChain;
  networkKey: string;
  chainId: number;
  sender: `0x${string}`;
  nonceKey?: string;
  nonce: string;
  nearAccountId?: string;
};

export interface EvmNonceManager {
  reserveNextNonce(input: ReserveNonceInput): Promise<bigint>;
  commitBroadcast(
    input: ReserveNonceInput & { nonce: bigint; txHash?: `0x${string}` },
  ): Promise<void>;
  releaseReservation(input: ReserveNonceInput & { nonce: bigint }): void;
  refreshFromChain(input: ReserveNonceInput): Promise<bigint>;
  clearForAccount(nearAccountId: string): void;
}

export type FetchChainNoncePort = (input: ReserveNonceInput) => Promise<bigint>;

export type CreateEvmNonceManagerWithFetcherArgs = {
  fetchChainNonce: FetchChainNoncePort;
  now?: () => number;
  refreshTtlMs?: number;
};

export type CreateEvmNonceManagerArgs = {
  chains: readonly TatchiChainConfig[];
  fetchImpl?: typeof fetch;
  now?: () => number;
  refreshTtlMs?: number;
};

type ChainWithChainId = Extract<TatchiChainConfig, { chainId: number }>;

export function toManagedNonceReservationSnapshot(
  input: ReserveNonceInput & { nonce: bigint },
): ManagedNonceReservationSnapshot {
  const nearAccountId = normalizeAccountId(input.nearAccountId);
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

  if (nearAccountId) {
    snapshot.nearAccountId = nearAccountId;
  }

  return snapshot;
}

export function fromManagedNonceReservationSnapshot(
  snapshot: ManagedNonceReservationSnapshot,
): ReserveNonceInput & { nonce: bigint } {
  const chain = snapshot.chain === 'tempo' ? 'tempo' : 'evm';
  const networkKey = String(snapshot.networkKey || '').trim();
  if (!networkKey) {
    throw new Error('[evmNonceManager] invalid managed nonce snapshot: networkKey');
  }
  const chainId = snapshot.chainId;
  const sender = normalizeSender(snapshot.sender);
  const nonce = normalizeBigint(snapshot.nonce, 'nonce');
  const parsedNonceKey =
    snapshot.nonceKey == null ? undefined : normalizeBigint(snapshot.nonceKey, 'nonceKey');
  const nearAccountId = normalizeAccountId(snapshot.nearAccountId);

  return {
    chain,
    networkKey,
    chainId,
    sender,
    ...(parsedNonceKey != null ? { nonceKey: parsedNonceKey } : {}),
    ...(nearAccountId ? { nearAccountId } : {}),
    nonce,
  };
}

type NormalizedInput = {
  chain: EvmNonceChain;
  networkKey: string;
  chainId: number;
  sender: `0x${string}`;
  nonceKey: bigint;
  nearAccountId?: string;
};

type NonceState = {
  chainNonce: bigint | null;
  nextCandidate: bigint | null;
  reserved: Set<string>;
  lastRefreshMs: number | null;
  inflightRefresh: Promise<bigint> | null;
};

const DEFAULT_REFRESH_TTL_MS = 5_000;
const DEFAULT_RPC_TIMEOUT_MS = 15_000;

class InMemoryEvmNonceManager implements EvmNonceManager {
  private readonly states = new Map<string, NonceState>();
  private readonly keyLocks = new Map<string, Promise<void>>();
  private readonly accountKeys = new Map<string, Set<string>>();

  private readonly fetchChainNonce: FetchChainNoncePort;
  private readonly now: () => number;
  private readonly refreshTtlMs: number;

  constructor(args: CreateEvmNonceManagerWithFetcherArgs) {
    this.fetchChainNonce = args.fetchChainNonce;
    this.now = args.now || Date.now;
    this.refreshTtlMs = normalizePositiveInt(args.refreshTtlMs, DEFAULT_REFRESH_TTL_MS);
  }

  async reserveNextNonce(input: ReserveNonceInput): Promise<bigint> {
    const normalized = normalizeInput(input);
    const key = toReservationKey(normalized);
    return await this.withKeyLock(key, async () => {
      const state = this.getOrCreateState(key);
      this.indexKeyByAccount(normalized.nearAccountId, key);

      if (this.shouldRefresh(state)) {
        await this.refreshFromChainLocked(normalized, state);
      }

      let candidate = state.nextCandidate ?? 0n;
      while (state.reserved.has(candidate.toString())) {
        candidate += 1n;
      }
      state.reserved.add(candidate.toString());
      state.nextCandidate = candidate + 1n;
      return candidate;
    });
  }

  async commitBroadcast(
    input: ReserveNonceInput & { nonce: bigint; txHash?: `0x${string}` },
  ): Promise<void> {
    void input.txHash;
    const normalized = normalizeInput(input);
    const key = toReservationKey(normalized);
    const nonce = normalizeBigint(input.nonce, 'nonce');
    await this.withKeyLock(key, async () => {
      const state = this.getOrCreateState(key);
      state.reserved.delete(nonce.toString());
      const minNext = nonce + 1n;
      if (state.nextCandidate == null || state.nextCandidate < minNext) {
        state.nextCandidate = minNext;
      }
    });
  }

  releaseReservation(input: ReserveNonceInput & { nonce: bigint }): void {
    const normalized = normalizeInput(input);
    const key = toReservationKey(normalized);
    const nonce = normalizeBigint(input.nonce, 'nonce').toString();
    const state = this.states.get(key);
    if (!state) return;
    state.reserved.delete(nonce);
    // If nothing is reserved, force the next reservation to refresh from chain.
    // This prevents local nonce drift after a failed broadcast that released
    // the last reservation (e.g. chain pending nonce=1 while local candidate=2).
    if (state.reserved.size === 0) {
      state.lastRefreshMs = null;
    }
  }

  async refreshFromChain(input: ReserveNonceInput): Promise<bigint> {
    const normalized = normalizeInput(input);
    const key = toReservationKey(normalized);
    const state = this.getOrCreateState(key);
    this.indexKeyByAccount(normalized.nearAccountId, key);
    return await this.refreshFromChainLocked(normalized, state);
  }

  clearForAccount(nearAccountId: string): void {
    const accountKey = normalizeAccountId(nearAccountId);
    if (!accountKey) return;
    const keys = this.accountKeys.get(accountKey);
    if (!keys) return;
    for (const key of keys) {
      this.states.delete(key);
    }
    this.accountKeys.delete(accountKey);
  }

  private async refreshFromChainLocked(input: NormalizedInput, state: NonceState): Promise<bigint> {
    if (state.inflightRefresh) {
      return await state.inflightRefresh;
    }
    const refreshTask = (async (): Promise<bigint> => {
      // eth_getTransactionCount returns the next usable nonce (not last used).
      const chainNextNonceRaw = await this.fetchChainNonce(input);
      const chainNextNonce = chainNextNonceRaw >= 0n ? chainNextNonceRaw : 0n;

      let highestReserved = 0n;
      const prunedReserved = new Set<string>();
      for (const reserved of state.reserved) {
        const value = parseBigintOrNull(reserved);
        if (value == null) continue;
        if (value >= chainNextNonce) {
          prunedReserved.add(reserved);
          if (value > highestReserved) highestReserved = value;
        }
      }
      state.reserved = prunedReserved;

      const nextFromChain = chainNextNonce;
      const nextFromCurrent = state.nextCandidate || 0n;
      const nextFromReserved = highestReserved > 0n ? highestReserved + 1n : 0n;
      state.nextCandidate = maxBigInt(0n, nextFromChain, nextFromCurrent, nextFromReserved);
      state.chainNonce = chainNextNonce;
      state.lastRefreshMs = this.now();

      return chainNextNonce;
    })();

    state.inflightRefresh = refreshTask;
    try {
      return await refreshTask;
    } finally {
      if (state.inflightRefresh === refreshTask) {
        state.inflightRefresh = null;
      }
    }
  }

  private shouldRefresh(state: NonceState): boolean {
    if (state.nextCandidate == null) return true;
    if (state.lastRefreshMs == null) return true;
    if (state.reserved.size > 0) return false;
    return this.now() - state.lastRefreshMs >= this.refreshTtlMs;
  }

  private getOrCreateState(key: string): NonceState {
    const existing = this.states.get(key);
    if (existing) return existing;
    const created: NonceState = {
      chainNonce: null,
      nextCandidate: null,
      reserved: new Set<string>(),
      lastRefreshMs: null,
      inflightRefresh: null,
    };
    this.states.set(key, created);
    return created;
  }

  private indexKeyByAccount(nearAccountId: string | undefined, key: string): void {
    const accountKey = normalizeAccountId(nearAccountId);
    if (!accountKey) return;
    const keys = this.accountKeys.get(accountKey);
    if (!keys) {
      this.accountKeys.set(accountKey, new Set<string>([key]));
      return;
    }
    keys.add(key);
  }

  private async withKeyLock<T>(key: string, task: () => Promise<T>): Promise<T> {
    const previous = this.keyLocks.get(key) || Promise.resolve();
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const next = previous.catch(() => undefined).then(() => gate);
    this.keyLocks.set(key, next);

    await previous.catch(() => undefined);
    try {
      return await task();
    } finally {
      release();
      if (this.keyLocks.get(key) === next) {
        this.keyLocks.delete(key);
      }
    }
  }
}

export function createEvmNonceManagerWithFetcher(
  args: CreateEvmNonceManagerWithFetcherArgs,
): EvmNonceManager {
  return new InMemoryEvmNonceManager(args);
}

export function createEvmNonceManager(args: CreateEvmNonceManagerArgs): EvmNonceManager {
  const fetchImpl = args.fetchImpl || fetch.bind(globalThis);
  return createEvmNonceManagerWithFetcher({
    now: args.now,
    refreshTtlMs: args.refreshTtlMs,
    fetchChainNonce: async (input) =>
      await fetchChainNonceFromRpc({
        chains: args.chains,
        input,
        fetchImpl,
      }),
  });
}

async function fetchChainNonceFromRpc(args: {
  chains: readonly TatchiChainConfig[];
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
        id: 'evm-nonce-manager',
        method: 'eth_getTransactionCount',
        params: [args.input.sender, 'pending'],
      }),
      signal: timeout.signal,
    });
    if (!response.ok) {
      throw new Error(`[evmNonceManager] RPC returned HTTP ${response.status}`);
    }
    const payload = (await response.json().catch(() => null)) as {
      result?: unknown;
      error?: { code?: unknown; message?: unknown };
    } | null;
    if (!payload) {
      throw new Error('[evmNonceManager] RPC returned invalid JSON');
    }
    if (payload.error) {
      const code = typeof payload.error.code === 'number' ? payload.error.code : 'unknown';
      const message = String(payload.error.message || 'unknown error');
      throw new Error(
        `[evmNonceManager] eth_getTransactionCount failed (${String(code)}): ${message}`,
      );
    }
    return parseRpcHexQuantity(payload.result, 'eth_getTransactionCount');
  } finally {
    timeout.clear();
  }
}

function resolveRpcUrlForInput(
  chains: readonly TatchiChainConfig[],
  input: ReserveNonceInput,
): string {
  const targetChainId = input.chainId;
  const networkKey = String(input.networkKey || '')
    .trim()
    .toLowerCase();
  const byChainId = (source: readonly TatchiChainConfig[]): TatchiChainConfig[] =>
    source.filter((chain) => {
      const chainId = getOptionalConfigChainId(chain);
      return typeof chainId === 'number' && chainId === targetChainId;
    });
  const byNetworkKey = (source: readonly TatchiChainConfig[]): TatchiChainConfig[] =>
    source.filter(
      (chain) =>
        String(chain.network || '')
          .trim()
          .toLowerCase() === networkKey,
    );

  const supportedChains = chains.filter((chain) => isSupportedNonceRoutingChain(chain));
  if (!supportedChains.length) {
    throw new Error('[evmNonceManager] missing RPC config for nonce-enabled chains');
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
      `[evmNonceManager] ambiguous networkKey mapping for ${input.networkKey} (chainId=${String(input.chainId)})`,
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
      `[evmNonceManager] ambiguous chainId routing for ${input.chain} chainId=${String(input.chainId)} across [${candidates}]`,
    );
  }
  if (chainIdMatches.length > 0) {
    const families = Array.from(
      new Set(chainIdMatches.map((chain) => chainFamilyFromNetwork(chain.network))),
    );
    throw new Error(
      `[evmNonceManager] chainId=${String(input.chainId)} is configured for [${families.join(', ')}] but is incompatible with ${input.chain} routing`,
    );
  }

  throw new Error(
    `[evmNonceManager] unable to resolve RPC URL for ${input.chain} ${input.networkKey} (chainId=${String(input.chainId)})`,
  );
}

function isSupportedNonceRoutingChain(chain: TatchiChainConfig): boolean {
  const family = chainFamilyFromNetwork(chain.network);
  return family === 'evm' || family === 'tempo';
}

function isChainCompatibleWithRequestChain(
  chain: TatchiChainConfig,
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
  chain: TatchiChainConfig;
  chainId: number;
  networkKey: string;
}): void {
  const configuredChainId = getOptionalConfigChainId(args.chain);
  if (typeof configuredChainId !== 'number') {
    throw new Error(
      `[evmNonceManager] configured network ${args.chain.network} is missing numeric chainId`,
    );
  }
  if (configuredChainId !== args.chainId) {
    throw new Error(
      `[evmNonceManager] chainId mismatch for network ${args.networkKey}: expected ${configuredChainId}, received ${String(args.chainId)}`,
    );
  }
}

function assertChainSupportsRequestedRoute(args: {
  chain: TatchiChainConfig;
  requestedChain: EvmNonceChain;
  networkKey: string;
  chainId: number;
}): void {
  if (isChainCompatibleWithRequestChain(args.chain, args.requestedChain)) {
    return;
  }
  const resolvedFamily = chainFamilyFromNetwork(args.chain.network);
  throw new Error(
    `[evmNonceManager] network ${args.networkKey} (family=${resolvedFamily}) is incompatible with ${args.requestedChain} request (chainId=${String(args.chainId)})`,
  );
}

function getOptionalConfigChainId(chain: TatchiChainConfig): number | undefined {
  return isChainWithChainId(chain) ? chain.chainId : undefined;
}

function isChainWithChainId(chain: TatchiChainConfig): chain is ChainWithChainId {
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
    throw new Error(`[evmNonceManager] missing rpcUrl for ${network}`);
  }
  return trimmed;
}

function toReservationKey(input: NormalizedInput): string {
  return [
    input.chain,
    input.networkKey,
    input.chainId.toString(),
    input.sender,
    input.nonceKey.toString(),
  ].join('|');
}

function normalizeInput(input: ReserveNonceInput): NormalizedInput {
  const chain = input.chain;
  if (chain !== 'evm' && chain !== 'tempo') {
    throw new Error(`[evmNonceManager] invalid chain '${String(input.chain)}'`);
  }
  const networkKey = String(input.networkKey || '')
    .trim()
    .toLowerCase();
  if (!networkKey) {
    throw new Error('[evmNonceManager] networkKey is required');
  }
  const chainId = input.chainId;
  const sender = normalizeAddress(input.sender, 'sender');
  const nonceKey = chain === 'tempo' ? normalizeBigint(input.nonceKey, 'nonceKey') : 0n;
  const nearAccountId = normalizeAccountId(input.nearAccountId);

  return {
    chain,
    networkKey,
    chainId,
    sender,
    nonceKey,
    ...(nearAccountId ? { nearAccountId } : {}),
  };
}

function normalizeAddress(value: unknown, label: string): `0x${string}` {
  const normalized = String(value || '')
    .trim()
    .toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(normalized)) {
    throw new Error(`[evmNonceManager] invalid ${label}: expected 20-byte 0x-prefixed hex`);
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
      throw new Error(`[evmNonceManager] ${label} must be non-negative`);
    }
    return parsed;
  } catch {
    throw new Error(`[evmNonceManager] invalid ${label}: expected bigint-compatible value`);
  }
}

function normalizeAccountId(value: unknown): string | undefined {
  const normalized = String(value || '').trim();
  return normalized || undefined;
}

function parseRpcHexQuantity(value: unknown, method: string): bigint {
  const raw = String(value || '').trim();
  if (!/^0x[0-9a-fA-F]+$/.test(raw)) {
    throw new Error(`[evmNonceManager] invalid ${method} result: expected hex quantity`);
  }
  return BigInt(raw);
}

function parseBigintOrNull(value: unknown): bigint | null {
  try {
    return BigInt(value as bigint | number | string);
  } catch {
    return null;
  }
}

function normalizePositiveInt(value: unknown, fallback: number): number {
  const parsed = Math.floor(Number(value));
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  return parsed;
}

function maxBigInt(...values: bigint[]): bigint {
  if (!values.length) return 0n;
  let max = values[0];
  for (let i = 1; i < values.length; i++) {
    if (values[i] > max) max = values[i];
  }
  return max;
}

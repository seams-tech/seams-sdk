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
  markBroadcastAccepted(
    input: ReserveNonceInput & { nonce: bigint; txHash?: `0x${string}` },
  ): Promise<void>;
  markBroadcastRejected(input: ReserveNonceInput & { nonce: bigint }): void;
  markFinalized(
    input: ReserveNonceInput & { nonce: bigint; txHash?: `0x${string}` },
  ): Promise<void>;
  markDroppedOrReplaced(
    input: ReserveNonceInput & {
      nonce: bigint;
      reason: 'dropped' | 'replaced';
      txHash?: `0x${string}`;
    },
  ): Promise<void>;
  reconcileLane(input: ReserveNonceInput): Promise<NonceLaneStatus>;
  clearForAccount(nearAccountId: string): void;
}

export type NonceLaneStatus = {
  chainNextNonce: bigint;
  unresolvedInFlightNonces: bigint[];
  blocked: boolean;
  blockedNonce?: bigint;
};

export type FetchChainNoncePort = (input: ReserveNonceInput) => Promise<bigint>;

export type CreateEvmNonceManagerWithFetcherArgs = {
  fetchChainNonce: FetchChainNoncePort;
  now?: () => number;
  refreshTtlMs?: number;
  staleInFlightThresholdMs?: number;
};

export type CreateEvmNonceManagerArgs = {
  chains: readonly TatchiChainConfig[];
  fetchImpl?: typeof fetch;
  now?: () => number;
  refreshTtlMs?: number;
  staleInFlightThresholdMs?: number;
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
  inFlight: Map<string, InFlightNonceRecord>;
  lastRefreshMs: number | null;
  inflightRefresh: Promise<bigint> | null;
};

type InFlightNonceRecord = {
  nonce: bigint;
  txHash?: `0x${string}`;
  status: 'accepted' | 'replaced';
  acceptedAtMs: number;
  updatedAtMs: number;
};

const DEFAULT_REFRESH_TTL_MS = 5_000;
const DEFAULT_RPC_TIMEOUT_MS = 15_000;
const DEFAULT_STALE_INFLIGHT_THRESHOLD_MS = 45_000;

class InMemoryEvmNonceManager implements EvmNonceManager {
  private readonly states = new Map<string, NonceState>();
  private readonly keyLocks = new Map<string, Promise<void>>();
  private readonly accountKeys = new Map<string, Set<string>>();

  private readonly fetchChainNonce: FetchChainNoncePort;
  private readonly now: () => number;
  private readonly refreshTtlMs: number;
  private readonly staleInFlightThresholdMs: number;

  constructor(args: CreateEvmNonceManagerWithFetcherArgs) {
    this.fetchChainNonce = args.fetchChainNonce;
    this.now = args.now || Date.now;
    this.refreshTtlMs = normalizePositiveInt(args.refreshTtlMs, DEFAULT_REFRESH_TTL_MS);
    this.staleInFlightThresholdMs = normalizePositiveInt(
      args.staleInFlightThresholdMs,
      DEFAULT_STALE_INFLIGHT_THRESHOLD_MS,
    );
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

      const blocked = this.readBlockedInFlight(state);
      if (blocked) {
        throw createNonceLaneBlockedError({
          input: normalized,
          blockedNonce: blocked.blockedNonce,
          ageMs: blocked.ageMs,
        });
      }

      let candidate = state.nextCandidate ?? 0n;
      while (
        state.reserved.has(candidate.toString()) ||
        state.inFlight.has(candidate.toString())
      ) {
        candidate += 1n;
      }
      state.reserved.add(candidate.toString());
      state.nextCandidate = candidate + 1n;
      return candidate;
    });
  }

  async markBroadcastAccepted(
    input: ReserveNonceInput & { nonce: bigint; txHash?: `0x${string}` },
  ): Promise<void> {
    const normalized = normalizeInput(input);
    const key = toReservationKey(normalized);
    const nonce = normalizeBigint(input.nonce, 'nonce');
    await this.withKeyLock(key, async () => {
      const state = this.getOrCreateState(key);
      state.reserved.delete(nonce.toString());
      state.inFlight.set(nonce.toString(), {
        nonce,
        ...(input.txHash ? { txHash: input.txHash } : {}),
        status: 'accepted',
        acceptedAtMs: this.now(),
        updatedAtMs: this.now(),
      });
      const minNext = nonce + 1n;
      if (state.nextCandidate == null || state.nextCandidate < minNext) {
        state.nextCandidate = minNext;
      }
    });
  }

  markBroadcastRejected(input: ReserveNonceInput & { nonce: bigint }): void {
    const normalized = normalizeInput(input);
    const key = toReservationKey(normalized);
    const nonce = normalizeBigint(input.nonce, 'nonce').toString();
    const state = this.states.get(key);
    if (!state) return;
    state.reserved.delete(nonce);
    if (state.reserved.size === 0 && state.inFlight.size === 0) {
      state.lastRefreshMs = null;
    }
  }

  async markFinalized(
    input: ReserveNonceInput & { nonce: bigint; txHash?: `0x${string}` },
  ): Promise<void> {
    void input.txHash;
    const normalized = normalizeInput(input);
    const key = toReservationKey(normalized);
    const nonce = normalizeBigint(input.nonce, 'nonce');
    await this.withKeyLock(key, async () => {
      const state = this.getOrCreateState(key);
      state.reserved.delete(nonce.toString());
      state.inFlight.delete(nonce.toString());
      const minNext = nonce + 1n;
      state.chainNonce = state.chainNonce == null ? minNext : maxBigInt(state.chainNonce, minNext);
      if (state.nextCandidate == null || state.nextCandidate < minNext) {
        state.nextCandidate = minNext;
      }
      state.lastRefreshMs = this.now();
    });
  }

  async markDroppedOrReplaced(
    input: ReserveNonceInput & {
      nonce: bigint;
      reason: 'dropped' | 'replaced';
      txHash?: `0x${string}`;
    },
  ): Promise<void> {
    const normalized = normalizeInput(input);
    const key = toReservationKey(normalized);
    const nonce = normalizeBigint(input.nonce, 'nonce');
    await this.withKeyLock(key, async () => {
      const state = this.getOrCreateState(key);
      state.reserved.delete(nonce.toString());
      if (input.reason === 'dropped') {
        state.inFlight.delete(nonce.toString());
        if (state.chainNonce == null || state.chainNonce <= nonce) {
          state.nextCandidate =
            state.nextCandidate == null ? nonce : minBigInt(state.nextCandidate, nonce);
        }
      } else {
        const prev = state.inFlight.get(nonce.toString());
        state.inFlight.set(nonce.toString(), {
          nonce,
          ...(input.txHash ? { txHash: input.txHash } : prev?.txHash ? { txHash: prev.txHash } : {}),
          status: 'replaced',
          acceptedAtMs: prev?.acceptedAtMs ?? this.now(),
          updatedAtMs: this.now(),
        });
      }
      state.lastRefreshMs = null;
    });
  }

  async reconcileLane(input: ReserveNonceInput): Promise<NonceLaneStatus> {
    const normalized = normalizeInput(input);
    const key = toReservationKey(normalized);
    return await this.withKeyLock(key, async () => {
      const state = this.getOrCreateState(key);
      this.indexKeyByAccount(normalized.nearAccountId, key);
      const chainNextNonce = await this.refreshFromChainLocked(normalized, state);
      const unresolvedInFlightNonces = Array.from(state.inFlight.values())
        .map((entry) => entry.nonce)
        .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
      const blockedState = this.readBlockedInFlight(state);
      return {
        chainNextNonce,
        unresolvedInFlightNonces,
        blocked: !!blockedState,
        ...(blockedState ? { blockedNonce: blockedState.blockedNonce } : {}),
      };
    });
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

      let highestInFlight = 0n;
      const prunedInFlight = new Map<string, InFlightNonceRecord>();
      for (const [key, record] of state.inFlight.entries()) {
        if (record.nonce < chainNextNonce) continue;
        prunedInFlight.set(key, record);
        if (record.nonce > highestInFlight) highestInFlight = record.nonce;
      }
      state.inFlight = prunedInFlight;

      const nextFromChain = chainNextNonce;
      const nextFromCurrent = state.nextCandidate || 0n;
      const nextFromReserved = highestReserved > 0n ? highestReserved + 1n : 0n;
      const nextFromInFlight = highestInFlight > 0n ? highestInFlight + 1n : 0n;
      state.nextCandidate = maxBigInt(
        0n,
        nextFromChain,
        nextFromCurrent,
        nextFromReserved,
        nextFromInFlight,
      );
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
    if (state.inFlight.size > 0) return true;
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
      inFlight: new Map<string, InFlightNonceRecord>(),
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

  private readBlockedInFlight(
    state: NonceState,
  ): { blockedNonce: bigint; ageMs: number } | null {
    if (state.inFlight.size === 0) return null;
    if (state.chainNonce == null) return null;

    let oldestNonce: bigint | null = null;
    let oldestUpdatedAtMs: number | null = null;
    for (const record of state.inFlight.values()) {
      if (oldestNonce == null || record.nonce < oldestNonce) {
        oldestNonce = record.nonce;
        oldestUpdatedAtMs = record.updatedAtMs;
      }
    }
    if (oldestNonce == null || oldestUpdatedAtMs == null) return null;
    if (state.chainNonce > oldestNonce) return null;

    const ageMs = Math.max(0, this.now() - oldestUpdatedAtMs);
    if (ageMs < this.staleInFlightThresholdMs) return null;
    return {
      blockedNonce: oldestNonce,
      ageMs,
    };
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
    staleInFlightThresholdMs: args.staleInFlightThresholdMs,
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

function minBigInt(a: bigint, b: bigint): bigint {
  return a < b ? a : b;
}

function createNonceLaneBlockedError(args: {
  input: NormalizedInput;
  blockedNonce: bigint;
  ageMs: number;
}): Error & {
  code: 'nonce_lane_blocked';
  retryable: true;
  details: {
    chain: EvmNonceChain;
    networkKey: string;
    chainId: number;
    blockedNonce: string;
    ageMs: number;
  };
} {
  const error = new Error(
    `[evmNonceManager] nonce lane blocked on ${args.input.networkKey} (nonce=${args.blockedNonce.toString()}) for ${args.ageMs}ms; reconcile or replace/dropped report required`,
  ) as Error & {
    code: 'nonce_lane_blocked';
    retryable: true;
    details: {
      chain: EvmNonceChain;
      networkKey: string;
      chainId: number;
      blockedNonce: string;
      ageMs: number;
    };
  };
  error.code = 'nonce_lane_blocked';
  error.retryable = true;
  error.details = {
    chain: args.input.chain,
    networkKey: args.input.networkKey,
    chainId: args.input.chainId,
    blockedNonce: args.blockedNonce.toString(),
    ageMs: args.ageMs,
  };
  return error;
}

import type { NearClient } from '@/core/rpcClients/near/NearClient';
import type { NonceLaneStatus } from '@/core/rpcClients/evm/nonceBackend';
import type { TransactionContext } from '@/core/types/rpc';
import type { AccessKeyView, BlockResult } from '@near-js/types';
import { errorMessage } from '@shared/utils/errors';
import { isObject, isString } from '@shared/utils/validation';
import {
  NearNonceReconcileReason,
  NonceDurableLeaseState,
  type NearNonceLane,
  type NearNonceLease,
} from './nonceTypes';
import { nonceLaneKey } from './nonceLaneKeys';
import { maxBigint, normalizeBigint, normalizeRequiredString } from './nonceUtils';

export type NearNonceLaneState = {
  accountId: string | null;
  publicKey: string | null;
  transactionContext: TransactionContext | null;
  lastNonceUpdate: number | null;
  lastBlockHeightUpdate: number | null;
  inflightFetch: Promise<TransactionContext> | null;
  inflightId: number;
  refreshTimer: ReturnType<typeof setTimeout> | null;
  prefetchTimer: ReturnType<typeof setTimeout> | null;
  reservedNonces: Set<string>;
  lastReservedNonce: string | null;
  inFlight: Map<string, NearInFlightNonceRecord>;
};

export type NearInFlightNonceRecord = {
  nonce: bigint;
  txHash: string;
  acceptedAtMs: number;
  updatedAtMs: number;
};

export function createNearNonceLaneState(): NearNonceLaneState {
  return {
    accountId: null,
    publicKey: null,
    transactionContext: null,
    lastNonceUpdate: null,
    lastBlockHeightUpdate: null,
    inflightFetch: null,
    inflightId: 0,
    refreshTimer: null,
    prefetchTimer: null,
    reservedNonces: new Set<string>(),
    lastReservedNonce: null,
    inFlight: new Map<string, NearInFlightNonceRecord>(),
  };
}

export function clearNearRefreshTimer(state: NearNonceLaneState): void {
  if (!state.refreshTimer) return;
  clearTimeout(state.refreshTimer);
  state.refreshTimer = null;
}

export function clearNearPrefetchTimer(state: NearNonceLaneState): void {
  if (!state.prefetchTimer) return;
  clearTimeout(state.prefetchTimer);
  state.prefetchTimer = null;
}

export function clearNearTransactionContext(state: NearNonceLaneState): void {
  state.transactionContext = null;
  state.lastNonceUpdate = null;
  state.lastBlockHeightUpdate = null;
  state.inflightFetch = null;
  state.reservedNonces.clear();
  state.lastReservedNonce = null;
  state.inFlight.clear();
  clearNearRefreshTimer(state);
  clearNearPrefetchTimer(state);
}

export function clearNearAccessKeyState(state: NearNonceLaneState): void {
  state.accountId = null;
  state.publicKey = null;
  clearNearTransactionContext(state);
}

export function initializeNearAccessKeyState(input: {
  state: NearNonceLaneState;
  accountId: string;
  publicKey: string;
}): void {
  const accountId = normalizeRequiredString(input.accountId, 'accountId');
  const publicKey = normalizeRequiredString(input.publicKey, 'publicKey');
  if (input.state.accountId === accountId && input.state.publicKey === publicKey) {
    return;
  }
  input.state.accountId = accountId;
  input.state.publicKey = publicKey;
  clearNearTransactionContext(input.state);
}

export async function reserveNearNoncesFromState(input: {
  state: NearNonceLaneState;
  lane: NearNonceLane;
  countInput: number;
  readActiveLeaseNonces: (laneKey: string, input?: { lane?: NearNonceLane }) => Promise<Set<string>>;
}): Promise<string[]> {
  if (!input.state.transactionContext) {
    throw new Error('NEAR transaction context not available - call fetchNearContext() first');
  }
  const count = Math.max(0, Math.floor(Number(input.countInput || 0)));
  if (count <= 0) return [];

  const laneKey = nonceLaneKey(input.lane);
  const activeDurableNonces = await input.readActiveLeaseNonces(laneKey, { lane: input.lane });
  let highestDurable = 0n;
  for (const nonce of activeDurableNonces) {
    const value = BigInt(nonce);
    if (value > highestDurable) highestDurable = value;
  }
  const start = maxBigint(
    input.state.lastReservedNonce ? BigInt(input.state.lastReservedNonce) + 1n : 0n,
    BigInt(input.state.transactionContext.nextNonce),
    highestDurable > 0n ? highestDurable + 1n : 0n,
  );
  const planned: string[] = [];
  let candidateValue = start;
  for (let index = 0; index < count; index += 1) {
    while (
      input.state.reservedNonces.has(candidateValue.toString()) ||
      activeDurableNonces.has(candidateValue.toString())
    ) {
      candidateValue += 1n;
    }
    const candidate = candidateValue.toString();
    planned.push(candidate);
    candidateValue += 1n;
  }
  for (const nonce of planned) {
    input.state.reservedNonces.add(nonce);
  }
  input.state.lastReservedNonce = planned[planned.length - 1] || input.state.lastReservedNonce;
  return planned;
}

export function computeLastReservedNonce(reserved: Set<string>): string | null {
  let last: bigint | null = null;
  for (const value of reserved) {
    try {
      const parsed = BigInt(value);
      if (last === null || parsed > last) last = parsed;
    } catch {}
  }
  return last === null ? null : last.toString();
}

export function releaseNearNonceFromState(state: NearNonceLaneState, nonce: string): void {
  if (!state.reservedNonces.delete(String(nonce))) return;
  state.lastReservedNonce = computeLastReservedNonce(state.reservedNonces);
}

export function releaseAllNearNoncesFromState(state: NearNonceLaneState): void {
  state.reservedNonces.clear();
  state.lastReservedNonce = null;
}

export async function markNearBroadcastAcceptedState(input: {
  lease: NearNonceLease;
  state: NearNonceLaneState;
  txHash: string;
  nowMs: number;
  persistCoordinationLease: (
    lease: NearNonceLease,
    state: typeof NonceDurableLeaseState.BroadcastAccepted,
  ) => Promise<void>;
}): Promise<void> {
  const nonce = BigInt(input.lease.nonce);
  input.state.inFlight.set(nonce.toString(), {
    nonce,
    txHash: input.txHash,
    acceptedAtMs: input.nowMs,
    updatedAtMs: input.nowMs,
  });
  await input.persistCoordinationLease(input.lease, NonceDurableLeaseState.BroadcastAccepted);
}

export async function reconcileNearLaneState(input: {
  lane: NearNonceLane;
  state: NearNonceLaneState;
  nearClient: NearClient;
  now: () => number;
  activeLeases: Iterable<NearNonceLease>;
  removeCoordinationLease: (lease: NearNonceLease) => Promise<void>;
  transitionLease: (input: {
    lease: NearNonceLease;
    transition: 'finalize' | 'drop';
    reason: string;
    txHash?: string;
  }) => void;
}): Promise<NonceLaneStatus> {
  initializeNearAccessKeyState({
    state: input.state,
    accountId: input.lane.accountId,
    publicKey: input.lane.publicKey,
  });
  const accessKeyInfoRaw = await input.nearClient.viewAccessKey(
    input.lane.accountId,
    input.lane.publicKey,
  );
  if (!isAccessKeyViewLike(accessKeyInfoRaw)) {
    throw new Error(`Access key not found or invalid for account ${input.lane.accountId}`);
  }
  const accessKeyInfo = normalizeAccessKeyView(accessKeyInfoRaw);
  const chainNonce = BigInt(accessKeyInfo.nonce);
  const chainNextNonce = chainNonce + 1n;
  const unresolvedInFlightNonces: bigint[] = [];

  for (const lease of input.activeLeases) {
    const leaseNonce = BigInt(lease.nonce);
    const inFlight = input.state.inFlight.get(leaseNonce.toString());
    if (leaseNonce > chainNonce) {
      if (inFlight) unresolvedInFlightNonces.push(leaseNonce);
      continue;
    }
    if (!inFlight?.txHash) {
      continue;
    }
    const txOutcome = await readNearTxOutcome({
      nearClient: input.nearClient,
      txHash: inFlight.txHash,
      accountId: input.lane.accountId,
    });
    if (txOutcome === 'finalized') {
      input.transitionLease({
        lease,
        transition: 'finalize',
        reason: 'near_tx_status_finalized',
        txHash: inFlight.txHash,
      });
      await input.removeCoordinationLease(lease);
      input.state.inFlight.delete(leaseNonce.toString());
      releaseNearNonceFromState(input.state, leaseNonce.toString());
      continue;
    }
    if (txOutcome === 'missing') {
      input.transitionLease({
        lease,
        transition: 'drop',
        reason: NearNonceReconcileReason.NonceAdvancedHashMissing,
        txHash: inFlight.txHash,
      });
      await input.removeCoordinationLease(lease);
      input.state.inFlight.delete(leaseNonce.toString());
      releaseNearNonceFromState(input.state, leaseNonce.toString());
      continue;
    }
    unresolvedInFlightNonces.push(leaseNonce);
  }

  const candidateNext = maxBigint(
    chainNextNonce,
    input.state.transactionContext?.nextNonce ? BigInt(input.state.transactionContext.nextNonce) : 0n,
    input.state.lastReservedNonce ? BigInt(input.state.lastReservedNonce) + 1n : 0n,
  );
  input.state.transactionContext = {
    ...(input.state.transactionContext || {
      nearPublicKeyStr: input.lane.publicKey,
      txBlockHeight: '0',
      txBlockHash: '',
    }),
    accessKeyInfo,
    nextNonce: candidateNext.toString(),
  };
  input.state.lastNonceUpdate = input.now();
  if (input.state.reservedNonces.size > 0) {
    const pruned = pruneReservedNearNonces(chainNonce, input.state.reservedNonces);
    input.state.reservedNonces = pruned.set;
    input.state.lastReservedNonce = pruned.lastReserved;
  }

  return {
    chainNextNonce,
    unresolvedInFlightNonces: unresolvedInFlightNonces.sort((a, b) =>
      a < b ? -1 : a > b ? 1 : 0,
    ),
    blocked: false,
  };
}

async function readNearTxOutcome(input: {
  nearClient: NearClient;
  txHash: string;
  accountId: string;
}): Promise<'finalized' | 'missing' | 'unknown'> {
  try {
    const outcome = await input.nearClient.txStatus(input.txHash, input.accountId);
    void outcome;
    return 'finalized';
  } catch (error: unknown) {
    const message = errorMessage(error);
    if (/unknown transaction|does not exist|not found|not found in storage/i.test(message)) {
      return 'missing';
    }
    return 'unknown';
  }
}

export function pruneReservedNearNonces(
  chainNonce: bigint,
  reserved: Set<string>,
): { set: Set<string>; lastReserved: string | null } {
  const next = new Set<string>();
  let last: bigint | null = null;
  for (const nonce of reserved) {
    try {
      const parsed = BigInt(nonce);
      if (parsed <= chainNonce) continue;
      next.add(nonce);
      if (last === null || parsed > last) last = parsed;
    } catch {}
  }
  return { set: next, lastReserved: last === null ? null : last.toString() };
}

export function isMissingNearAccessKeyError(message: string): boolean {
  return (
    message.includes('does not exist while viewing') ||
    message.includes('Access key not found') ||
    message.includes('unknown public key') ||
    message.includes('does not exist')
  );
}

export async function fetchNearFreshDataForState(input: {
  state: NearNonceLaneState;
  nearClient: NearClient;
  force?: boolean;
  now: () => number;
  nonceFreshnessThresholdMs: number;
  blockFreshnessThresholdMs: number;
}): Promise<TransactionContext> {
  const { state } = input;
  if (!state.accountId || !state.publicKey) {
    throw new Error('[NonceCoordinator] NEAR access key is not initialized');
  }
  if (state.inflightFetch && !input.force) {
    return state.inflightFetch;
  }

  const capturedAccountId = state.accountId;
  const capturedPublicKey = state.publicKey;
  const requestId = ++state.inflightId;
  const fetchPromise = (async () => {
    try {
      const nowMs = input.now();
      const isNonceStale =
        input.force ||
        !state.lastNonceUpdate ||
        nowMs - state.lastNonceUpdate >= input.nonceFreshnessThresholdMs;
      const isBlockStale =
        input.force ||
        !state.lastBlockHeightUpdate ||
        nowMs - state.lastBlockHeightUpdate >= input.blockFreshnessThresholdMs;

      let accessKeyInfo = state.transactionContext?.accessKeyInfo;
      let txBlockHeight = state.transactionContext?.txBlockHeight;
      let txBlockHash = state.transactionContext?.txBlockHash;
      const fetchAccessKey = isNonceStale || !accessKeyInfo;
      const fetchBlock = isBlockStale || !txBlockHeight || !txBlockHash;

      let maybeAccessKey: unknown = accessKeyInfo ?? null;
      let maybeBlock: unknown = null;
      let accessKeyError: unknown = null;
      let blockError: unknown = null;
      const tasks: Promise<void>[] = [];

      if (fetchAccessKey) {
        tasks.push(
          (async () => {
            try {
              maybeAccessKey = await input.nearClient.viewAccessKey(
                capturedAccountId,
                capturedPublicKey,
              );
            } catch (error: unknown) {
              const message = errorMessage(error);
              if (isMissingNearAccessKeyError(message)) {
                maybeAccessKey = null;
                return;
              }
              accessKeyError = error;
            }
          })(),
        );
      }

      if (fetchBlock) {
        tasks.push(
          (async () => {
            try {
              maybeBlock = await input.nearClient.viewBlock({ finality: 'final' });
            } catch (error: unknown) {
              blockError = error;
            }
          })(),
        );
      }

      if (tasks.length > 0) {
        await Promise.all(tasks);
      }
      if (accessKeyError) throw accessKeyError;
      if (blockError) throw blockError;

      if (fetchAccessKey) {
        accessKeyInfo = isAccessKeyViewLike(maybeAccessKey)
          ? normalizeAccessKeyView(maybeAccessKey)
          : state.transactionContext?.accessKeyInfo || makePlaceholderAccessKey();
      }
      if (fetchBlock) {
        if (!isBlockResultLike(maybeBlock)) {
          throw new Error('[NonceCoordinator] failed to fetch NEAR block info');
        }
        txBlockHeight = String(maybeBlock.header.height);
        txBlockHash = maybeBlock.header.hash;
      }

      const nextCandidate = maxBigint(
        accessKeyInfo?.nonce !== undefined ? BigInt(accessKeyInfo.nonce) + 1n : 0n,
        state.transactionContext?.nextNonce ? BigInt(state.transactionContext.nextNonce) : 0n,
        state.lastReservedNonce ? BigInt(state.lastReservedNonce) + 1n : 0n,
        1n,
      );
      const transactionContext: TransactionContext = {
        nearPublicKeyStr: capturedPublicKey,
        accessKeyInfo: accessKeyInfo!,
        nextNonce: nextCandidate.toString(),
        txBlockHeight: txBlockHeight!,
        txBlockHash: txBlockHash!,
      };

      if (
        capturedAccountId === state.accountId &&
        capturedPublicKey === state.publicKey &&
        requestId === state.inflightId
      ) {
        state.transactionContext = transactionContext;
        const commitMs = input.now();
        if (fetchAccessKey) state.lastNonceUpdate = commitMs;
        if (fetchBlock) state.lastBlockHeightUpdate = commitMs;
      }
      return transactionContext;
    } finally {
      if (requestId === state.inflightId) {
        state.inflightFetch = null;
      }
    }
  })();

  state.inflightFetch = fetchPromise;
  return fetchPromise;
}

export async function updateNearNonceFromBlockchainState(input: {
  state: NearNonceLaneState;
  nearClient: NearClient;
  actualNonce: string;
  now: () => number;
}): Promise<void> {
  const { state } = input;
  if (!state.accountId || !state.publicKey) {
    throw new Error('[NonceCoordinator] NEAR access key is not initialized');
  }
  try {
    const accessKeyInfoRaw = await input.nearClient.viewAccessKey(state.accountId, state.publicKey);
    if (!isAccessKeyViewLike(accessKeyInfoRaw)) {
      throw new Error(`Access key not found or invalid for account ${state.accountId}`);
    }
    const accessKeyInfo = normalizeAccessKeyView(accessKeyInfoRaw);
    const chainNonce = BigInt(accessKeyInfo.nonce);
    const actual = BigInt(input.actualNonce);
    const candidateNext = maxBigint(
      chainNonce + 1n,
      actual + 1n,
      state.transactionContext?.nextNonce ? BigInt(state.transactionContext.nextNonce) : 0n,
      state.lastReservedNonce ? BigInt(state.lastReservedNonce) + 1n : 0n,
    );

    if (state.transactionContext) {
      state.transactionContext = {
        ...state.transactionContext,
        accessKeyInfo,
        nextNonce: candidateNext.toString(),
      };
    } else {
      state.transactionContext = {
        nearPublicKeyStr: state.publicKey,
        accessKeyInfo,
        nextNonce: candidateNext.toString(),
        txBlockHeight: '0',
        txBlockHash: '',
      };
    }
    state.lastNonceUpdate = input.now();
    state.inFlight.delete(input.actualNonce);
    releaseNearNonceFromState(state, input.actualNonce);
    if (state.reservedNonces.size > 0) {
      const pruned = pruneReservedNearNonces(chainNonce, state.reservedNonces);
      state.reservedNonces = pruned.set;
      state.lastReservedNonce = pruned.lastReserved;
    }
  } catch (error: unknown) {
    const message = errorMessage(error);
    if (isMissingNearAccessKeyError(message)) {
      const actual = BigInt(input.actualNonce);
      const candidateNext = maxBigint(
        actual + 1n,
        state.transactionContext?.nextNonce ? BigInt(state.transactionContext.nextNonce) : 0n,
        state.lastReservedNonce ? BigInt(state.lastReservedNonce) + 1n : 0n,
      );
      state.transactionContext = {
        ...(state.transactionContext || {
          nearPublicKeyStr: state.publicKey,
          accessKeyInfo: makePlaceholderAccessKey(),
          txBlockHeight: '0',
          txBlockHash: '',
        }),
        nextNonce: candidateNext.toString(),
      };
      state.lastNonceUpdate = input.now();
    }
  }
}

export function shouldPrefetchNearContext(input: {
  state: NearNonceLaneState;
  nowMs: number;
  blockFreshnessThresholdMs: number;
}): boolean {
  const blockStale =
    !input.state.lastBlockHeightUpdate ||
    input.nowMs - input.state.lastBlockHeightUpdate >= input.blockFreshnessThresholdMs;
  const missingContext = !input.state.transactionContext;
  return blockStale || missingContext;
}

export function isAccessKeyViewLike(value: unknown): value is AccessKeyView {
  if (!isObject(value)) return false;
  try {
    normalizeBigint((value as { nonce?: unknown }).nonce, 'near access-key nonce');
    return true;
  } catch {
    return false;
  }
}

export function normalizeAccessKeyView(value: AccessKeyView): AccessKeyView {
  const record = value as {
    nonce?: unknown;
    permission?: unknown;
    block_hash?: unknown;
    block_height?: unknown;
  };
  return {
    nonce: normalizeBigint(record.nonce, 'near access-key nonce'),
    permission: normalizeAccessKeyPermission(record.permission),
    block_hash: isString(record.block_hash) ? record.block_hash : '',
    block_height: typeof record.block_height === 'number' ? record.block_height : 0,
  };
}

function normalizeAccessKeyPermission(value: unknown): AccessKeyView['permission'] {
  if (value === 'FullAccess') return 'FullAccess';
  if (!isObject(value)) return 'FullAccess';
  const functionCall = value.FunctionCall;
  if (!isObject(functionCall)) return 'FullAccess';
  const methodNames = Array.isArray(functionCall.method_names)
    ? functionCall.method_names.filter(isString)
    : [];
  return {
    FunctionCall: {
      allowance: isString(functionCall.allowance) ? functionCall.allowance : '',
      receiver_id: isString(functionCall.receiver_id) ? functionCall.receiver_id : '',
      method_names: methodNames,
    },
  };
}

export function isBlockResultLike(value: unknown): value is BlockResult {
  const record = value as Partial<BlockResult> | null;
  if (!record || typeof record !== 'object') return false;
  const header = record.header as Partial<BlockResult['header']> | undefined;
  return !!header && typeof header.hash === 'string' && header.height !== undefined;
}

export function makePlaceholderAccessKey(): AccessKeyView {
  return {
    nonce: 0n,
    permission: 'FullAccess',
    block_height: 0,
    block_hash: '',
  };
}

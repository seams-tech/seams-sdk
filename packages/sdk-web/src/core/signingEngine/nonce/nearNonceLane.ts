import type { NearClient } from '@/core/rpcClients/near/NearClient';
import type { NonceLaneStatus } from '@/core/rpcClients/evm/nonceBackend';
import type { TransactionContext } from '@/core/types/rpc';
import type { AccessKeyView, BlockResult } from '@near-js/types';
import { errorMessage } from '@shared/utils/errors';
import { isImplicitNearAccountId } from '@shared/utils/near';
import { isObject, isString } from '@shared/utils/validation';
import {
  NearNonceReconcileReason,
  NonceDurableLeaseState,
  type NearNonceLane,
  type NearNonceLease,
} from './nonceTypes';
import { nonceLaneKey } from './nonceLaneKeys';
import { maxBigint, normalizeBigint, normalizeRequiredString } from './nonceUtils';

export type NearAccessKeySubject = {
  walletId: string;
  nearAccountId: string;
  publicKey: string;
};

type NearNonceMissingContext = {
  kind: 'missing';
};

type NearNonceReadyContext = {
  kind: 'ready';
  transactionContext: TransactionContext;
  lastNonceUpdateMs: number;
  lastBlockHeightUpdateMs: number;
};

type NearNoncePreviousContext = NearNonceMissingContext | NearNonceReadyContext;

export type NearNonceLaneLifecycle =
  | {
      kind: 'uninitialized';
    }
  | {
      kind: 'access_key_bound';
      subject: NearAccessKeySubject;
      context: NearNoncePreviousContext;
    }
  | {
      kind: 'access_key_lookup_pending';
      subject: NearAccessKeySubject;
      previousContext: NearNoncePreviousContext;
      promise: Promise<TransactionContext>;
    }
  | {
      kind: 'implicit_unfunded';
      subject: NearAccessKeySubject;
      readiness: Extract<NearExecutionReadiness, { kind: 'implicit_unfunded' }>;
    }
  | {
      kind: 'lookup_failed';
      subject: NearAccessKeySubject;
      readiness: Extract<NearExecutionReadiness, { kind: 'account_lookup_failed' }>;
    };

export type NearNonceLaneState = {
  lifecycle: NearNonceLaneLifecycle;
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

export type NearExecutionReadiness =
  | {
      kind: 'implicit_unfunded';
      walletId: string;
      nearAccountId: string;
      nearPublicKeyStr: string;
    }
  | {
      kind: 'access_key_available';
      walletId: string;
      nearAccountId: string;
      nearPublicKeyStr: string;
      nonce: bigint;
      accessKeyNonce: string;
      nextNonce: string;
      txBlockHeight: string;
      txBlockHash: string;
    }
  | {
      kind: 'sponsored_named_ready';
      walletId: string;
      nearAccountId: string;
      nearPublicKeyStr: string;
      nonce: bigint;
      accessKeyNonce: string;
      nextNonce: string;
      txBlockHeight: string;
      txBlockHash: string;
    }
  | {
      kind: 'account_lookup_failed';
      walletId: string;
      nearAccountId: string;
      nearPublicKeyStr: string;
      message: string;
    };

function readinessNonceFromTransactionContext(
  transactionContext: TransactionContext | null | undefined,
): bigint {
  const raw = String(
    transactionContext?.nextNonce ?? transactionContext?.accessKeyInfo?.nonce ?? '0',
  ).trim();
  if (!raw) return 0n;
  try {
    return BigInt(raw);
  } catch {
    return 0n;
  }
}

export function classifyNearExecutionReadiness(input: {
  walletId: string;
  nearAccountId: string;
  nearPublicKeyStr: string;
  accessKeyAvailable: boolean;
  transactionContext?: TransactionContext | null;
}): NearExecutionReadiness {
  const base = {
    walletId: String(input.walletId || '').trim(),
    nearAccountId: String(input.nearAccountId || '').trim(),
    nearPublicKeyStr: String(input.nearPublicKeyStr || '').trim(),
  };
  if (!input.accessKeyAvailable && isImplicitNearAccountId(base.nearAccountId)) {
    return {
      kind: 'implicit_unfunded',
      ...base,
    };
  }
  const ready = {
    ...base,
    nonce: readinessNonceFromTransactionContext(input.transactionContext),
    accessKeyNonce: String(input.transactionContext?.accessKeyInfo?.nonce ?? '').trim(),
    nextNonce: String(input.transactionContext?.nextNonce ?? '').trim(),
    txBlockHeight: String(input.transactionContext?.txBlockHeight ?? '').trim(),
    txBlockHash: String(input.transactionContext?.txBlockHash ?? '').trim(),
  };
  if (isImplicitNearAccountId(base.nearAccountId)) {
    return {
      kind: 'access_key_available',
      ...ready,
    };
  }
  return {
    kind: 'sponsored_named_ready',
    ...ready,
  };
}

export function readNearAccessKeySubject(state: NearNonceLaneState): NearAccessKeySubject | null {
  switch (state.lifecycle.kind) {
    case 'uninitialized':
      return null;
    case 'access_key_bound':
    case 'access_key_lookup_pending':
    case 'implicit_unfunded':
    case 'lookup_failed':
      return state.lifecycle.subject;
    default:
      return assertNeverNearNonceLaneLifecycle(state.lifecycle);
  }
}

export function requireNearAccessKeySubject(state: NearNonceLaneState): NearAccessKeySubject {
  const subject = readNearAccessKeySubject(state);
  if (!subject) {
    throw new Error('[NonceCoordinator] NEAR access key is not initialized');
  }
  return subject;
}

export function readNearTransactionContext(state: NearNonceLaneState): TransactionContext | null {
  const ready = readNearReadyContext(state.lifecycle);
  return ready?.transactionContext ?? null;
}

export function hasNearTransactionContext(state: NearNonceLaneState): boolean {
  return readNearTransactionContext(state) !== null;
}

export function hasNearInflightFetch(state: NearNonceLaneState): boolean {
  return readNearInflightFetch(state) !== null;
}

export function readNearActiveAccountId(state: NearNonceLaneState): string | null {
  return readNearAccessKeySubject(state)?.nearAccountId ?? null;
}

export function readNearActivePublicKey(state: NearNonceLaneState): string | null {
  return readNearAccessKeySubject(state)?.publicKey ?? null;
}

function readNearReadyContext(lifecycle: NearNonceLaneLifecycle): NearNonceReadyContext | null {
  switch (lifecycle.kind) {
    case 'uninitialized':
    case 'implicit_unfunded':
    case 'lookup_failed':
      return null;
    case 'access_key_bound':
      return lifecycle.context.kind === 'ready' ? lifecycle.context : null;
    case 'access_key_lookup_pending':
      return lifecycle.previousContext.kind === 'ready' ? lifecycle.previousContext : null;
    default:
      return assertNeverNearNonceLaneLifecycle(lifecycle);
  }
}

function readNearPreviousContext(lifecycle: NearNonceLaneLifecycle): NearNoncePreviousContext {
  const ready = readNearReadyContext(lifecycle);
  return ready ?? { kind: 'missing' };
}

function readNearInflightFetch(state: NearNonceLaneState): Promise<TransactionContext> | null {
  switch (state.lifecycle.kind) {
    case 'access_key_lookup_pending':
      return state.lifecycle.promise;
    case 'uninitialized':
    case 'access_key_bound':
    case 'implicit_unfunded':
    case 'lookup_failed':
      return null;
    default:
      return assertNeverNearNonceLaneLifecycle(state.lifecycle);
  }
}

function setNearAccessKeyReady(input: {
  state: NearNonceLaneState;
  subject: NearAccessKeySubject;
  transactionContext: TransactionContext;
  nowMs: number;
  updateNonce: boolean;
  updateBlock: boolean;
}): void {
  const previous = readNearReadyContext(input.state.lifecycle);
  input.state.lifecycle = {
    kind: 'access_key_bound',
    subject: input.subject,
    context: {
      kind: 'ready',
      transactionContext: input.transactionContext,
      lastNonceUpdateMs: input.updateNonce
        ? input.nowMs
        : (previous?.lastNonceUpdateMs ?? input.nowMs),
      lastBlockHeightUpdateMs: input.updateBlock
        ? input.nowMs
        : (previous?.lastBlockHeightUpdateMs ?? input.nowMs),
    },
  };
}

function setNearAccessKeyLookupPending(input: {
  state: NearNonceLaneState;
  subject: NearAccessKeySubject;
  promise: Promise<TransactionContext>;
}): void {
  input.state.lifecycle = {
    kind: 'access_key_lookup_pending',
    subject: input.subject,
    previousContext: readNearPreviousContext(input.state.lifecycle),
    promise: input.promise,
  };
}

function setNearImplicitUnfunded(input: {
  state: NearNonceLaneState;
  subject: NearAccessKeySubject;
}): void {
  input.state.lifecycle = {
    kind: 'implicit_unfunded',
    subject: input.subject,
    readiness: {
      kind: 'implicit_unfunded',
      walletId: input.subject.walletId,
      nearAccountId: input.subject.nearAccountId,
      nearPublicKeyStr: input.subject.publicKey,
    },
  };
}

function setNearLookupFailed(input: {
  state: NearNonceLaneState;
  subject: NearAccessKeySubject;
  message: string;
}): void {
  input.state.lifecycle = {
    kind: 'lookup_failed',
    subject: input.subject,
    readiness: {
      kind: 'account_lookup_failed',
      walletId: input.subject.walletId,
      nearAccountId: input.subject.nearAccountId,
      nearPublicKeyStr: input.subject.publicKey,
      message: input.message,
    },
  };
}

function assertNeverNearNonceLaneLifecycle(value: never): never {
  throw new Error(`[NonceCoordinator] unhandled NEAR nonce lane lifecycle: ${String(value)}`);
}

export function createNearNonceLaneState(): NearNonceLaneState {
  return {
    lifecycle: { kind: 'uninitialized' },
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
  const subject = readNearAccessKeySubject(state);
  state.lifecycle = subject
    ? {
        kind: 'access_key_bound',
        subject,
        context: { kind: 'missing' },
      }
    : { kind: 'uninitialized' };
  state.reservedNonces.clear();
  state.lastReservedNonce = null;
  state.inFlight.clear();
  clearNearRefreshTimer(state);
  clearNearPrefetchTimer(state);
}

export function clearNearAccessKeyState(state: NearNonceLaneState): void {
  state.lifecycle = { kind: 'uninitialized' };
  clearNearTransactionContext(state);
}

export function initializeNearAccessKeyState(input: {
  state: NearNonceLaneState;
  walletId: string;
  nearAccountId: string;
  publicKey: string;
}): void {
  const nearAccountId = normalizeRequiredString(input.nearAccountId, 'nearAccountId');
  const publicKey = normalizeRequiredString(input.publicKey, 'publicKey');
  const walletId = normalizeRequiredString(input.walletId, 'walletId');
  if (!walletId) {
    throw new Error('[NonceCoordinator] NEAR access key walletId is required');
  }
  const subject = { walletId, nearAccountId, publicKey };
  const currentSubject = readNearAccessKeySubject(input.state);
  if (
    currentSubject?.walletId === walletId &&
    currentSubject.nearAccountId === nearAccountId &&
    currentSubject.publicKey === publicKey
  ) {
    return;
  }
  input.state.lifecycle = {
    kind: 'access_key_bound',
    subject,
    context: { kind: 'missing' },
  };
  clearNearTransactionContext(input.state);
}

export function commitNearTransactionContextForState(input: {
  state: NearNonceLaneState;
  walletId: string;
  nearAccountId: string;
  publicKey: string;
  transactionContext: TransactionContext;
  nowMs: number;
}): void {
  initializeNearAccessKeyState({
    state: input.state,
    walletId: input.walletId,
    nearAccountId: input.nearAccountId,
    publicKey: input.publicKey,
  });
  setNearAccessKeyReady({
    state: input.state,
    subject: requireNearAccessKeySubject(input.state),
    transactionContext: input.transactionContext,
    nowMs: input.nowMs,
    updateNonce: true,
    updateBlock: true,
  });
}

export async function reserveNearNoncesFromState(input: {
  state: NearNonceLaneState;
  lane: NearNonceLane;
  countInput: number;
  readActiveLeaseNonces: (laneKey: string, input?: { lane?: NearNonceLane }) => Promise<Set<string>>;
}): Promise<string[]> {
  const transactionContext = readNearTransactionContext(input.state);
  if (!transactionContext) {
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
    BigInt(transactionContext.nextNonce),
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
    walletId: input.lane.walletId,
    nearAccountId: input.lane.nearAccountId,
    publicKey: input.lane.publicKey,
  });
  const accessKeyInfoRaw = await input.nearClient.viewAccessKey(
    input.lane.nearAccountId,
    input.lane.publicKey,
  );
  if (!isAccessKeyViewLike(accessKeyInfoRaw)) {
    throw new Error(`Access key not found or invalid for account ${input.lane.nearAccountId}`);
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
      accountId: input.lane.nearAccountId,
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

  const previousContext = readNearTransactionContext(input.state);
  const candidateNext = maxBigint(
    chainNextNonce,
    previousContext?.nextNonce ? BigInt(previousContext.nextNonce) : 0n,
    input.state.lastReservedNonce ? BigInt(input.state.lastReservedNonce) + 1n : 0n,
  );
  setNearAccessKeyReady({
    state: input.state,
    subject: {
      walletId: input.lane.walletId,
      nearAccountId: input.lane.nearAccountId,
      publicKey: input.lane.publicKey,
    },
    transactionContext: {
      ...(previousContext || {
      nearPublicKeyStr: input.lane.publicKey,
      txBlockHeight: '0',
      txBlockHash: '',
    }),
      accessKeyInfo,
      nextNonce: candidateNext.toString(),
    },
    nowMs: input.now(),
    updateNonce: true,
    updateBlock: false,
  });
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

export class NearImplicitAccountFundingRequiredError extends Error {
  readonly code = 'near_implicit_account_unfunded';
  readonly nearAccountId: string;
  readonly readiness: NearExecutionReadiness;

  constructor(args: { walletId: string; nearAccountId: string; nearPublicKeyStr: string }) {
    super(
      `NEAR implicit account ${args.nearAccountId} has no access key on-chain. Fund the account before direct NEAR signing.`,
    );
    this.name = 'NearImplicitAccountFundingRequiredError';
    this.nearAccountId = args.nearAccountId;
    this.readiness = classifyNearExecutionReadiness({
      walletId: args.walletId,
      nearAccountId: args.nearAccountId,
      nearPublicKeyStr: args.nearPublicKeyStr,
      accessKeyAvailable: false,
    });
  }
}

export class NearAccountLookupFailedError extends Error {
  readonly code = 'near_account_lookup_failed';
  readonly nearAccountId: string;
  readonly readiness: NearExecutionReadiness;

  constructor(args: {
    walletId: string;
    nearAccountId: string;
    nearPublicKeyStr: string;
    message: string;
  }) {
    super(args.message || `NEAR account ${args.nearAccountId} access key lookup failed.`);
    this.name = 'NearAccountLookupFailedError';
    this.nearAccountId = args.nearAccountId;
    this.readiness = {
      kind: 'account_lookup_failed',
      walletId: args.walletId,
      nearAccountId: args.nearAccountId,
      nearPublicKeyStr: args.nearPublicKeyStr,
      message: this.message,
    };
  }
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
  const inflightFetch = readNearInflightFetch(state);
  if (inflightFetch && !input.force) {
    return inflightFetch;
  }

  const capturedSubject = requireNearAccessKeySubject(state);
  const requestId = ++state.inflightId;
  const fetchPromise = (async () => {
    try {
      const nowMs = input.now();
      const readyContext = readNearReadyContext(state.lifecycle);
      const previousTransactionContext = readyContext?.transactionContext ?? null;
      const isNonceStale =
        input.force ||
        !readyContext ||
        nowMs - readyContext.lastNonceUpdateMs >= input.nonceFreshnessThresholdMs;
      const isBlockStale =
        input.force ||
        !readyContext ||
        nowMs - readyContext.lastBlockHeightUpdateMs >= input.blockFreshnessThresholdMs;

      let accessKeyInfo = previousTransactionContext?.accessKeyInfo;
      let txBlockHeight = previousTransactionContext?.txBlockHeight;
      let txBlockHash = previousTransactionContext?.txBlockHash;
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
                capturedSubject.nearAccountId,
                capturedSubject.publicKey,
              );
            } catch (error: unknown) {
              const message = errorMessage(error);
              if (isMissingNearAccessKeyError(message)) {
                if (isImplicitNearAccountId(capturedSubject.nearAccountId)) {
                  accessKeyError = new NearImplicitAccountFundingRequiredError({
                    walletId: capturedSubject.walletId,
                    nearAccountId: capturedSubject.nearAccountId,
                    nearPublicKeyStr: capturedSubject.publicKey,
                  });
                  return;
                }
                accessKeyError = new NearAccountLookupFailedError({
                  walletId: capturedSubject.walletId,
                  nearAccountId: capturedSubject.nearAccountId,
                  nearPublicKeyStr: capturedSubject.publicKey,
                  message,
                });
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
      if (accessKeyError) {
        if (accessKeyError instanceof NearImplicitAccountFundingRequiredError) {
          setNearImplicitUnfunded({ state, subject: capturedSubject });
        } else if (accessKeyError instanceof NearAccountLookupFailedError) {
          setNearLookupFailed({
            state,
            subject: capturedSubject,
            message: accessKeyError.message,
          });
        }
        throw accessKeyError;
      }
      if (blockError) throw blockError;

      if (fetchAccessKey) {
        accessKeyInfo = isAccessKeyViewLike(maybeAccessKey)
          ? normalizeAccessKeyView(maybeAccessKey)
          : previousTransactionContext?.accessKeyInfo || makePlaceholderAccessKey();
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
        previousTransactionContext?.nextNonce ? BigInt(previousTransactionContext.nextNonce) : 0n,
        state.lastReservedNonce ? BigInt(state.lastReservedNonce) + 1n : 0n,
        1n,
      );
      const transactionContext: TransactionContext = {
        nearPublicKeyStr: capturedSubject.publicKey,
        accessKeyInfo: accessKeyInfo!,
        nextNonce: nextCandidate.toString(),
        txBlockHeight: txBlockHeight!,
        txBlockHash: txBlockHash!,
      };

      if (
        nearAccessKeySubjectsMatch(readNearAccessKeySubject(state), capturedSubject) &&
        requestId === state.inflightId
      ) {
        setNearAccessKeyReady({
          state,
          subject: capturedSubject,
          transactionContext,
          nowMs: input.now(),
          updateNonce: fetchAccessKey,
          updateBlock: fetchBlock,
        });
      }
      return transactionContext;
    } finally {
      if (requestId === state.inflightId) {
        const subject = readNearAccessKeySubject(state);
        if (
          state.lifecycle.kind === 'access_key_lookup_pending' &&
          nearAccessKeySubjectsMatch(subject, capturedSubject)
        ) {
          state.lifecycle = {
            kind: 'access_key_bound',
            subject: capturedSubject,
            context: state.lifecycle.previousContext,
          };
        }
      }
    }
  })();

  setNearAccessKeyLookupPending({
    state,
    subject: capturedSubject,
    promise: fetchPromise,
  });
  return fetchPromise;
}

export async function updateNearNonceFromBlockchainState(input: {
  state: NearNonceLaneState;
  nearClient: NearClient;
  actualNonce: string;
  now: () => number;
}): Promise<void> {
  const { state } = input;
  const subject = requireNearAccessKeySubject(state);
  try {
    const accessKeyInfoRaw = await input.nearClient.viewAccessKey(subject.nearAccountId, subject.publicKey);
    if (!isAccessKeyViewLike(accessKeyInfoRaw)) {
      throw new Error(`Access key not found or invalid for account ${subject.nearAccountId}`);
    }
    const accessKeyInfo = normalizeAccessKeyView(accessKeyInfoRaw);
    const chainNonce = BigInt(accessKeyInfo.nonce);
    const actual = BigInt(input.actualNonce);
    const previousContext = readNearTransactionContext(state);
    const candidateNext = maxBigint(
      chainNonce + 1n,
      actual + 1n,
      previousContext?.nextNonce ? BigInt(previousContext.nextNonce) : 0n,
      state.lastReservedNonce ? BigInt(state.lastReservedNonce) + 1n : 0n,
    );

    setNearAccessKeyReady({
      state,
      subject,
      transactionContext: previousContext
        ? {
            ...previousContext,
            accessKeyInfo,
            nextNonce: candidateNext.toString(),
          }
        : {
            nearPublicKeyStr: subject.publicKey,
            accessKeyInfo,
            nextNonce: candidateNext.toString(),
            txBlockHeight: '0',
            txBlockHash: '',
          },
      nowMs: input.now(),
      updateNonce: true,
      updateBlock: false,
    });
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
      const previousContext = readNearTransactionContext(state);
      const candidateNext = maxBigint(
        actual + 1n,
        previousContext?.nextNonce ? BigInt(previousContext.nextNonce) : 0n,
        state.lastReservedNonce ? BigInt(state.lastReservedNonce) + 1n : 0n,
      );
      setNearAccessKeyReady({
        state,
        subject,
        transactionContext: previousContext
          ? {
              ...previousContext,
              nextNonce: candidateNext.toString(),
            }
          : {
              nearPublicKeyStr: subject.publicKey,
              accessKeyInfo: makePlaceholderAccessKey(),
              txBlockHeight: '0',
              txBlockHash: '',
              nextNonce: candidateNext.toString(),
            },
        nowMs: input.now(),
        updateNonce: true,
        updateBlock: false,
      });
    }
  }
}

export async function refreshNearNonceAfterBroadcastRejectedState(input: {
  state: NearNonceLaneState;
  nearClient: NearClient;
  now: () => number;
}): Promise<void> {
  const { state } = input;
  const subject = requireNearAccessKeySubject(state);
  const accessKeyInfoRaw = await input.nearClient.viewAccessKey(subject.nearAccountId, subject.publicKey);
  if (!isAccessKeyViewLike(accessKeyInfoRaw)) {
    throw new Error(`Access key not found or invalid for account ${subject.nearAccountId}`);
  }
  const accessKeyInfo = normalizeAccessKeyView(accessKeyInfoRaw);
  const chainNonce = BigInt(accessKeyInfo.nonce);
  const candidateNext = maxBigint(
    chainNonce + 1n,
    state.lastReservedNonce ? BigInt(state.lastReservedNonce) + 1n : 0n,
    1n,
  );
  const previousContext = readNearTransactionContext(state);

  setNearAccessKeyReady({
    state,
    subject,
    transactionContext: previousContext
      ? {
          ...previousContext,
          accessKeyInfo,
          nextNonce: candidateNext.toString(),
        }
      : {
          nearPublicKeyStr: subject.publicKey,
          accessKeyInfo,
          nextNonce: candidateNext.toString(),
          txBlockHeight: '0',
          txBlockHash: '',
        },
    nowMs: input.now(),
    updateNonce: true,
    updateBlock: false,
  });
  if (state.reservedNonces.size > 0) {
    const pruned = pruneReservedNearNonces(chainNonce, state.reservedNonces);
    state.reservedNonces = pruned.set;
    state.lastReservedNonce = pruned.lastReserved;
  }
}

export function shouldPrefetchNearContext(input: {
  state: NearNonceLaneState;
  nowMs: number;
  blockFreshnessThresholdMs: number;
}): boolean {
  const readyContext = readNearReadyContext(input.state.lifecycle);
  const blockStale =
    !readyContext ||
    input.nowMs - readyContext.lastBlockHeightUpdateMs >= input.blockFreshnessThresholdMs;
  const missingContext = !readyContext;
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

function nearAccessKeySubjectsMatch(
  left: NearAccessKeySubject | null,
  right: NearAccessKeySubject,
): boolean {
  return (
    left?.walletId === right.walletId &&
    left.nearAccountId === right.nearAccountId &&
    left.publicKey === right.publicKey
  );
}

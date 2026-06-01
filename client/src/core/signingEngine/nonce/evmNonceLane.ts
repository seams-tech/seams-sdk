import type { EvmNonceChain } from '@/core/rpcClients/evm/nonceBackend';
import type { EvmNonceLane } from './nonceTypes';
import { nonceLaneNetworkKey } from './nonceLaneKeys';

export type EvmNonceLaneState = {
  chainNonce: bigint | null;
  nextCandidate: bigint | null;
  inFlight: Map<string, EvmInFlightNonceRecord>;
  lastRefreshMs: number | null;
  inflightRefresh: Promise<bigint> | null;
};

export type EvmInFlightNonceRecord = {
  nonce: bigint;
  txHash?: `0x${string}`;
  status: 'accepted' | 'replaced';
  acceptedAtMs: number;
  updatedAtMs: number;
};

export function createEvmNonceLaneState(): EvmNonceLaneState {
  return {
    chainNonce: null,
    nextCandidate: null,
    inFlight: new Map<string, EvmInFlightNonceRecord>(),
    lastRefreshMs: null,
    inflightRefresh: null,
  };
}

export function readBlockedEvmInFlight(input: {
  state: EvmNonceLaneState;
  nowMs: number;
  staleInFlightThresholdMs: number;
}): { blockedNonce: bigint; ageMs: number } | null {
  const { state } = input;
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
  const ageMs = Math.max(0, input.nowMs - oldestUpdatedAtMs);
  if (ageMs < input.staleInFlightThresholdMs) return null;
  return { blockedNonce: oldestNonce, ageMs };
}

export function createEvmNonceLaneBlockedError(args: {
  lane: EvmNonceLane;
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
    `[NonceCoordinator] nonce lane blocked on ${nonceLaneNetworkKey(args.lane)} (nonce=${args.blockedNonce.toString()}) for ${args.ageMs}ms; reconcile or replace/dropped report required`,
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
    chain: args.lane.chainTarget.kind,
    networkKey: nonceLaneNetworkKey(args.lane),
    chainId: args.lane.chainTarget.chainId,
    blockedNonce: args.blockedNonce.toString(),
    ageMs: args.ageMs,
  };
  return error;
}

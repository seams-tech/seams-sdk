export type NearNonceLaneState = {
  accountId: string | null;
  publicKey: string | null;
  transactionContext: import('@/core/types/rpc').TransactionContext | null;
  lastNonceUpdate: number | null;
  lastBlockHeightUpdate: number | null;
  inflightFetch: Promise<import('@/core/types/rpc').TransactionContext> | null;
  inflightId: number;
  refreshTimer: ReturnType<typeof setTimeout> | null;
  prefetchTimer: ReturnType<typeof setTimeout> | null;
  reservedNonces: Set<string>;
  lastReservedNonce: string | null;
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
  };
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

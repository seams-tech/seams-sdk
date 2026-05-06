import {
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
} from '../../session/signingSession/ecdsaChainTarget';

export type NonceLifecycleMetricName =
  | 'broadcast_accepted'
  | 'broadcast_rejected'
  | 'finalized'
  | 'dropped'
  | 'replaced'
  | 'reconciled'
  | 'lane_blocked';

export type NonceLifecycleMetricEvent = {
  metric: NonceLifecycleMetricName;
  chainTarget: ThresholdEcdsaChainTarget;
  networkKey: string;
  chainId: number;
  sender: `0x${string}`;
  nonce: string;
  nonceKey?: string;
  nearAccountId?: string;
  txHash?: `0x${string}`;
  blockedNonce?: string;
  errorCode?: string;
};

export function emitNonceLifecycleMetric(event: NonceLifecycleMetricEvent): void {
  try {
    const networkKey = String(event.networkKey || '').trim();
    const nonce = String(event.nonce || '').trim();
    if (!networkKey || !nonce) return;

    console.debug('[nonce-lifecycle-metrics]', {
      metric: event.metric,
      chainTarget: thresholdEcdsaChainTargetKey(event.chainTarget),
      networkKey,
      chainId: event.chainId,
      sender: String(event.sender || '').trim().toLowerCase(),
      nonce,
      ...(event.nonceKey ? { nonceKey: String(event.nonceKey || '').trim() } : {}),
      ...(event.nearAccountId ? { nearAccountId: String(event.nearAccountId || '').trim() } : {}),
      ...(event.txHash ? { txHash: String(event.txHash || '').trim().toLowerCase() } : {}),
      ...(event.blockedNonce ? { blockedNonce: String(event.blockedNonce || '').trim() } : {}),
      ...(event.errorCode ? { errorCode: String(event.errorCode || '').trim().toLowerCase() } : {}),
      atMs: Date.now(),
    });
  } catch {}
}

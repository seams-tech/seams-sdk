export type ThresholdEd25519PresignMetricName =
  | 'ed25519_presign_pool_hit'
  | 'ed25519_presign_pool_miss'
  | 'ed25519_presign_refill_in_flight'
  | 'ed25519_one_rtt_finalize_ms'
  | 'ed25519_two_rtt_fallback_ms';

export type ThresholdEd25519PresignMetricEvent = {
  metric: ThresholdEd25519PresignMetricName;
  nearAccountId: string;
  nearNetworkId: string;
  operationId?: string;
  operationFingerprint?: string;
  durationMs?: number;
  depth?: number;
  targetDepth?: number;
  generation?: number;
};

export function emitThresholdEd25519PresignMetric(
  event: ThresholdEd25519PresignMetricEvent,
): void {
  try {
    const metric = String(event.metric || '').trim();
    const nearAccountId = String(event.nearAccountId || '').trim();
    const nearNetworkId = String(event.nearNetworkId || '').trim();
    if (!metric || !nearAccountId || !nearNetworkId) return;
    console.debug('[threshold-ed25519-presign-metrics]', {
      metric,
      nearAccountId,
      nearNetworkId,
      ...(event.operationId ? { operationId: String(event.operationId || '').trim() } : {}),
      ...(event.operationFingerprint
        ? { operationFingerprint: String(event.operationFingerprint || '').trim() }
        : {}),
      ...(typeof event.durationMs === 'number'
        ? { durationMs: Math.max(0, Math.floor(event.durationMs)) }
        : {}),
      ...(typeof event.depth === 'number' ? { depth: Math.max(0, Math.floor(event.depth)) } : {}),
      ...(typeof event.targetDepth === 'number'
        ? { targetDepth: Math.max(0, Math.floor(event.targetDepth)) }
        : {}),
      ...(typeof event.generation === 'number'
        ? { generation: Math.max(0, Math.floor(event.generation)) }
        : {}),
      atMs: Date.now(),
    });
  } catch {}
}

export type ThresholdSessionMetricCurve = 'ed25519' | 'ecdsa';

export type ThresholdSessionMetricName =
  | 'cache_hit'
  | 'rehydrate_hit'
  | 'rehydrate_fail'
  | 'session_mismatch';

export type ThresholdSessionMetricEvent = {
  metric: ThresholdSessionMetricName;
  curve: ThresholdSessionMetricCurve;
  source: string;
  sessionId?: string;
  reason?: string;
};

export function emitThresholdSessionMetric(event: ThresholdSessionMetricEvent): void {
  try {
    console.debug('[threshold-session-metrics]', {
      metric: event.metric,
      curve: event.curve,
      source: String(event.source || '').trim() || 'unknown',
      ...(event.sessionId ? { sessionId: String(event.sessionId || '').trim() } : {}),
      ...(event.reason ? { reason: String(event.reason || '').trim() } : {}),
      atMs: Date.now(),
    });
  } catch {}
}

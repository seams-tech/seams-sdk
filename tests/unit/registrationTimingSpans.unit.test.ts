import { expect, test } from '@playwright/test';
import { emitRegistrationTimingSpan } from '../../packages/wallet/src/SeamsWeb/operations/registration/registration';

const traceContext = {
  kind: 'router_ab_trace_context_v1' as const,
  value: '0123456789abcdef0123456789abcdef',
};

test.describe('registration timing spans', () => {
  test('emits only the sanitized correlation fields', () => {
    const spans: unknown[] = [];

    emitRegistrationTimingSpan({
      callback: (span) => spans.push(span),
      span: 'frontend.wallet_ready',
      outcome: 'success',
      durationMs: 12.6,
      traceContext,
    });

    expect(spans).toEqual([
      {
        event: 'seams_registration_timing_span_v1',
        span: 'frontend.wallet_ready',
        operation: 'registration',
        outcome: 'success',
        duration_ms: 13,
        trace_id: traceContext.value,
      },
    ]);
  });

  test('telemetry sink failures cannot change registration behavior', () => {
    expect(() =>
      emitRegistrationTimingSpan({
        callback: () => {
          throw new Error('sink failed');
        },
        span: 'registration.post_touch_id',
        outcome: 'success',
        durationMs: -5,
        traceContext,
      }),
    ).not.toThrow();
  });
});

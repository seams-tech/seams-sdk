import { expect, test } from '@playwright/test';
import {
  createRouterAbTraceContextV1,
  parseRouterAbTraceContextV1,
  ROUTER_AB_TRACE_ID_HEADER_V1,
} from '@shared/utils/routerAbTraceContext';

test.describe('Router A/B trace context boundary', () => {
  test('accepts only opaque canonical lowercase hexadecimal IDs', () => {
    expect(ROUTER_AB_TRACE_ID_HEADER_V1).toBe('x-seams-trace-id');
    expect(parseRouterAbTraceContextV1('0123456789abcdef0123456789abcdef')).toEqual({
      ok: true,
      value: {
        kind: 'router_ab_trace_context_v1',
        value: '0123456789abcdef0123456789abcdef',
      },
    });
    expect(parseRouterAbTraceContextV1('0123456789ABCDEF0123456789ABCDEF').ok).toBe(false);
    expect(parseRouterAbTraceContextV1('wallet-account-id').ok).toBe(false);
    expect(parseRouterAbTraceContextV1(null)).toMatchObject({ ok: false, reason: 'missing' });
  });

  test('generates a canonical opaque context without domain data', () => {
    const context = createRouterAbTraceContextV1();
    expect(context.kind).toBe('router_ab_trace_context_v1');
    expect(context.value).toMatch(/^[0-9a-f]{32}$/);
  });
});

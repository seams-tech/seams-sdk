export const ROUTER_AB_TRACE_ID_HEADER_V1 = 'x-seams-trace-id' as const;

const TRACE_ID_PATTERN = /^[0-9a-f]{32}$/;

export type RouterAbTraceContextV1 = {
  readonly kind: 'router_ab_trace_context_v1';
  readonly value: string;
};

export type RouterAbTraceContextParseResultV1 =
  | { readonly ok: true; readonly value: RouterAbTraceContextV1 }
  | {
      readonly ok: false;
      readonly reason: 'missing' | 'invalid';
      readonly message: string;
    };

export function parseRouterAbTraceContextV1(raw: unknown): RouterAbTraceContextParseResultV1 {
  if (raw === null || raw === undefined || raw === '') {
    return {
      ok: false,
      reason: 'missing',
      message: 'Router trace ID is missing',
    };
  }
  if (typeof raw !== 'string' || !TRACE_ID_PATTERN.test(raw)) {
    return {
      ok: false,
      reason: 'invalid',
      message: 'Router trace ID must be 32 lowercase hexadecimal characters',
    };
  }
  return {
    ok: true,
    value: {
      kind: 'router_ab_trace_context_v1',
      value: raw,
    },
  };
}

export function createRouterAbTraceContextV1(): RouterAbTraceContextV1 {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  let value = '';
  for (const byte of bytes) value += byte.toString(16).padStart(2, '0');
  return {
    kind: 'router_ab_trace_context_v1',
    value,
  };
}

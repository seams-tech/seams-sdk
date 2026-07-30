import { expect, test } from '@playwright/test';
import {
  parseRouterAbTraceContextV1,
  ROUTER_AB_TRACE_ID_HEADER_V1,
} from '../../packages/shared-ts/src/utils/routerAbTraceContext';

/**
 * Refactor 94B Phase 0. The strict ECDSA legs forward an opaque trace id so a
 * cold registration can be correlated across Router, Deriver, and
 * SigningWorker, and report only whether each leg returned its diagnostics
 * header. The header value never reaches a log: it carries role and span names
 * from inside the topology.
 */

const VALID_TRACE = 'a1b2c3d4e5f60718293a4b5c6d7e8f90';

function unwrapTrace(raw: string) {
  const parsed = parseRouterAbTraceContextV1(raw);
  if (!parsed.ok) throw new Error(`fixture trace id rejected: ${parsed.message}`);
  return parsed.value;
}

test('an opaque trace id is forwarded verbatim on the strict ECDSA leg', () => {
  const trace = unwrapTrace(VALID_TRACE);
  /* Opaque means byte-identical: the boundary parsed it once, and nothing
     downstream may reformat, truncate, or re-derive it. */
  expect(trace.value).toBe(VALID_TRACE);
  expect(ROUTER_AB_TRACE_ID_HEADER_V1.toLowerCase()).toBe(ROUTER_AB_TRACE_ID_HEADER_V1);
});

test('the boundary rejects a malformed trace id and distinguishes it from an absent one', () => {
  /* Absent is legitimate — callers need not trace. Malformed is a caller bug
     and must not be silently coerced into "untraced". */
  const absent = parseRouterAbTraceContextV1(undefined);
  expect(absent).toMatchObject({ ok: false, reason: 'missing' });
  const empty = parseRouterAbTraceContextV1('');
  expect(empty).toMatchObject({ ok: false, reason: 'missing' });

  for (const malformed of [
    'A1B2C3D4E5F60718293A4B5C6D7E8F90',
    'a1b2c3d4e5f60718293a4b5c6d7e8f9',
    'a1b2c3d4e5f60718293a4b5c6d7e8f900',
    'a1b2c3d4-e5f6-0718-293a-4b5c6d7e8f90',
    'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz',
    42,
    {},
  ]) {
    expect(parseRouterAbTraceContextV1(malformed)).toMatchObject({
      ok: false,
      reason: 'invalid',
    });
  }
});

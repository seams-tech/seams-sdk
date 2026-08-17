import { expect, test } from '@playwright/test';
import { parseYaoServerTimingBuckets } from '../../packages/sdk-web/src/SeamsWeb/operations/registration/registration';
import { mergeRouterServerTiming } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/registration/d1WalletRegistrationService';

/*
 * Refactor 94B Phase 0. Gateway ECDSA boundary timings ride a `Server-Timing`
 * response header, never the wire body. These specs pin the two properties
 * that keep that safe: the body is unchanged, and nothing the header contains
 * can influence registration.
 */

/** Mirrors takeEcdsaGatewayServerTiming in walletRegistrationRoutes.ts. */
function takeGatewayServerTiming<
  T extends { ok: boolean; gatewayServerTiming?: readonly (readonly [string, number])[] },
>(result: T): { body: T; headers?: Record<string, string> } {
  if (!result.ok || !result.gatewayServerTiming?.length) {
    const { gatewayServerTiming: _dropped, ...body } = result;
    return { body: body as T };
  }
  const header = result.gatewayServerTiming
    .map(([name, durationMs]) => `${name};dur=${Math.max(0, durationMs).toFixed(1)}`)
    .join(', ');
  const { gatewayServerTiming: _stripped, ...body } = result;
  return { body: body as T, headers: { 'Server-Timing': header } };
}

const RESPOND_BODY = {
  ok: true as const,
  registrationCeremonyId: 'ceremony-1',
  ecdsa: {
    kind: 'router_ab_ecdsa_registration_forwarded_v1' as const,
    strictResult: { opaque: 'payload' },
  },
};

test('gateway timings never reach the response body', () => {
  const withTiming = {
    ...RESPOND_BODY,
    gatewayServerTiming: [
      ['ecdsa_respond_d1_claim', 12],
      ['ecdsa_respond_router', 2102],
      ['ecdsa_respond_total', 2130],
    ] as const,
  };

  const { body, headers } = takeGatewayServerTiming(withTiming);

  // The wire body must be byte-identical to the uninstrumented response.
  expect(JSON.stringify(body)).toBe(JSON.stringify(RESPOND_BODY));
  expect('gatewayServerTiming' in body).toBe(false);
  expect(headers?.['Server-Timing']).toBe(
    'ecdsa_respond_d1_claim;dur=12.0, ecdsa_respond_router;dur=2102.0, ecdsa_respond_total;dur=2130.0',
  );
});

test('a failed response carries no timing header and no timing field', () => {
  const failure = { ok: false as const, code: 'invalid_state', message: 'nope' };
  const { body, headers } = takeGatewayServerTiming(failure);
  expect(JSON.stringify(body)).toBe(JSON.stringify(failure));
  expect(headers).toBeUndefined();
});

test('an empty timing list produces no header rather than an empty one', () => {
  const { body, headers } = takeGatewayServerTiming({ ...RESPOND_BODY, gatewayServerTiming: [] });
  expect(JSON.stringify(body)).toBe(JSON.stringify(RESPOND_BODY));
  expect(headers).toBeUndefined();
});

test('negative durations are clamped rather than emitted', () => {
  const { headers } = takeGatewayServerTiming({
    ...RESPOND_BODY,
    gatewayServerTiming: [['ecdsa_respond_d1_claim', -5]] as const,
  });
  expect(headers?.['Server-Timing']).toBe('ecdsa_respond_d1_claim;dur=0.0');
});

test('unknown and malformed metrics cannot affect registration', () => {
  // The browser parser ignores everything it does not recognise, so a Router
  // rename, an injected metric, or a garbage duration yields no buckets at all
  // rather than a bad value flowing into timing state.
  // A genuinely unknown metric is dropped; a recognised one is not.
  expect(parseYaoServerTimingBuckets('ecdsa_respond_unmeasured;dur=2102')).toEqual([]);
  expect(parseYaoServerTimingBuckets('ecdsa_respond_router;dur=2102')).toEqual([
    ['ecdsaRespondRouterMs', 2102],
  ]);
  expect(parseYaoServerTimingBuckets('yao_d1_claim;dur=not-a-number')).toEqual([]);
  expect(parseYaoServerTimingBuckets('yao_d1_claim;dur=-1')).toEqual([]);
  expect(parseYaoServerTimingBuckets('__proto__;dur=1, constructor;dur=2')).toEqual([]);
  // A recognised metric still parses when surrounded by noise.
  expect(parseYaoServerTimingBuckets('cfCacheStatus;desc="HIT", yao_d1_claim;dur=7, junk')).toEqual(
    [['yaoServerD1ClaimMs', 7]],
  );
});

/*
 * The Router's own header is folded into the Gateway's span list at the
 * service binding, so the Router and role-worker breakdown reaches the browser
 * on one header. That fold is the only place the Gateway re-emits bytes it did
 * not author, so these specs pin its bounds.
 */

test('router spans are folded into the gateway span list', () => {
  const gateway: Array<readonly [string, number]> = [['ecdsa_respond_d1_claim', 12]];
  mergeRouterServerTiming(
    gateway,
    'ecdsa_rt_admission;dur=31, ecdsa_rt_derivers;dur=1840, ecdsa_a_preload;dur=910',
  );
  expect(gateway).toEqual([
    ['ecdsa_respond_d1_claim', 12],
    ['ecdsa_rt_admission', 31],
    ['ecdsa_rt_derivers', 1840],
    ['ecdsa_a_preload', 910],
  ]);
});

test('a metric name cannot forge extra entries downstream', () => {
  const gateway: Array<readonly [string, number]> = [];
  // The browser parses `name;dur=x` pairs out of one header, so a name
  // carrying separators or quotes must never survive the fold.
  mergeRouterServerTiming(gateway, 'ecdsa_rt total;dur=1, "quoted";dur=2, ok_name;dur=3');
  expect(gateway).toEqual([['ok_name', 3]]);
});

test('malformed and descriptive router metrics are dropped', () => {
  const gateway: Array<readonly [string, number]> = [];
  mergeRouterServerTiming(
    gateway,
    'cfCacheStatus;desc="HIT", ecdsa_rt_total;dur=NaN, ecdsa_rt_admission;dur=-4, bare',
  );
  expect(gateway).toEqual([]);
});

test('the fold is bounded so a chatty peer cannot grow the header without limit', () => {
  const gateway: Array<readonly [string, number]> = [];
  const flood = Array.from({ length: 100 }, (_, index) => `m${index};dur=1`).join(', ');
  mergeRouterServerTiming(gateway, flood);
  expect(gateway).toHaveLength(32);
  expect(gateway[0]).toEqual(['m0', 1]);
  expect(gateway[31]).toEqual(['m31', 1]);
});

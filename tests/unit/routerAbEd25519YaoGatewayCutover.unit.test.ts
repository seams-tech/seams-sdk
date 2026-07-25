import { expect, test } from '@playwright/test';
import { resolveRouterAbEd25519YaoGatewayRegistrationRouteV1 } from '../../packages/sdk-server-ts/src/router/cloudflare/routerAbEd25519YaoGatewayCutover';

test('keeps admission and execute on the legacy runtime throughout the drain window', () => {
  const drainUntilMs = 2_000;
  const operations = ['registration_admission', 'registration_execute'] as const;
  for (const operation of operations) {
    expect(
      resolveRouterAbEd25519YaoGatewayRegistrationRouteV1({
        operation,
        nowMs: 1_999,
        drainUntilMs,
      }),
    ).toEqual({ kind: 'legacy_runtime', drainUntilMs });
  }
});

test('enables both registration operations only after the drain boundary', () => {
  const drainUntilMs = 2_000;
  const routes = (['registration_admission', 'registration_execute'] as const).map((operation) =>
    resolveRouterAbEd25519YaoGatewayRegistrationRouteV1({
      operation,
      nowMs: drainUntilMs,
      drainUntilMs,
    }),
  );
  expect(routes).toEqual([
    { kind: 'partitioned_d1', drainUntilMs },
    { kind: 'partitioned_d1', drainUntilMs },
  ]);
});

test('rejects invalid deployment timestamps', () => {
  expect(() =>
    resolveRouterAbEd25519YaoGatewayRegistrationRouteV1({
      operation: 'registration_admission',
      nowMs: -1,
      drainUntilMs: 2_000,
    }),
  ).toThrow('nowMs');
  expect(() =>
    resolveRouterAbEd25519YaoGatewayRegistrationRouteV1({
      operation: 'registration_execute',
      nowMs: 1_000,
      drainUntilMs: Number.POSITIVE_INFINITY,
    }),
  ).toThrow('drainUntilMs');
});

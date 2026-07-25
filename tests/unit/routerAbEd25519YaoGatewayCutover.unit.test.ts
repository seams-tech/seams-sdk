import { expect, test } from '@playwright/test';
import { resolveRouterAbEd25519YaoGatewayRegistrationRouteV1 } from '../../packages/sdk-server-ts/src/router/cloudflare/routerAbEd25519YaoGatewayCutover';

test('keeps admission and execute on the legacy runtime throughout the drain window', () => {
  const admissionCutoffMs = 2_000;
  const drainUntilMs = 12_000;
  const operations = ['registration_admission', 'registration_execute'] as const;
  for (const operation of operations) {
    expect(
      resolveRouterAbEd25519YaoGatewayRegistrationRouteV1({
        operation,
        nowMs: 1_999,
        admissionCutoffMs,
        drainUntilMs,
      }),
    ).toEqual({ kind: 'legacy_runtime', admissionCutoffMs, drainUntilMs });
  }
});

test('blocks new admissions while allowing old executes to drain', () => {
  const admissionCutoffMs = 2_000;
  const drainUntilMs = 12_000;
  expect(
    resolveRouterAbEd25519YaoGatewayRegistrationRouteV1({
      operation: 'registration_admission',
      nowMs: admissionCutoffMs,
      admissionCutoffMs,
      drainUntilMs,
    }),
  ).toEqual({ kind: 'admission_blocked', admissionCutoffMs, drainUntilMs });
  expect(
    resolveRouterAbEd25519YaoGatewayRegistrationRouteV1({
      operation: 'registration_execute',
      nowMs: admissionCutoffMs,
      admissionCutoffMs,
      drainUntilMs,
    }),
  ).toEqual({ kind: 'legacy_runtime', admissionCutoffMs, drainUntilMs });
});

test('enables both registration operations only after the final drain boundary', () => {
  const admissionCutoffMs = 2_000;
  const drainUntilMs = 12_000;
  const routes = (['registration_admission', 'registration_execute'] as const).map((operation) =>
    resolveRouterAbEd25519YaoGatewayRegistrationRouteV1({
      operation,
      nowMs: drainUntilMs,
      admissionCutoffMs,
      drainUntilMs,
    }),
  );
  expect(routes).toEqual([
    { kind: 'partitioned_d1', admissionCutoffMs, drainUntilMs },
    { kind: 'partitioned_d1', admissionCutoffMs, drainUntilMs },
  ]);
});

test('rejects invalid deployment timestamps', () => {
  expect(() =>
    resolveRouterAbEd25519YaoGatewayRegistrationRouteV1({
      operation: 'registration_admission',
      nowMs: -1,
      admissionCutoffMs: 1_000,
      drainUntilMs: 2_000,
    }),
  ).toThrow('nowMs');
  expect(() =>
    resolveRouterAbEd25519YaoGatewayRegistrationRouteV1({
      operation: 'registration_execute',
      nowMs: 1_000,
      admissionCutoffMs: 2_000,
      drainUntilMs: Number.POSITIVE_INFINITY,
    }),
  ).toThrow('drainUntilMs');
  expect(() =>
    resolveRouterAbEd25519YaoGatewayRegistrationRouteV1({
      operation: 'registration_execute',
      nowMs: 1_000,
      admissionCutoffMs: 3_000,
      drainUntilMs: 2_000,
    }),
  ).toThrow('admissionCutoffMs');
});

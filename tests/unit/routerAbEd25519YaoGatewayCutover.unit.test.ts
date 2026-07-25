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
        cutover: { registration: { admissionCutoffMs, drainUntilMs } },
      }),
    ).toEqual({ kind: 'legacy_runtime', window: { admissionCutoffMs, drainUntilMs } });
  }
});

test('blocks new admissions while allowing old executes to drain', () => {
  const admissionCutoffMs = 2_000;
  const drainUntilMs = 12_000;
  expect(
    resolveRouterAbEd25519YaoGatewayRegistrationRouteV1({
      operation: 'registration_admission',
      nowMs: admissionCutoffMs,
      cutover: { registration: { admissionCutoffMs, drainUntilMs } },
    }),
  ).toEqual({ kind: 'admission_blocked', window: { admissionCutoffMs, drainUntilMs } });
  expect(
    resolveRouterAbEd25519YaoGatewayRegistrationRouteV1({
      operation: 'registration_execute',
      nowMs: admissionCutoffMs,
      cutover: { registration: { admissionCutoffMs, drainUntilMs } },
    }),
  ).toEqual({ kind: 'legacy_runtime', window: { admissionCutoffMs, drainUntilMs } });
});

test('enables both registration operations only after the final drain boundary', () => {
  const admissionCutoffMs = 2_000;
  const drainUntilMs = 12_000;
  const routes = (['registration_admission', 'registration_execute'] as const).map((operation) =>
    resolveRouterAbEd25519YaoGatewayRegistrationRouteV1({
      operation,
      nowMs: drainUntilMs,
      cutover: { registration: { admissionCutoffMs, drainUntilMs } },
    }),
  );
  expect(routes).toEqual([
    { kind: 'partitioned_d1', window: { admissionCutoffMs, drainUntilMs } },
    { kind: 'partitioned_d1', window: { admissionCutoffMs, drainUntilMs } },
  ]);
});

test('rejects invalid deployment timestamps', () => {
  expect(() =>
    resolveRouterAbEd25519YaoGatewayRegistrationRouteV1({
      operation: 'registration_admission',
      nowMs: -1,
      cutover: { registration: { admissionCutoffMs: 1_000, drainUntilMs: 2_000 } },
    }),
  ).toThrow('nowMs');
  expect(() =>
    resolveRouterAbEd25519YaoGatewayRegistrationRouteV1({
      operation: 'registration_execute',
      nowMs: 1_000,
      cutover: { registration: { admissionCutoffMs: 2_000, drainUntilMs: Number.POSITIVE_INFINITY } },
    }),
  ).toThrow('drainUntilMs');
  expect(() =>
    resolveRouterAbEd25519YaoGatewayRegistrationRouteV1({
      operation: 'registration_execute',
      nowMs: 1_000,
      cutover: { registration: { admissionCutoffMs: 3_000, drainUntilMs: 2_000 } },
    }),
  ).toThrow('admissionCutoffMs');
});

test('every ceremony phase pairs with the store its admission used', () => {
  const window = { admissionCutoffMs: 1_000, drainUntilMs: 2_000 } as const;
  const all = { registration: window, recovery: window, export: window } as const;
  const admissions = ['registration_admission', 'recovery_admission', 'export_admission'] as const;
  const continuations = [
    'registration_execute',
    'recovery_execute',
    'recovery_activate',
    'export_execute',
  ] as const;

  for (const operation of [...admissions, ...continuations]) {
    expect(
      resolveRouterAbEd25519YaoGatewayRegistrationRouteV1({ operation, nowMs: 500, cutover: all }).kind,
    ).toBe('legacy_runtime');
    expect(
      resolveRouterAbEd25519YaoGatewayRegistrationRouteV1({ operation, nowMs: 2_500, cutover: all })
        .kind,
    ).toBe('partitioned_d1');
  }

  // Inside the drain only admission stops, so a ceremony admitted before the
  // cutoff finishes every remaining phase on the store it started on.
  for (const operation of admissions) {
    expect(
      resolveRouterAbEd25519YaoGatewayRegistrationRouteV1({ operation, nowMs: 1_500, cutover: all })
        .kind,
    ).toBe('admission_blocked');
  }
  for (const operation of continuations) {
    expect(
      resolveRouterAbEd25519YaoGatewayRegistrationRouteV1({ operation, nowMs: 1_500, cutover: all })
        .kind,
    ).toBe('legacy_runtime');
  }
});

test('a family with no configured window stays on the legacy runtime', () => {
  // Registration has fully drained; recovery and export have not been cut over.
  const cutover = {
    registration: { admissionCutoffMs: 1_000, drainUntilMs: 2_000 },
  } as const;

  expect(
    resolveRouterAbEd25519YaoGatewayRegistrationRouteV1({
      operation: 'registration_admission',
      nowMs: 9_000,
      cutover,
    }).kind,
  ).toBe('partitioned_d1');

  // Sharing registration's elapsed window would send these straight to D1 with
  // no drain, stranding ceremonies admitted against the legacy runtime.
  for (const operation of ['recovery_admission', 'recovery_activate', 'export_execute'] as const) {
    expect(
      resolveRouterAbEd25519YaoGatewayRegistrationRouteV1({ operation, nowMs: 9_000, cutover }).kind,
    ).toBe('legacy_runtime');
  }
});

test('each family drains on its own schedule', () => {
  const cutover = {
    registration: { admissionCutoffMs: 1_000, drainUntilMs: 2_000 },
    recovery: { admissionCutoffMs: 8_000, drainUntilMs: 9_000 },
  } as const;

  expect(
    resolveRouterAbEd25519YaoGatewayRegistrationRouteV1({
      operation: 'registration_admission',
      nowMs: 8_500,
      cutover,
    }).kind,
  ).toBe('partitioned_d1');
  expect(
    resolveRouterAbEd25519YaoGatewayRegistrationRouteV1({
      operation: 'recovery_admission',
      nowMs: 8_500,
      cutover,
    }).kind,
  ).toBe('admission_blocked');
  expect(
    resolveRouterAbEd25519YaoGatewayRegistrationRouteV1({
      operation: 'recovery_execute',
      nowMs: 8_500,
      cutover,
    }).kind,
  ).toBe('legacy_runtime');
});

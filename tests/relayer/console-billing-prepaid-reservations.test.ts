import { expect, test } from '@playwright/test';
import {
  createInMemoryConsoleBillingPrepaidReservationService,
  createPostgresConsoleBillingPrepaidReservationService,
} from '@server/router/express-adaptor';
import { withConsoleTenantContextTx } from '../../packages/sdk-server-ts/src/console/shared/postgresTenantContext';
import { getPostgresPool } from '../../packages/sdk-server-ts/src/storage/postgres';

function randomNamespace(prefix: string): string {
  return `${prefix}:${Date.now()}:${Math.random().toString(16).slice(2)}`;
}

async function expectReservationError(fn: () => Promise<unknown>, code: string): Promise<void> {
  let caught: any;
  try {
    await fn();
  } catch (error: unknown) {
    caught = error;
  }
  expect(caught).toBeTruthy();
  expect(String(caught?.code || '')).toBe(code);
}

test.describe('console billing prepaid reservations', () => {
  const baseNow = new Date('2026-03-17T10:00:00.000Z');
  const ctx = {
    orgId: 'org-console-billing-prepaid-reservations',
    actorUserId: 'user-console-billing-prepaid-reservations',
    roles: ['admin'],
  };

  test('in-memory reservation service tracks org-scoped available balance and expires stale holds', async () => {
    let currentNowMs = baseNow.getTime();
    const service = createInMemoryConsoleBillingPrepaidReservationService({
      now: () => new Date(currentNowMs),
      defaultReservationTtlMs: 60_000,
    });

    const first = await service.reserve(ctx, {
      sourceEventId: 'mem-reserve-1',
      environmentId: 'dev',
      policyId: 'policy-org-balance',
      postedBalanceMinor: 500,
      estimatedSpendMinor: 200,
    });
    expect(first.summary.reservedMinor).toBe(200);
    expect(first.summary.activeReservationCount).toBe(1);
    expect(first.availableBalanceMinor).toBe(300);

    const duplicate = await service.reserve(ctx, {
      sourceEventId: 'mem-reserve-1',
      environmentId: 'dev',
      policyId: 'policy-org-balance',
      postedBalanceMinor: 500,
      estimatedSpendMinor: 200,
    });
    expect(duplicate.reservation.id).toBe(first.reservation.id);
    expect(duplicate.summary.reservedMinor).toBe(200);
    expect(duplicate.summary.activeReservationCount).toBe(1);

    await expectReservationError(
      async () =>
        await service.reserve(ctx, {
          sourceEventId: 'mem-reserve-2',
          environmentId: 'dev',
          policyId: 'policy-org-balance',
          postedBalanceMinor: 500,
          estimatedSpendMinor: 400,
        }),
      'prepaid_balance_insufficient',
    );

    const settled = await service.settle(ctx, {
      sourceEventId: 'mem-reserve-1',
      settledSpendMinor: 150,
      txOrExecutionRef: '0xsettled',
      pricingVersion: 'static:v1',
    });
    expect(settled?.reservation.status).toBe('SETTLED');
    expect(settled?.reservation.settledMinor).toBe(150);
    expect(settled?.reservation.releasedMinor).toBe(50);
    expect(settled?.summary.reservedMinor).toBe(0);
    expect(settled?.summary.activeReservationCount).toBe(0);

    const releasable = await service.reserve(ctx, {
      sourceEventId: 'mem-release-1',
      environmentId: 'dev',
      policyId: 'policy-org-balance',
      postedBalanceMinor: 500,
      estimatedSpendMinor: 125,
    });
    expect(releasable.summary.reservedMinor).toBe(125);

    const released = await service.release(ctx, {
      sourceEventId: 'mem-release-1',
    });
    expect(released?.reservation.status).toBe('RELEASED');
    expect(released?.reservation.releasedMinor).toBe(125);
    expect(released?.summary.reservedMinor).toBe(0);
    expect(released?.summary.activeReservationCount).toBe(0);

    await service.reserve(ctx, {
      sourceEventId: 'mem-expire-1',
      environmentId: 'dev',
      policyId: 'policy-org-balance',
      postedBalanceMinor: 500,
      estimatedSpendMinor: 300,
    });
    currentNowMs += 120_000;
    const expired = await service.expireStaleReservations({
      at: new Date(currentNowMs),
    });
    expect(expired.expiredCount).toBe(1);
    const expiredReservation = await service.getReservationBySourceEventId(ctx, 'mem-expire-1');
    expect(expiredReservation?.status).toBe('EXPIRED');
    expect(expiredReservation?.releasedMinor).toBe(300);
    const summary = await service.getSummary(ctx);
    expect(summary.reservedMinor).toBe(0);
    expect(summary.activeReservationCount).toBe(0);
  });

  test('in-memory: underestimation settles above reserved amount and negative posted balance blocks future reservations', async () => {
    const service = createInMemoryConsoleBillingPrepaidReservationService({
      now: () => new Date(baseNow),
      defaultReservationTtlMs: 60_000,
    });

    const reserved = await service.reserve(ctx, {
      sourceEventId: 'mem-underestimate-1',
      environmentId: 'dev',
      policyId: 'policy-1',
      postedBalanceMinor: 500,
      estimatedSpendMinor: 100,
    });
    expect(reserved.reservation.requestedMinor).toBe(100);
    expect(reserved.availableBalanceMinor).toBe(400);

    // Settle at higher amount than estimated (underestimation scenario)
    const settled = await service.settle(ctx, {
      sourceEventId: 'mem-underestimate-1',
      settledSpendMinor: 200,
      txOrExecutionRef: '0xunderest',
      pricingVersion: 'static:v1',
    });
    expect(settled?.reservation.status).toBe('SETTLED');
    expect(settled?.reservation.settledMinor).toBe(200);
    // releasedMinor is 0 because settled > requested
    expect(settled?.reservation.releasedMinor).toBe(0);
    expect(settled?.summary.reservedMinor).toBe(0);
    expect(settled?.summary.activeReservationCount).toBe(0);

    // After the billing debit of 200 on a 500 balance, posted balance would be 300.
    // But if the org spent more than their balance, posted balance can go negative.
    // Simulate negative posted balance: org had 50, reserved 30, settled 80 → balance is -30.
    const reserved2 = await service.reserve(ctx, {
      sourceEventId: 'mem-underestimate-2',
      environmentId: 'dev',
      policyId: 'policy-1',
      postedBalanceMinor: 50,
      estimatedSpendMinor: 30,
    });
    expect(reserved2.availableBalanceMinor).toBe(20);

    const settled2 = await service.settle(ctx, {
      sourceEventId: 'mem-underestimate-2',
      settledSpendMinor: 80,
      txOrExecutionRef: '0xunderest-2',
      pricingVersion: 'static:v1',
    });
    expect(settled2?.reservation.settledMinor).toBe(80);

    // Future reservation with negative posted balance should be rejected
    await expectReservationError(
      async () =>
        await service.reserve(ctx, {
          sourceEventId: 'mem-underestimate-blocked',
          environmentId: 'dev',
          policyId: 'policy-1',
          postedBalanceMinor: -30,
          estimatedSpendMinor: 10,
        }),
      'prepaid_balance_insufficient',
    );

    // Zero posted balance should also be rejected
    await expectReservationError(
      async () =>
        await service.reserve(ctx, {
          sourceEventId: 'mem-underestimate-zero',
          environmentId: 'dev',
          policyId: 'policy-1',
          postedBalanceMinor: 0,
          estimatedSpendMinor: 10,
        }),
      'prepaid_balance_insufficient',
    );
  });

  test.describe('Postgres', () => {
    const postgresUrl = String(process.env.POSTGRES_URL || '').trim();
    const enabled = Boolean(postgresUrl);
    const namespace = randomNamespace('test:console-billing-prepaid-reservations:postgres');

    test.afterAll(async () => {
      if (!enabled) return;
      const pool = await getPostgresPool(postgresUrl);
      await withConsoleTenantContextTx(pool, { namespace, orgId: ctx.orgId }, async (q) => {
        await q.query('DELETE FROM console_billing_prepaid_reservations WHERE namespace = $1', [
          namespace,
        ]);
        await q.query(
          'DELETE FROM console_billing_prepaid_reservation_summaries WHERE namespace = $1',
          [namespace],
        );
      });
    });

    test('postgres reservation service reserves atomically and reconciles settle and release flows', async () => {
      test.skip(!enabled, 'POSTGRES_URL not set');
      const service = await createPostgresConsoleBillingPrepaidReservationService({
        postgresUrl,
        namespace,
        logger: console as any,
        ensureSchema: true,
        now: () => new Date(baseNow),
        defaultReservationTtlMs: 60_000,
      });

      const concurrentResults = await Promise.allSettled([
        service.reserve(ctx, {
          sourceEventId: 'pg-reserve-1',
          environmentId: 'prod',
          policyId: 'policy-org-balance',
          postedBalanceMinor: 1_000,
          estimatedSpendMinor: 700,
        }),
        service.reserve(ctx, {
          sourceEventId: 'pg-reserve-2',
          environmentId: 'prod',
          policyId: 'policy-org-balance',
          postedBalanceMinor: 1_000,
          estimatedSpendMinor: 400,
        }),
      ]);

      const fulfilled = concurrentResults.filter((entry) => entry.status === 'fulfilled');
      const rejected = concurrentResults.filter((entry) => entry.status === 'rejected');
      expect(fulfilled).toHaveLength(1);
      expect(rejected).toHaveLength(1);
      expect(String((rejected[0] as PromiseRejectedResult).reason?.code || '')).toBe(
        'prepaid_balance_insufficient',
      );

      const reserved = (fulfilled[0] as PromiseFulfilledResult<
        Awaited<ReturnType<typeof service.reserve>>
      >).value;
      expect(['pg-reserve-1', 'pg-reserve-2']).toContain(reserved.reservation.sourceEventId);
      expect(reserved.summary.reservedMinor).toBe(reserved.reservation.requestedMinor);
      expect(reserved.summary.activeReservationCount).toBe(1);

      const duplicate = await service.reserve(ctx, {
        sourceEventId: reserved.reservation.sourceEventId,
        environmentId: 'prod',
        policyId: 'policy-org-balance',
        postedBalanceMinor: 1_000,
        estimatedSpendMinor: reserved.reservation.requestedMinor,
      });
      expect(duplicate.reservation.id).toBe(reserved.reservation.id);
      expect(duplicate.summary.reservedMinor).toBe(reserved.summary.reservedMinor);

      const settled = await service.settle(ctx, {
        sourceEventId: reserved.reservation.sourceEventId,
        settledSpendMinor: 450,
        txOrExecutionRef: '0xpg-settle',
        pricingVersion: 'static:v1',
      });
      expect(settled?.reservation.status).toBe('SETTLED');
      expect(settled?.reservation.settledMinor).toBe(450);
      expect(settled?.reservation.releasedMinor).toBe(
        Math.max(reserved.reservation.requestedMinor - 450, 0),
      );
      expect(settled?.summary.reservedMinor).toBe(0);
      expect(settled?.summary.activeReservationCount).toBe(0);

      const releaseCandidate = await service.reserve(ctx, {
        sourceEventId: 'pg-release-1',
        environmentId: 'prod',
        policyId: 'policy-org-balance',
        postedBalanceMinor: 1_000,
        estimatedSpendMinor: 200,
      });
      expect(releaseCandidate.summary.reservedMinor).toBe(200);

      const released = await service.release(ctx, {
        sourceEventId: 'pg-release-1',
      });
      expect(released?.reservation.status).toBe('RELEASED');
      expect(released?.reservation.releasedMinor).toBe(200);
      expect(released?.summary.reservedMinor).toBe(0);
      expect(released?.summary.activeReservationCount).toBe(0);
    });

    test('postgres reservation service survives same-org burst traffic without overspending posted balance', async () => {
      test.skip(!enabled, 'POSTGRES_URL not set');
      const service = await createPostgresConsoleBillingPrepaidReservationService({
        postgresUrl,
        namespace,
        logger: console as any,
        ensureSchema: true,
        now: () => new Date(baseNow),
        defaultReservationTtlMs: 60_000,
      });

      const postedBalanceMinor = 1_000;
      const estimatedSpendMinor = 10;
      const burstSize = 200;
      const results = await Promise.allSettled(
        Array.from({ length: burstSize }, (_, index) =>
          service.reserve(ctx, {
            sourceEventId: `pg-burst-${index + 1}`,
            environmentId: 'prod',
            policyId: 'policy-org-balance',
            postedBalanceMinor,
            estimatedSpendMinor,
          }),
        ),
      );

      const fulfilled = results.filter(
        (entry): entry is PromiseFulfilledResult<Awaited<ReturnType<typeof service.reserve>>> =>
          entry.status === 'fulfilled',
      );
      const rejected = results.filter((entry): entry is PromiseRejectedResult => entry.status === 'rejected');

      expect(fulfilled).toHaveLength(postedBalanceMinor / estimatedSpendMinor);
      expect(rejected).toHaveLength(burstSize - postedBalanceMinor / estimatedSpendMinor);
      expect(
        rejected.every(
          (entry) => String((entry.reason as { code?: unknown } | null)?.code || '') === 'prepaid_balance_insufficient',
        ),
      ).toBe(true);

      const summary = await service.getSummary(ctx);
      expect(summary.reservedMinor).toBe(postedBalanceMinor);
      expect(summary.activeReservationCount).toBe(postedBalanceMinor / estimatedSpendMinor);

      const settledResults = await Promise.all(
        fulfilled.map((entry, index) =>
          service.settle(ctx, {
            sourceEventId: entry.value.reservation.sourceEventId,
            settledSpendMinor: estimatedSpendMinor,
            txOrExecutionRef: `0xpg-burst-${(index + 1).toString(16).padStart(4, '0')}`,
            pricingVersion: 'static:v1',
          }),
        ),
      );
      expect(settledResults).toHaveLength(postedBalanceMinor / estimatedSpendMinor);
      const afterSettle = await service.getSummary(ctx);
      expect(afterSettle.reservedMinor).toBe(0);
      expect(afterSettle.activeReservationCount).toBe(0);
    });
  });
});

import { expect, test } from '@playwright/test';
import {
  createInMemoryConsoleSponsorshipSpendCapService,
  createPostgresConsoleSponsorshipSpendCapService,
} from '@server/router/express-adaptor';
import { withConsoleTenantContextTx } from '../../server/src/console/shared/postgresTenantContext';
import { getPostgresPool } from '../../server/src/storage/postgres';

function randomNamespace(prefix: string): string {
  return `${prefix}:${Date.now()}:${Math.random().toString(16).slice(2)}`;
}

async function expectSpendCapError(fn: () => Promise<unknown>, code: string): Promise<void> {
  let caught: any;
  try {
    await fn();
  } catch (error: unknown) {
    caught = error;
  }
  expect(caught).toBeTruthy();
  expect(String(caught?.code || '')).toBe(code);
}

test.describe('console sponsorship spend-cap service', () => {
  const fixedNow = new Date('2026-03-10T12:00:00.000Z');
  const ctx = {
    orgId: 'org-console-sponsorship-spend-cap',
    actorUserId: 'user-console-sponsorship-spend-cap',
    roles: ['admin'],
  };

  test('in-memory isolates wallet-chain buckets and reconciles reserve/settle/release flows', async () => {
    const service = createInMemoryConsoleSponsorshipSpendCapService({
      now: () => new Date(fixedNow),
    });

    const walletAReserve = await service.reserve(ctx, {
      sourceEventId: 'mem-wallet-a-1',
      environmentId: 'dev',
      policyId: 'policy-wallets',
      accountRef: 'near:alice.testnet',
      chainId: 42_431,
      mode: 'WALLET_CHAIN_TOTAL',
      period: 'WEEKLY',
      capMinor: 1_000,
      estimatedSpendMinor: 600,
    });
    expect(walletAReserve.usage.windowStartAt).toBe('2026-03-09T00:00:00.000Z');
    expect(walletAReserve.usage.windowEndAt).toBe('2026-03-16T00:00:00.000Z');
    expect(walletAReserve.usage.reservedMinor).toBe(600);
    expect(walletAReserve.usage.availableMinor).toBe(400);

    const walletBReserve = await service.reserve(ctx, {
      sourceEventId: 'mem-wallet-b-1',
      environmentId: 'dev',
      policyId: 'policy-wallets',
      accountRef: 'near:bob.testnet',
      chainId: 42_431,
      mode: 'WALLET_CHAIN_TOTAL',
      period: 'WEEKLY',
      capMinor: 1_000,
      estimatedSpendMinor: 700,
    });
    expect(walletBReserve.usage.reservedMinor).toBe(700);
    expect(walletBReserve.usage.availableMinor).toBe(300);

    await expectSpendCapError(
      async () =>
        await service.reserve(ctx, {
          sourceEventId: 'mem-wallet-a-2',
          environmentId: 'dev',
          policyId: 'policy-wallets',
          accountRef: 'near:alice.testnet',
          chainId: 42_431,
          mode: 'WALLET_CHAIN_TOTAL',
          period: 'WEEKLY',
          capMinor: 1_000,
          estimatedSpendMinor: 500,
        }),
      'spend_cap_exceeded',
    );

    const walletASettled = await service.settle(ctx, {
      sourceEventId: 'mem-wallet-a-1',
      settledSpendMinor: 450,
    });
    expect(walletASettled?.reservation.status).toBe('SETTLED');
    expect(walletASettled?.reservation.releasedMinor).toBe(150);
    expect(walletASettled?.usage.reservedMinor).toBe(0);
    expect(walletASettled?.usage.settledMinor).toBe(450);
    expect(walletASettled?.usage.availableMinor).toBe(550);

    const walletBReleased = await service.release(ctx, {
      sourceEventId: 'mem-wallet-b-1',
    });
    expect(walletBReleased?.reservation.status).toBe('RELEASED');
    expect(walletBReleased?.usage.reservedMinor).toBe(0);
    expect(walletBReleased?.usage.settledMinor).toBe(0);
    expect(walletBReleased?.usage.availableMinor).toBe(1_000);

    const duplicateWalletAReserve = await service.reserve(ctx, {
      sourceEventId: 'mem-wallet-a-1',
      environmentId: 'dev',
      policyId: 'policy-wallets',
      accountRef: 'near:alice.testnet',
      chainId: 42_431,
      mode: 'WALLET_CHAIN_TOTAL',
      period: 'WEEKLY',
      capMinor: 1_000,
      estimatedSpendMinor: 600,
    });
    expect(duplicateWalletAReserve.reservation.status).toBe('SETTLED');
    expect(duplicateWalletAReserve.usage.reservedMinor).toBe(0);
    expect(duplicateWalletAReserve.usage.settledMinor).toBe(450);
  });

  test.describe('Postgres', () => {
    const postgresUrl = String(process.env.POSTGRES_URL || '').trim();
    const enabled = Boolean(postgresUrl);
    const namespace = randomNamespace('test:console-sponsorship-spend-caps:postgres');

    test.afterAll(async () => {
      if (!enabled) return;
      const pool = await getPostgresPool(postgresUrl);
      await withConsoleTenantContextTx(pool, { namespace, orgId: ctx.orgId }, async (q) => {
        await q.query('DELETE FROM console_sponsorship_spend_cap_windows WHERE namespace = $1', [
          namespace,
        ]);
        await q.query(
          'DELETE FROM console_sponsorship_spend_cap_reservations WHERE namespace = $1',
          [namespace],
        );
      });
    });

    test('postgres reserves atomically under concurrency and reconciles usage windows', async () => {
      test.skip(!enabled, 'POSTGRES_URL not set');
      const service = await createPostgresConsoleSponsorshipSpendCapService({
        postgresUrl,
        namespace,
        logger: console as any,
        ensureSchema: true,
        now: () => new Date(fixedNow),
      });

      const concurrentResults = await Promise.allSettled([
        service.reserve(ctx, {
          sourceEventId: 'pg-chain-1',
          environmentId: 'prod',
          policyId: 'policy-chain',
          chainId: 1,
          mode: 'CHAIN_TOTAL',
          period: 'MONTHLY',
          capMinor: 1_000,
          estimatedSpendMinor: 700,
        }),
        service.reserve(ctx, {
          sourceEventId: 'pg-chain-2',
          environmentId: 'prod',
          policyId: 'policy-chain',
          chainId: 1,
          mode: 'CHAIN_TOTAL',
          period: 'MONTHLY',
          capMinor: 1_000,
          estimatedSpendMinor: 400,
        }),
      ]);

      const fulfilled = concurrentResults.filter((entry) => entry.status === 'fulfilled');
      const rejected = concurrentResults.filter((entry) => entry.status === 'rejected');
      expect(fulfilled).toHaveLength(1);
      expect(rejected).toHaveLength(1);
      expect(String((rejected[0] as PromiseRejectedResult).reason?.code || '')).toBe(
        'spend_cap_exceeded',
      );

      const reserved = (fulfilled[0] as PromiseFulfilledResult<
        Awaited<ReturnType<typeof service.reserve>>
      >).value;
      expect(['pg-chain-1', 'pg-chain-2']).toContain(reserved.reservation.sourceEventId);

      const usageAfterReserve = await service.getWindowUsage(ctx, {
        environmentId: 'prod',
        policyId: 'policy-chain',
        chainId: 1,
        mode: 'CHAIN_TOTAL',
        period: 'MONTHLY',
        at: fixedNow,
      });
      expect(usageAfterReserve?.reservedMinor).toBe(reserved.reservation.requestedMinor);
      expect(usageAfterReserve?.settledMinor).toBe(0);

      const settled = await service.settle(ctx, {
        sourceEventId: reserved.reservation.sourceEventId,
        settledSpendMinor: 350,
      });
      expect(settled?.reservation.status).toBe('SETTLED');
      expect(settled?.reservation.releasedMinor).toBe(
        reserved.reservation.requestedMinor - 350,
      );
      expect(settled?.usage.reservedMinor).toBe(0);
      expect(settled?.usage.settledMinor).toBe(350);

      const followupReserve = await service.reserve(ctx, {
        sourceEventId: 'pg-chain-3',
        environmentId: 'prod',
        policyId: 'policy-chain',
        chainId: 1,
        mode: 'CHAIN_TOTAL',
        period: 'MONTHLY',
        capMinor: 1_000,
        estimatedSpendMinor: 500,
      });
      expect(followupReserve.usage.reservedMinor).toBe(500);
      expect(followupReserve.usage.settledMinor).toBe(350);

      const released = await service.release(ctx, {
        sourceEventId: 'pg-chain-3',
      });
      expect(released?.reservation.status).toBe('RELEASED');
      expect(released?.usage.reservedMinor).toBe(0);
      expect(released?.usage.settledMinor).toBe(350);

      const usageAfterRelease = await service.getWindowUsage(ctx, {
        environmentId: 'prod',
        policyId: 'policy-chain',
        chainId: 1,
        mode: 'CHAIN_TOTAL',
        period: 'MONTHLY',
        at: fixedNow,
      });
      expect(usageAfterRelease?.reservedMinor).toBe(0);
      expect(usageAfterRelease?.settledMinor).toBe(350);
      expect(usageAfterRelease?.availableMinor).toBe(650);
    });
  });
});

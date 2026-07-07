import { expect, test } from '@playwright/test';
import { createInMemoryConsoleSponsorshipSpendCapService } from '@seams-internal/console-server/router/express-adaptor';

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
});

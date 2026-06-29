import { expect, test } from '@playwright/test';
import {
  createInMemoryConsoleBillingService,
  createInMemoryConsoleBillingPrepaidReservationService,
  createConsoleRouter,
  createInMemoryConsoleSponsoredCallService,
  type ConsoleAuthAdapter,
  type ConsoleBillingService,
  type ConsoleSponsoredCallService,
} from '@server/router/express-adaptor';
import { createCloudflareConsoleRouter } from '@server/router/cloudflare-adaptor';
import { callCf, fetchJson, startExpressRouter } from './helpers';

const baseNow = new Date('2026-03-19T00:00:00.000Z');
const ctx = {
  orgId: 'org-sponsored-history',
  actorUserId: 'user-sponsored-history',
  roles: ['admin'],
};

function makeConsoleAuthAdapter(input: {
  userId: string;
  orgId: string;
  roles: string[];
}): ConsoleAuthAdapter {
  return {
    authenticate: async () => ({
      ok: true,
      claims: {
        userId: input.userId,
        orgId: input.orgId,
        roles: input.roles,
      },
    }),
  };
}

async function seedSponsoredCallRecord(
  service: ConsoleSponsoredCallService,
  input: {
    id: string;
    environmentId: string;
    policyId: string;
    receiptStatus?: 'success' | 'reverted' | 'broadcast_failed' | 'rpc_rejected';
    chainFamily?: 'evm' | 'near';
    charged?: boolean;
    settledSpendMinor?: number;
    billingLedgerEntryId?: string | null;
  },
): Promise<void> {
  await service.createRecord(ctx, {
    id: input.id,
    environmentId: input.environmentId,
    apiKeyId: `pk_${input.id}`,
    apiKeyKind: 'publishable_key',
    route: 'sponsored_evm_call_v1',
    policyId: input.policyId,
    policyNameAtEvent: `Policy ${input.policyId}`,
    templateId: `template_${input.policyId}`,
    chainFamily: input.chainFamily || 'evm',
    intentKind: input.chainFamily === 'near' ? 'near_delegate' : 'evm_call',
    executorKind: input.chainFamily === 'near' ? 'near_delegate' : 'evm_eoa',
    accountRef: `near:${input.id}.testnet`,
    targetRef: `evm:1:0x${input.id.padStart(40, '1').slice(0, 40)}`,
    sponsorRef: 'evm:1:0x2222222222222222222222222222222222222222',
    txOrExecutionRef: `0x${input.id.padStart(64, 'a').slice(0, 64)}`,
    receiptStatus: input.receiptStatus || 'success',
    feeUnit: input.chainFamily === 'near' ? 'yocto_near' : 'wei',
    feeAmount: '42',
    detailsJson: JSON.stringify({ seeded: input.id }),
    estimatedSpendMinor: 80,
    settledSpendMinor: input.settledSpendMinor ?? (input.charged === false ? 0 : 60),
    pricingVersion: 'pricing-test-v1',
    pricingSource: 'test',
    billingLedgerEntryId:
      input.billingLedgerEntryId === undefined
        ? input.charged === false
          ? null
          : `ble_${input.id}`
        : input.billingLedgerEntryId,
    prepaidReservationId: `bpr_${input.id}`,
    charged: input.charged !== false,
    chargedReason: input.charged === false ? 'no_charge' : 'gas_burned',
    settledAt: baseNow.toISOString(),
    idempotencyKey: `idem_${input.id}`,
  });
}

async function callHistoryRoute(
  mode: 'express' | 'cloudflare',
  input: {
    auth: ConsoleAuthAdapter;
    sponsoredCalls: ConsoleSponsoredCallService;
    billing?: ConsoleBillingService;
    path?: string;
  },
): Promise<{ status: number; json: Record<string, unknown> | null }> {
  if (mode === 'express') {
    const router = createConsoleRouter({
      auth: input.auth,
      billing: input.billing,
      sponsoredCalls: input.sponsoredCalls,
    });
    const server = await startExpressRouter(router);
    try {
      const response = await fetchJson(
        `${server.baseUrl}${input.path || '/console/billing/sponsored-executions'}`,
      );
      return { status: response.status, json: response.json };
    } finally {
      await server.close();
    }
  }

  const handler = createCloudflareConsoleRouter({
    auth: input.auth,
    billing: input.billing,
    sponsoredCalls: input.sponsoredCalls,
  });
  const response = await callCf(handler, {
    method: 'GET',
    path: input.path || '/console/billing/sponsored-executions',
  });
  return { status: response.status, json: response.json };
}

async function seedSponsoredExecutionDebit(
  billing: ConsoleBillingService,
  input: {
    id: string;
    amountMinor: number;
  },
): Promise<string> {
  const result = await billing.recordSponsoredExecutionDebit(ctx, {
    amountMinor: input.amountMinor,
    sourceEventId: `seed:${input.id}`,
    walletId: `wallet_${input.id}`,
    occurredAt: baseNow.toISOString(),
    txOrExecutionRef: `tx_${input.id}`,
    pricingVersion: 'pricing-test-v1',
  });
  expect(result.ledgerEntryId).toBeTruthy();
  return String(result.ledgerEntryId);
}

test.describe('console sponsored call history', () => {
  test('in-memory service lists sponsored records with default 90-day lookback and cursor pagination', async () => {
    let currentNowMs = baseNow.getTime() - 100 * 24 * 60 * 60 * 1000;
    const service = createInMemoryConsoleSponsoredCallService({
      now: () => new Date(currentNowMs),
    });

    await seedSponsoredCallRecord(service, {
      id: 'old',
      environmentId: 'env-old',
      policyId: 'policy-old',
    });
    currentNowMs = baseNow.getTime() - 2 * 24 * 60 * 60 * 1000;
    await seedSponsoredCallRecord(service, {
      id: 'recent-a',
      environmentId: 'env-prod',
      policyId: 'policy-a',
    });
    currentNowMs = baseNow.getTime() - 1 * 24 * 60 * 60 * 1000;
    await seedSponsoredCallRecord(service, {
      id: 'recent-b',
      environmentId: 'env-prod',
      policyId: 'policy-b',
      receiptStatus: 'reverted',
      charged: false,
    });

    const firstPage = await service.listRecords(ctx, {
      environmentId: 'env-prod',
      limit: 1,
    });
    expect(firstPage.items).toHaveLength(1);
    expect(firstPage.items[0]?.id).toBe('recent-b');
    expect(firstPage.nextCursor).toBeTruthy();

    const secondPage = await service.listRecords(ctx, {
      environmentId: 'env-prod',
      limit: 1,
      cursor: firstPage.nextCursor || undefined,
    });
    expect(secondPage.items).toHaveLength(1);
    expect(secondPage.items[0]?.id).toBe('recent-a');
    expect(secondPage.nextCursor).toBeNull();

    const chargedOnly = await service.listRecords(ctx, {
      charged: true,
    });
    expect(chargedOnly.items.map((item) => item.id)).toEqual(['recent-a']);

    const overviewSummary = await service.getOverviewSummary(ctx);
    expect(overviewSummary.trailing30Days.chargedExecutionCount).toBe(1);
    expect(overviewSummary.trailing30Days.chargedSettledSpendMinor).toBe(60);
    expect(overviewSummary.trailing90Days.chargedExecutionCount).toBe(1);
    expect(overviewSummary.trailing90Days.chargedSettledSpendMinor).toBe(60);
  });

  for (const mode of ['express', 'cloudflare'] as const) {
    test(`console router (${mode}) exposes sponsored execution history`, async () => {
      const service = createInMemoryConsoleSponsoredCallService({
        now: () => new Date(baseNow),
      });
      await seedSponsoredCallRecord(service, {
        id: 'router-a',
        environmentId: 'env-router',
        policyId: 'policy-router',
      });
      await seedSponsoredCallRecord(service, {
        id: 'router-b',
        environmentId: 'env-router',
        policyId: 'policy-router',
        charged: false,
      });

      const auth = makeConsoleAuthAdapter({
        userId: ctx.actorUserId,
        orgId: ctx.orgId,
        roles: ['billing_admin'],
      });

      const response = await callHistoryRoute(mode, {
        auth,
        sponsoredCalls: service,
        path: '/console/billing/sponsored-executions?environmentId=env-router&charged=true',
      });
      expect(response.status).toBe(200);
      const page = response.json?.page as Record<string, unknown> | undefined;
      expect(Array.isArray(page?.items)).toBe(true);
      expect((page?.items as Array<Record<string, unknown>>).map((item) => item.id)).toEqual([
        'router-a',
      ]);
      expect(page?.nextCursor ?? null).toBeNull();
    });

    test(`console router (${mode}) rejects invalid sponsored history filters`, async () => {
      const auth = makeConsoleAuthAdapter({
        userId: ctx.actorUserId,
        orgId: ctx.orgId,
        roles: ['billing_admin'],
      });
      const service = createInMemoryConsoleSponsoredCallService({
        now: () => new Date(baseNow),
      });
      const response = await callHistoryRoute(mode, {
        auth,
        sponsoredCalls: service,
        path: '/console/billing/sponsored-executions?receiptStatus=not_real',
      });
      expect(response.status).toBe(400);
      expect(response.json?.code).toBe('invalid_query');
    });

    test(`console router (${mode}) exposes sponsored execution reconciliation`, async () => {
      const sponsoredCalls = createInMemoryConsoleSponsoredCallService({
        now: () => new Date(baseNow),
      });
      const billing = createInMemoryConsoleBillingService({
        now: () => new Date(baseNow),
      });
      const matchedDebitId = await seedSponsoredExecutionDebit(billing, {
        id: 'matched',
        amountMinor: 60,
      });
      const mismatchedDebitId = await seedSponsoredExecutionDebit(billing, {
        id: 'mismatch',
        amountMinor: 75,
      });
      const unexpectedDebitId = await seedSponsoredExecutionDebit(billing, {
        id: 'unexpected',
        amountMinor: 60,
      });

      await seedSponsoredCallRecord(sponsoredCalls, {
        id: 'matched',
        environmentId: 'env-router',
        policyId: 'policy-router',
        billingLedgerEntryId: matchedDebitId,
      });
      await seedSponsoredCallRecord(sponsoredCalls, {
        id: 'missing',
        environmentId: 'env-router',
        policyId: 'policy-router',
        billingLedgerEntryId: null,
      });
      await seedSponsoredCallRecord(sponsoredCalls, {
        id: 'mismatch',
        environmentId: 'env-router',
        policyId: 'policy-router',
        billingLedgerEntryId: mismatchedDebitId,
        settledSpendMinor: 60,
      });
      await seedSponsoredCallRecord(sponsoredCalls, {
        id: 'unexpected',
        environmentId: 'env-router',
        policyId: 'policy-router',
        charged: false,
        billingLedgerEntryId: unexpectedDebitId,
      });

      const auth = makeConsoleAuthAdapter({
        userId: ctx.actorUserId,
        orgId: ctx.orgId,
        roles: ['billing_admin'],
      });
      const response = await callHistoryRoute(mode, {
        auth,
        billing,
        sponsoredCalls,
        path: '/console/billing/sponsored-executions/reconciliation?environmentId=env-router',
      });
      expect(response.status).toBe(200);
      const page = response.json?.page as Record<string, unknown> | undefined;
      const statusById = Object.fromEntries(
        ((page?.items as Array<Record<string, unknown>>) || []).map((item) => [
          String((item.record as Record<string, unknown> | undefined)?.id || ''),
          String(item.status || ''),
        ]),
      );
      expect(statusById).toEqual({
        matched: 'matched',
        missing: 'missing_billing_debit',
        mismatch: 'amount_mismatch',
        unexpected: 'unexpected_billing_debit',
      });
      expect(page?.summary).toEqual({
        matchedCount: 1,
        notChargedCount: 0,
        missingBillingDebitCount: 1,
        amountMismatchCount: 1,
        unexpectedBillingDebitCount: 1,
        mismatchCount: 3,
      });
    });

    test(`console router (${mode}) enriches billing overview with sponsorship summary fields`, async () => {
      const billing = createInMemoryConsoleBillingService({
        now: () => new Date(baseNow),
      });
      const prepaidReservations = createInMemoryConsoleBillingPrepaidReservationService({
        now: () => new Date(baseNow),
      });
      let currentNowMs = baseNow.getTime() - 40 * 24 * 60 * 60 * 1000;
      const sponsoredCalls = createInMemoryConsoleSponsoredCallService({
        now: () => new Date(currentNowMs),
      });
      await billing.grantManualSupportCredit(
        {
          orgId: ctx.orgId,
          actorUserId: 'platform-admin-overview',
          roles: ['platform_admin'],
        },
        {
          amountMinor: 5000,
          reasonCode: 'support_credit',
          note: 'seed credit',
          idempotencyKey: 'overview-seed-credit',
        },
      );
      await prepaidReservations.reserve(ctx, {
        sourceEventId: 'overview-reservation',
        environmentId: 'env-router',
        policyId: 'policy-router',
        postedBalanceMinor: 5000,
        estimatedSpendMinor: 800,
      });
      await seedSponsoredCallRecord(sponsoredCalls, {
        id: 'overview-90d',
        environmentId: 'env-router',
        policyId: 'policy-router',
        settledSpendMinor: 70,
      });
      currentNowMs = baseNow.getTime() - 2 * 24 * 60 * 60 * 1000;
      await seedSponsoredCallRecord(sponsoredCalls, {
        id: 'overview-30d',
        environmentId: 'env-router',
        policyId: 'policy-router',
        settledSpendMinor: 60,
      });
      currentNowMs = baseNow.getTime() - 1 * 24 * 60 * 60 * 1000;
      await seedSponsoredCallRecord(sponsoredCalls, {
        id: 'overview-uncharged',
        environmentId: 'env-router',
        policyId: 'policy-router',
        charged: false,
      });

      const auth = makeConsoleAuthAdapter({
        userId: ctx.actorUserId,
        orgId: ctx.orgId,
        roles: ['billing_admin'],
      });
      const response = await (async () => {
        if (mode === 'express') {
          const router = createConsoleRouter({
            auth,
            billing,
            prepaidReservations,
            sponsoredCalls,
          });
          const server = await startExpressRouter(router);
          try {
            const res = await fetchJson(`${server.baseUrl}/console/billing/overview`);
            return { status: res.status, json: res.json };
          } finally {
            await server.close();
          }
        }
        const handler = createCloudflareConsoleRouter({
          auth,
          billing,
          prepaidReservations,
          sponsoredCalls,
        });
        const res = await callCf(handler, {
          method: 'GET',
          path: '/console/billing/overview',
        });
        return { status: res.status, json: res.json };
      })();
      expect(response.status).toBe(200);
      const overview = response.json?.overview as Record<string, unknown> | undefined;
      expect(overview?.reservedSponsorshipMinor).toBe(800);
      expect(overview?.activeSponsorshipReservationCount).toBe(1);
      expect(overview?.trailing30DaySponsoredSpendMinor).toBe(60);
      expect(overview?.trailing30DaySponsoredExecutionCount).toBe(1);
      expect(overview?.trailing90DaySponsoredSpendMinor).toBe(130);
      expect(overview?.trailing90DaySponsoredExecutionCount).toBe(2);
    });
  }
});

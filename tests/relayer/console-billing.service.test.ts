import { expect, test } from '@playwright/test';
import {
  createInMemoryConsoleBillingService,
  createPostgresConsoleBillingService,
  type ConsoleBillingService,
} from '@server/router/express-adaptor';
import { withConsoleTenantContextTx } from '../../server/src/console/shared/postgresTenantContext';
import { getPostgresPool } from '../../server/src/storage/postgres';

function randomNamespace(prefix: string): string {
  return `${prefix}:${Date.now()}:${Math.random().toString(16).slice(2)}`;
}

async function expectBillingError(fn: () => Promise<unknown>, code: string): Promise<void> {
  let caught: any;
  try {
    await fn();
  } catch (error: unknown) {
    caught = error;
  }
  expect(caught).toBeTruthy();
  expect(String(caught?.code || '')).toBe(code);
}

async function settleCreditPurchase(
  service: ConsoleBillingService,
  ctx: { orgId: string; actorUserId: string; roles: string[] },
  creditPackId: 'usd_50' | 'usd_200' | 'usd_500' | 'usd_1000' = 'usd_200',
): Promise<{
  checkoutSession: Awaited<ReturnType<ConsoleBillingService['createStripeCheckoutSession']>>;
  purchase: NonNullable<
    Awaited<ReturnType<ConsoleBillingService['processStripeWebhookEvent']>>['purchase']
  >;
  invoice: NonNullable<
    Awaited<ReturnType<ConsoleBillingService['processStripeWebhookEvent']>>['invoice']
  >;
}> {
  const checkoutSession = await service.createStripeCheckoutSession(ctx, {
    successUrl: 'https://app.example.com/dashboard/billing/account?checkout=success',
    cancelUrl: 'https://app.example.com/dashboard/billing/account?checkout=cancel',
    creditPackId,
  });
  const projection = await service.processStripeWebhookEvent({
    eventId: `evt_purchase_${Date.now()}_${Math.random().toString(16).slice(2)}`,
    eventType: 'checkout.session.completed',
    orgId: ctx.orgId,
    checkoutSessionId: checkoutSession.id,
    providerCustomerRef: checkoutSession.customerRef,
    providerRef: checkoutSession.id,
  });
  expect(projection.accepted).toBe(true);
  expect(projection.purchase).toBeTruthy();
  expect(projection.invoice).toBeTruthy();
  return {
    checkoutSession,
    purchase: projection.purchase!,
    invoice: projection.invoice!,
  };
}

test.describe('console billing service prepaid model', () => {
  test('in-memory service uses injected prepaid billing provider adapters', async () => {
    const service = createInMemoryConsoleBillingService({
      providers: {
        stripe: {
          createSetupIntent: () => ({
            id: 'seti_mem_provider',
            clientSecret: 'seti_mem_provider_secret',
            customerRef: 'cus_mem_provider',
            expiresAt: '2026-03-01T00:30:00.000Z',
          }),
          createCheckoutSession: () => ({
            id: 'cs_mem_provider',
            url: 'https://checkout.example/memory',
            customerRef: 'cus_mem_provider',
            expiresAt: '2026-03-01T00:30:00.000Z',
          }),
          createCustomerPortalSession: () => ({
            id: 'bps_mem_provider',
            url: 'https://billing.example/memory',
            customerRef: 'cus_mem_provider',
            expiresAt: '2026-03-01T00:30:00.000Z',
          }),
        },
      },
    });

    const ctx = {
      orgId: 'org-provider-adapter-memory',
      actorUserId: 'ops-provider-adapter-memory',
      roles: ['ops'],
    };

    const setupIntent = await service.createStripeSetupIntent(ctx, {});
    expect(setupIntent.id).toBe('seti_mem_provider');
    expect(setupIntent.clientSecret).toBe('seti_mem_provider_secret');
    expect(setupIntent.customerRef).toBe('cus_mem_provider');
    expect(setupIntent.expiresAt).toBe('2026-03-01T00:30:00.000Z');

    const checkoutSession = await service.createStripeCheckoutSession(ctx, {
      successUrl: 'https://app.example.com/dashboard/billing/account?checkout=success',
      cancelUrl: 'https://app.example.com/pricing?checkout=cancel',
      creditPackId: 'usd_200',
    });
    expect(checkoutSession.id).toBe('cs_mem_provider');
    expect(checkoutSession.url).toBe('https://checkout.example/memory');
    expect(checkoutSession.customerRef).toBe('cus_mem_provider');
    expect(checkoutSession.creditPackId).toBe('usd_200');
    expect(checkoutSession.amountMinor).toBe(20000);
    expect(checkoutSession.expiresAt).toBe('2026-03-01T00:30:00.000Z');

    const portalSession = await service.createStripeCustomerPortalSession(ctx, {
      returnUrl: 'https://app.example.com/dashboard/billing/account',
    });
    expect(portalSession.id).toBe('bps_mem_provider');
    expect(portalSession.url).toBe('https://billing.example/memory');
    expect(portalSession.customerRef).toBe('cus_mem_provider');
    expect(portalSession.expiresAt).toBe('2026-03-01T00:30:00.000Z');

    const projection = await service.processStripeWebhookEvent({
      eventId: 'evt_mem_provider_purchase',
      eventType: 'checkout.session.completed',
      orgId: ctx.orgId,
      checkoutSessionId: checkoutSession.id,
      providerCustomerRef: checkoutSession.customerRef,
      providerRef: checkoutSession.id,
    });
    expect(projection.accepted).toBe(true);
    expect(projection.purchase?.status).toBe('SETTLED');
    expect(projection.purchase?.creditPackId).toBe('usd_200');
    expect(projection.invoice?.documentType).toBe('PURCHASE_RECEIPT');

    const overview = await service.getOverview(ctx);
    expect(overview.creditBalanceMinor).toBe(20000);
    expect(overview.recentCreditPurchasedMinor).toBe(20000);
  });

  test('in-memory service enforces admin-only card mutations', async () => {
    const service = createInMemoryConsoleBillingService();
    const nonAdminCtx = {
      orgId: 'org-rbac-memory',
      actorUserId: 'billing-admin-1',
      roles: ['billing_admin'],
    };

    await expectBillingError(async () => {
      await service.addCardPaymentMethod(nonAdminCtx, {
        providerRef: 'pm_mem_forbidden',
        brand: 'visa',
        last4: '4242',
        expMonth: 1,
        expYear: 2031,
      });
    }, 'forbidden');

    await expectBillingError(async () => {
      await service.removeCardPaymentMethod(nonAdminCtx, 'pm_missing');
    }, 'forbidden');

    await expectBillingError(async () => {
      await service.setDefaultCardPaymentMethod(nonAdminCtx, 'pm_missing');
    }, 'forbidden');
  });

  test('in-memory card payment method lifecycle keeps a default method', async () => {
    const service = createInMemoryConsoleBillingService();
    const ctx = {
      orgId: 'org-card-defaults-memory',
      actorUserId: 'admin-card-defaults-memory',
      roles: ['admin'],
    };

    const pm1 = await service.addCardPaymentMethod(ctx, {
      providerRef: 'pm_mem_1',
      brand: 'visa',
      last4: '1111',
      expMonth: 1,
      expYear: 2031,
    });
    expect(pm1.isDefault).toBe(true);

    const pm2 = await service.addCardPaymentMethod(ctx, {
      providerRef: 'pm_mem_2',
      brand: 'mastercard',
      last4: '2222',
      expMonth: 2,
      expYear: 2032,
    });
    expect(pm2.isDefault).toBe(false);

    const updatedDefault = await service.setDefaultCardPaymentMethod(ctx, pm2.id);
    expect(updatedDefault?.id).toBe(pm2.id);
    expect(updatedDefault?.isDefault).toBe(true);

    const removed = await service.removeCardPaymentMethod(ctx, pm2.id);
    expect(removed.removed).toBe(true);

    const methods = await service.listPaymentMethods(ctx);
    expect(methods.length).toBe(1);
    expect(methods[0]?.id).toBe(pm1.id);
    expect(methods[0]?.isDefault).toBe(true);
  });

  test('in-memory service settles prepaid purchase receipts idempotently by event id', async () => {
    const service = createInMemoryConsoleBillingService();
    const ctx = {
      orgId: 'org-stripe-webhook-memory',
      actorUserId: 'ops-webhook-memory',
      roles: ['ops'],
    };

    const checkoutSession = await service.createStripeCheckoutSession(ctx, {
      successUrl: 'https://app.example.com/dashboard/billing/account?checkout=success',
      cancelUrl: 'https://app.example.com/dashboard/billing/account?checkout=cancel',
      creditPackId: 'usd_200',
    });

    const first = await service.processStripeWebhookEvent({
      eventId: 'evt_mem_same',
      eventType: 'checkout.session.completed',
      orgId: ctx.orgId,
      checkoutSessionId: checkoutSession.id,
      providerCustomerRef: checkoutSession.customerRef,
      providerRef: checkoutSession.id,
    });
    expect(first.accepted).toBe(true);
    expect(first.purchase?.status).toBe('SETTLED');
    expect(first.invoice?.documentType).toBe('PURCHASE_RECEIPT');

    const duplicate = await service.processStripeWebhookEvent({
      eventId: 'evt_mem_same',
      eventType: 'checkout.session.completed',
      orgId: ctx.orgId,
      checkoutSessionId: checkoutSession.id,
      providerCustomerRef: checkoutSession.customerRef,
      providerRef: checkoutSession.id,
    });
    expect(duplicate.accepted).toBe(false);
    expect(duplicate.purchase?.status).toBe('SETTLED');

    const overview = await service.getOverview(ctx);
    expect(overview.creditBalanceMinor).toBe(20000);
  });

  test('in-memory service MAW counts distinct wallets with exclusions and idempotency', async () => {
    const service = createInMemoryConsoleBillingService();
    const ctx = {
      orgId: 'org-maw-memory',
      actorUserId: 'ops-maw-memory',
      roles: ['ops'],
    };

    const first = await service.recordUsageEvent(ctx, {
      walletId: 'wallet_mem_1',
      action: 'transfer',
      succeeded: true,
      sourceEventId: 'maw_mem_evt_1',
    });
    expect(first.accepted).toBe(true);
    expect(first.counted).toBe(true);
    expect(first.monthlyActiveWallets).toBe(1);
    expect(first.debitAppliedMinor).toBe(300);
    expect(first.creditBalanceMinor).toBe(-300);
    expect(first.statementId).toBeTruthy();

    const secondSameWallet = await service.recordUsageEvent(ctx, {
      walletId: 'wallet_mem_1',
      action: 'swap',
      succeeded: true,
      sourceEventId: 'maw_mem_evt_2',
    });
    expect(secondSameWallet.accepted).toBe(true);
    expect(secondSameWallet.counted).toBe(true);
    expect(secondSameWallet.monthlyActiveWallets).toBe(1);
    expect(secondSameWallet.debitAppliedMinor).toBe(0);

    const excluded = await service.recordUsageEvent(ctx, {
      walletId: 'wallet_mem_2',
      action: 'wallet_created',
      succeeded: true,
      sourceEventId: 'maw_mem_evt_3',
    });
    expect(excluded.accepted).toBe(true);
    expect(excluded.counted).toBe(false);
    expect(excluded.monthlyActiveWallets).toBe(1);

    const thirdDistinct = await service.recordUsageEvent(ctx, {
      walletId: 'wallet_mem_3',
      action: 'contract_call',
      succeeded: true,
      sourceEventId: 'maw_mem_evt_4',
    });
    expect(thirdDistinct.accepted).toBe(true);
    expect(thirdDistinct.counted).toBe(true);
    expect(thirdDistinct.monthlyActiveWallets).toBe(2);
    expect(thirdDistinct.debitAppliedMinor).toBe(300);

    const duplicate = await service.recordUsageEvent(ctx, {
      walletId: 'wallet_mem_3',
      action: 'contract_call',
      succeeded: true,
      sourceEventId: 'maw_mem_evt_4',
    });
    expect(duplicate.accepted).toBe(false);
    expect(duplicate.counted).toBe(false);
    expect(duplicate.monthlyActiveWallets).toBe(2);

    const usage = await service.getMonthlyActiveWallets(ctx, first.monthUtc);
    expect(usage.usageMetricVersion).toBe('maw_v1');
    expect(usage.monthUtc).toBe(first.monthUtc);
    expect(usage.monthlyActiveWallets).toBe(2);
  });

  test('in-memory service creates one statement per org per period month', async () => {
    let current = new Date('2026-01-20T00:00:00.000Z');
    const service = createInMemoryConsoleBillingService({
      now: () => current,
    });
    const ctx = {
      orgId: 'org-month-rollover-memory',
      actorUserId: 'ops-month-rollover',
      roles: ['ops'],
    };

    const januaryDocuments = await service.listInvoices(ctx);
    expect(januaryDocuments.length).toBe(1);
    expect(januaryDocuments[0]?.periodMonthUtc).toBe('2026-01');
    expect(januaryDocuments[0]?.documentType).toBe('USAGE_STATEMENT');
    expect(januaryDocuments[0]?.status).toBe('PAID');

    current = new Date('2026-02-02T00:00:00.000Z');
    const februaryDocuments = await service.listInvoices(ctx);
    expect(februaryDocuments.some((invoice) => invoice.periodMonthUtc === '2026-01')).toBe(true);
    expect(februaryDocuments.some((invoice) => invoice.periodMonthUtc === '2026-02')).toBe(true);
    expect(februaryDocuments.filter((invoice) => invoice.periodMonthUtc === '2026-02').length).toBe(
      1,
    );

    current = new Date('2026-02-10T00:00:00.000Z');
    const februaryDocumentsAgain = await service.listInvoices(ctx);
    expect(
      februaryDocumentsAgain.filter((invoice) => invoice.periodMonthUtc === '2026-02').length,
    ).toBe(1);
  });

  test('in-memory service regenerates monthly usage statements idempotently from MAW rollups', async () => {
    const current = new Date('2026-02-05T00:00:00.000Z');
    const service = createInMemoryConsoleBillingService({
      now: () => current,
    });
    const ctx = {
      orgId: 'org-invoice-generation-memory',
      actorUserId: 'ops-invoice-generation',
      roles: ['ops'],
    };

    await service.recordUsageEvent(ctx, {
      walletId: 'wallet_a',
      action: 'transfer',
      succeeded: true,
      occurredAt: '2026-01-05T01:00:00.000Z',
      sourceEventId: 'invoice_gen_mem_1',
    });
    await service.recordUsageEvent(ctx, {
      walletId: 'wallet_b',
      action: 'swap',
      succeeded: true,
      occurredAt: '2026-01-06T01:00:00.000Z',
      sourceEventId: 'invoice_gen_mem_2',
    });
    await service.recordUsageEvent(ctx, {
      walletId: 'wallet_c',
      action: 'wallet_created',
      succeeded: true,
      occurredAt: '2026-01-07T01:00:00.000Z',
      sourceEventId: 'invoice_gen_mem_3',
    });

    const generation = await service.generateMonthlyInvoice(ctx, {
      periodMonthUtc: '2026-01',
    });
    expect(generation.generated).toBe(false);
    expect(generation.monthlyActiveWallets).toBe(2);
    expect(generation.pricing.mawUnitPriceMinor).toBe(300);
    expect(generation.invoice.periodMonthUtc).toBe('2026-01');
    expect(generation.invoice.documentType).toBe('USAGE_STATEMENT');
    expect(generation.invoice.amountDueMinor).toBe(600);
    expect(generation.invoice.amountPaidMinor).toBe(600);
    expect(generation.lineItems.length).toBe(1);
    expect(generation.lineItems[0]?.itemType).toBe('MAW_USAGE_DEBIT');
    expect(generation.lineItems[0]?.quantity).toBe(2);
    expect(generation.lineItems[0]?.amountMinor).toBe(600);

    const listed = await service.listInvoiceLineItems(ctx, generation.invoice.id);
    expect(listed.length).toBe(1);
    expect(listed[0]?.itemType).toBe('MAW_USAGE_DEBIT');

    const secondRun = await service.generateMonthlyInvoice(ctx, {
      periodMonthUtc: '2026-01',
    });
    expect(secondRun.generated).toBe(false);
    expect(secondRun.invoice.amountDueMinor).toBe(600);
  });

  test('in-memory service lists receipt and statement history with server-side filters', async () => {
    let current = new Date('2026-01-20T00:00:00.000Z');
    const service = createInMemoryConsoleBillingService({
      now: () => current,
    });
    const ctx = {
      orgId: 'org-invoice-history-memory',
      actorUserId: 'ops-invoice-history',
      roles: ['ops'],
    };

    await service.recordUsageEvent(ctx, {
      walletId: 'wallet_january_1',
      action: 'transfer',
      succeeded: true,
      sourceEventId: 'usage_january_1',
      occurredAt: '2026-01-09T00:00:00.000Z',
    });
    await service.generateMonthlyInvoice(ctx, { periodMonthUtc: '2026-01' });
    current = new Date('2026-02-20T00:00:00.000Z');
    await service.recordUsageEvent(ctx, {
      walletId: 'wallet_february_1',
      action: 'transfer',
      succeeded: true,
      sourceEventId: 'usage_february_1',
      occurredAt: '2026-02-11T00:00:00.000Z',
    });
    await service.generateMonthlyInvoice(ctx, { periodMonthUtc: '2026-02' });
    current = new Date('2026-03-20T00:00:00.000Z');
    await service.recordUsageEvent(ctx, {
      walletId: 'wallet_march_1',
      action: 'transfer',
      succeeded: true,
      sourceEventId: 'usage_march_1',
      occurredAt: '2026-03-15T00:00:00.000Z',
    });
    const march = await service.generateMonthlyInvoice(ctx, { periodMonthUtc: '2026-03' });
    const receipt = await settleCreditPurchase(service, ctx, 'usd_200');
    expect(receipt.invoice.documentType).toBe('PURCHASE_RECEIPT');

    const firstPage = await service.listInvoicesPage(ctx, { limit: 1 });
    expect(firstPage.invoices.length).toBe(1);
    expect(firstPage.totalCount).toBe(4);
    expect(firstPage.nextCursor).toBeTruthy();
    expect(firstPage.summary.receiptCount).toBe(1);
    expect(firstPage.summary.statementCount).toBe(3);

    const secondPage = await service.listInvoicesPage(ctx, {
      limit: 1,
      cursor: firstPage.nextCursor || undefined,
    });
    expect(secondPage.invoices.length).toBe(1);
    expect(secondPage.invoices[0]?.id).not.toBe(firstPage.invoices[0]?.id);

    const paid = await service.listInvoicesPage(ctx, { status: 'PAID' });
    expect(paid.totalCount).toBe(4);
    expect(paid.summary.paidCount).toBe(4);

    const receipts = await service.listInvoicesPage(ctx, { documentType: 'PURCHASE_RECEIPT' });
    expect(receipts.totalCount).toBe(1);
    expect(receipts.invoices[0]?.documentType).toBe('PURCHASE_RECEIPT');

    const february = await service.listInvoicesPage(ctx, {
      documentType: 'USAGE_STATEMENT',
      periodMonthUtc: '2026-02',
    });
    expect(february.totalCount).toBe(1);
    expect(february.invoices[0]?.periodMonthUtc).toBe('2026-02');
    expect(february.invoices[0]?.documentType).toBe('USAGE_STATEMENT');

    const marchActivity = await service.getInvoiceActivity(ctx, march.invoice.id);
    expect(marchActivity).toBeTruthy();
    expect(
      marchActivity?.entries.some(
        (entry) => entry.type === 'LEDGER' && entry.toState === 'USAGE_DEBIT',
      ),
    ).toBe(true);

    const receiptActivity = await service.getInvoiceActivity(ctx, receipt.invoice.id);
    expect(receiptActivity).toBeTruthy();
    expect(
      receiptActivity?.entries.some(
        (entry) => entry.type === 'LEDGER' && entry.toState === 'CREDIT_PURCHASE',
      ),
    ).toBe(true);
  });

  test('postgres service enforces admin-only card mutations', async () => {
    const postgresUrl = String(process.env.POSTGRES_URL || '').trim();
    test.skip(!postgresUrl, 'POSTGRES_URL not set');
    const namespace = randomNamespace('test:console-billing:rbac');
    const service: ConsoleBillingService = await createPostgresConsoleBillingService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
    });

    const nonAdminCtx = {
      orgId: 'org-rbac-postgres',
      actorUserId: 'billing-admin-2',
      roles: ['billing_admin'],
    };

    try {
      await expectBillingError(async () => {
        await service.addCardPaymentMethod(nonAdminCtx, {
          providerRef: 'pm_pg_forbidden',
          brand: 'visa',
          last4: '4242',
          expMonth: 1,
          expYear: 2031,
        });
      }, 'forbidden');

      await expectBillingError(async () => {
        await service.removeCardPaymentMethod(nonAdminCtx, 'pm_missing');
      }, 'forbidden');
    } finally {
      const pool = await getPostgresPool(postgresUrl);
      await withConsoleTenantContextTx(pool, { namespace, orgId: nonAdminCtx.orgId }, async (q) => {
        await q.query('DELETE FROM console_stripe_webhook_events WHERE namespace = $1', [
          namespace,
        ]);
        await q.query('DELETE FROM console_payment_methods WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_invoice_line_items WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_usage_rollups_monthly WHERE namespace = $1', [
          namespace,
        ]);
        await q.query('DELETE FROM console_usage_meter_events WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_billing_credit_purchases WHERE namespace = $1', [
          namespace,
        ]);
        await q.query('DELETE FROM console_billing_ledger_entries WHERE namespace = $1', [
          namespace,
        ]);
        await q.query('DELETE FROM console_invoices WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_billing_accounts WHERE namespace = $1', [namespace]);
      });
    }
  });
});

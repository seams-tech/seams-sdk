import { expect, test } from '@playwright/test';
import {
  createInMemoryConsoleBillingService,
  createPostgresConsoleBillingService,
  type ConsoleBillingService,
} from '@server/router/express-adaptor';

function randomNamespace(prefix: string): string {
  return `${prefix}:${Date.now()}:${Math.random().toString(16).slice(2)}`;
}

async function settleCreditPurchase(
  service: ConsoleBillingService,
  ctx: { orgId: string; actorUserId: string; roles: string[] },
  creditPackId: 'usd_10' | 'usd_25' | 'usd_50' = 'usd_25',
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
          createCheckoutSession: () => ({
            id: 'cs_mem_provider',
            url: 'https://checkout.example/memory',
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

    const checkoutSession = await service.createStripeCheckoutSession(ctx, {
      successUrl: 'https://app.example.com/dashboard/billing/account?checkout=success',
      cancelUrl: 'https://app.example.com/pricing?checkout=cancel',
      creditPackId: 'usd_25',
    });
    expect(checkoutSession.id).toBe('cs_mem_provider');
    expect(checkoutSession.url).toBe('https://checkout.example/memory');
    expect(checkoutSession.customerRef).toBe('cus_mem_provider');
    expect(checkoutSession.creditPackId).toBe('usd_25');
    expect(checkoutSession.amountMinor).toBe(2500);
    expect(checkoutSession.expiresAt).toBe('2026-03-01T00:30:00.000Z');

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
    expect(projection.purchase?.creditPackId).toBe('usd_25');
    expect(projection.invoice?.documentType).toBe('PURCHASE_RECEIPT');

    const overview = await service.getOverview(ctx);
    expect(overview.creditBalanceMinor).toBe(2500);
    expect(overview.recentCreditPurchasedMinor).toBe(2500);
    expect(overview.liveEnvironmentState).toBe('HEALTHY');
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
      creditPackId: 'usd_25',
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
    expect(overview.creditBalanceMinor).toBe(2500);
  });

  test('in-memory service supports custom prepaid checkout amounts', async () => {
    const service = createInMemoryConsoleBillingService();
    const ctx = {
      orgId: 'org-custom-topup-memory',
      actorUserId: 'ops-custom-topup-memory',
      roles: ['ops'],
    };

    const checkoutSession = await service.createStripeCheckoutSession(ctx, {
      successUrl: 'https://app.example.com/dashboard/billing/account?checkout=success',
      cancelUrl: 'https://app.example.com/dashboard/billing/account?checkout=cancel',
      creditPackId: 'usd_custom',
      customAmountMinor: 12345,
    });

    expect(checkoutSession.creditPackId).toBe('usd_custom');
    expect(checkoutSession.amountMinor).toBe(12345);

    const projection = await service.processStripeWebhookEvent({
      eventId: 'evt_mem_custom_amount',
      eventType: 'checkout.session.completed',
      orgId: ctx.orgId,
      checkoutSessionId: checkoutSession.id,
      providerCustomerRef: checkoutSession.customerRef,
      providerRef: checkoutSession.id,
    });

    expect(projection.purchase?.creditPackId).toBe('usd_custom');
    expect(projection.purchase?.amountMinor).toBe(12345);
  });

  test('in-memory service appends manual support credits and admin debits idempotently', async () => {
    const service = createInMemoryConsoleBillingService();
    const ctx = {
      orgId: 'org-manual-adjustments-memory',
      actorUserId: 'admin-manual-adjustments-memory',
      roles: ['admin'],
    };

    const credit = await service.grantManualSupportCredit(ctx, {
      amountMinor: 1200,
      reasonCode: 'incident_credit',
      note: 'Applied support credit after incident review',
      idempotencyKey: 'manual-credit-memory-1',
    });
    expect(credit.created).toBe(true);
    expect(credit.adjustment.type).toBe('MANUAL_ADJUSTMENT');
    expect(credit.adjustment.amountMinor).toBe(1200);
    expect(credit.adjustment.actorType).toBe('USER');
    expect(credit.adjustment.actorUserId).toBe(ctx.actorUserId);
    expect(credit.adjustment.reasonCode).toBe('incident_credit');
    expect(credit.adjustment.note).toContain('incident review');
    expect(credit.adjustment.idempotencyKey).toBe('manual-credit-memory-1');
    expect(credit.creditBalanceMinor).toBe(1200);

    const duplicateCredit = await service.grantManualSupportCredit(ctx, {
      amountMinor: 1200,
      reasonCode: 'incident_credit',
      note: 'Applied support credit after incident review',
      idempotencyKey: 'manual-credit-memory-1',
    });
    expect(duplicateCredit.created).toBe(false);
    expect(duplicateCredit.adjustment.id).toBe(credit.adjustment.id);
    expect(duplicateCredit.creditBalanceMinor).toBe(1200);

    const debit = await service.appendManualAdminDebit(ctx, {
      amountMinor: 300,
      reasonCode: 'duplicate_credit_correction',
      note: 'Corrected duplicate support credit',
      idempotencyKey: 'manual-debit-memory-1',
    });
    expect(debit.created).toBe(true);
    expect(debit.adjustment.amountMinor).toBe(-300);
    expect(debit.adjustment.reasonCode).toBe('duplicate_credit_correction');
    expect(debit.creditBalanceMinor).toBe(900);

    const overview = await service.getOverview(ctx);
    expect(overview.creditBalanceMinor).toBe(900);
    expect(overview.liveEnvironmentState).toBe('LOW_BALANCE');

    const activity = await service.listAccountActivity(ctx, { limit: 5 });
    expect(activity.entries.map((entry) => entry.id)).toEqual([
      debit.adjustment.id,
      credit.adjustment.id,
    ]);
    expect(activity.entries[0]?.amountMinor).toBe(-300);
    expect(activity.entries[1]?.amountMinor).toBe(1200);
  });

  test('in-memory service derives blocked, low-balance, and healthy live-environment states', async () => {
    const service = createInMemoryConsoleBillingService();
    const ctx = {
      orgId: 'org-live-env-state-memory',
      actorUserId: 'admin-live-env-state-memory',
      roles: ['admin'],
    };

    const initialOverview = await service.getOverview(ctx);
    expect(initialOverview.creditBalanceMinor).toBe(0);
    expect(initialOverview.liveEnvironmentState).toBe('BLOCKED');

    await service.grantManualSupportCredit(ctx, {
      amountMinor: 1500,
      reasonCode: 'bootstrap_credit',
      note: 'Seeded balance below warning threshold',
      idempotencyKey: 'live-env-state-credit-low-memory',
    });
    const lowBalanceOverview = await service.getOverview(ctx);
    expect(lowBalanceOverview.creditBalanceMinor).toBe(1500);
    expect(lowBalanceOverview.liveEnvironmentState).toBe('LOW_BALANCE');

    await service.grantManualSupportCredit(ctx, {
      amountMinor: 1000,
      reasonCode: 'bootstrap_credit',
      note: 'Raised balance above warning threshold',
      idempotencyKey: 'live-env-state-credit-healthy-memory',
    });
    const healthyOverview = await service.getOverview(ctx);
    expect(healthyOverview.creditBalanceMinor).toBe(2500);
    expect(healthyOverview.liveEnvironmentState).toBe('HEALTHY');

    await service.appendManualAdminDebit(ctx, {
      amountMinor: 2600,
      reasonCode: 'correction',
      note: 'Corrected overstated prepaid balance',
      idempotencyKey: 'live-env-state-debit-blocked-memory',
    });
    const blockedOverview = await service.getOverview(ctx);
    expect(blockedOverview.creditBalanceMinor).toBe(-100);
    expect(blockedOverview.liveEnvironmentState).toBe('BLOCKED');
  });

  test('in-memory service forbids manual adjustments for non-admin users', async () => {
    const service = createInMemoryConsoleBillingService();
    const ctx = {
      orgId: 'org-manual-adjustments-forbidden-memory',
      actorUserId: 'ops-manual-adjustments-memory',
      roles: ['ops'],
    };

    await expect(
      service.grantManualSupportCredit(ctx, {
        amountMinor: 100,
        reasonCode: 'incident_credit',
        note: 'Should be rejected',
        idempotencyKey: 'manual-credit-forbidden-memory',
      }),
    ).rejects.toMatchObject({
      code: 'forbidden',
      status: 403,
    });

    await expect(
      service.appendManualAdminDebit(ctx, {
        amountMinor: 100,
        reasonCode: 'manual_debit',
        note: 'Should be rejected',
        idempotencyKey: 'manual-debit-forbidden-memory',
      }),
    ).rejects.toMatchObject({
      code: 'forbidden',
      status: 403,
    });
  });

  test('in-memory service links manual adjustments to invoice activity when relatedInvoiceId is provided', async () => {
    const service = createInMemoryConsoleBillingService();
    const ctx = {
      orgId: 'org-manual-adjustments-linked-memory',
      actorUserId: 'admin-manual-adjustments-linked-memory',
      roles: ['admin'],
    };

    const settled = await settleCreditPurchase(service, ctx, 'usd_25');
    const credit = await service.grantManualSupportCredit(ctx, {
      amountMinor: 500,
      reasonCode: 'invoice_correction',
      note: 'Linked credit for receipt correction timeline visibility',
      idempotencyKey: 'manual-credit-linked-memory-1',
      relatedInvoiceId: settled.invoice.id,
    });
    expect(credit.adjustment.relatedInvoiceId).toBe(settled.invoice.id);

    const invoiceActivity = await service.getInvoiceActivity(ctx, settled.invoice.id);
    expect(invoiceActivity).toBeTruthy();
    expect(
      invoiceActivity?.entries.some(
        (entry) =>
          entry.id === `${credit.adjustment.id}:MANUAL_ADJUSTMENT` &&
          entry.visibility === 'INTERNAL',
      ),
    ).toBe(true);

    const accountActivity = await service.listAccountActivity(ctx, { limit: 5 });
    expect(accountActivity.entries[0]?.relatedInvoiceId).toBe(settled.invoice.id);
  });

  test('in-memory service requires owner role for large manual admin debits', async () => {
    const service = createInMemoryConsoleBillingService();
    const adminCtx = {
      orgId: 'org-manual-adjustments-large-debit-memory',
      actorUserId: 'admin-manual-adjustments-large-debit-memory',
      roles: ['admin'],
    };

    await service.grantManualSupportCredit(adminCtx, {
      amountMinor: 75_000,
      reasonCode: 'bootstrap_credit',
      note: 'Seeded large balance for debit authorization test',
      idempotencyKey: 'manual-credit-large-debit-memory-1',
    });

    await expect(
      service.appendManualAdminDebit(adminCtx, {
        amountMinor: 50_000,
        reasonCode: 'large_debit_correction',
        note: 'Should require owner role',
        idempotencyKey: 'manual-debit-large-debit-memory-forbidden',
      }),
    ).rejects.toMatchObject({
      code: 'forbidden',
      status: 403,
    });

    const ownerCtx = {
      ...adminCtx,
      roles: ['admin', 'owner'],
    };
    const debit = await service.appendManualAdminDebit(ownerCtx, {
      amountMinor: 50_000,
      reasonCode: 'large_debit_correction',
      note: 'Owner approved large debit',
      idempotencyKey: 'manual-debit-large-debit-memory-owner',
    });
    expect(debit.created).toBe(true);
    expect(debit.adjustment.amountMinor).toBe(-50_000);
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
    const receipt = await settleCreditPurchase(service, ctx, 'usd_25');
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

  test('in-memory service derives invoice projections from purchases and ledger entries', async () => {
    let current = new Date('2026-03-20T00:00:00.000Z');
    const service = createInMemoryConsoleBillingService({
      now: () => current,
    });
    const ctx = {
      orgId: 'org-invoice-projection-memory',
      actorUserId: 'ops-invoice-projection',
      roles: ['ops'],
    };

    const usage = await service.recordUsageEvent(ctx, {
      walletId: 'wallet_projection_1',
      action: 'transfer',
      succeeded: true,
      sourceEventId: 'projection_mem_usage_1',
      occurredAt: '2026-03-09T00:00:00.000Z',
    });
    expect(usage.statementId).toBeTruthy();

    const receipt = await settleCreditPurchase(service, ctx, 'usd_25');

    const invoices = await service.listInvoices(ctx);
    expect(invoices.some((invoice) => invoice.id === usage.statementId)).toBe(true);
    expect(invoices.some((invoice) => invoice.id === receipt.invoice.id)).toBe(true);

    const statement = await service.getInvoice(ctx, String(usage.statementId || ''));
    expect(statement?.documentType).toBe('USAGE_STATEMENT');
    expect(statement?.amountDueMinor).toBe(300);

    const statementItems = await service.listInvoiceLineItems(ctx, String(usage.statementId || ''));
    expect(statementItems.length).toBe(1);
    expect(statementItems[0]?.itemType).toBe('MAW_USAGE_DEBIT');
    expect(statementItems[0]?.amountMinor).toBe(300);

    const receiptItems = await service.listInvoiceLineItems(ctx, receipt.invoice.id);
    expect(receiptItems.length).toBe(1);
    expect(receiptItems[0]?.itemType).toBe('CREDIT_TOP_UP');
    expect(receiptItems[0]?.amountMinor).toBe(2500);

    const statementActivity = await service.getInvoiceActivity(
      ctx,
      String(usage.statementId || ''),
    );
    expect(
      statementActivity?.entries.some(
        (entry) => entry.type === 'LEDGER' && entry.toState === 'USAGE_DEBIT',
      ),
    ).toBe(true);

    const receiptActivity = await service.getInvoiceActivity(ctx, receipt.invoice.id);
    expect(
      receiptActivity?.entries.some(
        (entry) => entry.type === 'LEDGER' && entry.toState === 'CREDIT_PURCHASE',
      ),
    ).toBe(true);
  });
});

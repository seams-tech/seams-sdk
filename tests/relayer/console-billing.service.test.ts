import { test, expect } from '@playwright/test';
import {
  createInMemoryConsoleBillingService,
  createPostgresConsoleBillingService,
  type ConsoleBillingService,
} from '@server/router/express-adaptor';
import { getPostgresPool } from '../../server/src/storage/postgres';

function randomNamespace(prefix: string): string {
  return `${prefix}:${Date.now()}:${Math.random().toString(16).slice(2)}`;
}

async function expectBillingError(
  fn: () => Promise<unknown>,
  code: string,
): Promise<void> {
  let caught: any;
  try {
    await fn();
  } catch (error: unknown) {
    caught = error;
  }
  expect(caught).toBeTruthy();
  expect(String(caught?.code || '')).toBe(code);
}

test.describe('console billing service rbac', () => {
  test('in-memory service uses injected billing provider adapters', async () => {
    const service = createInMemoryConsoleBillingService({
      providers: {
        stripe: {
          createSetupIntent: () => ({
            id: 'seti_mem_provider',
            clientSecret: 'seti_mem_provider_secret',
            customerRef: 'cus_mem_provider',
            expiresAt: '2026-03-01T00:30:00.000Z',
          }),
          createPaymentIntent: () => ({
            providerRef: 'pi_mem_provider',
            clientSecret: 'pi_mem_provider_secret',
          }),
        },
        stablecoin: {
          allocateDestination: () => ({
            destinationAddress: 'pay_mem_provider_destination',
          }),
        },
      },
    });

    const cardCtx = {
      orgId: 'org-provider-adapter-memory-card',
      actorUserId: 'ops-provider-adapter-memory',
      roles: ['ops'],
    };
    const setupIntent = await service.createStripeSetupIntent(cardCtx, {});
    expect(setupIntent.id).toBe('seti_mem_provider');
    expect(setupIntent.clientSecret).toBe('seti_mem_provider_secret');
    expect(setupIntent.customerRef).toBe('cus_mem_provider');
    expect(setupIntent.expiresAt).toBe('2026-03-01T00:30:00.000Z');

    const cardInvoices = await service.listInvoices(cardCtx);
    expect(cardInvoices.length).toBeGreaterThan(0);
    const cardIntent = await service.createStripePaymentIntent(cardCtx, {
      invoiceId: cardInvoices[0].id,
    });
    expect(cardIntent.providerRef).toBe('pi_mem_provider');
    expect(cardIntent.clientSecret).toBe('pi_mem_provider_secret');

    const stableCtx = {
      orgId: 'org-provider-adapter-memory-stable',
      actorUserId: 'ops-provider-adapter-memory',
      roles: ['ops'],
    };
    const stableInvoices = await service.listInvoices(stableCtx);
    expect(stableInvoices.length).toBeGreaterThan(0);
    const quote = await service.createStablecoinQuote(stableCtx, {
      invoiceId: stableInvoices[0].id,
      asset: 'USDC',
      chain: 'Ethereum',
    });
    const stableIntent = await service.createStablecoinPaymentIntent(stableCtx, {
      invoiceId: stableInvoices[0].id,
      quoteId: quote.id,
    });
    expect(stableIntent.destinationAddress).toBe('pay_mem_provider_destination');
  });

  test('in-memory service enforces admin-only card mutations', async () => {
    const service = createInMemoryConsoleBillingService();
    const nonAdminCtx = {
      orgId: 'org-rbac-memory',
      actorUserId: 'billing-admin-1',
      roles: ['billing_admin'],
    };

    await expectBillingError(
      async () => {
        await service.addCardPaymentMethod(nonAdminCtx, {
          providerRef: 'pm_mem_forbidden',
          brand: 'visa',
          last4: '4242',
          expMonth: 1,
          expYear: 2031,
        });
      },
      'forbidden',
    );

    await expectBillingError(
      async () => {
        await service.removeCardPaymentMethod(nonAdminCtx, 'pm_missing');
      },
      'forbidden',
    );

    await expectBillingError(
      async () => {
        await service.setDefaultCardPaymentMethod(nonAdminCtx, 'pm_missing');
      },
      'forbidden',
    );
  });

  test('in-memory service reconciles stablecoin intent to settled', async () => {
    const service = createInMemoryConsoleBillingService();
    const ctx = {
      orgId: 'org-reconcile-memory',
      actorUserId: 'ops-1',
      roles: ['ops'],
    };

    const invoices = await service.listInvoices(ctx);
    expect(invoices.length).toBeGreaterThan(0);
    const invoiceId = invoices[0].id;

    const quote = await service.createStablecoinQuote(ctx, {
      invoiceId,
      asset: 'USDC',
      chain: 'Ethereum',
    });
    const created = await service.createStablecoinPaymentIntent(ctx, {
      invoiceId,
      quoteId: quote.id,
    });
    expect(created.state).toBe('PENDING');

    const confirming = await service.reconcileStablecoinPaymentIntent(ctx, created.id, {
      observedAmountMinor: created.expectedAmountMinor,
      observedConfirmations: Math.max(created.requiredConfirmations - 1, 0),
    });
    expect(confirming?.state).toBe('CONFIRMING');

    const settled = await service.reconcileStablecoinPaymentIntent(ctx, created.id, {
      observedAmountMinor: created.expectedAmountMinor,
      observedConfirmations: created.requiredConfirmations,
    });
    expect(settled?.state).toBe('SETTLED');
    expect(settled?.settledAt).toBeTruthy();
    expect(settled?.reorgRiskWindowEndsAt).toBeTruthy();
    expect(settled?.withinReorgRiskWindow).toBe(true);

    const invoice = await service.getInvoice(ctx, invoiceId);
    expect(invoice?.status).toBe('PAID');
  });

  test('in-memory service tracks stablecoin post-settlement reorg risk window', async () => {
    let current = new Date('2026-03-01T00:00:00.000Z');
    const service = createInMemoryConsoleBillingService({
      now: () => current,
    });
    const ctx = {
      orgId: 'org-stablecoin-risk-window-memory',
      actorUserId: 'ops-risk-window',
      roles: ['ops'],
    };

    const invoices = await service.listInvoices(ctx);
    expect(invoices.length).toBeGreaterThan(0);
    const invoiceId = invoices[0].id;

    const quote = await service.createStablecoinQuote(ctx, {
      invoiceId,
      asset: 'USDC',
      chain: 'NEAR',
    });
    const created = await service.createStablecoinPaymentIntent(ctx, {
      invoiceId,
      quoteId: quote.id,
    });
    const settled = await service.reconcileStablecoinPaymentIntent(ctx, created.id, {
      observedAmountMinor: created.expectedAmountMinor,
      observedConfirmations: created.requiredConfirmations,
    });
    expect(settled?.state).toBe('SETTLED');
    expect(settled?.settledAt).toBe(current.toISOString());
    expect(settled?.reorgRiskWindowEndsAt).toBe(new Date(current.getTime() + (6 * 60 * 60 * 1000)).toISOString());
    expect(settled?.withinReorgRiskWindow).toBe(true);

    current = new Date(current.getTime() + (6 * 60 * 60 * 1000) + (60 * 1000));
    const afterRiskWindow = await service.getStablecoinPaymentIntent(ctx, created.id);
    expect(afterRiskWindow?.state).toBe('SETTLED');
    expect(afterRiskWindow?.withinReorgRiskWindow).toBe(false);
    expect(afterRiskWindow?.reorgRiskWindowEndsAt).toBe(new Date(new Date('2026-03-01T00:00:00.000Z').getTime() + (6 * 60 * 60 * 1000)).toISOString());
  });

  test('in-memory service auto-expires stablecoin intent before reconcile/cancel', async () => {
    let current = new Date('2026-03-01T00:00:00.000Z');
    const service = createInMemoryConsoleBillingService({
      now: () => current,
    });
    const ctx = {
      orgId: 'org-expire-guard-memory',
      actorUserId: 'ops-expire-guard',
      roles: ['ops'],
    };

    const invoices = await service.listInvoices(ctx);
    expect(invoices.length).toBeGreaterThan(0);
    const invoiceId = invoices[0].id;

    const quote = await service.createStablecoinQuote(ctx, {
      invoiceId,
      asset: 'USDC',
      chain: 'Ethereum',
    });
    const created = await service.createStablecoinPaymentIntent(ctx, {
      invoiceId,
      quoteId: quote.id,
    });
    expect(created.state).toBe('PENDING');

    current = new Date(current.getTime() + (16 * 60 * 1000));

    const reconciled = await service.reconcileStablecoinPaymentIntent(ctx, created.id, {
      observedAmountMinor: created.expectedAmountMinor,
      observedConfirmations: created.requiredConfirmations,
    });
    expect(reconciled?.state).toBe('EXPIRED');

    const canceled = await service.cancelStablecoinPaymentIntent(ctx, created.id);
    expect(canceled?.state).toBe('EXPIRED');

    const invoice = await service.getInvoice(ctx, invoiceId);
    expect(invoice?.status).toBe('OPEN');
    expect(invoice?.amountPaidMinor).toBe(0);
  });

  test('in-memory service enforces stablecoin quote single-use and stale-amount guards', async () => {
    const service = createInMemoryConsoleBillingService();
    const ctx = {
      orgId: 'org-quote-semantics-memory',
      actorUserId: 'ops-quote-semantics',
      roles: ['ops'],
    };

    const invoices = await service.listInvoices(ctx);
    expect(invoices.length).toBeGreaterThan(0);
    const invoiceId = invoices[0].id;

    const quoteA = await service.createStablecoinQuote(ctx, {
      invoiceId,
      asset: 'USDC',
      chain: 'Ethereum',
    });
    const createdA = await service.createStablecoinPaymentIntent(ctx, {
      invoiceId,
      quoteId: quoteA.id,
    });
    expect(createdA.state).toBe('PENDING');
    const canceledA = await service.cancelStablecoinPaymentIntent(ctx, createdA.id);
    expect(canceledA?.state).toBe('CANCELED');

    await expectBillingError(
      async () => {
        await service.createStablecoinPaymentIntent(ctx, {
          invoiceId,
          quoteId: quoteA.id,
        });
      },
      'quote_already_consumed',
    );

    const quoteB = await service.createStablecoinQuote(ctx, {
      invoiceId,
      asset: 'USDT',
      chain: 'Base',
    });
    const quoteC = await service.createStablecoinQuote(ctx, {
      invoiceId,
      asset: 'USDT',
      chain: 'Base',
    });
    const createdB = await service.createStablecoinPaymentIntent(ctx, {
      invoiceId,
      quoteId: quoteB.id,
    });
    expect(createdB.state).toBe('PENDING');

    const partialAmount = Math.max(createdB.expectedAmountMinor - 1, 1);
    const partiallySettled = await service.reconcileStablecoinPaymentIntent(ctx, createdB.id, {
      observedAmountMinor: partialAmount,
      observedConfirmations: createdB.requiredConfirmations,
    });
    expect(partiallySettled?.state).toBe('PARTIALLY_SETTLED');

    await expectBillingError(
      async () => {
        await service.createStablecoinPaymentIntent(ctx, {
          invoiceId,
          quoteId: quoteC.id,
        });
      },
      'quote_amount_mismatch',
    );
  });

  test('in-memory service blocks concurrent active card payment intents on one invoice', async () => {
    const service = createInMemoryConsoleBillingService();
    const ctx = {
      orgId: 'org-card-intent-gate-memory',
      actorUserId: 'ops-card-intent-gate',
      roles: ['ops'],
    };

    const invoices = await service.listInvoices(ctx);
    expect(invoices.length).toBeGreaterThan(0);
    const invoiceId = invoices[0].id;

    const firstIntent = await service.createStripePaymentIntent(ctx, {
      invoiceId,
    });
    expect(firstIntent.state).toBe('CREATED');

    await expectBillingError(
      async () => {
        await service.createStripePaymentIntent(ctx, {
          invoiceId,
        });
      },
      'active_payment_intent_exists',
    );
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

    const secondSameWallet = await service.recordUsageEvent(ctx, {
      walletId: 'wallet_mem_1',
      action: 'swap',
      succeeded: true,
      sourceEventId: 'maw_mem_evt_2',
    });
    expect(secondSameWallet.accepted).toBe(true);
    expect(secondSameWallet.counted).toBe(true);
    expect(secondSameWallet.monthlyActiveWallets).toBe(1);

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

  test('in-memory service creates one invoice per org per period month', async () => {
    let current = new Date('2026-01-20T00:00:00.000Z');
    const service = createInMemoryConsoleBillingService({
      now: () => current,
    });
    const ctx = {
      orgId: 'org-month-rollover-memory',
      actorUserId: 'ops-month-rollover',
      roles: ['ops'],
    };

    const janInvoices = await service.listInvoices(ctx);
    expect(janInvoices.length).toBe(1);
    expect(janInvoices[0].periodMonthUtc).toBe('2026-01');

    current = new Date('2026-02-02T00:00:00.000Z');
    const febInvoices = await service.listInvoices(ctx);
    expect(febInvoices.some((invoice) => invoice.periodMonthUtc === '2026-01')).toBe(true);
    expect(febInvoices.some((invoice) => invoice.periodMonthUtc === '2026-02')).toBe(true);
    expect(febInvoices.filter((invoice) => invoice.periodMonthUtc === '2026-02').length).toBe(1);

    current = new Date('2026-02-10T00:00:00.000Z');
    const febInvoicesAgain = await service.listInvoices(ctx);
    expect(febInvoicesAgain.filter((invoice) => invoice.periodMonthUtc === '2026-02').length).toBe(1);
  });

  test('in-memory service generates monthly invoice from MAW rollup with deterministic line items', async () => {
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
    expect(generation.generated).toBe(true);
    expect(generation.monthlyActiveWallets).toBe(2);
    expect(generation.pricing.baseFeeMinor).toBe(1900);
    expect(generation.pricing.mawUnitPriceMinor).toBe(300);
    expect(generation.invoice.periodMonthUtc).toBe('2026-01');
    expect(generation.invoice.amountDueMinor).toBe(2500);
    expect(generation.lineItems.length).toBe(2);
    const baseFeeItem = generation.lineItems.find((item) => item.itemType === 'PLAN_BASE_FEE');
    const mawItem = generation.lineItems.find((item) => item.itemType === 'MAW_USAGE');
    expect(baseFeeItem?.amountMinor).toBe(1900);
    expect(mawItem?.quantity).toBe(2);
    expect(mawItem?.amountMinor).toBe(600);

    const listed = await service.listInvoiceLineItems(ctx, generation.invoice.id);
    expect(listed.length).toBe(2);

    const secondRun = await service.generateMonthlyInvoice(ctx, {
      periodMonthUtc: '2026-01',
    });
    expect(secondRun.generated).toBe(false);
    expect(secondRun.invoice.amountDueMinor).toBe(2500);
  });

  test('in-memory service reconciles stripe intent to settled', async () => {
    const service = createInMemoryConsoleBillingService();
    const ctx = {
      orgId: 'org-stripe-reconcile-memory',
      actorUserId: 'ops-2',
      roles: ['ops'],
    };

    const invoices = await service.listInvoices(ctx);
    expect(invoices.length).toBeGreaterThan(0);
    const invoiceId = invoices[0].id;

    const created = await service.createStripePaymentIntent(ctx, {
      invoiceId,
    });
    expect(created.state).toBe('CREATED');

    const actionRequired = await service.reconcileStripePaymentIntent(ctx, created.id, {
      providerStatus: 'ACTION_REQUIRED',
      sourceEventId: `evt_${Date.now()}_action_required`,
    });
    expect(actionRequired?.state).toBe('ACTION_REQUIRED');

    const pending = await service.reconcileStripePaymentIntent(ctx, created.id, {
      providerStatus: 'PENDING',
      sourceEventId: `evt_${Date.now()}_pending`,
    });
    expect(pending?.state).toBe('PENDING');

    const settled = await service.reconcileStripePaymentIntent(ctx, created.id, {
      providerStatus: 'SUCCEEDED',
      settledAmountMinor: created.amountMinor,
      sourceEventId: `evt_${Date.now()}_succeeded`,
    });
    expect(settled?.state).toBe('SETTLED');

    const invoice = await service.getInvoice(ctx, invoiceId);
    expect(invoice?.status).toBe('PAID');
  });

  test('in-memory service processes Stripe webhook events idempotently by event id', async () => {
    const service = createInMemoryConsoleBillingService();
    const ctx = {
      orgId: 'org-stripe-webhook-memory',
      actorUserId: 'ops-webhook-memory',
      roles: ['ops'],
    };

    const invoices = await service.listInvoices(ctx);
    expect(invoices.length).toBeGreaterThan(0);
    const invoiceId = invoices[0].id;

    const created = await service.createStripePaymentIntent(ctx, {
      invoiceId,
    });
    expect(created.state).toBe('CREATED');

    const first = await service.processStripeWebhookEvent({
      eventId: `evt_mem_${Date.now()}_1`,
      providerRef: created.providerRef,
      providerStatus: 'SUCCEEDED',
      settledAmountMinor: created.amountMinor,
    });
    expect(first.accepted).toBe(true);
    expect(first.paymentIntent?.state).toBe('SETTLED');

    const sameEvent = await service.processStripeWebhookEvent({
      eventId: 'evt_mem_same',
      providerRef: created.providerRef,
      providerStatus: 'SUCCEEDED',
      settledAmountMinor: created.amountMinor,
    });
    expect(sameEvent.accepted).toBe(true);
    expect(sameEvent.paymentIntent?.state).toBe('SETTLED');
    const sameEventDuplicate = await service.processStripeWebhookEvent({
      eventId: 'evt_mem_same',
      providerRef: created.providerRef,
      providerStatus: 'SUCCEEDED',
      settledAmountMinor: created.amountMinor,
    });
    expect(sameEventDuplicate.accepted).toBe(false);
    expect(sameEventDuplicate.paymentIntent?.state).toBe('SETTLED');

    const invoice = await service.getInvoice(ctx, invoiceId);
    expect(invoice?.status).toBe('PAID');
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
      await expectBillingError(
        async () => {
          await service.addCardPaymentMethod(nonAdminCtx, {
            providerRef: 'pm_pg_forbidden',
            brand: 'visa',
            last4: '4242',
            expMonth: 1,
            expYear: 2031,
          });
        },
        'forbidden',
      );

      await expectBillingError(
        async () => {
          await service.removeCardPaymentMethod(nonAdminCtx, 'pm_missing');
        },
        'forbidden',
      );
    } finally {
      const pool = await getPostgresPool(postgresUrl);
      await pool.query('DELETE FROM console_payment_state_transitions WHERE namespace = $1', [namespace]);
      await pool.query('DELETE FROM console_stripe_webhook_events WHERE namespace = $1', [namespace]);
      await pool.query('DELETE FROM console_stablecoin_payment_intents WHERE namespace = $1', [namespace]);
      await pool.query('DELETE FROM console_stablecoin_quotes WHERE namespace = $1', [namespace]);
      await pool.query('DELETE FROM console_stripe_payment_intents WHERE namespace = $1', [namespace]);
      await pool.query('DELETE FROM console_payment_methods WHERE namespace = $1', [namespace]);
      await pool.query('DELETE FROM console_invoice_line_items WHERE namespace = $1', [namespace]);
      await pool.query('DELETE FROM console_usage_rollups_monthly WHERE namespace = $1', [namespace]);
      await pool.query('DELETE FROM console_usage_meter_events WHERE namespace = $1', [namespace]);
      await pool.query('DELETE FROM console_invoices WHERE namespace = $1', [namespace]);
      await pool.query('DELETE FROM console_billing_accounts WHERE namespace = $1', [namespace]);
    }
  });
});

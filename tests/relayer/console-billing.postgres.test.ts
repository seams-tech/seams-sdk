import { test, expect } from '@playwright/test';
import {
  createPostgresConsoleBillingService,
  runPostgresConsoleBillingMonthlyFinalization,
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

test.describe('console billing postgres service', () => {
  const postgresUrl = String(process.env.POSTGRES_URL || '').trim();
  const enabled = Boolean(postgresUrl);
  const namespace = randomNamespace('test:console-billing:postgres');
  let service: ConsoleBillingService | null = null;

  test.beforeAll(async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    service = await createPostgresConsoleBillingService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
    });
  });

  test.afterAll(async () => {
    if (!enabled) return;
    const pool = await getPostgresPool(postgresUrl);
    // Transition ledger is append-only by contract; cleanup omits this table.
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
  });

  test('stablecoin payment intent locks invoice rail from stripe card rail', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ctx = {
      orgId: 'org-postgres-rail-lock',
      actorUserId: 'admin-1',
      roles: ['admin'],
    };
    const invoices = await service!.listInvoices(ctx);
    expect(invoices.length).toBeGreaterThan(0);
    const invoiceId = invoices[0].id;

    const quote = await service!.createStablecoinQuote(ctx, {
      invoiceId,
      asset: 'USDC',
      chain: 'Base',
    });
    expect(quote.id).toBeTruthy();

    const intent = await service!.createStablecoinPaymentIntent(ctx, {
      invoiceId,
      quoteId: quote.id,
    });
    expect(intent.rail).toBe('STABLECOIN');
    expect(intent.requiredConfirmations).toBe(20);

    await expectBillingError(
      async () => {
        await service!.createStripePaymentIntent(ctx, { invoiceId });
      },
      'invoice_rail_locked',
    );
  });

  test('card payment method lifecycle keeps a default method', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ctx = {
      orgId: 'org-postgres-card-defaults',
      actorUserId: 'admin-2',
      roles: ['admin'],
    };

    const pm1 = await service!.addCardPaymentMethod(ctx, {
      providerRef: 'pm_pg_1',
      brand: 'visa',
      last4: '1111',
      expMonth: 1,
      expYear: 2031,
    });
    expect(pm1.isDefault).toBe(true);

    const pm2 = await service!.addCardPaymentMethod(ctx, {
      providerRef: 'pm_pg_2',
      brand: 'mastercard',
      last4: '2222',
      expMonth: 2,
      expYear: 2032,
    });
    expect(pm2.isDefault).toBe(false);

    const updatedDefault = await service!.setDefaultCardPaymentMethod(ctx, pm2.id);
    expect(updatedDefault?.id).toBe(pm2.id);
    expect(updatedDefault?.isDefault).toBe(true);

    const removed = await service!.removeCardPaymentMethod(ctx, pm2.id);
    expect(removed.removed).toBe(true);

    const methods = await service!.listPaymentMethods(ctx);
    expect(methods.length).toBe(1);
    expect(methods[0].id).toBe(pm1.id);
    expect(methods[0].isDefault).toBe(true);
  });

  test('postgres service uses injected billing provider adapters', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const providerNamespace = randomNamespace('test:console-billing:providers');
    const providerService = await createPostgresConsoleBillingService({
      postgresUrl,
      namespace: providerNamespace,
      logger: console as any,
      ensureSchema: true,
      providers: {
        stripe: {
          createSetupIntent: () => ({
            id: 'seti_pg_provider',
            clientSecret: 'seti_pg_provider_secret',
            customerRef: 'cus_pg_provider',
            expiresAt: '2026-03-01T00:30:00.000Z',
          }),
          createPaymentIntent: () => ({
            providerRef: 'pi_pg_provider',
            clientSecret: 'pi_pg_provider_secret',
          }),
        },
        stablecoin: {
          allocateDestination: () => ({
            destinationAddress: 'pay_pg_provider_destination',
          }),
        },
      },
    });
    const cardCtx = {
      orgId: 'org-postgres-provider-adapter-card',
      actorUserId: 'ops-provider-adapter',
      roles: ['ops'],
    };
    const stableCtx = {
      orgId: 'org-postgres-provider-adapter-stable',
      actorUserId: 'ops-provider-adapter',
      roles: ['ops'],
    };

    try {
      const setupIntent = await providerService.createStripeSetupIntent(cardCtx, {});
      expect(setupIntent.id).toBe('seti_pg_provider');
      expect(setupIntent.clientSecret).toBe('seti_pg_provider_secret');
      expect(setupIntent.customerRef).toBe('cus_pg_provider');
      expect(setupIntent.expiresAt).toBe('2026-03-01T00:30:00.000Z');

      const cardInvoices = await providerService.listInvoices(cardCtx);
      expect(cardInvoices.length).toBeGreaterThan(0);
      const cardIntent = await providerService.createStripePaymentIntent(cardCtx, {
        invoiceId: cardInvoices[0].id,
      });
      expect(cardIntent.providerRef).toBe('pi_pg_provider');
      expect(cardIntent.clientSecret).toBe('pi_pg_provider_secret');

      const stableInvoices = await providerService.listInvoices(stableCtx);
      expect(stableInvoices.length).toBeGreaterThan(0);
      const quote = await providerService.createStablecoinQuote(stableCtx, {
        invoiceId: stableInvoices[0].id,
        asset: 'USDT',
        chain: 'Base',
      });
      const stableIntent = await providerService.createStablecoinPaymentIntent(stableCtx, {
        invoiceId: stableInvoices[0].id,
        quoteId: quote.id,
      });
      expect(stableIntent.destinationAddress).toBe('pay_pg_provider_destination');
    } finally {
      const pool = await getPostgresPool(postgresUrl);
      await pool.query('DELETE FROM console_stripe_webhook_events WHERE namespace = $1', [providerNamespace]);
      await pool.query('DELETE FROM console_stablecoin_payment_intents WHERE namespace = $1', [providerNamespace]);
      await pool.query('DELETE FROM console_stablecoin_quotes WHERE namespace = $1', [providerNamespace]);
      await pool.query('DELETE FROM console_stripe_payment_intents WHERE namespace = $1', [providerNamespace]);
      await pool.query('DELETE FROM console_payment_methods WHERE namespace = $1', [providerNamespace]);
      await pool.query('DELETE FROM console_invoice_line_items WHERE namespace = $1', [providerNamespace]);
      await pool.query('DELETE FROM console_usage_rollups_monthly WHERE namespace = $1', [providerNamespace]);
      await pool.query('DELETE FROM console_usage_meter_events WHERE namespace = $1', [providerNamespace]);
      await pool.query('DELETE FROM console_invoices WHERE namespace = $1', [providerNamespace]);
      await pool.query('DELETE FROM console_billing_accounts WHERE namespace = $1', [providerNamespace]);
    }
  });

  test('reconcile moves intent confirming -> settled and updates invoice', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ctx = {
      orgId: 'org-postgres-reconcile',
      actorUserId: 'admin-4',
      roles: ['admin'],
    };
    const invoices = await service!.listInvoices(ctx);
    expect(invoices.length).toBeGreaterThan(0);
    const invoiceId = invoices[0].id;

    const quote = await service!.createStablecoinQuote(ctx, {
      invoiceId,
      asset: 'USDT',
      chain: 'Ethereum',
    });
    const created = await service!.createStablecoinPaymentIntent(ctx, {
      invoiceId,
      quoteId: quote.id,
    });
    expect(created.state).toBe('PENDING');

    const confirming = await service!.reconcileStablecoinPaymentIntent(ctx, created.id, {
      observedAmountMinor: created.expectedAmountMinor,
      observedConfirmations: Math.max(created.requiredConfirmations - 1, 0),
      sourceEventId: `evt_${Date.now()}_confirming`,
    });
    expect(confirming?.state).toBe('CONFIRMING');

    const settled = await service!.reconcileStablecoinPaymentIntent(ctx, created.id, {
      observedAmountMinor: created.expectedAmountMinor,
      observedConfirmations: created.requiredConfirmations,
      sourceEventId: `evt_${Date.now()}_settled`,
    });
    expect(settled?.state).toBe('SETTLED');
    expect(settled?.settledAt).toBeTruthy();
    expect(settled?.reorgRiskWindowEndsAt).toBeTruthy();
    expect(settled?.withinReorgRiskWindow).toBe(true);

    const invoice = await service!.getInvoice(ctx, invoiceId);
    expect(invoice?.status).toBe('PAID');
    expect(Number(invoice?.amountPaidMinor || 0)).toBeGreaterThanOrEqual(created.expectedAmountMinor);

    const pool = await getPostgresPool(postgresUrl);
    const transitions = await pool.query(
      `SELECT from_state, to_state, reason
         FROM console_payment_state_transitions
        WHERE namespace = $1 AND payment_id = $2
        ORDER BY id ASC`,
      [namespace, created.id],
    );
    expect(transitions.rows.length).toBe(3);
    expect(String((transitions.rows[0] as any).to_state)).toBe('PENDING');
    expect(String((transitions.rows[1] as any).to_state)).toBe('CONFIRMING');
    expect(String((transitions.rows[2] as any).to_state)).toBe('SETTLED');
  });

  test('stablecoin settlement stores and updates post-settlement reorg risk window state', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const riskNamespace = randomNamespace('test:console-billing:risk-window');
    let current = new Date('2026-03-01T00:00:00.000Z');
    const riskService = await createPostgresConsoleBillingService({
      postgresUrl,
      namespace: riskNamespace,
      logger: console as any,
      ensureSchema: true,
      now: () => current,
    });
    const ctx = {
      orgId: 'org-postgres-risk-window',
      actorUserId: 'ops-risk-window',
      roles: ['ops'],
    };

    try {
      const invoices = await riskService.listInvoices(ctx);
      expect(invoices.length).toBeGreaterThan(0);
      const invoiceId = invoices[0].id;

      const quote = await riskService.createStablecoinQuote(ctx, {
        invoiceId,
        asset: 'USDC',
        chain: 'NEAR',
      });
      const created = await riskService.createStablecoinPaymentIntent(ctx, {
        invoiceId,
        quoteId: quote.id,
      });
      const settled = await riskService.reconcileStablecoinPaymentIntent(ctx, created.id, {
        observedAmountMinor: created.expectedAmountMinor,
        observedConfirmations: created.requiredConfirmations,
        sourceEventId: `evt_${Date.now()}_risk_settled`,
      });
      const expectedRiskEndsAt = new Date(current.getTime() + (6 * 60 * 60 * 1000)).toISOString();
      expect(settled?.state).toBe('SETTLED');
      expect(settled?.settledAt).toBe(current.toISOString());
      expect(settled?.reorgRiskWindowEndsAt).toBe(expectedRiskEndsAt);
      expect(settled?.withinReorgRiskWindow).toBe(true);

      const pool = await getPostgresPool(postgresUrl);
      const persisted = await pool.query(
        `SELECT settled_at_ms, reorg_risk_window_ends_at_ms
           FROM console_stablecoin_payment_intents
          WHERE namespace = $1 AND id = $2`,
        [riskNamespace, created.id],
      );
      expect(persisted.rows.length).toBe(1);
      expect(Number((persisted.rows[0] as any).settled_at_ms || 0)).toBe(current.getTime());
      expect(Number((persisted.rows[0] as any).reorg_risk_window_ends_at_ms || 0)).toBe(current.getTime() + (6 * 60 * 60 * 1000));

      current = new Date(current.getTime() + (6 * 60 * 60 * 1000) + (60 * 1000));
      const afterRiskWindow = await riskService.getStablecoinPaymentIntent(ctx, created.id);
      expect(afterRiskWindow?.state).toBe('SETTLED');
      expect(afterRiskWindow?.reorgRiskWindowEndsAt).toBe(expectedRiskEndsAt);
      expect(afterRiskWindow?.withinReorgRiskWindow).toBe(false);
    } finally {
      const pool = await getPostgresPool(postgresUrl);
      await pool.query('DELETE FROM console_stripe_webhook_events WHERE namespace = $1', [riskNamespace]);
      await pool.query('DELETE FROM console_stablecoin_payment_intents WHERE namespace = $1', [riskNamespace]);
      await pool.query('DELETE FROM console_stablecoin_quotes WHERE namespace = $1', [riskNamespace]);
      await pool.query('DELETE FROM console_stripe_payment_intents WHERE namespace = $1', [riskNamespace]);
      await pool.query('DELETE FROM console_payment_methods WHERE namespace = $1', [riskNamespace]);
      await pool.query('DELETE FROM console_invoice_line_items WHERE namespace = $1', [riskNamespace]);
      await pool.query('DELETE FROM console_usage_rollups_monthly WHERE namespace = $1', [riskNamespace]);
      await pool.query('DELETE FROM console_usage_meter_events WHERE namespace = $1', [riskNamespace]);
      await pool.query('DELETE FROM console_invoices WHERE namespace = $1', [riskNamespace]);
      await pool.query('DELETE FROM console_billing_accounts WHERE namespace = $1', [riskNamespace]);
    }
  });

  test('stablecoin quote semantics enforce single-use and stale-amount guards', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ctx = {
      orgId: 'org-postgres-quote-semantics',
      actorUserId: 'ops-quote-semantics',
      roles: ['ops'],
    };
    const invoices = await service!.listInvoices(ctx);
    expect(invoices.length).toBeGreaterThan(0);
    const invoiceId = invoices[0].id;

    const quoteA = await service!.createStablecoinQuote(ctx, {
      invoiceId,
      asset: 'USDC',
      chain: 'Ethereum',
    });
    const createdA = await service!.createStablecoinPaymentIntent(ctx, {
      invoiceId,
      quoteId: quoteA.id,
    });
    expect(createdA.state).toBe('PENDING');
    const canceledA = await service!.cancelStablecoinPaymentIntent(ctx, createdA.id);
    expect(canceledA?.state).toBe('CANCELED');

    await expectBillingError(
      async () => {
        await service!.createStablecoinPaymentIntent(ctx, {
          invoiceId,
          quoteId: quoteA.id,
        });
      },
      'quote_already_consumed',
    );

    const quoteB = await service!.createStablecoinQuote(ctx, {
      invoiceId,
      asset: 'USDT',
      chain: 'Base',
    });
    const quoteC = await service!.createStablecoinQuote(ctx, {
      invoiceId,
      asset: 'USDT',
      chain: 'Base',
    });
    const createdB = await service!.createStablecoinPaymentIntent(ctx, {
      invoiceId,
      quoteId: quoteB.id,
    });
    expect(createdB.state).toBe('PENDING');

    const partialAmount = Math.max(createdB.expectedAmountMinor - 1, 1);
    const partiallySettled = await service!.reconcileStablecoinPaymentIntent(ctx, createdB.id, {
      observedAmountMinor: partialAmount,
      observedConfirmations: createdB.requiredConfirmations,
      sourceEventId: `evt_${Date.now()}_partial`,
    });
    expect(partiallySettled?.state).toBe('PARTIALLY_SETTLED');

    await expectBillingError(
      async () => {
        await service!.createStablecoinPaymentIntent(ctx, {
          invoiceId,
          quoteId: quoteC.id,
        });
      },
      'quote_amount_mismatch',
    );
  });

  test('expired stablecoin intent is immutable for reconcile/cancel paths', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const expiryNamespace = randomNamespace('test:console-billing:expiry-guard');
    let current = new Date('2026-03-01T00:00:00.000Z');
    const expiryService = await createPostgresConsoleBillingService({
      postgresUrl,
      namespace: expiryNamespace,
      logger: console as any,
      ensureSchema: true,
      now: () => current,
    });
    const ctx = {
      orgId: 'org-postgres-expiry-guard',
      actorUserId: 'ops-expiry-guard',
      roles: ['ops'],
    };

    try {
      const invoices = await expiryService.listInvoices(ctx);
      expect(invoices.length).toBeGreaterThan(0);
      const invoiceId = invoices[0].id;

      const quote = await expiryService.createStablecoinQuote(ctx, {
        invoiceId,
        asset: 'USDC',
        chain: 'Ethereum',
      });
      const created = await expiryService.createStablecoinPaymentIntent(ctx, {
        invoiceId,
        quoteId: quote.id,
      });
      expect(created.state).toBe('PENDING');

      current = new Date(current.getTime() + (16 * 60 * 1000));

      const reconciled = await expiryService.reconcileStablecoinPaymentIntent(ctx, created.id, {
        observedAmountMinor: created.expectedAmountMinor,
        observedConfirmations: created.requiredConfirmations,
      });
      expect(reconciled?.state).toBe('EXPIRED');

      const canceled = await expiryService.cancelStablecoinPaymentIntent(ctx, created.id);
      expect(canceled?.state).toBe('EXPIRED');

      const invoice = await expiryService.getInvoice(ctx, invoiceId);
      expect(invoice?.status).toBe('OPEN');
      expect(invoice?.amountPaidMinor).toBe(0);

      const pool = await getPostgresPool(postgresUrl);
      const transitions = await pool.query(
        `SELECT to_state
           FROM console_payment_state_transitions
          WHERE namespace = $1 AND payment_id = $2
          ORDER BY id ASC`,
        [expiryNamespace, created.id],
      );
      expect(transitions.rows.length).toBe(2);
      expect(String((transitions.rows[0] as any).to_state)).toBe('PENDING');
      expect(String((transitions.rows[1] as any).to_state)).toBe('EXPIRED');
    } finally {
      const pool = await getPostgresPool(postgresUrl);
      await pool.query('DELETE FROM console_stripe_webhook_events WHERE namespace = $1', [expiryNamespace]);
      await pool.query('DELETE FROM console_stablecoin_payment_intents WHERE namespace = $1', [expiryNamespace]);
      await pool.query('DELETE FROM console_stablecoin_quotes WHERE namespace = $1', [expiryNamespace]);
      await pool.query('DELETE FROM console_stripe_payment_intents WHERE namespace = $1', [expiryNamespace]);
      await pool.query('DELETE FROM console_payment_methods WHERE namespace = $1', [expiryNamespace]);
      await pool.query('DELETE FROM console_invoice_line_items WHERE namespace = $1', [expiryNamespace]);
      await pool.query('DELETE FROM console_usage_rollups_monthly WHERE namespace = $1', [expiryNamespace]);
      await pool.query('DELETE FROM console_usage_meter_events WHERE namespace = $1', [expiryNamespace]);
      await pool.query('DELETE FROM console_invoices WHERE namespace = $1', [expiryNamespace]);
      await pool.query('DELETE FROM console_billing_accounts WHERE namespace = $1', [expiryNamespace]);
    }
  });

  test('stripe card intents reject concurrent active attempts per invoice', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ctx = {
      orgId: 'org-postgres-card-intent-gate',
      actorUserId: 'ops-card-intent-gate',
      roles: ['ops'],
    };
    const invoices = await service!.listInvoices(ctx);
    expect(invoices.length).toBeGreaterThan(0);
    const invoiceId = invoices[0].id;

    const created = await service!.createStripePaymentIntent(ctx, { invoiceId });
    expect(created.state).toBe('CREATED');

    await expectBillingError(
      async () => {
        await service!.createStripePaymentIntent(ctx, { invoiceId });
      },
      'active_payment_intent_exists',
    );
  });

  test('reconcile moves stripe intent action_required -> settled and updates invoice', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ctx = {
      orgId: 'org-postgres-stripe-reconcile',
      actorUserId: 'admin-5',
      roles: ['admin'],
    };
    const invoices = await service!.listInvoices(ctx);
    expect(invoices.length).toBeGreaterThan(0);
    const invoiceId = invoices[0].id;

    const created = await service!.createStripePaymentIntent(ctx, { invoiceId });
    expect(created.state).toBe('CREATED');

    const actionRequired = await service!.reconcileStripePaymentIntent(ctx, created.id, {
      providerStatus: 'ACTION_REQUIRED',
      sourceEventId: `evt_${Date.now()}_action_required`,
    });
    expect(actionRequired?.state).toBe('ACTION_REQUIRED');

    const pending = await service!.reconcileStripePaymentIntent(ctx, created.id, {
      providerStatus: 'PENDING',
      sourceEventId: `evt_${Date.now()}_pending`,
    });
    expect(pending?.state).toBe('PENDING');

    const settled = await service!.reconcileStripePaymentIntent(ctx, created.id, {
      providerStatus: 'SUCCEEDED',
      settledAmountMinor: created.amountMinor,
      sourceEventId: `evt_${Date.now()}_succeeded`,
    });
    expect(settled?.state).toBe('SETTLED');

    const invoice = await service!.getInvoice(ctx, invoiceId);
    expect(invoice?.status).toBe('PAID');
    expect(Number(invoice?.amountPaidMinor || 0)).toBeGreaterThanOrEqual(created.amountMinor);

    const pool = await getPostgresPool(postgresUrl);
    const transitions = await pool.query(
      `SELECT to_state
         FROM console_payment_state_transitions
        WHERE namespace = $1 AND payment_id = $2
        ORDER BY id ASC`,
      [namespace, created.id],
    );
    expect(transitions.rows.length).toBe(4);
    expect(String((transitions.rows[0] as any).to_state)).toBe('CREATED');
    expect(String((transitions.rows[1] as any).to_state)).toBe('ACTION_REQUIRED');
    expect(String((transitions.rows[2] as any).to_state)).toBe('PENDING');
    expect(String((transitions.rows[3] as any).to_state)).toBe('SETTLED');
  });

  test('Stripe webhook events reconcile by providerRef and dedupe by event id', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ctx = {
      orgId: 'org-postgres-stripe-webhook',
      actorUserId: 'ops-webhook-postgres',
      roles: ['ops'],
    };
    const invoices = await service!.listInvoices(ctx);
    expect(invoices.length).toBeGreaterThan(0);
    const invoiceId = invoices[0].id;

    const created = await service!.createStripePaymentIntent(ctx, { invoiceId });
    expect(created.state).toBe('CREATED');

    const eventId = `evt_pg_${Date.now()}_1`;
    const first = await service!.processStripeWebhookEvent({
      eventId,
      providerRef: created.providerRef,
      providerStatus: 'SUCCEEDED',
      settledAmountMinor: created.amountMinor,
    });
    expect(first.accepted).toBe(true);
    expect(first.paymentIntent?.state).toBe('SETTLED');

    const duplicate = await service!.processStripeWebhookEvent({
      eventId,
      providerRef: created.providerRef,
      providerStatus: 'SUCCEEDED',
      settledAmountMinor: created.amountMinor,
    });
    expect(duplicate.accepted).toBe(false);
    expect(duplicate.paymentIntent?.state).toBe('SETTLED');

    const pool = await getPostgresPool(postgresUrl);
    const events = await pool.query(
      `SELECT event_id, payment_intent_id
         FROM console_stripe_webhook_events
        WHERE namespace = $1 AND event_id = $2`,
      [namespace, eventId],
    );
    expect(events.rows.length).toBe(1);
    expect(String((events.rows[0] as any).payment_intent_id || '')).toBe(created.id);

    const invoice = await service!.getInvoice(ctx, invoiceId);
    expect(invoice?.status).toBe('PAID');
  });

  test('usage events roll up MAW with exclusions and source-event idempotency', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ctx = {
      orgId: 'org-postgres-maw',
      actorUserId: 'ops-maw-1',
      roles: ['ops'],
    };

    const first = await service!.recordUsageEvent(ctx, {
      walletId: 'wallet_pg_1',
      action: 'transfer',
      succeeded: true,
      sourceEventId: 'maw_pg_evt_1',
    });
    expect(first.accepted).toBe(true);
    expect(first.counted).toBe(true);
    expect(first.monthlyActiveWallets).toBe(1);

    const secondSameWallet = await service!.recordUsageEvent(ctx, {
      walletId: 'wallet_pg_1',
      action: 'swap',
      succeeded: true,
      sourceEventId: 'maw_pg_evt_2',
    });
    expect(secondSameWallet.accepted).toBe(true);
    expect(secondSameWallet.counted).toBe(true);
    expect(secondSameWallet.monthlyActiveWallets).toBe(1);

    const excluded = await service!.recordUsageEvent(ctx, {
      walletId: 'wallet_pg_2',
      action: 'wallet_created',
      succeeded: true,
      sourceEventId: 'maw_pg_evt_3',
    });
    expect(excluded.accepted).toBe(true);
    expect(excluded.counted).toBe(false);
    expect(excluded.monthlyActiveWallets).toBe(1);

    const thirdDistinct = await service!.recordUsageEvent(ctx, {
      walletId: 'wallet_pg_3',
      action: 'contract_call',
      succeeded: true,
      isSimulation: true,
      sourceEventId: 'maw_pg_evt_4',
    });
    expect(thirdDistinct.accepted).toBe(true);
    expect(thirdDistinct.counted).toBe(false);
    expect(thirdDistinct.monthlyActiveWallets).toBe(1);

    const fourthDistinct = await service!.recordUsageEvent(ctx, {
      walletId: 'wallet_pg_4',
      action: 'contract_call',
      succeeded: true,
      sourceEventId: 'maw_pg_evt_5',
    });
    expect(fourthDistinct.accepted).toBe(true);
    expect(fourthDistinct.counted).toBe(true);
    expect(fourthDistinct.monthlyActiveWallets).toBe(2);

    const duplicate = await service!.recordUsageEvent(ctx, {
      walletId: 'wallet_pg_4',
      action: 'contract_call',
      succeeded: true,
      sourceEventId: 'maw_pg_evt_5',
    });
    expect(duplicate.accepted).toBe(false);
    expect(duplicate.counted).toBe(false);
    expect(duplicate.monthlyActiveWallets).toBe(2);

    const usage = await service!.getMonthlyActiveWallets(ctx, first.monthUtc);
    expect(usage.monthUtc).toBe(first.monthUtc);
    expect(usage.usageMetricVersion).toBe('maw_v1');
    expect(usage.monthlyActiveWallets).toBe(2);

    const pool = await getPostgresPool(postgresUrl);
    const rollup = await pool.query(
      `SELECT monthly_active_wallets
         FROM console_usage_rollups_monthly
        WHERE namespace = $1 AND org_id = $2 AND month_utc = $3`,
      [namespace, ctx.orgId, first.monthUtc],
    );
    expect(rollup.rows.length).toBe(1);
    expect(Number((rollup.rows[0] as any).monthly_active_wallets)).toBe(2);
  });

  test('monthly invoice generation materializes MAW line items idempotently', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ctx = {
      orgId: 'org-postgres-invoice-generation',
      actorUserId: 'ops-invoice-gen',
      roles: ['ops'],
    };

    await service!.recordUsageEvent(ctx, {
      walletId: 'wallet_g1',
      action: 'transfer',
      succeeded: true,
      occurredAt: '2026-01-05T01:00:00.000Z',
      sourceEventId: 'invoice_gen_pg_1',
    });
    await service!.recordUsageEvent(ctx, {
      walletId: 'wallet_g2',
      action: 'swap',
      succeeded: true,
      occurredAt: '2026-01-06T01:00:00.000Z',
      sourceEventId: 'invoice_gen_pg_2',
    });
    await service!.recordUsageEvent(ctx, {
      walletId: 'wallet_g3',
      action: 'wallet_created',
      succeeded: true,
      occurredAt: '2026-01-07T01:00:00.000Z',
      sourceEventId: 'invoice_gen_pg_3',
    });

    const generation = await service!.generateMonthlyInvoice(ctx, {
      periodMonthUtc: '2026-01',
    });
    expect(generation.generated).toBe(true);
    expect(generation.monthlyActiveWallets).toBe(2);
    expect(generation.invoice.periodMonthUtc).toBe('2026-01');
    expect(generation.invoice.amountDueMinor).toBe(2500);
    expect(generation.lineItems.length).toBe(2);

    const listedLineItems = await service!.listInvoiceLineItems(ctx, generation.invoice.id);
    expect(listedLineItems.length).toBe(2);
    const baseFeeItem = listedLineItems.find((item) => item.itemType === 'PLAN_BASE_FEE');
    const mawItem = listedLineItems.find((item) => item.itemType === 'MAW_USAGE');
    expect(baseFeeItem?.amountMinor).toBe(1900);
    expect(mawItem?.quantity).toBe(2);
    expect(mawItem?.amountMinor).toBe(600);

    const secondRun = await service!.generateMonthlyInvoice(ctx, {
      periodMonthUtc: '2026-01',
    });
    expect(secondRun.generated).toBe(false);
    expect(secondRun.invoice.id).toBe(generation.invoice.id);
    expect(secondRun.invoice.amountDueMinor).toBe(2500);

    const pool = await getPostgresPool(postgresUrl);
    const persisted = await pool.query(
      `SELECT item_type, amount_minor
         FROM console_invoice_line_items
        WHERE namespace = $1 AND org_id = $2 AND invoice_id = $3
        ORDER BY item_type ASC`,
      [namespace, ctx.orgId, generation.invoice.id],
    );
    expect(persisted.rows.length).toBe(2);
    expect(String((persisted.rows[0] as any).item_type)).toBe('MAW_USAGE');
    expect(String((persisted.rows[1] as any).item_type)).toBe('PLAN_BASE_FEE');
  });

  test('monthly finalization job generates prior-month invoices for all orgs in namespace', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const finalizationNamespace = randomNamespace('test:console-billing:finalization-job');
    let current = new Date('2026-02-15T00:00:00.000Z');
    const finalizationService = await createPostgresConsoleBillingService({
      postgresUrl,
      namespace: finalizationNamespace,
      logger: console as any,
      ensureSchema: true,
      now: () => current,
    });
    const orgA = {
      orgId: 'org-finalization-a',
      actorUserId: 'ops-finalization-a',
      roles: ['ops'],
    };
    const orgB = {
      orgId: 'org-finalization-b',
      actorUserId: 'ops-finalization-b',
      roles: ['ops'],
    };

    try {
      await finalizationService.recordUsageEvent(orgA, {
        walletId: 'wallet_finalization_a_1',
        action: 'transfer',
        succeeded: true,
        occurredAt: '2026-01-05T01:00:00.000Z',
        sourceEventId: 'finalization_evt_a_1',
      });
      await finalizationService.recordUsageEvent(orgB, {
        walletId: 'wallet_finalization_b_1',
        action: 'swap',
        succeeded: true,
        occurredAt: '2026-01-06T01:00:00.000Z',
        sourceEventId: 'finalization_evt_b_1',
      });
      await finalizationService.recordUsageEvent(orgB, {
        walletId: 'wallet_finalization_b_2',
        action: 'approve',
        succeeded: true,
        occurredAt: '2026-01-07T01:00:00.000Z',
        sourceEventId: 'finalization_evt_b_2',
      });

      const firstRun = await runPostgresConsoleBillingMonthlyFinalization({
        postgresUrl,
        namespace: finalizationNamespace,
        periodMonthUtc: '2026-01',
        now: () => current,
        ensureSchema: false,
        logger: console as any,
      });
      expect(firstRun.periodMonthUtc).toBe('2026-01');
      expect(firstRun.orgCount).toBe(2);
      expect(firstRun.generatedCount).toBe(2);
      expect(firstRun.skippedCount).toBe(0);
      expect(firstRun.failures.length).toBe(0);

      const secondRun = await runPostgresConsoleBillingMonthlyFinalization({
        postgresUrl,
        namespace: finalizationNamespace,
        periodMonthUtc: '2026-01',
        now: () => current,
        ensureSchema: false,
        logger: console as any,
      });
      expect(secondRun.orgCount).toBe(2);
      expect(secondRun.generatedCount).toBe(0);
      expect(secondRun.skippedCount).toBe(2);
      expect(secondRun.failures.length).toBe(0);

      const orgAJanInvoice = (await finalizationService.listInvoices(orgA))
        .find((invoice) => invoice.periodMonthUtc === '2026-01');
      const orgBJanInvoice = (await finalizationService.listInvoices(orgB))
        .find((invoice) => invoice.periodMonthUtc === '2026-01');
      expect(orgAJanInvoice?.amountDueMinor).toBe(2200);
      expect(orgBJanInvoice?.amountDueMinor).toBe(2500);
    } finally {
      const pool = await getPostgresPool(postgresUrl);
      await pool.query('DELETE FROM console_stripe_webhook_events WHERE namespace = $1', [finalizationNamespace]);
      await pool.query('DELETE FROM console_stablecoin_payment_intents WHERE namespace = $1', [finalizationNamespace]);
      await pool.query('DELETE FROM console_stablecoin_quotes WHERE namespace = $1', [finalizationNamespace]);
      await pool.query('DELETE FROM console_stripe_payment_intents WHERE namespace = $1', [finalizationNamespace]);
      await pool.query('DELETE FROM console_payment_methods WHERE namespace = $1', [finalizationNamespace]);
      await pool.query('DELETE FROM console_invoice_line_items WHERE namespace = $1', [finalizationNamespace]);
      await pool.query('DELETE FROM console_usage_rollups_monthly WHERE namespace = $1', [finalizationNamespace]);
      await pool.query('DELETE FROM console_usage_meter_events WHERE namespace = $1', [finalizationNamespace]);
      await pool.query('DELETE FROM console_invoices WHERE namespace = $1', [finalizationNamespace]);
      await pool.query('DELETE FROM console_billing_accounts WHERE namespace = $1', [finalizationNamespace]);
    }
  });

  test('postgres bootstrap creates one invoice per org per period month', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    let current = new Date('2026-01-20T00:00:00.000Z');
    const rolloverNamespace = randomNamespace('test:console-billing:rollover');
    const rolloverService = await createPostgresConsoleBillingService({
      postgresUrl,
      namespace: rolloverNamespace,
      logger: console as any,
      ensureSchema: true,
      now: () => current,
    });
    const ctx = {
      orgId: 'org-postgres-rollover',
      actorUserId: 'ops-rollover-1',
      roles: ['ops'],
    };

    try {
      const janInvoices = await rolloverService.listInvoices(ctx);
      expect(janInvoices.length).toBe(1);
      expect(janInvoices[0].periodMonthUtc).toBe('2026-01');

      current = new Date('2026-02-02T00:00:00.000Z');
      const febInvoices = await rolloverService.listInvoices(ctx);
      expect(febInvoices.some((invoice) => invoice.periodMonthUtc === '2026-01')).toBe(true);
      expect(febInvoices.some((invoice) => invoice.periodMonthUtc === '2026-02')).toBe(true);
      expect(febInvoices.filter((invoice) => invoice.periodMonthUtc === '2026-02').length).toBe(1);

      current = new Date('2026-02-10T00:00:00.000Z');
      const febInvoicesAgain = await rolloverService.listInvoices(ctx);
      expect(febInvoicesAgain.filter((invoice) => invoice.periodMonthUtc === '2026-02').length).toBe(1);
    } finally {
      const pool = await getPostgresPool(postgresUrl);
      await pool.query('DELETE FROM console_stripe_webhook_events WHERE namespace = $1', [rolloverNamespace]);
      await pool.query('DELETE FROM console_stablecoin_payment_intents WHERE namespace = $1', [rolloverNamespace]);
      await pool.query('DELETE FROM console_stablecoin_quotes WHERE namespace = $1', [rolloverNamespace]);
      await pool.query('DELETE FROM console_stripe_payment_intents WHERE namespace = $1', [rolloverNamespace]);
      await pool.query('DELETE FROM console_payment_methods WHERE namespace = $1', [rolloverNamespace]);
      await pool.query('DELETE FROM console_invoice_line_items WHERE namespace = $1', [rolloverNamespace]);
      await pool.query('DELETE FROM console_usage_rollups_monthly WHERE namespace = $1', [rolloverNamespace]);
      await pool.query('DELETE FROM console_usage_meter_events WHERE namespace = $1', [rolloverNamespace]);
      await pool.query('DELETE FROM console_invoices WHERE namespace = $1', [rolloverNamespace]);
      await pool.query('DELETE FROM console_billing_accounts WHERE namespace = $1', [rolloverNamespace]);
    }
  });

  test('payment transitions are append-only and include create/cancel records', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ctx = {
      orgId: 'org-postgres-transitions',
      actorUserId: 'admin-3',
      roles: ['admin'],
    };
    const invoices = await service!.listInvoices(ctx);
    expect(invoices.length).toBeGreaterThan(0);
    const invoiceId = invoices[0].id;

    const quote = await service!.createStablecoinQuote(ctx, {
      invoiceId,
      asset: 'USDC',
      chain: 'Ethereum',
    });
    const intent = await service!.createStablecoinPaymentIntent(ctx, {
      invoiceId,
      quoteId: quote.id,
    });
    const canceled = await service!.cancelStablecoinPaymentIntent(ctx, intent.id);
    expect(canceled?.state).toBe('CANCELED');

    const pool = await getPostgresPool(postgresUrl);
    const transitions = await pool.query(
      `SELECT id, from_state, to_state, actor_type, actor_user_id, reason
         FROM console_payment_state_transitions
        WHERE namespace = $1 AND payment_id = $2
        ORDER BY id ASC`,
      [namespace, intent.id],
    );
    expect(transitions.rows.length).toBe(2);

    const first = transitions.rows[0] as any;
    expect(first.from_state).toBeNull();
    expect(String(first.to_state)).toBe('PENDING');
    expect(String(first.actor_type)).toBe('USER');
    expect(String(first.actor_user_id)).toBe(ctx.actorUserId);
    expect(String(first.reason)).toBe('payment_intent_created');

    const second = transitions.rows[1] as any;
    expect(String(second.from_state)).toBe('PENDING');
    expect(String(second.to_state)).toBe('CANCELED');
    expect(String(second.actor_type)).toBe('USER');
    expect(String(second.actor_user_id)).toBe(ctx.actorUserId);
    expect(String(second.reason)).toBe('payment_intent_canceled');

    const transitionId = Number(first.id);
    expect(Number.isFinite(transitionId)).toBe(true);
    let mutationError: any;
    try {
      await pool.query(
        `UPDATE console_payment_state_transitions
            SET reason = 'tampered'
          WHERE id = $1`,
        [transitionId],
      );
    } catch (error: unknown) {
      mutationError = error;
    }
    expect(mutationError).toBeTruthy();
  });
});

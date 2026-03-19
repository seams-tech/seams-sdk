import { test, expect } from '@playwright/test';
import {
  createPostgresConsoleBillingService,
  runPostgresConsoleBillingMonthlyFinalization,
  type ConsoleBillingService,
} from '@server/router/express-adaptor';
import { withConsoleTenantContextTx } from '../../server/src/console/shared/postgresTenantContext';
import { getPostgresPool } from '../../server/src/storage/postgres';

function randomNamespace(prefix: string): string {
  return `${prefix}:${Date.now()}:${Math.random().toString(16).slice(2)}`;
}

type BillingCtx = {
  orgId: string;
  actorUserId: string;
  roles: string[];
};

const PRIMARY_TEST_ORG_IDS = [
  'org-postgres-purchase-webhook',
  'org-postgres-maw',
  'org-postgres-concurrent-billing-reads',
  'org-postgres-manual-adjustments',
  'org-postgres-manual-adjustments-linked',
  'org-postgres-manual-adjustments-large-debit',
];

async function queryInOrg(input: {
  postgresUrl: string;
  namespace: string;
  orgId: string;
  text: string;
  values: unknown[];
}): Promise<{ rows: any[]; rowCount?: number }> {
  const pool = await getPostgresPool(input.postgresUrl);
  return withConsoleTenantContextTx(pool, { namespace: input.namespace, orgId: input.orgId }, (q) =>
    q.query(input.text, input.values),
  );
}

async function cleanupBillingNamespaceForOrgs(input: {
  postgresUrl: string;
  namespace: string;
  orgIds: string[];
}): Promise<void> {
  const pool = await getPostgresPool(input.postgresUrl);
  const namespace = String(input.namespace || '').trim();
  if (!namespace) return;
  const orgIds = Array.from(
    new Set(input.orgIds.map((orgId) => String(orgId || '').trim()).filter(Boolean)),
  );

  for (const orgId of orgIds) {
    await withConsoleTenantContextTx(pool, { namespace, orgId }, async (q) => {
      await q.query('DELETE FROM console_stripe_webhook_events WHERE namespace = $1', [namespace]);
      await q.query('DELETE FROM console_invoice_line_items WHERE namespace = $1', [namespace]);
      await q.query('DELETE FROM console_usage_rollups_monthly WHERE namespace = $1', [namespace]);
      await q.query('DELETE FROM console_usage_meter_events WHERE namespace = $1', [namespace]);
      await q.query('DELETE FROM console_billing_credit_purchases WHERE namespace = $1', [
        namespace,
      ]);
      await q.query('DELETE FROM console_billing_ledger_postings WHERE namespace = $1', [
        namespace,
      ]);
      await q.query('DELETE FROM console_billing_ledger_entries WHERE namespace = $1', [namespace]);
      await q.query('DELETE FROM console_invoices WHERE namespace = $1', [namespace]);
      await q.query('DELETE FROM console_billing_accounts WHERE namespace = $1', [namespace]);
    });
  }
  await pool.query('DELETE FROM console_billing_ledger_accounts WHERE namespace = $1', [namespace]);
}

async function settleCreditPurchase(
  service: ConsoleBillingService,
  ctx: BillingCtx,
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

async function insertUsageMeterEvent(input: {
  postgresUrl: string;
  namespace: string;
  orgId: string;
  walletId: string;
  action: 'transfer' | 'swap' | 'approve' | 'contract_call';
  occurredAt: string;
  sourceEventId: string;
}): Promise<void> {
  const pool = await getPostgresPool(input.postgresUrl);
  const occurredAtMs = Date.parse(input.occurredAt);
  await withConsoleTenantContextTx(pool, { namespace: input.namespace, orgId: input.orgId }, (q) =>
    q.query(
      `INSERT INTO console_usage_meter_events
        (namespace, id, org_id, wallet_id, action, succeeded, is_simulation, is_internal_retry, occurred_at_ms, month_utc, source_event_id)
       VALUES
        ($1, $2, $3, $4, $5, TRUE, FALSE, FALSE, $6, $7, $8)`,
      [
        input.namespace,
        `ume_seed_${Math.random().toString(16).slice(2)}`,
        input.orgId,
        input.walletId,
        input.action,
        occurredAtMs,
        input.occurredAt.slice(0, 7),
        input.sourceEventId,
      ],
    ),
  );
}

test.describe('console billing postgres service prepaid model', () => {
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
    await cleanupBillingNamespaceForOrgs({
      postgresUrl,
      namespace,
      orgIds: PRIMARY_TEST_ORG_IDS,
    });
  });

  test('postgres service uses injected prepaid billing provider adapters', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const providerNamespace = randomNamespace('test:console-billing:providers');
    const providerService = await createPostgresConsoleBillingService({
      postgresUrl,
      namespace: providerNamespace,
      logger: console as any,
      ensureSchema: true,
      providers: {
        stripe: {
          createCheckoutSession: () => ({
            id: 'cs_pg_provider',
            url: 'https://checkout.example/postgres',
            customerRef: 'cus_pg_provider',
            expiresAt: '2026-03-01T00:30:00.000Z',
          }),
          getCheckoutSession: () => ({
            id: 'cs_pg_provider',
            orgId: 'org-postgres-provider-adapter',
            customerRef: 'cus_pg_provider',
            paymentStatus: 'paid',
            checkoutStatus: 'complete',
          }),
        },
      },
    });
    const ctx = {
      orgId: 'org-postgres-provider-adapter',
      actorUserId: 'ops-provider-adapter-postgres',
      roles: ['ops'],
    } satisfies BillingCtx;

    try {
      const checkoutSession = await providerService.createStripeCheckoutSession(ctx, {
        successUrl: 'https://app.example.com/dashboard/billing/account?checkout=success',
        cancelUrl: 'https://app.example.com/pricing?checkout=cancel',
        creditPackId: 'usd_25',
      });
      expect(checkoutSession.id).toBe('cs_pg_provider');
      expect(checkoutSession.url).toBe('https://checkout.example/postgres');
      expect(checkoutSession.customerRef).toBe('cus_pg_provider');
      expect(checkoutSession.creditPackId).toBe('usd_25');
      expect(checkoutSession.amountMinor).toBe(2500);
      expect(checkoutSession.expiresAt).toBe('2026-03-01T00:30:00.000Z');

      const projection = await providerService.processStripeWebhookEvent({
        eventId: 'evt_pg_provider_purchase',
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

      const overview = await providerService.getOverview(ctx);
      expect(overview.creditBalanceMinor).toBe(2500);
      expect(overview.recentCreditPurchasedMinor).toBe(2500);
    } finally {
      await cleanupBillingNamespaceForOrgs({
        postgresUrl,
        namespace: providerNamespace,
        orgIds: [ctx.orgId],
      });
    }
  });

  test('Stripe webhook settles prepaid purchase receipts idempotently and persists projection rows', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ctx = {
      orgId: 'org-postgres-purchase-webhook',
      actorUserId: 'ops-webhook-postgres',
      roles: ['ops'],
    } satisfies BillingCtx;

    const checkoutSession = await service!.createStripeCheckoutSession(ctx, {
      successUrl: 'https://app.example.com/dashboard/billing/account?checkout=success',
      cancelUrl: 'https://app.example.com/dashboard/billing/account?checkout=cancel',
      creditPackId: 'usd_25',
    });
    const eventId = `evt_pg_same_${Date.now()}`;

    const first = await service!.processStripeWebhookEvent({
      eventId,
      eventType: 'checkout.session.completed',
      orgId: ctx.orgId,
      checkoutSessionId: checkoutSession.id,
      providerCustomerRef: checkoutSession.customerRef,
      providerRef: checkoutSession.id,
    });
    expect(first.accepted).toBe(true);
    expect(first.purchase?.status).toBe('SETTLED');
    expect(first.purchase?.creditPackId).toBe('usd_25');
    expect(first.invoice?.documentType).toBe('PURCHASE_RECEIPT');

    const duplicate = await service!.processStripeWebhookEvent({
      eventId,
      eventType: 'checkout.session.completed',
      orgId: ctx.orgId,
      checkoutSessionId: checkoutSession.id,
      providerCustomerRef: checkoutSession.customerRef,
      providerRef: checkoutSession.id,
    });
    expect(duplicate.accepted).toBe(false);
    expect(duplicate.purchase?.status).toBe('SETTLED');
    expect(duplicate.invoice?.id).toBe(first.invoice?.id);

    const overview = await service!.getOverview(ctx);
    expect(overview.creditBalanceMinor).toBe(2500);
    expect(overview.recentCreditPurchasedMinor).toBe(2500);

    const receipts = await service!.listInvoicesPage(ctx, { documentType: 'PURCHASE_RECEIPT' });
    expect(receipts.totalCount).toBe(1);
    expect(receipts.summary.receiptCount).toBe(1);
    expect(receipts.invoices[0]?.id).toBe(first.invoice?.id);

    const lineItems = await service!.listInvoiceLineItems(ctx, first.invoice!.id);
    expect(lineItems.length).toBe(1);
    expect(lineItems[0]?.itemType).toBe('CREDIT_TOP_UP');
    expect(lineItems[0]?.amountMinor).toBe(2500);

    const purchases = await queryInOrg({
      postgresUrl,
      namespace,
      orgId: ctx.orgId,
      text: `SELECT status, provider_checkout_session_ref, related_invoice_id
         FROM console_billing_credit_purchases
        WHERE namespace = $1 AND org_id = $2`,
      values: [namespace, ctx.orgId],
    });
    expect(purchases.rows.length).toBe(1);
    expect(String((purchases.rows[0] as any).status || '')).toBe('SETTLED');
    expect(String((purchases.rows[0] as any).provider_checkout_session_ref || '')).toBe(
      checkoutSession.id,
    );
    expect(String((purchases.rows[0] as any).related_invoice_id || '')).toBe(first.invoice?.id);

    const ledger = await queryInOrg({
      postgresUrl,
      namespace,
      orgId: ctx.orgId,
      text: `SELECT entry_type, amount_minor, related_purchase_id
         FROM console_billing_ledger_entries
        WHERE namespace = $1 AND org_id = $2 AND related_purchase_id = $3`,
      values: [namespace, ctx.orgId, first.purchase!.id],
    });
    expect(ledger.rows.length).toBe(1);
    expect(String((ledger.rows[0] as any).entry_type || '')).toBe('CREDIT_PURCHASE');
    expect(Number((ledger.rows[0] as any).amount_minor || 0)).toBe(2500);

    const postings = await queryInOrg({
      postgresUrl,
      namespace,
      orgId: ctx.orgId,
      text: `SELECT account_id, direction, amount_minor
         FROM console_billing_ledger_postings
        WHERE namespace = $1
          AND org_id = $2
          AND related_purchase_id = $3
        ORDER BY direction ASC, account_id ASC`,
      values: [namespace, ctx.orgId, first.purchase!.id],
    });
    expect(
      postings.rows.map((row) => ({
        account_id: String((row as any).account_id || ''),
        direction: String((row as any).direction || ''),
        amount_minor: Number((row as any).amount_minor || 0),
      })),
    ).toEqual([
      {
        account_id: 'acct:org_prepaid_liability:org-postgres-purchase-webhook',
        direction: 'CREDIT',
        amount_minor: 2500,
      },
      {
        account_id: 'acct:processor_clearing:stripe',
        direction: 'DEBIT',
        amount_minor: 2500,
      },
    ]);

    const webhookEvents = await queryInOrg({
      postgresUrl,
      namespace,
      orgId: ctx.orgId,
      text: `SELECT event_id, org_id, provider_ref
         FROM console_stripe_webhook_events
        WHERE namespace = $1 AND org_id = $2 AND event_id = $3`,
      values: [namespace, ctx.orgId, eventId],
    });
    expect(webhookEvents.rows.length).toBe(1);
    expect(String((webhookEvents.rows[0] as any).provider_ref || '')).toBe(checkoutSession.id);
    expect(String((webhookEvents.rows[0] as any).org_id || '')).toBe(ctx.orgId);
  });

  test('postgres service appends manual support credits and admin debits idempotently', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ctx = {
      orgId: 'org-postgres-manual-adjustments',
      actorUserId: 'admin-manual-adjustments-postgres',
      roles: ['platform_admin'],
    } satisfies BillingCtx;

    const credit = await service!.grantManualSupportCredit(ctx, {
      amountMinor: 1200,
      reasonCode: 'incident_credit',
      note: 'Applied support credit after incident review',
      idempotencyKey: 'manual-credit-postgres-1',
    });
    expect(credit.created).toBe(true);
    expect(credit.adjustment.amountMinor).toBe(1200);
    expect(credit.creditBalanceMinor).toBe(1200);

    const duplicateCredit = await service!.grantManualSupportCredit(ctx, {
      amountMinor: 1200,
      reasonCode: 'incident_credit',
      note: 'Applied support credit after incident review',
      idempotencyKey: 'manual-credit-postgres-1',
    });
    expect(duplicateCredit.created).toBe(false);
    expect(duplicateCredit.adjustment.id).toBe(credit.adjustment.id);
    expect(duplicateCredit.creditBalanceMinor).toBe(1200);

    const debit = await service!.appendManualAdminDebit(ctx, {
      amountMinor: 300,
      reasonCode: 'duplicate_credit_correction',
      note: 'Corrected duplicate support credit',
      idempotencyKey: 'manual-debit-postgres-1',
    });
    expect(debit.created).toBe(true);
    expect(debit.adjustment.amountMinor).toBe(-300);
    expect(debit.creditBalanceMinor).toBe(900);

    const overview = await service!.getOverview(ctx);
    expect(overview.creditBalanceMinor).toBe(900);

    const activity = await service!.listAccountActivity(ctx, { limit: 5 });
    expect(activity.entries.map((entry) => entry.id)).toEqual([
      debit.adjustment.id,
      credit.adjustment.id,
    ]);
    expect(activity.entries[0]?.amountMinor).toBe(-300);
    expect(activity.entries[1]?.amountMinor).toBe(1200);

    const ledger = await queryInOrg({
      postgresUrl,
      namespace,
      orgId: ctx.orgId,
      text: `SELECT entry_type, amount_minor, actor_type, actor_user_id, reason_code, note, idempotency_key
         FROM console_billing_ledger_entries
        WHERE namespace = $1
          AND org_id = $2
          AND entry_type = 'MANUAL_ADJUSTMENT'
        ORDER BY created_at_ms ASC, id ASC`,
      values: [namespace, ctx.orgId],
    });
    expect(
      ledger.rows.map((row) => ({
        entry_type: String((row as any).entry_type || ''),
        amount_minor: Number((row as any).amount_minor || 0),
        actor_type: String((row as any).actor_type || ''),
        actor_user_id: String((row as any).actor_user_id || ''),
        reason_code: String((row as any).reason_code || ''),
        idempotency_key: String((row as any).idempotency_key || ''),
      })),
    ).toEqual([
      {
        entry_type: 'MANUAL_ADJUSTMENT',
        amount_minor: 1200,
        actor_type: 'USER',
        actor_user_id: ctx.actorUserId,
        reason_code: 'incident_credit',
        idempotency_key: 'manual-credit-postgres-1',
      },
      {
        entry_type: 'MANUAL_ADJUSTMENT',
        amount_minor: -300,
        actor_type: 'USER',
        actor_user_id: ctx.actorUserId,
        reason_code: 'duplicate_credit_correction',
        idempotency_key: 'manual-debit-postgres-1',
      },
    ]);

    const postings = await queryInOrg({
      postgresUrl,
      namespace,
      orgId: ctx.orgId,
      text: `SELECT account_id, direction, amount_minor
         FROM console_billing_ledger_postings
        WHERE namespace = $1
          AND org_id = $2
          AND source_event_id IS NULL
          AND related_purchase_id IS NULL
        ORDER BY created_at_ms ASC, account_id ASC, direction ASC`,
      values: [namespace, ctx.orgId],
    });
    expect(postings.rows.length).toBe(4);
  });

  test('postgres service links manual adjustments to invoice activity when relatedInvoiceId is provided', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ctx = {
      orgId: 'org-postgres-manual-adjustments-linked',
      actorUserId: 'admin-manual-adjustments-linked-postgres',
      roles: ['platform_admin'],
    } satisfies BillingCtx;

    const settled = await settleCreditPurchase(service!, ctx, 'usd_25');
    const credit = await service!.grantManualSupportCredit(ctx, {
      amountMinor: 500,
      reasonCode: 'invoice_correction',
      note: 'Linked correction for receipt timeline visibility',
      idempotencyKey: 'manual-credit-linked-postgres-1',
      relatedInvoiceId: settled.invoice.id,
    });
    expect(credit.adjustment.relatedInvoiceId).toBe(settled.invoice.id);

    const invoiceActivity = await service!.getInvoiceActivity(ctx, settled.invoice.id);
    expect(invoiceActivity).toBeTruthy();
    expect(
      invoiceActivity?.entries.some(
        (entry) =>
          entry.id === credit.adjustment.id &&
          entry.toState === 'MANUAL_ADJUSTMENT' &&
          entry.visibility === 'INTERNAL',
      ),
    ).toBe(true);

    const ledger = await queryInOrg({
      postgresUrl,
      namespace,
      orgId: ctx.orgId,
      text: `SELECT related_invoice_id
         FROM console_billing_ledger_entries
        WHERE namespace = $1 AND org_id = $2 AND id = $3`,
      values: [namespace, ctx.orgId, credit.adjustment.id],
    });
    expect(String((ledger.rows[0] as any)?.related_invoice_id || '')).toBe(settled.invoice.id);
  });

  test('postgres service allows large manual admin debits for platform_admin', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const platformCtx = {
      orgId: 'org-postgres-manual-adjustments-large-debit',
      actorUserId: 'admin-manual-adjustments-large-debit-postgres',
      roles: ['platform_admin'],
    } satisfies BillingCtx;

    await service!.grantManualSupportCredit(platformCtx, {
      amountMinor: 75_000,
      reasonCode: 'bootstrap_credit',
      note: 'Seeded large balance for owner guard test',
      idempotencyKey: 'manual-credit-large-debit-postgres-1',
    });

    const debit = await service!.appendManualAdminDebit(platformCtx, {
      amountMinor: 50_000,
      reasonCode: 'large_debit_correction',
      note: 'Platform operator approved large debit',
      idempotencyKey: 'manual-debit-large-debit-postgres-platform',
    });
    expect(debit.created).toBe(true);
    expect(debit.adjustment.amountMinor).toBe(-50_000);
  });

  test('usage events roll up MAW with exclusions and source-event idempotency', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ctx = {
      orgId: 'org-postgres-maw',
      actorUserId: 'ops-maw-postgres',
      roles: ['ops'],
    } satisfies BillingCtx;

    const first = await service!.recordUsageEvent(ctx, {
      walletId: 'wallet_pg_1',
      action: 'transfer',
      succeeded: true,
      sourceEventId: 'maw_pg_evt_1',
    });
    expect(first.accepted).toBe(true);
    expect(first.counted).toBe(true);
    expect(first.monthlyActiveWallets).toBe(1);
    expect(first.debitAppliedMinor).toBe(300);
    expect(first.creditBalanceMinor).toBe(-300);
    expect(first.statementId).toBeTruthy();

    const secondSameWallet = await service!.recordUsageEvent(ctx, {
      walletId: 'wallet_pg_1',
      action: 'swap',
      succeeded: true,
      sourceEventId: 'maw_pg_evt_2',
    });
    expect(secondSameWallet.accepted).toBe(true);
    expect(secondSameWallet.counted).toBe(true);
    expect(secondSameWallet.monthlyActiveWallets).toBe(1);
    expect(secondSameWallet.debitAppliedMinor).toBe(0);

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
      sourceEventId: 'maw_pg_evt_4',
    });
    expect(thirdDistinct.accepted).toBe(true);
    expect(thirdDistinct.counted).toBe(true);
    expect(thirdDistinct.monthlyActiveWallets).toBe(2);
    expect(thirdDistinct.debitAppliedMinor).toBe(300);

    const duplicate = await service!.recordUsageEvent(ctx, {
      walletId: 'wallet_pg_3',
      action: 'contract_call',
      succeeded: true,
      sourceEventId: 'maw_pg_evt_4',
    });
    expect(duplicate.accepted).toBe(false);
    expect(duplicate.counted).toBe(false);
    expect(duplicate.monthlyActiveWallets).toBe(2);

    const usage = await service!.getMonthlyActiveWallets(ctx, first.monthUtc);
    expect(usage.monthUtc).toBe(first.monthUtc);
    expect(usage.usageMetricVersion).toBe('maw_v1');
    expect(usage.monthlyActiveWallets).toBe(2);

    const postings = await queryInOrg({
      postgresUrl,
      namespace,
      orgId: ctx.orgId,
      text: `SELECT account_id, direction, amount_minor, source_event_id
         FROM console_billing_ledger_postings
        WHERE namespace = $1
          AND org_id = $2
          AND source_event_id = $3
        ORDER BY direction ASC, account_id ASC`,
      values: [namespace, ctx.orgId, 'maw_pg_evt_1'],
    });
    expect(
      postings.rows.map((row) => ({
        account_id: String((row as any).account_id || ''),
        direction: String((row as any).direction || ''),
        amount_minor: Number((row as any).amount_minor || 0),
        source_event_id: String((row as any).source_event_id || ''),
      })),
    ).toEqual([
      {
        account_id: 'acct:revenue_usage',
        direction: 'CREDIT',
        amount_minor: 300,
        source_event_id: 'maw_pg_evt_1',
      },
      {
        account_id: 'acct:org_prepaid_liability:org-postgres-maw',
        direction: 'DEBIT',
        amount_minor: 300,
        source_event_id: 'maw_pg_evt_1',
      },
    ]);

    const rollup = await queryInOrg({
      postgresUrl,
      namespace,
      orgId: ctx.orgId,
      text: `SELECT monthly_active_wallets
         FROM console_usage_rollups_monthly
        WHERE namespace = $1 AND org_id = $2 AND month_utc = $3`,
      values: [namespace, ctx.orgId, first.monthUtc],
    });
    expect(rollup.rows.length).toBe(1);
    expect(Number((rollup.rows[0] as any).monthly_active_wallets || 0)).toBe(2);
  });

  test('postgres service records sponsored execution debits idempotently and projects them into statements', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ctx = {
      orgId: 'org-postgres-sponsored-debits',
      actorUserId: 'ops-sponsored-debits-postgres',
      roles: ['ops'],
    } satisfies BillingCtx;

    await settleCreditPurchase(service!, ctx, 'usd_25');

    const first = await service!.recordSponsoredExecutionDebit(ctx, {
      amountMinor: 125,
      sourceEventId: 'sponsored_pg_evt_1',
      walletId: 'alice.testnet',
      occurredAt: '2026-03-12T00:00:00.000Z',
      txOrExecutionRef: 'tx_pg_123',
      pricingVersion: 'pricing-pg-v1',
    });
    expect(first.accepted).toBe(true);
    expect(first.debitAppliedMinor).toBe(125);
    expect(first.creditBalanceMinor).toBe(2375);
    expect(first.statementId).toBeTruthy();

    const duplicate = await service!.recordSponsoredExecutionDebit(ctx, {
      amountMinor: 125,
      sourceEventId: 'sponsored_pg_evt_1',
      walletId: 'alice.testnet',
      occurredAt: '2026-03-12T00:00:00.000Z',
    });
    expect(duplicate.accepted).toBe(false);
    expect(duplicate.debitAppliedMinor).toBe(0);
    expect(duplicate.creditBalanceMinor).toBe(2375);

    const overview = await service!.getOverview(ctx);
    expect(overview.creditBalanceMinor).toBe(2375);

    const accountActivity = await service!.listAccountActivity(ctx, { limit: 5 });
    expect(accountActivity.entries.some((entry) => entry.type === 'SPONSORED_EXECUTION_DEBIT')).toBe(
      true,
    );

    const statementId = String(first.statementId || '');
    const statement = await service!.getInvoice(ctx, statementId);
    expect(statement?.documentType).toBe('USAGE_STATEMENT');
    expect(statement?.amountDueMinor).toBe(125);

    const lineItems = await service!.listInvoiceLineItems(ctx, statementId);
    expect(lineItems.some((item) => item.itemType === 'SPONSORED_EXECUTION_DEBIT')).toBe(true);
    expect(
      lineItems.find((item) => item.itemType === 'SPONSORED_EXECUTION_DEBIT')?.amountMinor,
    ).toBe(125);

    const postings = await queryInOrg({
      postgresUrl,
      namespace,
      orgId: ctx.orgId,
      text: `SELECT account_id, direction, amount_minor, source_event_id
         FROM console_billing_ledger_postings
        WHERE namespace = $1
          AND org_id = $2
          AND source_event_id = $3
        ORDER BY direction ASC, account_id ASC`,
      values: [namespace, ctx.orgId, 'sponsored_pg_evt_1'],
    });
    expect(
      postings.rows.map((row) => ({
        account_id: String((row as any).account_id || ''),
        direction: String((row as any).direction || ''),
        amount_minor: Number((row as any).amount_minor || 0),
        source_event_id: String((row as any).source_event_id || ''),
      })),
    ).toEqual([
      {
        account_id: 'acct:revenue_usage',
        direction: 'CREDIT',
        amount_minor: 125,
        source_event_id: 'sponsored_pg_evt_1',
      },
      {
        account_id: 'acct:org_prepaid_liability:org-postgres-sponsored-debits',
        direction: 'DEBIT',
        amount_minor: 125,
        source_event_id: 'sponsored_pg_evt_1',
      },
    ]);
  });

  test('postgres service allows concurrent overview and MAW reads without deadlock', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ctx = {
      orgId: 'org-postgres-concurrent-billing-reads',
      actorUserId: 'ops-concurrent-billing-reads-postgres',
      roles: ['ops'],
    } satisfies BillingCtx;

    await service!.recordUsageEvent(ctx, {
      walletId: 'wallet_pg_concurrent_1',
      action: 'transfer',
      succeeded: true,
      sourceEventId: 'maw_pg_concurrent_evt_1',
      occurredAt: '2026-03-02T00:00:00.000Z',
    });
    await service!.recordUsageEvent(ctx, {
      walletId: 'wallet_pg_concurrent_2',
      action: 'swap',
      succeeded: true,
      sourceEventId: 'maw_pg_concurrent_evt_2',
      occurredAt: '2026-03-03T00:00:00.000Z',
    });
    await service!.getMonthlyActiveWallets(ctx, '2026-03');

    const rounds = await Promise.all(
      Array.from({ length: 6 }, async () =>
        Promise.all([
          service!.getOverview(ctx),
          service!.getMonthlyActiveWallets(ctx, '2026-03'),
          service!.listInvoicesPage(ctx, { limit: 10 }),
        ]),
      ),
    );

    for (const [overview, usage, invoices] of rounds) {
      expect(overview.currentMonthUtc).toBe('2026-03');
      expect(overview.monthlyActiveWallets).toBe(2);
      expect(usage.monthUtc).toBe('2026-03');
      expect(usage.monthlyActiveWallets).toBe(2);
      expect(invoices.totalCount).toBeGreaterThanOrEqual(1);
    }
  });

  test('postgres service regenerates monthly usage statements idempotently from MAW rollups', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const generationNamespace = randomNamespace('test:console-billing:invoice-generation');
    const current = new Date('2026-02-05T00:00:00.000Z');
    const generationService = await createPostgresConsoleBillingService({
      postgresUrl,
      namespace: generationNamespace,
      logger: console as any,
      ensureSchema: true,
      now: () => current,
    });
    const ctx = {
      orgId: 'org-postgres-invoice-generation',
      actorUserId: 'ops-invoice-generation-postgres',
      roles: ['ops'],
    } satisfies BillingCtx;

    try {
      await generationService.recordUsageEvent(ctx, {
        walletId: 'wallet_a',
        action: 'transfer',
        succeeded: true,
        occurredAt: '2026-01-05T01:00:00.000Z',
        sourceEventId: 'invoice_gen_pg_1',
      });
      await generationService.recordUsageEvent(ctx, {
        walletId: 'wallet_b',
        action: 'swap',
        succeeded: true,
        occurredAt: '2026-01-06T01:00:00.000Z',
        sourceEventId: 'invoice_gen_pg_2',
      });
      await generationService.recordUsageEvent(ctx, {
        walletId: 'wallet_c',
        action: 'wallet_created',
        succeeded: true,
        occurredAt: '2026-01-07T01:00:00.000Z',
        sourceEventId: 'invoice_gen_pg_3',
      });

      const generation = await generationService.generateMonthlyInvoice(ctx, {
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

      const listed = await generationService.listInvoiceLineItems(ctx, generation.invoice.id);
      expect(listed.length).toBe(1);
      expect(listed[0]?.itemType).toBe('MAW_USAGE_DEBIT');

      const secondRun = await generationService.generateMonthlyInvoice(ctx, {
        periodMonthUtc: '2026-01',
      });
      expect(secondRun.generated).toBe(false);
      expect(secondRun.invoice.id).toBe(generation.invoice.id);
      expect(secondRun.invoice.amountDueMinor).toBe(600);

      const persisted = await queryInOrg({
        postgresUrl,
        namespace: generationNamespace,
        orgId: ctx.orgId,
        text: `SELECT item_type, amount_minor
           FROM console_invoice_line_items
          WHERE namespace = $1 AND org_id = $2 AND invoice_id = $3`,
        values: [generationNamespace, ctx.orgId, generation.invoice.id],
      });
      expect(persisted.rows.length).toBe(1);
      expect(String((persisted.rows[0] as any).item_type || '')).toBe('MAW_USAGE_DEBIT');
      expect(Number((persisted.rows[0] as any).amount_minor || 0)).toBe(600);
    } finally {
      await cleanupBillingNamespaceForOrgs({
        postgresUrl,
        namespace: generationNamespace,
        orgIds: [ctx.orgId],
      });
    }
  });

  test('postgres service lists receipt and statement history with filters, pagination, and activity', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const historyNamespace = randomNamespace('test:console-billing:history');
    let current = new Date('2026-01-20T00:00:00.000Z');
    const historyService = await createPostgresConsoleBillingService({
      postgresUrl,
      namespace: historyNamespace,
      logger: console as any,
      ensureSchema: true,
      now: () => current,
    });
    const ctx = {
      orgId: 'org-postgres-invoice-history',
      actorUserId: 'ops-invoice-history-postgres',
      roles: ['ops'],
    } satisfies BillingCtx;

    try {
      await historyService.recordUsageEvent(ctx, {
        walletId: 'wallet_january_1',
        action: 'transfer',
        succeeded: true,
        sourceEventId: 'usage_january_1',
        occurredAt: '2026-01-09T00:00:00.000Z',
      });
      await historyService.generateMonthlyInvoice(ctx, { periodMonthUtc: '2026-01' });

      current = new Date('2026-02-20T00:00:00.000Z');
      await historyService.recordUsageEvent(ctx, {
        walletId: 'wallet_february_1',
        action: 'transfer',
        succeeded: true,
        sourceEventId: 'usage_february_1',
        occurredAt: '2026-02-11T00:00:00.000Z',
      });
      await historyService.generateMonthlyInvoice(ctx, { periodMonthUtc: '2026-02' });

      current = new Date('2026-03-20T00:00:00.000Z');
      await historyService.recordUsageEvent(ctx, {
        walletId: 'wallet_march_1',
        action: 'transfer',
        succeeded: true,
        sourceEventId: 'usage_march_1',
        occurredAt: '2026-03-15T00:00:00.000Z',
      });
      const march = await historyService.generateMonthlyInvoice(ctx, { periodMonthUtc: '2026-03' });
      const receipt = await settleCreditPurchase(historyService, ctx, 'usd_25');
      expect(receipt.invoice.documentType).toBe('PURCHASE_RECEIPT');

      const firstPage = await historyService.listInvoicesPage(ctx, { limit: 1 });
      expect(firstPage.invoices.length).toBe(1);
      expect(firstPage.totalCount).toBe(4);
      expect(firstPage.nextCursor).toBeTruthy();
      expect(firstPage.summary.receiptCount).toBe(1);
      expect(firstPage.summary.statementCount).toBe(3);
      expect(firstPage.summary.paidCount).toBe(4);

      const secondPage = await historyService.listInvoicesPage(ctx, {
        limit: 1,
        cursor: firstPage.nextCursor || undefined,
      });
      expect(secondPage.invoices.length).toBe(1);
      expect(secondPage.invoices[0]?.id).not.toBe(firstPage.invoices[0]?.id);

      const receipts = await historyService.listInvoicesPage(ctx, {
        documentType: 'PURCHASE_RECEIPT',
      });
      expect(receipts.totalCount).toBe(1);
      expect(receipts.invoices[0]?.documentType).toBe('PURCHASE_RECEIPT');

      const february = await historyService.listInvoicesPage(ctx, {
        documentType: 'USAGE_STATEMENT',
        periodMonthUtc: '2026-02',
      });
      expect(february.totalCount).toBe(1);
      expect(february.invoices[0]?.periodMonthUtc).toBe('2026-02');
      expect(february.invoices[0]?.documentType).toBe('USAGE_STATEMENT');

      const marchActivity = await historyService.getInvoiceActivity(ctx, march.invoice.id);
      expect(marchActivity).toBeTruthy();
      expect(
        marchActivity?.entries.some(
          (entry) => entry.type === 'LEDGER' && entry.toState === 'USAGE_DEBIT',
        ),
      ).toBe(true);

      const receiptActivity = await historyService.getInvoiceActivity(ctx, receipt.invoice.id);
      expect(receiptActivity).toBeTruthy();
      expect(
        receiptActivity?.entries.some(
          (entry) => entry.type === 'LEDGER' && entry.toState === 'CREDIT_PURCHASE',
        ),
      ).toBe(true);
    } finally {
      await cleanupBillingNamespaceForOrgs({
        postgresUrl,
        namespace: historyNamespace,
        orgIds: [ctx.orgId],
      });
    }
  });

  test('postgres service rebuilds invoice projections from ledger and purchase state', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const projectionNamespace = randomNamespace('test:console-billing:projection-rebuild');
    let current = new Date('2026-03-20T00:00:00.000Z');
    const projectionService = await createPostgresConsoleBillingService({
      postgresUrl,
      namespace: projectionNamespace,
      logger: console as any,
      ensureSchema: true,
      now: () => current,
    });
    const ctx = {
      orgId: 'org-postgres-projection-rebuild',
      actorUserId: 'ops-projection-rebuild-postgres',
      roles: ['ops'],
    } satisfies BillingCtx;

    try {
      await projectionService.recordUsageEvent(ctx, {
        walletId: 'wallet_projection_1',
        action: 'transfer',
        succeeded: true,
        sourceEventId: 'projection_usage_1',
        occurredAt: '2026-03-09T00:00:00.000Z',
      });
      const statement = await projectionService.generateMonthlyInvoice(ctx, {
        periodMonthUtc: '2026-03',
      });
      const receipt = await settleCreditPurchase(projectionService, ctx, 'usd_25');

      await queryInOrg({
        postgresUrl,
        namespace: projectionNamespace,
        orgId: ctx.orgId,
        text: `DELETE FROM console_invoice_line_items
               WHERE namespace = $1 AND org_id = $2`,
        values: [projectionNamespace, ctx.orgId],
      });
      await queryInOrg({
        postgresUrl,
        namespace: projectionNamespace,
        orgId: ctx.orgId,
        text: `DELETE FROM console_invoices
               WHERE namespace = $1 AND org_id = $2`,
        values: [projectionNamespace, ctx.orgId],
      });

      const rebuilt = await projectionService.listInvoicesPage(ctx, {});
      expect(rebuilt.totalCount).toBe(2);
      expect(rebuilt.invoices.some((invoice) => invoice.id === statement.invoice.id)).toBe(true);
      expect(rebuilt.invoices.some((invoice) => invoice.id === receipt.invoice.id)).toBe(true);

      const rebuiltStatement = await projectionService.getInvoice(ctx, statement.invoice.id);
      expect(rebuiltStatement?.amountDueMinor).toBe(300);
      expect(rebuiltStatement?.documentType).toBe('USAGE_STATEMENT');

      const rebuiltReceipt = await projectionService.getInvoice(ctx, receipt.invoice.id);
      expect(rebuiltReceipt?.amountDueMinor).toBe(2500);
      expect(rebuiltReceipt?.documentType).toBe('PURCHASE_RECEIPT');

      const rebuiltStatementItems = await projectionService.listInvoiceLineItems(
        ctx,
        statement.invoice.id,
      );
      expect(rebuiltStatementItems.length).toBe(1);
      expect(rebuiltStatementItems[0]?.itemType).toBe('MAW_USAGE_DEBIT');
      expect(rebuiltStatementItems[0]?.amountMinor).toBe(300);

      const rebuiltReceiptItems = await projectionService.listInvoiceLineItems(
        ctx,
        receipt.invoice.id,
      );
      expect(rebuiltReceiptItems.length).toBe(1);
      expect(rebuiltReceiptItems[0]?.itemType).toBe('CREDIT_TOP_UP');
      expect(rebuiltReceiptItems[0]?.amountMinor).toBe(2500);

      const rebuiltActivity = await projectionService.getInvoiceActivity(ctx, statement.invoice.id);
      expect(
        rebuiltActivity?.entries.some(
          (entry) => entry.type === 'LEDGER' && entry.toState === 'USAGE_DEBIT',
        ),
      ).toBe(true);
    } finally {
      await cleanupBillingNamespaceForOrgs({
        postgresUrl,
        namespace: projectionNamespace,
        orgIds: [ctx.orgId],
      });
    }
  });

  test('monthly finalization job generates prior-month prepaid statements from usage meter rows', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const finalizationNamespace = randomNamespace('test:console-billing:finalization-job');
    const current = new Date('2026-02-15T00:00:00.000Z');
    const finalizationService = await createPostgresConsoleBillingService({
      postgresUrl,
      namespace: finalizationNamespace,
      logger: console as any,
      ensureSchema: true,
      now: () => current,
    });
    const orgA = {
      orgId: 'org-postgres-finalization-a',
      actorUserId: 'ops-finalization-a',
      roles: ['ops'],
    } satisfies BillingCtx;
    const orgB = {
      orgId: 'org-postgres-finalization-b',
      actorUserId: 'ops-finalization-b',
      roles: ['ops'],
    } satisfies BillingCtx;

    try {
      await insertUsageMeterEvent({
        postgresUrl,
        namespace: finalizationNamespace,
        orgId: orgA.orgId,
        walletId: 'wallet_finalization_a_1',
        action: 'transfer',
        occurredAt: '2026-01-05T01:00:00.000Z',
        sourceEventId: 'finalization_evt_a_1',
      });
      await insertUsageMeterEvent({
        postgresUrl,
        namespace: finalizationNamespace,
        orgId: orgB.orgId,
        walletId: 'wallet_finalization_b_1',
        action: 'swap',
        occurredAt: '2026-01-06T01:00:00.000Z',
        sourceEventId: 'finalization_evt_b_1',
      });
      await insertUsageMeterEvent({
        postgresUrl,
        namespace: finalizationNamespace,
        orgId: orgB.orgId,
        walletId: 'wallet_finalization_b_2',
        action: 'approve',
        occurredAt: '2026-01-07T01:00:00.000Z',
        sourceEventId: 'finalization_evt_b_2',
      });

      const firstRun = await runPostgresConsoleBillingMonthlyFinalization({
        postgresUrl,
        namespace: finalizationNamespace,
        orgIds: [orgA.orgId, orgB.orgId],
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
        orgIds: [orgA.orgId, orgB.orgId],
        periodMonthUtc: '2026-01',
        now: () => current,
        ensureSchema: false,
        logger: console as any,
      });
      expect(secondRun.orgCount).toBe(2);
      expect(secondRun.generatedCount).toBe(0);
      expect(secondRun.skippedCount).toBe(2);
      expect(secondRun.failures.length).toBe(0);

      const orgAJanStatement = (await finalizationService.listInvoices(orgA)).find(
        (invoice) =>
          invoice.periodMonthUtc === '2026-01' && invoice.documentType === 'USAGE_STATEMENT',
      );
      const orgBJanStatement = (await finalizationService.listInvoices(orgB)).find(
        (invoice) =>
          invoice.periodMonthUtc === '2026-01' && invoice.documentType === 'USAGE_STATEMENT',
      );
      expect(orgAJanStatement?.amountDueMinor).toBe(300);
      expect(orgBJanStatement?.amountDueMinor).toBe(600);
    } finally {
      await cleanupBillingNamespaceForOrgs({
        postgresUrl,
        namespace: finalizationNamespace,
        orgIds: [orgA.orgId, orgB.orgId],
      });
    }
  });

  test('postgres bootstrap creates one statement per org per period month', async () => {
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
      actorUserId: 'ops-rollover-postgres',
      roles: ['ops'],
    } satisfies BillingCtx;

    try {
      const januaryDocuments = await rolloverService.listInvoices(ctx);
      expect(januaryDocuments.length).toBe(1);
      expect(januaryDocuments[0]?.periodMonthUtc).toBe('2026-01');
      expect(januaryDocuments[0]?.documentType).toBe('USAGE_STATEMENT');
      expect(januaryDocuments[0]?.status).toBe('PAID');

      current = new Date('2026-02-02T00:00:00.000Z');
      const februaryDocuments = await rolloverService.listInvoices(ctx);
      expect(februaryDocuments.some((invoice) => invoice.periodMonthUtc === '2026-01')).toBe(true);
      expect(februaryDocuments.some((invoice) => invoice.periodMonthUtc === '2026-02')).toBe(true);
      expect(
        februaryDocuments.filter((invoice) => invoice.periodMonthUtc === '2026-02').length,
      ).toBe(1);

      current = new Date('2026-02-10T00:00:00.000Z');
      const februaryDocumentsAgain = await rolloverService.listInvoices(ctx);
      expect(
        februaryDocumentsAgain.filter((invoice) => invoice.periodMonthUtc === '2026-02').length,
      ).toBe(1);
    } finally {
      await cleanupBillingNamespaceForOrgs({
        postgresUrl,
        namespace: rolloverNamespace,
        orgIds: [ctx.orgId],
      });
    }
  });
});

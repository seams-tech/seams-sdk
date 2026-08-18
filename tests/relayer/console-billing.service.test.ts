import { expect, test } from '@playwright/test';
import {
  createInMemoryConsoleBillingService,
  verifyAndParseStripeWebhookRequest,
  type ConsoleBillingService,
} from '../../packages/console-server-ts/src/billing';
import {
  createInMemoryConsoleAuditService,
  type ConsoleAuditService,
} from '../../packages/console-server-ts/src/audit';
import { dispatchBillingStripePostProcessingEvent } from '../../packages/console-server-ts/src/router/stripePostProcessing';

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

async function makeStripeSignature(input: {
  secret: string;
  timestampSeconds: number;
  rawBody: string;
}): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(input.secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(`${input.timestampSeconds}.${input.rawBody}`),
  );
  return `t=${input.timestampSeconds},v1=${bytesToHex(new Uint8Array(signature))}`;
}

async function settleCreditPurchase(
  service: ConsoleBillingService,
  ctx: { orgId: string; actorUserId: string },
  creditPackId: 'usd_10' | 'usd_25' | 'usd_50' = 'usd_25',
): Promise<{
  checkoutSession: Awaited<ReturnType<ConsoleBillingService['createStripeCheckoutSession']>>;
  purchase: Extract<
    NonNullable<
      Awaited<ReturnType<ConsoleBillingService['processStripeWebhookEvent']>>['purchase']
    >,
    { status: 'SETTLED' }
  >;
  invoice: NonNullable<
    Awaited<ReturnType<ConsoleBillingService['processStripeWebhookEvent']>>['invoice']
  >;
}> {
  const checkoutSession = await service.createStripeCheckoutSession(ctx, {
    creditPackId,
  });
  const projection = await service.processStripeWebhookEvent({
    eventId: `evt_purchase_${Date.now()}_${Math.random().toString(16).slice(2)}`,
    eventType: 'checkout.session.completed',
    orgId: ctx.orgId,
    checkoutSessionId: checkoutSession.id,
    providerCustomerRef: checkoutSession.customerRef,
    providerPaymentRef: `pi_${checkoutSession.purchaseId}`,
    providerRef: checkoutSession.id,
    purchaseId: checkoutSession.purchaseId,
    creditPackId,
    amountMinor: checkoutSession.amountMinor,
    currency: 'USD',
    paymentStatus: 'paid',
  });
  expect(projection.accepted).toBe(true);
  expect(projection.purchase).toBeTruthy();
  expect(projection.invoice).toBeTruthy();
  if (!projection.purchase || projection.purchase.status !== 'SETTLED' || !projection.invoice) {
    throw new Error('Expected a settled test credit purchase and receipt');
  }
  return {
    checkoutSession,
    purchase: projection.purchase,
    invoice: projection.invoice,
  };
}

test.describe('console billing service prepaid model', () => {
  test('Stripe post-processing resumes after a crash without duplicating its audit event', async () => {
    const ctx = {
      orgId: 'org-stripe-post-processing-memory',
      actorUserId: 'user-stripe-post-processing-memory',
    };
    const service = createInMemoryConsoleBillingService();
    const audit = createInMemoryConsoleAuditService({ seedDemoData: false });
    const checkout = await service.createStripeCheckoutSession(ctx, {
      creditPackId: 'usd_25',
    });
    const eventId = 'evt_stripe_post_processing_memory';
    await service.processStripeWebhookEvent({
      eventId,
      eventType: 'checkout.session.completed',
      orgId: ctx.orgId,
      checkoutSessionId: checkout.id,
      providerCustomerRef: checkout.customerRef,
      providerPaymentRef: `pi_${checkout.purchaseId}`,
      providerRef: checkout.id,
      purchaseId: checkout.purchaseId,
      creditPackId: checkout.creditPackId,
      amountMinor: checkout.amountMinor,
      currency: 'USD',
      paymentStatus: 'paid',
    });

    const crashAfterAudit: ConsoleAuditService = new Proxy(audit, {
      get(target, property, receiver) {
        if (property !== 'appendEvent') return Reflect.get(target, property, receiver);
        return async (...args: Parameters<ConsoleAuditService['appendEvent']>) => {
          await target.appendEvent(...args);
          throw new Error('simulated crash after audit append');
        };
      },
    });
    const first = await dispatchBillingStripePostProcessingEvent(
      {
        billing: service,
        audit: crashAfterAudit,
        webhooks: null,
        logger: {},
      },
      eventId,
    );
    expect(first.completed).toBe(false);
    expect(await service.getStripePostProcessingOutboxItem(eventId)).toMatchObject({
      auditCompletedAt: null,
      customerWebhookCompletedAt: null,
      attemptCount: 1,
      lastError: 'simulated crash after audit append',
    });

    const second = await dispatchBillingStripePostProcessingEvent(
      {
        billing: service,
        audit,
        webhooks: null,
        logger: {},
      },
      eventId,
    );
    expect(second.completed).toBe(true);
    expect(await service.getStripePostProcessingOutboxItem(eventId)).toMatchObject({
      attemptCount: 1,
      lastError: null,
    });
    const events = await audit.listEvents(ctx, {
      category: 'BILLING',
      limit: 10,
    });
    expect(events).toHaveLength(1);
    expect(events[0]?.id).toBe(`stripe:${eventId}:credit-purchase-settled`);
  });

  test('in-memory service uses injected prepaid billing provider adapters', async () => {
    const service = createInMemoryConsoleBillingService({
      providers: {
        stripe: {
          createCheckoutSession: (input) => {
            expect(input.successUrl).toBe(
              'https://console.example.com/dashboard/billing/account?checkout=success&checkout_session_id={CHECKOUT_SESSION_ID}',
            );
            expect(input.cancelUrl).toBe(
              'https://console.example.com/dashboard/billing/account?checkout=cancel',
            );
            return {
              id: 'cs_mem_provider',
              url: 'https://checkout.example/memory',
              customerRef: 'cus_mem_provider',
              expiresAt: '2026-03-01T00:30:00.000Z',
            };
          },
          getCheckoutSession: () => ({
            id: 'cs_mem_provider',
            orgId: 'org-provider-adapter-memory',
            customerRef: 'cus_mem_provider',
            paymentIntentRef: 'pi_mem_provider',
            paymentStatus: 'paid',
            checkoutStatus: 'complete',
            purchaseId: 'unused_mem_purchase',
            creditPackId: 'usd_25',
            amountMinor: 2500,
            currency: 'USD',
          }),
          createRefund: (input) => ({
            id: `re_${input.refundId}`,
            status: 'succeeded',
            failureCode: null,
          }),
          getRefund: (input) => ({
            id: input.providerRefundId,
            status: 'succeeded',
            failureCode: null,
          }),
        },
      },
      consoleBaseUrl: 'https://console.example.com',
    });

    const ctx = {
      orgId: 'org-provider-adapter-memory',
      actorUserId: 'ops-provider-adapter-memory',
    };

    const checkoutSession = await service.createStripeCheckoutSession(ctx, {
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
      providerPaymentRef: 'pi_mem_provider',
      providerRef: checkoutSession.id,
      purchaseId: checkoutSession.purchaseId,
      creditPackId: 'usd_25',
      amountMinor: 2500,
      currency: 'USD',
      paymentStatus: 'paid',
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
    };

    const checkoutSession = await service.createStripeCheckoutSession(ctx, {
      creditPackId: 'usd_25',
    });

    const first = await service.processStripeWebhookEvent({
      eventId: 'evt_mem_same',
      eventType: 'checkout.session.completed',
      orgId: ctx.orgId,
      checkoutSessionId: checkoutSession.id,
      providerCustomerRef: checkoutSession.customerRef,
      providerPaymentRef: `pi_${checkoutSession.purchaseId}`,
      providerRef: checkoutSession.id,
      purchaseId: checkoutSession.purchaseId,
      creditPackId: 'usd_25',
      amountMinor: 2500,
      currency: 'USD',
      paymentStatus: 'paid',
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
      providerPaymentRef: `pi_${checkoutSession.purchaseId}`,
      providerRef: checkoutSession.id,
      purchaseId: checkoutSession.purchaseId,
      creditPackId: 'usd_25',
      amountMinor: 2500,
      currency: 'USD',
      paymentStatus: 'paid',
    });
    expect(duplicate.accepted).toBe(false);
    expect(duplicate.purchase?.status).toBe('SETTLED');

    const overview = await service.getOverview(ctx);
    expect(overview.creditBalanceMinor).toBe(2500);
  });

  test('checkout settlement uses the exact paid session and verifies the purchased pack', async () => {
    const service = createInMemoryConsoleBillingService();
    const ctx = {
      orgId: 'org-stripe-exact-checkout',
      actorUserId: 'ops-stripe-exact-checkout',
    };
    const first = await service.createStripeCheckoutSession(ctx, {
      creditPackId: 'usd_10',
    });
    const second = await service.createStripeCheckoutSession(ctx, {
      creditPackId: 'usd_50',
    });
    expect(first.customerRef).toBe(second.customerRef);

    await expect(
      service.processStripeWebhookEvent({
        eventId: 'evt_mem_mismatched_amount',
        eventType: 'checkout.session.completed',
        orgId: ctx.orgId,
        checkoutSessionId: first.id,
        providerCustomerRef: first.customerRef,
        providerPaymentRef: `pi_${first.purchaseId}`,
        providerRef: first.id,
        purchaseId: first.purchaseId,
        creditPackId: 'usd_10',
        amountMinor: 5000,
        currency: 'USD',
        paymentStatus: 'paid',
      }),
    ).rejects.toMatchObject({ code: 'checkout_session_mismatch' });

    const settled = await service.processStripeWebhookEvent({
      eventId: 'evt_mem_exact_first_session',
      eventType: 'checkout.session.completed',
      orgId: ctx.orgId,
      checkoutSessionId: first.id,
      providerCustomerRef: first.customerRef,
      providerPaymentRef: `pi_${first.purchaseId}`,
      providerRef: first.id,
      purchaseId: first.purchaseId,
      creditPackId: 'usd_10',
      amountMinor: 1000,
      currency: 'USD',
      paymentStatus: 'paid',
    });
    expect(settled.purchase?.id).toBe(first.purchaseId);
    expect(settled.purchase?.amountMinor).toBe(1000);
    expect((await service.getOverview(ctx)).creditBalanceMinor).toBe(1000);

    const expired = await service.processStripeWebhookEvent({
      eventId: 'evt_mem_expired_second_session',
      eventType: 'checkout.session.expired',
      orgId: ctx.orgId,
      checkoutSessionId: second.id,
      providerRef: second.id,
      purchaseId: second.purchaseId,
    });
    expect(expired.purchase?.status).toBe('CANCELED');
  });

  test('in-memory service appends manual support credits and admin debits idempotently', async () => {
    const service = createInMemoryConsoleBillingService();
    const ctx = {
      orgId: 'org-manual-adjustments-memory',
      actorUserId: 'admin-manual-adjustments-memory',
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
    for (const entry of activity.entries) {
      expect(entry.postings).toHaveLength(2);
      expect(entry.postings[0].direction).toBe('DEBIT');
      expect(entry.postings[1].direction).toBe('CREDIT');
      expect(entry.postings[0].amountMinor).toBe(entry.postings[1].amountMinor);
    }
  });

  test('in-memory refunds are partial, provider-backed, idempotent, and ledger-posted after success', async () => {
    const service = createInMemoryConsoleBillingService();
    const ctx = {
      orgId: 'org-refunds-memory',
      actorUserId: 'support-refunds-memory',
      platformSupport: true as const,
    };
    const settled = await settleCreditPurchase(service, ctx, 'usd_25');

    const first = await service.createRefund(ctx, {
      purchaseId: settled.purchase.id,
      amountMinor: 1000,
      reason: 'customer_request',
      idempotencyKey: 'refund-memory-1',
    });
    expect(first.created).toBe(true);
    expect(first.refund.status).toBe('succeeded');
    expect(first.creditBalanceMinor).toBe(1500);

    const duplicate = await service.createRefund(ctx, {
      purchaseId: settled.purchase.id,
      amountMinor: 1000,
      reason: 'customer_request',
      idempotencyKey: 'refund-memory-1',
    });
    expect(duplicate.created).toBe(false);
    expect(duplicate.refund.id).toBe(first.refund.id);
    expect(duplicate.creditBalanceMinor).toBe(1500);

    const remainder = await service.createRefund(ctx, {
      purchaseId: settled.purchase.id,
      amountMinor: 1500,
      reason: 'customer_request',
      idempotencyKey: 'refund-memory-2',
    });
    expect(remainder.refund.status).toBe('succeeded');
    expect(remainder.creditBalanceMinor).toBe(0);

    await expect(
      service.createRefund(ctx, {
        purchaseId: settled.purchase.id,
        amountMinor: 1,
        reason: 'over_refund',
        idempotencyKey: 'refund-memory-3',
      }),
    ).rejects.toMatchObject({ code: 'refund_amount_exceeds_purchase' });

    const refunds = await service.listRefunds(ctx);
    expect(refunds.map((refund) => refund.id)).toEqual([remainder.refund.id, first.refund.id]);
    const activity = await service.listAccountActivity(ctx, { eventType: 'REFUND' });
    expect(activity.entries).toHaveLength(2);
    expect(activity.entries.every((entry) => entry.amountMinor < 0)).toBe(true);
  });

  test('in-memory refund ledger waits for provider success and enforces unused credit', async () => {
    let providerStatus: 'pending' | 'succeeded' = 'pending';
    const service = createInMemoryConsoleBillingService({
      providers: {
        stripe: {
          createCheckoutSession: (input) => ({
            id: `cs_${input.purchaseId}`,
            url: 'https://checkout.example/refund-pending',
            customerRef: 'cus_refund_pending',
            expiresAt: '2026-03-01T00:30:00.000Z',
          }),
          getCheckoutSession: (input) => ({
            id: input.checkoutSessionId,
            orgId: 'org-refund-pending-memory',
            customerRef: 'cus_refund_pending',
            paymentIntentRef: 'pi_refund_pending',
            paymentStatus: 'paid',
            checkoutStatus: 'complete',
            purchaseId: 'unused_refund_pending_purchase',
            creditPackId: 'usd_10',
            amountMinor: 1000,
            currency: 'USD',
          }),
          createRefund: (input) => ({
            id: `re_${input.refundId}`,
            status: providerStatus,
            failureCode: null,
          }),
          getRefund: (input) => ({
            id: input.providerRefundId,
            status: providerStatus,
            failureCode: null,
          }),
        },
      },
    });
    const ctx = {
      orgId: 'org-refund-pending-memory',
      actorUserId: 'support-refund-pending-memory',
      platformSupport: true as const,
    };
    const settled = await settleCreditPurchase(service, ctx, 'usd_10');
    await service.recordUsageEvent(ctx, {
      resourceId: 'refund-pending-wallet',
      shouldCount: true,
      sourceEventId: 'refund-pending-usage',
    });
    await expect(
      service.createRefund(ctx, {
        purchaseId: settled.purchase.id,
        amountMinor: 800,
        reason: 'exceeds_unused_credit',
        idempotencyKey: 'refund-pending-too-large',
      }),
    ).rejects.toMatchObject({ code: 'refund_amount_exceeds_credit' });

    const pending = await service.createRefund(ctx, {
      purchaseId: settled.purchase.id,
      amountMinor: 500,
      reason: 'customer_request',
      idempotencyKey: 'refund-pending-1',
    });
    expect(pending.refund.status).toBe('provider_pending');
    expect(pending.creditBalanceMinor).toBe(700);
    expect((await service.listAccountActivity(ctx, { eventType: 'REFUND' })).entries).toHaveLength(
      0,
    );

    providerStatus = 'succeeded';
    const reconciled = await service.reconcileRefund(ctx, { refundId: pending.refund.id });
    expect(reconciled.refund.status).toBe('succeeded');
    expect(reconciled.creditBalanceMinor).toBe(200);
    expect((await service.listAccountActivity(ctx, { eventType: 'REFUND' })).entries).toHaveLength(
      1,
    );
  });

  test('external refunds may make credit negative and dispute wins restore their debit', async () => {
    const service = createInMemoryConsoleBillingService();
    const ctx = {
      orgId: 'org-external-refund-memory',
      actorUserId: 'ops-external-refund-memory',
    };
    const settled = await settleCreditPurchase(service, ctx, 'usd_10');
    await service.recordUsageEvent(ctx, {
      resourceId: 'external-refund-wallet',
      shouldCount: true,
      sourceEventId: 'external-refund-usage',
    });

    const external = await service.processStripeWebhookEvent({
      eventId: 'evt_external_refund',
      eventType: 'refund.updated',
      refund: {
        providerRefundId: 're_external_refund',
        refundId: null,
        purchaseId: settled.purchase.id,
        orgId: ctx.orgId,
        providerPaymentRef: settled.purchase.providerPaymentRef,
        amountMinor: 1000,
        status: 'succeeded',
        reason: 'provider_refund',
        failureCode: null,
      },
    });
    expect(external.refunds[0]?.status).toBe('succeeded');
    expect((await service.getOverview(ctx)).creditBalanceMinor).toBe(-300);
    expect((await service.getOverview(ctx)).liveEnvironmentState).toBe('BLOCKED');

    const opened = await service.processStripeWebhookEvent({
      eventId: 'evt_dispute_opened',
      eventType: 'charge.dispute.created',
      orgId: ctx.orgId,
      purchaseId: settled.purchase.id,
      providerPaymentRef: settled.purchase.providerPaymentRef,
      providerDisputeId: 'dp_external_refund',
      amountMinor: 500,
    });
    expect(opened.dispute?.status).toBe('open');
    expect((await service.getOverview(ctx)).creditBalanceMinor).toBe(-800);

    const won = await service.processStripeWebhookEvent({
      eventId: 'evt_dispute_won',
      eventType: 'charge.dispute.closed',
      orgId: ctx.orgId,
      purchaseId: settled.purchase.id,
      providerPaymentRef: settled.purchase.providerPaymentRef,
      providerDisputeId: 'dp_external_refund',
      amountMinor: 500,
      outcome: 'won',
    });
    expect(won.dispute?.status).toBe('won');
    expect((await service.getOverview(ctx)).creditBalanceMinor).toBe(-300);
  });

  test('in-memory service derives blocked, low-balance, and healthy live-environment states', async () => {
    const service = createInMemoryConsoleBillingService();
    const ctx = {
      orgId: 'org-live-env-state-memory',
      actorUserId: 'admin-live-env-state-memory',
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

  test('in-memory service links manual adjustments to invoice activity when relatedInvoiceId is provided', async () => {
    const service = createInMemoryConsoleBillingService();
    const ctx = {
      orgId: 'org-manual-adjustments-linked-memory',
      actorUserId: 'admin-manual-adjustments-linked-memory',
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

  test('in-memory service records large manual admin debits', async () => {
    const service = createInMemoryConsoleBillingService();
    const platformCtx = {
      orgId: 'org-manual-adjustments-large-debit-memory',
      actorUserId: 'admin-manual-adjustments-large-debit-memory',
    };

    await service.grantManualSupportCredit(platformCtx, {
      amountMinor: 75_000,
      reasonCode: 'bootstrap_credit',
      note: 'Seeded large balance for debit authorization test',
      idempotencyKey: 'manual-credit-large-debit-memory-1',
    });

    const debit = await service.appendManualAdminDebit(platformCtx, {
      amountMinor: 50_000,
      reasonCode: 'large_debit_correction',
      note: 'Platform operator approved large debit',
      idempotencyKey: 'manual-debit-large-debit-memory-platform',
    });
    expect(debit.created).toBe(true);
    expect(debit.adjustment.amountMinor).toBe(-50_000);
  });

  test('in-memory service MAW counts distinct wallets with exclusions and idempotency', async () => {
    const service = createInMemoryConsoleBillingService();
    const ctx = {
      orgId: 'org-maw-memory',
      actorUserId: 'ops-maw-memory',
    };

    const first = await service.recordUsageEvent(ctx, {
      resourceId: 'wallet_mem_1',
      shouldCount: true,
      sourceEventId: 'maw_mem_evt_1',
    });
    expect(first.accepted).toBe(true);
    expect(first.counted).toBe(true);
    expect(first.monthlyActiveResources).toBe(1);
    expect(first.debitAppliedMinor).toBe(300);
    expect(first.creditBalanceMinor).toBe(-300);
    expect(first.statementId).toBeTruthy();

    const secondSameWallet = await service.recordUsageEvent(ctx, {
      resourceId: 'wallet_mem_1',
      shouldCount: true,
      sourceEventId: 'maw_mem_evt_2',
    });
    expect(secondSameWallet.accepted).toBe(true);
    expect(secondSameWallet.counted).toBe(true);
    expect(secondSameWallet.monthlyActiveResources).toBe(1);
    expect(secondSameWallet.debitAppliedMinor).toBe(0);

    const excluded = await service.recordUsageEvent(ctx, {
      resourceId: 'wallet_mem_2',
      shouldCount: false,
      sourceEventId: 'maw_mem_evt_3',
    });
    expect(excluded.accepted).toBe(true);
    expect(excluded.counted).toBe(false);
    expect(excluded.monthlyActiveResources).toBe(1);

    const thirdDistinct = await service.recordUsageEvent(ctx, {
      resourceId: 'wallet_mem_3',
      shouldCount: true,
      sourceEventId: 'maw_mem_evt_4',
    });
    expect(thirdDistinct.accepted).toBe(true);
    expect(thirdDistinct.counted).toBe(true);
    expect(thirdDistinct.monthlyActiveResources).toBe(2);
    expect(thirdDistinct.debitAppliedMinor).toBe(300);

    const duplicate = await service.recordUsageEvent(ctx, {
      resourceId: 'wallet_mem_3',
      shouldCount: true,
      sourceEventId: 'maw_mem_evt_4',
    });
    expect(duplicate.accepted).toBe(false);
    expect(duplicate.counted).toBe(false);
    expect(duplicate.monthlyActiveResources).toBe(2);

    const usage = await service.getMonthlyActiveResources(ctx, first.monthUtc);
    expect(usage.usageMetricVersion).toBe('active_resource_v1');
    expect(usage.monthUtc).toBe(first.monthUtc);
    expect(usage.monthlyActiveResources).toBe(2);
  });

  test('in-memory service records sponsored execution debits idempotently and projects them into statements', async () => {
    const service = createInMemoryConsoleBillingService();
    const ctx = {
      orgId: 'org-sponsored-debits-memory',
      actorUserId: 'ops-sponsored-debits-memory',
    };

    await settleCreditPurchase(service, ctx, 'usd_25');

    const first = await service.recordProductExecutionDebit(ctx, {
      amountMinor: 125,
      sourceEventId: 'sponsored_mem_evt_1',
      resourceId: 'alice.testnet',
      occurredAt: '2026-03-12T00:00:00.000Z',
      txOrExecutionRef: 'tx_mem_123',
      pricingVersion: 'pricing-mem-v1',
    });
    expect(first.accepted).toBe(true);
    expect(first.debitAppliedMinor).toBe(125);
    expect(first.creditBalanceMinor).toBe(2375);
    expect(first.statementId).toBeTruthy();

    const duplicate = await service.recordProductExecutionDebit(ctx, {
      amountMinor: 125,
      sourceEventId: 'sponsored_mem_evt_1',
      resourceId: 'alice.testnet',
      occurredAt: '2026-03-12T00:00:00.000Z',
    });
    expect(duplicate.accepted).toBe(false);
    expect(duplicate.debitAppliedMinor).toBe(0);
    expect(duplicate.creditBalanceMinor).toBe(2375);

    const overview = await service.getOverview(ctx);
    expect(overview.creditBalanceMinor).toBe(2375);

    const accountActivity = await service.listAccountActivity(ctx, { limit: 5 });
    expect(accountActivity.entries.some((entry) => entry.type === 'PRODUCT_EXECUTION_DEBIT')).toBe(
      true,
    );

    const statementId = String(first.statementId || '');
    const statement = await service.getInvoice(ctx, statementId);
    expect(statement?.documentType).toBe('USAGE_STATEMENT');
    expect(statement?.amountDueMinor).toBe(125);

    const lineItems = await service.listInvoiceLineItems(ctx, statementId);
    expect(lineItems.some((item) => item.itemType === 'PRODUCT_EXECUTION_DEBIT')).toBe(true);
    expect(lineItems.find((item) => item.itemType === 'PRODUCT_EXECUTION_DEBIT')?.amountMinor).toBe(
      125,
    );

    const activity = await service.getInvoiceActivity(ctx, statementId);
    expect(
      activity?.entries.some(
        (entry) => entry.type === 'LEDGER' && entry.toState === 'PRODUCT_EXECUTION_DEBIT',
      ),
    ).toBe(true);
  });

  test('in-memory service creates one statement per org per period month', async () => {
    let current = new Date('2026-01-20T00:00:00.000Z');
    const service = createInMemoryConsoleBillingService({
      now: () => current,
    });
    const ctx = {
      orgId: 'org-month-rollover-memory',
      actorUserId: 'ops-month-rollover',
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
    };

    await service.recordUsageEvent(ctx, {
      resourceId: 'wallet_a',
      shouldCount: true,
      occurredAt: '2026-01-05T01:00:00.000Z',
      sourceEventId: 'invoice_gen_mem_1',
    });
    await service.recordUsageEvent(ctx, {
      resourceId: 'wallet_b',
      shouldCount: true,
      occurredAt: '2026-01-06T01:00:00.000Z',
      sourceEventId: 'invoice_gen_mem_2',
    });
    await service.recordUsageEvent(ctx, {
      resourceId: 'wallet_c',
      shouldCount: false,
      occurredAt: '2026-01-07T01:00:00.000Z',
      sourceEventId: 'invoice_gen_mem_3',
    });

    const generation = await service.generateMonthlyInvoice(ctx, {
      periodMonthUtc: '2026-01',
    });
    expect(generation.generated).toBe(false);
    expect(generation.monthlyActiveResources).toBe(2);
    expect(generation.pricing.activeResourceUnitPriceMinor).toBe(300);
    expect(generation.invoice.periodMonthUtc).toBe('2026-01');
    expect(generation.invoice.documentType).toBe('USAGE_STATEMENT');
    expect(generation.invoice.amountDueMinor).toBe(600);
    expect(generation.invoice.amountPaidMinor).toBe(600);
    expect(generation.lineItems.length).toBe(1);
    expect(generation.lineItems[0]?.itemType).toBe('ACTIVE_RESOURCE_USAGE_DEBIT');
    expect(generation.lineItems[0]?.quantity).toBe(2);
    expect(generation.lineItems[0]?.amountMinor).toBe(600);

    const listed = await service.listInvoiceLineItems(ctx, generation.invoice.id);
    expect(listed.length).toBe(1);
    expect(listed[0]?.itemType).toBe('ACTIVE_RESOURCE_USAGE_DEBIT');

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
    };

    await service.recordUsageEvent(ctx, {
      resourceId: 'wallet_january_1',
      shouldCount: true,
      sourceEventId: 'usage_january_1',
      occurredAt: '2026-01-09T00:00:00.000Z',
    });
    await service.generateMonthlyInvoice(ctx, { periodMonthUtc: '2026-01' });
    current = new Date('2026-02-20T00:00:00.000Z');
    await service.recordUsageEvent(ctx, {
      resourceId: 'wallet_february_1',
      shouldCount: true,
      sourceEventId: 'usage_february_1',
      occurredAt: '2026-02-11T00:00:00.000Z',
    });
    await service.generateMonthlyInvoice(ctx, { periodMonthUtc: '2026-02' });
    current = new Date('2026-03-20T00:00:00.000Z');
    await service.recordUsageEvent(ctx, {
      resourceId: 'wallet_march_1',
      shouldCount: true,
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
    const current = new Date('2026-03-20T00:00:00.000Z');
    const service = createInMemoryConsoleBillingService({
      now: () => current,
    });
    const ctx = {
      orgId: 'org-invoice-projection-memory',
      actorUserId: 'ops-invoice-projection',
    };

    const usage = await service.recordUsageEvent(ctx, {
      resourceId: 'wallet_projection_1',
      shouldCount: true,
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
    expect(statementItems[0]?.itemType).toBe('ACTIVE_RESOURCE_USAGE_DEBIT');
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

  test('Stripe webhook verification uses the untouched raw body and parses the event envelope', async () => {
    const now = new Date('2026-03-20T00:00:00.000Z');
    const timestampSeconds = Math.floor(now.getTime() / 1000);
    const secret = 'whsec_console_billing_test';
    const rawBody = JSON.stringify({
      id: 'evt_signed_checkout',
      type: 'checkout.session.completed',
      data: {
        object: {
          id: 'cs_signed_checkout',
          client_reference_id: 'org-signed-checkout',
          customer: 'cus_signed_checkout',
          payment_intent: 'pi_signed_checkout',
          payment_status: 'paid',
          amount_total: 2500,
          currency: 'usd',
          metadata: {
            org_id: 'org-signed-checkout',
            purchase_id: 'bcp_signed_checkout',
            credit_pack_id: 'usd_25',
          },
        },
      },
    });
    const signatureHeader = await makeStripeSignature({
      secret,
      timestampSeconds,
      rawBody,
    });

    const parsed = await verifyAndParseStripeWebhookRequest({
      rawBody,
      signatureHeader,
      secret,
      now,
    });
    expect(parsed).toEqual({
      eventId: 'evt_signed_checkout',
      eventType: 'checkout.session.completed',
      orgId: 'org-signed-checkout',
      providerCustomerRef: 'cus_signed_checkout',
      checkoutSessionId: 'cs_signed_checkout',
      providerPaymentRef: 'pi_signed_checkout',
      providerRef: 'cs_signed_checkout',
      purchaseId: 'bcp_signed_checkout',
      creditPackId: 'usd_25',
      amountMinor: 2500,
      currency: 'USD',
      paymentStatus: 'paid',
    });

    await expect(
      verifyAndParseStripeWebhookRequest({
        rawBody: `${rawBody} `,
        signatureHeader,
        secret,
        now,
      }),
    ).rejects.toMatchObject({ code: 'invalid_stripe_signature' });

    const unpaidRawBody = rawBody.replace('"payment_status":"paid"', '"payment_status":"unpaid"');
    await expect(
      verifyAndParseStripeWebhookRequest({
        rawBody: unpaidRawBody,
        signatureHeader: await makeStripeSignature({
          secret,
          timestampSeconds,
          rawBody: unpaidRawBody,
        }),
        secret,
        now,
      }),
    ).rejects.toMatchObject({ code: 'invalid_stripe_payload' });
  });
});
